#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Pure metadata/command controls for the distinct full-CRT builder."""
import ast
import copy
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import hashlib
import json

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import build_wine_service_child as build
import native_service_converter as converter
from native_probe_elf import nid


class Mapping:
    def offset(self, address, size, flags):
        if not (0x1000 <= address <= 0x1100 - size and flags == 6):
            raise ValueError('not a unique writable import slot')
        return address - 0x1000


def fixture():
    needed = ['libSceLibcInternal.sprx', 'libkernel.sprx', 'libSceNet.sprx']
    names = list(build.CRT_IMPORTS)
    providers = {name: {'definitions': {}, 'sha256': str(i) * 64} for i, name in enumerate(needed, 1)}
    linked, converted = Mapping(), Mapping()
    linked.kind = 3; converted.kind = 0xfe10
    linked.needed = needed; converted.needed = [s.replace('.sprx', '.prx') for s in needed]
    converted.modules = {1: 'libSceLibcInternal', 2: 'libkernel', 3: 'libSceNet'}
    converted.libraries = {0: 'libSceLibcInternal', 1: 'libkernel', 2: 'libSceNet'}
    linked.symbols = [{}]; converted.symbols = [{}]
    linked.relocations = []; converted.relocations = []
    for index, name in enumerate(names, 1):
        provider = build.CRT_IMPORTS[name]; rank = needed.index(provider)
        providers[provider]['definitions'][name] = 'FUNC'
        symbol = {'name': name, 'type': 2, 'binding': 1, 'visibility': 0, 'section': 0, 'value': 0, 'size': 0}
        linked.symbols.append(symbol)
        converted.symbols.append({**symbol, 'name': nid(name) + '#' + 'ABC'[rank] + '#' + 'BCD'[rank]})
        relocation = {'symbol': index, 'type': 6, 'addend': 0, 'address': 0x1000 + index * 8}
        linked.relocations.append(relocation); converted.relocations.append(dict(relocation))
    return linked, converted, providers


class WineServiceChildBuild(unittest.TestCase):
    def test_shared_client_header_is_part_of_service_identity(self):
        self.assertIn('native/pw_lapy_client.h', build.HEADERS)
        class InertCommands:
            def run(self, *argv):
                if 'status' in argv:
                    return ''
                return '1' * 40
        project, sources = build.source_identity(ROOT, InertCommands())
        name = 'native/pw_lapy_client.h'
        self.assertEqual(sources[name], build.sha(ROOT / name))
        mutated = dict(sources, **{name: '0' * 64})
        self.assertNotEqual(build.identity({'project': project, 'sources': sources}),
                            build.identity({'project': project, 'sources': mutated}))

    def test_root_shared_headers_are_frozen(self):
        for name in ('native/pw_data_mount.c', 'native/pw_data_mount.h',
                     'native/pw_lapy_elevation.c', 'native/pw_lapy_elevation.h',
                     'native/lapy_elevation_protocol.h', 'native/pw_lapy_client.h',
                     'native/pw_sha256.h'):
            self.assertIn(name, build.TITLE_USER_SOURCES)

    def test_helper_inputs_bind_source_producer_and_reject_old_cohorts(self):
        import importlib.util
        import build_owned_helper as helper
        spec = importlib.util.spec_from_file_location('owned_fixture', ROOT / 'tests/test_owned_helper.py')
        fixture_module = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture_module)
        fixture = fixture_module.Admission(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        sdk = fixture.repo.parent / 'sdk'; sdk.mkdir()
        fixture.build['sdk_path'] = str(sdk)
        fixture.build['command_paths']['SDK'] = str(sdk)
        for command in fixture.build['commands']:
            command['argv'] = [v.replace('/inert-sdk', str(sdk)) for v in command['argv']]
        fixture.rebind()
        args = types.SimpleNamespace(helper_directory=fixture.out)
        with patch.object(helper, 'producer_llvm_identity', return_value=fixture.host_llvm), \
             patch.object(helper, 'sdk_record', return_value=fixture.sdk), \
             patch.object(helper, 'inspect_elf', return_value=fixture.build['inspection']):
            expected = build.helper_inputs(args, fixture.repo, fixture.project, sdk)
            self.assertTrue(expected['toolchain_reverified'])
            self.assertFalse(expected['runtime_validated'])
            self.assertEqual(expected['elf'], helper.record(fixture.out / 'lapy.elf'))
            retained = fixture.repo.parent / 'retained'; retained.mkdir()
            build.retain_helper(fixture.out, retained / 'owned-helper')
            self.assertEqual(build.helper_inputs(types.SimpleNamespace(service_work=retained),
                             fixture.repo, fixture.project, sdk), expected)
            for field, value in [('protocol_version', 1), ('protocol_sha256', '0'*64),
                                 ('elf_sha256', '0'*64), ('console_validated', True),
                                 ('features', ['root_layout_probe_retry'])]:
                bad = dict(fixture.manifest); bad[field] = value
                fixture.write('lapy-manifest.json', bad)
                with self.subTest(field=field), self.assertRaises(ValueError):
                    build.helper_inputs(args, fixture.repo, fixture.project, sdk)
            fixture.write('lapy-manifest.json', fixture.manifest)
            with self.assertRaisesRegex(ValueError, 'cohort'):
                build.helper_inputs(args, fixture.repo, {'commit':'f'*40, 'tree':'e'*40}, sdk)
            (fixture.out / 'obj' / (helper.UNITS[0] + '.o')).write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'objects'):
                build.helper_inputs(args, fixture.repo, fixture.project, sdk)
        legacy = types.SimpleNamespace(helper=fixture.out / 'lapy.elf',
            helper_manifest=fixture.out / 'lapy-manifest.json', helper_release=fixture.out / 'release.json')
        with self.assertRaisesRegex(ValueError, 'source-bound'):
            build.helper_inputs(legacy, fixture.repo, fixture.project, sdk)

    def test_native_build_uses_verified_actual_helper_before_child_and_title(self):
        script = (ROOT / 'tools/build_native.sh').read_text()
        producer = script.index('tools/build_owned_helper.py" build')
        validator = script.index('record = validate_owned_helper')
        macro = script.index('common=(-DPW_LAPY_HELPER_SHA256')
        child = script.index('tools/build_wine_service_child.py" --work')
        self.assertLess(producer, validator); self.assertLess(validator, macro); self.assertLess(macro, child)
        self.assertIn('--helper-directory "$build/owned-helper"', script)
        self.assertNotIn('fetch_lapy_helper.py', script)
        self.assertNotIn('43fab6d8', script)
        self.assertIn("print(record['elf']['sha256'])", script)
        source = Path(build.__file__).read_text()
        self.assertIn("'pw-wine-service-child/2'", source)
        self.assertNotIn("'pw-wine-service-child/1'", source)
        self.assertNotIn('HELPER_SHA =', source)
        self.assertIn("'console_execution_verified': False", source)

    def test_retained_child_refuses_legacy_and_mixed_manifest_before_elf_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            bound = {'project': {'commit': 'a'*40, 'tree': 'b'*40},
                     'helper': {'elf': {'sha256': 'ab'*32}, 'protocol_sha256': 'cd'*32}}
            args = types.SimpleNamespace(service_work=work)
            for schema, mutation in [('pw-wine-service-child/1', None),
                                     ('pw-wine-service-child/2', 'helper'),
                                     ('pw-wine-service-child/2', 'project')]:
                manifest = {'schema': schema, **copy.deepcopy(bound)}
                if mutation:
                    manifest[mutation] = {'stale': True}
                (work / 'native-wine-child-build.json').write_text(json.dumps(manifest))
                with patch.object(build, 'inputs', return_value=(bound, (work,)*6)), \
                     patch.object(build, 'Elf') as elf:
                    with self.assertRaisesRegex(ValueError, 'source/runtime inputs differ'):
                        build.verify_child(args, None)
                    elf.assert_not_called()

    def test_static_net_input_policy_binds_exact_functions_and_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk=Path(directory);(sdk/'target/lib').mkdir(parents=True)
            path=sdk/'target/lib/libSceNet.so';path.write_bytes(b'original inert Net provider')
            description={'soname':'libSceNet.sprx','definitions':{call:'FUNC' for call in build.NET_FUNCTIONS}}
            with patch.object(build,'provider',return_value=description):
                result=build.net_inputs(sdk,Path('/inert'),None)
                self.assertEqual(result,{'provider':{'soname':'libSceNet.sprx',**build.record(path)},
                    'functions':list(build.NET_FUNCTIONS),'acquisition':'static-imports',
                    'initialization':'native-root-transport','explicit_net_init':False,'runtime_validated':False})
                self.assertNotIn('sceNetInit',result['functions'])
                path.write_bytes(b'changed provider bytes')
                self.assertNotEqual(result['provider'],build.net_inputs(sdk,Path('/inert'),None)['provider'])
                for call in build.NET_FUNCTIONS:
                    for kind in ('OBJECT',None):
                        description['definitions'][call]=kind
                        with self.subTest(call=call,kind=kind),self.assertRaises(ValueError):
                            build.net_inputs(sdk,Path('/inert'),None)
                    description['definitions'][call]='FUNC'
                description['soname']='wrong'
                with self.assertRaises(ValueError):build.net_inputs(sdk,Path('/inert'),None)

    def test_converter_replay_binds_every_specialization_field(self):
        original = b"/* original high-layout writer */\n" + b"".join(before for before, _ in converter.EDITS)
        with tempfile.TemporaryDirectory() as directory, patch.object(
                converter, 'TITLE_WRITER_SHA256', hashlib.sha256(original).hexdigest()):
            root = Path(directory); native = root / 'native'; work = root / 'work'
            native.mkdir(); work.mkdir(); (native / 'sce_module_writer.cpp').write_bytes(original)
            _, record = converter.prepare_converter_source(native / 'sce_module_writer.cpp',
                work / 'sce_module_writer.service.cpp', service=True, foundation=build.TITLE_FOUNDATION)
            manifest = {'converter_specialization': record}
            build.verify_converter_copy(native, work, manifest)
            for key in record:
                wrong = copy.deepcopy(manifest); wrong['converter_specialization'][key] = 'stale'
                with self.subTest(field=key), self.assertRaisesRegex(ValueError, 'specialization report'):
                    build.verify_converter_copy(native, work, wrong)
            wrong = copy.deepcopy(manifest); wrong['converter_specialization']['foundation_commit'] = build.FOUNDATION
            with self.assertRaisesRegex(ValueError, 'specialization report'):
                build.verify_converter_copy(native, work, wrong)
            (work / 'sce_module_writer.service.cpp').write_bytes(original)
            with self.assertRaisesRegex(ValueError, 'source copy'):
                build.verify_converter_copy(native, work, manifest)

    def test_generated_header_requires_both_actual_capabilities(self):
        bound={'runtime': {'creation_abi':1, 'creation_protocol':962, 'private_dispatch_abi':1, 'private_dispatch_wow64_abi':1,
                           'ntdll_sha256':'b'*64}, 'project': {'commit':'a'*40, 'tree':'b'*40}, 'helper': {'elf': {'sha256': 'ab'*32}, 'project': {'commit':'a'*40, 'tree':'b'*40}, 'toolchain_reverified': True, 'runtime_validated': False}}
        text=build.child_header(bound,'a'*40)
        self.assertIn('#define PW_WINE_CHILD_WOW64_ABI 1\n',text)
        self.assertIn('b'*64,text)
        self.assertIn('ab'*32,text)
        wrong=copy.deepcopy(bound);wrong['helper']['elf']['sha256']='invalid'
        with self.assertRaises(ValueError):build.child_header(wrong,'a'*40)
        for name, value in [('project', {'commit':'c'*40,'tree':'b'*40}),
                            ('toolchain_reverified', False), ('runtime_validated', True)]:
            wrong=copy.deepcopy(bound);wrong['helper'][name]=value
            with self.assertRaises(ValueError):build.child_header(wrong,'a'*40)
        alternate=copy.deepcopy(bound);alternate['helper']['elf']['sha256']='cd'*32
        self.assertIn('cd'*32,build.child_header(alternate,'a'*40))
        self.assertNotEqual(build.identity(bound),build.identity(alternate))
        for name in ('private_dispatch_abi','private_dispatch_wow64_abi','creation_abi','creation_protocol'):
            wrong=copy.deepcopy(bound);wrong['runtime'].pop(name)
            with self.assertRaises(ValueError):build.child_header(wrong,'a'*40)
        with self.assertRaises(ValueError):build.child_header(bound,'old-build')

    def test_title_fixture_hash_is_current_standalone_and_read_only(self):
        digest='a'*64
        pair={'files':{name:{'bytes':123,'sha256':digest} for name in ('parent.exe','child.exe')}}
        def image(data,flags=4):
            return types.SimpleNamespace(data=data,programs=[(1,flags,0,0x1000,0,len(data))],
                                         offset=lambda address,size,required:address-0x1000)
        result=build.fixture_title_identity(image(b'\0'+digest.encode()+b'\0'),{'fixture_child_sha256':digest},pair)
        self.assertEqual(result['addresses'],[0x1001])
        for item,decl in [(image(b'old\0'),digest),(image(b'x'+digest.encode()+b'\0'),digest),
                          (image(digest.encode()+b'\0',6),digest),(image(digest.encode()+b'\0'),'b'*64)]:
            with self.assertRaises(ValueError):build.fixture_title_identity(item,{'fixture_child_sha256':decl},pair)
        changed=copy.deepcopy(pair);changed['files']['parent.exe']['sha256']='b'*64
        with self.assertRaises(ValueError):build.fixture_title_identity(image(digest.encode()+b'\0'),{'fixture_child_sha256':digest},changed)

    def test_full_crt_graph(self):
        graph = build.ordinary_graph(*fixture())
        self.assertEqual(set(graph), set(build.CRT_IMPORTS))
        self.assertEqual(graph['_init_env']['provider'], 'libSceLibcInternal.sprx')

    def add_import(self, linked, converted, providers, name, provider):
        index=len(linked.symbols);rank=linked.needed.index(provider)
        providers[provider]['definitions'][name]='FUNC'
        symbol={'name':name,'type':2,'binding':1,'visibility':0,'section':0,'value':0,'size':0}
        linked.symbols.append(symbol)
        converted.symbols.append({**symbol,'name':nid(name)+'#'+'ABC'[rank]+'#'+'BCD'[rank]})
        relocation={'symbol':index,'type':6,'addend':0,'address':0x1000+index*8}
        linked.relocations.append(relocation);converted.relocations.append(dict(relocation))

    def test_extra_bound_net_calls_including_init_are_refused(self):
        for name,provider in [('sceNetInit','libSceNet.sprx'),('sceNetTerm','libSceNet.sprx'),
                              ('sceNetShutdown','libSceNet.sprx'),('sceNetInit','libkernel.sprx')]:
            linked,converted,providers=fixture()
            self.add_import(linked,converted,providers,name,provider)
            with self.subTest(name=name,provider=provider),self.assertRaisesRegex(ValueError,'exactly seven'):
                build.ordinary_graph(linked,converted,providers)

    def test_old_dynamic_acquisition_calls_are_refused(self):
        for name in ('sceKernelDlsym','sceSysmoduleLoadModuleInternal','sceSysmoduleGetModuleHandleInternal'):
            linked,converted,providers=fixture()
            self.add_import(linked,converted,providers,name,'libkernel.sprx')
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'dynamic Net acquisition'):
                build.ordinary_graph(linked,converted,providers)

    def test_each_required_net_import_and_provider_is_exact(self):
        for name in build.NET_FUNCTIONS:
            linked,converted,providers=fixture()
            providers['libkernel.sprx']['definitions'][name]='FUNC'
            index=next(i for i,s in enumerate(linked.symbols) if s.get('name')==name)
            converted.symbols[index]['name']=nid(name)+'#B#C'
            with self.subTest(wrong_provider=name),self.assertRaisesRegex(ValueError,'lifecycle'):
                build.ordinary_graph(linked,converted,providers)
            linked,converted,providers=fixture()
            index=next(i for i,s in enumerate(linked.symbols) if s.get('name')==name)
            linked.symbols.pop(index);converted.symbols.pop(index)
            for image in (linked,converted):
                image.relocations=[r for r in image.relocations if r['symbol']!=index]
                for r in image.relocations:
                    if r['symbol']>index:r['symbol']-=1
            with self.subTest(missing=name),self.assertRaisesRegex(ValueError,'lifecycle'):
                build.ordinary_graph(linked,converted,providers)

    def test_actual_link_and_converter_commands_receive_all_three_stubs(self):
        # Execute only these actual builder AST statements with an inert recorder.
        # This checks routing; no compiler, converter or target binary runs.
        function=next(n for n in ast.parse(Path(build.__file__).read_text()).body
                      if isinstance(n,ast.FunctionDef) and n.name=='build')
        statements=[]
        for node in function.body:
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='stubs' for t in node.targets):
                statements.append(node)
            elif isinstance(node,ast.Expr) and isinstance(node.value,ast.Call):
                call=node.value
                if isinstance(call.func,ast.Attribute) and call.func.attr=='run' and (
                        any(isinstance(n,ast.Constant) and n.value=='bin/prospero-lld' for n in ast.walk(call)) or
                        any(isinstance(n,ast.Constant) and n.value=='--component' for n in ast.walk(call))):
                    statements.append(node)
        self.assertEqual(len(statements),3)
        calls=[]
        scope={'sdk':Path('/sdk'),'title':Path('/title'),'environment':[],
               'linked':Path('/linked'),'converted':Path('/converted'),'crt':Path('/crt'),
               'objects':[],'tool':Path('/tool'),'PROVIDERS':build.PROVIDERS,
               'commands':types.SimpleNamespace(run=lambda *args:calls.append(args))}
        exec(compile(ast.Module(body=statements,type_ignores=[]),build.__file__,'exec'),scope)
        expected=[Path('/sdk/target/lib')/leaf for leaf in
                  ('libSceLibcInternal.so','libkernel.so','libSceNet.so')]
        self.assertEqual(list(calls[0][-3:]),expected)
        self.assertEqual([calls[1][i+1] for i,arg in enumerate(calls[1]) if arg=='--stub'],expected)

    def test_wrong_provider_set(self):
        linked, converted, providers = fixture()
        linked.needed.append('libkernel_web.sprx')
        with self.assertRaisesRegex(ValueError, 'exactly ordinary'):
            build.ordinary_graph(linked, converted, providers)
        linked, converted, providers = fixture()
        linked.needed[-1] = 'libSceSysmodule.sprx'
        with self.assertRaisesRegex(ValueError, 'exactly ordinary'):
            build.ordinary_graph(linked, converted, providers)

    def test_data_import_and_nonfunction_provider(self):
        for field in ('import', 'provider'):
            linked, converted, providers = fixture()
            if field == 'import':
                linked.symbols[1]['type'] = converted.symbols[1]['type'] = 1
            else:
                providers['libSceLibcInternal.sprx']['definitions']['_init_env'] = 'OBJECT'
            with self.assertRaisesRegex(ValueError, 'type/provider'):
                build.ordinary_graph(linked, converted, providers)

    def test_missing_lifecycle_import(self):
        linked, converted, providers = fixture()
        linked.symbols.pop(); converted.symbols.pop(); linked.relocations.pop(); converted.relocations.pop()
        with self.assertRaisesRegex(ValueError, 'lifecycle'):
            build.ordinary_graph(linked, converted, providers)

    def test_wrong_nid_and_provider_qualifier(self):
        for name in ('bad#A#B', nid('_init_env') + '#B#C'):
            linked, converted, providers = fixture()
            converted.symbols[1]['name'] = name
            with self.assertRaises(ValueError):
                build.ordinary_graph(linked, converted, providers)

    def test_nonzero_addend_and_readonly_target(self):
        for field, value in [('addend', 1), ('address', 0x2000), ('type', 1)]:
            linked, converted, providers = fixture()
            linked.relocations[0][field] = converted.relocations[0][field] = value
            with self.assertRaises(ValueError):
                build.ordinary_graph(linked, converted, providers)

    def test_first_provider_selection_is_checked(self):
        linked, converted, providers = fixture()
        providers['libSceLibcInternal.sprx']['definitions']['pthread_create'] = 'FUNC'
        with self.assertRaisesRegex(ValueError, 'first provider'):
            build.ordinary_graph(linked, converted, providers)

    def test_identity_changes_with_runtime_and_source(self):
        inputs = {'project': {'commit': 'a' * 40, 'tree': 'b' * 40},
                  'runtime': {'ntdll_sha256': 'c' * 64, 'private_dispatch_abi': 1},
                  'sources': {'main.c': 'd' * 64}, 'app_crt_sha256': build.CRT_SHA}
        baseline = build.identity(inputs)
        self.assertRegex(baseline, '^[0-9a-f]{40}$')
        self.assertEqual(baseline, build.identity(copy.deepcopy(inputs)))
        for section, key, value in [('runtime', 'ntdll_sha256', 'e' * 64), ('sources', 'main.c', 'f' * 64),
                                    ('project', 'commit', '1' * 40)]:
            changed = copy.deepcopy(inputs); changed[section][key] = value
            self.assertNotEqual(baseline, build.identity(changed))

    def test_fresh_output_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory(prefix='pw-crt-builder-') as temporary:
            root = Path(temporary); original = root / 'input'; original.mkdir()
            with self.assertRaisesRegex(ValueError, 'overlaps'):
                build.output_directory(original / 'out', (original,))
            alias = root / 'alias'; alias.symlink_to(original, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                build.output_directory(alias / 'out', (original,))
            out = build.output_directory(root / 'out', (original,))
            with self.assertRaisesRegex(ValueError, 'absent'):
                build.output_directory(out, (original,))

    def test_original_converter_and_crt_are_distinct_inputs(self):
        self.assertEqual(build.FOUNDATION, '30597512539e7edfde079cbcaf4a626bc0a948c5')
        self.assertEqual(build.TITLE_FOUNDATION, '9c0b994a048521af6fb84c73ded364504fe250e9')
        self.assertNotEqual(build.FOUNDATION, build.TITLE_FOUNDATION)
        self.assertEqual(build.CRT_SHA, 'a99fe406e36d8ce82e68e0245898ba064e28a56a9853f746e9cf13d23cc17a00')

    def test_disassembly_refuses_raw_traps_and_bad_decode(self):
        build.check_disassembly('100000000 <_start>:\n 100000000: retq\n')
        for instruction in ('syscall', 'sysenter', 'int $0x80', 'int 128', '(bad)', '<unknown>', '.byte 0x0f'):
            with self.subTest(instruction=instruction), self.assertRaises(ValueError):
                build.check_disassembly('100000000 <_start>:\n 100000000: ' + instruction + '\n')
        with self.assertRaisesRegex(ValueError, 'empty'):
            build.check_disassembly('file format elf64-x86-64\n')

    def test_title_route_requires_marker_functions_and_unchanged_code(self):
        class Image:
            def __init__(self):
                self.data = b'CODE' + b'\0' * 124 + build.TITLE_MARKER.encode() + b'\0'
                self.programs = [(1, 5, 0, 0x1000, 0, 4), (1, 4, 128, 0x2000, 0, len(self.data) - 128)]
            def offset(self, address, size, flags):
                for _, actual_flags, offset, virtual, _, extent in self.programs:
                    if actual_flags & flags == flags and virtual <= address and address - virtual + size <= extent:
                        return offset + address - virtual
                raise ValueError('unmapped fixture segment')
        linked, recovered = Image(), Image()
        symbols = '\n'.join(f'{i}: 0000000000001000 4 FUNC GLOBAL DEFAULT 1 {name}'
                            for i, name in enumerate(build.TITLE_FUNCTIONS, 1))
        self.assertEqual(set(build.check_route(linked, recovered, symbols)['functions']), set(build.TITLE_FUNCTIONS))
        with self.assertRaisesRegex(ValueError, 'defined fixture route'):
            build.check_route(linked, recovered, '')
        recovered.data = b'FAIL' + recovered.data[4:]
        with self.assertRaisesRegex(ValueError, 'route bytes'):
            build.check_route(linked, recovered, symbols)
        recovered.data = b'CODE' + b'\0' * (len(recovered.data) - 4)
        with self.assertRaisesRegex(ValueError, 'compiled source identity'):
            build.check_route(linked, recovered, symbols)


if __name__ == '__main__':
    unittest.main()
