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
    needed = ['libSceLibcInternal.sprx', 'libkernel.sprx', 'libSceSysmodule.sprx']
    names = list(build.CRT_IMPORTS)
    providers = {name: {'definitions': {}, 'sha256': str(i) * 64} for i, name in enumerate(needed, 1)}
    linked, converted = Mapping(), Mapping()
    linked.kind = 3; converted.kind = 0xfe10
    linked.needed = needed; converted.needed = [s.replace('.sprx', '.prx') for s in needed]
    converted.modules = {1: 'libSceLibcInternal', 2: 'libkernel', 3: 'libSceSysmodule'}
    converted.libraries = {0: 'libSceLibcInternal', 1: 'libkernel', 2: 'libSceSysmodule'}
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
    def test_helper_inputs_bind_same_title_pin_manifest_and_retained_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'tools').mkdir();(root/'native').mkdir();work=root/'child';work.mkdir()
            (root/'native/lapy_elevation_protocol.h').write_bytes(b'original test protocol')
            elf=b'\x7fELF'+b'original inert helper';digest=hashlib.sha256(elf).hexdigest()
            script='lapy_release='+build.HELPER_RELEASE+'\nlapy_elf_sha256='+digest+'\n'
            (root/'tools/build_native.sh').write_text(script)
            manifest={'schema':'lapy-owned-build/1','mode':'elf-helper','target_title':'PPSA99995',
                      'elf_sha256':digest,'protocol_sha256':build.sha(root/'native/lapy_elevation_protocol.h'),
                      'features':['root_layout_probe_retry'],'max_requests':1,'service':False,'require_client_result':False}
            release={'repository':'mpereiraesaa/PS5-Lapy-JB-Daemon','tag_name':build.HELPER_RELEASE,
                     'release_url':'https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon/releases/tag/'+build.HELPER_RELEASE}
            (work/'lapy.elf').write_bytes(elf);(work/'lapy-manifest.json').write_text(json.dumps(manifest))
            (work/'lapy-release.json').write_text(json.dumps(release))
            args=types.SimpleNamespace(service_work=work)
            with patch.object(build,'HELPER_SHA',digest):
                expected=build.helper_inputs(args,root)
                explicit=types.SimpleNamespace(helper=work/'lapy.elf',helper_manifest=work/'lapy-manifest.json',helper_release=work/'lapy-release.json')
                self.assertEqual(expected,build.helper_inputs(explicit,root))
                for key,value in [('target_title','OTHER'),('elf_sha256','0'*64),('protocol_sha256','0'*64),
                                  ('max_requests',2),('service',True),('require_client_result',True),('features',[])]:
                    bad=dict(manifest);bad[key]=value;(work/'lapy-manifest.json').write_text(json.dumps(bad))
                    with self.subTest(field=key),self.assertRaises(ValueError):build.helper_inputs(args,root)
                (work/'lapy-manifest.json').write_text(json.dumps(manifest))
                (work/'lapy.elf').write_bytes(elf+b'changed')
                with self.assertRaises(ValueError):build.helper_inputs(args,root)
                (work/'lapy.elf').write_bytes(elf)
                (root/'tools/build_native.sh').write_text(script.replace(digest,'f'*64))
                with self.assertRaisesRegex(ValueError,'title pin'):build.helper_inputs(args,root)
                (root/'tools/build_native.sh').write_text(script)
                bad=dict(release,tag_name='different');(work/'lapy-release.json').write_text(json.dumps(bad))
                with self.assertRaisesRegex(ValueError,'release identity'):build.helper_inputs(args,root)

    def test_dynamic_providers_require_all_exact_function_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk=Path(directory);(sdk/'target/lib').mkdir(parents=True)
            providers={}
            for name,calls in build.DYNAMIC_FUNCTIONS.items():
                leaf=(build.PROVIDERS|build.DYNAMIC_PROVIDERS)[name]
                (sdk/'target/lib'/leaf).write_bytes(('inert '+name).encode())
                providers[leaf]={'soname':name,'definitions':{call:'FUNC' for call in calls}}
            def inspect(path,*unused):return providers[path.name]
            with patch.object(build,'provider',side_effect=inspect):
                result=build.dynamic_inputs(sdk,Path('/inert'),None)
                self.assertFalse(result['runtime_validated']);self.assertEqual(result['net_internal_id'],'0x8000001c')
                self.assertEqual(result['sysmodule_acquisition'],'static-imports')
                self.assertNotIn('sysmodule_path',result)
                self.assertEqual({name:item['binding'] for name,item in result['providers'].items()},
                    {'libkernel.sprx':'static','libSceSysmodule.sprx':'static','libSceNet.sprx':'dynamic'})
                for name,calls in build.DYNAMIC_FUNCTIONS.items():
                    leaf=(build.PROVIDERS|build.DYNAMIC_PROVIDERS)[name]
                    for call in calls:
                        providers[leaf]['definitions'][call]='OBJECT'
                        with self.subTest(call=call),self.assertRaises(ValueError):build.dynamic_inputs(sdk,Path('/inert'),None)
                        providers[leaf]['definitions'][call]='FUNC'
                    providers[leaf]['soname']='wrong'
                    with self.assertRaises(ValueError):build.dynamic_inputs(sdk,Path('/inert'),None)
                    providers[leaf]['soname']=name

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
        bound={'runtime': {'private_dispatch_abi':1, 'private_dispatch_wow64_abi':1,
                           'ntdll_sha256':'b'*64}, 'helper': {'elf': {'sha256': build.HELPER_SHA}}}
        text=build.child_header(bound,'a'*40)
        self.assertIn('#define PW_WINE_CHILD_WOW64_ABI 1\n',text)
        self.assertIn('b'*64,text)
        self.assertIn(build.HELPER_SHA,text)
        wrong=copy.deepcopy(bound);wrong['helper']['elf']['sha256']='0'*64
        with self.assertRaises(ValueError):build.child_header(wrong,'a'*40)
        for name in ('private_dispatch_abi','private_dispatch_wow64_abi'):
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

    def test_valid_bound_static_net_imports_are_refused(self):
        for name in build.DYNAMIC_FUNCTIONS['libSceNet.sprx']:
            linked,converted,providers=fixture()
            self.add_import(linked,converted,providers,name,'libkernel.sprx')
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'dynamically resolved calls'):
                build.ordinary_graph(linked,converted,providers)

    def test_sysmodule_import_set_is_exact(self):
        linked,converted,providers=fixture()
        self.add_import(linked,converted,providers,'sceSysmoduleUnloadModuleInternal','libSceSysmodule.sprx')
        with self.assertRaisesRegex(ValueError,'exactly two static Sysmodule imports'):
            build.ordinary_graph(linked,converted,providers)
        for name in build.SYSMODULE_FUNCTIONS:
            linked,converted,providers=fixture()
            providers['libkernel.sprx']['definitions'][name]='FUNC'
            index=next(i for i,s in enumerate(linked.symbols) if s.get('name')==name)
            converted.symbols[index]['name']=nid(name)+'#B#C'
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'lifecycle'):
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
                  ('libSceLibcInternal.so','libkernel.so','libSceSysmodule.so')]
        self.assertEqual(list(calls[0][-3:]),expected)
        self.assertEqual([calls[1][i+1] for i,arg in enumerate(calls[1]) if arg=='--stub'],expected)

    def test_wrong_provider_set(self):
        linked, converted, providers = fixture()
        linked.needed.append('libkernel_web.sprx')
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
