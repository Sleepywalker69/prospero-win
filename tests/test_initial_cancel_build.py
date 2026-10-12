#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Inert build-plan/static-admission mutations; never invoke target compilers."""
import copy
import hashlib
import importlib
from pathlib import Path
import sys
import shutil
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import build_initial_cancel as title


class Arrays:
    def __init__(self, tags):
        self.tags = tags

    def has(self, tag):
        return tag in self.tags

    def tag(self, tag):
        return self.tags[tag]


class IsolatedPlan(unittest.TestCase):
    def setUp(self):
        self.project = {'commit': '1' * 40, 'tree': '2' * 40}
        self.bound = {'project': self.project, 'helper': {'project': self.project,
            'elf': {'sha256': 'a' * 64}, 'toolchain_reverified': True, 'runtime_validated': False}}
        self.paths = {name: '/inert/' + name.lower() for name in
                      ('REPO', 'SDK', 'FOUNDATION', 'TITLE', 'LLVM', 'LLVM_CONFIG', 'ZROOT', 'ZLIB', 'HELPER')}
        self.out = Path('/inert/fresh-output')

    def test_exact_units_crt_and_actual_verified_digest(self):
        identity, plan = title.command_plan(self.bound, self.paths, self.out)
        self.assertEqual(len(plan), 10)
        compiled = [c[c.index('-c') + 1] for c in plan if '-c' in c]
        self.assertEqual(compiled, ['/inert/repo/' + unit for unit in title.UNITS] +
                         ['/inert/title/tooling/native/app_crt.cpp'])
        self.assertFalse(any('wine64_main' in arg or 'fetch_lapy_helper' in arg for c in plan for arg in c))
        self.assertEqual(sum('-DPW_LAPY_INITIAL_CANCEL_ONLY=1' in c for c in plan), 4)
        self.assertEqual(sum('-DPW_LAPY_HELPER_SHA256="' + 'a' * 64 + '"' in c for c in plan), 4)
        self.assertEqual(sum('-DPW_BUILD_ID="' + identity + '"' in c for c in plan), 4)
        self.assertIn('-z', plan[6]); self.assertIn('defs', plan[6])
        self.assertTrue(all('--no-default-config' in c for c in plan[:6]))
        self.assertIn('/inert/title/tooling/native/sce_module_writer.cpp', plan[7])
        self.assertFalse(any('service.cpp' in arg for c in plan for arg in c))

    def test_source_cohort_or_unverified_helper_refused(self):
        for key, value in [('project', {'commit': '3' * 40}), ('toolchain_reverified', False),
                           ('runtime_validated', True), ('elf', {'sha256': 'unbuilt-placeholder'})]:
            bound = copy.deepcopy(self.bound); bound['helper'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                title.command_plan(bound, self.paths, self.out)

    def test_digest_and_source_changes_change_compiled_identity(self):
        first, before = title.command_plan(self.bound, self.paths, self.out)
        changed = copy.deepcopy(self.bound); changed['helper']['elf']['sha256'] = 'b' * 64
        after, commands = title.command_plan(changed, self.paths, self.out)
        self.assertNotEqual(first, after)
        self.assertNotEqual(before[1], commands[1])
        self.assertIn('-DPW_LAPY_HELPER_SHA256="' + 'b' * 64 + '"', commands[1])

    def test_environment_is_explicit_and_no_ambient_include_inputs(self):
        with patch.dict(title.os.environ, {'CPATH': '/unexpected', 'LIBRARY_PATH': '/unexpected'}):
            _, plan = title.command_plan(self.bound, self.paths, self.out)
        self.assertEqual(plan[1][:3], ['env', '-i', 'PATH=/usr/bin:/bin'])
        self.assertFalse(any('/unexpected' in arg for c in plan for arg in c))

    def test_nonempty_constructor_arrays_refused(self):
        title.validate_constructor_arrays([Arrays({}), Arrays({27: 0, 28: 0, 33: 0})])
        for tag in (27, 28, 33):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                title.validate_constructor_arrays([Arrays({tag: 8})])

    def map_bytes(self):
        objects = [self.out / 'obj/app_crt.o'] + [self.out / 'obj' /
                    (unit.replace('/', '_') + '.o') for unit in title.UNITS]
        return ''.join('100 100 20 16 ' + str(obj) + ':(.text)\n' for obj in objects).encode()

    def test_exact_link_map_and_foreign_or_missing_object_mutations(self):
        original = self.map_bytes()
        title.validate_link_map(original, self.out)
        for changed in [original + b'100 /foreign/wine64_main.o:(.text)\n',
                        b'\n'.join(original.splitlines()[1:]),
                        original.replace(b'app_crt.o', b'replacement_crt.o')]:
            with self.subTest(changed=changed[:40]), self.assertRaises(ValueError):
                title.validate_link_map(changed, self.out)


class StdioImportContract(unittest.TestCase):
    def fixture(self):
        # Reuse original inert import/relocation mappings, not target binaries.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import test_wine_service_child_build as service
        linked, converted, providers = service.fixture()
        for index in reversed(range(1,len(linked.symbols))):
            if linked.symbols[index]['name'] in title.FORBIDDEN:
                for image in (linked,converted):
                    image.symbols.pop(index)
                    image.relocations=[r for r in image.relocations if r['symbol']!=index]
                    for relocation in image.relocations:
                        if relocation['symbol']>index:relocation['symbol']-=1
        exports = {}
        for name in sorted(title.STDIO_POINTERS):
            index = len(linked.symbols)
            symbol = {'name':name,'type':1,'binding':1,'visibility':0,'section':0,'value':0,'size':0}
            linked.symbols.append(symbol)
            converted.symbols.append(dict(symbol,name=service.nid(name)+'#A#B'))
            relocation = {'address':max(r['address'] for r in linked.relocations)+8,'symbol':index,'type':6,'addend':0}
            linked.relocations.append(relocation); converted.relocations.append(dict(relocation))
            providers[title.STDIO_PROVIDER]['definitions'][name] = 'OBJECT'
            exports[name] = dict(symbol,section=5,value=0x3269c)
        return linked, converted, providers, exports

    def test_exact_stdio_pointers_and_existing_function_contract(self):
        inputs = self.fixture(); graph = title.inspect_import_contract(*inputs)
        for name in title.STDIO_POINTERS:
            self.assertEqual(graph[name]['provider'],title.STDIO_PROVIDER)
            self.assertEqual(len(graph[name]['relocations']),1)
        self.assertIn('_init_env',graph)

    def test_import_export_and_converter_mutations_refused(self):
        import test_wine_service_child_build as service
        for name in sorted(title.STDIO_POINTERS):
            for field,values in [('type',[0,2,6]),('binding',[0,2]),('visibility',[1,2,3]),
                                 ('section',[1]),('value',[1]),('size',[8])]:
                for value in values:
                    linked,converted,providers,exports=self.fixture()
                    index=next(i for i,s in enumerate(linked.symbols) if s.get('name')==name)
                    linked.symbols[index][field]=converted.symbols[index][field]=value
                    with self.subTest(name=name,field=field,value=value),self.assertRaises(ValueError):
                        title.inspect_import_contract(linked,converted,providers,exports)
            for field,value in [('name','other'),('type',2),('binding',2),('visibility',3),('section',0),('section',0xfff1),('section',0xffff),('size',8)]:
                linked,converted,providers,exports=self.fixture();exports[name][field]=value
                with self.subTest(export=field),self.assertRaises(ValueError):
                    title.inspect_import_contract(linked,converted,providers,exports)
            linked,converted,providers,exports=self.fixture()
            index=next(i for i,s in enumerate(linked.symbols) if s.get('name')==name)
            providers[title.STDIO_PROVIDER]['definitions'].pop(name)
            providers['libkernel.sprx']['definitions'][name]='OBJECT'
            converted.symbols[index]['name']=service.nid(name)+'#B#C'
            with self.assertRaisesRegex(ValueError,'stdio pointer contract'):
                title.inspect_import_contract(linked,converted,providers,exports)
            linked,converted,providers,exports=self.fixture()
            index=next(i for i,s in enumerate(linked.symbols) if s.get('name')==name)
            converted.symbols[index]['type']=2
            with self.assertRaisesRegex(ValueError,'conversion changed'):
                title.inspect_import_contract(linked,converted,providers,exports)
        linked,converted,providers,exports=self.fixture()
        linked.symbols[1]['type']=converted.symbols[1]['type']=1
        providers[title.STDIO_PROVIDER]['definitions'][linked.symbols[1]['name']]='OBJECT'
        with self.assertRaisesRegex(ValueError,'import type'):
            title.inspect_import_contract(linked,converted,providers,exports)

    def test_stdio_relocation_mutations_refused(self):
        for name in sorted(title.STDIO_POINTERS):
            for mutation in ('missing','duplicate','plt','copy','relative','addend','unaligned','unmapped','alias','local-alias','partial-overlap'):
                linked,converted,providers,exports=self.fixture()
                index=next(i for i,s in enumerate(linked.symbols) if s.get('name')==name)
                for image in (linked,converted):
                    reloc=next(r for r in image.relocations if r['symbol']==index)
                    if mutation=='missing': image.relocations.remove(reloc)
                    elif mutation=='duplicate': image.relocations.append(dict(reloc))
                    elif mutation in ('plt','copy','relative'): reloc['type']={'plt':7,'copy':5,'relative':8}[mutation]
                    elif mutation=='addend': reloc['addend']=8
                    elif mutation=='unaligned': reloc['address']+=1
                    elif mutation=='unmapped': reloc['address']=0x2000
                    elif mutation=='alias': reloc['address']=image.relocations[0]['address']
                    elif mutation in ('local-alias','partial-overlap'):
                        image.relocations.append(dict(reloc,symbol=0,type=8,address=reloc['address']+(4 if mutation=='partial-overlap' else 0)))
                with self.subTest(name=name,mutation=mutation),self.assertRaises(ValueError):
                    title.inspect_import_contract(linked,converted,providers,exports)
            for side in (0,1):
                inputs=self.fixture()
                with patch.object(inputs[side],'offset',side_effect=ValueError('not writable')):
                    with self.assertRaisesRegex(ValueError,'not writable'):
                        title.inspect_import_contract(*inputs)

    def test_provider_hash_and_unique_exports(self):
        from types import SimpleNamespace
        data=b'inert provider';record={'sha256':hashlib.sha256(data).hexdigest()}
        exports=self.fixture()[3];symbols=list(exports.values())
        with patch.object(title,'Elf',return_value=SimpleNamespace(symbols=symbols)):
            self.assertEqual(title.inspect_stdio_exports(data,record),exports)
            with self.assertRaisesRegex(ValueError,'provider changed'):
                title.inspect_stdio_exports(data+b'changed',record)
        for changed in (symbols[:1],symbols+symbols[:1]):
            with patch.object(title,'Elf',return_value=SimpleNamespace(symbols=changed)):
                with self.assertRaisesRegex(ValueError,'ambiguous'):
                    title.inspect_stdio_exports(data,record)


class MockedBuildReceipt(unittest.TestCase):
    """All producer inputs, compiler/converter calls and ELF inspection are inert."""
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='pw-inert-title-receipt-')
        self.addCleanup(temp.cleanup)
        base = Path(temp.name)
        self.repo, self.sdk, self.foundation, self.helper = [base / name for name in
                                                           ('repo', 'sdk', 'foundation', 'helper')]
        for path in (self.repo, self.sdk, self.foundation, self.helper): path.mkdir()
        self.out = base / 'fresh-output'
        self.paths = {name: str(base / name.lower()) for name in
                      ('REPO', 'SDK', 'FOUNDATION', 'TITLE', 'LLVM', 'LLVM_CONFIG', 'ZROOT', 'ZLIB', 'HELPER')}
        runtime = Path(self.paths['TITLE']) / 'runtime'; runtime.mkdir(parents=True)
        (runtime / 'libc.prx').write_bytes(b'inert libc fixture, never loaded')
        for name in title.helper.OUTPUTS: (self.helper / name).write_bytes(b'inert fixture ' + name.encode())
        project = {'commit': '1' * 40, 'tree': '2' * 40}
        self.bound = {'project': project, 'helper': {'project': project,
            'elf': title.helper.record(self.helper / 'lapy.elf'),
            'toolchain_reverified': True, 'runtime_validated': False}}
        self.calls = []
        calls = self.calls
        def fake_run(recorder, *args):
            argv = [str(arg) for arg in args]; calls.append(argv); output = ''
            if '-dM' in argv:
                output = '#define __PROSPERO__ 1\n#define __FreeBSD__ 1\n#define __x86_64__ 1\n'
            elif '-c' in argv:
                Path(argv[argv.index('-o') + 1]).write_bytes(b'inert object ' + argv[argv.index('-c') + 1].encode())
            elif any(arg.startswith('-Map=') for arg in argv):
                Path(argv[argv.index('-o') + 1]).write_bytes(b'inert linked image, never run')
                objects = [arg for arg in argv if arg.endswith('.o')]
                path = Path(next(arg[5:] for arg in argv if arg.startswith('-Map=')))
                path.write_text(''.join('100 100 20 16 ' + obj + ':(.text)\n' for obj in objects))
            elif argv[0].endswith('/ps5-native-tool'):
                Path(argv[argv.index('--out') + 1]).write_bytes(b'inert converted fixture ' + argv[1].encode())
            elif '-o' in argv:
                Path(argv[argv.index('-o') + 1]).write_bytes(b'inert converter placeholder, never run')
            recorder.records.append({'argv': argv, 'exit': 0, 'output': output, 'environment': title.COMMAND_ENV})
            return output
        def fake_inspect(directory, sdk, bindir, identity, helper_sha, recorder):
            recorder.run(bindir / 'llvm-readelf', '-sW', directory / 'title.linked.elf')
            recovered = directory / 'title.recovered.elf'
            if not recovered.exists(): recovered.write_bytes(b'inert recovered fixture')
            return {'runtime_validated': False, 'inert': True}
        for patcher in (patch.object(title, 'title_inputs', return_value=(self.bound, self.paths)),
                        patch.object(title.Commands, 'run', fake_run),
                        patch.object(title, 'inspect_title', side_effect=fake_inspect)):
            patcher.start(); self.addCleanup(patcher.stop)
        self.result = title.build_title(self.repo, self.sdk, self.foundation, self.helper, self.out)

    def manifest(self):
        return title.helper.read_json(self.out / 'initial-cancel-build.json', output=True)

    def write(self, value):
        (self.out / 'initial-cancel-build.json').write_bytes(title.helper.canonical(value))

    def verify(self, output=None):
        return title.verify_title(self.repo, self.sdk, self.foundation, self.helper, output or self.out)

    def test_complete_mocked_receipt_is_static_only_and_repeatable(self):
        self.assertTrue(self.result['static_build_verified'])
        self.assertFalse(self.result['target_ready'])
        self.assertFalse(self.result['no_reboot_lifecycle_verified'])
        self.assertEqual(self.verify()['title'], self.result['title'])

    def test_extra_payload_execution_record_and_substituted_analyzer_rejected(self):
        original = self.manifest()
        extra = copy.deepcopy(original)
        extra['commands'].append({'argv': ['/inert/payload'], 'exit': 0, 'output': '', 'environment': title.COMMAND_ENV})
        self.write(extra)
        with self.assertRaises(ValueError): self.verify()
        changed = copy.deepcopy(original); changed['commands'][-1]['argv'][0] = '/unreviewed/llvm-readelf'
        self.write(changed)
        with self.assertRaises(ValueError): self.verify()
        self.assertFalse(any(argv[0] in ('/inert/payload', '/unreviewed/llvm-readelf') for argv in self.calls))

    def test_coordinated_tool_path_rewrite_rejected_before_any_inspection(self):
        changed = self.manifest(); old = changed['build_paths']['LLVM']
        changed['build_paths']['LLVM'] = '/unreviewed'
        for command in changed['commands']:
            command['argv'] = [arg.replace(old, '/unreviewed') for arg in command['argv']]
        self.write(changed); before = len(self.calls)
        with self.assertRaises(ValueError): self.verify()
        self.assertEqual(len(self.calls), before)

    def test_rehashed_helper_swap_or_ready_claim_rejected(self):
        original = self.manifest(); changed = copy.deepcopy(original); changed['target_ready'] = True
        self.write(changed)
        with self.assertRaises(ValueError): self.verify()
        self.write(original); (self.out / 'lapy.elf').write_bytes(b'changed inert helper')
        changed = copy.deepcopy(original); changed['artifacts']['lapy.elf'] = title.helper.record(self.out / 'lapy.elf')
        self.write(changed)
        with self.assertRaises(ValueError): self.verify()

    def test_output_archive_relocation_preserves_bound_inputs_and_tail(self):
        relocated = self.out.parent / 'relocated-output'; shutil.copytree(self.out, relocated)
        self.assertEqual(self.verify(relocated)['title'], self.result['title'])


if __name__ == '__main__':
    unittest.main()
