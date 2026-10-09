#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Pure metadata/command controls for the distinct full-CRT builder."""
import copy
from pathlib import Path
import sys
import tempfile
import types
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import build_wine_service_child as build
from native_probe_elf import nid


class Mapping:
    def offset(self, address, size, flags):
        if not (0x1000 <= address <= 0x1100 - size and flags == 6):
            raise ValueError('not a unique writable import slot')
        return address - 0x1000


def fixture():
    needed = ['libSceLibcInternal.sprx', 'libkernel.sprx']
    names = ['_init_env', 'atexit', 'exit', 'pthread_create']
    providers = {name: {'definitions': {}, 'sha256': str(i) * 64} for i, name in enumerate(needed, 1)}
    linked, converted = Mapping(), Mapping()
    linked.kind = 3; converted.kind = 0xfe10
    linked.needed = needed; converted.needed = [s.replace('.sprx', '.prx') for s in needed]
    converted.modules = {1: 'libSceLibcInternal', 2: 'libkernel'}
    converted.libraries = {0: 'libSceLibcInternal', 1: 'libkernel'}
    linked.symbols = [{}]; converted.symbols = [{}]
    linked.relocations = []; converted.relocations = []
    for index, name in enumerate(names, 1):
        provider = build.CRT_IMPORTS[name]; rank = needed.index(provider)
        providers[provider]['definitions'][name] = 'FUNC'
        symbol = {'name': name, 'type': 2, 'binding': 1, 'visibility': 0, 'section': 0, 'value': 0, 'size': 0}
        linked.symbols.append(symbol)
        converted.symbols.append({**symbol, 'name': nid(name) + '#' + 'AB'[rank] + '#' + 'BC'[rank]})
        relocation = {'symbol': index, 'type': 6, 'addend': 0, 'address': 0x1000 + index * 8}
        linked.relocations.append(relocation); converted.relocations.append(dict(relocation))
    return linked, converted, providers


class WineServiceChildBuild(unittest.TestCase):
    def test_generated_header_requires_both_actual_capabilities(self):
        bound={'runtime': {'private_dispatch_abi':1, 'private_dispatch_wow64_abi':1,
                           'ntdll_sha256':'b'*64}}
        text=build.child_header(bound,'a'*40)
        self.assertIn('#define PW_WINE_CHILD_WOW64_ABI 1\n',text)
        self.assertIn('b'*64,text)
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
