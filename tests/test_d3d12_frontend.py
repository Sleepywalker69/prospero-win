#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original inert PE-byte and producer-command controls; never execute a PE."""
from pathlib import Path
import io
import copy
import json
import os
import shutil
import stat
import subprocess
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import yaml

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import build_d3d12_frontend as build
import check_d3d12_frontend as check


def inert_image(name):
    data = bytearray(0x2600); data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 0x80); data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664, 3, 0, 0, 0, 240,
                     0x2022 if name.endswith('.dll') else 0x22)
    op = 0x98
    struct.pack_into('<H', data, op, 0x20b)
    struct.pack_into('<I', data, op + 16, 0x4000)
    struct.pack_into('<I', data, op + 56, 0x6000)
    struct.pack_into('<I', data, op + 60, 0x200)
    struct.pack_into('<HH', data, op + 68, 3, 0x160)
    struct.pack_into('<I', data, op + 108, 16)
    for i, (label, address, size, raw, flags) in enumerate((
        (b'.rdata', 0x1000, 0x2000, 0x200, 0x40000040),
        (b'.text', 0x4000, 0x200, 0x2200, 0x60000020),
        (b'.reloc', 0x5000, 0x200, 0x2400, 0x42000040))):
        section = op + 240 + i * 40
        data[section:section + 8] = label.ljust(8, b'\0')
        struct.pack_into('<IIII', data, section + 8, size, address, size, raw)
        struct.pack_into('<I', data, section + 36, flags)
    data[0x2200] = 0xc3  # Inert parser input; these bytes are never loaded.
    cursor = 0x1100
    def put(address, fmt, *values):
        struct.pack_into(fmt, data, address - 0x1000 + 0x200, *values)
    def emit(raw, alignment=1):
        nonlocal cursor
        cursor = (cursor + alignment - 1) & -alignment
        address = cursor; cursor += len(raw)
        data[address - 0x1000 + 0x200:cursor - 0x1000 + 0x200] = raw
        return address
    exports = sorted(check.REQUIRED_EXPORTS.get(name, set()))
    if name == 'd3d12core.dll':
        exports.append('D3D12SDKVersion')
    if exports:
        struct.pack_into('<II', data, op + 112, 0x1000, 0x600)
        put(0x1000, '<IIHHIIIIIII', 0, 0, 0, 0, 0, 1, len(exports), len(exports), 0x1040, 0x1080, 0x10c0)
        for i, symbol in enumerate(exports):
            put(0x1040 + i * 4, '<I', 0x1800 if symbol == 'D3D12SDKVersion' else 0x4000)
            put(0x1080 + i * 4, '<I', emit(symbol.encode() + b'\0'))
            put(0x10c0 + i * 2, '<H', i)
        put(0x1800, '<I', 614)
    imports = sorted(check.QUERY_IMPORTS) if name.endswith('.exe') else [('kernel32.dll', 'CloseHandle')]
    libraries = sorted({dll for dll, _ in imports})
    struct.pack_into('<II', data, op + 120, 0x2000, (len(libraries) + 1) * 20)
    cursor = 0x2080
    for i, dll in enumerate(libraries):
        dll_rva = emit(dll.encode() + b'\0')
        names = [emit(b'\0\0' + symbol.encode() + b'\0', 2) for library, symbol in imports if library == dll]
        thunk = emit(b''.join(struct.pack('<Q', address) for address in names) + b'\0' * 8, 8)
        put(0x2000 + i * 20, '<IIIII', thunk, 0, 0, dll_rva, thunk)
    struct.pack_into('<II', data, op + 112 + 5 * 8, 0x5000, 12)
    struct.pack_into('<IIHH', data, 0x2400, 0x4000, 12, 0xa008, 0)
    return data


class FrontendTests(unittest.TestCase):
    def test_actual_byte_candidate_scope_stays_build_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp)
            for name in check.NAMES:
                (app / name).write_bytes(inert_image(name))
            report = check.inspect_candidate(app)
            self.assertTrue(report['pe_link_verified'])
            self.assertFalse(report['pe_import_graph_verified'])
            self.assertFalse(report['runtime_verified'])
            self.assertFalse(report['console_package_approved'])
            self.assertEqual(report['files']['d3d12core.dll']['sdk_version_data'], 614)
            (app / 'extra.dll').write_bytes(b'not silently ignored')
            with self.assertRaisesRegex(ValueError, 'membership'):
                check.inspect_candidate(app)

    def test_wrong_headers_relocations_imports_and_data_exports_fail(self):
        edits = {
            'wrong architecture': lambda b: struct.pack_into('<H', b, 0x84, 0x14c),
            'COFF not PE': lambda b: b.__setitem__(slice(0, 2), b'XX'),
            'relocations stripped': lambda b: struct.pack_into('<H', b, 0x96, 0x2023),
            'ASLR missing': lambda b: struct.pack_into('<H', b, 0x98 + 70, 0x120),
            'NX missing': lambda b: struct.pack_into('<H', b, 0x98 + 70, 0x60),
            'high entropy missing': lambda b: struct.pack_into('<H', b, 0x98 + 70, 0x140),
            'empty relocations': lambda b: struct.pack_into('<II', b, 0x98 + 152, 0, 0),
            'padding only': lambda b: struct.pack_into('<H', b, 0x2408, 0),
            'relocation type': lambda b: struct.pack_into('<H', b, 0x2408, 0x3008),
            'relocation extent': lambda b: struct.pack_into('<I', b, 0x2404, 100),
            'relocation target': lambda b: struct.pack_into('<I', b, 0x2400, 0x6000),
            'SDKVersion wrong value': lambda b: struct.pack_into('<I', b, 0xa00, 613),
            'SDKVersion is code': lambda b: struct.pack_into('<I', b, 0x244, 0x4000),
            'SDKVersion unmapped': lambda b: struct.pack_into('<I', b, 0x244, 0x6000),
            'unexpected CRT DLL': lambda b: b.__setitem__(slice(b.index(b'kernel32.dll'), b.index(b'kernel32.dll') + 12), b'ucrtbase.dll'),
            'truncated image': lambda b: b.__delitem__(slice(0x2400, None)),
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'd3d12core.dll'
            for label, edit in edits.items():
                data = inert_image(path.name); edit(data); path.write_bytes(data)
                with self.subTest(label=label), self.assertRaises(ValueError):
                    check.inspect_image(path)

    def test_required_query_import_and_sdk_forwarder_are_not_assumed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'd3d12-capability-query.exe'
            data = inert_image(path.name); start = data.index(b'D3D12CreateDevice'); data[start] = ord('X')
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'query API'):
                check.inspect_image(path)
            path = Path(tmp) / 'd3d12core.dll'; data = inert_image(path.name)
            struct.pack_into('<I', data, 0x244, 0x1500)
            forward = b'other.SDKVersion\0'
            data[0x700:0x700 + len(forward)] = forward
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'data export'):
                check.inspect_image(path)

    def test_builder_commands_link_real_exe_without_running_it(self):
        commands = build.commands(Path('/prepared-source'), Path('/new-output'))
        self.assertEqual(len(commands), 3)
        self.assertEqual([command[0] for command in commands], ['meson', 'ninja', 'x86_64-w64-mingw32-gcc-posix'])
        for flag in ('-Denable_tests=false', '-Denable_extras=false', '-Denable_dxilconv=false', '--wrap-mode=nodownload'):
            self.assertIn(flag, commands[0])
        self.assertIn('-j2', commands[1])
        for flag in ('-Wall', '-Wextra', '-Werror', '-static', '-static-libgcc', '-ld3d12', '-ldxgi', '-ldxguid'):
            self.assertIn(flag, commands[2])
        self.assertIn('--enable-reloc-section', ' '.join(commands[2]))
        self.assertTrue(commands[2][-1].endswith('/app/d3d12-capability-query.exe'))
        for name, digest in build.FIXTURES.items():
            self.assertEqual(build.sha(ROOT / 'tests/fixtures' / name), digest)
        self.assertEqual(build.sha(ROOT / 'tools/inspect_graphics_pe.py'), build.PE_INSPECTOR_SHA)

    def test_actual_glslang_wrapper_precedes_competing_inherited_path(self):
        # Only original tiny host scripts execute here, never a shader compiler.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); chosen = root / 'chosen'; other = root / 'other'; work = root / 'work'
            chosen.mkdir(); other.mkdir(); work.mkdir()
            selected = {}
            for name in set(build.TOOL_ALIASES.values()):
                path = chosen / name; path.write_text('#!/bin/sh\nprintf "selected-provider\\n"\n'); path.chmod(0o755)
                selected[name] = str(path.resolve())
            wrong = other / 'glslang'; wrong.write_text('#!/bin/sh\nprintf "wrong-provider\\n"\n'); wrong.chmod(0o755)
            with patch.dict(os.environ, {'PATH': str(other)}, clear=False):
                env = build.build_environment(work, selected)
            actual = shutil.which('glslang', path=env['PATH'])
            self.assertEqual(Path(actual).resolve(), Path(selected['glslangValidator']))
            result = subprocess.run(['glslang'], env=env, text=True, capture_output=True, check=True)
            self.assertEqual(result.stdout, 'selected-provider\n')
            self.assertEqual(env['PATH'].split(os.pathsep)[0], str(work / 'tools'))

    def test_source_pins_cleanliness_and_nested_membership_are_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for relative in build.SOURCES:
                (root / relative).mkdir(parents=True, exist_ok=True)
            problem = {'kind': None}
            def git(path, *args):
                relative = str(path.relative_to(root))
                relative = '' if relative == '.' else relative
                if args == ('rev-parse', '--show-toplevel'):
                    return str(path)
                if args == ('rev-parse', 'HEAD'):
                    return '0' * 40 if problem['kind'] == 'pin' else build.SOURCES[relative][1]
                if args[0] == 'status':
                    return '?? untracked-input' if problem['kind'] == 'dirty' else ''
                expected = {}
                if not relative:
                    expected = {name: value[1] for name, value in build.SOURCES.items()
                                if name and not name.startswith('subprojects/dxil-spirv/')}
                elif relative == 'subprojects/dxil-spirv':
                    expected = dict(build.UNUSED_DXIL_GITLINKS)
                    expected['third_party/spirv-headers'] = build.SOURCES[relative + '/third_party/spirv-headers'][1]
                if problem['kind'] == 'dependency':
                    expected['unexpected'] = '0' * 40
                return '\n'.join('160000 commit ' + pin + '\t' + name for name, pin in expected.items())
            with patch.object(build, 'git', git):
                build.verify_sources(root)
                for kind in ('pin', 'dirty', 'dependency'):
                    problem['kind'] = kind
                    with self.subTest(kind=kind), self.assertRaises(ValueError):
                        build.verify_sources(root)
                problem['kind'] = None
                unused = root / 'subprojects/dxil-spirv/third_party/SPIRV-Tools'
                unused.mkdir(); (unused / 'unexpected.c').write_text('original test input')
                with self.assertRaisesRegex(ValueError, 'must remain empty'):
                    build.verify_sources(root)

    def test_source_archive_cannot_silently_omit_license_or_build_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'source.tar'
            listing = '100644 blob ' + '1' * 40 + '\tLICENSE\n100644 blob ' + '2' * 40 + '\tmeson.build'
            for names in (('LICENSE', 'meson.build'), ('meson.build',), ('LICENSE', 'meson.build', 'extra')):
                with tarfile.open(path, 'w') as archive:
                    for name in names:
                        record = tarfile.TarInfo(name); record.size = 1
                        archive.addfile(record, io.BytesIO(b'x'))
                with patch.object(build, 'git', return_value=listing):
                    if len(names) == 2:
                        build.verify_archive(Path(tmp), path)
                    else:
                        with self.subTest(names=names), self.assertRaisesRegex(ValueError, 'tracked blobs'):
                            build.verify_archive(Path(tmp), path)

    def test_fetch_commands_are_exact_public_pins_without_recursive_downloads(self):
        for relative, (repository, pin) in build.SOURCES.items():
            commands = build.checkout_commands(Path('/new-checkout') / relative, repository, pin)
            self.assertEqual(len(commands), 4)
            self.assertEqual(commands[1][-1], 'https://github.com/' + repository + '.git')
            self.assertEqual(commands[2][-4:], ['fetch', '--depth=1', 'origin', pin])
            self.assertNotIn('--recursive', str(commands))
        source = (ROOT / 'tools/build_d3d12_frontend.py').read_text()
        for name in ('LICENSE', 'NOTICE.md', 'THIRD_PARTY.md', 'project.tar'):
            self.assertIn(name, source)
        self.assertIn("'tree': git(ROOT, 'rev-parse', 'HEAD^{tree}')", source)
        self.assertLess(source.index('verify_checkpoint(work)', source.index('def build(')),
                        source.index('subprocess.run(argv', source.index('def build(')))
        self.assertGreater(source.rindex('verify_checkpoint(work)'), source.index('subprocess.run(argv', source.index('def build(')))

    def test_checkpoint_rejects_changed_project_source_tool_and_runtime_bindings(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); sources = work / 'sources'; sources.mkdir()
            (sources / 'fixture').mkdir(); (sources / 'compiler-runtime').mkdir()
            for name in build.FIXTURES:
                shutil.copy2(ROOT / 'tests/fixtures' / name, sources / 'fixture' / name)
            tool = work / 'original-tool-bytes'; tool.write_bytes(b'original test metadata only')
            runtime = {'packages': {name: {} for name in build.RUNTIME_PACKAGES},
                       'libraries': {name: {'path': str(tool), 'sha256': build.sha(tool)} for name in build.RUNTIME_LIBRARIES}}
            (sources / 'compiler-runtime/PROVENANCE.json').write_text(json.dumps(runtime))
            (sources / 'project.tar').write_bytes(b'original archive-identity mock')
            upstream = {}
            for index, (relative, (repo, pin)) in enumerate(build.SOURCES.items()):
                archive = sources / ('upstream-' + str(index) + '.tar'); archive.write_bytes(relative.encode())
                upstream[relative] = {'repository': 'https://github.com/' + repo, 'commit': pin,
                                      'archive': archive.name, 'sha256': build.sha(archive)}
            value = {'schema': 'pw-d3d12-source-checkpoint/1', 'fixture': build.FIXTURES,
                     'unused_gitlinks': build.UNUSED_DXIL_GITLINKS, 'runtime_verified': False,
                     'project': {'commit': '1' * 40, 'tree': '2' * 40, 'archive': 'project.tar',
                                 'sha256': build.sha(sources / 'project.tar')},
                     'upstream': upstream, 'runtime': runtime,
                     'tools': {name: {'path': str(tool), 'sha256': build.sha(tool)} for name in build.TOOLS},
                     'source_files': build.source_inventory(sources, normalize=True)}
            def git(_path, *args):
                if args == ('rev-parse', 'HEAD'):
                    return '1' * 40
                if args == ('rev-parse', 'HEAD^{tree}'):
                    return '2' * 40
                return ''
            mutations = {
                'project archive': lambda v: v['project'].__setitem__('sha256', '0' * 64),
                'source pin': lambda v: v['upstream'][''].__setitem__('commit', '0' * 40),
                'tool bytes': lambda v: v['tools']['git'].__setitem__('sha256', '0' * 64),
                'runtime omitted': lambda v: v['runtime']['libraries'].pop('libwinpthread.a'),
                'project revision': lambda v: v['project'].__setitem__('tree', '0' * 40),
                'retained source omitted': lambda v: v['source_files'].pop('fixture/d3d12_capability_query.c'),
            }
            checkpoint = work / 'SOURCE-CHECKPOINT.json'; checkpoint.write_text(json.dumps(value))
            with patch.object(build, 'git', git), patch.object(build, 'verify_sources'), patch.object(build.shutil, 'which', return_value=str(tool)):
                build.verify_checkpoint(work)
                for label, mutate in mutations.items():
                    changed = copy.deepcopy(value); mutate(changed); checkpoint.write_text(json.dumps(changed))
                    with self.subTest(label=label), self.assertRaises(ValueError):
                        build.verify_checkpoint(work)

    def test_notice_mode_is_normalized_before_inventory_and_tar_data_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'sources'; source.mkdir()
            notice = source / 'LICENSE'; notice.write_text('original license-shaped test data\n'); notice.chmod(0o777)
            before = build.sha(notice)
            with self.assertRaisesRegex(ValueError, 'mode'):
                build.source_inventory(source)
            expected = build.source_inventory(source, normalize=True)
            self.assertEqual(build.sha(notice), before)
            self.assertEqual(stat.S_IMODE(notice.stat().st_mode), 0o644)
            archive = root / 'source.tar'
            with tarfile.open(archive, 'w') as value:
                value.add(source, arcname='sources')
            extracted = root / 'extracted'; extracted.mkdir()
            with tarfile.open(archive) as value:
                value.extractall(extracted, filter='data')
            self.assertEqual(build.source_inventory(extracted / 'sources'), expected)

    def test_workflow_is_opt_in_and_retains_source_before_any_compile(self):
        path = ROOT / '.github/workflows/d3d12-frontend.yml'
        workflow = yaml.safe_load(path.read_text())
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        job = workflow['jobs']['d3d12-frontend']
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertEqual(job['timeout-minutes'], 60)
        self.assertIn('head.repo.full_name == github.repository', job['if'])
        self.assertIn('build-d3d12-frontend', job['if'])
        steps = job['steps']
        source = next(i for i, step in enumerate(steps) if 'build_d3d12_frontend.py sources' in step.get('run', ''))
        compile_step = next(i for i, step in enumerate(steps) if 'build_d3d12_frontend.py build' in step.get('run', ''))
        retained = next(i for i, step in enumerate(steps) if step.get('with', {}).get('name', '').startswith('d3d12-source-checkpoint-'))
        self.assertLess(source, retained); self.assertLess(retained, compile_step)
        self.assertEqual(steps[compile_step]['timeout-minutes'], 35)
        self.assertEqual(steps[-1]['if'], '${{ always() }}')
        self.assertIn('/d3d12/sources/', steps[-1]['with']['path'])
        self.assertIn('/d3d12/app/', steps[-1]['with']['path'])
        self.assertIn('/d3d12/build/libs/d3d12/d3d12.dll', steps[-1]['with']['path'])
        self.assertIn('/d3d12/build/libs/d3d12core/d3d12core.dll', steps[-1]['with']['path'])
        for step in steps:
            if 'uses' in step:
                self.assertRegex(step['uses'], r'@[0-9a-f]{40}$')
            self.assertNotRegex(step.get('run', ''), r'(?m)^\s*(?:wine(?:64)?|wineserver)\s|(?:^|\n)\s*[^\n]*\.exe\s*$')
        self.assertFalse(steps[0]['with']['persist-credentials'])


if __name__ == '__main__':
    unittest.main()
