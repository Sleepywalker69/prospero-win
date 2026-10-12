#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Receipt controls on inert ELF/COFF fixtures; no SDK compilation or execution.

The actual recorder, object readers, verifier, collector, and JSON/hash helpers
are exercised. Only expensive external input discovery and process execution
are replaced. Fixture objects contain headers/data, never executable code.
Passing these tests is not evidence of a successful target compilation.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import check_focus_target_compile as target

BASE = (
    'dlls/ntdll/unix/creation.o', 'dlls/ntdll/unix/loader.o',
    'dlls/ntdll/unix/process.o', 'dlls/ntdll/unix/server.o',
    'dlls/ntdll/unix/signal_x86_64.o', 'dlls/ntdll/unix/thread.o',
    'dlls/ntdll/unix/virtual.o', 'dlls/wow64/x86_64-windows/syscall.o',
    'dlls/win32u/ps5drv.o', 'dlls/win32u/window.o',
    'dlls/win32u/winstation.o', 'dlls/win32u/syscall.o',
    'dlls/dnsapi/i386-windows/main.o', 'dlls/dnsapi/i386-windows/query.o',
    'dlls/dnsapi/x86_64-windows/main.o', 'dlls/dnsapi/x86_64-windows/query.o',
    'server/creation.o', 'server/trace.o', 'server/process.o',
    'server/ptrace.o', 'server/request.o', 'server/thread.o',
)
FOCUS = tuple('server/' + name + '.o' for name in
              ('pw_focus_core', 'pw_focus_requests', 'queue', 'window', 'winstation', 'user', 'main'))
SYNTAX = ('wine/ps5/pw_wine_fixture_provider.c', 'wine/ps5/pw_wine_fixture_socket.c',
          'wine/ps5/pw_wine_compat.c', 'native/pw_wine_child_data.c')
GENERATED = ('build/Makefile', 'build/include/config.h', 'build/.prospero-stamp',
             'configure.log', 'user-driver-compiler', 'user-driver-sdk-compiler')
RUNTIME_OUTPUTS = ('report.json', 'prx', 'install', 'prefix', 'native-wine-child.self', 'PPSA99995')
NO_RUNTIME_CLAIMS = ('complete_runtime', 'target_executed', 'runtime_validated', 'input_enabled',
                     'provider_enabled', 'native_entry_enabled', 'package_enabled',
                     'full_module_markers_verified', 'owner_worker_compiled', 'owner_worker_linked')
POLLUTED_ENV = ('PW_WINE_CACHED_CC', 'PW_CACHE_RESTORE_HIT', 'PW_CACHE_MATCHED_KEY',
                'CCACHE_DIR', 'CCACHE_CONFIGPATH', 'CCACHE_NAMESPACE', 'CC', 'CXX',
                'i386_CC', 'x86_64_CC', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS', 'CROSSCFLAGS',
                'i386_CFLAGS', 'x86_64_CFLAGS', 'PW_WINDOWS_CHROMIUM_IPC_DIR',
                'PW_WINE_CHILD_UI_ENABLED', 'PS5VK_SDK', 'PROSPERO_RADV',
                'PS5_OPENGL_SDK', 'PROSPERO_CA_BUNDLE', 'MAKEFLAGS', 'MFLAGS',
                'GNUMAKEFLAGS', 'BASH_ENV', 'ENV', 'CPATH', 'LIBRARY_PATH')


def elf_fixture(*, nobits=False):
    """ELF64 AMD64 ET_REL with a null section and an inert data/BSS section."""
    data = bytearray(196)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', data, 16, 1, 62, 1)
    struct.pack_into('<Q', data, 40, 64)
    struct.pack_into('<H', data, 52, 64)
    struct.pack_into('<HHH', data, 58, 64, 2, 0)
    struct.pack_into('<I', data, 128 + 4, 8 if nobits else 1)
    struct.pack_into('<QQ', data, 128 + 24, 1 << 20 if nobits else 192, 4096 if nobits else 4)
    data[192:] = b'DATA'
    return bytes(data)


def coff_fixture(machine=0x8664, *, bss=False):
    """One inert COFF data/BSS section, no optional header or executable code."""
    data = bytearray(60 if bss else 64)
    struct.pack_into('<HH', data, 0, machine, 1)
    data[20:28] = b'.bss\0\0\0\0' if bss else b'.data\0\0\0'
    struct.pack_into('<II', data, 36, 4096 if bss else 4, 0 if bss else 60)
    struct.pack_into('<I', data, 56, 0x80 if bss else 0x40)
    if not bss:
        data[60:] = b'DATA'
    return bytes(data)


def inert_object(name):
    if '-windows/' in name:
        return coff_fixture(0x14c if '/i386-windows/' in name else 0x8664)
    return elf_fixture()


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


class ObjectFormats(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='focus-format-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'inert.o'

    def read_object(self, data, name='server/creation.o'):
        self.path.write_bytes(data)
        return target.object_record(self.path, name)

    def test_real_parsers_accept_inert_relocatables_and_hash_bytes(self):
        for name, data, fmt in (
            ('server/creation.o', elf_fixture(), 'ELF64-AMD64-REL'),
            ('server/creation.o', elf_fixture(nobits=True), 'ELF64-AMD64-REL'),
            ('dlls/dnsapi/i386-windows/main.o', coff_fixture(0x14c), 'COFF-I386'),
            ('dlls/dnsapi/x86_64-windows/query.o', coff_fixture(), 'COFF-AMD64'),
            ('dlls/dnsapi/i386-windows/main.o', coff_fixture(0x14c, bss=True), 'COFF-I386'),
            ('dlls/dnsapi/x86_64-windows/query.o', coff_fixture(bss=True), 'COFF-AMD64'),
        ):
            with self.subTest(name=name, size=len(data)):
                got = self.read_object(data, name)
                self.assertEqual(got['format'], fmt)
                self.assertEqual(got['bytes'], len(data))
                self.assertEqual(got['sha256'], hashlib.sha256(data).hexdigest())

    def test_elf_rejects_wrong_architecture_type_and_truncated_tables(self):
        mutations = ((4, '<B', 1), (5, '<B', 2), (16, '<H', 2),
                     (18, '<H', 3), (20, '<I', 0), (52, '<H', 63),
                     (40, '<Q', 1), (40, '<Q', 192), (58, '<H', 32),
                     (60, '<H', 0), (62, '<H', 2),
                     (152, '<Q', 197), (160, '<Q', 5))
        for offset, fmt, value in mutations:
            with self.subTest(offset=offset, value=value):
                data = bytearray(elf_fixture())
                struct.pack_into(fmt, data, offset, value)
                with self.assertRaises(ValueError):
                    self.read_object(bytes(data))
        for data in (b'', b'\x7fELF', elf_fixture()[:100], b'not an object'):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                self.read_object(data)

    def test_coff_rejects_wrong_machine_optional_header_and_outside_sections(self):
        name = 'dlls/dnsapi/x86_64-windows/main.o'
        mutations = ((0, '<H', 0x14c), (2, '<H', 0), (2, '<H', 1025),
                     (16, '<H', 240), (36, '<I', 5), (40, '<I', 0),
                     (40, '<I', 59), (40, '<I', 65))
        for offset, fmt, value in mutations:
            with self.subTest(offset=offset, value=value):
                data = bytearray(coff_fixture())
                struct.pack_into(fmt, data, offset, value)
                with self.assertRaises(ValueError):
                    self.read_object(bytes(data), name)
        for data in (coff_fixture()[:19], coff_fixture()[:59], elf_fixture()):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                self.read_object(data, name)
        with self.assertRaises(ValueError):
            self.read_object(coff_fixture(), 'dlls/dnsapi/i386-windows/query.o')

    def test_coff_bss_allowance_does_not_accept_raw_data_without_a_pointer(self):
        data = bytearray(coff_fixture(bss=True))
        struct.pack_into('<I', data, 56, 0x40)
        with self.assertRaises(ValueError):
            self.read_object(bytes(data), 'dlls/wow64/x86_64-windows/syscall.o')
        data = bytearray(coff_fixture(bss=True))
        struct.pack_into('<I', data, 40, 60)
        with self.assertRaises(ValueError):
            self.read_object(bytes(data), 'dlls/wow64/x86_64-windows/syscall.o')

    def test_object_symlinks_and_directories_are_refused(self):
        other = self.path.with_name('ordinary.o')
        other.write_bytes(elf_fixture())
        self.path.symlink_to(other)
        with self.assertRaises(ValueError):
            target.object_record(self.path, 'server/creation.o')
        self.path.unlink()
        self.path.mkdir()
        with self.assertRaises(ValueError):
            target.object_record(self.path, 'server/creation.o')


class ReceiptControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='focus-receipts-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.serial = 0
        self.cohorts = {}
        self.cohort = {'project': {'commit': 'a' * 40, 'tree': 'b' * 40},
                       'tls': {'inputs': {'sources': {}}},
                       'build_compilers': {name: {'path': str(self.root / 'inert-tools' / name),
                                                  'bytes': 0, 'sha256': '0' * 64}
                                           for name in ('gcc', 'g++', 'i686-w64-mingw32-gcc',
                                                        'x86_64-w64-mingw32-gcc')},
                       'fixture': 'inert external-input boundary, not SDK provenance'}
        self.current = patch.object(target, 'current_inputs', side_effect=self.current_inputs)
        self.staged = patch.object(target, 'staged_inputs', side_effect=self.staged_inputs)
        self.current.start()
        self.staged.start()
        self.addCleanup(self.current.stop)
        self.addCleanup(self.staged.stop)

    def current_inputs(self, state):
        return copy.deepcopy(self.cohorts.get(state['paths']['out'], self.cohort))

    def staged_inputs(self, state):
        # Replace Git/SDK inspection at this boundary, while retaining actual
        # file hashes so source/configuration drift remains observable.
        work = Path(state['paths']['work'])
        names = [*GENERATED, *('source/' + name[:-2] + '.c' for name in FOCUS)]
        if state['neutral']:
            names += ['focus-neutral.json', 'source/include/wine/pw_focus_build.h']
        return {'inert_fixture': True, 'files': {name: target.record(work / name) for name in names}}

    def prepare_work(self, state):
        work = Path(state['paths']['work'])
        for name in GENERATED:
            put(work / name, 'inert fixture only: ' + name + '\n')
        for name in FOCUS:
            put(work / 'source' / (name[:-2] + '.c'), '/* inert source: ' + name + ' */\n')
        if state['neutral']:
            put(work / 'focus-neutral.json', '{}\n')
            put(work / 'source/include/wine/pw_focus_build.h', '/* inert generated header */\n')
        put(work / 'service-translation-units.log', 'inert subprocess fixture; no compiler invoked\n')
        write_json(work / 'compile-check-only.json', {
            'schema': 'pw-wine-build-stage/1', 'stage': 'target-translation-units', 'complete_runtime': False})

    def new_case(self, neutral=0):
        self.serial += 1
        case = self.root / ('case-' + str(self.serial))
        case.mkdir()
        paths = {'repo': str(ROOT)}
        for name in target.PATH_FIELDS:
            if name != 'repo':
                path = case / name
                path.mkdir()
                paths[name] = str(path)
        paths.update(work=str(case / 'work'), out=str(case / 'receipt'))
        state = {'schema': 'pw-focus-target-compile-inputs/1', 'neutral': neutral,
                 'jobs': 2, 'run_id': '123456', 'run_attempt': '2', 'paths': paths,
                 'cohort': copy.deepcopy(self.cohort)}
        self.cohorts[paths['out']] = copy.deepcopy(self.cohort)
        out = Path(paths['out'])
        out.mkdir()
        write_json(out / 'INPUTS.json', state)
        put(out / 'driver.log', 'inert subprocess fixture; no compiler invoked\n')
        self.prepare_work(state)
        return state

    def invoke_record(self, state, stage, *, argv=None, effect=None):
        command = target.expected_command(state, stage) if argv is None else argv
        def compile_fixture(actual, **kwargs):
            self.assertEqual(actual, command)
            self.assertEqual(kwargs, {'check': False, 'timeout': 1500})
            for name in target.objects(stage):
                put(Path(state['paths']['work']) / 'build' / name, inert_object(name))
            return subprocess.CompletedProcess(actual, 0)
        with patch.object(target.subprocess, 'run', side_effect=effect or compile_fixture) as invoked:
            target.command_record(argparse.Namespace(receipt=Path(state['paths']['out']),
                                                    stage=stage, command=['--', *command]))
        return invoked

    def complete(self, state):
        for stage in target.stages(state['neutral']):
            self.invoke_record(state, stage)
        out = Path(state['paths']['out'])
        write_json(out / 'DRIVER-RESULT.json', {'argv': target.driver_command(state), 'exit': 0,
                                              'selected_flags': target.selected_flags(state)})
        _, receipt = target.verify_work(out, finished=False)
        target.write_new(out / 'TARGET-COMPILE.json', receipt)
        self.assertEqual(target.verify_work(out)[1], receipt)
        return out, receipt

    def mutate(self, path, change):
        value = target.read(path)
        change(value)
        write_json(path, value)

    def assert_rejected(self, out, pattern=None, *, finished=True):
        error = self.assertRaisesRegex(ValueError, pattern) if pattern else self.assertRaises((ValueError, FileNotFoundError))
        with error:
            target.verify_work(out, finished=finished)

    def test_positive_both_modes_have_exact_objects_four_syntax_checks_and_no_runtime_claim(self):
        for neutral in (0, 1):
            with self.subTest(neutral=neutral):
                state = self.new_case(neutral)
                out, receipt = self.complete(state)
                self.assertEqual(set(receipt['objects']), set(BASE + (FOCUS if neutral else ())))
                self.assertEqual(len(receipt['objects']), 29 if neutral else 22)
                self.assertEqual(receipt['syntax_only_units'], list(SYNTAX))
                self.assertEqual([row['stage'] for row in receipt['commands']],
                                 ['service'] + (['focus'] if neutral else []) + ['syntax-' + str(i) for i in range(4)])
                self.assertEqual(sum(row['syntax_only'] for row in receipt['commands']), 4)
                self.assertEqual(receipt['protocol'], 963 if neutral else 962)
                self.assertIs(receipt['neutral'], bool(neutral))
                self.assertIs(type(receipt['focus_mode']), int)
                self.assertEqual(receipt['focus_mode'], neutral)
                self.assertNotIn('mode', receipt)
                self.assertIs(receipt['compile_only'], True)
                self.assertIs(receipt['compiler_cache_used'], False)
                for flag in NO_RUNTIME_CLAIMS:
                    self.assertIs(receipt[flag], False)
                self.assertEqual(receipt['selected_flags'], target.selected_flags(state))
                self.assertEqual(receipt['inputs'], target.record(out / 'INPUTS.json'))
                self.assertEqual(receipt['driver_result'], target.record(out / 'DRIVER-RESULT.json'))
                for row in receipt['commands']:
                    self.assertIs(row['objects_absent_before'], True)
                    self.assertEqual(row['exit'], 0)
                    if row['syntax_only']:
                        self.assertEqual(row['objects'], {})

    def test_focus_mode_is_typed_and_cross_bound_to_default_and_neutral(self):
        for neutral in (0, 1):
            state = self.new_case(neutral)
            out, _ = self.complete(state)
            path = out / 'TARGET-COMPILE.json'
            original = path.read_bytes()
            mutations = [lambda row: row.pop('focus_mode'),
                         lambda row: row.update(mode=1),
                         lambda row: row.update(focus_mode=1-neutral),
                         lambda row: row.update(focus_mode=bool(neutral)),
                         lambda row: row.update(focus_mode=float(neutral)),
                         lambda row: row.update(focus_mode=str(neutral)),
                         lambda row: row.update(protocol=962 if neutral else 963),
                         lambda row: row.update(neutral=not bool(neutral))]
            for i, mutate in enumerate(mutations):
                with self.subTest(neutral=neutral, mutation=i):
                    self.mutate(path, mutate)
                    self.assert_rejected(out, 'accepted compile receipt')
                    path.write_bytes(original)
            self.assertEqual(target.verify_work(out)[1]['focus_mode'], neutral)

    def test_expected_commands_force_source_rebuild_and_exact_targets(self):
        self.assertEqual(tuple(target.BASE_OBJECTS), BASE)
        self.assertEqual(tuple(target.FOCUS_OBJECTS), FOCUS)
        self.assertEqual(tuple(target.SYNTAX), SYNTAX)
        for neutral in (0, 1):
            state = self.new_case(neutral)
            service = target.expected_command(state, 'service')
            self.assertEqual(service[:5], ['make', '-C', state['paths']['work'] + '/build', '-k', '-j2'])
            self.assertEqual(service[-22:], list(BASE))
            self.assertEqual(service.count('-W'), 20)
            if neutral:
                command = target.expected_command(state, 'focus')
                self.assertEqual(command[-7:], list(FOCUS))
                self.assertEqual(command.count('-W'), 6)
                self.assertNotIn('-k', command)
                self.assertIn(state['paths']['work'] + '/source/server/main.c', command)
            for i, source in enumerate(SYNTAX):
                command = target.expected_command(state, 'syntax-' + str(i))
                self.assertEqual(command[0], state['paths']['sdk'] + '/bin/prospero-clang')
                self.assertEqual(command[-2:], ['-fsyntax-only', str(ROOT / source)])
                self.assertIn('-std=c11' if i == 3 else '-std=gnu11', command)
                self.assertEqual('-fPIC' in command, i != 3)
                self.assertIn('-Werror', command)
                self.assertEqual('-DPW_WINE_FOCUS_NEUTRAL=1' in command, bool(neutral))
                self.assertEqual('-DPW_FOCUS_SERVER_REQUESTS=1' in command, bool(neutral))
                self.assertNotIn('-o', command)

    def test_selected_flags_bind_native_and_both_cross_compiler_paths(self):
        for neutral in (0, 1):
            state = self.new_case(neutral)
            flags = target.selected_flags(state)
            wanted = {'PW_WINE_PRIVATE_DISPATCH': '1', 'PW_WINE_SERVICE_FIXTURE': '1',
                      'PW_WINE_FOCUS_NEUTRAL': str(neutral), 'CFLAGS': '-O2 -g', 'CCACHE_DISABLE': '1'}
            for variable, compiler in (('CC', 'gcc'), ('CXX', 'g++'),
                                       ('i386_CC', 'i686-w64-mingw32-gcc'),
                                       ('x86_64_CC', 'x86_64-w64-mingw32-gcc')):
                wanted[variable] = state['cohort']['build_compilers'][compiler]['path']
            for name, value in wanted.items():
                self.assertEqual(flags[name], value)

    def test_record_refuses_out_of_order_unknown_duplicate_and_changed_argv_before_launch(self):
        state = self.new_case(1)
        out = Path(state['paths']['out'])
        for stage, command in [('focus', target.expected_command(state, 'focus')),
                               ('syntax-1', target.expected_command(state, 'syntax-1')),
                               ('unknown', []), ('service', ['make', '-j8'])]:
            with self.subTest(stage=stage), patch.object(target.subprocess, 'run') as invoked:
                with self.assertRaises((ValueError, FileNotFoundError)):
                    target.command_record(argparse.Namespace(receipt=out, stage=stage, command=command))
                invoked.assert_not_called()
        self.invoke_record(state, 'service')
        with patch.object(target.subprocess, 'run') as invoked, self.assertRaises(ValueError):
            target.command_record(argparse.Namespace(receipt=out, stage='service',
                                                    command=target.expected_command(state, 'service')))
        invoked.assert_not_called()

    def test_record_refuses_existing_or_symlinked_objects_before_launch(self):
        for name, linked in ((BASE[0], False), (BASE[7], False), (BASE[-1], True)):
            with self.subTest(name=name, symlink=linked):
                state = self.new_case()
                path = Path(state['paths']['work']) / 'build' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if linked:
                    path.symlink_to(self.root / 'absent-object')
                else:
                    path.write_bytes(inert_object(name))
                with patch.object(target.subprocess, 'run') as invoked, self.assertRaisesRegex(ValueError, 'not fresh'):
                    target.command_record(argparse.Namespace(receipt=Path(state['paths']['out']), stage='service',
                                                            command=target.expected_command(state, 'service')))
                invoked.assert_not_called()
        state = self.new_case(1)
        self.invoke_record(state, 'service')
        put(Path(state['paths']['work']) / 'build' / FOCUS[0], elf_fixture())
        with patch.object(target.subprocess, 'run') as invoked, self.assertRaisesRegex(ValueError, 'not fresh'):
            target.command_record(argparse.Namespace(receipt=Path(state['paths']['out']), stage='focus',
                                                    command=target.expected_command(state, 'focus')))
        invoked.assert_not_called()

    def test_record_retains_failed_exit_and_timeout_and_blocks_next_stage(self):
        for code in (2, -9, 124):
            with self.subTest(code=code):
                state = self.new_case()
                def fail(command, **kwargs):
                    if code == 124:
                        raise subprocess.TimeoutExpired(command, 1500)
                    return subprocess.CompletedProcess(command, code)
                with self.assertRaisesRegex(ValueError, 'compile command failed'):
                    self.invoke_record(state, 'service', effect=fail)
                out = Path(state['paths']['out'])
                got = target.read(out / 'command-0.json')
                self.assertEqual(got['exit'], code)
                self.assertEqual(got['objects'], {})
                self.assertFalse((out / 'TARGET-COMPILE.json').exists())
                with patch.object(target.subprocess, 'run') as invoked, self.assertRaisesRegex(ValueError, 'previous compile'):
                    target.command_record(argparse.Namespace(receipt=out, stage='syntax-0',
                                                            command=target.expected_command(state, 'syntax-0')))
                invoked.assert_not_called()

    def test_zero_exit_without_valid_objects_does_not_create_success_receipt(self):
        for malformed in (False, True):
            state = self.new_case()
            def empty_compile(command, **kwargs):
                if malformed:
                    put(Path(state['paths']['work']) / 'build' / BASE[0], b'not an ELF object')
                return subprocess.CompletedProcess(command, 0)
            with self.subTest(malformed=malformed), self.assertRaises((ValueError, FileNotFoundError)):
                self.invoke_record(state, 'service', effect=empty_compile)
            self.assertFalse((Path(state['paths']['out']) / 'command-0.json').exists())

    def test_every_object_is_bound_and_missing_or_tampered_objects_fail(self):
        state = self.new_case(1)
        out, _ = self.complete(state)
        for name in BASE + FOCUS:
            path = Path(state['paths']['work']) / 'build' / name
            original = path.read_bytes()
            with self.subTest(name=name, change='valid bytes changed'):
                path.write_bytes(original + b'inert changed data')
                self.assert_rejected(out, 'objects changed')
            with self.subTest(name=name, change='missing'):
                path.unlink()
                self.assert_rejected(out)
            path.write_bytes(original)
        self.assertEqual(len(target.verify_work(out)[1]['objects']), 29)

    def test_recorded_command_fields_are_strict_including_json_booleans(self):
        state = self.new_case(1)
        out, _ = self.complete(state)
        path = out / 'command-0.json'
        original = path.read_bytes()
        mutations = [lambda row: row.update(stage='focus'), lambda row: row.update(exit=1),
                     lambda row: row.update(exit=False), lambda row: row.update(exit=0.0),
                     lambda row: row.update(syntax_only=True), lambda row: row.update(syntax_only=0),
                     lambda row: row.update(objects_absent_before=1),
                     lambda row: row.update(objects_absent_before=False),
                     lambda row: row['argv'].append('--extra'),
                     lambda row: row['argv'].__setitem__(4, '-j8'),
                     lambda row: row['objects'].pop(BASE[0]),
                     lambda row: row['objects'].update({'server/extra.o': row['objects'][BASE[0]]})]
        for i, mutate in enumerate(mutations):
            with self.subTest(mutation=i):
                self.mutate(path, mutate)
                self.assert_rejected(out, finished=False)
                path.write_bytes(original)
        syntax = out / 'command-2.json'
        self.mutate(syntax, lambda row: row.update(syntax_only=False))
        self.assert_rejected(out, 'stage type/freshness', finished=False)

    def test_missing_extra_or_reordered_command_receipts_fail(self):
        state = self.new_case(1)
        out, _ = self.complete(state)
        first = out / 'command-0.json'
        original = first.read_bytes()
        first.unlink()
        self.assert_rejected(out, 'inventory', finished=False)
        first.write_bytes(original)
        extra = out / 'command-99.json'
        extra.write_bytes(original)
        self.assert_rejected(out, 'inventory', finished=False)
        extra.unlink()
        second = out / 'command-1.json'
        first.write_bytes(second.read_bytes())
        second.write_bytes(original)
        self.assert_rejected(out, finished=False)

    def test_driver_argv_exit_and_selected_flags_are_bound(self):
        state = self.new_case(1)
        out, _ = self.complete(state)
        path = out / 'DRIVER-RESULT.json'
        original = path.read_bytes()
        changes = [lambda row: row.update(exit=1), lambda row: row.update(exit=False),
                   lambda row: row.update(exit=0.0), lambda row: row['argv'].remove('--compile-check'),
                   lambda row: row['selected_flags'].update(PW_WINE_FOCUS_NEUTRAL='0'),
                   lambda row: row['selected_flags'].update(CCACHE_DISABLE='0'),
                   *[lambda row, name=name: row['selected_flags'].update({name: '/wrong/compiler'})
                     for name in ('CC', 'CXX', 'i386_CC', 'x86_64_CC')],
                   lambda row: row.pop('selected_flags')]
        for i, change in enumerate(changes):
            with self.subTest(mutation=i):
                self.mutate(path, change)
                with self.assertRaises((ValueError, KeyError)):
                    target.verify_work(out, finished=False)
                path.write_bytes(original)

    def test_input_mode_run_identity_jobs_output_and_cohort_are_strict(self):
        state = self.new_case()
        out, _ = self.complete(state)
        path = out / 'INPUTS.json'
        original = path.read_bytes()
        changes = [lambda row: row.update(neutral=True), lambda row: row.update(neutral=2),
                   lambda row: row.update(neutral='0'), lambda row: row.update(neutral=1),
                   lambda row: row.update(jobs=True), lambda row: row.update(jobs=0),
                   lambda row: row.update(jobs=9), lambda row: row.update(run_id='0'),
                   lambda row: row.update(run_attempt='01'), lambda row: row.update(run_id=123456),
                   lambda row: row['paths'].update(out=str(out.parent / 'different')),
                   lambda row: row['cohort']['project'].update(commit='c' * 40)]
        for i, change in enumerate(changes):
            with self.subTest(mutation=i):
                self.mutate(path, change)
                self.assert_rejected(out, finished=False)
                path.write_bytes(original)

    def test_live_source_and_staged_configuration_drift_are_rejected(self):
        state = self.new_case(1)
        out, _ = self.complete(state)
        self.cohorts[state['paths']['out']]['project']['tree'] = 'f' * 40
        self.assert_rejected(out, 'inputs changed', finished=False)
        self.cohorts[state['paths']['out']] = copy.deepcopy(self.cohort)
        for name in ('build/include/config.h', 'source/server/pw_focus_requests.c',
                     'source/include/wine/pw_focus_build.h'):
            with self.subTest(name=name):
                path = Path(state['paths']['work']) / name
                original = path.read_bytes()
                path.write_bytes(original + b'/* changed */\n')
                self.assert_rejected(out, 'staged source/configuration changed', finished=False)
                path.write_bytes(original)
        # Even when the expensive staging boundary is held constant, the real
        # verifier independently rehashes every focus source captured before it ran.
        staged = target.read(out / 'STAGED-SOURCE.json')
        with patch.object(target, 'staged_inputs', return_value=staged):
            path = Path(state['paths']['work']) / 'source/server/user.c'
            path.write_text('/* source changed after recorded compilation */\n')
            self.assert_rejected(out, 'focus command source changed', finished=False)

    def test_every_forbidden_runtime_output_and_dangling_link_is_rejected(self):
        state = self.new_case()
        out, _ = self.complete(state)
        for name in RUNTIME_OUTPUTS:
            path = Path(state['paths']['work']) / name
            with self.subTest(name=name):
                path.mkdir()
                self.assert_rejected(out, 'runtime/package', finished=False)
                path.rmdir()
                path.symlink_to(self.root / 'missing-runtime-output')
                self.assert_rejected(out, 'runtime/package', finished=False)
                path.unlink()

    def test_missing_or_changed_compile_only_marker_is_rejected(self):
        state = self.new_case()
        out, _ = self.complete(state)
        marker = Path(state['paths']['work']) / 'compile-check-only.json'
        original = marker.read_bytes()
        marker.unlink()
        self.assert_rejected(out)
        marker.write_bytes(original)
        self.mutate(marker, lambda row: row.update(complete_runtime=True))
        self.assert_rejected(out, 'compile-only exit marker', finished=False)

    def test_final_receipt_and_retained_logs_cannot_be_rewritten(self):
        state = self.new_case(1)
        out, _ = self.complete(state)
        accepted = out / 'TARGET-COMPILE.json'
        original = accepted.read_bytes()
        for flag in ('target_executed', 'runtime_validated', 'owner_worker_compiled', 'compile_only'):
            with self.subTest(flag=flag):
                self.mutate(accepted, lambda row: row.update({flag: not row[flag]}))
                self.assert_rejected(out, 'accepted compile receipt')
                accepted.write_bytes(original)
        for path in (out / 'driver.log', Path(state['paths']['work']) / 'service-translation-units.log'):
            original_log = path.read_bytes()
            path.write_bytes(original_log + b'changed\n')
            self.assert_rejected(out, 'accepted compile receipt')
            path.write_bytes(original_log)
        accepted.unlink()
        self.assert_rejected(out)

    def test_collect_refuses_crossed_modes_changed_cohort_and_run(self):
        control = self.new_case(0)
        neutral = self.new_case(1)
        off, _ = self.complete(control)
        on, _ = self.complete(neutral)
        output = self.root / 'collected'
        for left, right in ((on, off), (off, off), (on, on)):
            with self.subTest(control=left, neutral=right), self.assertRaisesRegex(ValueError, 'controls crossed'):
                target.collect(argparse.Namespace(control=left, neutral=right, out=output))
            self.assertFalse(output.exists())
        state_path = on / 'INPUTS.json'
        self.mutate(state_path, lambda row: row['cohort'].update(fixture='different cohort'))
        self.cohorts[str(on)]['fixture'] = 'different cohort'
        write_json(on / 'TARGET-COMPILE.json', target.verify_work(on, finished=False)[1])
        with self.assertRaisesRegex(ValueError, 'cohort differs'):
            target.collect(argparse.Namespace(control=off, neutral=on, out=output))
        self.assertFalse(output.exists())
        self.mutate(state_path, lambda row: row.update(cohort=copy.deepcopy(self.cohort), run_attempt='3'))
        self.cohorts[str(on)] = copy.deepcopy(self.cohort)
        write_json(on / 'TARGET-COMPILE.json', target.verify_work(on, finished=False)[1])
        with self.assertRaisesRegex(ValueError, 'run/attempt differs'):
            target.collect(argparse.Namespace(control=off, neutral=on, out=output))
        self.assertFalse(output.exists())

    def run_args(self, neutral=0):
        self.serial += 1
        case = self.root / ('run-' + str(self.serial))
        case.mkdir()
        values = {'repo': ROOT, 'neutral': neutral, 'jobs': 2,
                  'run_id': '123456', 'run_attempt': '2',
                  'work': case / 'work', 'out': case / 'receipt'}
        for name in target.PATH_FIELDS:
            if name != 'repo':
                values[name] = case / name
                values[name].mkdir()
        return argparse.Namespace(**values)

    def driver_fixture(self, args):
        def execute(command, **kwargs):
            state = target.read(args.out / 'INPUTS.json')
            self.assertEqual(command, target.driver_command(state))
            self.assertEqual(kwargs['cwd'], ROOT)
            self.assertEqual(kwargs['timeout'], 1800)
            self.assertEqual(kwargs['stderr'], subprocess.STDOUT)
            env = kwargs['env']
            selected = target.selected_flags(state)
            for key, value in selected.items():
                self.assertEqual(env[key], value)
            for key in POLLUTED_ENV:
                if key not in selected:
                    self.assertNotIn(key, env)
            self.assertEqual(env['PROSPERO_TLS_ROOT'], str(args.tls))
            self.assertEqual(env['PYTHONDONTWRITEBYTECODE'], '1')
            self.assertEqual(env['CONFIG_SITE'], '/dev/null')
            self.assertEqual(env['LC_ALL'], 'C')
            self.assertEqual(env['TZ'], 'UTC')
            self.prepare_work(state)
            for stage in target.stages(state['neutral']):
                self.invoke_record(state, stage)
            kwargs['stdout'].write('inert driver completed; no compiler invoked\n')
            return subprocess.CompletedProcess(command, 0)
        return execute

    def test_run_sanitizes_inherited_cache_and_compiler_settings_and_verifies_receipt(self):
        for neutral in (0, 1):
            with self.subTest(neutral=neutral):
                args = self.run_args(neutral)
                polluted = {key: 'MUST-NOT-LEAK' for key in POLLUTED_ENV}
                polluted.update(PW_WINE_PRIVATE_DISPATCH='0', PW_WINE_SERVICE_FIXTURE='0',
                                PW_WINE_FOCUS_NEUTRAL='1' if not neutral else '0', CFLAGS='-O0',
                                CONFIG_SITE='/untrusted-config.site', LC_ALL='unexpected', TZ='unexpected')
                with patch.dict(os.environ, polluted), patch.object(target.subprocess, 'run',
                        side_effect=self.driver_fixture(args)) as driver:
                    result = target.run(args)
                driver.assert_called_once()
                self.assertEqual(target.verify_work(args.out)[1], result)
                self.assertEqual(len(result['objects']), 29 if neutral else 22)
                first_log = json.loads((args.out / 'driver.log').read_text().splitlines()[0])
                self.assertEqual(first_log['selected_flags'], result['selected_flags'])
                self.assertFalse((args.out / 'UNACCEPTED-TARGET.json').exists())

    def test_run_invalid_identity_selector_and_outputs_fail_before_driver(self):
        for key, value in (('neutral', True), ('neutral', 2), ('jobs', 0), ('jobs', 9),
                           ('run_id', '0'), ('run_attempt', ''), ('run_attempt', '01')):
            args = self.run_args()
            setattr(args, key, value)
            with self.subTest(key=key, value=value), patch.object(target.subprocess, 'run') as driver:
                with self.assertRaises(ValueError):
                    target.run(args)
                driver.assert_not_called()
                self.assertFalse(args.out.exists())
                self.assertFalse(args.work.exists())
        for existing in ('work', 'out', 'same-path', 'input-overlap'):
            args = self.run_args()
            if existing in ('work', 'out'):
                getattr(args, existing).mkdir()
            elif existing == 'same-path':
                args.work = args.out
            else:
                args.work = args.wine_source / 'new-output'
            with self.subTest(existing=existing), patch.object(target.subprocess, 'run') as driver:
                with self.assertRaises(ValueError):
                    target.run(args)
                driver.assert_not_called()

    def test_noncanonical_paths_cannot_bypass_input_output_or_mode_separation(self):
        for name in (*target.PATH_FIELDS, 'work', 'out'):
            args = self.run_args()
            original = getattr(args, name)
            if name == 'repo':
                alias = ROOT / 'tools' / '..'
            else:
                hop = original.parent / 'canonical-hop'
                hop.mkdir(exist_ok=True)
                alias = hop / '..' / original.name
            setattr(args, name, alias)
            with self.subTest(api='run', path=name), patch.object(target.subprocess, 'run') as driver:
                with self.assertRaisesRegex(ValueError, 'noncanonical'):
                    target.run(args)
                driver.assert_not_called()
        state = self.new_case(0)
        out = Path(state['paths']['out'])
        hop = out.parent / 'canonical-hop'
        hop.mkdir()
        alias = hop / '..' / out.name
        with patch.object(target.subprocess, 'run') as compiler:
            with self.assertRaisesRegex(ValueError, 'noncanonical'):
                target.command_record(argparse.Namespace(receipt=alias, stage='service',
                                                        command=target.expected_command(state, 'service')))
            compiler.assert_not_called()
        off, _ = self.complete(state)
        with self.assertRaisesRegex(ValueError, 'noncanonical'):
            target.verify_work(alias)
        state_path = off / 'INPUTS.json'
        original = state_path.read_bytes()
        for name in (*target.PATH_FIELDS, 'work', 'out'):
            with self.subTest(api='retained input', path=name):
                value = Path(state['paths'][name])
                self.mutate(state_path, lambda row, name=name, value=value:
                            row['paths'].update({name: str(value / '..' / value.name)}))
                self.assert_rejected(off, 'noncanonical', finished=False)
                state_path.write_bytes(original)
        for change in (lambda row: row['paths'].pop('tls'),
                       lambda row: row['paths'].update(unexpected=str(self.root))):
            self.mutate(state_path, change)
            self.assert_rejected(off, 'path inventory', finished=False)
            state_path.write_bytes(original)
        on, _ = self.complete(self.new_case(1))
        output = self.root / 'collected'
        hop = self.root / 'canonical-hop'
        hop.mkdir()
        for control, neutral, destination in ((alias, on, output), (off, alias, output),
                                              (off, on, hop / '..' / output.name)):
            with self.subTest(api='collect', control=control, neutral=neutral, out=destination):
                with self.assertRaisesRegex(ValueError, 'noncanonical'):
                    target.collect(argparse.Namespace(control=control, neutral=neutral, out=destination))
                self.assertFalse(output.exists())

    def test_failed_or_timed_out_driver_never_leaves_an_accepted_receipt(self):
        for code in (1, -9, 124):
            args = self.run_args()
            def failed(command, **kwargs):
                if code == 124:
                    raise subprocess.TimeoutExpired(command, 1800)
                return subprocess.CompletedProcess(command, code)
            with self.subTest(code=code), patch.object(target.subprocess, 'run', side_effect=failed):
                with self.assertRaisesRegex(ValueError, 'compile-only driver failed'):
                    target.run(args)
            self.assertEqual(target.read(args.out / 'DRIVER-RESULT.json')['exit'], code)
            self.assertFalse((args.out / 'TARGET-COMPILE.json').exists())

    def test_run_final_recheck_failure_retires_the_unaccepted_receipt(self):
        args = self.run_args(1)
        calls = 0
        def external_inputs(state):
            nonlocal calls
            calls += 1
            cohort = self.current_inputs(state)
            if calls == 3:
                cohort['project']['tree'] = 'f' * 40
            return cohort
        with patch.object(target, 'current_inputs', side_effect=external_inputs), \
                patch.object(target.subprocess, 'run', side_effect=self.driver_fixture(args)):
            with self.assertRaisesRegex(ValueError, 'inputs changed'):
                target.run(args)
        self.assertEqual(calls, 3)
        self.assertFalse((args.out / 'TARGET-COMPILE.json').exists())
        self.assertTrue((args.out / 'UNACCEPTED-TARGET.json').is_file())
        self.assertEqual(len(target.read(args.out / 'UNACCEPTED-TARGET.json')['objects']), 29)

    def test_collect_requires_separate_mode_work_directories(self):
        control, neutral = self.new_case(0), self.new_case(1)
        off, _ = self.complete(control)
        on, _ = self.complete(neutral)
        # Keep both real verifications valid while deliberately rebinding the
        # neutral evidence to the control work directory. Collection must still
        # reject this, even though the inert objects have identical bytes.
        shared = Path(control['paths']['work'])
        original = Path(neutral['paths']['work'])
        for name in ('focus-neutral.json', 'source/include/wine/pw_focus_build.h'):
            put(shared / name, (original / name).read_bytes())
        for name in FOCUS:
            put(shared / 'build' / name, (original / 'build' / name).read_bytes())
        neutral['paths']['work'] = str(shared)
        write_json(on / 'INPUTS.json', neutral)
        write_json(on / 'STAGED-SOURCE.json', self.staged_inputs(neutral))
        for i, stage in enumerate(target.stages(1)):
            self.mutate(on / ('command-' + str(i) + '.json'),
                        lambda row, stage=stage: row.update(argv=target.expected_command(neutral, stage)))
        self.mutate(on / 'DRIVER-RESULT.json', lambda row: row.update(argv=target.driver_command(neutral)))
        write_json(on / 'TARGET-COMPILE.json', target.verify_work(on, finished=False)[1])
        target.verify_work(off)
        target.verify_work(on)
        output = self.root / 'collected'
        with self.assertRaisesRegex(ValueError, 'directories overlap'):
            target.collect(argparse.Namespace(control=off, neutral=on, out=output))
        self.assertFalse(output.exists())

    def collect_fixture(self, *, drift=False):
        control, neutral = self.new_case(0), self.new_case(1)
        off, _ = self.complete(control)
        on, _ = self.complete(neutral)
        output = self.root / 'collected'
        freetype = Path(control['paths']['work']) / 'freetype/freetype-inert.tar.xz'
        put(freetype, b'inert corresponding-source fixture, not a real dependency archive')
        pins = {'FREETYPE_VERSION': 'inert', 'FREETYPE_SHA256': target.record(freetype)['sha256']}
        archived = []
        def archive_boundary(root, revision, destination):
            # Only source archive discovery is replaced. Actual receipt checks,
            # all copy/hash operations, inventory and checksums stay production.
            archived.append((Path(root), revision, destination.name))
            data = b'INERT UNIT-TEST ARCHIVE. No SDK or target compilation.\n'
            with tarfile.open(destination, 'w:gz') as archive:
                info = tarfile.TarInfo('INERT-FIXTURE.txt')
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            if drift and len(archived) == 1:
                path = Path(control['paths']['work']) / 'build' / BASE[0]
                path.write_bytes(path.read_bytes() + b'changed during collection')
        with patch.object(target, 'archive_git', side_effect=archive_boundary), \
                patch.object(target.package, 'script_pins', return_value=pins):
            if drift:
                with self.assertRaisesRegex(ValueError, 'objects changed'):
                    target.collect(argparse.Namespace(control=off, neutral=on, out=output))
                return output
            result = target.collect(argparse.Namespace(control=off, neutral=on, out=output))
        self.assertEqual([entry[2] for entry in archived],
                         ['project.tar.gz', 'wine.tar.gz', 'sdk.tar.gz', 'title-foundation.tar.gz'])
        self.assertEqual(archived[0][1], self.cohort['project']['commit'])
        self.assertEqual(archived[1][1], target.focus.WINE_COMMIT)
        self.assertEqual(archived[2][1], target.SDK_COMMIT)
        self.assertEqual(archived[3][1], target.TITLE_FOUNDATION)
        return output, result

    def test_positive_collect_retains_and_hashes_the_real_receipt_evidence(self):
        output, result = self.collect_fixture()
        self.assertEqual(result['schema'], target.PAIR_SCHEMA)
        self.assertEqual(result['control_objects'], 22)
        self.assertEqual(result['neutral_objects'], 29)
        self.assertEqual(result['syntax_only_units_per_mode'], 4)
        self.assertIs(result['compile_only'], True)
        self.assertIs(result['compiler_cache_used'], False)
        for flag in NO_RUNTIME_CLAIMS:
            self.assertIs(result[flag], False)
        self.assertEqual(target.read(output / 'TRANSLATION-UNIT-VALIDATION.json'), result)
        inventory = target.package.inventory(output)
        self.assertEqual((output / 'SHA256SUMS').read_bytes(), target.package.checksums(inventory))
        for name, entry in result['inventory'].items():
            self.assertEqual(entry, inventory[name])
        for mode, names in (('control', BASE), ('neutral', BASE + FOCUS)):
            receipt = target.read(output / mode / 'TARGET-COMPILE.json')
            actual = {name: target.object_record(output / mode / 'objects' / name, name) for name in names}
            self.assertEqual(actual, receipt['objects'])
            self.assertTrue((output / mode / 'generated/build/include/config.h').is_file())
            self.assertTrue((output / mode / 'driver.log').is_file())
        self.assertTrue((output / 'neutral/pw_focus_build.h').is_file())
        self.assertFalse((output / 'control/pw_focus_build.h').exists())

    def test_collect_rechecks_inputs_after_copy_and_never_accepts_drift(self):
        output = self.collect_fixture(drift=True)
        self.assertFalse((output / 'TRANSLATION-UNIT-VALIDATION.json').exists())
        self.assertFalse((output / 'SHA256SUMS').exists())

    def test_json_duplicate_keys_and_overwrite_are_refused(self):
        path = self.root / 'duplicate.json'
        path.write_text('{"neutral": 0, "neutral": 1}\n')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            target.read(path)
        path.write_text('{}\n')
        with self.assertRaises(FileExistsError):
            target.write_new(path, {'replacement': True})
        self.assertEqual(path.read_text(), '{}\n')


class CommandLineControls(unittest.TestCase):
    def test_missing_arguments_and_invalid_selector_fail_without_outputs(self):
        with tempfile.TemporaryDirectory(prefix='focus-cli-') as temporary:
            root = Path(temporary)
            output = root / 'must-not-exist'
            cases = ([], ['run'], ['record'], ['collect'], ['verify'],
                     ['run', '--neutral', '2'], ['run', '--neutral', 'true'],
                     ['collect', '--control', str(root), '--neutral', str(root)])
            for args in cases:
                with self.subTest(args=args):
                    result = subprocess.run([sys.executable, str(ROOT / 'tools/check_focus_target_compile.py'), *args],
                                            capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertFalse(output.exists())

    def test_actual_buildscript_receipt_hook_routes_exact_commands_and_stops_on_failure(self):
        source = (ROOT / 'tools/build_wine_ps5.sh').read_text()
        block = source.split('# Compile complete experimental units', 1)[1].split("# The SDK's libc", 1)[0]
        block = block.split('\n', 1)[1]
        with tempfile.TemporaryDirectory(prefix='focus-hook-') as temporary:
            root = Path(temporary)
            sdk = root / 'sdk'
            # This file is copied by the real gate but must never be executed.
            put(sdk / 'bin/prospero-clang', '#!/bin/sh\nexit 97\n')
            (sdk / 'bin/prospero-clang').chmod(0o755)
            for neutral in (0, 1):
                stages = ['service'] + (['focus'] if neutral else []) + ['syntax-' + str(i) for i in range(4)]
                for fail_stage in ('', *stages):
                    with self.subTest(neutral=neutral, fail_stage=fail_stage):
                        work = root / ('mode-' + str(neutral) + '-' + (fail_stage or 'success'))
                        work.mkdir()
                        receipt = work / 'receipt'
                        calls = work / 'hook-calls.jsonl'
                        state = {'neutral': neutral, 'jobs': 2,
                                 'paths': {name: str(root / name) for name in target.PATH_FIELDS}}
                        state['paths'].update(repo=str(ROOT), sdk=str(sdk), work=str(work), out=str(receipt))
                        flags = '-DPW_WINE_SERVICE_FIXTURE=1'
                        if neutral:
                            flags += ' -DPW_WINE_FOCUS_NEUTRAL=1 -DPW_FOCUS_SERVER_ADAPTER=1'
                            flags += ' -DPW_FOCUS_SERVER_REQUESTS=1 -I' + str(work / 'source/include')
                        # Intercept just python3 at the recorder process boundary.
                        # An accidental direct make/compiler call must fail.
                        setup = ("set -eu\nroot=$REPO\nsdk=$SDK\nwork=$WORK\nbuild=$work/build\n"
                                 "tree=$work/source\nwine_cc=$sdk/bin/prospero-clang\njobs=2\n"
                                 "service_fixture=1\nfocus_neutral=$NEUTRAL\ncompile_check_only=1\n"
                                 "compile_receipt=$RECEIPT\nservice_cflags=$FLAGS\n"
                                 "fail() { exit 73; }\nmake() { exit 96; }\n"
                                 "python3() { \"$REAL_PYTHON\" -c 'import json,os,sys; "
                                 "f=open(os.environ[\"CALLS\"], \"a\"); "
                                 "f.write(json.dumps(sys.argv[1:])+chr(10)); f.close(); "
                                 "raise SystemExit(9 if sys.argv[6] == os.environ[\"FAIL_STAGE\"] else 0)' \"$@\"; }\n")
                        result = subprocess.run(['sh'], input=setup + block + '\necho FULL_CONTINUATION\n',
                            env=dict(os.environ, REPO=str(ROOT), SDK=str(sdk), WORK=str(work),
                                     NEUTRAL=str(neutral), RECEIPT=str(receipt), FLAGS=flags,
                                     REAL_PYTHON=sys.executable, CALLS=str(calls), FAIL_STAGE=fail_stage),
                            capture_output=True, text=True, timeout=20)
                        self.assertEqual(result.returncode, 73 if fail_stage else 0, result.stderr)
                        expected = stages[:stages.index(fail_stage) + 1] if fail_stage else stages
                        rows = [json.loads(line) for line in calls.read_text().splitlines()]
                        self.assertEqual(len(rows), len(expected))
                        for stage, row in zip(expected, rows):
                            self.assertEqual(row[:7], [str(ROOT / 'tools/check_focus_target_compile.py'),
                                'record', '--receipt', str(receipt), '--stage', stage, '--'])
                            self.assertEqual(row[7:], target.expected_command(state, stage))
                        self.assertEqual((work / 'compile-check-only.json').exists(), not bool(fail_stage))
                        self.assertNotIn('FULL_CONTINUATION', result.stdout)
                        for name in RUNTIME_OUTPUTS:
                            self.assertFalse((work / name).exists())

    def test_buildscript_rejects_compile_receipt_without_compile_only_and_missing_fixture(self):
        with tempfile.TemporaryDirectory(prefix='focus-gate-') as temporary:
            root = Path(temporary)
            work = root / 'must-not-exist'
            env = dict(os.environ, PW_WINE_FOCUS_NEUTRAL='0', PW_WINE_SERVICE_FIXTURE='0',
                       CFLAGS='', CPPFLAGS='', CROSSCFLAGS='', i386_CFLAGS='', x86_64_CFLAGS='')
            for options, message in (
                (['--compile-check-receipt', str(root / 'receipt')], 'requires --compile-check'),
                (['--compile-check'], 'requires PW_WINE_SERVICE_FIXTURE=1'),
            ):
                with self.subTest(options=options):
                    result = subprocess.run(['sh', str(ROOT / 'tools/build_wine_ps5.sh'),
                                             '--work', str(work), *options], env=env,
                                            capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn(message, result.stderr)
                    self.assertFalse(work.exists())


if __name__ == '__main__':
    unittest.main()
