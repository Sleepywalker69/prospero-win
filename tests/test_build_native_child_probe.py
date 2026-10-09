#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Synthetic analyzer controls for the original native worker build boundary."""
from pathlib import Path
import hashlib
import importlib.util
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('worker_build', ROOT / 'tools/build_native_child_probe.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def elf(kind):
    value = bytearray(256)
    value[:8] = b'\x7fELF\x02\x01\x01\x09'
    struct.pack_into('<HHIQQQIHHHHHH', value, 16, kind, 62, 1, 128, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', value, 64, 1, 5, 0, 0, 0, len(value), len(value), 0x4000)
    return bytes(value)


class WorkerBuildTests(unittest.TestCase):
    def test_mode_and_linked_sources_bind_the_worker_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in build.SOURCES + build.FD_SOURCES + build.PEER_SOURCES + build.SERVICE_SOURCES:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)
            with mock.patch.object(build, 'ROOT', root):
                hello_sources, hello = build.mode_inputs('hello')
                fd_sources, fd = build.mode_inputs('fd')
                peer_sources, peer = build.mode_inputs('peer-exit')
                service_sources, service = build.mode_inputs('service')
                self.assertEqual(len({hello, fd, peer, service}), 4)
                self.assertEqual(set(service_sources), set(build.SERVICE_SOURCES))
                (root / build.SERVICE_SOURCES[0]).write_text('changed finite fd3 worker')
                self.assertNotEqual(build.mode_inputs('service')[1], service)
                self.assertEqual(build.mode_inputs('hello')[1], hello)
                self.assertEqual(build.mode_inputs('fd')[1], fd)
                self.assertEqual(build.mode_inputs('peer-exit')[1], peer)
                self.assertEqual(set(peer_sources) - set(hello_sources), set(build.PEER_SOURCES))
                self.assertNotEqual(hello, fd)
                self.assertEqual(set(fd_sources) - set(hello_sources), set(build.FD_SOURCES))
                (root / build.FD_SOURCES[0]).write_text('changed descriptor implementation')
                self.assertEqual(build.mode_inputs('hello')[1], hello)
                self.assertNotEqual(build.mode_inputs('fd')[1], fd)
                self.assertEqual(build.mode_inputs('peer-exit')[1], peer)
                (root / build.PEER_SOURCES[0]).write_text('changed credential/event implementation')
                self.assertNotEqual(build.mode_inputs('peer-exit')[1], peer)
                self.assertEqual(build.mode_inputs('hello')[1], hello)
                with self.assertRaises(ValueError):
                    build.mode_inputs('unknown')

    def test_preload_metadata_survives_allowed_self_reconstruction(self):
        fixture_spec = importlib.util.spec_from_file_location('preload_fixture', ROOT / 'tests/test_native_service_converter.py')
        fixture_module = importlib.util.module_from_spec(fixture_spec)
        fixture_spec.loader.exec_module(fixture_module)
        value = fixture_module.fixture()
        struct.pack_into('<I', value, 68, 7)  # synthetic file-backed executable LOAD
        struct.pack_into('<H', value, 56, 5)
        struct.pack_into('<IIQQQQQQ', value, 64 + 4 * 56, 4, 0, len(value), 0, 0, 24, 0, 4)
        value += struct.pack('<III4s', 4, 8, 3, b'SIE\0') + b'build-id'
        recovered = bytearray(value); recovered[7] = 9; recovered[-24:] = bytes(24)
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / 'original.elf'; extracted = Path(tmp) / 'recovered.elf'
            original.write_bytes(value); extracted.write_bytes(recovered)
            build.verify_reconstruction(original, extracted)
        before = build.inspect_service_preload(bytes(value))
        after = build.inspect_service_preload(bytes(recovered))
        self.assertNotEqual(before['elf_sha256'], after['elf_sha256'])
        build.compare_service_preload(before, after)
        moved = bytearray(recovered)
        struct.pack_into('<Q', moved, 0x390, 0x1088)
        struct.pack_into('<Q', moved, 0x288, fixture_module.module.PRELOAD_MASK)
        moved_metadata = build.inspect_service_preload(bytes(moved))
        with self.assertRaises(ValueError):
            build.compare_service_preload(before, moved_metadata)
        moved[0x288] ^= 1
        with self.assertRaises(ValueError):
            build.inspect_service_preload(bytes(moved))
        for field in before.keys() - {'elf_sha256'}:
            changed = dict(after); changed[field] = 'incorrect metadata'
            with self.subTest(field=field), self.assertRaises(ValueError):
                build.compare_service_preload(before, changed)

    def test_only_pinned_unmapped_sie_note_may_be_zeroed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); original = root / 'worker.elf'; recovered = root / 'extracted.elf'
            value = bytearray(elf(0xFE10))
            struct.pack_into('<Q', value, 24, 240)
            struct.pack_into('<H', value, 56, 3)
            struct.pack_into('<IIQQQQQQ', value, 120, 0x6fffff01, 0, 256, 0, 0, 16, 16, 1)
            struct.pack_into('<IIQQQQQQ', value, 176, 4, 0, 272, 0, 0, 24, 0, 4)
            value += b'version-records!' + struct.pack('<III4s', 4, 8, 3, b'SIE\0') + b'build-id'
            self.assertEqual(len(value), 296)
            for abi in (0, 3, 9):
                value[7] = abi; original.write_bytes(value)
                expected = bytearray(value); expected[7] = 9; expected[-24:] = bytes(24)
                recovered.write_bytes(expected)
                result = build.verify_reconstruction(original, recovered)
                self.assertEqual(result['zeroed_unmapped_sie_note']['bytes'], 24)
            # Byte/header/version corruption, an unzeroed tail, and truncation
            # remain rejected; this is not a generic non-LOAD exemption.
            for location in (7, 24, 128, 240, 256, 272, 295):
                bad = bytearray(expected); bad[location] ^= 1; recovered.write_bytes(bad)
                with self.subTest(offset=location), self.assertRaises(ValueError):
                    build.verify_reconstruction(original, recovered)
            recovered.write_bytes(expected[:-1])
            with self.assertRaises(ValueError):
                build.verify_reconstruction(original, recovered)
            # A tail that overlaps a LOAD, has storage semantics, or names a
            # different note cannot use the pinned omission rule.
            for offset, fmt, replacement in ((96, '<Q', 296), (220, '<I', 1),
                                              (224, '<Q', 8), (284, '<I', 0x00554e47)):
                bad = bytearray(value); struct.pack_into(fmt, bad, offset, replacement)
                if offset == 96:
                    struct.pack_into('<Q', bad, 104, replacement)  # valid larger LOAD, overlapping the note
                original.write_bytes(bad); recovered.write_bytes(expected)
                with self.subTest(header_offset=offset), self.assertRaises(ValueError):
                    build.verify_reconstruction(original, recovered)

    def test_real_ps5_target_emits_unwind_records(self):
        compiler = shutil.which('clang-18') or shutil.which('clang')
        readelf = shutil.which('readelf')
        if not compiler or not readelf:
            self.skipTest('Clang and readelf are required for the compile-only target check')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'original.c'; obj = root / 'original.o'
            source.write_text('extern void original_external(void);\n'
                              'long original_worker(long value) { original_external(); return value + 1; }\n')
            subprocess.run([compiler, '-target', 'x86_64-sie-ps5', *build.WORKER_FLAGS,
                            '-c', str(source), '-o', str(obj)], check=True, capture_output=True, text=True)
            frames = subprocess.run([readelf, '--debug-dump=frames', str(obj)],
                                    check=True, capture_output=True, text=True).stdout
            self.assertIn(' CIE', frames)
            self.assertRegex(frames, r'FDE .*pc=')

    def test_only_extent_changes_and_exact_extraction_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'before.self'; target = root / 'after.self'
            value = bytearray(b'\x4f\x15\x3d\x1d' + bytes(range(4, 120)))
            struct.pack_into('<Q', value, 16, 96); source.write_bytes(value)
            class Converter:
                bad_digest = False
                changed_extract = False
                failed = False
                def run(self, *args):
                    if self.failed:
                        raise ValueError('converter failed')
                    if '--inspect' in args:
                        digest = '0' * 64 if self.bad_digest else hashlib.sha256(elf(0xFE10)).hexdigest()
                        return f'container: signed, plaintext\nintegrity: valid\ndigest: {digest}\n'
                    output = Path(args[-1])
                    data = elf(0xFE10)
                    if self.changed_extract and '.after.' in output.name:
                        data += b'changed'
                    output.write_bytes(data)
                    return ''
            converter = Converter()
            result = build.streamable_self(source, target, 'converter', converter)
            self.assertEqual(result['stream_extent'], 120)
            final = target.read_bytes()
            self.assertEqual(final[:16], value[:16]); self.assertEqual(final[24:], value[24:])
            self.assertEqual(struct.unpack_from('<Q', final, 16)[0], len(final))
            for field in ('bad_digest', 'changed_extract', 'failed'):
                with self.subTest(field=field):
                    setattr(converter, field, True)
                    with self.assertRaises(ValueError):
                        build.streamable_self(source, target, 'converter', converter)
                    setattr(converter, field, False)
            for extent in (0, 31, 121, (1 << 64) - 1):
                struct.pack_into('<Q', value, 16, extent); source.write_bytes(value)
                with self.assertRaisesRegex(ValueError, 'declared extent'):
                    build.streamable_self(source, target, 'converter', converter)

    def test_exact_kernel_function_closure_and_original_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); linked = root / 'worker.elf'; linked.write_bytes(elf(3))
            sdk = root / 'sdk'; (sdk / 'target/lib').mkdir(parents=True)
            provider = sdk / 'target/lib/libkernel.so'; provider.write_bytes(b'synthetic provider identity')
            class Analyzer:
                needed = 'libkernel.sprx'
                imports = set(build.IMPORTS)
                kind = 'FUNC'
                binding = 'GLOBAL'
                entry = '80'
                initialization = ''
                instruction = 'retq'
                copy_instruction = 'retq'
                sections = ('  [ 2] .eh_frame_hdr PROGBITS 00004000 004000 000024 00 A 0 0 4\n'
                            '  [ 3] .eh_frame X86_64_UNWIND 00004028 004028 000040 00 A 0 0 8\n')
                failed = False
                def run(self, *args):
                    if self.failed:
                        raise ValueError('analyzer failed')
                    path = Path(args[-1])
                    if '--section-headers' in args:
                        return self.sections
                    if '-dW' in args:
                        return (f'Shared library: [{self.needed}]\n' if path == linked else
                                'Library soname: [libkernel.sprx]\n')
                    if '--dyn-syms' in args:
                        return ''.join(f'{i}: 0 0 {self.kind if path == linked else "FUNC"} '
                                       f'{self.binding} DEFAULT {"UND" if path == linked else "1"} {name}\n'
                                       for i, name in enumerate(sorted(self.imports), 1))
                    if '-sW' in args:
                        return f'1: {self.entry} 1 FUNC GLOBAL DEFAULT 1 _start\n' + self.initialization
                    return (f'00000080 <_start>:\n 80: {self.instruction}\n'
                            f'00000090 <memcpy>:\n 90: {self.copy_instruction}\n'
                            '000000a0 <memset>:\n a0: retq\n000000b0 <memcmp>:\n b0: retq\n')
            analyzer = Analyzer()
            self.assertEqual(build.validate_link(linked, sdk, root, analyzer)['imports'], sorted(build.IMPORTS))
            with self.assertRaises(ValueError):
                build.validate_link(linked, sdk, root, analyzer, 'fd')
            analyzer.imports = set(build.FD_IMPORTS)
            self.assertEqual(build.validate_link(linked, sdk, root, analyzer, 'fd')['imports'], sorted(build.FD_IMPORTS))
            with self.assertRaises(ValueError):
                build.validate_link(linked, sdk, root, analyzer, 'hello')
            for forbidden in ('__error', 'bind', 'listen', 'accept', 'unlink', '__patch_init'):
                analyzer.imports = build.FD_IMPORTS | {forbidden}
                with self.subTest(forbidden=forbidden), self.assertRaises(ValueError):
                    build.validate_link(linked, sdk, root, analyzer, 'fd')
            analyzer.imports = set(build.IMPORTS)
            with self.assertRaises(ValueError):
                build.validate_link(linked, sdk, root, analyzer, 'peer-exit')
            analyzer.imports = set(build.PEER_IMPORTS)
            self.assertEqual(build.validate_link(linked, sdk, root, analyzer, 'peer-exit')['imports'], sorted(build.PEER_IMPORTS))
            # Ordinary AF_UNIX setup requires close-on-exec and SO_NBIO
            # readback; inherited stdio still uses fcntl.
            for missing in ('ioctl', 'fcntl', 'getsockopt'):
                analyzer.imports = build.PEER_IMPORTS - {missing}
                with self.subTest(peer_missing=missing), self.assertRaises(ValueError):
                    build.validate_link(linked, sdk, root, analyzer, 'peer-exit')
            for other_mode, expected in (('hello', build.IMPORTS), ('fd', build.FD_IMPORTS)):
                for extra in ('ioctl', 'getsockopt'):
                    analyzer.imports = expected | {extra}
                    with self.subTest(mode=other_mode, extra=extra), self.assertRaises(ValueError):
                        build.validate_link(linked, sdk, root, analyzer, other_mode)
            for forbidden in ('__error', 'kqueue', 'kevent', 'sysctl', 'socketpair', 'shutdown', '__patch_init'):
                analyzer.imports = build.PEER_IMPORTS | {forbidden}
                with self.subTest(peer_forbidden=forbidden), self.assertRaises(ValueError):
                    build.validate_link(linked, sdk, root, analyzer, 'peer-exit')
            analyzer.imports = set(build.SERVICE_IMPORTS)
            self.assertEqual(build.validate_link(linked, sdk, root, analyzer, 'service')['imports'], sorted(build.SERVICE_IMPORTS))
            for missing in build.SERVICE_IMPORTS:
                analyzer.imports = build.SERVICE_IMPORTS - {missing}
                with self.subTest(service_missing=missing), self.assertRaises(ValueError):
                    build.validate_link(linked, sdk, root, analyzer, 'service')
            for forbidden in ('fcntl', 'ioctl', 'read', 'write', 'setsockopt', '__error', 'socket', 'socketpair', 'sceSystemServiceAddLocalProcess'):
                analyzer.imports = build.SERVICE_IMPORTS | {forbidden}
                with self.subTest(service_extra=forbidden), self.assertRaises(ValueError):
                    build.validate_link(linked, sdk, root, analyzer, 'service')
            analyzer.imports = set(build.IMPORTS)
            for field, bad in (('needed', 'libkernel_web.sprx'), ('imports', build.IMPORTS | {'__error'}),
                               ('imports', build.IMPORTS - {'_exit'}), ('kind', 'OBJECT'), ('binding', 'LOCAL'),
                               ('entry', '81'), ('initialization', '__patch_init'), ('instruction', 'syscall'),
                               ('sections', ''),
                               ('sections', analyzer.sections.splitlines()[0]),
                               ('sections', analyzer.sections.splitlines()[1]),
                               ('sections', analyzer.sections.replace('000040 00 A', '000000 00 A')),
                               ('sections', analyzer.sections + analyzer.sections),
                               ('copy_instruction', 'callq 90 <memcpy>'), ('failed', True)):
                with self.subTest(field=field, value=bad):
                    old = getattr(analyzer, field); setattr(analyzer, field, bad)
                    with self.assertRaises(ValueError):
                        build.validate_link(linked, sdk, root, analyzer)
                    setattr(analyzer, field, old)


if __name__ == '__main__':
    unittest.main()
