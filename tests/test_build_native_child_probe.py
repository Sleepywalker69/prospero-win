#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Synthetic analyzer controls for the original native worker build boundary."""
from pathlib import Path
import hashlib
import importlib.util
import struct
import sys
import tempfile
import unittest

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
                failed = False
                def run(self, *args):
                    if self.failed:
                        raise ValueError('analyzer failed')
                    path = Path(args[-1])
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
            for field, bad in (('needed', 'libkernel_web.sprx'), ('imports', build.IMPORTS | {'__error'}),
                               ('imports', build.IMPORTS - {'_exit'}), ('kind', 'OBJECT'), ('binding', 'LOCAL'),
                               ('entry', '81'), ('initialization', '__patch_init'), ('instruction', 'syscall'),
                               ('copy_instruction', 'callq 90 <memcpy>'), ('failed', True)):
                with self.subTest(field=field, value=bad):
                    old = getattr(analyzer, field); setattr(analyzer, field, bad)
                    with self.assertRaises(ValueError):
                        build.validate_link(linked, sdk, root, analyzer)
                    setattr(analyzer, field, old)


if __name__ == '__main__':
    unittest.main()
