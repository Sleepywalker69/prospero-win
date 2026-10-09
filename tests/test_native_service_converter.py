#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Pure source-copy and synthetic ELF controls; no target code is executed."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("service_converter", Path(__file__).resolve().parents[1] /
                                             "tools/native_service_converter.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture():
    data = bytearray(1024)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 0xFE10, 62, 1)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HHH", data, 52, 64, 56, 4)
    headers = [(1, 6, 0x200, 0x1000, 0x1000, 0x200, 0x200, 0x4000),
               (0x61000001, 4, 0x200, 0x1000, 0x1000, 0x60, 0x60, 8),
               (0x6474E552, 4, 0x200, 0x1000, 0x1000, 0x100, 0x100, 1),
               (2, 6, 0x300, 0x1100, 0x1100, 128, 128, 8)]
    for index, header in enumerate(headers):
        struct.pack_into("<IIQQQQQQ", data, 64 + index * 56, *header)
    struct.pack_into("<Q4sIII", data, 0x200, 0x60, b"ORBI", 5, 0x08050001, 0x02000009)
    struct.pack_into("<Q", data, 0x258, 1)
    struct.pack_into("<Q", data, 0x280, module.PRELOAD_MASK)
    for index, entry in enumerate(((7, 0x1180), (8, 24), (9, 24), (0x6FFFFFF9, 1),
                                  (23, 0x11B0), (2, 0), (20, 7), (0, 0))):
        struct.pack_into("<QQ", data, 0x300 + index * 16, *entry)
    struct.pack_into("<QQq", data, 0x380, 0x1050, 8, 0x1080)
    return data


class ServiceConverterTests(unittest.TestCase):
    def test_metadata_roundtrip(self):
        result = module.inspect_service_preload(bytes(fixture()))
        self.assertEqual(result["mask_address"], 0x1080)
        self.assertEqual(result["pointer_address"], 0x1050)
        self.assertEqual(result["preload_mask"], "0x8000000000000002")

    def test_wrong_header_layout_and_bounds(self):
        changes = [(0, b"X"), (4, b"\x01"), (18, b"\x03\x00"), (32, b"\xff" * 8),
                   (64 + 56 + 32, struct.pack("<Q", 0x58)), (0x208, b"NOPE"),
                   (0x20C, struct.pack("<I", 6)), (0x210, struct.pack("<I", 0)),
                   (0x258, bytes(8)), (0x250, struct.pack("<Q", module.PRELOAD_MASK))]
        for offset, value in changes:
            with self.subTest(offset=offset):
                data = fixture(); data[offset:offset + len(value)] = value
                with self.assertRaises(ValueError): module.inspect_service_preload(bytes(data))
        with self.assertRaises(ValueError): module.inspect_service_preload(bytes(fixture()[:700]))

    def test_relocation_type_count_pointer_and_mask(self):
        changes = [(0x388, 6), (0x388, (1 << 32) | 8), (0x380, 0x1051),
                   (0x390, -1), (0x390, 0x1081), (0x390, 0x1010),
                   (0x390, 0x1300), (0x390, 0x1170), (0x280, 0),
                   (0x338, 0), (0x338, 2), (0x318, 25), (0x328, 16)]
        for offset, value in changes:
            with self.subTest(offset=offset, value=value):
                data = fixture(); struct.pack_into("<Q", data, offset, value & (2**64 - 1))
                with self.assertRaises(ValueError): module.inspect_service_preload(bytes(data))

    def test_duplicate_pointer_and_mask_relocation(self):
        for destination in (0x1050, 0x1051, 0x1080, 0x107F):
            with self.subTest(destination=destination):
                data = fixture()
                struct.pack_into("<Q", data, 0x318, 48)
                struct.pack_into("<Q", data, 0x338, 2)
                struct.pack_into("<QQq", data, 0x398, destination, 8, 0x1080)
                with self.assertRaises(ValueError): module.inspect_service_preload(bytes(data))

    def test_jump_relocations_cannot_modify_pointer_or_mask(self):
        for destination in (0x1050, 0x104F, 0x1051, 0x1080, 0x107F, 0x1081):
            with self.subTest(destination=destination):
                data = fixture(); struct.pack_into("<Q", data, 0x358, 24)
                struct.pack_into("<QQq", data, 0x3B0, destination, (1 << 32) | 7, 0)
                with self.assertRaises(ValueError): module.inspect_service_preload(bytes(data))
        data = fixture(); struct.pack_into("<Q", data, 0x358, 24)
        struct.pack_into("<QQq", data, 0x3B0, 0x10A0, (1 << 32) | 7, 0)
        self.assertEqual(module.inspect_service_preload(bytes(data))["jump_relocation_count"], 1)

    def test_jump_table_formats_and_other_relocation_formats(self):
        changes = [(0x358, 25), (0x358, 0x10000), (0x368, 17), (0x340, 17),
                   (0x340, 36), (0x340, 0x60000011), (0x340, 7)]
        for offset, value in changes:
            with self.subTest(offset=offset, value=value):
                data = fixture(); struct.pack_into("<Q", data, offset, value)
                with self.assertRaises(ValueError): module.inspect_service_preload(bytes(data))
        data = fixture(); struct.pack_into("<Q", data, 0x358, 24)
        struct.pack_into("<Q", data, 0x348, 0x1180)
        with self.assertRaises(ValueError): module.inspect_service_preload(bytes(data))
        data = fixture(); struct.pack_into("<Q", data, 0x358, 24)
        struct.pack_into("<QQq", data, 0x3B0, 0x10A0, (1 << 32) | 5, 0)
        with self.assertRaises(ValueError): module.inspect_service_preload(bytes(data))

    def test_missing_duplicate_segments_and_mapping(self):
        for offset, fmt, value in ((64 + 56, "<I", 0),
                                   (64 + 3 * 56, "<I", 0x61000001),
                                   (68, "<I", 4),
                                   (64 + 2 * 56 + 32, "<Q", 0x80),
                                   (64 + 2 * 56 + 8, "<Q", 0x201),
                                   (0x330, "<Q", 9)):
            with self.subTest(offset=offset):
                data = fixture(); struct.pack_into(fmt, data, offset, value)
                with self.assertRaises(ValueError): module.inspect_service_preload(bytes(data))

    def test_readonly_partial_and_zero_fill_load_aliases(self):
        for address, length, stored in ((0x1080, 8, 8), (0x1084, 8, 8),
                                        (0x107C, 8, 8), (0x1080, 8, 0)):
            with self.subTest(address=address, stored=stored):
                data = fixture(); struct.pack_into("<H", data, 56, 5)
                struct.pack_into("<IIQQQQQQ", data, 64 + 4 * 56,
                                 1, 4, 0x290, address, address, stored, length, 1)
                with self.assertRaises(ValueError): module.inspect_service_preload(bytes(data))

    def test_source_hash_and_marker_guards(self):
        with self.assertRaises(ValueError): module.service_writer_bytes(b"unrecognized source")
        original = b"/* retained license */\n" + b"".join(before for before, _ in module.EDITS)
        with patch.object(module, "WRITER_SHA256", hashlib.sha256(original).hexdigest()):
            expected = b"/* retained license */\n" + b"".join(after for _, after in module.EDITS)
            self.assertEqual(module.service_writer_bytes(original), expected)
            self.assertEqual(module.service_writer_bytes(original), module.service_writer_bytes(original))
        for source in (original + module.EDITS[0][0], original.replace(module.EDITS[0][0], b"")):
            with patch.object(module, "WRITER_SHA256", hashlib.sha256(source).hexdigest()):
                with self.assertRaises(ValueError): module.service_writer_bytes(source)

    def test_existing_modes_copy_nothing_and_keep_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "original.cpp"; output = root / "copy.cpp"
            source.write_bytes(b"original mode converter bytes\n")
            before = source.read_bytes()
            for mode in ("hello", "fd", "peer-exit"):
                with self.subTest(mode=mode):
                    selected, record = module.prepare_converter_source(source, output, service=False)
                    self.assertEqual(selected, source)
                    self.assertFalse(output.exists())
                    self.assertEqual(source.read_bytes(), before)
                    self.assertEqual(record["original_sha256"], record["selected_sha256"])
            with self.assertRaises(ValueError): module.prepare_converter_source(source, output, service="false")

    def test_title_writer_requires_explicit_matching_pin(self):
        original = b"/* high-layout title writer */\n" + b"".join(before for before, _ in module.EDITS)
        digest = hashlib.sha256(original).hexdigest()
        with tempfile.TemporaryDirectory() as directory, patch.object(module, "TITLE_WRITER_SHA256", digest):
            source = Path(directory) / "original.cpp"; source.write_bytes(original)
            output = Path(directory) / "service.cpp"
            selected, record = module.prepare_converter_source(
                source, output, service=True, foundation=module.TITLE_FOUNDATION)
            self.assertEqual(selected, output)
            self.assertEqual(record["foundation_commit"], module.TITLE_FOUNDATION)
            self.assertEqual(record["original_sha256"], digest)
            self.assertEqual(record["edits"], 2)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(output.read_bytes(), module.service_writer_bytes(original, foundation=module.TITLE_FOUNDATION))
            self.assertEqual(record["selected_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
            with self.assertRaisesRegex(ValueError, "source hash"):
                module.service_writer_bytes(original)
            for foundation, service in (("unrecognized", True), (module.TITLE_FOUNDATION, False)):
                with self.assertRaisesRegex(ValueError, "selection"):
                    module.prepare_converter_source(source, output, foundation=foundation, service=service)
            with self.assertRaisesRegex(ValueError, "source hash"):
                module.service_writer_bytes(original + b"changed", foundation=module.TITLE_FOUNDATION)
        for source in (original + module.EDITS[0][0], original.replace(module.EDITS[0][0], b"")):
            with patch.object(module, "TITLE_WRITER_SHA256", hashlib.sha256(source).hexdigest()):
                with self.assertRaisesRegex(ValueError, "not unique"):
                    module.service_writer_bytes(source, foundation=module.TITLE_FOUNDATION)

    def test_service_copy_is_exclusive_and_preserves_original(self):
        original = b"/* license preserved */\n" + b"".join(before for before, _ in module.EDITS)
        with tempfile.TemporaryDirectory() as directory, patch.object(module, "WRITER_SHA256", hashlib.sha256(original).hexdigest()):
            root = Path(directory); source = root / "original.cpp"; output = root / "copy.cpp"
            source.write_bytes(original)
            selected, record = module.prepare_converter_source(source, output, service=True)
            self.assertEqual(selected, output)
            self.assertEqual(output.read_bytes(), module.service_writer_bytes(original))
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(record["selected_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
            with self.assertRaises(FileExistsError): module.prepare_converter_source(source, output, service=True)
            with self.assertRaises(ValueError): module.prepare_converter_source(source, source, service=True)
            link = root / "link.cpp"; link.symlink_to(root / "missing")
            with self.assertRaises(FileExistsError): module.prepare_converter_source(source, link, service=True)
            self.assertEqual(source.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
