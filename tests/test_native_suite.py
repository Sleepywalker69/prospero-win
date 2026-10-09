#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Original byte/filesystem controls. No native executable or socket runs."""
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check_native_suite as check
from native_probe_elf import Elf, extract_self, nid, sha

CALL = "sceSystemServiceAddLocalProcess"


def elf_fixture(converted=False, bss=False, zero_load=False):
    strings = bytearray(b"\0")
    def string(value):
        at = len(strings); strings.extend(value.encode() + b"\0"); return at
    needed = string("libSceSystemService.prx" if converted else "libSceSystemService.sprx")
    symbol = string(nid(CALL) + "#A#B" if converted else CALL)
    module = string("libSceSystemService")
    version_at = 0xD08 if zero_load else 0xD00
    data = bytearray(version_at + 4)
    data[:8] = b"\x7fELF\x02\x01\x01\x09"
    struct.pack_into("<HHIQQ", data, 16, 0xFE10 if converted else 3, 62, 1, 0x1000, 64)
    tags = [(5, 0x2100), (10, len(strings)), (6, 0x2300), (11, 24), (0x6100003F, 48),
            (7, 0x2400), (8, 24), (9, 24), (1, needed), (23, 0x2418), (2, 0), (20, 7)]
    if converted:
        tags += [(0x61000045, (1 << 48) | (1 << 32) | module),
                 (0x61000049, (1 << 32) | module)]
    tags.append((0, 0))
    programs = [(1, 1, 0x400, 0x1000, 0x1000, 16, 16, 8),
                (1, 6, 0x500, 0x2000, 0x2000, 0x800, 0x800, 8),
                (2, 6, 0x500, 0x2000, 0x2000, len(tags) * 16, len(tags) * 16, 8),
                (0x6FFFFF01, 0, version_at, 0, 0, 4, 4, 1)]
    if zero_load:
        programs.append((1, 6, 0xD00, 0x3000, 0x3000, 8, 8, 8))
    if bss:
        programs.append((1, 6, version_at, 0x4000, 0x4000, 0, 4096, 8))
    struct.pack_into("<HHH", data, 52, 64, 56, len(programs))
    for index, p in enumerate(programs): struct.pack_into("<IIQQQQQQ", data, 64 + index * 56, *p)
    data[0x400:0x410] = b"\x90" * 16
    for index, tag in enumerate(tags): struct.pack_into("<qQ", data, 0x500 + index * 16, *tag)
    data[0x600:0x600 + len(strings)] = strings
    struct.pack_into("<IBBHQQ", data, 0x800 + 24, symbol, 0x12, 0, 0, 0, 0)
    struct.pack_into("<QQq", data, 0x900, 0x27F0, (1 << 32) | 6, 0)
    data[version_at:] = b"VERS"
    return bytes(data)


def self_fixture(data):
    count = struct.unpack_from("<H", data, 56)[0]
    programs = [struct.unpack_from("<IIQQQQQQ", data, 64 + i * 56) for i in range(count)]
    selected = [(i, p) for i, p in enumerate(programs) if p[0] == 1 and p[5]]
    header_size = 64 + 56 * count
    elf_at = 32 + len(selected) * 32
    extended = (elf_at + header_size + 15) & ~15
    start = (extended + 64 + 15) & ~15
    size = start + sum(p[5] for _, p in selected)
    result = bytearray(size + 4)
    result[:4] = b"\x4f\x15\x3d\x1d"
    struct.pack_into("<Q", result, 16, size)
    struct.pack_into("<H", result, 24, len(selected))
    result[elf_at:elf_at + header_size] = data[:header_size]
    result[extended + 32:extended + 64] = bytes.fromhex(sha(data))
    cursor = start
    for index, (program, p) in enumerate(selected):
        struct.pack_into("<QQQQ", result, 32 + index * 32, 0x800 | (program << 20), cursor, p[5], p[5])
        result[cursor:cursor + p[5]] = data[p[2]:p[2] + p[5]]
        cursor += p[5]
    result[cursor:] = b"VERS"
    return bytes(result)


def graph():
    return {"libSceSystemService.sprx": {"soname": "libSceSystemService.sprx", "sha256": "a" * 64,
                                        "definitions": {CALL: "FUNC"}}}


class NativeSuiteTests(unittest.TestCase):
    def test_pinned_nid_and_static_elf_binding(self):
        self.assertEqual(nid("sceSystemServiceHideSplashScreen"), "Vo5V8KAwCmk")
        result = check.inspect_bindings(Elf(elf_fixture()), Elf(elf_fixture(True)), graph(), {CALL})
        self.assertEqual(result[CALL]["provider"], "libSceSystemService.sprx")

    def test_wrong_function_types_and_missing_provider(self):
        for kind in ("OBJECT", "TLS", "NOTYPE"):
            p = graph(); p["libSceSystemService.sprx"]["definitions"][CALL] = kind
            with self.assertRaises(ValueError): check.inspect_bindings(Elf(elf_fixture()), Elf(elf_fixture(True)), p, {CALL})
        with self.assertRaises(ValueError): check.inspect_bindings(Elf(elf_fixture()), Elf(elf_fixture(True)), {}, {CALL})
        a, b = Elf(elf_fixture()), Elf(elf_fixture(True))
        a.symbols[1]["type"] = b.symbols[1]["type"] = 1
        with self.assertRaises(ValueError): check.inspect_bindings(a, b, graph(), {CALL})

    def test_wrong_first_provider_and_missing_required_import(self):
        a, b = Elf(elf_fixture()), Elf(elf_fixture(True))
        a.needed.insert(0, "shadow.sprx"); b.needed.insert(0, "shadow.prx")
        p = graph(); p["shadow.sprx"] = {"sha256": "b" * 64, "definitions": {CALL: "FUNC"}}
        with self.assertRaises(ValueError): check.inspect_bindings(a, b, p, {CALL})
        with self.assertRaises(ValueError): check.inspect_bindings(Elf(elf_fixture()), Elf(elf_fixture(True)), graph(), {"missing"})

    def test_wrong_nid_provider_id_and_relocation(self):
        for name in ("wrong#B#B", nid(CALL) + "#C#B", nid(CALL) + "#B#?", nid(CALL) + "#B"):
            a, b = Elf(elf_fixture()), Elf(elf_fixture(True)); b.symbols[1]["name"] = name
            with self.assertRaises(ValueError): check.inspect_bindings(a, b, graph(), {CALL})
        a, b = Elf(elf_fixture()), Elf(elf_fixture(True)); b.relocations[0]["addend"] = 1
        with self.assertRaises(ValueError): check.inspect_bindings(a, b, graph(), {CALL})

    def test_self_roundtrip_and_bss_without_file_record(self):
        for bss, zero in ((False, False), (True, False), (False, True)):
            data = elf_fixture(True, bss, zero)
            self.assertEqual(extract_self(self_fixture(data)), data)

    def test_self_rejects_missing_zero_load_and_digest_mutation(self):
        data = bytearray(self_fixture(elf_fixture(True, zero_load=True)))
        struct.pack_into("<Q", data, 32 + 2 * 32, 4 << 20)
        with self.assertRaisesRegex(ValueError, "omits a nonempty LOAD"): extract_self(bytes(data))
        data = bytearray(self_fixture(elf_fixture(True))); data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "digest"): extract_self(bytes(data))

    def test_elf_rejects_entry_alias_and_truncation(self):
        data = bytearray(elf_fixture(True)); count = struct.unpack_from("<H", data, 56)[0]
        struct.pack_into("<H", data, 56, count + 1)
        struct.pack_into("<IIQQQQQQ", data, 64 + count * 56, 1, 4, 0x401, 0x1000, 0x1000, 1, 1, 1)
        with self.assertRaisesRegex(ValueError, "ambiguous"): Elf(bytes(data))
        for cut in (0, 63, 100, 2000):
            with self.assertRaises(ValueError): Elf(elf_fixture(True)[:cut])

    def test_compiled_identity_and_embedded_image_storage(self):
        def image(data, flags=4):
            return SimpleNamespace(data=data, programs=[(1, flags, 0, 0x1000, 0x1000, len(data), len(data), 8)],
                                   offset=lambda address, size, flags: address - 0x1000)
        self.assertEqual(check.compiled_identity(image(b"xxcommit\0yy"), "commit")["addresses"], [0x1002])
        for value in (image(b"old\0"), image(b"commit-dirty\0"), image(b"commit\0", 6)):
            with self.assertRaises(ValueError): check.compiled_identity(value, "commit")
        self.assertEqual(check.embedded_image(image(b"abcWORKERxyz"), b"WORKER")["address"], 0x1003)
        for value in (image(b"WORKERWORKER"), image(b"WORKER", 6), image(b"missing")):
            with self.assertRaises(ValueError): check.embedded_image(value, b"WORKER")

    def test_exact_seven_roles_modes_and_changed_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "PPSA99995-native-suite"; root.mkdir()
            for role, name in check.ROLES.items():
                path = root / name; path.parent.mkdir(exist_ok=True); path.write_bytes(role.encode())
                path.chmod(int(check.ROLE_MODES[role], 8))
            measured = check.role_records(root)
            self.assertEqual(len(measured), 7)
            self.assertEqual(measured["lapy"]["mode"], "0644")
            self.assertTrue(all(v["path"].startswith("PPSA99995/") for v in measured.values()))
            (root / "native-service.self").write_bytes(b"mixed")
            self.assertNotEqual(measured, check.role_records(root))
            (root / "lapy.elf").chmod(0o755)
            with self.assertRaises(ValueError): check.role_records(root)

    def test_mixed_worker_sources_modes_and_claims(self):
        sources = {"original.c": "a" * 64}; build_id = "b" * 40
        original = {"schema": "pw-native-service-build/1", "mode": "service", "sources": sources,
                    "build_id": build_id, "foundation_commit": check.worker_builder.FOUNDATION,
                    "console_execution_verified": False, "windows_process_support": False,
                    "platform_authentication_verified": False}
        check.worker_identity(original, "service", sources, build_id)
        for key, value in (("schema", "pw-native-child-build/1"), ("mode", "peer-exit"),
                           ("sources", {"original.c": "c" * 64}), ("build_id", "d" * 40),
                           ("foundation_commit", "e" * 40), ("console_execution_verified", True)):
            item = copy.deepcopy(original); item[key] = value
            with self.assertRaises(ValueError): check.worker_identity(item, "service", sources, build_id)

    def test_default_comparison_rehashes_actual_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "child").mkdir(); (root / "default-control").mkdir()
            record = {}
            for name in ("worker.linked.elf", "worker.elf", "native-child.self"):
                data = name.encode(); record[name] = {"bytes": len(data), "sha256": sha(data)}
                for folder in ("child", "default-control"): (root / folder / name).write_bytes(data)
            (root / "default-mode-comparison.json").write_text(json.dumps(record))
            self.assertEqual(check.default_comparison(root), record)
            (root / "default-control/worker.elf").write_bytes(b"changed")
            with self.assertRaises(ValueError): check.default_comparison(root)
            (root / "child/worker.elf").write_bytes(b"changed")
            with self.assertRaises(ValueError): check.default_comparison(root)

    def test_provider_index_real_empty_directory_seam(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); sdk = root / "sdk"; (sdk / "target/lib").mkdir(parents=True)
            output = root / "out"; output.mkdir()
            commands = SimpleNamespace(run=lambda *args: self.fail("unexpected analyzer on empty tree"))
            self.assertEqual(check.index_sdk_providers(sdk, output, root, commands), {})
            self.assertTrue((output / "no-prxs").is_dir())

    def test_provider_type_and_analyzer_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "provider.so"; path.write_bytes(b"fixture provider")
            lines = ["Library soname: [libSceSystemService.sprx]", "1: 10 0 FUNC GLOBAL DEFAULT 5 " + CALL]
            commands = SimpleNamespace(run=lambda *args: lines[0] if "-dW" in args else lines[1])
            self.assertEqual(check.provider(path, path.parent, commands)["definitions"][CALL], "FUNC")
            lines[0] = "no soname"
            with self.assertRaises(ValueError): check.provider(path, path.parent, commands)
            def failure(*args): raise ValueError("analyzer failed")
            with self.assertRaisesRegex(ValueError, "analyzer failed"):
                check.provider(path, path.parent, SimpleNamespace(run=failure))

    def test_sdk_archive_tree_modes_and_commit(self):
        commit = "a" * 40
        content = b"one\n"
        blob = hashlib.sha1(b"blob 4\0" + content).digest()
        raw_tree = b"100644 README\0" + blob
        expected = hashlib.sha1(b"tree " + str(len(raw_tree)).encode() + b"\0" + raw_tree).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sdk.tar.gz"
            def archive(mode=0o644, name="README", repeated=False):
                with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": commit}) as stream:
                    for _ in range(2 if repeated else 1):
                        item = tarfile.TarInfo(name); item.mode = mode; item.size = len(content)
                        stream.addfile(item, io.BytesIO(content))
            archive(); self.assertEqual(check.source_archive(path, commit, expected)["tree"], expected)
            with self.assertRaises(ValueError): check.source_archive(path, "b" * 40, expected)
            for args in ((0o755, "README", False), (0o644, "../README", False), (0o644, "README", True)):
                archive(*args)
                with self.assertRaises(ValueError): check.source_archive(path, commit, expected)


if __name__ == "__main__":
    unittest.main()
