#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Executable acceptance controls with original report/ELF/SELF/tool fixtures."""
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prx_check", ROOT / "tools/check_wine_prx_build.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def binary(kind=3):
    value = bytearray(224)
    value[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", value, 16, kind, 62, 1)
    struct.pack_into("<Q", value, 32, 64)
    struct.pack_into("<HHH", value, 52, 64, 56, 2)
    struct.pack_into("<IIQQQQQQ", value, 64, 1, 5, 192, 0, 0, 16, 16, 16)
    struct.pack_into("<IIQQQQQQ", value, 120, 1, 6, 208, 0x1000, 0, 16, 32, 16)
    value[192] = 0xc3
    return bytes(value)


class Fixture:
    def __init__(self, root):
        self.work, self.sdk, self.foundation, self.llvm, self.output = [root / p for p in
                ("work", "sdk", "foundation", "llvm", "evidence")]
        self.wine, self.pin, self.patches = "a" * 40, "b" * 40, ["0100-fixture.patch"]
        self.mode = "valid"
        self.forbidden = "libkernel_web.sprx"
        self.system_soname = "libkernel.sprx"
        provider = self.sdk / "target/lib/libkernel.so"
        provider.parent.mkdir(parents=True)
        provider.write_bytes(binary())
        self.report = {"schema": 1, "wine_commit": self.wine, "patches": self.patches,
                       "sources": {"prx_foundation": self.pin}, "tls_configured": True,
                       "tls": {"schema": "pw-tls-runtime/1"}, "errors": [], "targets": {},
                       "pe": {}, "prx": {"status": "0", "modules": {}}}
        for target in [f"dlls/{n}/{n}.so" for n in check.UNIX] + ["server/wineserver"]:
            path = self.write("build/" + target, binary())
            self.report["targets"][target] = {"built": True, "bytes": path.stat().st_size, "sha256": check.sha(path)}
        for arch in ("i386", "x86_64"):
            for name in check.PE + (("wow64",) if arch == "x86_64" else ()):
                target = f"{arch}-windows/{name}.dll"
                self.report["pe"][target] = check.sha(self.write("pe/" + target, b"synthetic PE fixture"))
        for name in check.MODULES:
            self.write(f"prx/{name}.shared.elf", binary() + name.encode())
            self.write(f"prx/{name}.elf", binary(0xfe18))
            container = struct.pack("<I", 0x1d3d154f) + b"synthetic container" + bytes(64)
            path = self.write(f"prx/sce_module/{name}.prx", container)
            entry = {"built": True, "bytes": len(container), "sha256": check.sha(path), "needed": self.needed(name)}
            entry.update({field: [] for field in (*check.DIAGNOSTICS, "data_imports")})
            self.report["prx"]["modules"][name] = entry
        self.write("source/dlls/secur32/schannel_gnutls.c", b"LOAD_FUNCPTR(gnutls_handshake)\n")
        self.write("source/dlls/crypt32/unixlib.c", b"LOAD_FUNCPTR(gnutls_global_init)\n")

    def write(self, name, contents):
        path = self.work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        return path

    def needed(self, name):
        return [self.system_soname] + (["ntdll.prx"] if name == "secur32" else [])

    def run(self, argv, **kwargs):
        command, name = Path(argv[0]).name, Path(argv[-1]).name.split(".")[0]
        output, code = "", 0
        if command == "git":
            output = self.pin if Path(argv[2]) == self.foundation else self.wine
        elif command == "llvm-readelf":
            if "--dyn-syms" in argv:
                exports = ["module_start", "NtClose"]
                if name == "secur32": exports += ["__wine_unix_call_funcs", "__wine_unix_call_wow64_funcs"]
                if name == "libgnutls": exports += ["gnutls_handshake", "gnutls_global_init"]
                if self.mode == "missing-export" and name == "libgnutls": exports.remove("gnutls_handshake")
                output = "\n".join(f"{i}: 00000128 1 FUNC GLOBAL DEFAULT 1 {symbol}" for i, symbol in enumerate(exports, 1))
                output += "\n9: 00000000 0 FUNC GLOBAL DEFAULT UND malloc\n"
                if self.mode == "unresolved": output += "10: 0 0 FUNC GLOBAL DEFAULT UND missing_import\n"
                if self.mode == "data-import": output += "11: 0 0 OBJECT GLOBAL DEFAULT UND malloc\n"
                if Path(argv[-1]).parent == self.sdk / "target/lib":
                    binding, visibility = ("LOCAL", "DEFAULT") if self.mode == "private-provider" else ("GLOBAL", "DEFAULT")
                    if self.mode == "hidden-provider": visibility = "HIDDEN"
                    output = f"1: 00000128 1 FUNC {binding} {visibility} 1 malloc\n"
            elif "-d" in argv:
                output = "\n".join(f"Shared library: [{lib}]" for lib in self.needed(name))
                if self.mode == "forbidden": output += f"\nShared library: [{self.forbidden}]"
                soname = self.system_soname if Path(argv[-1]).parent == self.sdk / "target/lib" else name + ".prx"
                if self.mode == "wrong-soname": soname = "wrong.sprx"
                if self.mode == "wrong-own-soname" and name == "wineps5": soname = "wrong-module.prx"
                output += f"\nLibrary soname: [{soname}]"
            else: output = "synthetic header inspection\n"
        elif command == "llvm-nm":
            output = "malloc T 128 1\nNtClose T 129 1\n"
        elif command == "llvm-objdump":
            output = "00000000 <module_start>:\n 0: retq\n"
            if self.mode == "syscall": output += " 1: syscall\n"
        elif command == "ps5-native-tool":
            if "--inspect" in argv:
                output = "container: signed, plaintext\nintegrity: valid\n"
                if self.mode == "invalid-integrity": output = output.replace("valid", "INVALID")
                if self.mode == "unsigned-inspection": output = "container: unsigned ELF\n"
                if self.mode == "encrypted": output = output.replace("plaintext", "encrypted")
            else:
                original = Path(argv[argv.index("--file") + 1]).stem
                value = bytearray((self.work / f"prx/{original}.elf").read_bytes())
                value[7] = 9  # documented default OSABI normalization
                if self.mode == "changed-load": value[-1] ^= 1
                for mode, offset in (("changed-entry", 24), ("changed-address", 80),
                                     ("changed-memory", 104), ("changed-alignment", 112)):
                    if self.mode == mode: struct.pack_into("<Q", value, offset, 32)
                Path(argv[-1]).write_bytes(value)
        else:
            raise AssertionError(argv)
        if command.startswith("llvm-") and self.mode == "analyzer-error": code, output = 23, ""
        if command.startswith("llvm-") and self.mode == "empty-analysis": output = ""
        return subprocess.CompletedProcess(argv, code, output, "synthetic analyzer error" if code else "")

    def validate(self):
        self.write("report.json", json.dumps(self.report).encode())
        with patch.object(check.subprocess, "run", side_effect=self.run):
            return check.validate(self.work, self.sdk, self.foundation, self.llvm, self.output,
                                  self.wine, self.pin, self.patches)


class DataFixture(Fixture):
    """Only four documented system globals, with real ELF-style symbol indices."""
    SYMBOLS = ("__isthreaded", "__stderrp", "__stdoutp", "environ")

    def __init__(self, root, defect=""):
        self.consumer = "wowprospero" if defect.startswith("app-shadow") else "ntdll"
        self.defect = defect
        super().__init__(root)
        (self.sdk / "target/lib/libSceLibcInternal.so").write_bytes(binary() + b"libc")
        kind = "OBJECT" if defect not in {"consumer-func", "consumer-notype"} else "FUNC"
        self.report["prx"]["modules"][self.consumer]["data_imports"] = sorted(self.SYMBOLS) if kind == "OBJECT" else []
        if defect == "unknown-data":
            self.report["prx"]["modules"][self.consumer]["data_imports"].append("unknown_data")

    def needed(self, name):
        return (["ntdll.prx"] if name in {"secur32", "wowprospero"} else []) + ["libSceLibcInternal.sprx", "libkernel.sprx"]

    def run(self, argv, **kwargs):
        result = super().run(argv, **kwargs)
        path, command = Path(argv[-1]), Path(argv[0]).name
        name = path.name.split(".")[0]
        output = result.stdout
        if command == "llvm-readelf":
            if "-d" in argv and path.parent == self.sdk / "target/lib":
                output = f"Library soname: [{name}.sprx]\n"
            if "--dyn-syms" in argv:
                if path.parent == self.sdk / "target/lib":
                    symbols = self.SYMBOLS[:-1] if name == "libSceLibcInternal" else self.SYMBOLS[-1:]
                    if self.defect == "wrong-provider":
                        symbols = () if name == "libSceLibcInternal" else self.SYMBOLS
                    kind = "FUNC" if self.defect == "provider-func" else "NOTYPE" if self.defect == "provider-notype" else "OBJECT"
                    output = "1: 00000128 1 FUNC GLOBAL DEFAULT 1 malloc\n" + "\n".join(
                        f"{i}: 00000128 0 {kind} GLOBAL DEFAULT 1 {symbol}" for i, symbol in enumerate(symbols, 2))
                elif name == self.consumer:
                    kind = "FUNC" if self.defect == "consumer-func" else "NOTYPE" if self.defect == "consumer-notype" else "OBJECT"
                    output += "\n" + "\n".join(f"{i}: 00000000 0 {kind} GLOBAL DEFAULT UND {symbol}"
                                               for i, symbol in enumerate(self.SYMBOLS, 12))
                    if self.defect == "unknown-data": output += "\n30: 0 0 OBJECT GLOBAL DEFAULT UND unknown_data\n"
                elif name == "ntdll" and self.defect.startswith("app-shadow"):
                    kind = "FUNC" if self.defect == "app-shadow-func" else "OBJECT"
                    output += f"\n30: 00000128 0 {kind} GLOBAL DEFAULT 1 __stderrp\n"
            if "-r" in argv:
                if self.defect == "reloc-tool-failure":
                    return subprocess.CompletedProcess(argv, 31, "", "synthetic relocation analyzer failure")
                output = "Relocation section '.rela.dyn':\n"
                for i, symbol in enumerate(self.SYMBOLS, 12):
                    reloc = "R_X86_64_64" if symbol == "environ" else "R_X86_64_GLOB_DAT"
                    if self.defect.startswith("reloc-type:"): reloc = self.defect.split(":", 1)[1]
                    target = 0x1000 + (i - 12) * 8
                    if self.defect == "readonly-write": target = 0
                    if self.defect == "outside-write": target = 0x9000
                    if self.defect == "straddling-write": target = 0x101c
                    index = 99 if self.defect == "wrong-index" else i
                    addend = "8" if self.defect == "nonzero-addend" else "0"
                    code = 1 if reloc == "R_X86_64_64" else 6
                    if self.defect == "wrong-reloc-info": code = 99
                    output += f"{target:016x} {((index << 32) | code):016x} {reloc} 0000000000000000 {symbol} + {addend}\n"
                if self.defect == "missing-relocs": output = "No relocations\n"
                if self.defect == "malformed-extra": output += "unparsed __stderrp relocation\n"
                if self.defect == "malformed-info": output += "00001000 garbage R_X86_64_GLOB_DAT 0 __stderrp + 0\n"
        return subprocess.CompletedProcess(argv, result.returncode, output, result.stderr)


class PrxBuildContracts(unittest.TestCase):
    def test_documented_system_data_has_exact_provider_type_and_relocations(self):
        with tempfile.TemporaryDirectory() as d:
            f = DataFixture(Path(d))
            result = f.validate()["modules"]["ntdll"]["system_data_imports"]
            self.assertEqual(set(result), set(DataFixture.SYMBOLS))
            for symbol, entry in result.items():
                self.assertEqual(entry["provider"], check.SYSTEM_DATA[symbol])
                self.assertTrue(entry["relocations"])

    def test_system_data_exceptions_do_not_waive_hostile_imports(self):
        defects = ("app-shadow-object", "app-shadow-func", "wrong-provider", "provider-func", "provider-notype",
                   "consumer-func", "consumer-notype", "unknown-data", "missing-relocs", "malformed-extra",
                   "malformed-info", "wrong-index", "wrong-reloc-info", "nonzero-addend", "readonly-write", "outside-write",
                   "straddling-write", "reloc-tool-failure", "reloc-type:R_X86_64_COPY", "reloc-type:R_X86_64_JUMP_SLOT",
                   "reloc-type:R_X86_64_DTPMOD64", "reloc-type:R_X86_64_TPOFF64", "reloc-type:R_X86_64_32")
        for defect in defects:
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as d:
                f = DataFixture(Path(d), defect)
                with self.assertRaises(ValueError):
                    f.validate()

    def test_complete_build_is_checked(self):
        with tempfile.TemporaryDirectory() as d:
            f = Fixture(Path(d))
            result = f.validate()
            self.assertEqual(set(result["modules"]), set(check.MODULES))
            self.assertGreater(len(list(f.output.glob("*-tool.log"))), 80)

    def test_cli_also_requires_tls_runtime_provenance(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            arguments = ["check_wine_prx_build.py"]
            for name in ("work", "sdk", "foundation", "llvm-bindir", "output"):
                arguments.extend(("--" + name, str(root / name)))
            with patch.object(sys, "argv", arguments), patch.object(check, "validate", return_value={}), \
                    patch.object(check.Commands, "run", side_effect=ValueError("invalid TLS runtime manifest")):
                self.assertEqual(check.main(), 1)
            self.assertFalse((root / "output/checks.json").exists())

    def test_false_success_analyzers_and_containers_are_rejected(self):
        for mode in ("missing-export", "unresolved", "data-import", "forbidden", "syscall", "invalid-integrity",
                     "unsigned-inspection", "encrypted", "changed-load", "analyzer-error", "empty-analysis",
                     "private-provider", "hidden-provider", "wrong-soname", "changed-entry", "changed-address", "changed-memory", "changed-alignment"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                f = Fixture(Path(d))
                f.mode = mode
                if mode == "forbidden":
                    for entry in f.report["prx"]["modules"].values(): entry["needed"].append("libkernel_web.sprx")
                with self.assertRaises(ValueError): f.validate()

    def test_provider_aliases_and_ambiguity_use_actual_soname(self):
        with tempfile.TemporaryDirectory() as d:
            f = Fixture(Path(d))
            original = f.sdk / "target/lib/libkernel.so"
            actual = original.with_name("different-installed-name.so")
            original.rename(actual)
            original.symlink_to(actual.name)
            original.with_name("libkernel_stub_weak.so").symlink_to(actual.name)
            self.assertEqual(set(f.validate()["modules"]), set(check.MODULES))
            copy = original.with_name("distinct-provider.so")
            copy.write_bytes(actual.read_bytes())
            self.assertEqual(set(f.validate()["modules"]), set(check.MODULES))
            copy.write_bytes(actual.read_bytes() + b"different provider bytes")
            with self.assertRaisesRegex(ValueError, "ambiguous distinct providers"):
                f.validate()
        with tempfile.TemporaryDirectory() as d:
            f = Fixture(Path(d))
            f.system_soname = "libkernel_web.sprx"
            for name, entry in f.report["prx"]["modules"].items(): entry["needed"] = f.needed(name)
            # The filename remains harmless-looking libkernel.so.
            with self.assertRaisesRegex(ValueError, "forbidden import provider"):
                f.validate()

    def test_unreferenced_module_must_keep_its_own_soname(self):
        with tempfile.TemporaryDirectory() as d:
            f = Fixture(Path(d))
            f.mode = "wrong-own-soname"
            with self.assertRaisesRegex(ValueError, "own SONAME"):
                f.validate()

    def test_all_forbidden_provider_suffixes_are_rejected(self):
        for stem in check.FORBIDDEN:
            for suffix in (".so", ".sprx", ".prx"):
                with self.subTest(stem=stem, suffix=suffix), tempfile.TemporaryDirectory() as d:
                    f = Fixture(Path(d))
                    f.mode, f.forbidden = "forbidden", stem + suffix
                    for entry in f.report["prx"]["modules"].values(): entry["needed"].append(f.forbidden)
                    with self.assertRaisesRegex(ValueError, "forbidden import provider"):
                        f.validate()

    def test_report_and_artifact_omissions_are_rejected(self):
        for case in ("skipped", "tls-off", "missing-module", "missing-both", "missing-entry", "hash", "diagnostic",
                     "missing-diagnostic", "empty-module", "plain-elf", "bad-elf", "bad-segment", "missing-pe"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as d:
                f = Fixture(Path(d))
                entry = f.report["prx"]["modules"]["libgnutls"]
                module = f.work / "prx/sce_module/libgnutls.prx"
                if case == "skipped": f.report["prx"]["status"] = "skipped: no converter"
                elif case == "tls-off": f.report["tls_configured"] = False
                elif case in ("missing-module", "missing-both"):
                    module.unlink()
                    if case == "missing-both": (f.work / "prx/sce_module/secur32.prx").unlink()
                elif case == "missing-entry": del f.report["prx"]["modules"]["libgnutls"]
                elif case == "hash": entry["sha256"] = "0" * 64
                elif case == "diagnostic": entry["raw_syscalls"] = ["unexpected"]
                elif case == "missing-diagnostic": del entry["errors"]
                elif case == "empty-module": module.write_bytes(b"")
                elif case == "plain-elf":
                    module.write_bytes(binary(0xfe18)); entry.update(bytes=module.stat().st_size, sha256=check.sha(module))
                elif case in ("bad-elf", "bad-segment"):
                    target = f.work / "prx/libgnutls.elf"
                    value = bytearray(target.read_bytes())
                    struct.pack_into("<Q" if case == "bad-segment" else "<H", value, 96 if case == "bad-segment" else 16, 999999 if case == "bad-segment" else 2)
                    target.write_bytes(value)
                elif case == "missing-pe": (f.work / "pe/i386-windows/ntdll.dll").unlink()
                with self.assertRaises((ValueError, KeyError)): f.validate()


if __name__ == "__main__":
    unittest.main()
