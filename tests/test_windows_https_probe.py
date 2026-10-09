#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Host-only static artifact/policy regressions. Never execute the PE fixture."""
import importlib.util
from pathlib import Path
import re
import struct
import sys
import unittest

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("https_image", ROOT / "tools/inspect_windows_https_probe.py")
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)


def synthetic_pe():
    """Original inert PE-shaped bytes, used solely as parser input."""
    data = bytearray(0x1600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 3, 0, 0, 0, 0xf0, 0x22)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20b)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<I", data, opt + 56, 0x5000)
    struct.pack_into("<HH", data, opt + 68, 3, 0x160)
    struct.pack_into("<I", data, opt + 108, 16)
    struct.pack_into("<II", data, opt + 120, 0x2000, 80)
    struct.pack_into("<II", data, opt + 152, 0x4000, 12)
    for i, (name, rva, raw, size, flags) in enumerate([
        (b".text", 0x1000, 0x200, 0x200, 0x60000020),
        (b".rdata", 0x2000, 0x400, 0x1000, 0x40000040),
        (b".reloc", 0x4000, 0x1400, 0x200, 0x42000040),
    ]):
        section = opt + 0xf0 + 40 * i
        data[section:section + 8] = name.ljust(8, b"\0")
        struct.pack_into("<IIII", data, section + 8, size, rva, size, raw)
        struct.pack_into("<I", data, section + 36, flags)
    imports = [
        ("KERNEL32.dll", ["CreateThread", "WaitForSingleObject", "GetExitCodeThread", "CloseHandle",
                          "GetTickCount64", "GetCurrentProcess", "GetCurrentProcessId",
                          "TerminateProcess", "GetSystemTime"]),
        ("WINHTTP.dll", ["WinHttpOpen", "WinHttpSetTimeouts", "WinHttpSetOption", "WinHttpConnect",
                         "WinHttpOpenRequest", "WinHttpSetStatusCallback", "WinHttpSendRequest",
                         "WinHttpReceiveResponse", "WinHttpQueryHeaders", "WinHttpQueryOption", "WinHttpCloseHandle"]),
        ("CRYPT32.dll", ["CertFreeCertificateContext"]),
    ]
    cursor = 0x480
    def emit(value, alignment=1):
        nonlocal cursor
        cursor = (cursor + alignment - 1) & -alignment
        start = cursor
        data[start:start + len(value)] = value
        cursor += len(value)
        return 0x2000 + start - 0x400
    for i, (library, names) in enumerate(imports):
        library_rva = emit(library.encode() + b"\0")
        function_rvas = [emit(b"\0\0" + name.encode() + b"\0", 2) for name in names]
        thunk = emit(b"".join(struct.pack("<Q", n) for n in function_rvas) + b"\0" * 8, 8)
        struct.pack_into("<IIIII", data, 0x400 + 20 * i, thunk, 0, 0, library_rva, thunk)
    struct.pack_into("<IIHH", data, 0x1400, 0x1000, 12, 0xa008, 0)
    return data


class ArtifactContract(unittest.TestCase):
    def test_inert_complete_image(self):
        result = image.inspect(synthetic_pe())
        self.assertFalse(result["executed"])
        self.assertEqual(result["dir64_relocations"], 1)
        self.assertEqual(set(result["imports"]), {"kernel32.dll", "winhttp.dll", "crypt32.dll"})

    def test_rejects_security_relocation_and_import_mutations(self):
        mutations = {
            "relocations stripped": lambda b: struct.pack_into("<H", b, 0x96, 0x23),
            "wrong machine": lambda b: struct.pack_into("<H", b, 0x84, 0x14c),
            "wrong optional magic": lambda b: struct.pack_into("<H", b, 0x98, 0x10b),
            "missing NX": lambda b: struct.pack_into("<H", b, 0x98 + 70, 0x60),
            "missing ASLR": lambda b: struct.pack_into("<H", b, 0x98 + 70, 0x120),
            "missing high entropy": lambda b: struct.pack_into("<H", b, 0x98 + 70, 0x140),
            "empty relocations": lambda b: struct.pack_into("<II", b, 0x98 + 152, 0, 0),
            "bad relocation extent": lambda b: struct.pack_into("<I", b, 0x1404, 100),
            "wrong relocation type": lambda b: struct.pack_into("<H", b, 0x1408, 0x3008),
            "padding only": lambda b: struct.pack_into("<H", b, 0x1408, 0),
            "invalid relocation target": lambda b: struct.pack_into("<I", b, 0x1400, 0x5000),
            "unmapped import name": lambda b: struct.pack_into("<I", b, 0x40c, 0xffff0000),
            "missing IAT": lambda b: struct.pack_into("<I", b, 0x410, 0),
            "unmapped IAT": lambda b: struct.pack_into("<I", b, 0x410, 0xffff0000),
            "short IAT": lambda b: struct.pack_into("<I", b, 0x410, 0x2ff8),
            "unexpected CRT DLL": lambda b: b.__setitem__(slice(b.index(b"KERNEL32.dll"), b.index(b"KERNEL32.dll") + 12), b"ucrtbase.dll"),
            "missing WinHTTP API": lambda b: b.__setitem__(b.index(b"WinHttpSendRequest"), ord("X")),
            "delay imports": lambda b: struct.pack_into("<II", b, 0x98 + 112 + 13 * 8, 0x2200, 32),
            "truncated file": lambda b: b.__delitem__(slice(0x1400, None)),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                data = synthetic_pe()
                mutate(data)
                with self.assertRaises(ValueError):
                    image.inspect(data)

    def test_builder_keeps_link_and_static_inspection_contract(self):
        builder = (ROOT / "tools/build_windows_https_probe.ps1").read_text()
        for flag in ["/W4", "/WX", "/MT", "/FIXED:NO", "/DYNAMICBASE", "/HIGHENTROPYVA", "/NXCOMPAT"]:
            self.assertIn(flag, builder)
        self.assertIn("inspect_windows_https_probe.py", builder)
        self.assertIn("PE-VALIDATION.json", builder)
        self.assertLess(builder.index("inspect_windows_https_probe.py"), builder.index("Get-FileHash"))
        self.assertNotRegex(builder, r"(?im)^\s*&\s*\$exe\b")

    def test_fixture_retains_strict_request_policy_and_absolute_budget(self):
        source = (ROOT / "tests/fixtures/windows_https_probe.c").read_text()
        source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
        self.assertIn("WINHTTP_ACCESS_TYPE_NO_PROXY", source)
        self.assertIn('L"HEAD", L"/"', source)
        for flag in ["WINHTTP_DISABLE_REDIRECTS", "WINHTTP_DISABLE_COOKIES", "WINHTTP_DISABLE_AUTHENTICATION",
                     "WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH", "WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2"]:
            self.assertIn(flag, source)
        self.assertNotRegex(source, r"option\([^;]*WINHTTP_OPTION_SECURITY_FLAGS")
        self.assertNotRegex(source, r"\b(?:WinHttpSetCredentials|CreateProcess\w*|CertAdd\w*)\s*\(")
        self.assertIn("#define PROBE_TOTAL_MS 25000", source)
        self.assertIn("PROBE_TOTAL_MS - elapsed", source)
        self.assertGreaterEqual(source.count("elapsed >= PROBE_TOTAL_MS"), 3)
        self.assertIn("flags == expected_flag ? EXIT_PASS : EXIT_INCONCLUSIVE", source)


if __name__ == "__main__":
    unittest.main()
