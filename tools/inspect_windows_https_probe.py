#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Inspect the linked diagnostic as data; never load or execute it."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

REQUIRED_IMPORTS = {
    "winhttp.dll": {
        "WinHttpOpen", "WinHttpSetTimeouts", "WinHttpSetOption", "WinHttpConnect",
        "WinHttpOpenRequest", "WinHttpSetStatusCallback", "WinHttpSendRequest",
        "WinHttpReceiveResponse", "WinHttpQueryHeaders", "WinHttpQueryOption", "WinHttpCloseHandle",
    },
    "crypt32.dll": {"CertFreeCertificateContext"},
    "kernel32.dll": {
        "CreateThread", "WaitForSingleObject", "GetExitCodeThread", "CloseHandle",
        "GetTickCount64", "GetCurrentProcess", "GetCurrentProcessId", "TerminateProcess", "GetSystemTime",
    },
}


def inspect(data):
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    def unpack(fmt, offset):
        size = struct.calcsize(fmt)
        require(0 <= offset <= len(data) - size, "truncated PE field")
        return struct.unpack_from(fmt, data, offset)

    require(64 <= len(data) <= 32 * 1024 * 1024 and data[:2] == b"MZ", "not a bounded PE image")
    pe, = unpack("<I", 60)
    require(pe >= 64 and data[pe:pe + 4] == b"PE\0\0", "invalid PE signature")
    machine, count, _, _, _, opt_size, characteristics = unpack("<HHIIIHH", pe + 4)
    require(machine == 0x8664 and 0 < count <= 96, "expected AMD64 image")
    require(characteristics & 2 and not characteristics & 0x2000, "expected executable, not DLL")
    require(not characteristics & 1, "base relocations stripped; check /FIXED:NO")
    opt = pe + 24
    require(opt_size >= 112 + 14 * 8 and opt + opt_size <= len(data), "short optional header")
    require(unpack("<H", opt)[0] == 0x20b, "expected PE32+")
    entry, = unpack("<I", opt + 16)
    image_size, = unpack("<I", opt + 56)
    subsystem, flags = unpack("<HH", opt + 68)
    require(subsystem == 3, "expected console subsystem")
    require(flags & 0x160 == 0x160, "missing ASLR, high-entropy VA or NX compatibility")
    require(unpack("<I", opt + 108)[0] >= 14, "missing PE directories")
    sections = []
    for i in range(count):
        base = opt + opt_size + 40 * i
        virtual, rva, raw_size, raw = unpack("<IIII", base + 8)
        section_flags, = unpack("<I", base + 36)
        require(raw + raw_size <= len(data) and rva + max(virtual, raw_size) <= image_size,
                "section outside file/image")
        sections.append((rva, raw_size, raw, virtual, section_flags))

    def offset(rva, size=1):
        matches = [raw + rva - start for start, raw_size, raw, _, _ in sections
                   if start <= rva and rva - start + size <= raw_size]
        require(len(matches) == 1, "unmapped or ambiguous RVA")
        return matches[0]

    def string(rva):
        chars = bytearray()
        for i in range(512):
            value = data[offset(rva + i)]
            if not value:
                try:
                    return chars.decode("ascii")
                except UnicodeDecodeError as error:
                    raise ValueError("non-ASCII import") from error
            chars.append(value)
        raise ValueError("unterminated import name")

    def directory(index):
        return unpack("<II", opt + 112 + 8 * index)

    require(any(rva <= entry < rva + virtual and flag & 0x20000000
                for rva, _, _, virtual, flag in sections), "entry is not executable image data")
    offset(entry)
    require(directory(13) == (0, 0), "unexpected delay imports")
    import_rva, import_size = directory(1)
    require(import_rva and 20 <= import_size <= 4096, "missing or oversized imports")
    imports = {}
    for i in range(import_size // 20):
        descriptor = unpack("<IIIII", offset(import_rva + 20 * i, 20))
        if not any(descriptor):
            break
        original, _, _, name, first = descriptor
        library = string(name).lower()
        require(library in REQUIRED_IMPORTS and library not in imports, "unexpected or duplicate DLL import")
        require(first, "missing import address table")
        functions = []
        for j in range(4096):
            offset(first + 8 * j, 8)  # Include the terminating IAT slot.
            value, = unpack("<Q", offset((original or first) + 8 * j, 8))
            if not value:
                break
            require(not value & (1 << 63), "unexpected ordinal import")
            functions.append(string(value + 2))
        else:
            raise ValueError("unterminated thunk table")
        require(REQUIRED_IMPORTS[library] <= set(functions), "missing required diagnostic API import")
        require(not any(name.startswith("CreateProcess") for name in functions), "unexpected process creation import")
        imports[library] = sorted(functions)
    else:
        raise ValueError("unterminated import descriptors")
    require(set(imports) == set(REQUIRED_IMPORTS), "missing expected DLL import")
    reloc_rva, reloc_size = directory(5)
    require(reloc_rva and 8 <= reloc_size <= len(data), "missing base relocation directory")
    cursor = 0
    dir64_count = 0
    while cursor < reloc_size:
        require(reloc_size - cursor >= 8, "truncated relocation block")
        page, size = unpack("<II", offset(reloc_rva + cursor, 8))
        require(not page & 0xfff and 8 <= size <= reloc_size - cursor and size % 4 == 0,
                "invalid relocation block")
        for pos in range(8, size, 2):
            value, = unpack("<H", offset(reloc_rva + cursor + pos, 2))
            kind, delta = value >> 12, value & 0xfff
            require(kind in (0, 10), "unexpected AMD64 base relocation type")
            if kind == 10:
                require(page + delta + 8 <= image_size, "relocation target outside image")
                offset(page + delta, 8)
                dir64_count += 1
        cursor += size
    require(dir64_count > 0, "no usable DIR64 base relocations")
    return {
        "validation": "static-linked-PE-only", "executed": False,
        "machine": "0x8664", "optional_magic": "0x20b", "subsystem": subsystem,
        "dll_characteristics": hex(flags), "relocations_stripped": False,
        "dir64_relocations": dir64_count, "imports": imports,
        "image_sha256": hashlib.sha256(data).hexdigest(), "image_bytes": len(data),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = inspect(args.image.read_bytes())
    result["source_sha256"] = hashlib.sha256(args.source.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("PASS: linked AMD64 PE, base relocations and direct imports verified without execution.")


if __name__ == "__main__":
    main()
