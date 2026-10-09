#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fail-closed CI checks for the existing no-external-graphics Wine PRX build.

SELF parsing is delegated to the pinned public converter, whose inspection
exit status alone does not reject an invalid integrity digest. These are
build-format checks, not platform signature authentication or console tests.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

MODULES = ("ntdll", "win32u", "wineserver", "wowprospero", "wineps5", "libfreetype", "xinput1_3",
           "winevulkan", "opengl32", "ws2_32", "crypt32", "dwrite", "secur32", "libgnutls")
UNIX = ("ntdll", "win32u", "winevulkan", "opengl32", "ws2_32", "crypt32", "dwrite", "secur32")
PE = ("ntdll", "win32u", "xinput1_1", "xinput1_2", "xinput1_3", "xinput1_4", "xinputuap",
      "quartz", "opengl32", "winevulkan")
DIAGNOSTICS = ("unresolved", "errors", "title_unbound", "webkit_unbound", "raw_syscalls")
# Public SDK v0.42 GLOBAL OBJECT ABI, not application-PRX data imports.
# See sce_stubs/libSceLibcInternal.c, sce_stubs/libkernel.c and the system
# data-import distinction in docs/WINE_PS5_BUILD.md. This is build evidence;
# the new artifacts and __isthreaded have not been validated on a console.
SYSTEM_DATA = {"__isthreaded": "libSceLibcInternal.sprx", "__stderrp": "libSceLibcInternal.sprx",
               "__stdoutp": "libSceLibcInternal.sprx", "environ": "libkernel.sprx"}
FORBIDDEN = {"libkernel_sys", "libkernel_web", "libScePosixForWebKit"}
MAX_FILE = 128 * 1024 * 1024


def require(value, message):
    if not value:
        raise ValueError(message)


def data(path: Path, limit=MAX_FILE) -> bytes:
    require(path.is_file() and 0 < path.stat().st_size <= limit, f"missing/oversized artifact: {path}")
    return path.read_bytes()


def sha(path: Path) -> str:
    return hashlib.sha256(data(path)).hexdigest()


def elf(path: Path, kind: int) -> tuple[bytes, list[tuple[int, int, int]]]:
    value = data(path)
    require(len(value) >= 64 and value[:7] == b"\x7fELF\x02\x01\x01", f"not ELF64 little-endian: {path}")
    require(struct.unpack_from("<HHI", value, 16) == (kind, 62, 1), f"unexpected ELF type/target: {path}")
    offset = struct.unpack_from("<Q", value, 32)[0]
    size, count = struct.unpack_from("<HH", value, 54)
    require(size == 56 and 0 < count <= 256 and offset >= 64 and offset + size * count <= len(value),
            f"invalid program table: {path}")
    require(struct.unpack_from("<H", value, 52)[0] == 64, f"invalid ELF header size: {path}")
    loads = []
    executable = False
    entry = struct.unpack_from("<Q", value, 24)[0]
    entry_mapped = False
    for index in range(count):
        ptype, flags, start, address, _, length, memory, _ = struct.unpack_from("<IIQQQQQQ", value, offset + size * index)
        require(start + length <= len(value), f"program segment outside file: {path}")
        if ptype == 1:
            require(length <= memory, f"invalid LOAD size: {path}")
            loads.append((start, length, flags))
            executable |= bool(flags & 1 and length)
            entry_mapped |= bool(flags & 1 and address <= entry < address + length)
    require(kind != 0xFE18 or entry_mapped, f"module entry is outside executable file-backed LOAD: {path}")
    require(loads and executable, f"no executable LOAD segment: {path}")
    return value, loads


class Commands:
    def __init__(self, output: Path):
        self.output = output
        output.mkdir(parents=True, exist_ok=True)
        self.sequence = 0

    def run(self, *command) -> str:
        self.sequence += 1
        args = [str(arg) for arg in command]
        result = subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=120)
        (self.output / f"{self.sequence:03d}-tool.log").write_text(
            json.dumps(args) + "\n" + result.stdout + "\nSTDERR:\n" + result.stderr + f"\nEXIT={result.returncode}\n")
        require(result.returncode == 0, f"artifact analyzer failed: {args[0]} (exit {result.returncode})")
        return result.stdout



def provider_index(sdk: Path, prx: Path, bindir: Path, commands: Commands) -> dict[str, Path]:
    """Use real SONAMEs; SDK names/aliases need not match installed filenames."""
    providers, seen, hashes = {}, set(), set()
    for directory, pattern in ((sdk / "target/lib", "*.so"), (prx, "*.shared.elf")):
        base = directory.resolve(strict=True)
        for path in sorted(directory.glob(pattern)):
            real = path.resolve(strict=True)
            require(real.is_relative_to(base), f"provider symlink leaves its artifact directory: {path}")
            if real in seen:
                continue  # SDK weak-stub aliases point to the same physical file.
            seen.add(real)
            digest = sha(real)
            if digest in hashes:
                continue  # Release ZIPs may materialize an alias as identical bytes.
            hashes.add(digest)
            dynamic = commands.run(bindir / "llvm-readelf", "-d", real)
            names = re.findall(r"Library soname: \[([^\]]+)\]", dynamic)
            require(len(names) == 1, f"missing/ambiguous provider SONAME: {path}")
            name = names[0]
            require(re.fullmatch(r"[A-Za-z0-9_.+-]+", name), f"invalid provider SONAME: {name}")
            require(name not in providers, f"ambiguous distinct providers for SONAME: {name}")
            providers[name] = real
    return providers


def validate(work: Path, sdk: Path, foundation: Path, bindir: Path, output: Path,
             wine_commit: str, foundation_commit: str, patches: list[str]) -> dict:
    report = json.loads(data(work / "report.json", 4 * 1024 * 1024))
    require(report["schema"] == 1 and report["wine_commit"] == wine_commit and report["patches"] == patches,
            "unexpected Wine source/patch identity")
    require(report["sources"]["prx_foundation"] == foundation_commit, "unexpected PRX foundation identity")
    require(report["prx"]["status"] == "0", "PRX conversion was skipped or failed")
    require(report["tls_configured"] is True and not report.get("tls_error") and
            report["tls"]["schema"] == "pw-tls-runtime/1", "TLS runtime provenance absent or failed")
    require(not report["errors"], "Wine build report contains errors")
    targets = [f"dlls/{name}/{name}.so" for name in UNIX] + ["server/wineserver"]
    for target in targets:
        entry = report["targets"][target]
        require(entry["built"] is True and entry["bytes"] == len(data(work / "build" / target)) and
                entry["sha256"] == sha(work / "build" / target), f"missing/changed Unix target: {target}")
    expected_pe = {f"{arch}-windows/{name}.dll" for arch in ("i386", "x86_64") for name in PE}
    expected_pe.update({"x86_64-windows/wow64.dll", "x86_64-windows/wow64win.dll"})
    require(set(report["pe"]) == expected_pe, "unexpected patched PE module set")
    for name in expected_pe:
        require(report["pe"][name] == sha(work / "pe" / name), f"missing/changed PE module: {name}")
    entries = report["prx"]["modules"]
    require(set(entries) == set(MODULES), "missing or unexpected PRX module")
    commands = Commands(output)
    require(commands.run("git", "-C", foundation, "rev-parse", "HEAD").strip() == foundation_commit,
            "converter checkout is not pinned")
    require(commands.run("git", "-C", work / "source", "rev-parse", "HEAD").strip() == wine_commit,
            "Wine checkout is not pinned")
    prx = work / "prx"
    tool = foundation / "build/host/ps5-native-tool"
    providers = provider_index(sdk, prx, bindir, commands)
    provider_exports = {}
    measured = {}
    for name in MODULES:
        entry = entries[name]
        module = prx / "sce_module" / f"{name}.prx"
        require(entry["built"] is True and entry["bytes"] == len(data(module)) and entry["sha256"] == sha(module),
                f"missing/changed PRX: {name}")
        for field in DIAGNOSTICS:
            require(entry[field] == [], f"{name}: missing or nonempty {field}")
        shared = prx / f"{name}.shared.elf"
        require(providers.get(name + ".prx") == shared.resolve(strict=True),
                f"{name}: own SONAME does not identify the checked shared module")
        shared_bytes, _ = elf(shared, 3)
        commands.run(bindir / "llvm-readelf", "-h", "-l", "-d", shared)
        symbols = commands.run(bindir / "llvm-readelf", "--dyn-syms", "-W", shared)
        imports, definitions, import_types, import_indices = set(), set(), {}, {}
        for line in symbols.splitlines():
            fields = line.split()
            if len(fields) >= 8 and re.fullmatch(r"\d+:", fields[0]):
                symbol = fields[7].split("@")[0]
                if fields[6] == "UND":
                    require(fields[3] != "TLS", f"{name}: unsupported TLS data import {symbol}")
                    require(symbol not in import_types or import_types[symbol] == fields[3],
                            f"{name}: conflicting import types for {symbol}")
                    imports.add(symbol)
                    import_types[symbol] = fields[3]
                    import_indices[int(fields[0][:-1])] = symbol
                elif fields[4] in {"GLOBAL", "WEAK"} and fields[5] in {"DEFAULT", "PROTECTED"}:
                    definitions.add(symbol)
        require(definitions and "module_start" in definitions, f"{name}: no inspected module exports")
        data_imports = {symbol for symbol, kind in import_types.items() if kind == "OBJECT"}
        require(entry["data_imports"] == sorted(data_imports), f"{name}: reported data imports differ from actual ELF")
        require(data_imports <= SYSTEM_DATA.keys(), f"{name}: unsupported data imports {sorted(data_imports - SYSTEM_DATA.keys())}")
        require(all(import_types[symbol] == "OBJECT" for symbol in imports & SYSTEM_DATA.keys()),
                f"{name}: system data import has the wrong consumer symbol type")
        needed_text = commands.run(bindir / "llvm-readelf", "-d", shared)
        needed = re.findall(r"Shared library: \[([^\]]+)\]", needed_text)
        require(needed and set(needed) == set(entry["needed"]), f"{name}: missing/mismatched import graph")
        provided = set()
        for library in needed:
            stem, suffix = Path(library).stem, Path(library).suffix
            require(re.fullmatch(r"[A-Za-z0-9_.+-]+", library) and stem not in FORBIDDEN and
                    suffix in {".so", ".sprx", ".prx"}, f"{name}: forbidden import provider {library}")
            require(library in providers, f"{name}: missing provider SONAME {library}")
            provider = providers[library]
            if provider not in provider_exports:
                listing = commands.run(bindir / "llvm-readelf", "--dyn-syms", "-W", provider)
                names = {fields[7].split("@")[0]: fields[3] for line in listing.splitlines() if
                         len(fields := line.split()) >= 8 and re.fullmatch(r"\d+:", fields[0]) and
                         fields[6] != "UND" and fields[4] in {"GLOBAL", "WEAK"} and
                         fields[5] in {"DEFAULT", "PROTECTED"}}
                require(names, f"empty dynamic export provider: {library}")
                provider_exports[provider] = names
            provided |= provider_exports[provider].keys()
        require(not imports - provided, f"{name}: unresolved actual imports {sorted(imports - provided)}")
        system_data = {}
        for symbol in sorted(data_imports):
            # The pinned converter selects the first matching DT_NEEDED
            # provider. A later system export cannot excuse an earlier app
            # provider or wrong symbol type.
            selected = next(library for library in needed if symbol in provider_exports[providers[library]])
            require(selected == SYSTEM_DATA[symbol] and
                    provider_exports[providers[selected]][symbol] == "OBJECT",
                    f"{name}: wrong first provider/type for system data {symbol}")
            system_data[symbol] = {"provider": selected, "relocations": []}
        if system_data:
            # Imported pointers are written into the module's writable LOAD
            # storage (including zero-filled tails); stub object sizes are 0
            # and do not describe the firmware object's real storage size.
            offset = struct.unpack_from("<Q", shared_bytes, 32)[0]
            size, count = struct.unpack_from("<HH", shared_bytes, 54)
            writable = []
            for index in range(count):
                ptype, flags, _, address, _, _, memory, _ = struct.unpack_from("<IIQQQQQQ", shared_bytes, offset + size * index)
                if ptype == 1 and flags & 2 and address + memory <= 1 << 64:
                    writable.append((address, address + memory))
            relocations = commands.run(bindir / "llvm-readelf", "-r", "-W", shared)
            for line in relocations.splitlines():
                fields = line.split()
                mentioned = any(field.split("@")[0] in system_data for field in fields)
                if not fields or not re.fullmatch(r"[0-9a-fA-F]{1,16}", fields[0]):
                    require(not mentioned, f"{name}: malformed relevant data relocation")
                    continue
                require(len(fields) >= 3 and re.fullmatch(r"[0-9a-fA-F]{1,16}", fields[1]),
                        f"{name}: malformed relocation record")
                index = int(fields[1], 16) >> 32
                symbol = import_indices.get(index)
                if symbol not in system_data and not mentioned:
                    continue
                require(symbol in system_data and len(fields) == 7 and fields[4].split("@")[0] == symbol and
                        fields[2] in {"R_X86_64_64", "R_X86_64_GLOB_DAT"} and
                        (int(fields[1], 16) & 0xffffffff) == {"R_X86_64_64": 1, "R_X86_64_GLOB_DAT": 6}[fields[2]] and
                        fields[5] == "+" and
                        re.fullmatch(r"(?:0[xX])?0+", fields[6]),
                        f"{name}: unsupported/mismatched data relocation for {symbol}")
                target = int(fields[0], 16)
                require(any(start <= target and target + 8 <= end for start, end in writable),
                        f"{name}: data relocation write is outside a writable LOAD")
                system_data[symbol]["relocations"].append({"offset": fields[0], "type": fields[2], "addend": 0})
            require(all(item["relocations"] for item in system_data.values()),
                    f"{name}: system data import has no checked relocation")
        listing = commands.run(bindir / "llvm-objdump", "-d", "--no-show-raw-insn", shared)
        instructions, function = 0, None
        for line in listing.splitlines():
            match = re.match(r"[0-9a-f]+ <(.+)>:$", line)
            if match:
                function = match.group(1)
            if re.match(r"\s*[0-9a-f]+:\s+\S", line):
                instructions += 1
            if re.match(r"\s*[0-9a-f]+:\s+syscall(?:\s|$)", line):
                require(name == "ntdll" and function in {"__wine_syscall_dispatcher", "__wine_unix_call_dispatcher"},
                        f"{name}: raw syscall in {function}")
        require(instructions, f"{name}: empty disassembly")
        if name == "secur32":
            require({"__wine_unix_call_funcs", "__wine_unix_call_wow64_funcs"} <= definitions and
                    "ntdll.prx" in needed, "secur32 lacks real Unix-call/ntdll linkage")
        if name == "libgnutls":
            sources = [work / "source/dlls/secur32/schannel_gnutls.c", work / "source/dlls/crypt32/unixlib.c"]
            required = set(re.findall(r"LOAD_FUNCPTR\((gnutls_[a-z0-9_]+)\)", "\n".join(p.read_text() for p in sources)))
            require(required and required <= definitions, "GnuTLS source-selected exports are missing")
        container = data(module)
        require(len(container) >= 32 and struct.unpack_from("<I", container)[0] in {0x1D3D154F, 0xEEF51454},
                f"{name}: not a SELF-format container")
        inspection = commands.run(tool, "self", "--inspect", "--file", module)
        require(re.search(r"^container: signed, plaintext$", inspection, re.M) and
                re.search(r"^integrity: valid$", inspection, re.M) and "INVALID" not in inspection,
                f"{name}: unsigned/encrypted/invalid container integrity")
        extracted = output / f"{name}.extracted.elf"
        commands.run(tool, "self", "--extract", "--file", module, "--out", extracted)
        original, loads = elf(prx / f"{name}.elf", 0xFE18)
        recovered, recovered_loads = elf(extracted, 0xFE18)
        # The pinned self::normalize_header may change OSABI 0/3 to 9.
        # For the already validated AMD64/module type, every other header
        # and program-table byte must survive, as must the LOAD payloads.
        offset = struct.unpack_from("<Q", original, 32)[0]
        size, count = struct.unpack_from("<HH", original, 54)
        expected_abi = 9 if original[7] in {0, 3} else original[7]
        require(recovered[7] == expected_abi and original[:7] == recovered[:7] and
                original[8:64] == recovered[8:64] and
                original[offset:offset + size * count] == recovered[offset:offset + size * count],
                f"{name}: extracted ELF header/program metadata differs")
        require(loads == recovered_loads and all(original[start:start + size] == recovered[start:start + size]
                                                for start, size, _ in loads), f"{name}: extracted LOAD bytes differ")
        commands.run(bindir / "llvm-readelf", "-h", "-l", extracted)
        measured[name] = {"sha256": sha(module), "shared_sha256": sha(shared), "converted_sha256": sha(prx / f"{name}.elf"),
                          "extracted_sha256": sha(extracted), "needed": needed, "defined_symbols": len(definitions),
                          "system_data_imports": system_data}
    return {"schema": "pw-prx-ci-check/1", "scope": "compile/link/conversion only; no platform signature authentication; converted export NIDs and native loading unverified",
            "modules": measured}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("work", "sdk", "foundation", "llvm-bindir", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    script = (root / "tools/build_wine_ps5.sh").read_text()
    def pin(name):
        return re.search(rf"^{name}=([0-9a-f]{{40}})$", script, re.M).group(1)
    try:
        result = validate(args.work, args.sdk, args.foundation, args.llvm_bindir, args.output,
                          pin("WINE_COMMIT"), pin("MODULE_EXPORTS_COMMIT"),
                          sorted(p.name for p in (root / "wine/patches").glob("*.patch")))
        # Existing packaging provenance checks bind both TLS modules, roots
        # and notices to the actual dependency build manifest.
        Commands(args.output / "tls-provenance").run(sys.executable, root / "tools/tls_manifest.py",
                                                     "verify-runtime", "--root", args.work)
        (args.output / "checks.json").write_text(json.dumps(result, indent=2) + "\n")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, struct.error, subprocess.SubprocessError) as error:
        print(f"check_wine_prx_build: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
