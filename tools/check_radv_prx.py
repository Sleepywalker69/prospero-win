#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Independent libvulkan link/container gate; no firmware/native loading claim.

The original 14-module Wine checker is unchanged. The 512MiB ELF budget here
covers the unstripped link from the verified 258MiB RADV archive.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
from check_wine_prx_build import Commands, FORBIDDEN, SYSTEM_DATA, data, provider_index, require

FOUNDATION = '30597512539e7edfde079cbcaf4a626bc0a948c5'
REQUIRED_EXPORTS = {'module_start', 'module_stop', 'vkGetInstanceProcAddr', 'vkGetDeviceProcAddr',
                    'pw_videoout_idle', 'pw_videoout_show_tiled', 'pw_videoout_cursor'}
SYSTEM_PROVIDER_HASHES = {
    'libkernel.so': 'c6579f2614d8b8f905a673f810a1b562f1432b07397d61c11e876b5648428753',
    'libSceLibcInternal.so': 'c2d4fb695495e3dd33599eff1f283cf88615dbd06f4c4acb4547494d32a022b7',
}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def graphics_elf(path: Path, kind: int) -> tuple[bytes, list[tuple[int, int, int]]]:
    value = data(path, 512 * 1024 * 1024)
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


def inspect_link(work, sdk, bindir, commands):
    name = 'libvulkan'
    shared = work / 'libvulkan.shared.elf'
    # The SDK index stays under the original bounded provider rules. The large
    # driver itself is inspected separately, without changing the Wine checker.
    providers = provider_index(sdk, work / 'radv/stubs', bindir, commands)
    dynamic = commands.run(bindir / 'llvm-readelf', '-d', shared)
    require(re.findall(r'Library soname: \[([^\]]+)\]', dynamic) == ['libvulkan.prx'],
            'wrong driver SONAME')
    for filename, expected in SYSTEM_PROVIDER_HASHES.items():
        require(sha(sdk / 'target/lib' / filename) == expected, 'system provider differs from verified runtime: ' + filename)
    gpu_stubs = {}
    for name in ('libSceAgc', 'libSceAgcDriver'):
        path = work / 'radv/stubs' / (name + '.so')
        graphics_elf(path, 3)
        dynamic = commands.run(bindir / 'llvm-readelf', '-d', path)
        soname = re.findall(r'Library soname: \[([^\]]+)\]', dynamic)
        require(soname == [name + '.prx'] and soname[0] not in providers,
                'missing/ambiguous source-built GPU provider: ' + name)
        providers[soname[0]] = path.resolve(strict=True)
        gpu_stubs[name] = {'file': str(path.resolve(strict=True)), 'sha256': sha(path)}
    name = 'libvulkan'
    provider_exports = {}
    shared_bytes, _ = graphics_elf(shared, 3)
    commands.run(bindir / "llvm-readelf", "-h", "-l", "-d", shared)
    symbols = commands.run(bindir / "llvm-readelf", "--dyn-syms", "-W", shared)
    imports, definitions, definition_types, import_types, import_indices = set(), set(), {}, {}, {}
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
                require(symbol not in definition_types or definition_types[symbol] == fields[3],
                        f"{name}: conflicting export types for {symbol}")
                definitions.add(symbol)
                definition_types[symbol] = fields[3]
    require(definitions and "module_start" in definitions, f"{name}: no inspected module exports")
    data_imports = {symbol for symbol, kind in import_types.items() if kind == "OBJECT"}
    require(data_imports <= SYSTEM_DATA.keys(), f"{name}: unsupported data imports {sorted(data_imports - SYSTEM_DATA.keys())}")
    require(all(import_types[symbol] == "OBJECT" for symbol in imports & SYSTEM_DATA.keys()),
            f"{name}: system data import has the wrong consumer symbol type")
    needed_text = commands.run(bindir / "llvm-readelf", "-d", shared)
    needed = re.findall(r"Shared library: \[([^\]]+)\]", needed_text)
    require(needed, "libvulkan: missing actual import graph")
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
    for symbol in imports - data_imports:
        selected = next(library for library in needed if symbol in provider_exports[providers[library]])
        require(import_types[symbol] in {'FUNC', 'NOTYPE'} and
                provider_exports[providers[selected]][symbol] == 'FUNC',
                f'{name}: wrong first function provider/type for {symbol}')
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
    require(REQUIRED_EXPORTS <= definitions and
            all(definition_types[name] == 'FUNC' for name in REQUIRED_EXPORTS),
            'driver lacks required real function entry points')
    require(not re.search(r'^\s*[0-9a-f]+:\s+(?:sysenter|int\s+\$?0x80)(?:\s|$)', listing, re.M),
            'driver contains an additional raw syscall instruction')
    return {'needed': needed, 'imports': sorted(imports), 'defined_symbols': len(definitions),
            'required_export_types': {name: definition_types[name] for name in sorted(REQUIRED_EXPORTS)},
            'gpu_stubs': gpu_stubs,
            'required_exports': sorted(REQUIRED_EXPORTS), 'system_data_imports': system_data,
            'providers': {library: {'file': str(providers[library]), 'sha256': sha(providers[library])}
                          for library in needed},
            'additional_to_existing_Wine_system_graph': sorted(set(needed) - {'libkernel.sprx', 'libSceLibcInternal.sprx'}),
            'shared_sha256': sha(shared)}


def validate(work, sdk, foundation, bindir, output):
    commands = Commands(output)
    require(commands.run('git', '-C', foundation, 'rev-parse', 'HEAD').strip() == FOUNDATION,
            'converter source pin differs')
    require(not commands.run('git', '-C', foundation, 'status', '--porcelain', '--untracked-files=all',
                             '--', 'tooling/native').strip(), 'converter sources/layout are modified')
    require(commands.run(bindir / 'llvm-config', '--version').strip().startswith('18.'),
            'driver inspection requires LLVM18')
    log = (work / 'libvulkan.link.log').read_text(errors='replace')
    require(not re.search(r'(?im)undefined symbol|\berror:', log), 'driver link/conversion reported unresolved symbols or errors')
    measured = inspect_link(work, sdk, bindir, commands)
    tool = foundation / 'build/host/ps5-native-tool'
    module = work / 'sce_module/libvulkan.prx'
    container = data(module, 512 * 1024 * 1024)
    require(len(container) >= 32 and struct.unpack_from('<I', container)[0] in {0x1D3D154F, 0xEEF51454},
            'driver is not a SELF-format container')
    text = commands.run(tool, 'self', '--inspect', '--file', module)
    require(re.search(r'^container: signed, plaintext$', text, re.M) and
            re.search(r'^integrity: valid$', text, re.M) and 'INVALID' not in text,
            'driver SELF structure/integrity failed')
    recovered_path = output / 'libvulkan.extracted.elf'
    commands.run(tool, 'self', '--extract', '--file', module, '--out', recovered_path)
    original, loads = graphics_elf(work / 'radv/libvulkan.elf', 0xFE18)
    recovered, recovered_loads = graphics_elf(recovered_path, 0xFE18)
    offset = struct.unpack_from('<Q', original, 32)[0]
    size, count = struct.unpack_from('<HH', original, 54)
    expected_abi = 9 if original[7] in {0, 3} else original[7]
    require(recovered[7] == expected_abi and original[:7] == recovered[:7] and
            original[8:64] == recovered[8:64] and
            original[offset:offset + size * count] == recovered[offset:offset + size * count],
            'driver extracted ELF metadata differs')
    require(loads == recovered_loads and all(original[start:start + size] == recovered[start:start + size]
                                            for start, size, _ in loads), 'driver extracted LOAD bytes differ')
    recorded_digest = re.findall(r'^digest: ([0-9a-f]{64})$', text, re.M)
    require(recorded_digest == [sha(recovered_path)], 'inspected SELF digest does not match extracted ELF')
    measured.update(prx_sha256=sha(module), converted_sha256=sha(work / 'radv/libvulkan.elf'),
                    extracted_sha256=sha(recovered_path))
    return {'schema': 'pw-radv-prx-check/1',
            'scope': 'actual link/provider/SELF metadata checks; no firmware authentication, converted export-NID or native loading proof',
            'module': measured, 'runtime_verified': False, 'drop_in_package_approved': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('work', 'sdk', 'foundation', 'llvm-bindir', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        result = validate(args.work, args.sdk, args.foundation, args.llvm_bindir, args.output)
        (args.output / 'CHECKS.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        print('RADV driver link/container checks passed; native loading and graphics runtime remain unverified')
    except (OSError, ValueError) as error:
        raise SystemExit('check_radv_prx: ' + str(error))


if __name__ == '__main__':
    main()
