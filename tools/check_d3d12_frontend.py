#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Inspect actual linked D3D12 candidate bytes without loading any image.

This is a link-level report. A separate exact Wine/DXVK/driver consumer must
still resolve all static and dynamic providers before console packaging.
"""
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from inspect_graphics_pe import Image, require

NAMES = ('d3d12.dll', 'd3d12core.dll', 'd3d12-capability-query.exe')
ALLOWED_IMPORTS = {
    'd3d12-capability-query.exe': {'kernel32.dll', 'msvcrt.dll', 'd3d12.dll', 'dxgi.dll'},
    'd3d12.dll': {'kernel32.dll', 'msvcrt.dll', 'dxgi.dll', 'ntdll.dll', 'user32.dll'},
    'd3d12core.dll': {'kernel32.dll', 'msvcrt.dll', 'dxgi.dll', 'ntdll.dll', 'user32.dll',
                    'advapi32.dll', 'gdi32.dll', 'ole32.dll'},
}
REQUIRED_EXPORTS = {
    'd3d12.dll': {'D3D12CreateDevice', 'D3D12GetDebugInterface', 'D3D12CreateRootSignatureDeserializer',
                  'D3D12CreateVersionedRootSignatureDeserializer', 'D3D12EnableExperimentalFeatures',
                  'D3D12SerializeRootSignature', 'D3D12SerializeVersionedRootSignature', 'D3D12GetInterface'},
    'd3d12core.dll': {'D3D12GetInterface'},
}
QUERY_IMPORTS = {
    ('d3d12.dll', 'D3D12CreateDevice'), ('dxgi.dll', 'CreateDXGIFactory1'),
    *(('kernel32.dll', name) for name in ('CreateThread', 'WaitForSingleObject', 'GetExitCodeThread',
      'CloseHandle', 'GetTickCount64', 'TerminateProcess', 'ExitProcess', 'GetEnvironmentVariableA')),
}


def relocation_contract(image):
    require(not image.characteristics & 1, 'relocations stripped')
    address, size = image.directories[5]
    require(address and 8 <= size <= 16 << 20, 'missing/oversized relocation directory')
    count, cursor, targets = 0, 0, set()
    while cursor < size:
        require(size - cursor >= 8, 'truncated relocation block header')
        page, block = image.at(address + cursor, '<II')
        require(page % 4096 == 0 and 8 <= block <= size - cursor and block % 4 == 0,
                'invalid relocation block size/page')
        for offset in range(8, block, 2):
            item = image.at(address + cursor + offset, '<H')[0]
            kind, within = item >> 12, item & 0xfff
            if not kind:
                continue
            require(kind == 10, 'non-DIR64 relocation in AMD64 candidate')
            target = page + within
            require(target not in targets and
                    sum(start <= target and target + 8 <= start + span
                        for _, start, span, _, _, _ in image.sections) == 1,
                    'duplicate/unmapped relocation target')
            targets.add(target); count += 1
        cursor += block
    require(count > 0, 'no actual DIR64 relocations')
    return count


def inspect_image(path):
    image = Image(path)
    name = path.name
    require(name in NAMES, 'unexpected frontend filename')
    op = image.u32(60) + 24
    flags = image.u16(op + 70)
    require(flags & 0x160 == 0x160, 'ASLR/high-entropy/NX flags missing')
    require(image.characteristics & 2, 'image is not executable')
    require(bool(image.characteristics & 0x2000) == name.endswith('.dll'), 'DLL/EXE type differs')
    require(image.entry and image.executable(image.entry), 'missing/non-code image entry')
    if name.endswith('.exe'):
        require(image.u16(op + 68) == 3, 'query must use console subsystem')
    relocations = relocation_contract(image)
    libraries = {library for library, _, _ in image.imports}
    unexpected = sorted(libraries - ALLOWED_IMPORTS[name])
    require(not unexpected, 'unexpected direct DLL imports require review: ' + ', '.join(unexpected))
    for symbol in REQUIRED_EXPORTS.get(name, ()):
        require(image.exports.get(symbol, {}).get('executable'), 'missing real function export: ' + symbol)
    if name.endswith('.exe'):
        require(QUERY_IMPORTS <= {(library, symbol) for library, symbol, _ in image.imports},
                'missing original query API imports')
    version = None
    if name == 'd3d12core.dll':
        value = image.exports.get('D3D12SDKVersion', {})
        require('rva' in value and value.get('executable') is False, 'SDKVersion must be a non-forwarded data export')
        version = image.at(value['rva'], '<I')[0]
        require(version == 614, 'unexpected SDKVersion data value')
    return {'sha256': image.sha256, 'machine': 'AMD64', 'pe32_plus': True,
            'dir64_relocations': relocations, 'dll_characteristics': flags,
            'sdk_version_data': version, 'imports': [{'library': dll, 'symbol': symbol, 'kind': kind}
                                                   for dll, symbol, kind in image.imports],
            'required_function_exports': sorted(REQUIRED_EXPORTS.get(name, ())) }


def inspect_candidate(app):
    require(app.is_dir() and not app.is_symlink(), 'candidate must be an owned directory')
    require({path.name for path in app.iterdir()} == set(NAMES), 'candidate membership differs')
    require(all(path.is_file() and not path.is_symlink() for path in app.iterdir()), 'candidate contains linked/nonregular file')
    return {'schema': 'pw-d3d12-link-check/1', 'scope': 'actual AMD64 PE link/header/export/import inspection',
            'pe_link_verified': True, 'pe_import_graph_verified': False,
            'runtime_verified': False, 'console_package_approved': False,
            'files': {name: inspect_image(app / name) for name in NAMES},
            'unresolved_consumer_contracts': [
                'exact accepted Wine static+delay imports, ordinals, API sets and forwarded provider closure',
                'source-built DXVK 2.1+ dxgi.dll identity and its required private interop interfaces',
                'matching d3d12core.dll dynamic D3D12GetInterface and IVKD3DCoreInterface contract',
                'winevulkan.dll then vulkan-1.dll dynamic vkGetInstanceProcAddr plus matching native PRXs/driver',
                'optional wineopenxr.dll path is conditional and is not covered by this non-VR diagnostic',
                'actual startup, truthful Vulkan/D3D12 features, resource semantics and native cleanup'],
            'sdk_version_scope': 'exported data identity only; no claim of full Agility SDK configuration support'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.report.exists(), 'report already exists')
        result = inspect_candidate(args.app)
        args.report.write_text(json.dumps(result, indent=2) + '\n')
    except (ValueError, OSError) as error:
        parser.exit(1, 'D3D12 PE inspection failed: ' + str(error) + '\n')
