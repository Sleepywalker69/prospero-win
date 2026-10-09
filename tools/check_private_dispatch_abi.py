#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Static-only check of pinned Wine AMD64 syscall-thunk operands."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import re
import os
import shutil
import sys
sys.dont_write_bytecode = True

PREFIX = bytes.fromhex('4c8bd1b8')
MIDDLE = bytes.fromhex('f604250803fe7f0175030f05c3eb01c3ff1425')
SLOTS = {0: 0x7ffe1000, 1: 0x7ffe4000}


def general_release_admissible(report):
    # This general producer has no reviewed per-runtime/per-child ABI staging.
    # A present experimental declaration, including an unknown version or
    # malformed value, must not be silently treated as a legacy runtime.
    return isinstance(report, dict) and 'private_dispatcher' not in report


def thunk_shape(code):
    return len(code) >= 32 and code[:4] == PREFIX and code[8:27] == MIDDLE and code[31] == 0xc3


def check_image(data, anchor, mode):
    def need(condition, message):
        if not condition:
            raise ValueError(message)
    def field(fmt, offset):
        need(0 <= offset <= len(data) - struct.calcsize(fmt), 'truncated PE')
        return struct.unpack_from(fmt, data, offset)
    need(data[:2] == b'MZ', 'not a PE')
    pe, = field('<I', 60)
    need(data[pe:pe + 4] == b'PE\0\0', 'bad PE signature')
    machine, count, _, _, _, optional_size, _ = field('<HHIIIHH', pe + 4)
    optional = pe + 24
    need(machine == 0x8664 and field('<H', optional)[0] == 0x20b, 'expected AMD64 PE32+')
    need(0 < count <= 96 and optional_size >= 120, 'bad PE layout')
    sections = []
    for i in range(count):
        base = optional + optional_size + i * 40
        _, rva, raw_size, raw = field('<IIII', base + 8)
        need(raw + raw_size <= len(data), 'section exceeds file')
        sections.append((rva, raw_size, raw))
    def offset(rva, size=1):
        hits = [raw + rva - start for start, length, raw in sections
                if start <= rva and rva - start + size <= length]
        need(len(hits) == 1, 'unmapped/ambiguous RVA')
        return hits[0]
    def string(rva):
        result = bytearray()
        for i in range(512):
            char = data[offset(rva + i)]
            if not char:
                return result.decode('ascii')
            result.append(char)
        raise ValueError('unterminated export name')
    export_rva, export_size = field('<II', optional + 112)
    need(export_rva and export_size >= 40, 'missing exports')
    exports = field('<IIHHIIIIIII', offset(export_rva, 40))
    _, _, _, _, _, _, functions, names, function_rva, name_rva, ordinal_rva = exports
    need(0 < functions <= 65536 and 0 < names <= 65536, 'bad export counts')
    anchor_seen = False
    checked = {}
    for i in range(names):
        nrva, = field('<I', offset(name_rva + i * 4, 4))
        ordinal, = field('<H', offset(ordinal_rva + i * 2, 2))
        need(ordinal < functions, 'bad export ordinal')
        name = string(nrva)
        rva, = field('<I', offset(function_rva + ordinal * 4, 4))
        if export_rva <= rva < export_rva + export_size:
            need(name != anchor, 'anchor is a forwarder')
            continue
        try:
            start = offset(rva, 32)
        except ValueError:
            need(name != anchor, 'anchor has no complete thunk')
            continue
        code = data[start:start + 32]
        if name == anchor:
            need(thunk_shape(code), 'anchor thunk shape mismatch')
            anchor_seen = True
        if thunk_shape(code):
            slot, = struct.unpack_from('<I', code, 27)
            need(slot == SLOTS[mode], f'{name}: dispatcher operand mismatch')
            checked[name] = rva
    need(anchor_seen and checked, 'no matching anchor/syscall thunks')
    return {'sha256': hashlib.sha256(data).hexdigest(), 'machine': 'AMD64',
            'anchor': anchor, 'slot': hex(SLOTS[mode]), 'thunk_exports_checked': len(checked)}



def check_build(work, mode, readelf, *, require_wow64=False):
    """Supplement the unchanged complete PRX checker with ABI evidence."""
    def need(condition, message):
        if not condition:
            raise ValueError(message)
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()
    work = Path(work)
    report = json.loads((work/'report.json').read_text())
    need(isinstance(report, dict) and report.get('prx', {}).get('status') == '0' and
         report.get('errors') == [], 'Wine build failed, was skipped, or has no complete report')
    modules = {}
    for name, anchor in [('ntdll', 'NtClose'), ('win32u', 'NtUserGetThreadState')]:
        path = work/'pe/x86_64-windows'/(name+'.dll')
        modules[name] = check_image(path.read_bytes(), anchor, mode)
    pe_identity = {'abi': mode, 'executed': False, 'scope': 'PE thunk bytes only', 'modules': modules}
    native = work/'build/dlls/ntdll/ntdll.so'
    need(report.get('targets', {}).get('dlls/ntdll/ntdll.so', {}).get('sha256') == sha(native),
         'native ntdll differs from its build report')
    export = '__wine_ps5_private_dispatch_abi'
    checked = {}
    for path in (native, work/'prx/ntdll.shared.elf'):
        result = subprocess.run([str(readelf), '--dyn-syms', '-W', str(path)],
                                check=True, capture_output=True, text=True, timeout=60)
        need(re.search(r"Symbol table .* contains [1-9][0-9]* entries:", result.stdout),
             'native symbol analyzer returned no table')
        rows = [line.split() for line in result.stdout.splitlines()
                if len(line.split()) >= 8 and line.split()[7] == export]
        if mode:
            need(len(rows) == 1 and rows[0][3:6] == ['FUNC', 'GLOBAL', 'DEFAULT'] and
                 rows[0][6] != 'UND', 'native ABI export is absent or not a defined visible function')
        else:
            need(not rows, 'OFF native module contains an experimental ABI export')
        checked[str(path.relative_to(work))] = sha(path)
    if mode:
        declaration = report.get('private_dispatcher')
        need(isinstance(declaration, dict) and declaration.get('abi') == 1 and
             declaration.get('runtime_validated') is False and
             declaration.get('native_abi_export') == export and
             declaration.get('native_elf_sha256') == sha(native) and
             declaration.get('pe_identity') == pe_identity, 'experimental report disagrees with actual ABI artifacts')
        need(json.loads((work/'private-dispatch-pe.json').read_text()) == pe_identity,
             'staged PE identity disagrees with actual module bytes')
    else:
        need('private_dispatcher' not in report, 'OFF report contains an experimental ABI declaration')
    result = {'mode': mode, 'executed': False, 'pe_identity': pe_identity, 'native_sha256': checked,
              'report_sha256': sha(work/'report.json'),
              'scope': 'compile/link identity only; no mapping, protection, cleanup or child execution'}
    if require_wow64 or (mode and 'wow64_abi' in report.get('private_dispatcher', {})):
        need(mode == 1, 'translated-I386 capability requires private dispatcher ON')
        from private_dispatch_wow64 import check_runtime
        compiler = os.environ.get('PW_DISPATCH_CLANG') or shutil.which('clang-18') or shutil.which('cc')
        need(compiler, 'host C compiler is required for the inert I386 byte validator')
        result['wow64'] = check_runtime(work, report, compiler)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--mode', type=int, choices=(0, 1))
    selection.add_argument('--refuse-release-report', type=Path)
    parser.add_argument('--ntdll', type=Path)
    parser.add_argument('--win32u', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--build-work', type=Path)
    parser.add_argument('--llvm-readelf', type=Path)
    parser.add_argument('--require-wow64', action='store_true')
    args = parser.parse_args()
    if args.refuse_release_report:
        if args.ntdll or args.win32u or args.output or args.build_work or args.llvm_readelf or args.require_wow64:
            parser.error('release refusal check does not accept module/output arguments')
        report = json.loads(args.refuse_release_report.read_text())
        if not general_release_admissible(report):
            parser.error('experimental private-dispatch runtime is not accepted by the general release packager')
        return
    if args.build_work:
        if args.ntdll or args.win32u or not args.output or not args.llvm_readelf:
            parser.error('build validation requires --llvm-readelf and --output, without explicit PE inputs')
        result = check_build(args.build_work, args.mode, args.llvm_readelf, require_wow64=args.require_wow64)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
        print('PASS: actual PE/native dispatcher build identities agree; no runtime execution.')
        return
    if args.require_wow64:
        parser.error('--require-wow64 requires --build-work')
    if args.llvm_readelf:
        parser.error('--llvm-readelf is used only with --build-work')
    if not args.ntdll or not args.win32u or not args.output:
        parser.error('module validation requires --ntdll, --win32u and --output')
    result = {'abi': args.mode, 'executed': False, 'scope': 'PE thunk bytes only', 'modules': {}}
    for name, path, anchor in [('ntdll', args.ntdll, 'NtClose'), ('win32u', args.win32u, 'NtUserGetThreadState')]:
        result['modules'][name] = check_image(path.read_bytes(), anchor, args.mode)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: matching pinned AMD64 PE thunk operands; no runtime or child execution.')


if __name__ == '__main__':
    main()
