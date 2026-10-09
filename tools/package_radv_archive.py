#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Archive-only RADV prerequisite; never claims a linked or loadable PS5 module."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
from check_wine_prx_build import Commands
from package_diagnostic_kit import archive, copy_owned_tree, git, repository, require, sha

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    'vulkan': ('https://github.com/mpereiraesaa/PS5_Vulkan', '50daad6104db5072a2f3c95283d604d21684f0c2'),
    'mesa': ('https://github.com/mpereiraesaa/PS5_Mesa', '9d3cd417ff488bd1a7cc68c1f1c8e1df409c2a11'),
    'payload': ('https://github.com/mihawk-99/PS5_PayloadSDK', '95c08f27386fc698f6bbe21dde3030140a41d10b'),
    'sdk': ('https://github.com/ps5-payload-dev/sdk', '4eb701204fc3f8d31e84cf8ca272974e2be9c867'),
}
DOWNLOADS = {
    'ps5-payload-sdk.zip': ('https://github.com/ps5-payload-dev/sdk/releases/download/v0.42/ps5-payload-sdk.zip',
                          '8cfbc7cd5811e719eb4f0c47eea668d3dc7b40bc8ab11c4a5031d40c23ec02da'),
    'zlib-1.3.2.tar.gz': ('https://zlib.net/fossils/zlib-1.3.2.tar.gz',
                        'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'),
    'zlib-1.3.1.tar.gz': ('https://github.com/mesonbuild/wrapdb/releases/download/zlib_1.3.1-1/zlib-1.3.1.tar.gz',
                        '9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23'),
    'zlib_1.3.1-1_patch.zip': ('https://wrapdb.mesonbuild.com/v2/zlib_1.3.1-1/get_patch',
                            'e79b98eb24a75392009cec6f99ca5cdca9881ff20bfa174e8b8926d5c7a47095'),
}
REQUIRED = {'vk_icdGetInstanceProcAddr', 'vk_common_GetDeviceProcAddr', 'wsi_videoout_idle',
            'wsi_videoout_show_tiled', 'wsi_videoout_present_rect'}


def object_functions(value, name):
    require(len(value) >= 64 and value[:7] == b'\x7fELF\x02\x01\x01', f'not ELF64 little endian: {name}')
    require(struct.unpack_from('<HHI', value, 16) == (1, 62, 1), f'not AMD64 relocatable ELF: {name}')
    offset = struct.unpack_from('<Q', value, 40)[0]
    size, count = struct.unpack_from('<HH', value, 58)
    require(size == 64 and count > 0 and offset + size * count <= len(value), f'invalid sections: {name}')
    sections = [struct.unpack_from('<IIQQQQIIQQ', value, offset + size * i) for i in range(count)]
    functions = set()
    for section in sections:
        _, kind, _, _, start, length, link, _, _, entry = section
        require(kind == 8 or start + length <= len(value), f'section outside object: {name}')
        if kind != 2:
            continue
        require(entry == 24 and length % entry == 0 and link < count, f'invalid symbol table: {name}')
        strings = sections[link]
        require(strings[1] == 3 and strings[4] + strings[5] <= len(value), f'invalid symbol strings: {name}')
        table = value[strings[4]:strings[4] + strings[5]]
        for at in range(start, start + length, entry):
            index, info, _, defined, address, symbol_size = struct.unpack_from('<IBBHQQ', value, at)
            require(index < len(table), f'invalid symbol name: {name}')
            end = table.find(b'\0', index)
            require(end >= 0, f'unterminated symbol name: {name}')
            if info >> 4 in (1, 2) and info & 15 == 2 and defined not in (0, 0xfff1, 0xfff2):
                require(defined < count, f'invalid symbol definition: {name}')
                owner = sections[defined]
                require(owner[1] == 1 and owner[2] & 4 and address < owner[5] and
                        address + symbol_size <= owner[5], f'function is outside executable storage: {name}')
                functions.add(table[index:end].decode('ascii', errors='strict'))
    return functions


def inspect_archive(path):
    """Bounded regular ar parser; reject thin archives, bitcode and wrong machines."""
    require(path.is_file() and 8 < path.stat().st_size <= 1024 ** 3, 'archive missing or oversized')
    members, functions, longnames = [], set(), b''
    with path.open('rb') as stream:
        require(stream.read(8) == b'!<arch>\n', 'expected a self-contained regular archive')
        while header := stream.read(60):
            require(len(header) == 60 and header[58:] == b'`\n', 'malformed ar header')
            raw = header[:16].decode('ascii').strip()
            number = header[48:58].decode('ascii').strip()
            require(number.isdecimal() and int(number) <= 256 * 1024 ** 2, 'bad archive member size')
            length = int(number); value = stream.read(length)
            require(len(value) == length, 'truncated archive member')
            if length & 1:
                require(stream.read(1) == b'\n', 'invalid archive padding')
            if raw == '//':
                longnames = value; continue
            if raw in ('/', '/SYM64/'):
                continue
            if raw.startswith('#1/'):
                require(raw[3:].isdigit() and int(raw[3:]) <= len(value), 'invalid BSD archive name')
                size = int(raw[3:]); name = value[:size].rstrip(b'\0').decode('ascii'); value = value[size:]
            elif re.fullmatch(r'/\d+', raw):
                start = int(raw[1:]); end = longnames.find(b'/\n', start)
                require(start < len(longnames) and end >= start, 'invalid GNU archive name')
                name = longnames[start:end].decode('ascii')
            else:
                name = raw.removesuffix('/')
            require(name and '/' not in name and name not in ('.', '..'), 'unsafe archive member name')
            functions |= object_functions(value, name)
            members.append(name)
    require(members and REQUIRED <= functions, f'missing required RADV definitions: {sorted(REQUIRED - functions)}')
    return {'members': len(members), 'machine': 'ELF64 little-endian AMD64 ET_REL',
            'required_defined_functions': sorted(REQUIRED), 'global_function_count': len(functions), 'sha256': sha(path)}


def licence_path(source, path):
    require(path.resolve(strict=True).is_relative_to(source.resolve(strict=True)),
            'licence symlink leaves pinned source')
    return path


def source_bundle(args):
    require(not args.out.exists() or not any(args.out.iterdir()), 'output must be new or empty')
    require(not git(ROOT, 'status', '--porcelain'), 'project checkout is dirty')
    project = {'repository': repository(args.repository), 'commit': git(ROOT, 'rev-parse', 'HEAD'),
               'tree': git(ROOT, 'rev-parse', 'HEAD^{tree}')}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'sources').mkdir(); (args.out / 'LICENSES').mkdir()
    archive(ROOT, args.out / 'sources/prospero-win.tar.gz')
    sources = {}
    for key, (url, commit) in PINS.items():
        source = args.inputs / key
        require(git(source, 'rev-parse', 'HEAD') == commit and not git(source, 'status', '--porcelain'),
                f'source revision or worktree differs: {key}')
        archive(source, args.out / 'sources' / (key + '.tar.gz'))
        sources[key] = {'repository': url, 'commit': commit, 'tree': git(source, 'rev-parse', 'HEAD^{tree}')}
        destination = args.out / 'LICENSES' / key; destination.mkdir()
        for pattern in ('LICENSE*', 'COPYING*', 'licenses', 'docs/license.rst'):
            for path in source.glob(pattern):
                licence_path(source, path)
                target = destination / path.name
                if target.exists():
                    continue
                if path.is_dir():
                    copy_owned_tree(path, target)
                elif path.is_file():
                    shutil.copy2(path, target)
        require(any(destination.iterdir()), f'no source licence material: {key}')
    for name, (_, digest) in DOWNLOADS.items():
        path = args.inputs / 'downloads' / name
        require(path.is_file() and sha(path) == digest, f'download digest mismatch: {name}')
        shutil.copy2(path, args.out / 'sources' / name)
    for name in ('LICENSE', 'NOTICE.md', 'THIRD_PARTY.md'):
        shutil.copy2(ROOT / name, args.out / name)
    shutil.copy2(ROOT / 'docs/RADV_ARCHIVE_CI.md', args.out / 'README.md')
    return {'schema': 'pw-radv-prerequisite/1', 'scope': args.mode, 'project': project, 'sources': sources,
            'downloads': {k: {'url': v[0], 'sha256': v[1]} for k,v in DOWNLOADS.items()},
            'linked_prx': False, 'module_loading_verified': False, 'vulkan_runtime_verified': False,
            'dxvk_or_game_compatibility_verified': False,
            'remaining_gates': ['actual final PRX import/provider/data/syscall inspection',
                                'SELF metadata, integrity and LOAD-byte inspection',
                                'authoritative graphical runtime packaging', 'console runtime and graphics controls']}


def finish(args, manifest):
    manifest['source_sha256'] = {p.name: sha(p) for p in sorted((args.out / 'sources').iterdir())}
    (args.out / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (args.out / 'SHA256SUMS').write_text(''.join(f'{sha(p)}  {p.relative_to(args.out).as_posix()}\n'
                                                for p in sorted(args.out.rglob('*')) if p.is_file() and p.name != 'SHA256SUMS'))
    print(json.dumps({'scope': args.mode, 'archive_checked': 'archive' in manifest, 'out': str(args.out)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('sources', 'archive'))
    for key in ('inputs', 'out'):
        parser.add_argument('--' + key, required=True, type=Path)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--llvm-bindir', type=Path, default=Path('/usr/lib/llvm-18/bin'))
    args = parser.parse_args()
    try:
        manifest = source_bundle(args)
        if args.mode == 'archive':
            vulkan = args.inputs / 'vulkan'
            sdk = vulkan / '.deps/native/ps5-payload-sdk'
            release = vulkan / '.deps/native/radv-release'
            path = release / 'lib/libvulkan_radeon.ps5.a'
            measured = inspect_archive(path)
            provenance = (release / 'PROVENANCE.txt').read_text()
            for key, value in (('revision', PINS['mesa'][1]), ('sdk', PINS['payload'][1]),
                               ('assertions', 'off'), ('archive sha256', measured['sha256'])):
                require(re.findall(r'^' + re.escape(key) + r': (.+)$', provenance, re.M) == [value],
                        f'wrong archive provenance: {key}')
            require((sdk / '.ps5-sdk-revision').read_text().strip() == PINS['payload'][1], 'SDK fork stamp differs')
            for item in ('target/lib/libps5platform.a', 'target/lib/libc++.a', 'target/lib/libc++abi.a',
                         'target/lib/libunwind.a', 'bin/prospero-clang', 'bin/prospero-lld'):
                require((sdk / item).is_file(), f'link prerequisite absent: {item}')
            for item in ('bin/prospero-clang', 'bin/prospero-lld'):
                require(os.access(sdk / item, os.X_OK), f'SDK tool is not executable: {item}')
            commands = Commands(args.out / 'inspection')
            commands.run(args.llvm_bindir / 'llvm-ar', 't', path)
            commands.run(args.llvm_bindir / 'llvm-readelf', '-h', path)
            commands.run(args.llvm_bindir / 'llvm-nm', '-g', '--defined-only', path)
            # All source/link-recipe files remain authoritative at the exact pin.
            producer = args.out / 'producer'; producer.mkdir()
            subprocess.run(['git', '-C', str(vulkan), 'archive', 'HEAD', '--output', str(producer / 'vulkan-source.tar')], check=True)
            copy_owned_tree(sdk, producer / 'ps5-payload-sdk')
            copy_owned_tree(release, producer / 'radv-release')
            manifest['archive'] = measured
        finish(args, manifest)
    except (OSError, ValueError, UnicodeError, struct.error, subprocess.SubprocessError) as error:
        raise SystemExit('package_radv_archive: ' + str(error))


if __name__ == '__main__':
    main()
