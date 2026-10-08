#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Package owned producer outputs for a software-GDI diagnostic kit.

Uses package_release.sh without changing its input contracts. Does not export a
prefix, run a vendor executable, connect to a console, or publish a release.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
from urllib.parse import urlparse

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
CORE_PE = ('ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll', 'gdi32.dll',
           'advapi32.dll', 'shell32.dll', 'ole32.dll', 'ws2_32.dll', 'crypt32.dll',
           'secur32.dll', 'wininet.dll', 'winhttp.dll', 'win32u.dll', 'notepad.exe')
NOTEPAD_RECIPE = '''name: Wine Notepad diagnostic
game_slug: diagnostic-notepad
runner: wine
prospero:
  graphics: gdi
  display: {desktop: 800x600, scaling: fit}
script:
  game:
    exe: drive_c/windows/system32/notepad.exe
    prefix: $GAMEDIR
  wine: {dxvk: false}
  installer:
  - task: {name: create_prefix, prefix: $GAMEDIR, install_gecko: false, install_mono: false}
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def repository(value):
    require(re.fullmatch(r'https://github\.com/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', value),
            'repository must be a public HTTPS GitHub owner/repository URL without credentials')
    return value


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()


def pe(path, machine):
    path = Path(path)
    require(path.is_file() and 64 <= path.stat().st_size <= 128 << 20, f'missing/oversized PE: {path}')
    with path.open('rb') as stream:
        dos = stream.read(64)
        require(dos[:2] == b'MZ', f'not PE: {path}')
        offset = struct.unpack_from('<I', dos, 60)[0]
        require(64 <= offset <= path.stat().st_size - 26, f'bad PE header offset: {path}')
        stream.seek(offset)
        header = stream.read(26)
    require(header[:4] == b'PE\0\0' and struct.unpack_from('<H', header, 4)[0] == machine,
            f'wrong PE machine: {path}')
    require(struct.unpack_from('<H', header, 24)[0] == (0x10b if machine == 0x14c else 0x20b),
            f'wrong PE optional header: {path}')


def copy_owned_tree(source, destination):
    """Preserve internal links portably; refuse host-file/home-directory escapes."""
    source = Path(source).resolve(strict=True)
    links = []
    for path in source.rglob('*'):
        if path.is_symlink():
            target = path.resolve(strict=True)
            require(target.is_relative_to(source), f'symlink escapes artifact: {path}')
            links.append((path.relative_to(source), os.path.relpath(target, path.parent)))
        elif not path.is_dir():
            require(path.is_file(), f'non-regular artifact: {path}')
    shutil.copytree(source, destination, symlinks=True)
    for relative, target in links:
        path = Path(destination) / relative
        path.unlink()
        path.symlink_to(target)


def archive(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as zipped:
        proc = subprocess.Popen(['git', '-C', str(source), 'archive', 'HEAD'], stdout=subprocess.PIPE)
        shutil.copyfileobj(proc.stdout, zipped, 1 << 20)
        proc.stdout.close()
        require(proc.wait() == 0, f'cannot archive source: {source}')


def validate_host(host):
    usr = host / 'install/usr'
    require((usr / 'bin/wine').is_file() and (usr / 'bin/wineserver').is_file(), 'host Wine executable/server missing')
    config = (host / 'build/include/config.h').read_text()
    for name in ('SONAME_LIBX11', 'SONAME_LIBFREETYPE', 'SONAME_LIBFONTCONFIG', 'SONAME_LIBGNUTLS'):
        require(re.search(r'^#define ' + name + r'\s+"[^\"]+"', config, re.M), f'host Wine lacks {name}')
    for arch, machine in (('i386-windows', 0x14c), ('x86_64-windows', 0x8664)):
        for name in CORE_PE:
            pe(usr / 'lib/wine' / arch / name, machine)
    require((usr / 'share/wine/nls/locale.nls').is_file(), 'host Wine NLS absent')
    return usr


def common(args):
    out = args.out.resolve()
    require(not out.exists() or not any(out.iterdir()), 'output must be a new or empty directory')
    require(not git(ROOT, 'status', '--porcelain'), 'project checkout is dirty')
    url = repository(args.repository)
    commit, tree = git(ROOT, 'rev-parse', 'HEAD'), git(ROOT, 'rev-parse', 'HEAD^{tree}')
    wine_pin = re.search(r'^WINE_COMMIT=([0-9a-f]{40})$', (ROOT / 'tools/build_wine_ps5.sh').read_text(), re.M).group(1)
    require(git(args.wine_source, 'rev-parse', 'HEAD') == wine_pin, 'wrong Wine source revision')
    usr = validate_host(args.host_work)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'pc/tools').mkdir(parents=True)
    (out / 'pc/recipes').mkdir()
    copy_owned_tree(usr, out / 'pc/host-wine/usr')
    for name in ('pw_install.py', 'pw_prefix.py'):
        shutil.copy2(ROOT / 'tools' / name, out / 'pc/tools' / name)
    (out / 'pc/recipes/diagnostic-notepad.yml').write_text(NOTEPAD_RECIPE)
    shutil.copy2(ROOT / 'docs/DIAGNOSTIC_KIT.md', out / 'README.md')
    shutil.copy2(ROOT / 'docs/DEVELOPMENT.md', out / 'DEVELOPMENT.md')
    for name in ('LICENSE', 'NOTICE.md', 'LICENSING.md', 'THIRD_PARTY.md'):
        shutil.copy2(ROOT / name, out / name)
    copy_owned_tree(ROOT / 'LICENSES', out / 'LICENSES')
    (out / 'LICENSES/wine/libs').mkdir(parents=True)
    for name in ('LICENSE', 'COPYING.LIB', 'AUTHORS', 'NOTICES.md'):
        shutil.copy2(args.wine_source / name, out / 'LICENSES/wine' / name)
    for path in (args.wine_source / 'libs').glob('*/*'):
        if path.is_file() and path.name.startswith(('LICENSE', 'COPYING', 'COPYRIGHT')):
            target = out / 'LICENSES/wine/libs' / path.parent.name
            target.mkdir(exist_ok=True)
            shutil.copy2(path, target / path.name)
    archive(ROOT, out / 'sources/prospero-win.tar.gz')
    archive(args.wine_source, out / 'sources/wine.tar.gz')
    (out / 'provenance').mkdir()
    shutil.copy2(args.host_work / 'configure.log', out / 'provenance/host-configure.log')
    return out, {'schema': 'pw-diagnostic-kit/1', 'scope': args.mode,
                 'project': {'repository': url, 'commit': commit, 'tree': tree}, 'wine_commit': wine_pin,
                 'graphics': 'software GDI only', 'prefix_included': False, 'console_execution_verified': False,
                 'tls_handshake_verified': False, 'process_creation_supported': False,
                 'vendor_installers_or_game_files_included': False,
                 'missing_features': ['Vulkan driver/DXVK rendering', 'external OpenGL/Zink backend',
                                      'Windows child-process creation', 'proven Battle.net installation/login']}


def validate_native_link(shared, sdk, prx, bindir, commands):
    """Inspect actual title-context linkage; native CPU needs no data imports."""
    from check_wine_prx_build import FORBIDDEN, SYSTEM_DATA, elf, provider_index
    elf(shared, 3)
    dynamic = commands.run(bindir / 'llvm-readelf', '-d', shared)
    require(re.findall(r'Library soname: \[([^\]]+)\]', dynamic) == ['wow64native.prx'],
            'native CPU has wrong or ambiguous SONAME')
    needed = re.findall(r'Shared library: \[([^\]]+)\]', dynamic)
    require('ntdll.prx' in needed, 'native CPU lacks actual ntdll linkage')
    for library in needed:
        require(re.fullmatch(r'[A-Za-z0-9_.+-]+', library) and
                Path(library).stem not in FORBIDDEN and
                Path(library).suffix in {'.so', '.sprx', '.prx'},
                f'native CPU has forbidden import provider {library}')
    providers = provider_index(sdk, prx, bindir, commands)
    require(providers.get('ntdll.prx') == (prx / 'ntdll.shared.elf').resolve(strict=True),
            'native CPU ntdll SONAME does not identify the matching Wine module')
    symbols = commands.run(bindir / 'llvm-readelf', '--dyn-syms', '-W', shared)
    imports, definitions = {}, set()
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) >= 8 and re.fullmatch(r'\d+:', fields[0]):
            symbol = fields[7].split('@')[0]
            if fields[6] == 'UND':
                require(fields[3] in {'FUNC', 'NOTYPE'} and symbol not in SYSTEM_DATA,
                        f'native CPU has unsupported data/TLS import {symbol}')
                imports[symbol] = fields[3]
            elif fields[4] in {'GLOBAL', 'WEAK'} and fields[5] in {'DEFAULT', 'PROTECTED'}:
                definitions.add(symbol)
    require({'module_start', '__wine_unix_call_funcs'} <= definitions,
            'native CPU lacks inspected module/Unix-call exports')
    provided = {}
    for library in needed:
        require(library in providers, f'native CPU has missing provider SONAME {library}')
        listing = commands.run(bindir / 'llvm-readelf', '--dyn-syms', '-W', providers[library])
        names = {fields[7].split('@')[0]: fields[3] for line in listing.splitlines() if
                 len(fields := line.split()) >= 8 and re.fullmatch(r'\d+:', fields[0]) and
                 fields[6] != 'UND' and fields[4] in {'GLOBAL', 'WEAK'} and
                 fields[5] in {'DEFAULT', 'PROTECTED'}}
        require(names, f'native CPU has empty dynamic provider {library}')
        for name, kind in names.items():
            provided.setdefault(name, (library, kind))
    require(not imports.keys() - provided.keys(),
            f'native CPU has unresolved actual imports {sorted(imports.keys() - provided.keys())}')
    for name, kind in imports.items():
        require(provided[name][1] == 'FUNC',
                f'native CPU import {name} resolves to incompatible first provider {provided[name]}')
    listing = commands.run(bindir / 'llvm-objdump', '-d', '--no-show-raw-insn', shared)
    require(any(re.match(r'\s*[0-9a-f]+:\s+\S', line) for line in listing.splitlines()),
            'native CPU has empty disassembly')
    require(not any(re.match(r'\s*[0-9a-f]+:\s+syscall(?:\s|$)', line) for line in listing.splitlines()),
            'native CPU contains a raw syscall')
    return {'needed': needed, 'imports': sorted(imports), 'definitions': sorted(definitions),
            'providers': {name: {'sha256': sha(providers[name]), 'file': str(providers[name])} for name in needed}}


def validate_native_cpu(args, output):
    # Reuse the reviewed bounded ELF/SELF inspection primitives, without
    # claiming independent export-NID decoding or console loading.
    from check_wine_prx_build import Commands, elf
    folder = args.native_cpu / 'ps5'
    tool = args.prx_foundation / 'build/host/ps5-native-tool'
    commands = Commands(output)
    elf(folder / 'wow64native.shared.elf', 3)
    text = commands.run(tool, 'self', '--inspect', '--file', folder / 'wow64native.prx')
    require(re.search(r'^container: signed, plaintext$', text, re.M) and
            re.search(r'^integrity: valid$', text, re.M) and 'INVALID' not in text,
            'native CPU has invalid SELF structure/integrity')
    recovered = output / 'wow64native.extracted.elf'
    commands.run(tool, 'self', '--extract', '--file', folder / 'wow64native.prx', '--out', recovered)
    original, loads = elf(folder / 'wow64native.elf', 0xFE18)
    extracted, recovered_loads = elf(recovered, 0xFE18)
    offset = struct.unpack_from('<Q', original, 32)[0]
    size, count = struct.unpack_from('<HH', original, 54)
    expected_abi = 9 if original[7] in (0, 3) else original[7]
    require(extracted[7] == expected_abi and original[:7] == extracted[:7] and
            original[8:64] == extracted[8:64] and
            original[offset:offset + size * count] == extracted[offset:offset + size * count] and
            loads == recovered_loads and all(original[start:start + size] == extracted[start:start + size]
                                             for start, size, _ in loads),
            'native CPU conversion changed ELF metadata or LOAD bytes')
    analyzer = shutil.which('llvm-readelf-18')
    require(analyzer, 'LLVM 18 artifact analyzer is unavailable')
    graph = validate_native_link(folder / 'wow64native.shared.elf', args.sdk, args.wine_work / 'prx',
                                 Path(analyzer).resolve().parent, commands)
    (output / 'linkage.json').write_text(json.dumps(graph, indent=2, sort_keys=True) + '\n')
    exports = commands.run(analyzer, '--dyn-syms', '-W', folder / 'wow64native.shared.elf')
    require(re.search(r'\bGLOBAL\s+DEFAULT\s+(?!UND)\S+\s+__wine_unix_call_funcs\b', exports),
            'native CPU Unix-call export absent')
    ntdll = commands.run(analyzer, '--dyn-syms', '-W', args.wine_work / 'prx/ntdll.shared.elf')
    require(re.search(r'\bGLOBAL\s+DEFAULT\s+(?!UND)\S+\s+__wine_prospero_native_wow64_caps\b', ntdll),
            'matching ntdll has no native-WoW64 capability export')


def finish(out, manifest):
    manifest['source_archive_sha256'] = {p.name: sha(p) for p in sorted((out / 'sources').iterdir()) if p.is_file()}
    (out / 'KIT-MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    files = {}
    for path in sorted(out.rglob('*')):
        if path.is_file():
            files[path.relative_to(out).as_posix()] = {'sha256': sha(path), 'mode': oct(stat.S_IMODE(path.stat().st_mode))}
    (out / 'FILES.json').write_text(json.dumps(files, indent=2, sort_keys=True) + '\n')
    (out / 'SHA256SUMS').write_text(''.join(f"{sha(path)}  {path.relative_to(out).as_posix()}\n"
                                        for path in sorted(out.rglob('*')) if path.is_file() and path.name != 'SHA256SUMS'))
    print(json.dumps({'out': str(out), 'scope': manifest['scope'], 'files': len(files)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('host-checkpoint', 'software-gdi-kit'))
    for name in ('out', 'host-work', 'wine-source'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--repository', required=True)
    for name in ('wine-work', 'native-foundation', 'prx-foundation', 'tls-work', 'native-cpu', 'cpu-dll', 'sdk-source', 'smoke-prefix', 'sdk'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    try:
        if args.mode == 'software-gdi-kit':
            require(all(getattr(args, n.replace('-', '_')) for n in
                        ('wine-work', 'native-foundation', 'prx-foundation', 'tls-work', 'native-cpu', 'cpu-dll', 'sdk-source', 'smoke-prefix', 'sdk')),
                    'complete kit inputs are required')
        out, manifest = common(args)
        if args.mode == 'host-checkpoint':
            finish(out, manifest)
            return
        for reg in ('system.reg', 'user.reg', 'userdef.reg'):
            require((args.smoke_prefix / reg).is_file(), 'real prefix smoke test is incomplete')
        pe(args.smoke_prefix / 'drive_c/windows/system32/notepad.exe', 0x8664)
        pe(args.cpu_dll, 0x8664)
        pe(args.native_cpu / 'x86_64-windows/wow64native.dll', 0x8664)
        require((args.native_cpu / 'ps5/wow64native.prx').is_file(), 'native CPU PRX missing')
        validate_native_cpu(args, out / 'provenance/native-cpu-inspection')
        subprocess.run([str(ROOT / 'tools/package_release.sh'), '--title', str(ROOT / 'dist/PPSA99995'),
                        '--wine-ps5', str(args.wine_work), '--host-wine', str(args.host_work / 'install/usr'),
                        '--cpu-dll', str(args.cpu_dll), '--native-cpu', str(args.native_cpu),
                        '--lapy-release', str(ROOT / 'build/native/lapy-helper-release.json'), '--out', str(out)], check=True)
        require(not (out / 'PPSA99995/win/wine/lib/wine/x86_64-unix/libvulkan.prx').exists(), 'software-GDI scope unexpectedly contains a Vulkan driver')
        require(not (out / 'PPSA99995/dev.conf').exists(), 'private dev.conf in kit')
        source_file = out / 'PPSA99995/SOURCES.txt'
        text, count = re.subn(r'^prospero-win  .+$',
                             f"prospero-win  {manifest['project']['repository']}  commit {manifest['project']['commit']}, tree {manifest['project']['tree']}",
                             source_file.read_text(), flags=re.M)
        require(count == 1, 'cannot bind package project provenance')
        source_file.write_text(text + '\nProject and dependency source archives are bundled in ../sources/.\n')
        shutil.copy2(args.cpu_dll, out / 'pc/wowprospero.dll')
        for name, source in (('native-foundation', args.native_foundation), ('prx-foundation', args.prx_foundation), ('payload-sdk', args.sdk_source)):
            expected = {'native-foundation': '9c0b994a048521af6fb84c73ded364504fe250e9',
                        'prx-foundation': '30597512539e7edfde079cbcaf4a626bc0a948c5',
                        'payload-sdk': '4eb701204fc3f8d31e84cf8ca272974e2be9c867'}[name]
            require(git(source, 'rev-parse', 'HEAD') == expected, f'wrong {name} source pin')
            archive(source, out / 'sources' / (name + '.tar.gz'))
            manifest[name + '_commit'] = git(source, 'rev-parse', 'HEAD')
        shutil.copy2(args.wine_work / 'report.json', out / 'provenance/wine-report.json')
        shutil.copy2(args.tls_work / 'root/tls-build-manifest.json', out / 'provenance/tls-build-manifest.json')
        tls = json.loads((args.tls_work / 'root/tls-build-manifest.json').read_text())
        for item in tls['inputs']['sources'].values():
            name = Path(urlparse(item['url']).path).name
            path = args.tls_work / name
            require(path.is_file() and sha(path) == item['sha256'], f'TLS source archive changed: {name}')
            shutil.copy2(path, out / 'sources' / name)
        for path, expected in ((args.wine_work / 'freetype/freetype-2.13.3.tar.xz',
                                '0550350666d427c74daeb85d5ac7bb353acba5f76956395995311a9c6f063289'),
                               (args.native_foundation / '.deps/native/zlib/zlib-1.3.2.tar.gz',
                                'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16')):
            require(path.is_file() and sha(path) == expected, f'missing/changed source archive: {path.name}')
            shutil.copy2(path, out / 'sources' / path.name)
        manifest['host_prefix_smoke_verified'] = True
        finish(out, manifest)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        raise SystemExit('package_diagnostic_kit: ' + str(error))


if __name__ == '__main__':
    main()
