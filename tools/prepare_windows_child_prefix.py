#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Prepare one fresh original-fixture prefix through the existing Wine tools.

Only initialize executes host Wine (wineboot, then wineserver -w). Export is
filesystem-only. Never execute the original fixture or any target ELF/SELF.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
import portable_prefix_audit as audit

SLUG = 'windows-child-fixture-v1'
APP = 'drive_c/windows-child-fixture'
BATTLE_SLUG = 'battlenet-experimental-v1'
BATTLE_APP = 'drive_c/installer'
WINE = '490f6d5dcbb2a5047345b8af88d114bbcaad69a8'
require, sha = audit.require, audit.sha


def load_tool(root, name):
    path = root / 'tools' / (name + '.py')
    spec = importlib.util.spec_from_file_location('fixture_' + name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True,
                          capture_output=True, text=True, timeout=60).stdout.strip()


def project(root):
    require(not git(root, 'status', '--porcelain', '--untracked-files=normal'), 'project must be clean')
    return {'commit': git(root, 'rev-parse', 'HEAD'), 'tree': git(root, 'rev-parse', 'HEAD^{tree}')}


def source_snapshot(source):
    """Bind actual tracked and staged-owned source bytes, not only the index."""
    raw = subprocess.run(['git', '-C', str(source), 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                         check=True, capture_output=True, timeout=60).stdout
    result = {}
    for name in sorted(set(raw.decode().rstrip('\0').split('\0'))):
        audit.safe_relative(name)
        path = source / name
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            result[name] = {'link': os.readlink(path)}
        else:
            require(stat.S_ISREG(info.st_mode), 'nonregular source input')
            result[name] = {'sha256': sha(path), 'executable': bool(info.st_mode & 0o111)}
    return result


def verify_source_snapshot(source, expected):
    require(source_snapshot(source) == expected, 'actual Wine source bytes differ from staged cohort')


def stage_reference(args):
    root, wine = args.repo.resolve(strict=True), args.wine_source.resolve(strict=True)
    require(git(wine, 'rev-parse', 'HEAD') == WINE, 'wrong reference Wine pin')
    out = absent(args.out, (root, wine)); out.mkdir()
    source = out / 'source'
    subprocess.run(['git', 'clone', '--quiet', '--shared', '--no-checkout', str(wine), str(source)], check=True)
    subprocess.run(['git', '-C', str(source), 'checkout', '--quiet', '--detach', WINE], check=True)
    patches = sorted((root / 'wine/patches').glob('*.patch'))
    for path in patches:
        subprocess.run(['git', '-C', str(source), 'apply', '--index', str(path)], check=True)
    subprocess.run([sys.executable, str(root / 'tools/stage_vk_batch.py'), '--source', str(source), '--repo', str(root)], check=True)
    for original, target in [('wine/ps5/time/pw_qpc_clock.h', 'dlls/ntdll/pw_qpc_clock.h'),
                             ('wine/ps5/input/pw_key_shared.h', 'dlls/win32u/pw_key_shared.h')]:
        shutil.copyfile(root / original, source / target)
    for name in ('pw_d3d9_window.c', 'pw_d3d9_window.h', 'pw_d3d9_window_driver.c', 'pw_d3d9_window_driver.h'):
        shutil.copyfile(root / 'wine/ps5' / name, source / 'dlls/win32u' / name)
    host = source_snapshot(source)
    ps5 = source_snapshot(source)
    json_out(args.report, {'schema': 'pw-windows-child-source-cohort/1', 'project': project(root),
                          'wine_commit': WINE, 'patches': {p.name: sha(p) for p in patches},
                          'host_source': host, 'ps5_source': ps5})


def ordinary(path, directory=False):
    path = Path(path)
    require(path.is_absolute(), 'paths must be absolute')
    for part in (path, *path.parents):
        require(not part.is_symlink(), 'symlink path component: ' + str(part))
    mode = path.lstat().st_mode
    require(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode), 'not an ordinary input: ' + str(path))
    return path


def absent(path, inputs=()):
    path = Path(path).absolute()
    require(not path.exists() and not path.is_symlink(), 'output already exists')
    ordinary(path.parent, True)
    for source in inputs:
        source = Path(source).resolve(strict=True)
        require(not path.is_relative_to(source) and not source.is_relative_to(path), 'output overlaps input')
    return path


def inventory(root, allow_internal_links=False):
    """Include the root and all directories; reject case aliases and special files."""
    root = ordinary(Path(root).absolute(), True)
    result, folded = {'.': {'type': 'directory', 'mode': stat.S_IMODE(root.stat().st_mode)}}, set()
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        audit.safe_relative(name)
        require(name.casefold() not in folded, 'case-colliding inventory')
        folded.add(name.casefold())
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            require(allow_internal_links and path.resolve(strict=True).is_relative_to(root), 'unapproved inventory link')
            result[name] = {'type': 'symlink', 'target': os.readlink(path)}
        elif stat.S_ISDIR(info.st_mode):
            result[name] = {'type': 'directory', 'mode': stat.S_IMODE(info.st_mode)}
        else:
            require(stat.S_ISREG(info.st_mode), 'special inventory object')
            result[name] = {'type': 'file', 'bytes': info.st_size, 'sha256': sha(path),
                            'mode': stat.S_IMODE(info.st_mode)}
    return result


def json_out(path, data):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write('\n')


def host_stamp(root, patches):
    units = ('pw_d3d9_window.c', 'pw_d3d9_window.h',
             'pw_d3d9_window_driver.c', 'pw_d3d9_window_driver.h')
    return hashlib.sha256((WINE + '\n--prefix=/usr --enable-archs=i386,x86_64 --disable-tests\n').encode() +
                          b''.join(p.read_bytes() for p in patches) +
                          b''.join((root / 'wine/ps5' / n).read_bytes() for n in units)).hexdigest()


def host_identity(root, host_work, cohort):
    source, build, host = host_work / 'source', host_work / 'build', host_work / 'install/usr'
    require(git(source, 'rev-parse', 'HEAD') == WINE, 'wrong host Wine source')
    patches = sorted((root / 'wine/patches').glob('*.patch'))
    reference = json.loads(cohort.read_text())
    require(reference['schema'] == 'pw-windows-child-source-cohort/1' and
            reference['project'] == project(root) and reference['wine_commit'] == WINE and
            reference['patches'] == {p.name: sha(p) for p in patches}, 'wrong independently staged source cohort')
    verify_source_snapshot(source, reference['host_source'])
    stamp = host_stamp(root, patches)
    require((build / '.prospero-stamp').read_text().strip() == stamp, 'stale host Wine build cohort')
    files = inventory(host, allow_internal_links=True)
    # The accepted auditor resolves internal file links and binds their bytes.
    host_files = {}
    for path in sorted(host.rglob('*')):
        if path.is_file():
            resolved = path.resolve(strict=True)
            require(resolved.is_relative_to(host.resolve()), 'host file link escapes installation')
            host_files['pc/host-wine/usr/' + path.relative_to(host).as_posix()] = {
                'bytes': resolved.stat().st_size, 'sha256': sha(resolved)}
    for relative in ('bin/wine', 'bin/wineserver', 'lib/wine/x86_64-windows/ntdll.dll',
                     'lib/wine/i386-windows/ntdll.dll', 'share/wine/wine.inf'):
        require((host / relative).is_file(), 'incomplete full host runtime: ' + relative)
    abi = load_tool(root, 'check_private_dispatch_abi')
    host_thunks = {name: abi.check_image((host / 'lib/wine/x86_64-windows' / (name + '.dll')).read_bytes(), anchor, 0)
                   for name, anchor in (('ntdll', 'NtClose'), ('win32u', 'NtUserGetThreadState'))}
    return {'project': project(root), 'wine_commit': WINE, 'patches': {p.name: sha(p) for p in patches},
            'patched_index_tree': git(source, 'write-tree'), 'stamp': stamp, 'cohort_sha256': sha(cohort),
            'files': files, 'host_files': host_files, 'host_dispatch_thunks': host_thunks,
            'tools': {n: sha(root / 'tools' / (n + '.py')) for n in ('pw_install', 'pw_prefix')}}, host


def battle_profile(root):
    # The installer is intentionally absent, so pw_install.profile() cannot
    # truthfully derive its architecture. This one explicit template is tested
    # with the existing native profile parser; no placeholder PE is produced.
    require((root / 'src/pw_game_profile.c').is_file(), 'current profile parser unavailable')
    return ('; Experimental user-supplied installer; execution has not been validated.\n'
            '[application]\n'
            'id = battlenet-experimental-v1\n'
            'name = Battle.net experimental installer\n'
            'executable = C:\\installer\\Battle.net-Setup.exe\n'
            'working_directory = C:\\installer\n'
            'prefix = battlenet-experimental-v1\n'
            'runtime = wine-wow64\narchitecture = pe32\ngraphics = auto\n'
            '\n[runtime]\ncpu = translator\n')


def recipe(battlenet=False):
    if battlenet:
        return {'name': 'Battle.net experimental installer', 'game_slug': BATTLE_SLUG, 'runner': 'wine',
                'prospero': {'graphics': 'auto'}, 'script': {'game': {
                    'exe': BATTLE_APP + '/Battle.net-Setup.exe', 'working_dir': '$GAMEDIR/' + BATTLE_APP},
                    'wine': {'dxvk': False}}}
    return {'name': 'Original Windows child-process fixture', 'game_slug': SLUG, 'runner': 'wine',
            'prospero': {'graphics': 'auto'}, 'script': {'game': {
                'exe': APP + '/parent.exe', 'working_dir': '$GAMEDIR/' + APP}, 'wine': {'dxvk': False}}}


def installer(root, host, library, battlenet=False):
    tool = load_tool(root, 'pw_install')
    args = argparse.Namespace(slug=BATTLE_SLUG if battlenet else SLUG, library=str(library), wine=str(host / 'bin/wine'),
                              resolution='1920x1080', file=[], input=[], disc=None, mesa_zink=None)
    return tool.Installer(recipe(battlenet), root / 'tools/prepare_windows_child_prefix.py', args)


def initialize(args, battlenet=False):
    root, host_work = args.repo.resolve(strict=True), args.host_work.resolve(strict=True)
    identity, host = host_identity(root, host_work, args.cohort)
    work = absent(args.work, (root, host_work))
    work.mkdir(mode=0o700)
    for name in ('home', 'cache', 'tmp', 'library'):
        (work / name).mkdir(mode=0o700)
    # Only the six built Wine fonts are discoverable during initialization.
    fontconfig = work / 'fonts.conf'
    require('&' not in str(host) and '<' not in str(host), 'unsupported font path')
    fontconfig.write_text('<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd">'
                          '<fontconfig><dir>' + str(host / 'share/wine/fonts') + '</dir>'
                          '<cachedir>' + str(work / 'cache') + '/fonts</cachedir></fontconfig>\n')
    os.environ.update(HOME=str(work / 'home'), XDG_CACHE_HOME=str(work / 'cache'),
                      XDG_CONFIG_HOME=str(work / 'home'), TMPDIR=str(work / 'tmp'),
                      USER='prospero', LOGNAME='prospero', FONTCONFIG_FILE=str(fontconfig),
                      FONTCONFIG_PATH=str(work), WINEDEBUG='-all')
    for name in ('WINEPREFIX', 'WINEDLLPATH', 'WINESERVERSOCKET', 'WINELOADER', 'WINESERVER'):
        os.environ.pop(name, None)
    setup = installer(root, host, work / 'library', battlenet)
    setup.gamedir.mkdir(parents=True, mode=0o700)
    setup.task({'name': 'create_prefix'})
    subprocess.run([str(setup.wineserver), '-w'], env=setup.wine_env(), check=True, timeout=60)
    after, _ = host_identity(root, host_work, args.cohort)
    require(after == identity, 'host/source changed during initialization')
    json_out(work / 'INITIALIZED.json', {'schema': 'pw-fixture-prefix-initialized/1', 'inputs': identity,
              'slug': BATTLE_SLUG if battlenet else SLUG, 'fixture_executed': False, 'operation': 'pw_install create_prefix; wineboot --init; wineserver -w'})


def compiler_inputs(name):
    selected = shutil.which(name)
    require(selected is not None, 'CPU compiler unavailable: ' + name)
    selected = Path(selected).resolve(strict=True)
    version = subprocess.run([str(selected), '--version'], check=True, capture_output=True, text=True, timeout=30).stdout
    record = {'path': str(selected), 'sha256': sha(selected), 'version': version, 'programs': {}, 'headers': {}}
    for program in ('cc1', 'as', 'ld'):
        value = subprocess.run([str(selected), '-print-prog-name=' + program], check=True,
                               capture_output=True, text=True, timeout=30).stdout.strip()
        path = Path(value) if '/' in value else Path(shutil.which(value) or '')
        require(path.is_file(), 'CPU compiler subprogram unavailable: ' + program)
        path = path.resolve(strict=True)
        record['programs'][program] = {'path': str(path), 'sha256': sha(path)}
    include = Path(subprocess.run([str(selected), '-print-file-name=include'], check=True,
                                  capture_output=True, text=True, timeout=30).stdout.strip()).resolve(strict=True)
    require(include.is_dir(), 'CPU compiler builtin include directory unavailable')
    record['headers'] = {p.relative_to(include).as_posix(): sha(p) for p in sorted(include.rglob('*')) if p.is_file()}
    return record


def consumed_build_inputs(host_work):
    build = host_work / 'build'
    names = ('tools/winegcc/winegcc', 'tools/winebuild/winebuild', 'dlls/ntdll/ntdll.so',
             'dlls/wow64/x86_64-windows/libwow64.a', 'dlls/ntdll/x86_64-windows/libntdll.a',
             'libs/winecrt0/x86_64-windows/libwinecrt0.a', 'libs/compiler-rt/x86_64-windows/libcompiler-rt.a')
    result = {name: {'bytes': (build / name).stat().st_size, 'sha256': sha(build / name)} for name in names}
    include, seen = build / 'include', set()
    for directory, directories, files in os.walk(include, followlinks=True):
        path = Path(directory); resolved = path.resolve(strict=True)
        require(resolved.is_relative_to(host_work.resolve()) and resolved not in seen, 'unsafe build include topology')
        seen.add(resolved)
        for name in files:
            source = path / name; actual = source.resolve(strict=True)
            require(actual.is_relative_to(host_work.resolve()) and actual.is_file(), 'build header escapes bound host work')
            result[source.relative_to(build).as_posix()] = {'bytes': actual.stat().st_size, 'sha256': sha(actual)}
    require(seen, 'host build include directory absent')
    return result


def cpu_inputs(root, host_work, cohort):
    identity, _ = host_identity(root, host_work, cohort)
    return {'project': identity['project'], 'host_stamp': identity['stamp'], 'cohort_sha256': sha(cohort),
            'recipe_sha256': sha(root / 'tools/build_wowprospero.sh'),
            'compilers': {name: compiler_inputs(name) for name in ('gcc', 'x86_64-w64-mingw32-gcc')},
            'host_build_inputs': consumed_build_inputs(host_work),
            'source_files': {str(p.relative_to(root)): sha(p) for directory in
                             ('wine/wowprospero', 'include', 'src') for p in sorted((root / directory).rglob('*')) if p.is_file()}}


def build_cpu(args):
    root, host_work = args.repo.resolve(strict=True), args.host_work.resolve(strict=True)
    inputs = cpu_inputs(root, host_work, args.cohort)
    out = absent(args.out, (root, host_work)); out.mkdir()
    command = ['sh', str(root / 'tools/build_wowprospero.sh'), '--build', str(host_work / 'build'),
               '--source', str(host_work / 'source'), '--output', str(out), '--jobs', '2']
    subprocess.run(command, check=True)
    require(cpu_inputs(root, host_work, args.cohort) == inputs, 'CPU build inputs changed')
    outputs = {str(p.relative_to(out)): {'bytes': p.stat().st_size, 'sha256': sha(p)} for p in sorted(out.rglob('*'))
               if p.is_file() and not p.is_symlink()}
    require('x86_64-windows/wowprospero.dll' in outputs, 'CPU DLL was not built')
    json_out(out / 'cpu-build.json', {'schema': 'pw-fixture-cpu-build/1', 'inputs': inputs,
                                     'outputs': outputs, 'command': command, 'executed': False})


def verify_cpu(directory, expected):
    manifest = json.loads((directory / 'cpu-build.json').read_text())
    require(manifest.get('schema') == 'pw-fixture-cpu-build/1' and manifest.get('inputs') == expected and
            manifest.get('executed') is False, 'CPU build input identity differs')
    for name, record in manifest['outputs'].items():
        audit.safe_relative(name)
        path = directory / name; ordinary(path)
        require(record == {'bytes': path.stat().st_size, 'sha256': sha(path)}, 'CPU build output changed')
    require('x86_64-windows/wowprospero.dll' in manifest['outputs'], 'CPU DLL absent from manifest')
    return manifest, directory / 'x86_64-windows/wowprospero.dll'


def validate_pair(directory, expected_project):
    metadata = json.loads((directory / 'fixture-source.json').read_text())
    require(metadata.get('schema') == 'pw-original-windows-child-msvc/1' and
            metadata.get('project') == expected_project and metadata.get('architecture') == 'x64',
            'fixture producer/source identity mismatch')
    compiler = metadata.get('compiler', {})
    require(compiler.get('name') == 'MSVC cl.exe' and isinstance(compiler.get('file_version'), str) and
            compiler['file_version'] and re.fullmatch('[0-9a-f]{64}', compiler.get('sha256', '')) and
            metadata.get('reference') == {'exit': 0, 'deadline_seconds': 45},
            'fixture lacks exact MSVC compiler and successful Windows reference evidence')
    parent, child = directory / 'parent.exe', directory / 'child.exe'
    ordinary(parent); ordinary(child)
    require(0 < parent.stat().st_size <= 16 << 20 and child.stat().st_size == parent.stat().st_size,
            'fixture pair must be identical bounded images')
    value = parent.read_bytes()
    require(0 < len(value) <= 16 << 20 and value == child.read_bytes(), 'fixture pair must be identical bounded images')
    require(metadata.get('files') == {p.name: {'bytes': p.stat().st_size, 'sha256': sha(p)} for p in (parent, child)},
            'fixture build record disagrees with bytes')
    require(len(value) >= 64 and value[:2] == b'MZ', 'invalid fixture PE')
    pe, = struct.unpack_from('<I', value, 60)
    require(pe <= len(value) - 24 - 152 and value[pe:pe + 4] == b'PE\0\0', 'truncated fixture PE')
    machine, = struct.unpack_from('<H', value, pe + 4)
    flags, = struct.unpack_from('<H', value, pe + 22)
    magic, = struct.unpack_from('<H', value, pe + 24)
    rva, size = struct.unpack_from('<II', value, pe + 24 + 112 + 40)
    require(machine == 0x8664 and magic == 0x20b and not flags & 1 and rva and size,
            'fixture requires AMD64 PE32+ and retained base relocations')
    return metadata


def verify_pair_copy(directory, metadata):
    for name in ('parent.exe', 'child.exe'):
        path = directory / name; ordinary(path)
        require({'bytes': path.stat().st_size, 'sha256': sha(path)} == metadata['files'][name],
                'exported original fixture differs')


def patched_pe_set(root, wine_work):
    checker = load_tool(root, 'check_wine_prx_build')
    expected = {a + '/' + n + '.dll' for a in ('i386-windows', 'x86_64-windows') for n in checker.PE}
    expected |= {'x86_64-windows/wow64.dll', 'x86_64-windows/wow64win.dll'}
    report = json.loads((wine_work / 'report.json').read_text())
    require(set(report['pe']) == expected and len(expected) == 22, 'wrong matched patched PE set')
    for name in expected:
        ordinary(wine_work / 'pe' / name)
        require(sha(wine_work / 'pe' / name) == report['pe'][name], 'stale patched PE: ' + name)
    return report['pe']


def replace_pes(prefix, wine_work, expected):
    changes = {}
    for name, digest in sorted(expected.items()):
        arch, leaf = name.split('/')
        relative = 'drive_c/windows/' + ('system32' if arch == 'x86_64-windows' else 'syswow64') + '/' + leaf
        target, source = prefix / relative, wine_work / 'pe' / name
        ordinary(target); ordinary(target.parent, True); ordinary(source)
        before = {'bytes': target.stat().st_size, 'sha256': sha(target)}
        require(sha(source) == digest, 'patched PE changed during staging')
        # The destination belongs to this freshly converted output only.
        target.write_bytes(source.read_bytes())
        target.chmod(0o644)
        changes[relative] = {'before': before, 'after': {'bytes': target.stat().st_size, 'sha256': sha(target)},
                             'source': 'pe/' + name}
        require(changes[relative]['after']['sha256'] == digest, 'patched PE copy failed')
    return changes


def verify_delta(before, after, changes):
    require(set(before) == set(after), 'unexpected prepared prefix additions/removals')
    for name in before:
        if name in changes:
            require(before[name]['type'] == after[name]['type'] == 'file' and
                    before[name]['sha256'] == changes[name]['before']['sha256'] and
                    after[name]['sha256'] == changes[name]['after']['sha256'] and after[name]['mode'] == 0o644,
                    'patched PE delta differs')
        else:
            require(before[name] == after[name], 'unapproved prefix mutation: ' + name)


def check_battlenet_runtime(repo, host_work, wine_work, cohort, cpu_output, llvm_bindir):
    identity, _ = host_identity(repo, host_work, cohort)
    reference = json.loads(cohort.read_text())
    verify_source_snapshot(wine_work / 'source', reference['ps5_source'])
    patched_pe_set(repo, wine_work)
    cpu, dll = verify_cpu(cpu_output, cpu_inputs(repo, host_work, cohort))
    dispatcher = load_tool(repo, 'check_private_dispatch_abi').check_build(
        wine_work, 1, llvm_bindir / 'llvm-readelf', require_wow64=True)
    require(dispatcher.get('wow64', {}).get('abi') == 1 and
            dispatcher['wow64'].get('runtime_validated') is False,
            'actual translated-I386 capability was not checked')
    report = json.loads((wine_work / 'report.json').read_text())
    require(report.get('service_fixture') == {'enabled': True, 'unix_define': 'PW_WINE_SERVICE_FIXTURE=1',
                                              'abi': 1, 'runtime_validated': False},
            'Battle child candidate lacks actual explicit service build selector')
    wow64 = load_tool(repo, 'private_dispatch_wow64')
    wow64.mapped_pe(dll.read_bytes(), 0x8664)
    require(cpu['inputs']['project'] == identity['project'], 'CPU and runtime source identities differ')
    return {'private_dispatcher': dispatcher, 'cpu': cpu,
            'cpu_manifest_sha256': sha(cpu_output / 'cpu-build.json'),
            'translator_pe': {'bytes': dll.stat().st_size, 'sha256': sha(dll)},
            'runtime_validated': False}


def export(args, battlenet=False):
    slug, application = (BATTLE_SLUG, BATTLE_APP) if battlenet else (SLUG, APP)
    root, host_work, work = (p.resolve(strict=True) for p in (args.repo, args.host_work, args.work))
    identity, host = host_identity(root, host_work, args.cohort)
    initialized = json.loads((work / 'INITIALIZED.json').read_text())
    require(initialized.get('inputs') == identity and initialized.get('slug') == slug,
            'prefix initialization cohort differs')
    wine_work = args.wine_work.resolve(strict=True)
    require(git(wine_work / 'source', 'rev-parse', 'HEAD') == WINE and
            git(wine_work / 'source', 'write-tree') == identity['patched_index_tree'], 'host and PS5 patch cohorts differ')
    verify_source_snapshot(wine_work / 'source', json.loads(args.cohort.read_text())['ps5_source'])
    cpu, cpu_dll = verify_cpu(args.cpu_output.resolve(strict=True), cpu_inputs(root, host_work, args.cohort))
    pair = None
    if not battlenet:
        pair = validate_pair(args.fixture.resolve(strict=True), identity['project'])
        require(pair.get('source_sha256') == sha(root / 'tests/fixtures/windows_child_process.c'), 'fixture source changed')
        require(pair.get('recipe_sha256') == sha(root / 'tools/build_windows_child_fixture.ps1'), 'fixture build recipe changed')
    runtime_check = check_battlenet_runtime(root, host_work, wine_work, args.cohort,
                                          args.cpu_output.resolve(strict=True), args.llvm_bindir) if battlenet else None
    expected = patched_pe_set(root, wine_work)
    abi = load_tool(root, 'check_private_dispatch_abi').check_build(wine_work, 1, args.llvm_bindir / 'llvm-readelf')
    converter = load_tool(root, 'pw_prefix')
    library, prefix = work / 'library', work / 'library/prefixes' / slug
    ordinary(prefix, True)
    require(not (library / '.pw').exists(), 'prefix has already been synced')
    issues, text = {'files': [], 'scan_complete': False}, {'schema': 'pw-seed-text-audit/1', 'files': [], 'scan_complete': False}
    # This archive is made from the verified pinned Wine Git commit by the producer.
    require(git(args.wine_source, 'rev-parse', 'HEAD') == WINE, 'wrong source archive checkout')
    expected_archive = subprocess.run(['git', '-C', str(args.wine_source), 'archive', WINE],
                                     check=True, capture_output=True, timeout=120).stdout
    import gzip
    require(gzip.decompress(args.wine_archive.read_bytes()) == expected_archive, 'Wine archive differs from pinned Git source')
    try:
        resources = audit.resource_hashes(host, identity['host_files'])
        generated = audit.generated_module_hashes(host, identity['host_files'], args.wine_archive, sha(args.wine_archive))
        fonts = audit.copy_portable_fonts(prefix, host, identity['host_files'])
        plans = {n: audit.portable_registry(n, (prefix / n).read_bytes(), host) for n in sorted(audit.REGISTRIES)}
        require(sum(len(p['rewrites']) for p in plans.values()) == 18, 'wrong font rewrite count')
        source_audit = audit.audit_source(converter, prefix, host, identity['host_files'], resources, generated,
                                         issues, text, plans)
    finally:
        if issues['files']:
            (work / 'UNAPPROVED-FILES.json').write_bytes(audit.unapproved_metadata(issues))
        (work / 'TEXT-AUDIT.json').write_bytes(audit.text_metadata(text))
    require(converter.CPU_KEY in (prefix / 'system.reg').read_bytes() and
            (prefix / 'drive_c/windows/winsxs').is_dir(), 'prefix initialization incomplete')
    app = prefix / application
    absent(app, ()); app.mkdir()
    if not battlenet:
        for name in ('parent.exe', 'child.exe'):
            shutil.copyfile(args.fixture / name, app / name)
            (app / name).chmod(0o644)
    setup = installer(root, host, library, battlenet)
    profile = library / 'profiles' / (slug + '.profile')
    profile.parent.mkdir(exist_ok=True)
    require(not profile.exists(), 'profile already exists')
    profile.write_text(battle_profile(root) if battlenet else setup.profile([]))
    audit.audit_text(profile.read_bytes(), 'fixture profile')
    out = absent(args.out, (root, host_work, wine_work, work, *((args.fixture,) if not battlenet else ())))
    remote = audit.FilesystemRemote(out)
    require(audit.sync_portable_registry(converter,
        ['push', slug, '--library', str(library), '--cpu-dll', str(cpu_dll)], remote, plans, prefix) == 0,
        'existing prefix converter failed')
    exported = out / 'data/prospero-win/prefixes' / slug
    require(not (out / 'data/prospero-win/profiles/profiles.lst').exists(), 'unexpected profile index')
    for name, plan in plans.items():
        require((exported / name).read_bytes() == converter.to_console(name, plan['data']), 'registry conversion differs')
    require(sha(exported / converter.CPU_DLL) == cpu['outputs']['x86_64-windows/wowprospero.dll']['sha256'], 'CPU conversion input differs')
    if battlenet:
        require(not any((exported / application).iterdir()), 'installer directory must remain empty')
    else:
        verify_pair_copy(exported / application, pair)
    for record in fonts.values():
        require(sha(exported / record['destination']) == record['sha256'], 'portable font changed')
    before = inventory(exported)
    changes = replace_pes(exported, wine_work, expected)
    after = inventory(exported)
    verify_delta(before, after, changes)
    for name, anchor in (('ntdll', 'NtClose'), ('win32u', 'NtUserGetThreadState')):
        selected = exported / 'drive_c/windows/system32' / (name + '.dll')
        actual = load_tool(root, 'check_private_dispatch_abi').check_image(selected.read_bytes(), anchor, 1)
        require(actual == abi['pe_identity']['modules'][name], 'prepared prefix private ABI differs')
    require(inventory(host, True) == identity['files'] and project(root) == identity['project'], 'inputs changed during export')
    result = {'schema': 'pw-windows-child-prefix/1', 'project': identity['project'], 'wine_commit': WINE,
              'patches': identity['patches'], 'host_stamp': identity['stamp'], 'tools': identity['tools'],
              'host_dispatch_thunks': identity['host_dispatch_thunks'],
              'fixture': pair, 'cpu': cpu, 'source_audit': source_audit, 'portable_fonts': fonts, 'patched_pe_delta': changes,
              'private_dispatcher': abi, 'inventory': inventory(out), 'fixture_executed': False,
              'console_execution_verified': False, 'scope': 'fresh hosted wineboot and filesystem conversion only'}
    if battlenet:
        for name in ('ntdll', 'win32u'):
            selected = exported / 'drive_c/windows/syswow64' / (name + '.dll')
            require(sha(selected) == runtime_check['private_dispatcher']['wow64']['i386_modules'][name]['sha256'],
                    'prepared prefix I386 module differs from actual checked capability')
        require(runtime_check == check_battlenet_runtime(root, host_work, wine_work, args.cohort,
                                                        args.cpu_output.resolve(strict=True), args.llvm_bindir),
                'Battle runtime inputs changed during prefix export')
        result.update(schema='pw-battlenet-experimental-prefix/1', runtime_check=runtime_check,
                      installer_included=False, installer_destination='C:\\installer\\Battle.net-Setup.exe')
        result.pop('fixture'); result.pop('fixture_executed')
    json_out(args.report, result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('stage-reference', 'build-cpu', 'initialize', 'export', 'initialize-battlenet', 'export-battlenet'))
    parser.add_argument('--repo', type=Path, required=True)
    for name in ('host-work', 'work', 'cohort', 'wine-work', 'wine-source', 'wine-archive', 'fixture',
                 'cpu-output', 'llvm-bindir', 'out', 'report'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    required = {'stage-reference': ('wine-source', 'out', 'report'),
                'build-cpu': ('host-work', 'cohort', 'out'), 'initialize': ('host-work', 'cohort', 'work'),
                'export': ('host-work', 'cohort', 'work', 'wine-work', 'wine-source', 'wine-archive', 'fixture',
                           'cpu-output', 'llvm-bindir', 'out', 'report')}
    required['initialize-battlenet'] = required['initialize']
    required['export-battlenet'] = tuple(n for n in required['export'] if n != 'fixture')
    require(all(getattr(args, n.replace('-', '_')) for n in required[args.operation]), 'missing operation inputs')
    {'stage-reference': stage_reference, 'build-cpu': build_cpu, 'initialize': initialize, 'export': export,
     'initialize-battlenet': lambda a: initialize(a, True),
     'export-battlenet': lambda a: export(a, True)}[args.operation](args)


if __name__ == '__main__':
    main()
