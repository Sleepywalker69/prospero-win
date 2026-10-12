#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Record and recheck uncached target translation units, never a runtime/package."""
from __future__ import annotations
import argparse
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
import package_windows_child_fixture as package
import tls_manifest
import wine_focus_neutral as focus
from build_wine_service_child import TITLE_FOUNDATION, WRAPPER_SHA
prefix, require = package.prefix, package.require
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'pw-focus-target-translation-units/1'
PAIR_SCHEMA = 'pw-focus-target-translation-unit-pair/1'
SDK_COMMIT = '4eb701204fc3f8d31e84cf8ca272974e2be9c867'
FALSE_FLAGS = ('complete_runtime', 'target_executed', 'runtime_validated', 'input_enabled',
               'provider_enabled', 'native_entry_enabled', 'package_enabled',
               'full_module_markers_verified', 'owner_worker_compiled', 'owner_worker_linked')
NTDLL = tuple('dlls/ntdll/unix/' + n for n in
              ('creation', 'loader', 'process', 'server', 'signal_x86_64', 'thread', 'virtual'))
WIN32U = tuple('dlls/win32u/' + n for n in ('ps5drv', 'window', 'winstation', 'syscall'))
SERVER = tuple('server/' + n for n in ('creation', 'trace', 'process', 'ptrace', 'request', 'thread'))
BASE_SOURCES = (*NTDLL, 'dlls/wow64/syscall', *WIN32U, 'dlls/dnsapi/main', 'dlls/dnsapi/query', *SERVER)
BASE_OBJECTS = tuple(n + '.o' for n in (*NTDLL, 'dlls/wow64/x86_64-windows/syscall', *WIN32U,
    *(f'dlls/dnsapi/{arch}-windows/{unit}' for arch in ('i386', 'x86_64') for unit in ('main', 'query')), *SERVER))
FOCUS_OBJECTS = tuple('server/' + n + '.o' for n in
                      ('pw_focus_core', 'pw_focus_requests', 'queue', 'window', 'winstation', 'user', 'main'))
FOCUS_FORCED = tuple('server/' + n for n in ('pw_focus_core', 'pw_focus_requests', 'queue', 'window', 'winstation', 'main'))
SYNTAX = ('wine/ps5/pw_wine_fixture_provider.c', 'wine/ps5/pw_wine_fixture_socket.c',
          'wine/ps5/pw_wine_compat.c', 'native/pw_wine_child_data.c')
PATH_FIELDS = ('repo', 'wine_source', 'host_tools', 'foundation', 'sdk', 'sdk_source', 'tls')


def exact(a, b, message):
    require(json.dumps(a, sort_keys=True, allow_nan=False) == json.dumps(b, sort_keys=True, allow_nan=False), message)


def canonical(path):
    path = Path(path).absolute()
    require('..' not in path.parts, 'noncanonical receipt/input path')
    return path


def state_paths(state):
    exact(sorted(state['paths']), sorted((*PATH_FIELDS, 'work', 'out')), 'input path inventory differs')
    return {name: canonical(value) for name, value in state['paths'].items()}


def record(path):
    path = prefix.ordinary(canonical(path))
    return {'bytes': path.stat().st_size, 'sha256': tls_manifest.digest(path)}


def write_new(path, value):
    with Path(path).open('x') as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def read(path):
    return package.read_json(canonical(path))


def git(path, *args):
    return prefix.git(path, *args)


def mode(value):
    require(type(value) is int and value in (0, 1), 'explicit neutral selector must be 0 or 1')
    return value


def stages(neutral):
    return ['service'] + (['focus'] if mode(neutral) else []) + ['syntax-' + str(i) for i in range(4)]


def expected_command(state, stage):
    p = state_paths(state)
    build, source = p['work'] / 'build', p['work'] / 'source'
    if stage in ('service', 'focus'):
        names = BASE_SOURCES if stage == 'service' else FOCUS_FORCED
        return ['make', '-C', str(build), *(['-k'] if stage == 'service' else []), '-j' + str(state['jobs']),
                *(v for name in names for v in ('-W', str(source / (name + '.c')))),
                *(BASE_OBJECTS if stage == 'service' else FOCUS_OBJECTS)]
    require(stage in stages(state['neutral']), 'unexpected compile stage')
    i = int(stage.rsplit('-', 1)[1])
    flags = ['-DPW_WINE_SERVICE_FIXTURE=1']
    if state['neutral']:
        flags += ['-DPW_WINE_FOCUS_NEUTRAL=1', '-DPW_FOCUS_SERVER_ADAPTER=1',
                  '-DPW_FOCUS_SERVER_REQUESTS=1', '-I' + str(source / 'include')]
    return [str(p['sdk'] / 'bin/prospero-clang'), '-std=c11' if i == 3 else '-std=gnu11',
            '-O2', '-Wall', '-Wextra', '-Werror', *([] if i == 3 else ['-fPIC']), *flags,
            '-fsyntax-only', str(p['repo'] / SYNTAX[i])]


def objects(stage):
    return BASE_OBJECTS if stage == 'service' else FOCUS_OBJECTS if stage == 'focus' else ()


def object_record(path, name):
    value = record(path)
    require(0 < value['bytes'] <= 64 << 20, 'invalid object size')
    data = Path(path).read_bytes()
    if '-windows/' in name:
        wanted = 0x14c if '/i386-windows/' in name else 0x8664
        require(len(data) >= 20 and struct.unpack_from('<H', data)[0] == wanted and
                0 < struct.unpack_from('<H', data, 2)[0] <= 1024 and
                struct.unpack_from('<H', data, 16)[0] == 0, 'wrong COFF target object')
        count = struct.unpack_from('<H', data, 2)[0]
        require(20 + count * 40 <= len(data), 'truncated COFF sections')
        for i in range(count):
            size, offset = struct.unpack_from('<II', data, 20 + i * 40 + 16)
            flags = struct.unpack_from('<I', data, 20 + i * 40 + 36)[0]
            bss = bool(flags & 0x80) and offset == 0
            require(not size or bss or 20 + count * 40 <= offset <= len(data) - size, 'COFF section outside object')
        value['format'] = 'COFF-I386' if wanted == 0x14c else 'COFF-AMD64'
    else:
        require(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01' and
                struct.unpack_from('<HHI', data, 16) == (1, 62, 1) and
                struct.unpack_from('<H', data, 52)[0] == 64, 'wrong ELF64 relocatable target object')
        offset = struct.unpack_from('<Q', data, 40)[0]
        size, count, names = struct.unpack_from('<HHH', data, 58)
        require(size == 64 and 0 < count <= 4096 and names < count and
                64 <= offset <= len(data) - count * size, 'invalid ELF object section table')
        for i in range(count):
            at = offset + i * size
            kind = struct.unpack_from('<I', data, at + 4)[0]
            start, length = struct.unpack_from('<QQ', data, at + 24)
            require(kind == 8 or (start <= len(data) and length <= len(data) - start), 'ELF section outside object')
        value['format'] = 'ELF64-AMD64-REL'
    return value


def selected_flags(state):
    compilers = state['cohort']['build_compilers']
    return {'PW_WINE_PRIVATE_DISPATCH': '1', 'PW_WINE_SERVICE_FIXTURE': '1',
            'PW_WINE_FOCUS_NEUTRAL': str(state['neutral']), 'CFLAGS': '-O2 -g', 'CCACHE_DISABLE': '1', 'CONFIG_SITE': '/dev/null',
            'CC': compilers['gcc']['path'], 'CXX': compilers['g++']['path'],
            'i386_CC': compilers['i686-w64-mingw32-gcc']['path'],
            'x86_64_CC': compilers['x86_64-w64-mingw32-gcc']['path']}


def compiler_provider(name):
    # Wine infers a PE target from the selected *-gcc alias, not the resolved
    # Debian/Ubuntu alternatives provider (*-gcc-win32 or *-gcc-posix).
    # Preserve the invocation name while binding the actual executable bytes.
    found = shutil.which(name)
    require(found is not None, 'selected compiler is missing: ' + name)
    invocation = canonical(found)
    provider = invocation.resolve(strict=True)
    require(os.access(invocation, os.X_OK), 'selected compiler is not executable')
    return {'path': str(invocation), 'real_path': str(provider), **record(provider)}


def current_inputs(state):
    p = state_paths(state)
    root, sdk = p['repo'], p['sdk']
    require(root == ROOT, 'compile checker loaded from another project')
    project = prefix.project(root)
    require(git(p['wine_source'], 'rev-parse', 'HEAD') == focus.WINE_COMMIT and
            not git(p['wine_source'], 'status', '--porcelain', '--untracked-files=normal'), 'raw Wine source differs')
    require(git(p['sdk_source'], 'rev-parse', 'HEAD') == SDK_COMMIT and
            not git(p['sdk_source'], 'status', '--porcelain', '--untracked-files=normal'), 'SDK source differs')
    require(git(p['foundation'], 'rev-parse', 'HEAD') == TITLE_FOUNDATION and
            not git(p['foundation'], 'status', '--porcelain', '--untracked-files=all', '--', 'tooling'), 'foundation source differs')
    require(sdk == p['foundation'] / '.deps/native/ps5-payload-sdk', 'unsupported SDK layout')
    require(record(p['foundation'] / 'tooling/prospero-clang18')['sha256'] == WRAPPER_SHA,
            'selected SDK compiler wrapper source differs')
    tls = tls_manifest.verify(p['tls'], tls_manifest.inputs(root / 'tools/build_tls_ps5.sh', sdk))
    host = p['host_tools'].parent
    exact(read(host / 'tools-only.json'), {'schema': 'pw-wine-build-stage/1', 'stage': 'host-tools',
                                        'complete_runtime': False}, 'host tools-only stage differs')
    require(git(host / 'source', 'rev-parse', 'HEAD') == focus.WINE_COMMIT, 'host source pin differs')
    tools = tls_manifest.tree_files(p['host_tools'] / 'tools')
    require('winebuild/winebuild' in tools and 'widl/widl' in tools, 'matching host tools absent')
    make = Path(shutil.which('make') or '/missing-make').resolve(strict=True)
    compilers = {name: compiler_provider(name) for name in
                 ('gcc', 'g++', 'i686-w64-mingw32-gcc', 'x86_64-w64-mingw32-gcc')}
    return {'project': project, 'project_files': prefix.source_snapshot(root),
            'build_compilers': compilers,
            'wine': {'commit': focus.WINE_COMMIT, 'tree': git(p['wine_source'], 'rev-parse', 'HEAD^{tree}')},
            'sdk_source': {'commit': SDK_COMMIT, 'tree': git(p['sdk_source'], 'rev-parse', 'HEAD^{tree}')},
            'foundation': TITLE_FOUNDATION, 'tls': tls, 'host_tools': tools,
            'host_stamp': record(p['host_tools'] / '.prospero-stamp'),
            'host_source': prefix.source_snapshot(host / 'source'),
            'make': {'path': str(make), **record(make)}, 'focus_source': focus.contract(root)}


def staged_inputs(state):
    p = state_paths(state)
    work, root = p['work'], p['repo']
    source = work / 'source'
    require(git(source, 'rev-parse', 'HEAD') == focus.WINE_COMMIT, 'staged Wine pin differs')
    protocol = re.findall(r'^#define SERVER_PROTOCOL_VERSION\s+(\d+)\s*$',
                          (source / 'include/wine/server_protocol.h').read_text(), re.M)
    require(protocol == [str(963 if state['neutral'] else 962)], 'staged protocol differs')
    header = source / 'include/wine/pw_focus_build.h'
    if state['neutral']:
        contract = focus.contract(root)
        exact(read(work / 'focus-neutral.json'), contract, 'neutral staging contract differs')
        require(prefix.ordinary(header).read_text() == focus.header(contract), 'generated focus header differs')
    else:
        require(not header.exists() and not (work / 'focus-neutral.json').exists(), 'default control contains neutral staging')
    generated = {n: record(work / n) for n in
                 ('build/Makefile', 'build/include/config.h', 'build/.prospero-stamp',
                  'configure.log', 'user-driver-compiler', 'user-driver-sdk-compiler')}
    require(generated['user-driver-compiler'] == generated['user-driver-sdk-compiler'] ==
            record(p['sdk'] / 'bin/prospero-clang'), 'target compiler was cached or substituted')
    return {'source_index': git(source, 'write-tree'), 'sources': prefix.source_snapshot(source),
            'generated': generated, 'focus_header': record(header) if state['neutral'] else None}


def read_state(out):
    state = read(out / 'INPUTS.json'); mode(state['neutral']); state_paths(state)
    require(state['schema'] == 'pw-focus-target-compile-inputs/1' and type(state['jobs']) is int and 1 <= state['jobs'] <= 8,
            'compile input schema/jobs differs')
    require(Path(state['paths']['out']) == out, 'receipt output path differs')
    for name in ('run_id', 'run_attempt'):
        require(isinstance(state[name], str) and re.fullmatch('[1-9][0-9]*', state[name]), 'invalid run identity')
    return state


def command_record(args):
    out = prefix.ordinary(canonical(args.receipt), True)
    state = read_state(out)
    require(Path(state['paths']['repo']) == ROOT, 'recording checker project differs')
    sequence = stages(state['neutral']); require(args.stage in sequence, 'unexpected command stage')
    index = sequence.index(args.stage)
    for i in range(index):
        prior = read(out / ('command-' + str(i) + '.json'))
        require(prior['stage'] == sequence[i] and type(prior['exit']) is int and prior['exit'] == 0,
                'previous compile command failed or order differs')
    path = out / ('command-' + str(index) + '.json')
    require(not path.exists() and not path.is_symlink(), 'compile command already recorded')
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    exact(command, expected_command(state, args.stage), 'actual compile command differs')
    work = Path(state['paths']['work'])
    for name in objects(args.stage):
        path_object = work / 'build' / name
        require(not path_object.exists() and not path_object.is_symlink(), 'target object was not fresh: ' + name)
    if index == 0:
        write_new(out / 'STAGED-SOURCE.json', staged_inputs(state))
    before = {name: record((work / 'source' / (name.removesuffix('.o') + '.c')))
              for name in FOCUS_OBJECTS} if args.stage == 'focus' else {}
    start = time.monotonic()
    try:
        result = subprocess.run(command, check=False, timeout=1500)
        code = result.returncode
    except subprocess.TimeoutExpired:
        code = 124
    outputs = {name: object_record(work / 'build' / name, name) for name in objects(args.stage)} if code == 0 else {}
    write_new(path, {'stage': args.stage, 'argv': command, 'exit': code,
                     'seconds': round(time.monotonic() - start, 6), 'objects': outputs,
                     'syntax_only': args.stage.startswith('syntax-'), 'objects_absent_before': True,
                     'focus_sources_before': before})
    require(code == 0, 'target compile command failed: ' + args.stage)


def driver_command(state):
    p = state['paths']
    return ['sh', str(ROOT / 'tools/build_wine_ps5.sh'), '--source', p['wine_source'],
            '--host-tools', p['host_tools'], '--foundation', p['foundation'], '--sdk', p['sdk'],
            '--work', p['work'], '--jobs', str(state['jobs']), '--compile-check', '--compile-check-receipt', p['out']]


def verify_work(out, *, finished=True):
    out = prefix.ordinary(canonical(out), True)
    state = read_state(out)
    driver = read(out / 'DRIVER-RESULT.json')
    require(type(driver['exit']) is int and driver['exit'] == 0, 'compile-only driver did not succeed')
    exact(driver['argv'], driver_command(state), 'compile-only driver command differs')
    exact(driver['selected_flags'], selected_flags(state), 'compile-only selected flags differ')
    exact(current_inputs(state), state['cohort'], 'source/SDK/compiler inputs changed')
    work = Path(state['paths']['work'])
    staged = read(out / 'STAGED-SOURCE.json')
    exact(staged_inputs(state), staged, 'staged source/configuration changed during compilation')
    exact(read(work / 'compile-check-only.json'), {'schema': 'pw-wine-build-stage/1',
        'stage': 'target-translation-units', 'complete_runtime': False}, 'compile-only exit marker differs')
    for name in ('report.json', 'prx', 'install', 'prefix', 'native-wine-child.self', 'PPSA99995'):
        require(not (work / name).exists() and not (work / name).is_symlink(), 'unexpected runtime/package output')
    sequence = stages(state['neutral']); commands, output = [], {}
    require({p.name for p in out.glob('command-*.json')} == {'command-' + str(i) + '.json' for i in range(len(sequence))},
            'command receipt inventory differs')
    for i, stage in enumerate(sequence):
        entry = read(out / ('command-' + str(i) + '.json'))
        require(entry['stage'] == stage and type(entry['exit']) is int and entry['exit'] == 0 and
                entry['syntax_only'] is stage.startswith('syntax-') and entry['objects_absent_before'] is True,
                'command failed or stage type/freshness differs')
        exact(entry['argv'], expected_command(state, stage), 'retained actual command differs')
        actual = {name: object_record(work / 'build' / name, name) for name in objects(stage)}
        exact(entry['objects'], actual, 'target objects changed or inventory differs')
        if stage == 'focus':
            exact(entry['focus_sources_before'], {name: record(work / 'source' / (name.removesuffix('.o') + '.c'))
                  for name in FOCUS_OBJECTS}, 'focus command source changed')
        output.update(actual); commands.append(entry)
    require(len(output) == (29 if state['neutral'] else 22), 'wrong selected object count')
    receipt = {'schema': SCHEMA, 'project': state['cohort']['project'], 'run_id': state['run_id'],
        'run_attempt': state['run_attempt'], 'neutral': bool(state['neutral']), 'focus_mode': state['neutral'],
        'protocol': 963 if state['neutral'] else 962, 'compile_only': True, 'compiler_cache_used': False,
        **{name: False for name in FALSE_FLAGS}, 'inputs': record(out / 'INPUTS.json'),
        'staged_source': record(out / 'STAGED-SOURCE.json'), 'objects': output, 'commands': commands,
        'driver_result': record(out / 'DRIVER-RESULT.json'), 'selected_flags': selected_flags(state),
        'syntax_only_units': list(SYNTAX), 'driver_log': record(out / 'driver.log'),
        'unit_log': record(work / 'service-translation-units.log'),
        'scope': 'actual target translation units only; no complete runtime, native owner/worker build or target execution'}
    if finished:
        exact(read(out / 'TARGET-COMPILE.json'), receipt, 'accepted compile receipt differs')
    return state, receipt


def run(args):
    require(type(args.neutral) is int and args.neutral in (0, 1), 'neutral must be explicit 0 or 1')
    require(1 <= args.jobs <= 8, 'bounded compile jobs required')
    for value in (args.run_id, args.run_attempt):
        require(re.fullmatch('[1-9][0-9]*', value or ''), 'actual run ID/attempt required')
    paths = {name: str(prefix.ordinary(canonical(getattr(args, name)), True)) for name in PATH_FIELDS}
    require(all(not re.search(r'\s', p) for p in paths.values()), 'build recipe paths cannot contain whitespace')
    existing = [Path(p) for p in paths.values()]
    work, out = (prefix.absent(canonical(p), existing) for p in (args.work, args.out))
    require(not work.is_relative_to(out) and not out.is_relative_to(work), 'work/receipt outputs overlap')
    paths.update(work=str(work), out=str(out))
    state = {'schema': 'pw-focus-target-compile-inputs/1', 'paths': paths, 'neutral': args.neutral,
             'jobs': args.jobs, 'run_id': args.run_id, 'run_attempt': args.run_attempt}
    state['cohort'] = current_inputs(state)
    out.mkdir(); write_new(out / 'INPUTS.json', state)
    # No inherited flags, configure site/cache, provider selection or compiler launcher.
    env = {name: os.environ[name] for name in ('PATH', 'HOME', 'TMPDIR', 'LLVM_CONFIG') if name in os.environ}
    env.update(LC_ALL='C', TZ='UTC', CONFIG_SITE='/dev/null')
    env.update(selected_flags(state))
    env.update(PYTHONDONTWRITEBYTECODE='1', PROSPERO_TLS_ROOT=paths['tls'])
    command = driver_command(state)
    with (out / 'driver.log').open('x') as log:
        log.write(json.dumps({'argv': command, 'selected_flags': selected_flags(state)}) + '\n'); log.flush()
        try:
            result = subprocess.run(command, env=env, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
    write_new(out / 'DRIVER-RESULT.json', {'argv': command, 'exit': code, 'selected_flags': selected_flags(state)})
    require(code == 0, 'target compile-only driver failed; see driver.log')
    _, receipt = verify_work(out, finished=False)
    write_new(out / 'TARGET-COMPILE.json', receipt)
    try:
        verify_work(out)
    except Exception:
        (out / 'TARGET-COMPILE.json').rename(out / 'UNACCEPTED-TARGET.json')
        raise
    return receipt


def archive_git(root, revision, destination):
    with destination.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as zipped:
        process = subprocess.Popen(['git', '-C', str(root), 'archive', revision], stdout=subprocess.PIPE)
        try:
            shutil.copyfileobj(process.stdout, zipped, 1 << 20)
        finally:
            process.stdout.close()
        require(process.wait(timeout=120) == 0, 'source archive command failed')


def collect(args):
    control, off = verify_work(args.control); neutral, on = verify_work(args.neutral)
    require(control['neutral'] == 0 and neutral['neutral'] == 1, 'paired controls crossed')
    exact(control['cohort'], neutral['cohort'], 'control/neutral source SDK compiler cohort differs')
    require((control['run_id'], control['run_attempt']) == (neutral['run_id'], neutral['run_attempt']), 'paired run/attempt differs')
    private = [Path(s['paths'][n]) for s in (control, neutral) for n in ('work', 'out')]
    require(all(not a.is_relative_to(b) and not b.is_relative_to(a) for i, a in enumerate(private)
                for b in private[i + 1:]), 'paired build or receipt directories overlap')
    forbidden = [Path(s['paths'][n]) for s in (control, neutral) for n in s['paths']]
    out = prefix.absent(canonical(args.out), forbidden); out.mkdir()
    for name, state, receipt in (('control', control, off), ('neutral', neutral, on)):
        d = out / name; d.mkdir(); evidence = Path(state['paths']['out']); work = Path(state['paths']['work'])
        for p in sorted(evidence.glob('*.json')):
            shutil.copyfile(prefix.ordinary(p), d / p.name)
        for leaf, p in [('driver.log', evidence / 'driver.log'), ('service-translation-units.log', work / 'service-translation-units.log'),
                        ('configure.log', work / 'configure.log')]:
            require(p.stat().st_size <= 16 << 20, 'compile diagnostic exceeds retained limit')
            shutil.copyfile(prefix.ordinary(p), d / leaf)
        for object_name, value in receipt['objects'].items():
            dest = d / 'objects' / object_name; dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(prefix.ordinary(work / 'build' / object_name), dest)
            exact(object_record(dest, object_name), value, 'copied object differs')
        for file in ('build/Makefile', 'build/include/config.h', 'build/.prospero-stamp', 'user-driver-compiler', 'user-driver-sdk-compiler'):
            dest = d / 'generated' / file; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(prefix.ordinary(work / file), dest)
        if state['neutral']:
            shutil.copyfile(work / 'focus-neutral.json', d / 'focus-neutral.json')
            shutil.copyfile(work / 'source/include/wine/pw_focus_build.h', d / 'pw_focus_build.h')
    sources = out / 'sources'; sources.mkdir(); p = {k: Path(v) for k, v in control['paths'].items()}
    for label, path, revision in [('project', p['repo'], off['project']['commit']),
                                 ('wine', p['wine_source'], focus.WINE_COMMIT), ('sdk', p['sdk_source'], SDK_COMMIT),
                                 ('title-foundation', p['foundation'], TITLE_FOUNDATION)]:
        archive_git(path, revision, sources / (label + '.tar.gz'))
    for role, value in control['cohort']['tls']['inputs']['sources'].items():
        filename = 'cacert-' + value['date'] + '.pem' if role == 'ca_bundle' else value['url'].rsplit('/', 1)[-1]
        original = p['tls'].parent / filename
        require(record(original)['sha256'] == value['sha256'], 'TLS corresponding source archive differs')
        shutil.copyfile(original, sources / filename)
    pins = package.script_pins(p['repo'] / 'tools/build_wine_ps5.sh')
    ft = Path(control['paths']['work']) / 'freetype' / ('freetype-' + pins['FREETYPE_VERSION'] + '.tar.xz')
    require(record(ft)['sha256'] == pins['FREETYPE_SHA256'], 'FreeType corresponding source archive differs')
    shutil.copyfile(ft, sources / ft.name)
    exact(verify_work(args.control)[1], off, 'control changed during collection')
    exact(verify_work(args.neutral)[1], on, 'neutral changed during collection')
    (out / 'SCOPE.txt').write_text(
        'Compile-only target translation-unit evidence. Default962: 22 objects; neutral963: 29 objects.\n'
        'Each mode also ran four syntax-only SDK unit checks. No target executable was run.\n'
        'No complete runtime, PRX, ELF/SELF module cohort, owner/worker build/link, title, prefix,\n'
        'package, active input route or provider is established by this artifact.\n'
        'Host native-entry return-78 and package-refusal controls remain separate evidence.\n'
        'Source and hashes detect stale/changed trusted build inputs; they are not signatures.\n')
    result = {'schema': PAIR_SCHEMA, 'project': off['project'], 'run_id': off['run_id'], 'run_attempt': off['run_attempt'],
              'compile_only': True, 'compiler_cache_used': False, **{name: False for name in FALSE_FLAGS},
              'control_objects': 22, 'neutral_objects': 29, 'syntax_only_units_per_mode': 4,
              'inventory': package.inventory(out), 'scope': on['scope']}
    write_new(out / 'TRANSLATION-UNIT-VALIDATION.json', result)
    (out / 'SHA256SUMS').write_bytes(package.checksums(package.inventory(out)))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest='action', required=True)
    build = commands.add_parser('run')
    for name in (*PATH_FIELDS, 'work', 'out'): build.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    build.add_argument('--neutral', type=int, choices=(0, 1), required=True); build.add_argument('--jobs', type=int, required=True)
    build.add_argument('--run-id', required=True); build.add_argument('--run-attempt', required=True)
    cmd = commands.add_parser('record'); cmd.add_argument('--receipt', type=Path, required=True); cmd.add_argument('--stage', required=True)
    cmd.add_argument('command', nargs=argparse.REMAINDER)
    pair = commands.add_parser('collect')
    for name in ('control', 'neutral', 'out'): pair.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'record': command_record(args)
    else:
        result = run(args) if args.action == 'run' else collect(args)
        print(json.dumps({'schema': result['schema'], 'project': result['project'], 'complete_runtime': False}))


if __name__ == '__main__':
    main()
