#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Explicit compiler-only Wine cache identity, launchers and per-stage evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import time

SCHEMA = 'pw-wine-compiler-cache/1'
SETTINGS = {'compiler_check': 'content', 'hard_link': 'false', 'sloppiness': '',
            'hash_dir': 'true', 'direct_mode': 'true', 'run_second_cpp': 'true',
            'remote_storage': '', 'ignore_options': '', 'ignore_headers_in_manifest': ''}
FLAGS = ('CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CROSSCFLAGS', 'i386_CFLAGS',
         'x86_64_CFLAGS', 'PW_WINE_PRIVATE_DISPATCH', 'PW_WINE_SERVICE_FIXTURE')


def sha(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'


def command(args):
    return subprocess.check_output([str(x) for x in args], text=True).strip()


def file_record(path):
    path = Path(path).absolute()
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError('expected regular compiler input: ' + str(path))
    return {'path': str(path), 'resolved': str(resolved), 'sha256': sha(path)}


def tree_record(path, ancestors=()):
    root = Path(path).resolve(strict=True)
    if not root.is_dir() or root in ancestors:
        raise ValueError('invalid or cyclic compiler input tree: ' + str(root))
    records = {}
    for directory, folders, files in os.walk(root, followlinks=False):
        for name in sorted(folders + files):
            item = Path(directory) / name
            relative = item.relative_to(root).as_posix()
            if item.is_symlink():
                resolved = item.resolve(strict=True)
                records[relative] = {'link': os.readlink(item), 'resolved': str(resolved)}
                if resolved.is_file():
                    records[relative]['sha256'] = sha(resolved)
                elif resolved.is_dir():
                    records[relative]['tree'] = tree_record(resolved, (*ancestors, root))
                else:
                    raise ValueError('special linked compiler input: ' + str(item))
            elif item.is_file():
                records[relative] = {'sha256': sha(item)}
            elif not item.is_dir():
                raise ValueError('special compiler input: ' + str(item))
    return {'path': str(root), 'entries': len(records), 'sha256': hashlib.sha256(canonical(records)).hexdigest()}


def executable(name):
    found = shutil.which(name)
    if not found:
        raise ValueError('required compiler tool unavailable: ' + name)
    # Preserve argv[0] (clang++ and target-prefixed GCC use their invocation name).
    return Path(found).absolute()


def compiler_record(path, kind):
    result = {'file': file_record(path), 'version': command([path, '--version']), 'kind': kind}
    providers = {}
    if kind == 'clang':
        resource = command([path, '-print-resource-dir'])
        result['resources'] = tree_record(resource)
    else:
        for name in ('cc1', 'cc1plus', 'as', 'ld', 'collect2', 'lto1'):
            provider = command([path, '-print-prog-name=' + name])
            selected = Path(provider) if '/' in provider else executable(provider)
            providers[name] = file_record(selected)
    # Record the real host libraries used by the selected compiler binary.
    libraries = {}
    with path.open('rb') as stream:
        is_elf = stream.read(4) == b'\x7fELF'
    linked = command(['ldd', path.resolve()]) if is_elf else ''
    for line in linked.splitlines():
        for token in line.split():
            if token.startswith('/') and Path(token).is_file():
                libraries[token] = sha(token)
    result.update(providers=providers, libraries=libraries)
    return result


def compatibility(repo, phase, providers, ccache, *, sdk=None, tls=None):
    names = command(['git', '-C', repo, 'ls-files', 'wine/patches', 'wine/ps5',
                     'tools/build_host_wine.sh', 'tools/build_wine_ps5.sh',
                     'tools/stage_vk_batch.py', 'tools/generate_vk_codecs.py',
                     'tools/wine_compile_cache.py', '.github/workflows/windows-child-fixture.yml']).splitlines()
    # Include this helper while the new file is being reviewed before its first commit.
    names = sorted(set(names) | {'tools/wine_compile_cache.py'})
    recipe = {name: sha(repo / name) for name in names}
    pin = re.search(r'^WINE_COMMIT=([0-9a-f]{40})$', (repo / 'tools/build_wine_ps5.sh').read_text(), re.M)
    if not pin:
        raise ValueError('missing Wine pin')
    value = {'schema': SCHEMA, 'phase': phase, 'os': Path('/etc/os-release').read_text(),
             'machine': platform.machine(), 'wine_commit': pin.group(1), 'recipe': recipe,
             'settings': SETTINGS, 'flags': {name: os.environ.get(name, '') for name in FLAGS},
             'ccache': {'file': file_record(ccache), 'version': command([ccache, '--version'])},
             'compilers': providers, 'system_headers': tree_record('/usr/include'),
             'packages': command(['dpkg-query', '-W', '-f=${Package}=${Version}\n'])}
    # GCC/MinGW's internal headers and target include trees are independent of /usr/include.
    value['cross_headers'] = {name: tree_record(path) for name, path in
        [('gcc', Path('/usr/lib/gcc')), ('gcc-cross', Path('/usr/lib/gcc-cross')), ('mingw32', Path('/usr/i686-w64-mingw32/include')),
         ('mingw64', Path('/usr/x86_64-w64-mingw32/include'))] if path.exists()}
    if phase == 'ps5':
        if sdk is None or tls is None:
            raise ValueError('PS5 cache requires exact SDK and TLS inputs')
        value['sdk'] = tree_record(sdk)
        value['tls'] = tree_record(tls)
    return value


def write_state(out, cache_dir, identity, compilers, ccache, project):
    out = Path(out).resolve()
    cache_dir = Path(cache_dir).resolve()
    if out == cache_dir or out in cache_dir.parents or cache_dir in out.parents:
        raise ValueError('cache objects and per-run evidence must be disjoint')
    out.mkdir(parents=True, exist_ok=False)
    key = 'wine-ccache-v1-' + identity['phase'] + '-' + hashlib.sha256(canonical(identity)).hexdigest()
    (out / 'compatibility.json').write_bytes(canonical(identity))
    config = dict(SETTINGS, max_size='3G', cache_dir=str(cache_dir), namespace=key,
                  extra_files_to_hash=str(out / 'compatibility.json'))
    (out / 'ccache.conf').write_text(''.join(k + ' = ' + v + '\n' for k, v in config.items()))
    launchers = out / 'launchers'; launchers.mkdir()
    mapping = {}
    for role, (compiler, kind) in compilers.items():
        # Wine configure derives target/strip from the real triple-bearing basename.
        target = launchers / role / Path(compiler).name
        target.parent.mkdir()
        target.write_text('#!/bin/sh\nexec ' + shlex.join([str(ccache), 'compiler_type=' + kind,
            'compiler_check=content', 'hard_link=false', 'sloppiness=', str(compiler)]) + ' "$@"\n')
        target.chmod(0o755)
        mapping[role] = str(target)
    state = {'schema': SCHEMA, 'key': key, 'project': project, 'phase': identity['phase'],
             'cache_dir': str(cache_dir), 'ccache': str(ccache), 'launchers': mapping,
             'compatibility_sha256': sha(out / 'compatibility.json'),
             'compilers': {role: [str(path), kind] for role, (path, kind) in compilers.items()}}
    (out / 'state.json').write_bytes(canonical(state))
    return state


def cache_env(state, directory):
    env = {k: v for k, v in os.environ.items() if not k.startswith('CCACHE_')}
    env['CCACHE_CONFIGPATH'] = str(Path(directory).resolve() / 'ccache.conf')
    return env


def stats(ccache, env):
    return {key: int(value) for key, value in
        (line.split() for line in subprocess.check_output([ccache, '--print-stats'], env=env, text=True).splitlines())}


def run_stage(directory, stage, argv):
    if not re.fullmatch(r'[a-z0-9-]+', stage) or not argv:
        raise ValueError('invalid cache stage')
    directory = Path(directory).resolve()
    state = json.loads((directory / 'state.json').read_text())
    if sha(directory / 'compatibility.json') != state['compatibility_sha256']:
        raise ValueError('cache compatibility input changed')
    env = cache_env(state, directory)
    cc = state['launchers']
    env.update(i386_CC=cc['i386'], x86_64_CC=cc['x86_64'])
    if state['phase'] == 'host':
        env.update(CC=cc['cc'], CXX=cc['cxx'])
    else:
        env['PW_WINE_CACHED_CC'] = cc['cc']
    ccache = state['ccache']
    subprocess.run([ccache, '--zero-stats'], env=env, check=True)
    (directory / (stage + '-config.txt')).write_text(subprocess.check_output([ccache, '--show-config'], env=env, text=True))
    before = stats(ccache, env)
    started = time.monotonic()
    result = None
    try:
        result = subprocess.run(argv, env=env)
        return result.returncode
    finally:
        record = {'schema': 'pw-wine-cache-stage/1', 'key': state['key'], 'project': state['project'],
                  'phase': state['phase'], 'stage': stage, 'argv': argv,
                  'elapsed_seconds': time.monotonic() - started,
                  'exit': result.returncode if result else None,
                  'cache_restore_hit': os.environ.get('PW_CACHE_RESTORE_HIT', ''),
                  'cache_matched_key': os.environ.get('PW_CACHE_MATCHED_KEY', '')}
        receipt = directory / (stage + '.json')
        receipt.write_bytes(canonical(record))
        try:
            after = stats(ccache, env)
            delta = {key: value - before.get(key, 0) for key, value in after.items()}
            hits = delta.get('direct_cache_hit', 0) + delta.get('preprocessed_cache_hit', 0)
            misses = delta.get('cache_miss', 0)
            record.update(counters=delta, compiler_hits=hits, compiler_misses=misses,
                          cacheable_hit_rate=hits / (hits + misses) if hits + misses else None,
                          cache_bytes=sum(p.stat().st_size for p in Path(state['cache_dir']).rglob('*') if p.is_file()))
            summary = subprocess.check_output([ccache, '--show-stats'], env=env, text=True)
            (directory / (stage + '-stats.txt')).write_text(summary)
            print(summary, flush=True)
        except Exception as error:
            record['statistics_error'] = str(error)
            raise
        finally:
            receipt.write_bytes(canonical(record))
            print(json.dumps(record), flush=True)


def compiler_smoke(directory, out, objects):
    """Compile twice through the actual selected launcher; never run target code."""
    directory = Path(directory).resolve()
    state = json.loads((directory / 'state.json').read_text())
    identity = json.loads((directory / 'compatibility.json').read_text())
    if sha(directory / 'compatibility.json') != state['compatibility_sha256']:
        raise ValueError('cache compatibility input changed')
    if Path(objects).exists():
        raise ValueError('compiler smoke requires a fresh, uncached object directory')
    probe = write_state(out, objects, identity, state['compilers'], state['ccache'], state['project'])
    out = Path(out).resolve()
    source = out / 'original-cache-control.c'
    source.write_text('#include <stdint.h>\nuint32_t pw_original_cache_control(uint32_t n) { return n ^ 0x512aU; }\n')
    output = out / 'probe.o'
    argv = [probe['launchers']['cc'], '-std=c11', '-O2', '-c', str(source), '-o', str(output)]
    if run_stage(out, 'cold', argv):
        raise ValueError('cold compiler cache control failed')
    shutil.copyfile(output, out / 'cold.o')
    output.unlink()
    if run_stage(out, 'warm', argv):
        raise ValueError('warm compiler cache control failed')
    shutil.copyfile(output, out / 'warm.o')
    cold = json.loads((out / 'cold.json').read_text())
    warm = json.loads((out / 'warm.json').read_text())
    if cold['compiler_misses'] < 1 or warm['compiler_hits'] < 1 or sha(out/'cold.o') != sha(out/'warm.o'):
        raise ValueError('compiler cache did not demonstrate identical cold/warm object bytes')
    result = {'schema': 'pw-wine-cache-compiler-control/1', 'key': state['key'], 'project': state['project'],
              'compiler': state['compilers']['cc'], 'source_sha256': sha(source),
              'cold_sha256': sha(out/'cold.o'), 'warm_sha256': sha(out/'warm.o'),
              'cold_misses': cold['compiler_misses'], 'warm_hits': warm['compiler_hits'],
              'target_code_executed': False}
    (out/'RESULT.json').write_bytes(canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prepare = sub.add_parser('prepare')
    prepare.add_argument('--repo', type=Path, required=True)
    prepare.add_argument('--phase', choices=('host', 'ps5'), required=True)
    prepare.add_argument('--out', type=Path, required=True)
    prepare.add_argument('--cache-dir', type=Path, required=True)
    prepare.add_argument('--sdk', type=Path)
    prepare.add_argument('--tls', type=Path)
    run = sub.add_parser('run')
    run.add_argument('--state', type=Path, required=True)
    run.add_argument('--stage', required=True)
    run.add_argument('command', nargs=argparse.REMAINDER)
    smoke = sub.add_parser('smoke')
    smoke.add_argument('--state', type=Path, required=True)
    smoke.add_argument('--out', type=Path, required=True)
    smoke.add_argument('--objects', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'smoke':
        print(json.dumps(compiler_smoke(args.state, args.out, args.objects)))
        return
    if args.action == 'run':
        argv = args.command[1:] if args.command[:1] == ['--'] else args.command
        raise SystemExit(run_stage(args.state, args.stage, argv))
    repo = args.repo.resolve(strict=True)
    ccache = executable('ccache')
    compilers = {'i386': (executable('i686-w64-mingw32-gcc'), 'gcc'),
                 'x86_64': (executable('x86_64-w64-mingw32-gcc'), 'gcc')}
    if args.phase == 'host':
        compilers.update(cc=(executable('clang-18'), 'clang'), cxx=(executable('clang++-18'), 'clang'))
    else:
        if args.sdk is None:
            parser.error('--sdk is required for PS5')
        compilers['cc'] = (args.sdk.resolve(strict=True) / 'bin/prospero-clang', 'clang')
    providers = {role: compiler_record(path, kind) for role, (path, kind) in compilers.items()}
    if args.phase == 'ps5':
        # The SDK dispatcher is a script: bind its actual selected backend separately.
        bindir = Path(command([os.environ.get('LLVM_CONFIG', 'llvm-config-18'), '--bindir']))
        providers['sdk_backend'] = compiler_record(bindir / 'clang', 'clang')
    identity = compatibility(repo, args.phase, providers, ccache, sdk=args.sdk, tls=args.tls)
    project = {k: command(['git', '-C', repo, 'rev-parse', v]) for k, v in
               [('commit', 'HEAD'), ('tree', 'HEAD^{tree}')]}
    state = write_state(args.out, args.cache_dir, identity, compilers, ccache, project)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write('key=' + state['key'] + '\n')
    print(json.dumps(state))


if __name__ == '__main__':
    main()
