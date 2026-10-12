#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""One owned Wine object: donor hit, make no-op, changed C, uncached byte control."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import wine_compile_cache as cache

PIN = '490f6d5dcbb2a5047345b8af88d114bbcaad69a8'
TARGET = 'server/process.o'
MARKER = b'\nstatic const unsigned int pw_cache_component_marker __attribute__((used)) = 0x50574341U;\n'
PACKAGES = ('build-essential ccache clang-18 lld-18 llvm-18 llvm-18-dev bison flex gcc-mingw-w64 '
            'g++-mingw-w64 pkg-config m4 patch curl wget unzip zip xvfb xauth libx11-dev libxext-dev '
            'libfreetype-dev libfontconfig-dev libvulkan-dev libgnutls28-dev libasound2-dev libpulse-dev zlib1g-dev').split()

def require(ok, message):
    if not ok:
        raise ValueError(message)

class Cancelled(BaseException):
    pass

def interrupted(signum, frame):
    raise Cancelled('benchmark cancelled')

class Budget:
    def __init__(self, seconds):
        require(0 < seconds <= 900, 'invalid benchmark budget')
        self.deadline = time.monotonic() + seconds

    def run(self, argv, log, env=None):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'benchmark deadline exhausted')
        started = time.monotonic()
        with Path(log).open('xb') as output:
            child = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, env=env, start_new_session=True)
            try:
                status = child.wait(timeout=remaining)
                require(status == 0, 'bounded subprocess failed; see ' + Path(log).name)
            finally:
                # A second cancellation must not interrupt bounded kill/reap.
                previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
                try:
                    try:
                        os.killpg(child.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=5)
                finally:
                    for sig, handler in previous.items():
                        signal.signal(sig, handler)
        return time.monotonic() - started

def generated_target(build, source):
    text = (build / 'Makefile').read_text()
    matches = []
    for line in text.splitlines():
        if line.startswith(TARGET + ': '):
            fields = line.split(': ', 1)[1].split()
            for name in fields:
                if name.endswith('/server/process.c'):
                    require('$' not in name, 'unexpanded target source')
                    matches.append((build / name).resolve())
    require(matches == [source.resolve()], 'generated process target source differs')
    require(not (build / TARGET).exists(), 'component object already built before measurement')

def bound_environment(state, directory):
    env = cache.cache_env(state, directory)
    cc = state['launchers']
    env.update(CC=cc['cc'], CXX=cc['cxx'], i386_CC=cc['i386'], x86_64_CC=cc['x86_64'])
    return env

def invocation_records(path):
    if not path.exists():
        return []
    require(path.stat().st_size <= 4 << 20, 'ccache invocation log exceeds bound')
    groups = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r'\[([^\]]+) ([0-9]+) *\] (.*)', line)
        require(match is not None, 'unrecognized ccache log framing')
        pid, message = match.group(2), match.group(3)
        group = groups.setdefault(pid, {'results': []})
        for label, key in [('Command line: ', 'command'), ('Compiler: ', 'compiler'), ('Source file: ', 'source'), ('Object file: ', 'object'), ('Working directory: ', 'cwd')]:
            if message.startswith(label):
                require(key not in group, 'ambiguous repeated invocation metadata')
                group[key] = message[len(label):]
        if message.startswith('Result: '):
            group['results'].append(message[len('Result: '):])
    require(all('command' in g for g in groups.values()), 'ccache PID lacks command identity')
    return list(groups.values())

def format_logged_argv(argv):
    result = []
    for item in argv:
        escaped = item.replace('\\', '\\\\').replace('"', '\\"')
        result.append('"' + escaped + '"' if not escaped or ' ' in escaped else escaped)
    return ' '.join(result)

def logged_argv(value):
    # Inverse of ccache v4.9.1 util::format_argv_for_logging; NOT shell syntax.
    require(0 < len(value) <= 65536 and all(32 <= ord(c) < 127 for c in value),
            'compiler command bound/characters')
    result, token, quoted, active, index = [], '', False, False, 0
    while index < len(value):
        char = value[index]
        if char == '\\':
            require(index + 1 < len(value) and value[index + 1] in ('\\', '"'),
                    'invalid logged argument escape')
            token += value[index + 1]
            active = True
            index += 2
            continue
        if char == '"':
            quoted = not quoted
            active = True
        elif char == ' ' and not quoted:
            require(active, 'empty command separator')
            result.append(token)
            token, active = '', False
        else:
            token += char
            active = True
        index += 1
    require(not quoted and active, 'unterminated command argument')
    result.append(token)
    require(len(result) <= 4096 and format_logged_argv(result) == value, 'noncanonical logged arguments')
    return result

def target_result(records, state, build, kind):
    require(len(records) == 1, 'expected exactly one compiler invocation')
    record = records[0]
    require(Path(record.get('cwd', '')).is_absolute() and Path(record['cwd']).resolve() == build.resolve(),
            'compiler working directory differs')
    argv = logged_argv(record['command'])
    source = (build.parent / 'source/server/process.c').resolve()
    output = (build / TARGET).resolve()
    require(record.get('compiler') and Path(record['compiler']).resolve() == Path(state['compilers']['cc'][0]).resolve(),
            'resolved compiler identity differs')
    require(state['compilers']['cc'][0] in argv and argv.count('-o') == 1 and '-c' in argv,
            'compiler invocation identity differs')
    index = argv.index('-o')
    require(index + 1 < len(argv) and (build / argv[index + 1]).resolve() == output,
            'compiler output differs')
    inputs = [a for a in argv if a.endswith('/server/process.c')]
    require(len(inputs) == 1 and (build / inputs[0]).resolve() == source, 'compiler source differs')
    if kind != 'disabled':
        require((build / record.get('source', '')).resolve() == source and
                (build / record.get('object', '')).resolve() == output, 'parsed compiler input/output differs')
    disposition = {'hit': 'preprocessed_cache_hit', 'miss': 'cache_miss', 'disabled': 'disabled'}[kind]
    require(record['results'].count(disposition) == 1, 'target cache result differs')
    allowed = {disposition}
    if kind == 'miss':
        allowed.update(('direct_cache_miss', 'preprocessed_cache_miss'))
    require(all(r in allowed or r.startswith(('local_storage_', 'remote_storage_', 'in_memory_cache_'))
                for r in record['results']), 'target invocation has error/uncacheable result')
    return record

def stats_file(path):
    require(path.stat().st_size <= 1 << 20, 'cache stats exceed bound')
    result = {}
    for line in path.read_text().splitlines():
        key, value = line.split()
        require(key not in result, 'duplicate counter')
        result[key] = int(value)
    return result

def stage(budget, repo, state_dir, build, label, output):
    state = json.loads((state_dir / 'state.json').read_text())
    cache.checked_identity(state_dir, state)
    env = bound_environment(state, state_dir)
    budget.run([state['ccache'], '--zero-stats'], output / (label + '-zero.log'), env)
    before_path, after_path = output / (label + '-before.txt'), output / (label + '-after.txt')
    budget.run([state['ccache'], '--print-stats'], before_path, env)
    log = output / (label + '-ccache.log')
    require(not log.exists(), 'invocation log must be new')
    measured_env = dict(env, CCACHE_LOGFILE=str(log))
    seconds = budget.run(['make', '-C', str(build), '-j2', TARGET], output / (label + '.log'), measured_env)
    budget.run([state['ccache'], '--print-stats'], after_path, env)
    before, after = stats_file(before_path), stats_file(after_path)
    counters = {key: value - before.get(key, 0) for key, value in after.items()}
    hits = counters.get('direct_cache_hit', 0) + counters.get('preprocessed_cache_hit', 0)
    misses = counters.get('cache_miss', 0)
    records = invocation_records(log)
    if label == 'component-donor-hit':
        target_result(records, state, build, 'hit')
    elif label == 'component-changed-c':
        target_result(records, state, build, 'miss')
    else:
        require(not records, 'make no-op invoked a compiler')
    result = {'seconds': seconds, 'hits': hits, 'misses': misses,
              'object_sha256': cache.sha(build / TARGET), 'counters': counters,
              'invocations': records, 'command_log': label + '.log'}
    (output / (label + '.json')).write_bytes(cache.canonical(result))
    return result

def measure(budget, repo, state_dir, work, output):
    source, build = work / 'source/server/process.c', work / 'build'
    generated_target(build, source)
    original = source.read_bytes()
    first = stage(budget, repo, state_dir, build, 'component-donor-hit', output)
    require(first['hits'] == 1 and first['misses'] == 0, 'required donor object hit absent; stop')
    budget.run(['make', '-C', str(build), '-q', TARGET], output / 'component-noop-query.log')
    noop = stage(budget, repo, state_dir, build, 'component-noop', output)
    require(noop['hits'] == noop['misses'] == 0 and all(value == 0 for value in noop['counters'].values()) and
            noop['object_sha256'] == first['object_sha256'], 'unchanged target was not a make no-op')
    noop['make_query_up_to_date'] = True
    try:
        require(MARKER not in original, 'benchmark marker already present')
        source.write_bytes(original + MARKER)
        stamp = time.time_ns()
        require(stamp > (build / TARGET).stat().st_mtime_ns, 'cannot order changed source after object')
        os.utime(source, ns=(stamp, stamp))
        require(source.stat().st_mtime_ns > (build / TARGET).stat().st_mtime_ns,
                'filesystem timestamp precision cannot establish dependency ordering')
        changed = stage(budget, repo, state_dir, build, 'component-changed-c', output)
        require(changed['misses'] == 1 and changed['hits'] == 0 and changed['object_sha256'] != first['object_sha256'],
                'controlled C change did not compile different bytes')
        state = json.loads((state_dir / 'state.json').read_text())
        cache.checked_identity(state_dir, state)
        env = bound_environment(state, state_dir)
        control_log = output / 'component-uncached-control-ccache.log'
        require(not control_log.exists(), 'control log must be new')
        env.update(CCACHE_DISABLE='1', CCACHE_LOGFILE=str(control_log))
        (build / TARGET).unlink()
        elapsed = budget.run(['make', '-C', str(build), '-j2', TARGET],
                             output / 'component-uncached-control.log', env=env)
        control_record = target_result(invocation_records(control_log), state, build, 'disabled')
        require(control_record['command'] == changed['invocations'][0]['command'],
                'cached/disabled compiler arguments differ')
        uncached = {'invocation': control_record, 'seconds': elapsed, 'object_sha256': cache.sha(build / TARGET),
                    'same_absolute_path': True, 'cache_disabled': True}
        require(uncached['object_sha256'] == changed['object_sha256'],
                'uncached same-path object bytes differ')
        return {'donor_hit': first, 'unchanged_make_noop': noop, 'changed_c': changed,
                'uncached_same_path_control': uncached,
                'original_source_sha256': __import__('hashlib').sha256(original).hexdigest(),
                'changed_source_sha256': cache.sha(source), 'target': TARGET,
                'target_code_executed': False, 'full_runtime_built': False}
    finally:
        source.write_bytes(original)

def run(repo, temp, seconds):
    budget = Budget(seconds)
    output = temp / 'wine-cache-component'
    require(not output.exists(), 'benchmark output already exists')
    output.mkdir()
    env = dict(os.environ)
    require(not any(env.get(k) for k in ('MAKEFLAGS', 'MFLAGS', 'GNUMAKEFLAGS', 'MAKEOVERRIDES',
                                        'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS')),
            'unexpected inherited compiler/make flags')
    env['PATH'] = '/usr/lib/llvm-18/bin:' + env['PATH']
    os.environ['PATH'] = env['PATH']
    # One shared deadline covers package setup, source fetch, identity, import,
    # configuration/tool build and every object/control compilation.
    budget.run(['sudo', 'apt-get', 'update'], output / 'apt-update.log', env)
    budget.run(['sudo', 'apt-get', 'install', '-y', '--no-install-recommends', *PACKAGES],
               output / 'apt-install.log', env)
    source, work = temp / 'wine-source', temp / 'wine-host'
    require(not source.exists() and not work.exists(), 'fresh Wine paths required')
    budget.run(['git', 'init', '--quiet', str(source)], output / 'git-init.log', env)
    budget.run(['git', '-C', str(source), 'remote', 'add', 'origin', 'https://github.com/wine-mirror/wine.git'],
               output / 'git-remote.log', env)
    budget.run(['git', '-C', str(source), 'fetch', '--depth=1', 'origin', PIN], output / 'git-fetch.log', env)
    budget.run(['git', '-C', str(source), 'checkout', '--detach', PIN], output / 'git-checkout.log', env)
    state = temp / 'fixture-evidence/ccache-host'
    require(not state.exists(), 'fresh compiler evidence required')
    budget.run([sys.executable, str(repo / 'tools/wine_compile_cache.py'), 'prepare',
                '--repo', str(repo), '--phase', 'host', '--out', str(state),
                '--cache-dir', str(temp / 'ccache-host')], output / 'fresh-partition.log', env)
    admitted = output / 'import'
    budget.run([sys.executable, str(repo / 'tools/import_host_compiler_cache.py'), 'download',
                '--out', str(admitted)], output / 'download.log', env)
    budget.run([sys.executable, str(repo / 'tools/import_host_compiler_cache.py'), 'import',
                '--out', str(admitted), '--fresh', str(state)], output / 'import.log', env)
    imported = json.loads((admitted / 'IMPORT-RECEIPT.json').read_text())
    print('PW_COMPONENT_IMPORT ' + json.dumps(imported, sort_keys=True), flush=True)
    budget.run([sys.executable, str(repo / 'tools/wine_compile_cache.py'), 'run', '--state', str(state),
                '--stage', 'component-host-tools', '--', 'sh', 'tools/build_host_wine.sh',
                '--source', str(source), '--work', str(work), '--jobs', '2', '--tools-only'],
               output / 'tools-only.log', env)
    result = measure(budget, repo, state, work, output)
    result.update(schema='pw-wine-cache-component/1', imported=imported,
                  project={'commit': os.environ['GITHUB_SHA']},
                  total_seconds=seconds - max(0, budget.deadline - time.monotonic()),
                  scope='single host C object; no whole-Wine speedup or runtime acceptance')
    (output / 'RESULT.json').write_bytes(cache.canonical(result))
    print('PW_COMPONENT_RESULT ' + json.dumps(result, sort_keys=True), flush=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--seconds', type=int, default=900)
    args = parser.parse_args()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    run(Path.cwd().resolve(), Path(os.environ['RUNNER_TEMP']).resolve(), args.seconds)

if __name__ == '__main__':
    main()
