#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Run eleven existing host/source controls against one verified producer kit.

The original native CPU artifact suite is explicitly unavailable because its
host .so and cpu.o were not retained. This never builds or exports a seed.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import time

sys.dont_write_bytecode = True
SUITES = [
    ('test_wine_protect_writecopy.py', 'wine protect write-copy passed:'),
    ('test_wine_decommit_zero.py', 'wine decommit zero passed:'),
    ('test_wine_seh_fp_state.py', 'wine seh fp state passed:'),
    ('test_wine_narrow_syscall_args.py', 'wine narrow syscall args passed:'),
    ('test_wine_sched_probe.py', 'wine sched probe passed:'),
    ('test_wine_process_counters.py', 'wine process counters passed:'),
    ('test_wine_processor_times.py', 'wine processor times passed:'),
    ('test_wine_directory_changes.py', 'wine directory changes passed:'),
    ('test_wine_dib_section.py', 'wine DIB section passed:'),
    ('test_wowprospero_contract.py', 'pinned wow64 cross-check passed;'),
    ('test_wine_lookup_misses.py', 'wine lookup misses passed: exact and other spellings,'),
]


def unpack_source(path, destination, commit):
    from export_notepad_seed import require, safe_relative
    require(not destination.exists(), 'source output already exists')
    destination.mkdir()
    with tarfile.open(path, 'r:gz') as archive:
        require(archive.pax_headers.get('comment') == commit, 'source archive commit mismatch')
        entries = archive.getmembers()
        require(len(entries) <= 100000 and sum(x.size for x in entries) <= 2 << 30,
                'source archive too large')
        seen = set()
        for entry in entries:
            if entry.name.rstrip('/') in ('.', ''):
                require(entry.isdir(), 'invalid root member'); continue
            name = str(safe_relative(entry.name.rstrip('/')))
            require(name not in seen, 'duplicate source path'); seen.add(name)
            require(entry.isfile() or entry.isdir() or entry.issym(), 'special source member')
            require(not entry.mode & 0o7000 and entry.size <= 128 << 20, 'invalid source mode/size')
        archive.extractall(destination, filter='data')
    for path in destination.rglob('*'):
        if path.is_symlink():
            require(path.resolve(strict=True).is_relative_to(destination.resolve()), 'source symlink escape')


def prepare(args):
    from export_notepad_seed import INPUTS, PROJECT, WINE, metadata, read_json, unpack, verify_tree
    metadata(read_json(args.run_json), read_json(args.artifacts_json))
    if args.work.exists():
        raise ValueError('work directory must be absent')
    args.work.mkdir()
    _, digest, member, scope = INPUTS['kit']
    unpack(args.kit_zip, args.work / 'kit', digest, member)
    verify_tree(args.work / 'kit', scope)
    unpack_source(args.work / 'kit/sources/prospero-win.tar.gz', args.work / 'project', PROJECT)
    unpack_source(args.work / 'kit/sources/wine.tar.gz', args.work / 'wine-source', WINE)
    (args.work / 'logs').mkdir(); (args.work / 'tmp').mkdir(); (args.work / 'cache').mkdir()
    wine = (args.work / 'kit/pc/host-wine/usr/bin/wine').resolve()
    wrapper = args.work / 'wine-no-addons'
    wrapper.write_text('#!/bin/sh\n' +
                       'export WINEDLLOVERRIDES="${WINEDLLOVERRIDES:+$WINEDLLOVERRIDES;}mshtml=;mscoree="\n' +
                       'exec ' + shlex.quote(str(wine)) + ' "$@"\n')
    wrapper.chmod(0o755)
    (args.work / 'INPUTS-VERIFIED.json').write_text(json.dumps({
        'artifact_id': INPUTS['kit'][0], 'artifact_sha256': digest,
        'project': PROJECT, 'wine': WINE, 'wine_executable': str(wine),
        'scope': '11 hosted controls; fixed-reserve deferred; original native CPU artifact suite unavailable',
        'optional_components_disabled': ['mshtml', 'mscoree']}, indent=2) + '\n')


def run_one(command, cwd, env, log, expected, timeout=180):
    timed_out = False
    cleanup = {'leader_reaped': False, 'owned_group_absent': None,
               'escaped_wine_daemons_verified': False, 'signal_errors': []}
    with log.open('w') as stream:
        stream.write(json.dumps(command) + '\n'); stream.flush()
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        def signal_group(value):
            try:
                os.killpg(child.pid, value)
            except ProcessLookupError:
                pass
            except OSError as error:
                cleanup['signal_errors'].append(str(error))
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            signal_group(signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            # A terminated group leader does not mean its descendants exited.
            signal_group(signal.SIGKILL)
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            deadline = time.monotonic() + 1
            cleanup['owned_group_absent'] = None
            while time.monotonic() < deadline:
                try:
                    os.killpg(child.pid, 0)
                    cleanup['owned_group_absent'] = False
                except ProcessLookupError:
                    cleanup['owned_group_absent'] = True
                    break
                except OSError as error:
                    cleanup['owned_group_absent'] = None
                    cleanup['signal_errors'].append(str(error)); break
                time.sleep(0.05)
            code = 124
        cleanup['leader_reaped'] = child.poll() is not None
        stream.write(f'\nEXIT={code}\n' + json.dumps({'cleanup': cleanup}) + '\n')
    text = log.read_text(errors='replace')
    skipped = bool(re.search(r'(?m)^SKIP\b|skipped: needs|skipped the', text))
    success = code == 0 and not skipped and expected in text
    return {'command': command, 'exit': code, 'timed_out': timed_out, 'cleanup': cleanup,
            'skip_detected': skipped, 'expected_receipt': expected,
            'status': 'passed' if success else 'failed', 'log': log.name}


def run(args):
    from export_notepad_seed import INPUTS, require, verify_tree
    require(os.environ.get('GITHUB_ACTIONS') == 'true', 'runtime checks are restricted to the hosted job')
    require((args.work / 'INPUTS-VERIFIED.json').is_file(), 'input preparation absent')
    verify_tree(args.work / 'kit', INPUTS['kit'][3])
    for name in ('cc', 'i686-w64-mingw32-gcc', 'x86_64-w64-mingw32-gcc', 'xvfb-run'):
        require(shutil.which(name), 'required host tool missing: ' + name)
    env = dict(os.environ, PROSPERO_HOST_WINE=str(args.work / 'wine-no-addons'),
               PROSPERO_WINE_SOURCE=str(args.work / 'wine-source'),
               PYTHONDONTWRITEBYTECODE='1', TMPDIR=str(args.work / 'tmp'),
               XDG_CACHE_HOME=str(args.work / 'cache'))
    results = []; stop_reason = None
    for index, (suite, expected) in enumerate(SUITES):
        command = [sys.executable, 'tests/' + suite]
        if index < 9:
            command = ['xvfb-run', '-a', *command]
        result = run_one(command, args.work / 'project', env,
                         args.work / 'logs' / (suite + '.log'), expected)
        result['suite'] = suite; results.append(result)
        print(suite + ': ' + result['status'], flush=True)
        if result['timed_out']:
            stop_reason = {'suite': suite, 'reason': 'per-suite timeout', 'cleanup': result['cleanup'],
                           'action': 'no later suites attempted; escaped Wine daemons remain unverified'}
            for pending, _ in SUITES[index + 1:]:
                results.append({'suite': pending, 'status': 'not_run_after_timeout',
                                'reason': 'stop after timeout; detached Wine daemons may escape the owned group'})
            break
    summary = {'scope': 'packaged host Wine and source controls; no vendor, PS5 or native transition claim',
               'results': results, 'stop_reason': stop_reason, 'deferred': [{
                   'suite': 'test_wine_fixed_reserve.py',
                   'reason': 'chosen-address behavior is held pending precise comparison with the earlier blocked MAP_FIXED experiment; never reroute that operation'}],
               'unavailable': [{
                   'suite': 'test_wow64native_scaffold.py',
                   'reason': 'original x86_64-unix/wow64native.so and x86_64-windows/cpu.o were not retained; shipped DLL/PRX metadata is separately checked'}],
               'prefix_or_seed_exported': False, 'runtime_rebuilt': False,
               'wine_daemon_cleanup_verified': False}
    (args.work / 'logs/RESULTS.json').write_text(json.dumps(summary, indent=2) + '\n')
    verify_tree(args.work / 'kit', INPUTS['kit'][3])
    return int(any(item['status'] != 'passed' for item in results))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'run'))
    parser.add_argument('--work', required=True, type=Path)
    for name in ('kit-zip', 'run-json', 'artifacts-json'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args(); args.work = args.work.resolve()
    if args.mode == 'prepare':
        if not all((args.kit_zip, args.run_json, args.artifacts_json)):
            parser.error('prepare requires kit ZIP and producer metadata')
        prepare(args); return 0
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
