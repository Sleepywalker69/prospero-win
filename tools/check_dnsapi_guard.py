#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Compile actual DNSAPI TUs with real Wine headers and a host boundary fixture.

This is not a PE build, resolver implementation or network test. Produced host
test code uses only the supplied platform mocks. All output paths must be fresh.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wine-source', type=Path, required=True)
    parser.add_argument('--dnsapi-source', type=Path)
    parser.add_argument('--fixtures', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cc', default=os.environ.get('CC', 'cc'))
    parser.add_argument('--ubsan', action='store_true')
    args = parser.parse_args()
    wine = args.wine_source.resolve(strict=True)
    dns = (args.dnsapi_source or wine / 'dlls/dnsapi').resolve(strict=True)
    fixtures = args.fixtures.resolve(strict=True)
    cc = shutil.which(args.cc)
    if not cc:
        parser.error('host C compiler is unavailable')
    cc = str(Path(cc).resolve())
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = out / 'source'; source.mkdir()
    inputs = {}
    for name in ('main.c', 'query.c', 'dnsapi.h'):
        original = dns / name
        shutil.copyfile(original, source / name)
        inputs[str(original)] = sha(original)
    for name in ('test_dnsapi_guard.c', 'dnsapi_test_alloc.h'):
        original = fixtures / name
        shutil.copyfile(original, source / name)
        inputs[str(original)] = sha(original)
    result = {'scope': 'actual complete DNSAPI main/query C with real Wine headers; host platform/dispatch mocks',
              'pe_build': False, 'network_execution': False, 'ubsan': args.ubsan,
              'runner_sha256': sha(Path(__file__)), 'inputs': inputs,
              'compiler': {'path': cc, 'sha256': sha(Path(cc)),
                           'version': subprocess.check_output([cc, '--version'], text=True)},
              'commands': [], 'success': False}
    common = [cc, '-D_GNU_SOURCE', '-include', 'wchar.h', '-std=gnu11', '-fshort-wchar',
              '-D__WINESRC__', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
              '-Wno-format', '-ffunction-sections', '-fdata-sections',
              '-I' + str(wine / 'include'), '-I' + str(source)]
    if args.ubsan:
        common += ['-fsanitize=undefined', '-fno-sanitize-recover=all']

    def run(label, command):
        completed = subprocess.run(command, text=True, capture_output=True)
        raw = out / (label + '.log')
        raw.write_text(completed.stdout + completed.stderr)
        result['commands'].append({'label': label, 'argv': command, 'exit': completed.returncode,
                                   'log': raw.name, 'log_sha256': sha(raw)})
        print(label, completed.returncode)
        if completed.stdout:
            print(completed.stdout, end='')
        if completed.stderr:
            print(completed.stderr, end='', file=sys.stderr)
        return completed.returncode == 0

    try:
        for unit in ('main', 'query'):
            if not run('compile-' + unit, common + ['-include', str(source / 'dnsapi_test_alloc.h'),
                       '-MMD', '-MF', str(out / (unit + '.d')), '-c', str(source / (unit + '.c')),
                       '-o', str(out / (unit + '.o'))]):
                return 1
        binary = out / 'test-dnsapi-guard'
        if not run('link', common + [str(source / 'test_dnsapi_guard.c'), str(out / 'main.o'),
                   str(out / 'query.o'), '-Wl,--gc-sections', '-o', str(binary)]):
            return 1
        result['binary_sha256'] = sha(binary)
        result['success'] = run('run', [str(binary)])
        return 0 if result['success'] else 1
    finally:
        dependencies = {}
        for dep in out.glob('*.d'):
            text = dep.read_text().replace('\\\n', ' ')
            for item in shlex.split(text.split(':', 1)[1]):
                p = Path(item)
                if not p.is_file():
                    raise RuntimeError('compiler dependency is missing: ' + str(p))
                dependencies[str(p)] = sha(p)
        result['actual_compiler_dependencies'] = dependencies
        result['inputs_unchanged'] = all(sha(Path(p)) == digest for p, digest in inputs.items())
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    sys.exit(main())
