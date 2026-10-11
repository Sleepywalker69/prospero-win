#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Build/admit the source-bound one-shot helper without downloading executables.

Only compilers and static analyzers run. A digest binds the actual post-link
bytes to this source cohort; it is not a signature or hardware validation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
from native_probe_elf import Elf, require
from tls_manifest import llvm_identity, tree_files

UPSTREAM = 'b48b7d7236eca25c7b9dfd6c040c763ae05dde80'
UPSTREAM_URL = 'https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon'
REPOSITORY = 'Sleepywalker69/prospero-win'
DIRECTORY = 'native/owned_helper'
UNITS = ('owned_root_daemon.c', 'donor_transaction.c', 'vnode_ref_probe.c', 'owned_helper_control.c')
HEADERS = ('donor_transaction.h', 'vnode_ref_probe.h', 'lapy_elevation_protocol.h', 'owned_helper_control.h')
FEATURES = ['root_layout_probe_retry', 'safe_transaction_cancel_v2']
OUTPUTS = ('lapy.elf', 'lapy-manifest.json', 'lapy-source.json', 'lapy-build.json')
ANALYZERS = ('llvm-readelf', 'llvm-objdump')
LLVM_TOOLS = {'llvm-config', 'clang', 'clang++', 'ld.lld', 'llvm-ar', 'llvm-nm', 'llvm-ranlib', *ANALYZERS}
MANIFEST_KEYS = {'schema', 'mode', 'target_title', 'max_requests', 'service', 'require_client_result',
                 'console_validated', 'features', 'protocol_version', 'protocol_bytes', 'build_id',
                 'elf_sha256', 'source_sha256', 'build_sha256', 'protocol_sha256'}
PROVIDERS = {'libkernel_web.sprx': 'libkernel_web.so',
             'libSceLibcInternal.sprx': 'libSceLibcInternal.so', 'libSceNet.sprx': 'libSceNet.so'}
FLAGS = ['--no-default-config', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-DTARGET_TITLE="PPSA99995"',
         '-DLAPY_SERVICE=0', '-DLAPY_ELF_HELPER=1', '-DLAPY_REQUIRE_CLIENT_RESULT=0', '-DLAPY_MAX_REQUESTS=0']


def raw(path: Path, limit: int = 32 << 20) -> bytes:
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= limit,
            'missing, linked or oversized helper input: ' + str(path))
    return path.read_bytes()


def digest(path: Path) -> str:
    require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0,
            'missing, linked or empty helper hash input: ' + str(path))
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def record(path: Path) -> dict:
    value = raw(path)
    return {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def read_json(path: Path, *, output: bool = False) -> dict:
    data = raw(path)
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate helper metadata key: ' + key)
            value[key] = item
        return value
    def invalid_constant(value):
        raise ValueError('non-finite helper metadata: ' + value)
    value = json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant,
                       parse_float=invalid_constant)
    def record_types(item):
        if isinstance(item, dict):
            if 'bytes' in item:
                require(type(item['bytes']) is int and item['bytes'] > 0, 'metadata byte count must be a positive integer')
            for child in item.values():
                record_types(child)
        elif isinstance(item, list):
            for child in item:
                record_types(child)
    record_types(value)
    require(isinstance(value, dict), 'helper metadata must be an object')
    require(not output or data == canonical(value), 'helper output metadata is not canonical')
    return value


def valid_hashes(value: dict) -> bool:
    return isinstance(value, dict) and bool(value) and all(
        isinstance(name, str) and isinstance(sha, str) and re.fullmatch('[0-9a-f]{64}', sha)
        for name, sha in value.items())


def expected_commands() -> list[list[str]]:
    includes = ['-I$REPO/' + DIRECTORY, '-I$REPO/native/ps5log', '-I$OUT']
    commands = [['$SDK/bin/prospero-clang', *FLAGS, *includes, '-c',
                 '$REPO/' + DIRECTORY + '/' + unit, '-o', '$OUT/obj/' + unit + '.o'] for unit in UNITS]
    commands += [['$SDK/bin/prospero-clang', *FLAGS, '-Wl,--no-undefined', '-Wl,-Map,$OUT/lapy.map',
                  *['$OUT/obj/' + unit + '.o' for unit in UNITS], '-o', '$OUT/lapy.elf'],
                 ['$LLVM/llvm-readelf', '-h', '-l', '-d', '-Ws', '$OUT/lapy.elf'],
                 ['$LLVM/llvm-objdump', '-d', '$OUT/lapy.elf']]
    return commands


def normalize_command(argv: list[str], paths: dict) -> list[str]:
    require(set(paths) == {'REPO', 'SDK', 'OUT', 'LLVM'} and
            all(isinstance(p, str) and Path(p).is_absolute() for p in paths.values()),
            'helper command paths are incomplete')
    result = list(argv)
    for name, path in sorted(paths.items(), key=lambda pair: len(pair[1]), reverse=True):
        replaced = []
        for arg in result:
            for prefix in ('', '-I', '-Wl,-Map,'):
                start = prefix + path
                if arg == start or arg.startswith(start + '/'):
                    arg = prefix + '$' + name + arg[len(start):]
                    break
            replaced.append(arg)
        result = replaced
    return result


def compiler_environment(llvm: dict) -> dict:
    # Compiler-sensitive inherited variables, credentials and per-user configs
    # are deliberately absent. --no-default-config is mandatory in FLAGS.
    return {'PATH': str(Path(llvm['bindir'])) + ':/usr/bin:/bin',
            'LLVM_CONFIG': llvm['config'], 'LANG': 'C', 'LC_ALL': 'C'}


def producer_llvm_identity(sdk: Path) -> dict:
    llvm = llvm_identity(sdk)
    for name in ANALYZERS:
        path = Path(llvm['bindir']) / name
        require(path.is_file() and os.access(path, os.X_OK), 'missing helper analyzer: ' + name)
        result = subprocess.run([str(path), '--version'], check=True, capture_output=True,
                                text=True, timeout=30)
        require(re.search(r'\bLLVM (?:version )?18(?:\.|\b)', result.stdout), 'helper analyzer is not LLVM 18')
        llvm['tools'][name] = {'path': str(path), 'real_path': str(path.resolve()),
                               'sha256': digest(path.resolve()), 'version': result.stdout.strip()}
    return llvm


def project_identity(repo: Path) -> dict:
    def git(*args):
        return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()
    require(not git('status', '--porcelain', '--untracked-files=normal'),
            'helper requires clean committed project source')
    result = {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}')}
    require(all(re.fullmatch('[0-9a-f]{40}', value) for value in result.values()), 'invalid project identity')
    return result


def source_record(repo: Path, project: dict) -> dict:
    origin = read_json(repo / DIRECTORY / 'UPSTREAM.json')
    require(origin.get('schema') == 'pw-owned-helper-upstream/1' and origin.get('commit') == UPSTREAM and
            origin.get('repository') == UPSTREAM_URL and origin.get('license') == 'MIT' and
            origin.get('license_sha256') == digest(repo / DIRECTORY / 'LICENSE'), 'helper source origin differs')
    names = [DIRECTORY + '/' + n for n in (*UNITS, *HEADERS, 'UPSTREAM.json', 'LICENSE', 'REVIEWED-COHORT.json')]
    names += ['native/ps5log/ps5log.h', 'native/lapy_elevation_protocol.h',
              'tools/build_owned_helper.py', 'tools/native_probe_elf.py', 'tools/tls_manifest.py']
    files = {name: record(repo / name) for name in names}
    cohort = read_json(repo / DIRECTORY / 'REVIEWED-COHORT.json')
    require(cohort.get('schema') == 'pw-owned-helper-reviewed-cohort/1' and
            cohort.get('upstream') == {'repository': UPSTREAM_URL, 'commit': UPSTREAM, 'candidate_is_modified': True},
            'helper reviewed source cohort differs')
    reviewed = cohort.get('files', [])
    require(isinstance(reviewed, list) and len(reviewed) == len(UNITS) + len(HEADERS) + 1 and
            {item.get('path') for item in reviewed} == {*UNITS, *HEADERS, 'LICENSE'} and
            all(set(item) == {'path', 'bytes', 'sha256'} and
                {'bytes': item['bytes'], 'sha256': item['sha256']} == files[DIRECTORY + '/' + item['path']]
                for item in reviewed), 'helper bytes differ from reviewed source cohort')
    require(cohort.get('license_notes') == [
        'Preserve the root MIT LICENSE copyright and disclaimer verbatim.',
        'lapy_elevation_protocol.h carries SPDX LGPL-2.1-or-later; preserve it. Do not describe the entire mixed cohort as MIT-only.'],
        'helper per-file license notices missing')
    require(files['tools/build_owned_helper.py']['sha256'] == digest(Path(__file__)),
            'executing helper recipe differs from the admitted repository')
    require(raw(repo / DIRECTORY / 'lapy_elevation_protocol.h') == raw(repo / 'native/lapy_elevation_protocol.h'),
            'helper/client protocol header differs')
    return {'schema': 'pw-owned-helper-source/1', 'repository': REPOSITORY, 'project': project,
            'upstream': {'repository': UPSTREAM_URL, 'commit': UPSTREAM}, 'files': files,
            'protocol_sha256': files['native/lapy_elevation_protocol.h']['sha256'],
            'license_notes': cohort['license_notes']}


def stable_toolchain(llvm: dict) -> dict:
    return {'version': llvm['version'], 'tools': {name: {'sha256': item['sha256'], 'version': item['version']}
            for name, item in llvm['tools'].items()}, 'resource_headers': llvm['resource_headers']}


def sdk_record(sdk: Path) -> dict:
    require((sdk / 'bin/prospero-clang').is_file() and (sdk / 'target/lib/crt1.o').is_file(), 'incomplete helper SDK')
    return {directory + '/' + name: sha for directory in ('bin', 'target', 'lib', 'libexec')
            if (sdk / directory).is_dir() for name, sha in tree_files(sdk / directory).items()}


def inspect_elf(elf: Path, sdk: Path) -> dict:
    image = Elf(raw(elf, 4 << 20))
    require(image.kind == 3 and set(image.needed) == set(PROVIDERS), 'helper target/provider graph differs')
    definitions = {}
    for soname, filename in PROVIDERS.items():
        path = sdk / 'target/lib' / filename
        provider = Elf(path.read_bytes(), module=True)
        require(provider.string(provider.tag(14)) == soname, 'helper provider SONAME differs')
        definitions[soname] = {s['name']: s['type'] for s in provider.symbols
                                if s['name'] and s['section'] and s['binding'] in (1, 2)}
    imports = {}
    for symbol in image.symbols[1:]:
        if symbol['section']:
            continue
        name = symbol['name']
        require(name and symbol['type'] in (0, 1, 2) and symbol['binding'] in (1, 2),
                'unsupported helper import: ' + name)
        found = [provider for provider in image.needed if name in definitions[provider]]
        require(found, 'unresolved helper import: ' + name)
        # ELF dependency order determines the ordinary dynamic lookup provider.
        expected = definitions[found[0]][name]
        require(symbol['type'] in (0, expected), 'helper import type differs: ' + name)
        imports[name] = {'provider': found[0], 'type': expected}
    require(all(r['type'] in (1, 6, 7, 8) for r in image.relocations), 'unsupported helper relocation')
    for relocation in image.relocations:
        image.offset(relocation['address'], 8, 2)
    return {'entry': hex(image.entry), 'needed': image.needed, 'imports': imports,
            'relocation_types': sorted({r['type'] for r in image.relocations}),
            'providers': {name: {'file': filename, 'sha256': digest((sdk / 'target/lib' / filename).resolve(strict=True))}
                          for name, filename in PROVIDERS.items()}}


def validate_owned_helper(directory: Path, repo: Path, expected_project: dict | None = None,
                          sdk: Path | None = None) -> dict:
    directory, repo = Path(directory), Path(repo)
    project = project_identity(repo)
    require(expected_project is None or project == expected_project, 'helper/project cohort differs')
    source = read_json(directory / 'lapy-source.json', output=True)
    require(source == source_record(repo, project), 'helper source identity differs')
    manifest, build = (read_json(directory / name, output=True) for name in ('lapy-manifest.json', 'lapy-build.json'))
    require(set(manifest) == MANIFEST_KEYS and
            all(type(manifest.get(key)) is int for key in ('max_requests', 'protocol_version', 'protocol_bytes')) and
            manifest.get('schema') == 'lapy-owned-build/1' and manifest.get('mode') == 'elf-helper' and
            manifest.get('target_title') == 'PPSA99995' and manifest.get('max_requests') == 1 and
            manifest.get('service') is False and manifest.get('require_client_result') is False and
            manifest.get('console_validated') is False and manifest.get('features') == FEATURES and
            manifest.get('protocol_version') == 2 and manifest.get('protocol_bytes') == 32,
            'helper lacks required one-shot cancellation contract')
    require(manifest.get('elf_sha256') == digest(directory / 'lapy.elf') and
            manifest.get('source_sha256') == digest(directory / 'lapy-source.json') and
            manifest.get('build_sha256') == digest(directory / 'lapy-build.json') and
            manifest.get('protocol_sha256') == source['protocol_sha256'], 'helper output digest differs')
    require(set(build) == {'schema', 'project', 'build_id', 'inputs', 'host_llvm', 'compiled_units',
                          'objects', 'commands', 'command_paths', 'inspection', 'elf', 'source',
                          'identity_header', 'link_map', 'console_validated', 'sdk_path', 'environment'} and
            build.get('console_validated') is False, 'helper build schema differs')
    inputs = build.get('inputs', {})
    require(isinstance(inputs, dict) and set(inputs) == {'source', 'flags', 'llvm', 'sdk'},
            'helper build input schema differs')
    require(build.get('schema') == 'pw-owned-helper-build/1' and build.get('project') == project and
            build.get('elf') == record(directory / 'lapy.elf') and build.get('source') == record(directory / 'lapy-source.json') and
            inputs.get('source') == source and inputs.get('flags') == FLAGS and
            re.match(r'^18(?:\.|$)', inputs.get('llvm', {}).get('version', '')) and
            build.get('build_id') == hashlib.sha256(canonical(inputs)).hexdigest() == manifest.get('build_id'),
            'helper build/source/toolchain identity differs')
    require(set(inputs.get('llvm', {}).get('tools', {})) ==
            LLVM_TOOLS and
            all(re.fullmatch('[0-9a-f]{64}', item.get('sha256', ''))
                for item in inputs['llvm']['tools'].values()) and
            valid_hashes(inputs['llvm'].get('resource_headers')) and valid_hashes(inputs.get('sdk')) and
            all(name in inputs.get('sdk', {}) for name in
                ('bin/prospero-clang', 'target/lib/crt1.o', 'target/lib/libc.a')),
            'helper compiler/SDK evidence is incomplete')
    require(build.get('compiled_units') == list(UNITS) and set(build.get('objects', {})) == set(UNITS) and
            all(build['objects'][unit] == record(directory / 'obj' / (unit + '.o')) for unit in UNITS),
            'helper objects are missing or mutated')
    require(build['identity_header'] == record(directory / 'owned_identity.h') and
            raw(directory / 'owned_identity.h') == ('#define LAPY_OWNED_ID \"' + build['build_id'] + '\"\n').encode() and
            build['link_map'] == record(directory / 'lapy.map'), 'helper identity or link map differs')
    host = build['host_llvm']
    require(build['command_paths']['LLVM'] == host['bindir'] and
            build['command_paths']['SDK'] == build['sdk_path'] and
            host['config'] == host['tools']['llvm-config']['path'] and
            all(host['tools'][name]['path'] == str(Path(host['bindir']) / name) for name in LLVM_TOOLS) and
            build['environment'] == compiler_environment(host), 'helper command/tool/environment roots differ')
    require(isinstance(build['commands'], list) and len(build['commands']) == len(expected_commands()) and
            all(set(command) == {'argv', 'exit', 'output'} and type(command['exit']) is int and command['exit'] == 0 and
                isinstance(command['output'], str) and
                normalize_command(command['argv'], build['command_paths']) == expected
                for command, expected in zip(build['commands'], expected_commands())),
            'helper compile/link/analyzer command boundary differs')
    require(all(command['argv'][0] == host['tools'][name]['path']
                for command, name in zip(build['commands'][-len(ANALYZERS):], ANALYZERS)),
            'helper analyzer command differs from its recorded exact tool path')
    require(stable_toolchain(build['host_llvm']) == inputs['llvm'], 'helper host tool identity differs')
    image = Elf(raw(directory / 'lapy.elf', 4 << 20))
    require(image.kind == 3 and set(image.needed) == set(PROVIDERS), 'helper target identity differs')
    require(build.get('inspection', {}).get('entry') == hex(image.entry) and
            build['inspection'].get('needed') == image.needed, 'helper ELF inspection differs')
    if sdk is not None:
        sdk = Path(sdk).resolve(strict=True)
        require(str(sdk) == build['sdk_path'], 'supplied helper SDK path differs from recorded build input')
        current_llvm = producer_llvm_identity(sdk)
        require(host['bindir'] == current_llvm['bindir'] and host['config'] == current_llvm['config'] and
                all(host['tools'][name]['path'] == current_llvm['tools'][name]['path'] for name in LLVM_TOOLS),
                'supplied analyzer/compiler paths differ from recorded build tools')
        require(inputs.get('sdk') == sdk_record(sdk) and
                inputs.get('llvm') == stable_toolchain(current_llvm) and
                build.get('inspection') == inspect_elf(directory / 'lapy.elf', sdk), 'helper SDK/link inspection differs')
    return {'elf': record(directory / 'lapy.elf'), 'manifest': record(directory / 'lapy-manifest.json'),
            'source': record(directory / 'lapy-source.json'), 'build': record(directory / 'lapy-build.json'),
            'protocol_sha256': source['protocol_sha256'], 'source_contract_commit': UPSTREAM, 'project': project,
            'source_to_binary_reproducibility_verified': False, 'runtime_validated': False, 'toolchain_reverified': sdk is not None}


def build_owned_helper(repo: Path, sdk: Path, out: Path) -> dict:
    repo, sdk = repo.resolve(strict=True), sdk.resolve(strict=True)
    out = out.resolve()
    require(not out.exists() and not repo.is_relative_to(out) and not sdk.is_relative_to(out) and
            not out.is_relative_to(repo) and not out.is_relative_to(sdk),
            'helper output must be a fresh non-overlapping directory')
    project = project_identity(repo)
    source = source_record(repo, project)
    llvm = producer_llvm_identity(sdk)
    inputs = {'source': source, 'flags': FLAGS, 'llvm': stable_toolchain(llvm), 'sdk': sdk_record(sdk)}
    identity = hashlib.sha256(canonical(inputs)).hexdigest()
    out.mkdir(parents=True)
    (out / 'obj').mkdir()
    (out / 'owned_identity.h').write_text('#define LAPY_OWNED_ID "' + identity + '"\n')
    env = compiler_environment(llvm)
    commands = []
    def run(argv):
        result = subprocess.run([str(a) for a in argv], env=env, capture_output=True, text=True)
        commands.append({'argv': [str(a) for a in argv], 'exit': result.returncode, 'output': result.stdout + result.stderr})
        (out / 'build.log').write_text('\n'.join(json.dumps(c) for c in commands) + '\n')
        require(result.returncode == 0, 'helper compiler/analyzer failed; see ' + str(out / 'build.log'))
        return result.stdout
    compiler = sdk / 'bin/prospero-clang'
    includes = ['-I' + str(repo / DIRECTORY), '-I' + str(repo / 'native/ps5log'), '-I' + str(out)]
    objects = []
    for unit in UNITS:
        obj = out / 'obj' / (unit + '.o')
        run([compiler, *FLAGS, *includes, '-c', repo / DIRECTORY / unit, '-o', obj])
        objects.append(obj)
    elf = out / 'lapy.elf'
    run([compiler, *FLAGS, '-Wl,--no-undefined', '-Wl,-Map,' + str(out / 'lapy.map'), *objects, '-o', elf])
    bindir = Path(llvm['bindir'])
    symbols = run([bindir / 'llvm-readelf', '-h', '-l', '-d', '-Ws', elf])
    run([bindir / 'llvm-objdump', '-d', elf])
    inspection = inspect_elf(elf, sdk)
    starts = [line.split() for line in symbols.splitlines() if len(line.split()) >= 8 and line.split()[7] == '_start']
    mains = [line.split() for line in symbols.splitlines() if len(line.split()) >= 8 and line.split()[7] == 'main']
    require(starts and mains and all(row[3] == 'FUNC' and int(row[1], 16) == int(inspection['entry'], 16) for row in starts),
            'helper CRT entry/main definition differs')
    def write(name, value):
        (out / name).write_bytes(canonical(value))
    require(project_identity(repo) == project and source_record(repo, project) == source and
            sdk_record(sdk) == inputs['sdk'] and stable_toolchain(producer_llvm_identity(sdk)) == inputs['llvm'],
            'source or toolchain changed during helper build')
    write('lapy-source.json', source)
    build = {'schema': 'pw-owned-helper-build/1', 'project': project, 'build_id': identity,
             'inputs': inputs, 'host_llvm': llvm, 'compiled_units': list(UNITS),
             'objects': {unit: record(obj) for unit, obj in zip(UNITS, objects)},
             'sdk_path': str(sdk), 'environment': env,
             'command_paths': {'REPO': str(repo), 'SDK': str(sdk), 'OUT': str(out), 'LLVM': str(bindir)},
             'identity_header': record(out / 'owned_identity.h'), 'link_map': record(out / 'lapy.map'),
             'commands': commands, 'inspection': inspection, 'elf': record(elf),
             'source': record(out / 'lapy-source.json'), 'console_validated': False}
    write('lapy-build.json', build)
    manifest = {'schema': 'lapy-owned-build/1', 'mode': 'elf-helper', 'target_title': 'PPSA99995',
                'max_requests': 1, 'service': False, 'require_client_result': False, 'console_validated': False,
                'features': FEATURES, 'protocol_version': 2, 'protocol_bytes': 32, 'build_id': identity,
                'elf_sha256': digest(elf), 'source_sha256': digest(out / 'lapy-source.json'),
                'build_sha256': digest(out / 'lapy-build.json'), 'protocol_sha256': source['protocol_sha256']}
    write('lapy-manifest.json', manifest)
    require(project_identity(repo) == project and source_record(repo, project) == source, 'source changed during helper build')
    return validate_owned_helper(out, repo, project, sdk)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('build', 'verify'))
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--sdk', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'build':
            require(args.sdk is not None, 'helper build requires --sdk')
            result = build_owned_helper(args.repo, args.sdk, args.out)
        else:
            result = validate_owned_helper(args.out, args.repo, sdk=args.sdk)
        print(json.dumps(result, indent=2, sort_keys=True))
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        print('owned helper rejected: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
