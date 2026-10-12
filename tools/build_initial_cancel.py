#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Build a source-bound, isolated initial-CANCEL title; never launch target code.

This produces static build evidence only. No output receives console admission:
the bound no-reboot helper-exit/recovery gate remains independent and mandatory.
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
import tempfile

sys.dont_write_bytecode = True
import build_owned_helper as helper
from native_probe_elf import Elf, extract_self, require
from check_native_suite import provider, inspect_bindings, compiled_identity
from build_wine_service_child import CRT_SHA, LAYOUT_SHA, WRAPPER_SHA, inspect_code
from build_native_child_probe import verify_reconstruction
from native_service_converter import FOUNDATION, TITLE_FOUNDATION, TITLE_WRITER_SHA256
from tls_manifest import tree_files

UNITS = ('native/pw_lapy_initial_cancel_main.c', 'native/pw_lapy_elevation.c',
         'native/ps5log/ps5log.c', 'native/ps5log/ps5log_ps5_net.c')
HEADERS = ('native/pw_lapy_initial_cancel_fixture.h', 'native/pw_lapy_elevation.h',
           'native/pw_lapy_client.h', 'native/pw_sha256.h', 'native/lapy_elevation_protocol.h',
           'native/ps5log/ps5log.h', 'native/ps5log/ps5log_ps5_net.h')
PROVIDERS = {'libSceLibcInternal.sprx': 'libSceLibcInternal.so',
             'libkernel.sprx': 'libkernel.so', 'libSceNet.sprx': 'libSceNet.so'}
FORBIDDEN = {'seteuid', 'setuid', 'setgid', 'setegid', 'geteuid', 'ptrace', 'kill', 'fork', 'rfork',
             'pw_lapy_elevation_request', 'pw_lapy_elevation_request_result', 'root_prepare',
             'pw_data_mount', 'sceKernelDlsym', 'sceKernelLoadStartModule'}
COMMAND_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
ARTIFACTS = ('title.linked.elf', 'title.elf', 'title.recovered.elf', 'eboot.bin', 'title.map', 'ps5-native-tool',
             'lapy.elf', 'lapy-manifest.json', 'lapy-source.json', 'lapy-build.json', 'libc.prx')


class Commands:
    def __init__(self, directory):
        self.directory = directory
        self.records = []

    def run(self, *args):
        argv = [str(arg) for arg in args]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=600, env=COMMAND_ENV)
        item = {'argv': argv, 'exit': result.returncode, 'output': result.stdout + result.stderr,
                'environment': COMMAND_ENV}
        self.records.append(item)
        (self.directory / 'commands.json').write_bytes(helper.canonical({'commands': self.records}))
        require(result.returncode == 0, 'title compiler/analyzer failed; inspect commands.json')
        return result.stdout


def git(directory, *args):
    return subprocess.check_output(['git', '-C', str(directory), *args], text=True).strip()


def title_inputs(repo, sdk, foundation, helper_directory):
    project = helper.project_identity(repo)
    admitted = helper.validate_owned_helper(helper_directory, repo, project, sdk)
    require(sdk.name == 'ps5-payload-sdk' and sdk.parent.name == 'native' and sdk.parent.parent.name == '.deps',
            'isolated title requires recognized SDK/foundation layout')
    title = sdk.parent.parent.parent
    require(git(title, 'rev-parse', 'HEAD') == TITLE_FOUNDATION and
            git(foundation, 'rev-parse', 'HEAD') == FOUNDATION, 'isolated title foundation pin differs')
    for checkout in (title, foundation):
        require(not git(checkout, 'status', '--porcelain', '--untracked-files=all', '--', 'tooling'),
                'foundation tooling changed from its pin')
    native = title / 'tooling/native'
    require(helper.digest(native / 'app_crt.cpp') == CRT_SHA and
            helper.digest(native / 'ps5-pie-high.ld') == LAYOUT_SHA and
            helper.digest(title / 'tooling/prospero-clang18') == WRAPPER_SHA and
            helper.digest(native / 'sce_module_writer.cpp') == TITLE_WRITER_SHA256,
            'CRT, layout, wrapper or original converter hash differs')
    llvm = helper.producer_llvm_identity(sdk)
    zroot = foundation / '.deps/native/zlib/root'
    archives = sorted(zroot.rglob('libz.a'))
    require(len(archives) == 1, 'isolated converter requires one recognized built zlib archive')
    sources = {name: helper.record(repo / name) for name in (*UNITS, *HEADERS)}
    # Includes the transitive Python validators; no unbound alternate recipe.
    sources.update({str(path.relative_to(repo)): helper.record(path)
                    for path in sorted((repo / 'tools').glob('*.py'))})
    require(sources['tools/build_initial_cancel.py']['sha256'] == helper.digest(Path(__file__)),
            'executing title recipe differs from admitted source')
    result = {'schema': 'pw-initial-cancel-build-inputs/1', 'project': project, 'sources': sources,
              'helper': admitted, 'sdk': helper.sdk_record(sdk), 'llvm': helper.stable_toolchain(llvm),
              'title_foundation': TITLE_FOUNDATION, 'converter_foundation': TITLE_FOUNDATION,
              'zlib_foundation': FOUNDATION, 'crt': helper.record(native / 'app_crt.cpp'),
              'layout': helper.record(native / 'ps5-pie-high.ld'),
              'wrapper': helper.record(title / 'tooling/prospero-clang18'),
              'converter_sources': tree_files(native), 'zlib_archive': helper.record(archives[0]),
              'zlib_headers': tree_files(zroot / 'usr/include'),
              'libc_companion': helper.record(title / 'runtime/libc.prx')}
    return result, {'REPO': str(repo), 'SDK': str(sdk), 'FOUNDATION': str(foundation),
                    'TITLE': str(title), 'LLVM': llvm['bindir'], 'LLVM_CONFIG': llvm['config'],
                    'ZROOT': str(zroot), 'ZLIB': str(archives[0]), 'HELPER': str(helper_directory)}


def command_plan(bound, paths, out):
    """The digest comes only from verified helper output, never a caller macro."""
    sha = bound['helper']['elf']['sha256']
    require(re.fullmatch('[0-9a-f]{64}', sha) and bound['helper']['project'] == bound['project'] and
            bound['helper'].get('toolchain_reverified') is True and bound['helper'].get('runtime_validated') is False,
            'title/helper source or actual digest differs')
    identity = hashlib.sha256(helper.canonical(bound)).hexdigest()
    repo, sdk, title, llvm = (Path(paths[key]) for key in ('REPO', 'SDK', 'TITLE', 'LLVM'))
    native = title / 'tooling/native'
    environment = ['env', '-i', 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C',
                   'PS5_PAYLOAD_SDK=' + str(sdk), 'PS5_CLANG=' + str(llvm / 'clang'),
                   'LLVM_CONFIG=' + paths['LLVM_CONFIG']]
    cc = [*environment, 'sh', str(title / 'tooling/prospero-clang18'), '--no-default-config']
    flags = ['-O2', '-Wall', '-Wextra', '-Werror', '-ffunction-sections', '-fdata-sections',
             '-fasynchronous-unwind-tables', '-DPW_LAPY_INITIAL_CANCEL_ONLY=1',
             '-DPW_LAPY_HELPER_SHA256="' + sha + '"', '-DPW_BUILD_ID="' + identity + '"',
             '-I' + str(repo / 'native'), '-I' + str(repo / 'native/ps5log')]
    plan = [cc + ['-dM', '-E', '-x', 'c', '/dev/null']]
    objects = []
    for unit in UNITS:
        obj = out / 'obj' / (unit.replace('/', '_') + '.o')
        extra = ['-include', str(repo / 'native/ps5log/ps5log_ps5_net.h')] if unit.endswith('/ps5log.c') else []
        plan.append(cc + ['-std=c11', *flags, *extra, '-c', str(repo / unit), '-o', str(obj)])
        objects.append(str(obj))
    crt = out / 'obj/app_crt.o'
    plan.append(cc + ['-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-exceptions', '-fno-rtti',
                     '-ffunction-sections', '-fdata-sections', '-fasynchronous-unwind-tables',
                     '-c', str(native / 'app_crt.cpp'), '-o', str(crt)])
    stubs = [str(sdk / 'target/lib' / name) for name in PROVIDERS.values()]
    plan.append([*environment, str(sdk / 'bin/prospero-lld'), '-T', str(native / 'ps5-pie-high.ld'),
                 '--eh-frame-hdr', '-e', '_start', '-z', 'defs', '-Map=' + str(out / 'title.map'),
                 '-o', str(out / 'title.linked.elf'), str(crt), *objects, '--as-needed', *stubs])
    tool = out / 'ps5-native-tool'
    plan.append([*environment, str(llvm / 'clang++'), '--no-default-config', '-std=c++20', '-O2', '-Wall',
                 '-Wextra', '-Werror', '-I', str(Path(paths['ZROOT']) / 'usr/include'), '-I', str(native),
                 *[str(native / name) for name in ('native_app_builder.cpp', 'self_container.cpp',
                   'elf_object.cpp', 'sce_module_writer.cpp')], paths['ZLIB'], '-o', str(tool)])
    plan.append([str(tool), 'link', '--in', str(out / 'title.linked.elf'), '--out', str(out / 'title.elf'),
                 *[arg for stub in stubs for arg in ('--stub', stub)], '--module-sdk', '0x02000009',
                 '--companion-sdk', '0x08050001', '--file-name', 'eboot.elf'])
    plan.append([str(tool), 'self', '--sign', '--in', str(out / 'title.elf'), '--out', str(out / 'eboot.bin'),
                 '--magic', '0x1D3D154F'])
    return identity, plan


def validate_constructor_arrays(images):
    for image in images:
        for tag in (27, 28, 33):
            require(not image.has(tag) or image.tag(tag) == 0, 'unexpected nonempty constructor/destructor array')


def validate_link_map(data, original_output):
    text = data.decode('utf-8')
    objects = {str(original_output / 'obj/app_crt.o'),
               *[str(original_output / 'obj' / (unit.replace('/', '_') + '.o')) for unit in UNITS]}
    observed = set(re.findall(r'[^\s()]+\.o(?=[:(\s]|$)', text))
    require(observed == objects, 'isolated link map has missing or foreign object input')


# Pinned SDK include/freebsd/stdio.h declares these as FILE * objects, not
# functions. ps5log_release_stdio/capture uses fflush/setvbuf on these pointers.
# Admit only their ordinary 64-bit GOT slots, never arbitrary data imports.
STDIO_POINTERS = {'__stdoutp', '__stderrp'}
STDIO_PROVIDER = 'libSceLibcInternal.sprx'


def inspect_import_contract(linked, converted, providers, stdio_exports):
    graph = inspect_bindings(linked, converted, providers)
    require(not FORBIDDEN.intersection(graph) and not any(name.startswith(('sceSysmodule', 'pw_wine_')) for name in graph),
            'isolated title contains forbidden ordinary-wrapper/native imports')
    for name in ('_init_env', 'atexit', 'exit'):
        require(graph.get(name, {}).get('provider') == STDIO_PROVIDER, 'full CRT import missing or misbound')
    objects, slots = set(), set()
    for symbol in linked.symbols[1:]:
        name = symbol['name']; chosen = graph[name]['provider']
        require(symbol['binding'] == 1 and symbol['visibility'] == 0,
                'unsupported isolated title import binding/visibility: ' + name)
        relocations = graph[name]['relocations']
        if name in STDIO_POINTERS:
            exported = stdio_exports.get(name, {})
            require(chosen == STDIO_PROVIDER and symbol['type'] == 1 and
                    symbol['section'] == 0 and symbol['value'] == 0 and symbol['size'] == 0 and
                    providers[chosen]['definitions'][name] == 'OBJECT' and
                    exported.get('name') == name and exported.get('type') == 1 and
                    exported.get('binding') == 1 and exported.get('visibility') == 0 and
                    0 < exported.get('section', 0) < 0xff00 and exported.get('size') == 0,
                    'unsupported isolated stdio pointer contract: ' + name)
            require(len(relocations) == 1 and relocations[0]['type'] == 6 and
                    relocations[0]['addend'] == 0 and relocations[0]['address'] % 8 == 0,
                    'unsupported isolated stdio pointer relocation: ' + name)
            address = relocations[0]['address']
            require(all(sum(r['address'] < address + 8 and address < r['address'] + 8
                            for r in image.relocations) == 1 for image in (linked, converted)),
                    'overlapping isolated stdio pointer relocation: ' + name)
            objects.add(name)
        else:
            require(symbol['type'] in (0, 2) and providers[chosen]['definitions'][name] == 'FUNC',
                    'unsupported isolated title import type: ' + name)
            require(relocations and all(r['type'] in (6, 7) and r['addend'] == 0 for r in relocations),
                    'unsupported isolated title import relocation: ' + name)
        for relocation in relocations:
            require(relocation['address'] % 8 == 0 and relocation['address'] not in slots,
                    'overlapping or unaligned isolated import slot')
            slots.add(relocation['address'])
            linked.offset(relocation['address'], 8, 6)
            converted.offset(relocation['address'], 8, 6)
    require(objects == STDIO_POINTERS, 'isolated logger stdio pointer set differs')
    return graph


def inspect_stdio_exports(data, provider_record):
    require(hashlib.sha256(data).hexdigest() == provider_record['sha256'],
            'isolated libc provider changed during inspection')
    exports = Elf(data, module=True).symbols
    rows = {name: [s for s in exports if s['name'] == name] for name in STDIO_POINTERS}
    require(all(len(items) == 1 for items in rows.values()), 'ambiguous isolated stdio provider exports')
    return {name: items[0] for name, items in rows.items()}


def inspect_title(directory, sdk, bindir, identity, helper_sha, commands):
    linked = Elf(helper.raw(directory / 'title.linked.elf', 4 << 20))
    converted_bytes = helper.raw(directory / 'title.elf', 4 << 20)
    converted = Elf(converted_bytes)
    require(set(linked.needed) == set(PROVIDERS) and len(linked.needed) == 3,
            'isolated title has unexpected provider closure')
    providers = {name: provider(sdk / 'target/lib' / leaf, bindir, commands)
                 for name, leaf in PROVIDERS.items()}
    require(all(item['soname'] == name for name, item in providers.items()), 'title provider SONAME differs')
    libc = helper.raw(sdk / 'target/lib' / PROVIDERS[STDIO_PROVIDER])
    graph = inspect_import_contract(linked, converted, providers,
                                    inspect_stdio_exports(libc, providers[STDIO_PROVIDER]))
    # This dedicated all-C body needs no additional constructors. Refuse an
    # unknown constructor path rather than inferring safety from main alone.
    validate_constructor_arrays((linked, converted))
    symbols = commands.run(bindir / 'llvm-readelf', '-sW', directory / 'title.linked.elf')
    names = {line.split()[7] for line in symbols.splitlines() if len(line.split()) >= 8}
    require(not FORBIDDEN.intersection(names) and 'pw_lapy_initial_cancel_result' in names,
            'normal elevation or unwanted entry body linked into isolated title')
    code = inspect_code(directory / 'title.linked.elf', bindir, commands)
    recovered_bytes = extract_self(helper.raw(directory / 'eboot.bin', 4 << 20))
    recovered = directory / 'title.recovered.elf'
    if recovered.exists():
        require(helper.raw(recovered) == recovered_bytes, 'retained title SELF extraction differs')
    else:
        with recovered.open('xb') as stream:
            stream.write(recovered_bytes)
    reconstruction = verify_reconstruction(directory / 'title.elf', recovered)
    compiled_identity(Elf(recovered_bytes), identity)
    compiled_identity(Elf(recovered_bytes), helper_sha)
    return {'graph': graph, 'code': code, 'constructors': 'no nonempty arrays; exact pinned full CRT retained',
            'source_identity': compiled_identity(converted, identity),
            'helper_identity': compiled_identity(converted, helper_sha),
            'self_reconstruction': reconstruction, 'runtime_validated': False}


def build_title(repo, sdk, foundation, helper_directory, out):
    originals = [repo, sdk, foundation, helper_directory]
    require(not out.exists() and all(not out.is_relative_to(p) and not p.is_relative_to(out) for p in originals),
            'title output must be fresh and outside all inputs')
    bound, paths = title_inputs(repo, sdk, foundation, helper_directory)
    identity, plan = command_plan(bound, paths, out)
    out.mkdir(parents=True); (out / 'obj').mkdir()
    commands = Commands(out)
    macros = commands.run(*plan[0])
    for name in ('__PROSPERO__', '__FreeBSD__', '__x86_64__'):
        require(re.search(r'^#define ' + name + r' [1-9][0-9]*$', macros, re.M), 'wrong isolated title target macro')
    for command in plan[1:]:
        commands.run(*command)
    validate_link_map(helper.raw(out / 'title.map'), out)
    inspection = inspect_title(out, sdk, Path(paths['LLVM']), identity, bound['helper']['elf']['sha256'], commands)
    for name in helper.OUTPUTS:
        (out / name).write_bytes(helper.raw(helper_directory / name))
    (out / 'libc.prx').write_bytes(helper.raw(Path(paths['TITLE']) / 'runtime/libc.prx'))
    require(title_inputs(repo, sdk, foundation, helper_directory)[0] == bound, 'isolated title input changed during build')
    manifest = {'schema': 'pw-initial-cancel-title-build/1', 'inputs': bound, 'build_id': identity,
                'build_paths': paths, 'original_output': str(out),
                'compiled_units': list(UNITS), 'objects': {p.name: helper.record(p) for p in sorted((out / 'obj').glob('*.o'))},
                'artifacts': {name: helper.record(out / name) for name in ARTIFACTS},
                'commands': commands.records, 'inspection': inspection, 'target_ready': False,
                'runtime_validated': False, 'no_reboot_lifecycle_verified': False}
    (out / 'initial-cancel-build.json').write_bytes(helper.canonical(manifest))
    return verify_title(repo, sdk, foundation, helper_directory, out)


def verify_title(repo, sdk, foundation, helper_directory, out):
    manifest = helper.read_json(out / 'initial-cancel-build.json', output=True)
    require(set(manifest) == {'schema', 'inputs', 'build_id', 'build_paths', 'original_output', 'compiled_units',
            'objects', 'artifacts', 'commands', 'inspection', 'target_ready', 'runtime_validated', 'no_reboot_lifecycle_verified'} and
            manifest['schema'] == 'pw-initial-cancel-title-build/1' and all(manifest[k] is False for k in
            ('target_ready', 'runtime_validated', 'no_reboot_lifecycle_verified')), 'isolated title manifest schema/admission differs')
    bound, current_paths = title_inputs(repo, sdk, foundation, helper_directory)
    require(manifest['build_paths'] == current_paths, 'recorded title tool/source paths differ from admitted inputs')
    require(manifest['inputs'] == bound, 'title source/helper/toolchain cohort differs')
    identity, plan = command_plan(bound, manifest['build_paths'], Path(manifest['original_output']))
    require(manifest['build_id'] == identity and manifest['compiled_units'] == list(UNITS), 'title identity/units differ')
    require(len(manifest['commands']) > len(plan) and all(set(c) == {'argv', 'exit', 'output', 'environment'} and type(c['exit']) is int and
            c['exit'] == 0 and c['environment'] == COMMAND_ENV for c in manifest['commands']) and
            [c['argv'] for c in manifest['commands'][:len(plan)]] == plan, 'isolated compile/link/conversion commands differ')
    expected_objects = {'app_crt.o', *[unit.replace('/', '_') + '.o' for unit in UNITS]}
    require(set(manifest['objects']) == expected_objects and all(record == helper.record(out / 'obj' / name)
            for name, record in manifest['objects'].items()), 'isolated actual objects differ')
    require(set(manifest['artifacts']) == set(ARTIFACTS) and all(record == helper.record(out / name)
            for name, record in manifest['artifacts'].items()), 'isolated artifact bytes differ')
    validate_link_map(helper.raw(out / 'title.map'), Path(manifest['original_output']))
    require(all(helper.raw(out / name) == helper.raw(helper_directory / name) for name in helper.OUTPUTS),
            'packaged helper does not match admitted producer bytes')
    # Fresh verifier logs remain separate from the immutable build receipt.
    check = Path(tempfile.mkdtemp(prefix='verification-', dir=out))
    verifier = Commands(check)
    inspection = inspect_title(out, sdk, Path(manifest['build_paths']['LLVM']), identity,
                               bound['helper']['elf']['sha256'], verifier)
    require(inspection == manifest['inspection'], 'isolated static title inspection differs')
    # Compare the complete tail to commands independently emitted by the
    # fixed inspection routine. Only the archived output root may relocate.
    def original_output_argument(arg):
        current = str(out)
        if arg == current or arg.startswith(current + '/'):
            return manifest['original_output'] + arg[len(current):]
        return arg
    expected_tail = [[original_output_argument(arg) for arg in command['argv']]
                     for command in verifier.records]
    require([c['argv'] for c in manifest['commands'][len(plan):]] == expected_tail,
            'unexpected or substituted command after isolated title build plan')
    return {'schema': 'pw-initial-cancel-static-admission/1', 'project': bound['project'],
            'title': helper.record(out / 'eboot.bin'), 'helper': bound['helper']['elf'],
            'build': helper.record(out / 'initial-cancel-build.json'), 'static_build_verified': True,
            'target_ready': False, 'no_reboot_lifecycle_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('build', 'verify'))
    for name in ('repo', 'sdk', 'foundation', 'helper', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        inputs = [getattr(args, name).resolve(strict=True) for name in ('repo', 'sdk', 'foundation', 'helper')]
        output = args.out.resolve()
        result = (build_title if args.action == 'build' else verify_title)(*inputs, output)
        print(json.dumps(result, indent=2, sort_keys=True))
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        print('isolated initial-CANCEL title rejected: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
