#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Build and statically inspect a full-CRT service child from one Wine cohort.

The original app_crt/high layout stay unchanged. A separate source copy of
the pinned converter adds the already reviewed service preload pointer.
No resulting target binary is executed by this tool.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

sys.dont_write_bytecode = True
from check_wine_prx_build import Commands, require
from check_native_suite import (provider, inspect_bindings, compiled_identity, embedded_image,
                                index_sdk_providers, source_archive, SERVICE_CALLS)
from native_probe_elf import Elf, extract_self
from native_service_converter import prepare_converter_source, inspect_service_preload, service_writer_bytes, FOUNDATION
from build_native_child_probe import streamable_self, verify_reconstruction, compare_service_preload
from check_private_dispatch_abi import check_build
from tls_manifest import llvm_identity, tree_files

ROOT = Path(__file__).resolve().parents[1]
TITLE_FOUNDATION = '9c0b994a048521af6fb84c73ded364504fe250e9'
CRT_SHA = 'a99fe406e36d8ce82e68e0245898ba064e28a56a9853f746e9cf13d23cc17a00'
LAYOUT_SHA = '72ee9a1605cce2836d2290fa9a6a6fba0c3c277e78094e7f07562e92dd5b4e49'
WRAPPER_SHA = 'c90881bd828048981da08644ae1e1730a0ef10692b6322cbd6a294de8c5c5346'
UNITS = ('native/pw_wine_child_wire.c', 'native/pw_wine_child_bootstrap.c', 'native/pw_wine_child_main.c',
         'native/pw_native_child_protocol.c', 'src/pw_wine_start.c', 'wine/ps5/pw_wine_prx.c', 'wine/ps5/pw_wine_threads.c')
HEADERS = ('native/pw_wine_child_wire.h', 'native/pw_wine_child_bootstrap.h', 'src/pw_wine_start.h',
           'native/pw_native_child_protocol.h', 'src/pw_wine_launch.h', 'include/prospero_win.h',
           'wine/ps5/pw_wine_prx.h', 'wine/ps5/pw_wine_threads.h', 'wine/ps5/pw_wine_fixture_socket.h')
PROVIDERS = {'libSceLibcInternal.sprx': 'libSceLibcInternal.so', 'libkernel.sprx': 'libkernel.so'}
CRT_IMPORTS = {'_init_env': 'libSceLibcInternal.sprx', 'atexit': 'libSceLibcInternal.sprx',
               'exit': 'libSceLibcInternal.sprx', 'pthread_create': 'libkernel.sprx'}
TITLE_MARKER = 'pw-wine-child-fixture/1'
TITLE_FUNCTIONS = ('pw_wine_fixture_owner_init', 'pw_wine_fixture_owner_pump')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def record(path):
    return {'bytes': path.stat().st_size, 'sha256': sha(path)}


def source_identity(root, commands):
    require(not commands.run('git', '-C', root, 'status', '--porcelain', '--untracked-files=normal').strip(),
            'service child requires clean committed project source')
    project = {'commit': commands.run('git', '-C', root, 'rev-parse', 'HEAD').strip(),
               'tree': commands.run('git', '-C', root, 'rev-parse', 'HEAD^{tree}').strip()}
    sources = {name: sha(root / name) for name in (*UNITS, *HEADERS, 'tools/build_wine_service_child.py',
               'tools/native_service_converter.py', 'tools/native_probe_elf.py', 'tools/check_native_suite.py')}
    return project, sources


def identity(inputs):
    return hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:40]


def output_directory(path, inputs):
    path = path.absolute()
    require(not path.exists() and not path.is_symlink(), 'service output must be absent')
    for part in (path.parent, *path.parent.parents):
        require(not part.is_symlink(), 'service output has a symlink parent')
    require(path.parent.is_dir(), 'service output parent does not exist')
    for original in inputs:
        original = original.resolve(strict=True)
        require(not path.is_relative_to(original) and not original.is_relative_to(path), 'service output overlaps an input')
    path.mkdir()
    return path


def ordinary_graph(linked, converted, providers):
    require(set(linked.needed) == set(PROVIDERS) and len(linked.needed) == 2,
            'full-CRT child needs exactly ordinary libc and kernel providers')
    graph = inspect_bindings(linked, converted, providers)
    for index, symbol in enumerate(linked.symbols[1:], 1):
        name = symbol['name']; entry = graph[name]
        selected = entry['provider']
        require(symbol['type'] in (0, 2) and symbol['binding'] == 1 and symbol['visibility'] == 0 and
                providers[selected]['definitions'][name] == 'FUNC', 'unsupported child import type/provider: ' + name)
        require(entry['relocations'] and all(r['type'] in (6, 7) and r['addend'] == 0 for r in entry['relocations']),
                'unsupported child function relocation: ' + name)
        for relocation in entry['relocations']:
            linked.offset(relocation['address'], 8, 6)
            converted.offset(relocation['address'], 8, 6)
    require(all(name in graph and graph[name]['provider'] == expected for name, expected in CRT_IMPORTS.items()),
            'full-CRT lifecycle imports missing or bound to wrong providers')
    return graph


def check_disassembly(disassembly):
    require(re.search(r'^\s*[0-9a-f]+:\s+\S', disassembly, re.M), 'child disassembly is empty')
    require(not re.search(r'\(bad\)|<unknown>|\.byte\b', disassembly, re.I), 'child analyzer has undecoded bytes')
    require(not re.search(r'^\s*[0-9a-f]+:\s+(?:syscall|sysenter)(?:\s|$)|'
                          r'^\s*[0-9a-f]+:\s+int\w*\s+\$?(?:0x80|128)(?:\s|$)', disassembly, re.M | re.I),
            'child contains raw syscall')


def inspect_code(path, bindir, commands):
    image = Elf(path.read_bytes())
    image.offset(image.entry, 1, 1)
    sections = commands.run(bindir / 'llvm-readelf', '--section-headers', '-W', path)
    unwind = re.findall(r'^\s*\[\s*\d+\]\s+(\.eh_frame(?:_hdr)?)\s+(PROGBITS|X86_64_UNWIND)'
                        r'\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\b', sections, re.M)
    require(len(unwind) == 2 and {n for n, _, _ in unwind} == {'.eh_frame', '.eh_frame_hdr'} and
            all(int(size, 16) > 0 for _, _, size in unwind), 'full-CRT child lacks unwind records')
    disassembly = commands.run(bindir / 'llvm-objdump', '-d', '--no-show-raw-insn', path)
    check_disassembly(disassembly)
    symbols = commands.run(bindir / 'llvm-readelf', '-sW', path)
    for name in ('_start', 'main', '_init', '_fini'):
        rows = [line.split() for line in symbols.splitlines() if len(line.split()) >= 8 and line.split()[7] == name]
        require(rows and all(r[3] == 'FUNC' and r[6] != 'UND' for r in rows), 'missing full-CRT function: ' + name)
        if name == '_start':
            require(all(int(r[1], 16) == image.entry for r in rows), 'ELF entry differs from app_crt _start')
    return {'entry': hex(image.entry), 'unwind_bytes': {n: int(s, 16) for n, _, s in unwind},
            'raw_syscalls': [], 'app_crt_functions': ['_start', '_init', '_fini', 'main']}


def inputs(args, commands):
    root, sdk, foundation, runtime, bindir = [Path(p).resolve(strict=True) for p in
        (args.work, args.sdk, args.foundation, args.runtime, args.llvm_bindir)]
    require(sdk.name == 'ps5-payload-sdk' and sdk.parent.name == 'native' and sdk.parent.parent.name == '.deps',
            'SDK must use its supported title foundation layout')
    title = sdk.parent.parent.parent
    require(commands.run('git', '-C', title, 'rev-parse', 'HEAD').strip() == TITLE_FOUNDATION and
            commands.run('git', '-C', foundation, 'rev-parse', 'HEAD').strip() == FOUNDATION, 'wrong foundation source')
    for checkout in (title, foundation):
        require(not commands.run('git', '-C', checkout, 'status', '--porcelain', '--untracked-files=all',
                                 '--', 'tooling').strip(), 'foundation source differs from its pin')
    native = title / 'tooling/native'
    require(sha(native / 'app_crt.cpp') == CRT_SHA and sha(native / 'ps5-pie-high.ld') == LAYOUT_SHA and
            sha(title / 'tooling/prospero-clang18') == WRAPPER_SHA, 'full-CRT/layout/compiler wrapper pin differs')
    llvm = llvm_identity(sdk)
    require(Path(llvm['bindir']).resolve() == bindir, 'child analyzer/compiler selection differs from SDK')
    require(re.search(r'LLVM version 18(?:\.|\b)', commands.run(bindir / 'llvm-readelf', '--version')),
            'child requires LLVM18')
    project, sources = source_identity(root, commands)
    abi = check_build(runtime, 1, bindir / 'llvm-readelf', require_wow64=True)
    require(abi.get('wow64', {}).get('abi') == 1 and abi['wow64'].get('runtime_validated') is False,
            'full-CRT child requires the checked translated-I386 runtime capability')
    declaration = json.loads((runtime / 'report.json').read_text()).get('service_fixture')
    require(declaration == {'enabled': True, 'unix_define': 'PW_WINE_SERVICE_FIXTURE=1',
                            'abi': 1, 'runtime_validated': False}, 'Wine service consumers were not explicitly built')
    result = {'project': project, 'sources': sources, 'runtime': {'ntdll_sha256': sha(runtime / 'prx/sce_module/ntdll.prx'),
              'private_dispatch_abi': 1, 'private_dispatch_wow64_abi': 1, 'report_sha256': sha(runtime / 'report.json'), 'abi_check': abi},
              'candidate_capabilities': [
                  {'mode': 1, 'prefix': 'windows-child-fixture-v1', 'guest_machine': 'AMD64',
                   'backend': 'native-amd64', 'runtime_validated': False},
                  {'mode': 2, 'prefix': 'battlenet-experimental-v1', 'guest_machine': 'I386',
                   'backend': 'wowprospero', 'runtime_validated': False}],
              'title_foundation': TITLE_FOUNDATION, 'converter_foundation': FOUNDATION,
              'app_crt_sha256': CRT_SHA, 'layout_sha256': LAYOUT_SHA, 'wrapper_sha256': WRAPPER_SHA,
              'libc_companion': record(title / 'runtime/libc.prx'), 'host_llvm': llvm,
              'sdk_headers': tree_files(sdk / 'target/include'), 'sdk_wrappers': tree_files(sdk / 'bin'),
              'providers': {name: record(sdk / 'target/lib' / leaf) for name, leaf in PROVIDERS.items()}}
    return result, (root, sdk, foundation, runtime, bindir, title)


def child_header(bound, build_id):
    require(bound['runtime'].get('private_dispatch_abi') == 1 and
            bound['runtime'].get('private_dispatch_wow64_abi') == 1,
            'child header cannot assert an absent ABI capability')
    require(re.fullmatch('[0-9a-f]{40}', build_id) and
            re.fullmatch('[0-9a-f]{64}', bound['runtime']['ntdll_sha256']), 'invalid child header identity')
    return ('#define PW_WINE_CHILD_BUILD_ID "' + build_id + '"\n' +
            '#define PW_WINE_CHILD_NTDLL_SHA256 "' + bound['runtime']['ntdll_sha256'] + '"\n' +
            '#define PW_WINE_CHILD_PRIVATE_DISPATCH_ABI 1\n' +
            '#define PW_WINE_CHILD_WOW64_ABI 1\n')


def build(args):
    out = output_directory(args.out, (args.sdk, args.foundation, args.runtime))
    commands = Commands(out / 'inspection')
    bound, paths = inputs(args, commands)
    root, sdk, foundation, runtime, bindir, title = paths
    build_id = identity(bound)
    header = out / 'wine-child-build.h'
    header.write_text(child_header(bound, build_id))
    environment = ['env', '-i', 'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C',
                   'PS5_PAYLOAD_SDK=' + str(sdk), 'PS5_CLANG=' + str(bindir / 'clang'),
                   'LLVM_CONFIG=' + bound['host_llvm']['config']]
    cc = [*environment, 'sh', title / 'tooling/prospero-clang18', '--no-default-config']
    macros = commands.run(*cc, '-dM', '-E', '-x', 'c', '/dev/null')
    for name in ('__PROSPERO__', '__FreeBSD__', '__x86_64__'):
        require(re.search(r'^#define ' + name + r' [1-9][0-9]*$', macros, re.M), 'wrong target macro: ' + name)
    objects = []
    for name in UNITS:
        obj = out / (name.replace('/', '_') + '.o')
        commands.run(*cc, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-ffunction-sections', '-fdata-sections',
                     '-fasynchronous-unwind-tables',
                     '-I' + str(out), '-I' + str(root / 'include'), '-I' + str(root / 'src'), '-I' + str(root / 'native'),
                     '-I' + str(root / 'wine/ps5'), '-c', root / name, '-o', obj)
        objects.append(obj)
    crt = out / 'app_crt.o'
    commands.run(*cc, '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-exceptions', '-fno-rtti',
                 '-ffunction-sections', '-fdata-sections', '-fasynchronous-unwind-tables',
                 '-c', title / 'tooling/native/app_crt.cpp', '-o', crt)
    linked = out / 'child.linked.elf'
    stubs = [sdk / 'target/lib' / name for name in ('libSceLibcInternal.so', 'libkernel.so')]
    commands.run(*environment, sdk / 'bin/prospero-lld', '-T', title / 'tooling/native/ps5-pie-high.ld',
                 '--eh-frame-hdr', '-e', '_start', '-z', 'defs', '-o', linked, crt, *objects, '--as-needed', *stubs)
    native = foundation / 'tooling/native'
    writer, specialized = prepare_converter_source(native / 'sce_module_writer.cpp', out / 'sce_module_writer.service.cpp', service=True)
    zroot = foundation / '.deps/native/zlib/root'
    archives = sorted(zroot.rglob('libz.a'))
    require(len(archives) == 1, 'converter requires one pinned built zlib archive')
    tool = out / 'ps5-native-tool'
    commands.run(*environment, bindir / 'clang++', '--no-default-config', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
                 '-I', zroot / 'usr/include', '-I', native, native / 'native_app_builder.cpp', native / 'self_container.cpp',
                 native / 'elf_object.cpp', writer, archives[0], '-o', tool)
    converted, signed, final = out / 'child.elf', out / 'child.original.self', out / 'native-wine-child.self'
    commands.run(tool, 'link', '--in', linked, '--out', converted, '--stub', stubs[0], '--stub', stubs[1],
                 '--module-sdk', '0x02000009', '--companion-sdk', '0x08050001', '--file-name', 'native-wine-child.elf',
                 '--component', 'pw_wine_service_child')
    providers = {name: provider(sdk / 'target/lib' / leaf, bindir, commands) for name, leaf in PROVIDERS.items()}
    require(all(p['soname'] == name for name, p in providers.items()), 'SDK provider SONAME differs')
    graph = ordinary_graph(Elf(linked.read_bytes()), Elf(converted.read_bytes()), providers)
    code = inspect_code(linked, bindir, commands)
    preload = inspect_service_preload(converted.read_bytes())
    commands.run(tool, 'self', '--sign', '--in', converted, '--out', signed, '--magic', '0x1D3D154F')
    framing = streamable_self(signed, final, tool, commands)
    recovered = final.with_suffix('.after.elf')
    reconstruction = verify_reconstruction(converted, recovered)
    require(extract_self(final.read_bytes()) == recovered.read_bytes(), 'independent SELF recovery differs')
    after = inspect_service_preload(recovered.read_bytes()); compare_service_preload(preload, after)
    compiled_identity(Elf(recovered.read_bytes()), build_id)
    final.chmod(0o755)
    require(inputs(args, commands)[0] == bound, 'service build inputs changed')
    manifest = {'schema': 'pw-wine-service-child/1', **bound,
                'worker': {**record(final), 'build_id': build_id},
                'linked': record(linked), 'converted': record(converted), 'reconstructed': record(recovered),
                'linkage': graph, 'code': code, 'reconstruction': reconstruction, 'framing': framing,
                'converter_specialization': specialized, 'converter_sha256': sha(tool),
                'converter_sources': {p.name: sha(p) for p in sorted(native.iterdir()) if p.is_file()},
                'zlib_archive': record(archives[0]), 'zlib_headers': tree_files(zroot / 'usr/include'),
                'preload_before_signing': preload, 'preload_after_recovery': after,
                'console_execution_verified': False, 'windows_process_support': False,
                'platform_authentication_verified': False}
    (out / 'native-wine-child-build.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (out / 'native-wine-child-build.h').write_text(header.read_text() +
        '#define PW_WINE_CHILD_SELF_SHA256 "' + manifest['worker']['sha256'] + '"\n' +
        '#define PW_WINE_CHILD_SELF_BYTES ' + str(manifest['worker']['bytes']) + '\n')
    value = final.read_bytes()
    with (out / 'native-wine-child-image.c').open('w') as stream:
        stream.write('/* Generated from the checked original full-CRT service SELF. */\n#include <stddef.h>\n'
                     'const unsigned char pw_wine_child_image[] = {\n')
        for start in range(0, len(value), 16):
            stream.write(','.join(str(v) for v in value[start:start + 16]) + ',\n')
        stream.write('};\nconst size_t pw_wine_child_image_size = sizeof(pw_wine_child_image);\n')
    for name, leaf in PROVIDERS.items():
        shutil.copyfile(sdk / 'target/lib' / leaf, out / leaf)
    return manifest


def verify_child(args, commands):
    """Recheck a retained build graph without trusting its previous report alone."""
    bound, paths = inputs(args, commands)
    root, sdk, foundation, runtime, bindir, title = paths
    work = args.service_work.resolve(strict=True)
    manifest = json.loads((work / 'native-wine-child-build.json').read_text())
    require(manifest.get('schema') == 'pw-wine-service-child/1' and
            all(manifest.get(k) == v for k, v in bound.items()), 'service child source/runtime inputs differ')
    require(manifest['worker']['build_id'] == identity(bound), 'service child build ID differs')
    for field, name in (('worker', 'native-wine-child.self'), ('linked', 'child.linked.elf'),
                        ('converted', 'child.elf'), ('reconstructed', 'native-wine-child.after.elf')):
        require(all(manifest[field].get(k) == v for k, v in record(work / name).items()), 'stale child artifact: ' + name)
    value = extract_self((work / 'native-wine-child.self').read_bytes())
    require(value == (work / 'native-wine-child.after.elf').read_bytes(), 'child SELF recovery differs')
    compiled_identity(Elf(value), manifest['worker']['build_id'])
    require(inspect_service_preload((work / 'child.elf').read_bytes()) == manifest['preload_before_signing'] and
            inspect_service_preload(value) == manifest['preload_after_recovery'], 'child preload report differs')
    compare_service_preload(manifest['preload_before_signing'], manifest['preload_after_recovery'])
    require(verify_reconstruction(work / 'child.elf', work / 'native-wine-child.after.elf') == manifest['reconstruction'],
            'child reconstruction report differs')
    providers = {name: provider(sdk / 'target/lib' / leaf, bindir, commands) for name, leaf in PROVIDERS.items()}
    require(ordinary_graph(Elf((work / 'child.linked.elf').read_bytes()), Elf((work / 'child.elf').read_bytes()), providers)
            == manifest['linkage'], 'child actual import graph differs')
    require(inspect_code(work / 'child.linked.elf', bindir, commands) == manifest['code'], 'child code inspection differs')
    native = foundation / 'tooling/native'
    require((work / 'sce_module_writer.service.cpp').read_bytes() ==
            service_writer_bytes((native / 'sce_module_writer.cpp').read_bytes()), 'service converter source copy differs')
    require(manifest['converter_sources'] == {p.name: sha(p) for p in sorted(native.iterdir()) if p.is_file()} and
            manifest['converter_sha256'] == sha(work / 'ps5-native-tool'), 'converter retained inputs/output differ')
    zroot = foundation / '.deps/native/zlib/root'; archives = sorted(zroot.rglob('libz.a'))
    require(len(archives) == 1 and manifest['zlib_archive'] == record(archives[0]) and
            manifest['zlib_headers'] == tree_files(zroot / 'usr/include'), 'converter zlib inputs differ')
    for name, leaf in PROVIDERS.items():
        require(record(work / leaf) == bound['providers'][name], 'retained service provider differs')
    for key in ('console_execution_verified', 'windows_process_support', 'platform_authentication_verified'):
        require(manifest.get(key) is False, 'child manifest makes unsupported execution claim')
    return manifest, paths


def check_route(linked, recovered, symbols):
    marker = compiled_identity(recovered, TITLE_MARKER)
    functions = {}
    for name in TITLE_FUNCTIONS:
        rows = [line.split() for line in symbols.splitlines() if len(line.split()) >= 8 and line.split()[7] == name]
        require(len(rows) == 1 and rows[0][3] == 'FUNC' and rows[0][6] != 'UND', 'missing defined fixture route: ' + name)
        address, size = int(rows[0][1], 16), int(rows[0][2])
        require(address > 0 and size > 0, 'empty fixture route function')
        before = linked.offset(address, size, 1); after = recovered.offset(address, size, 1)
        original, actual = linked.data[before:before + size], recovered.data[after:after + size]
        require(original == actual, 'fixture route bytes changed through conversion')
        functions[name] = {'address': address, 'bytes': size, 'sha256': hashlib.sha256(actual).hexdigest()}
    return {'mode': 1, 'marker': marker, 'functions': functions, 'runtime_validated': False}


def fixture_title_identity(image, title_inputs, pair):
    expected = pair['files']['child.exe']
    require(expected == pair['files']['parent.exe'] and
            title_inputs.get('fixture_child_sha256') == expected['sha256'],
            'title input differs from the validated same-byte original fixture')
    result = compiled_identity(image, expected['sha256'])
    # Require a standalone C string, not a suffix of another diagnostic string.
    for address in result['addresses']:
        offset = image.offset(address, 65, 4)
        require(any(p[0] == 1 and p[3] == address for p in image.programs) or
                (offset > 0 and image.data[offset - 1] == 0), 'fixture hash is not a standalone title literal')
    return result


def check_title(args):
    out = output_directory(args.out, (args.app, args.build, args.service_work, args.sdk, args.runtime, args.fixture))
    commands = Commands(out / 'inspection')
    manifest, paths = verify_child(args, commands)
    root, sdk, foundation, runtime, bindir, title = paths
    app, build = args.app.resolve(strict=True), args.build.resolve(strict=True)
    title_inputs = json.loads((build / 'wine-child-title-inputs.json').read_text())
    from prepare_windows_child_prefix import validate_pair
    pair = validate_pair(args.fixture.resolve(strict=True), manifest['project'])
    require(pair['source_sha256'] == sha(root / 'tests/fixtures/windows_child_process.c') and
            pair['recipe_sha256'] == sha(root / 'tools/build_windows_child_fixture.ps1'), 'title fixture source/recipe differs')
    fixture_sha = pair['files']['child.exe']['sha256']
    require(title_inputs == {'schema': 'pw-windows-child-title-inputs/1', 'project': manifest['project'],
            'mode': 1, 'define': 'PW_WINE_CHILD_FIXTURE_MODE=1', 'fixture_child_sha256': fixture_sha, 'build_script_sha256': sha(root / 'tools/build_native.sh'),
            'service_manifest_sha256': sha(args.service_work / 'native-wine-child-build.json')},
            'title fixture macro/source input record differs')
    # Retain actual bytes before parser/analyzer refusal for independent review.
    for name, original in (('title.linked.elf', build / 'llvm-pie.elf'), ('title.converted.elf', build / 'eboot.elf'),
                            ('title.self', app / 'eboot.bin')):
        shutil.copyfile(original, out / name)
    for name in ('native-wine-child.self', 'native-wine-child-build.json'):
        require((app / name).read_bytes() == (args.service_work / name).read_bytes(), 'packaged child differs: ' + name)
    require(record(app / 'sce_module/libc.prx') == manifest['libc_companion'], 'title/child libc companions differ')
    linked, converted = Elf((build / 'llvm-pie.elf').read_bytes()), Elf((build / 'eboot.elf').read_bytes())
    index = index_sdk_providers(sdk, out, bindir, commands)
    for path in sorted((build / 'import-stubs').glob('*.so')):
        item = provider(path, bindir, commands)
        require(item['soname'] not in index, 'duplicate title provider')
        index[item['soname']] = path
    require(all(name in index for name in linked.needed), 'title provider unavailable')
    providers = {name: provider(index[name], bindir, commands) for name in linked.needed}
    require(not any(n.split('.', 1)[0] in {'libkernel_sys', 'libkernel_web', 'libScePosixForWebKit'} for n in linked.needed),
            'title uses forbidden provider')
    graph = inspect_bindings(linked, converted, providers, SERVICE_CALLS)
    recovered = extract_self((app / 'eboot.bin').read_bytes())
    recovered_path = out / 'title.recovered.elf'; recovered_path.write_bytes(recovered)
    reconstruction = verify_reconstruction(build / 'eboot.elf', recovered_path)
    image = Elf(recovered)
    compiled = compiled_identity(image, manifest['project']['commit'])
    fixture_identity = fixture_title_identity(image, title_inputs, pair)
    embedded = embedded_image(image, (app / 'native-wine-child.self').read_bytes())
    route = check_route(linked, image, commands.run(bindir / 'llvm-readelf', '-sW', build / 'llvm-pie.elf'))
    sdk_source = source_archive(args.sdk_source_archive)
    for name in linked.needed:
        destination = out / 'providers' / (name + '.elf')
        destination.parent.mkdir(exist_ok=True)
        shutil.copyfile(index[name], destination)
    files = {}
    for path in sorted(app.rglob('*')):
        require(not path.is_symlink(), 'title contains symlink')
        if path.is_file():
            name = path.relative_to(app).as_posix()
            require(name != 'dev.conf', 'private dev.conf must never be packaged')
            files[name] = {**record(path), 'mode': path.stat().st_mode & 0o777}
    require(source_identity(root, commands)[0] == manifest['project'], 'project changed during title inspection')
    require(validate_pair(args.fixture.resolve(strict=True), manifest['project']) == pair, 'original fixture changed during title inspection')
    report = {'schema': 'pw-windows-child-title/1', 'project': manifest['project'],
              'build_id': manifest['project']['commit'], 'compiler': manifest['host_llvm'],
              'sdk_headers': manifest['sdk_headers'], 'sdk_wrappers': manifest['sdk_wrappers'], 'sdk_source': sdk_source,
              'files': files, 'title_compiled_identity': compiled, 'embedded_child': embedded,
              'fixture_route': route, 'build_inputs': title_inputs,
              'fixture_child_sha256': fixture_sha, 'fixture_child_identity': fixture_identity,
              'service_manifest_sha256': sha(args.service_work / 'native-wine-child-build.json'),
              'runtime': manifest['runtime'], 'imports': graph, 'reconstruction': reconstruction,
              'console_execution_verified': False, 'scope': 'matched source/build/static import and image identity only'}
    (out / 'native-wine-child-title.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, default=ROOT)
    parser.add_argument('--check-title', action='store_true')
    for name in ('sdk', 'foundation', 'runtime', 'out', 'llvm-bindir'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('build', 'app', 'service-work', 'sdk-source-archive', 'fixture'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    if args.check_title:
        require(all((args.build, args.app, args.service_work, args.sdk_source_archive, args.fixture)), 'title check requires title/child/SDK source inputs')
        result = check_title(args)
        print(json.dumps({'build_id': result['build_id'], 'scope': result['scope']}))
    else:
        result = build(args)
        print(json.dumps({'build_id': result['worker']['build_id'], 'worker': result['worker'], 'scope': 'static build only'}))


if __name__ == '__main__':
    main()
