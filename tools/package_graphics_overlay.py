#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Build-input and artifact contracts for the separate x64 D3D11 diagnostic."""
import argparse
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile

sys.dont_write_bytecode = True
from graphics_overlay_files import (BASE_COMMIT, BASE_TREE, DRIVER_COMMIT, DRIVER_TREE, DRIVER_DEST,
                                    DXVK, WINE, inventory, topology, read_json, require, sha, verify_base,
                                    verify_overlay)
from prepare_radv_prx import unpack_tar, verify_checksums
from package_diagnostic_kit import archive, copy_owned_tree, git, repository
from check_wine_prx_build import Commands, MODULES
from check_radv_prx import graphics_elf, inspect_link
from inspect_graphics_pe import Image, verify_graph

ROOT = Path(__file__).resolve().parents[1]
REPO = 'Sleepywalker69/prospero-win'
INPUTS = {
    'kit': {'run': 37861508535, 'head': '5319496afdd0b6db4a6f742633b9d4e77d959547',
            'artifact': 11588549010, 'sha256': 'fcdbc6b853150618df471dac460744e40aab83dd7c0289963afa9ac0067a6cc0',
            'member': 'prospero-software-gdi-diagnostic.tar.gz', 'workflow': '.github/workflows/diagnostic-kit.yml'},
    'driver': {'run': 37877727299, 'head': 'b8763a6cd27540b51b6bb3ebace10054920bbc27',
               'artifact': 11592264803, 'sha256': 'f7bb11abf687c57b024a3490d9c7b26a6a2be4f3300a09d3a7ea2340d4a0e260',
               'member': 'radv-driver-link-checked.tar.gz', 'workflow': '.github/workflows/radv-prx.yml'},
}
DRIVER_MANIFEST_SHA = '364f4bda59a3121c05ef1fe4533923a2fb7783dd87d0944c513024d13e39f064'
SDK_SHA = '8cfbc7cd5811e719eb4f0c47eea668d3dc7b40bc8ab11c4a5031d40c23ec02da'
DRIVER_SHA = '341318d3d89ddc78c56abd5666495e90ae44dbe6edfbdea7161c4446569d0183'
SOURCES = {
    'dxvk': ('https://github.com/doitsujin/dxvk.git', DXVK, ''),
    'vulkan-headers': ('https://github.com/KhronosGroup/Vulkan-Headers.git', '234c4b7370a8ea3239a214c9e871e4b17c89f4ab', 'include/vulkan'),
    'spirv-headers': ('https://github.com/KhronosGroup/SPIRV-Headers.git', '8b246ff75c6615ba4532fe4fde20f1be090c3764', 'include/spirv'),
    'display-info': ('https://github.com/doitsujin/libdisplay-info.git', '275e6459c7ab1ddd4b125f28d0440716e4888078', 'subprojects/libdisplay-info'),
    'directx-headers': ('https://github.com/Joshua-Ashton/mingw-directx-headers.git', '9df86f2341616ef1888ae59919feaa6d4fad693d', 'include/native/directx'),
}
REQUIRED = {'d3d11.dll': {'D3D11CreateDevice', 'D3D11CreateDeviceAndSwapChain'},
            'dxgi.dll': {'CreateDXGIFactory', 'CreateDXGIFactory1', 'CreateDXGIFactory2'}}


def metadata(kind, run, item):
    fixed = INPUTS[kind]
    require(run.get('id') == fixed['run'] and run.get('head_sha') == fixed['head'] and
            run.get('run_attempt') == 1 and run.get('status') == 'completed' and
            run.get('conclusion') == 'success' and run.get('path') == fixed['workflow'] and
            run.get('repository', {}).get('full_name') == REPO, 'wrong graphics input run: ' + kind)
    require(item.get('id') == fixed['artifact'] and item.get('digest') == 'sha256:' + fixed['sha256'] and
            not item.get('expired', True) and item.get('workflow_run', {}).get('id') == fixed['run'] and
            item.get('workflow_run', {}).get('head_sha') == fixed['head'] and
            item.get('workflow_run', {}).get('repository_id') == 1410835302 and
            item.get('workflow_run', {}).get('head_repository_id') == 1410835302,
            'wrong/expired graphics input artifact: ' + kind)


def unpack_zip(path, output, fixed):
    require(sha(path) == fixed['sha256'], 'graphics input ZIP checksum differs')
    tar_path = output.parent / (output.name + '.tar.gz')
    require(not output.exists() and not tar_path.exists(), 'input extraction already exists')
    with zipfile.ZipFile(path) as zipped:
        items = zipped.infolist()
        require(len(items) == 1 and items[0].filename == fixed['member'] and
                0 < items[0].file_size <= 4 << 30, 'unexpected input ZIP layout')
        with zipped.open(items[0]) as source, tar_path.open('xb') as target:
            shutil.copyfileobj(source, target, 1 << 20)
    unpack_tar(tar_path, output)
    verify_checksums(output)


def restore_system_stubs(driver, sdk):
    source = driver / 'sources/ps5-payload-sdk.zip'
    require(sha(source) == SDK_SHA and not sdk.exists(), 'wrong SDK archive or existing stub directory')
    target = sdk / 'target/lib'; target.mkdir(parents=True)
    count = total = 0
    with zipfile.ZipFile(source) as zipped:
        for entry in zipped.infolist():
            match = re.fullmatch(r'ps5-payload-sdk/target/lib/([A-Za-z0-9_.+-]+\.so)', entry.filename)
            if not match:
                continue
            mode = entry.external_attr >> 16
            require(not stat.S_ISLNK(mode) and entry.file_size <= 128 << 20, 'invalid SDK stub entry')
            total += entry.file_size; count += 1
            require(total <= 128 << 20 and count <= 1024, 'oversized SDK stub set')
            path = target / match[1]
            require(not path.exists(), 'duplicate SDK stub')
            with zipped.open(entry) as src, path.open('xb') as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
    require(count, 'no public SDK providers restored')


def verify_driver_files(driver):
    require(sha(driver / 'MANIFEST.json') == DRIVER_MANIFEST_SHA, 'driver inspection manifest changed')
    value = read_json(driver / 'MANIFEST.json')
    require(value.get('schema') == 'pw-radv-prx-check/1' and value.get('runtime_verified') is False and
            value.get('consumer', {}).get('commit') == DRIVER_COMMIT and
            value['consumer']['tree'] == DRIVER_TREE and value['module']['prx_sha256'] == DRIVER_SHA,
            'driver source/artifact identity differs')
    module = value['module']
    for name, key in [('driver/sce_module/libvulkan.prx', 'prx_sha256'),
                      ('driver/libvulkan.shared.elf', 'shared_sha256'),
                      ('driver/radv/libvulkan.elf', 'converted_sha256'),
                      ('inspection/libvulkan.extracted.elf', 'extracted_sha256')]:
        require(sha(driver / name) == module[key], 'checked driver binary differs: ' + name)
    require(stat.S_IMODE((driver / 'driver/sce_module/libvulkan.prx').stat().st_mode) == 0o755,
            'checked driver is not executable mode0755')
    graphics_elf(driver / 'driver/radv/libvulkan.elf', 0xfe18)
    graphics_elf(driver / 'inspection/libvulkan.extracted.elf', 0xfe18)
    return value


def verify_driver(driver, sdk, bindir, output):
    value = verify_driver_files(driver)
    module = value['module']
    # Accepted outer hash binds the original SELF inspection. Reinspect actual
    # ELF/provider bytes with fresh paths; never reinterpret old absolute paths.
    actual = inspect_link(driver / 'driver', sdk, bindir, Commands(output))
    for field in ('needed', 'imports', 'shared_sha256', 'required_export_types', 'system_data_imports'):
        require(actual[field] == module[field], 'driver graph differs: ' + field)
    for field in ('providers', 'gpu_stubs'):
        require(set(actual[field]) == set(module[field]) and
                all(actual[field][name]['sha256'] == module[field][name]['sha256'] for name in actual[field]),
                'restored driver providers differ')
    require(set(actual['needed']) == {'libSceAgc.prx', 'libSceAgcDriver.prx',
                                     'libSceLibcInternal.sprx', 'libSceVideoOut.sprx', 'libkernel.sprx'},
            'unexpected graphics provider graph')
    graphics_elf(driver / 'driver/radv/libvulkan.elf', 0xfe18)
    graphics_elf(driver / 'inspection/libvulkan.extracted.elf', 0xfe18)
    return actual


def verify_wine_graph(kit):
    report = read_json(kit / 'provenance/wine-report.json')
    require(report.get('wine_commit') == WINE and not report.get('errors') and
            report['prx']['status'] == '0' and set(report['prx']['modules']) == set(MODULES),
            'base Wine PRX report differs')
    directory = kit / 'PPSA99995/win/wine/lib/wine/x86_64-unix'
    require({p.stem for p in directory.glob('*.prx')} == set(MODULES) | {'wow64native'},
            'base runtime module membership differs')
    for name, entry in report['prx']['modules'].items():
        require(entry['built'] and not entry['unresolved'] and not entry['errors'] and
                sha(directory / (name + '.prx')) == entry['sha256'], 'base PRX bytes/status differ')
    require(report['prx']['modules']['winevulkan']['needed'] ==
            ['ntdll.prx', 'win32u.prx', 'libSceLibcInternal.sprx'], 'Wine Vulkan provider graph differs')
    for name, digest in report['pe'].items():
        require(sha(kit / 'PPSA99995/win/wine/lib/wine' / name) == digest, 'patched Wine PE changed')
    return {'wine_commit': WINE, 'modules': report['prx']['modules'], 'patched_pe': report['pe']}


def prepare(args):
    require(not args.work.exists(), 'work directory already exists')
    args.work.mkdir(parents=True)
    for kind in INPUTS:
        metadata(kind, read_json(args.inputs / (kind + '-run.json')), read_json(args.inputs / (kind + '-artifact.json')))
        unpack_zip(args.inputs / (kind + '.zip'), args.work / kind, INPUTS[kind])
    verify_base(args.work / 'kit')
    wine = verify_wine_graph(args.work / 'kit')
    restore_system_stubs(args.work / 'driver', args.work / 'sdk')
    driver = verify_driver(args.work / 'driver', args.work / 'sdk', args.llvm_bindir, args.work / 'driver-inspection')
    (args.work / 'INPUTS-VERIFIED.json').write_text(json.dumps({'inputs': INPUTS, 'wine': wine, 'driver': driver}, indent=2) + '\n')


RUNTIME_PACKAGES = ('gcc-mingw-w64-base', 'gcc-mingw-w64-x86-64-posix',
                    'g++-mingw-w64-x86-64-posix', 'mingw-w64-common', 'mingw-w64-x86-64-dev')
COMMON_LICENSES = ('GPL-2', 'GPL-3', 'LGPL-2', 'LGPL-2.1', 'LGPL-3')
RUNTIME_LIBRARIES = ('dllcrt2.o', 'crt2.o', 'libmingw32.a', 'libmingwex.a',
                     'libgcc.a', 'libgcc_eh.a', 'libstdc++.a', 'libwinpthread.a')


def collect_runtime_notices(sources, doc_root=Path('/usr/share/doc'), license_root=Path('/usr/share/common-licenses')):
    folder = sources / 'compiler-runtime'; folder.mkdir()
    records = {'scope': 'installed compiler/runtime source-package identities and distribution notices; compiler executables are not shipped',
               'packages': {}, 'libraries': {}, 'common_licenses': {}}
    for name in RUNTIME_PACKAGES:
        text = subprocess.check_output(['dpkg-query', '-W', '-f',
                                        '${Package}\t${Version}\t${source:Package}\t${source:Version}\n', name], text=True).strip()
        fields = text.split('\t'); require(len(fields) == 4 and all(fields), 'incomplete runtime package identity')
        notice = doc_root / name / 'copyright'
        require(notice.is_file(), 'missing installed runtime copyright: ' + name)
        target = folder / (name + '-copyright'); shutil.copy2(notice, target)
        records['packages'][name] = {'package': fields[0], 'version': fields[1],
                                    'source_package': fields[2], 'source_version': fields[3],
                                    'notice': target.name, 'sha256': sha(target)}
    for name in COMMON_LICENSES:
        source = license_root / name
        require(source.is_file(), 'missing full runtime licence text: ' + name)
        shutil.copy2(source, folder / name)
        records['common_licenses'][name] = sha(folder / name)
    for name in RUNTIME_LIBRARIES:
        path = Path(subprocess.check_output(['x86_64-w64-mingw32-g++-posix', '-print-file-name=' + name], text=True).strip())
        require(path.is_absolute() and path.is_file(), 'selected compiler runtime library is missing: ' + name)
        records['libraries'][name] = {'file': str(path.resolve()), 'sha256': sha(path)}
    (folder / 'RUNTIME-PROVENANCE.json').write_text(json.dumps(records, indent=2) + '\n')


def verify_runtime_notices(sources, doc_root=Path('/usr/share/doc'), license_root=Path('/usr/share/common-licenses')):
    folder = sources / 'compiler-runtime'; value = read_json(folder / 'RUNTIME-PROVENANCE.json')
    require(set(value['packages']) == set(RUNTIME_PACKAGES) and set(value['libraries']) == set(RUNTIME_LIBRARIES) and
            set(value['common_licenses']) == set(COMMON_LICENSES),
            'compiler/runtime provenance membership differs')
    for name, entry in value['packages'].items():
        require(entry['notice'] == name + '-copyright' and
                sha(folder / entry['notice']) == entry['sha256'] == sha(doc_root / name / 'copyright'),
                'compiler/runtime notice changed')
    for name, digest in value['common_licenses'].items():
        require(sha(folder / name) == digest == sha(license_root / name), 'full runtime licence text changed')
    for name, entry in value['libraries'].items():
        current = Path(subprocess.check_output(['x86_64-w64-mingw32-g++-posix', '-print-file-name=' + name], text=True).strip())
        require(str(current.resolve()) == entry['file'] and sha(current) == entry['sha256'],
                'selected compiler/runtime archive changed')
    return value


def fetch_sources(args):
    sources = args.work / 'sources'; sources.mkdir(exist_ok=False)
    source_root = args.work / 'dxvk'; records = {}
    for name, (url, pin, relative) in SOURCES.items():
        path = source_root / relative
        path.mkdir(parents=True, exist_ok=True)
        subprocess.run(['git', 'init', '--quiet', str(path)], check=True)
        subprocess.run(['git', '-C', str(path), 'remote', 'add', 'origin', url], check=True)
        subprocess.run(['git', '-C', str(path), 'fetch', '--depth=1', 'origin', pin], check=True)
        subprocess.run(['git', '-C', str(path), 'checkout', '--detach', 'FETCH_HEAD'], check=True)
        require(git(path, 'rev-parse', 'HEAD') == pin and not git(path, 'status', '--porcelain'), 'source pin/cleanliness differs')
        if relative:
            require(git(source_root, 'ls-tree', 'HEAD', relative).split()[2] == pin, 'DXVK gitlink differs')
            require(not any(line.startswith('160000 ') for line in git(path, 'ls-tree', '-r', 'HEAD').splitlines()),
                    'unrecorded nested source dependency')
        tar = sources / (name + '.tar.gz'); archive(path, tar)
        records[name] = {'url': url, 'commit': pin, 'archive': tar.name, 'sha256': sha(tar)}
    expected = {relative for _, _, relative in SOURCES.values() if relative}
    actual = {line.split('\t')[1] for line in git(source_root, 'ls-tree', '-r', 'HEAD').splitlines()
              if line.startswith('160000 ')}
    require(actual == expected, 'DXVK dependency membership differs')
    require(not git(ROOT, 'status', '--porcelain'), 'graphics consumer source is dirty')
    archive(ROOT, sources / 'graphics-consumer.tar.gz')
    records['consumer'] = {'url': repository(args.repository), 'commit': git(ROOT, 'rev-parse', 'HEAD'),
                           'tree': git(ROOT, 'rev-parse', 'HEAD^{tree}'), 'archive': 'graphics-consumer.tar.gz',
                           'sha256': sha(sources / 'graphics-consumer.tar.gz')}
    collect_runtime_notices(sources)
    (sources / 'SOURCES.json').write_text(json.dumps(records, indent=2) + '\n')


def verify_sources(work):
    verify_runtime_notices(work / 'sources')
    records = read_json(work / 'sources/SOURCES.json')
    recheck = work / 'source-recheck'; recheck.mkdir(exist_ok=True)
    require(set(records) == set(SOURCES) | {'consumer'}, 'source checkpoint membership differs')
    for name, (url, pin, relative) in SOURCES.items():
        path = work / 'dxvk' / relative
        require(records[name]['url'] == url and records[name]['commit'] == pin and
                git(path, 'rev-parse', 'HEAD') == pin and not git(path, 'status', '--porcelain'),
                'build source changed: ' + name)
        archive(path, recheck / (name + '.tar.gz'))
        require(records[name]['archive'] == name + '.tar.gz' and
                sha(work / 'sources' / records[name]['archive']) == records[name]['sha256'] ==
                sha(recheck / (name + '.tar.gz')), 'source archive changed')
    consumer = records['consumer']
    archive(ROOT, recheck / 'graphics-consumer.tar.gz')
    require(git(ROOT, 'rev-parse', 'HEAD') == consumer['commit'] and git(ROOT, 'rev-parse', 'HEAD^{tree}') == consumer['tree'] and
            not git(ROOT, 'status', '--porcelain') and
            sha(work / 'sources/graphics-consumer.tar.gz') == consumer['sha256'] ==
            sha(recheck / 'graphics-consumer.tar.gz'), 'consumer source changed')
    return records


def recipe(app):
    text = '''name: Original x64 D3D11 diagnostic
game_slug: diagnostic-d3d11
runner: wine
prospero:
  graphics: auto
  display: {desktop: 1920x1080, view: desktop, scaling: fit, show_fps: false}
script:
  game: {exe: drive_c/graphics-smoke/d3d11-clear.exe, prefix: $GAMEDIR}
  wine: {dxvk: false, overrides: {d3d11: n, dxgi: n}}
  files:
'''
    for name in ('d3d11.dll', 'dxgi.dll', 'd3d11-clear.exe'):
        text += f'  - {name}: {{url: "file://$SCRIPTDIR/../graphics-smoke/x64/{name}", filename: "{name}", sha256: "{sha(app / name)}"}}\n'
    text += '''  installer:
  - task: {name: create_prefix, prefix: $GAMEDIR, install_gecko: false, install_mono: false}
'''
    for name in ('d3d11.dll', 'dxgi.dll', 'd3d11-clear.exe'):
        text += f'  - copy: {{src: "{name}", dst: "$GAMEDIR/drive_c/graphics-smoke"}}\n'
    return text


def package(args):
    require(not args.out.exists(), 'output already exists')
    sources = verify_sources(args.work)
    verify_base(args.work / 'kit'); verify_wine_graph(args.work / 'kit')
    verify_checksums(args.work / 'driver')
    old = read_json(args.work / 'INPUTS-VERIFIED.json')
    require(old['inputs'] == INPUTS, 'input binding changed')
    # Every previously inspected native byte/provider is rebound by hash.
    require(sha(args.work / 'driver/MANIFEST.json') == DRIVER_MANIFEST_SHA, 'driver inspection manifest changed')
    driver_manifest = verify_driver_files(args.work / 'driver')
    current = driver_manifest['module']
    for name, digest in driver_manifest['source_archive_sha256'].items():
        require(re.fullmatch(r'[A-Za-z0-9_.+-]+', name) and
                sha(args.work / 'driver/sources' / name) == digest, 'driver corresponding source changed')
    for field in ('providers', 'gpu_stubs'):
        for name, entry in old['driver'][field].items():
            require(sha(Path(entry['file'])) == current[field][name]['sha256'], 'native provider changed after inspection')
    app = args.work / 'app'; require({p.name for p in app.iterdir()} == {'d3d11.dll','dxgi.dll','d3d11-clear.exe'},
                                    'unexpected application output')
    require(all(path.is_file() and not path.is_symlink() for path in app.iterdir()), 'application output must be owned regular files')
    for name in REQUIRED:
        require(Image(app / name).characteristics & 0x2000, 'DXVK output is not a DLL')
    exe = Image(app / 'd3d11-clear.exe')
    require(not exe.characteristics & 0x2000 and exe.entry and exe.executable(exe.entry), 'smoke executable entry is invalid')
    graph = verify_graph(args.work / 'kit/PPSA99995/win/wine/lib/wine/x86_64-windows', app, REQUIRED)
    args.out.mkdir(parents=True)
    payload = args.out / 'overlay'
    target = payload / DRIVER_DEST; target.parent.mkdir(parents=True); shutil.copy2(args.work / 'driver/driver/sce_module/libvulkan.prx', target)
    dest = payload / 'pc/graphics-smoke/x64'; shutil.copytree(app, dest)
    require(all(sha(dest / name) == graph['files'][name]['sha256'] for name in ('d3d11.dll','dxgi.dll','d3d11-clear.exe')),
            'copied PE bytes differ from inspected graph')
    recipes = payload / 'pc/recipes'; recipes.mkdir(); (recipes / 'diagnostic-d3d11.yml').write_text(recipe(app))
    copy_owned_tree(args.work / 'sources', args.out / 'sources/dxvk')
    copy_owned_tree(args.work / 'driver/sources', args.out / 'sources/driver')
    copy_owned_tree(args.work / 'driver/LICENSES', args.out / 'LICENSES/driver')
    copy_owned_tree(args.work / 'sources/compiler-runtime', args.out / 'LICENSES/compiler-runtime')
    for name, record in sources.items():
        require(sha(args.out / 'sources/dxvk' / record['archive']) == record['sha256'], 'copied source checkpoint changed')
    for name, digest in driver_manifest['source_archive_sha256'].items():
        require(sha(args.out / 'sources/driver' / name) == digest, 'copied driver source changed')
    for name in ('LICENSE','NOTICE.md','THIRD_PARTY.md'):
        shutil.copy2(ROOT / name, args.out / name)
    shutil.copy2(ROOT / 'tools/graphics_overlay_files.py', args.out / 'assemble_graphics_copy.py')
    for name in ('d3d11_clear_smoke.c', 'd3d11_smoke_contract.h'):
        shutil.copy2(ROOT / 'tools' / name, args.out / name)
    shutil.copy2(ROOT / 'docs/GRAPHICS_OVERLAY_CI.md', args.out / 'README-GRAPHICS.md')
    # DXVK's MIT licence and every dependency licence remain in exact source
    # archives; retain their top-level notices visibly as well.
    for name, (_, _, relative) in SOURCES.items():
        for path in (args.work / 'dxvk' / relative).iterdir():
            if path.is_file() and re.match(r'(?i)^(license|copying|copyright|notice)', path.name):
                dest = args.out / 'LICENSES' / name / path.name; dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(path, dest)
    evidence = args.out / 'provenance'; evidence.mkdir()
    for path, name in [(args.work/'INPUTS-VERIFIED.json','inputs.json'),
                       (args.work/'driver/MANIFEST.json','driver-manifest.json'),
                       (args.work/'TOOLCHAIN.txt','toolchain.txt')]: shutil.copy2(path, evidence/name)
    (evidence / 'pe-graph.json').write_text(json.dumps(graph, indent=2) + '\n')
    manifest = {'schema': 'pw-graphics-overlay/1', 'scope': 'x64-d3d11-diagnostic',
                'base_tree': BASE_TREE, 'driver_tree': DRIVER_TREE, 'dxvk_commit': DXVK,
                'producer': sources['consumer'], 'bound_inputs': INPUTS,
                'runtime_verified': False, 'prefix_included': False,
                'limitations': ['No console loading or GPU presentation measured', 'No D3D12/vkd3d-proton validation',
                                'No current Retail/Battle.net compatibility claim', 'No vendor assets or account data'],
                'topology': topology(args.out), 'files': inventory(args.out)}
    (args.out / 'GRAPHICS-MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (args.out / 'GRAPHICS-SHA256SUMS').write_text(''.join(f'{sha(path)}  {path.relative_to(args.out)}\n'
        for path in sorted(args.out.rglob('*')) if path.is_file() and path.name != 'GRAPHICS-SHA256SUMS'))
    digest = sha(args.out / 'GRAPHICS-MANIFEST.json'); verify_overlay(args.out, digest)
    print('GRAPHICS_MANIFEST_SHA256=' + digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare','sources','package'))
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--inputs', type=Path)
    parser.add_argument('--llvm-bindir', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--repository')
    args = parser.parse_args(); args.work = args.work.resolve()
    if args.mode == 'prepare':
        require(args.inputs and args.llvm_bindir, 'prepare needs input metadata/ZIPs and LLVM tools'); prepare(args)
    elif args.mode == 'sources':
        require(args.repository, 'source checkpoint needs explicit repository URL'); fetch_sources(args)
    else:
        require(args.out, 'package needs output'); package(args)


if __name__ == '__main__':
    main()
