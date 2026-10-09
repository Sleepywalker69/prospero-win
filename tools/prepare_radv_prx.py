#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Restore one verified RADV producer layout and package its separate PRX gate."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import zipfile

sys.dont_write_bytecode = True
from package_diagnostic_kit import archive, copy_owned_tree, git, repository, require, sha

ROOT = Path(__file__).resolve().parents[1]
RUN = 37867691558
HEAD = 'ab48410ea5b74e812e9276a908f84ae9ee2aa950'
PROJECT = 'ad48a6b3558b5eee96e7df75e477660c528cd3a0'
TREE = 'cede1918ae7e0cba67b555d58026aa3bd73cbf11'
ARTIFACT = 11589485912
ZIP_SHA = '130d03969a4f5ed4ff054db570cc61ca59133259dd295d7930626c3d7f0f6df8'
ARCHIVE_SHA = 'f347c9955cf93d10886ab0751b99f49d7f4bc48fbcd33f43bc22ca13667863d9'
VULKAN = '50daad6104db5072a2f3c95283d604d21684f0c2'
MESA = '9d3cd417ff488bd1a7cc68c1f1c8e1df409c2a11'
PAYLOAD = '95c08f27386fc698f6bbe21dde3030140a41d10b'
FOUNDATION = '30597512539e7edfde079cbcaf4a626bc0a948c5'
ZLIB_SHA = 'bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
MEMBER = 'radv-archive-prerequisite.tar.gz'
LINK_INPUTS = ('tools/link_radv_prx.sh', 'tools/gen_prx_descriptor.py',
               'wine/ps5/pw_vulkan_radv.c', 'wine/ps5/prx_eh_frame.ld',
               'wine/ps5/pw_wine_prx.h', 'wine/ps5/pw_radv_mkstemp.c')


def snapshot_consumer(work, repo):
    require(not git(ROOT, 'status', '--porcelain'), 'consumer source checkout is dirty')
    value = {'repository': repository(repo), 'commit': git(ROOT, 'rev-parse', 'HEAD'),
             'tree': git(ROOT, 'rev-parse', 'HEAD^{tree}'),
             'link_inputs': {name: sha(ROOT / name) for name in LINK_INPUTS}}
    archive(ROOT, work / 'consumer-source.tar.gz')
    value['source_archive_sha256'] = sha(work / 'consumer-source.tar.gz')
    return value


def verify_consumer(work):
    value = json.loads((work / 'INPUTS-VERIFIED.json').read_text())['link_consumer']
    require(not git(ROOT, 'status', '--porcelain') and
            git(ROOT, 'rev-parse', 'HEAD') == value['commit'] and
            git(ROOT, 'rev-parse', 'HEAD^{tree}') == value['tree'], 'link consumer identity changed')
    require(set(value['link_inputs']) == set(LINK_INPUTS) and
            all(sha(ROOT / name) == value['link_inputs'][name] for name in LINK_INPUTS),
            'link consumer source bytes changed')
    require(sha(work / 'consumer-source.tar.gz') == value['source_archive_sha256'],
            'link consumer source archive changed')
    return value


def relative(name):
    require(name and '\\' not in name and not any(ord(c) < 32 for c in name), 'invalid relative name')
    value = PurePosixPath(name)
    require(not value.is_absolute() and '..' not in value.parts, 'unsafe archive path')
    return value


def unpack_tar(path, out, commit=None):
    require(not out.exists(), 'extraction output already exists')
    out.mkdir(parents=True)
    with tarfile.open(path, 'r:*') as archive_file:
        if commit:
            require(archive_file.pax_headers.get('comment') == commit, 'source archive commit differs')
        entries = archive_file.getmembers()
        require(len(entries) <= 50000 and sum(x.size for x in entries) <= 4 << 30, 'oversized archive')
        names = set()
        for entry in entries:
            if entry.name.rstrip('/') in ('.', ''):
                require(entry.isdir(), 'invalid archive root'); continue
            name = str(relative(entry.name.rstrip('/')))
            require(name not in names, 'duplicate archive path'); names.add(name)
            require(entry.isfile() or entry.isdir() or entry.issym(), 'special/hardlink archive entry')
            require(0 <= entry.size <= 512 << 20 and not entry.mode & 0o7000, 'invalid member size/mode')
        archive_file.extractall(out, filter='data')
    for path in out.rglob('*'):
        if path.is_symlink():
            require(path.resolve(strict=True).is_relative_to(out.resolve()), 'extracted symlink escapes root')


def verify_checksums(root):
    files = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    checked = set()
    for line in (root / 'SHA256SUMS').read_text().splitlines():
        require(re.match(r'^[0-9a-f]{64}  ', line), 'invalid checksum line')
        digest, name = line.split('  ', 1)
        name = str(relative(name)); path = root / name
        require(name not in checked and path.resolve(strict=True).is_relative_to(root.resolve()), 'checksum duplicate/escape')
        require(sha(path) == digest, 'input checksum differs: ' + name); checked.add(name)
    require(checked == files - {'SHA256SUMS'}, 'input checksum coverage differs')


def metadata(run, item):
    require(run.get('id') == RUN and run.get('head_sha') == HEAD and run.get('run_attempt') == 1 and
            run.get('status') == 'completed' and run.get('conclusion') == 'success' and
            run.get('path') == '.github/workflows/radv-archive.yml' and
            run.get('repository', {}).get('full_name') == 'Sleepywalker69/prospero-win', 'wrong RADV producer run')
    require(item.get('id') == ARTIFACT and item.get('digest') == 'sha256:' + ZIP_SHA and
            not item.get('expired', True) and item.get('workflow_run', {}).get('id') == RUN and
            item.get('workflow_run', {}).get('head_sha') == HEAD and
            item.get('workflow_run', {}).get('repository_id') == 1410835302 and
            item.get('workflow_run', {}).get('head_repository_id') == 1410835302, 'wrong/expired RADV artifact')


def prepare(args):
    metadata(json.loads(args.run_json.read_text()), json.loads(args.artifact_json.read_text()))
    require(sha(args.zip) == ZIP_SHA and not args.work.exists(), 'artifact hash differs or work exists')
    args.work.mkdir(parents=True)
    tar_path = args.work / 'input.tar.gz'
    with zipfile.ZipFile(args.zip) as zipped:
        items = zipped.infolist()
        require(len(items) == 1 and items[0].filename == MEMBER and items[0].file_size <= 4 << 30,
                'unexpected input ZIP layout')
        with zipped.open(items[0]) as source, tar_path.open('xb') as out:
            shutil.copyfileobj(source, out, 1 << 20)
    inputs = args.work / 'inputs'
    unpack_tar(tar_path, inputs); verify_checksums(inputs)
    manifest = json.loads((inputs / 'MANIFEST.json').read_text())
    require(manifest['schema'] == 'pw-radv-prerequisite/1' and manifest['scope'] == 'archive' and
            manifest['project'] == {'repository': 'https://github.com/Sleepywalker69/prospero-win',
                                    'commit': PROJECT, 'tree': TREE}, 'wrong RADV project identity')
    for key, commit in (('vulkan', VULKAN), ('mesa', MESA), ('payload', PAYLOAD),
                        ('sdk', '4eb701204fc3f8d31e84cf8ca272974e2be9c867')):
        require(manifest['sources'][key]['commit'] == commit, 'RADV source pin differs: ' + key)
    require(manifest['archive']['sha256'] == ARCHIVE_SHA and
            sha(inputs / 'producer/radv-release/lib/libvulkan_radeon.ps5.a') == ARCHIVE_SHA,
            'actual RADV archive differs')
    require(sha(inputs / 'sources/zlib-1.3.2.tar.gz') == ZLIB_SHA, 'converter zlib source differs')
    radv = args.work / 'radv'
    unpack_tar(inputs / 'producer/vulkan-source.tar', radv, VULKAN)
    unpack_tar(inputs / 'sources/prospero-win.tar.gz', args.work / 'link-project', PROJECT)
    (radv / '.deps/native').mkdir(parents=True)
    copy_owned_tree(inputs / 'producer/ps5-payload-sdk', radv / '.deps/native/ps5-payload-sdk')
    copy_owned_tree(inputs / 'producer/radv-release', radv / '.deps/native/radv-release')
    require((radv / '.deps/native/ps5-payload-sdk/.ps5-sdk-revision').read_text().strip() == PAYLOAD,
            'restored SDK identity differs')
    # The immutable archive remains the baseline. The reviewed local link
    # repair executes from this checkout, with its own exact source identity.
    for name in LINK_INPUTS[1:-1]:
        require(sha(ROOT / name) == sha(args.work / 'link-project' / name),
                'unrelated runtime link input changed: ' + name)
    consumer = snapshot_consumer(args.work, args.repository)
    (args.work / 'INPUTS-VERIFIED.json').write_text(json.dumps({
        'run': RUN, 'head': HEAD, 'artifact': ARTIFACT, 'zip_sha256': ZIP_SHA,
        'archive_sha256': ARCHIVE_SHA, 'producer_project': manifest['project'],
        'link_consumer': consumer, 'link_recipe_scope': 'reviewed consumer mkstemp repair over immutable producer inputs',
        'layout_restored_from': {'radv_source': 'producer/vulkan-source.tar',
                                 'sdk': 'producer/ps5-payload-sdk', 'archive': 'producer/radv-release'},
        'old_absolute_paths_are_descriptive_only': True}, indent=2) + '\n')


def verify_checked_graph(work, checks):
    require(checks.get('schema') == 'pw-radv-prx-check/1', 'wrong driver check schema')
    module = checks['module']
    for name, key in (('prx/sce_module/libvulkan.prx', 'prx_sha256'),
                      ('prx/libvulkan.shared.elf', 'shared_sha256'),
                      ('prx/radv/libvulkan.elf', 'converted_sha256'),
                      ('inspection/libvulkan.extracted.elf', 'extracted_sha256')):
        path = work / name
        require(path.resolve(strict=True).is_relative_to(work.resolve()) and sha(path) == module[key],
                'checked driver graph changed: ' + name)
    roots = [(work / 'radv/.deps/native/ps5-payload-sdk/target/lib').resolve(),
             (work / 'prx/radv/stubs').resolve()]
    for entry in [*module['providers'].values(), *module['gpu_stubs'].values()]:
        path = Path(entry['file']).resolve(strict=True)
        require(any(path.is_relative_to(root) for root in roots) and sha(path) == entry['sha256'],
                'checked import provider/stub changed: ' + str(path))


def collect_failure(args):
    require(not args.out.exists(), 'failure output already exists')
    args.out.mkdir(parents=True)
    records = {'scope': 'failed build inputs; not an accepted driver', 'files': {}, 'omitted': []}
    total = 0
    def retain(path, name):
        nonlocal total
        if not path.is_file():
            return
        size = path.stat().st_size
        if not path.resolve().is_relative_to(args.work.resolve()) or size > 512 << 20 or total + size > 2 << 30:
            records['omitted'].append({'file': name, 'reason': 'outside owned work or bounded retention size'})
            return
        target = args.out / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target); total += size
        records['files'][name] = {'sha256': sha(target), 'bytes': size}
    for name in ('prx/libvulkan.shared.elf', 'prx/radv/libvulkan.elf', 'prx/sce_module/libvulkan.prx',
                 'prx/radv/stubs/libSceAgc.so', 'prx/radv/stubs/libSceAgcDriver.so',
                 'inspection/libvulkan.extracted.elf', 'INPUTS-VERIFIED.json', 'TOOLCHAIN.txt'):
        retain(args.work / name, name)
    for path in (args.work / 'prx/radv/obj').glob('*'):
        if path.suffix in ('.o', '.c'):
            retain(path, str(path.relative_to(args.work)))
    if (args.work / 'INPUTS-VERIFIED.json').is_file():
        for folder in ('sources', 'LICENSES'):
            for path in (args.work / 'inputs' / folder).rglob('*'):
                if path.is_file():
                    if path.name == 'ps5-payload-sdk.zip':
                        records['omitted'].append({'file': 'sources/' + path.name,
                            'reason': 'binary SDK is bound in the accepted input artifact; matching SDK source archives retained'})
                        continue
                    retain(path, str(path.relative_to(args.work / 'inputs')))
    if (args.work / 'consumer-source.tar.gz').is_file():
        retain(args.work / 'consumer-source.tar.gz', 'sources/driver-consumer.tar.gz')
    else:
        archive(ROOT, args.out / 'sources/driver-consumer.tar.gz')
    for name in ('LICENSE', 'NOTICE.md', 'THIRD_PARTY.md'):
        shutil.copy2(ROOT / name, args.out / name)
    if args.foundation and (args.foundation / '.git').exists():
        archive(args.foundation, args.out / 'sources/prx-foundation.tar.gz')
    for path in (args.out / 'sources').glob('*.tar.gz'):
        records['files'][str(path.relative_to(args.out))] = {'sha256': sha(path), 'bytes': path.stat().st_size}
    (args.out / 'FAILURE-INPUTS.json').write_text(json.dumps(records, indent=2, sort_keys=True) + '\n')


def package(args):
    require(not args.out.exists(), 'package output already exists')
    consumer = verify_consumer(args.work)
    checks = json.loads((args.work / 'inspection/CHECKS.json').read_text())
    verify_checked_graph(args.work, checks)
    require(git(args.foundation, 'rev-parse', 'HEAD') == FOUNDATION, 'converter source pin differs')
    require(not git(ROOT, 'status', '--porcelain'), 'consumer source checkout is dirty')
    out = args.out; out.mkdir(parents=True)
    copy_owned_tree(args.work / 'prx', out / 'driver')
    (out / 'driver/sce_module/libvulkan.prx').chmod(0o755)
    copy_owned_tree(args.work / 'inspection', out / 'inspection')
    copy_owned_tree(args.work / 'inputs/sources', out / 'sources')
    copy_owned_tree(args.work / 'inputs/LICENSES', out / 'LICENSES')
    archive(args.foundation, out / 'sources/prx-foundation.tar.gz')
    shutil.copy2(args.work / 'consumer-source.tar.gz', out / 'sources/driver-consumer.tar.gz')
    for name in ('LICENSE', 'NOTICE.md', 'THIRD_PARTY.md'):
        shutil.copy2(ROOT / name, out / name)
    shutil.copy2(ROOT / 'docs/RADV_PRX_CI.md', out / 'README.md')
    shutil.copy2(args.work / 'INPUTS-VERIFIED.json', out / 'INPUTS-VERIFIED.json')
    shutil.copy2(args.work / 'TOOLCHAIN.txt', out / 'TOOLCHAIN.txt')
    checks['packaged_prx_mode'] = '0o755'
    checks['converter_sha256'] = sha(args.foundation / 'build/host/ps5-native-tool')
    require(repository(args.repository) == consumer['repository'], 'consumer repository differs')
    checks['consumer'] = consumer
    checks['source_archive_sha256'] = {p.name: sha(p) for p in (out / 'sources').iterdir() if p.is_file()}
    (out / 'MANIFEST.json').write_text(json.dumps(checks, indent=2, sort_keys=True) + '\n')
    (out / 'SHA256SUMS').write_text(''.join(f'{sha(p)}  {p.relative_to(out).as_posix()}\n'
                                         for p in sorted(out.rglob('*')) if p.is_file() and p.name != 'SHA256SUMS'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'verify-consumer', 'package', 'failure'))
    parser.add_argument('--work', type=Path, required=True)
    for name in ('zip', 'run-json', 'artifact-json', 'foundation', 'out'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--repository')
    args = parser.parse_args(); args.work = args.work.resolve()
    if args.mode == 'prepare':
        require(all((args.zip, args.run_json, args.artifact_json, args.repository)), 'prepare inputs missing'); prepare(args)
    elif args.mode == 'verify-consumer':
        verify_consumer(args.work)
    elif args.mode == 'package':
        require(all((args.foundation, args.out, args.repository)), 'package inputs missing'); package(args)
    else:
        require(args.out, 'failure output missing'); collect_failure(args)


if __name__ == '__main__':
    main()
