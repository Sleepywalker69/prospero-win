#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Build-only x64 vkd3d producer from already prepared, exact public sources.

Only the sources phase fetches exact public commits. No package installation,
Wine invocation, prefix creation or PE execution.
The output is an inspectable build candidate, never a console-ready overlay.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True
from check_d3d12_frontend import inspect_candidate

ROOT = Path(__file__).resolve().parents[1]
PIN = 'c965c1351fd6915a65bb7f647319536252a24a93'
SOURCES = {
    '': ('HansKristian-Work/vkd3d-proton', PIN),
    'khronos/Vulkan-Headers': ('KhronosGroup/Vulkan-Headers', '29f979ee5aa58b7b005f805ea8df7a855c39ff37'),
    'khronos/SPIRV-Headers': ('KhronosGroup/SPIRV-Headers', '8b246ff75c6615ba4532fe4fde20f1be090c3764'),
    'subprojects/dxil-spirv': ('HansKristian-Work/dxil-spirv', '33cd5b2eee8a27da50ad7ed2762e56cca3a7b2c9'),
    'subprojects/dxil-spirv/third_party/spirv-headers': ('KhronosGroup/SPIRV-Headers', 'ec59c77a3bb5c747a369931ef101ac7c14823f2f'),
}
# These two declared gitlinks are not compiled by this pin's selected Meson
# static-library recipe. Record their exact identities without fetching them.
UNUSED_DXIL_GITLINKS = {
    'third_party/SPIRV-Tools': 'd9c1aee6a609c6d6ec1caab4def80720c44bd08d',
    'third_party/SPIRV-Cross': '476f384eb7d9e48613c45179e502a15ab95b6b49',
}
FIXTURES = {
    'd3d12_capability_query.c': 'c101938e6fbaad8d2e4c98bf880e19ab702a2a5a00506a33ac742cf22344f4d4',
    'd3d12_query_contract.h': '050b8e04e197a610c43157501a9d6e2e0d7e558673bda84a5b76bb98003e33fa',
}
PE_INSPECTOR_SHA = 'e2532a45f885634546a2990df31783f8dcfec9b691c0e43943bb7d6e845154c2'
TOOLS = ('git', 'meson', 'ninja', 'glslangValidator', 'x86_64-w64-mingw32-widl',
         'x86_64-w64-mingw32-gcc-posix', 'x86_64-w64-mingw32-g++-posix',
         'x86_64-w64-mingw32-ar', 'x86_64-w64-mingw32-strip', 'x86_64-w64-mingw32-objdump')
RUNTIME_PACKAGES = ('gcc-mingw-w64-base', 'gcc-mingw-w64-x86-64-posix',
                    'g++-mingw-w64-x86-64-posix', 'mingw-w64-common', 'mingw-w64-x86-64-dev')
RUNTIME_LIBRARIES = ('crt2.o', 'dllcrt2.o', 'libmingw32.a', 'libmingwex.a', 'libgcc.a',
                     'libgcc_eh.a', 'libstdc++.a', 'libwinpthread.a')
TOOL_ALIASES = {'x86_64-w64-mingw32-gcc': 'x86_64-w64-mingw32-gcc-posix',
                'x86_64-w64-mingw32-g++': 'x86_64-w64-mingw32-g++-posix',
                'widl': 'x86_64-w64-mingw32-widl', 'glslang': 'glslangValidator'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_inventory(folder, normalize=False):
    """Source archives/notices are data files; their outer mode is always 0644.

    Original executable/source modes remain inside each Git archive. Refuse
    links and special files; do not weaken a later consumer's mode checks.
    """
    require(folder.is_dir() and not folder.is_symlink(), 'source checkpoint root must be an owned directory')
    if normalize:
        folder.chmod(0o755)
    require(stat.S_IMODE(folder.stat().st_mode) == 0o755, 'source root directory mode differs')
    records = {}
    for path in sorted(folder.rglob('*')):
        require(not path.is_symlink(), 'linked source checkpoint entry')
        if path.is_dir():
            if normalize:
                path.chmod(0o755)
            require(stat.S_IMODE(path.stat().st_mode) == 0o755, 'source directory mode differs')
            continue
        require(path.is_file(), 'nonregular source checkpoint entry')
        if normalize:
            path.chmod(0o644)
        mode = stat.S_IMODE(path.stat().st_mode)
        require(mode == 0o644, 'source data-file mode differs')
        records[str(path.relative_to(folder))] = {'sha256': sha(path), 'mode': mode}
    return records


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()


def gitlinks(path):
    return {line.split('\t')[1]: line.split()[2]
            for line in git(path, 'ls-tree', '-r', 'HEAD').splitlines() if line.startswith('160000 ')}


def verify_archive(path, archive):
    # git archive may honor export-ignore attributes. Refuse any omission of
    # tracked blobs rather than claiming complete corresponding source.
    expected = {line.split('\t')[1] for line in git(path, 'ls-tree', '-r', 'HEAD').splitlines()
                if line.split()[1] == 'blob'}
    with tarfile.open(archive) as value:
        actual = {entry.name for entry in value.getmembers() if not entry.isdir()}
        require(actual == expected, 'source archive omitted/added tracked blobs')


def verify_sources(source):
    for relative, (_, pin) in SOURCES.items():
        path = source / relative
        require(path.is_dir() and not path.is_symlink(), 'missing/linked source: ' + relative)
        require(git(path, 'rev-parse', '--show-toplevel') == str(path.resolve()), 'source is not its own checkout')
        require(git(path, 'rev-parse', 'HEAD') == pin, 'source pin differs: ' + relative)
        require(not git(path, 'status', '--porcelain', '--untracked-files=all', '--ignored'),
                'dirty/untracked/ignored source input: ' + relative)
        expected = {}
        if not relative:
            expected = {name: value[1] for name, value in SOURCES.items()
                        if name and not name.startswith('subprojects/dxil-spirv/')}
        elif relative == 'subprojects/dxil-spirv':
            expected = dict(UNUSED_DXIL_GITLINKS)
            expected['third_party/spirv-headers'] = SOURCES[relative + '/third_party/spirv-headers'][1]
        require(gitlinks(path) == expected, 'source dependency membership differs: ' + relative)
    for relative in UNUSED_DXIL_GITLINKS:
        path = source / 'subprojects/dxil-spirv' / relative
        require(not path.exists() or (path.is_dir() and not path.is_symlink() and not any(path.iterdir())),
                'unused source dependency must remain empty: ' + relative)


def commands(source, output):
    link = '-Wl,--dynamicbase,--high-entropy-va,--nxcompat,--enable-reloc-section'
    return [
        ['meson', 'setup', str(output / 'build'), str(source), '--cross-file', str(source / 'build-win64.txt'),
         '--buildtype=release', '--wrap-mode=nodownload', '--prefix=' + str(output / 'install'),
         '--bindir=x64', '--libdir=x64', '-Denable_tests=false', '-Denable_extras=false',
         '-Denable_dxilconv=false', '-Denable_renderdoc=false', '-Denable_profiling=false',
         '-Denable_descriptor_qa=false', '-Denable_trace=false',
         "-Dc_link_args=['" + link + "']", "-Dcpp_link_args=['" + link + "']"],
        ['ninja', '-C', str(output / 'build'), '-j2', 'install'],
        ['x86_64-w64-mingw32-gcc-posix', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
         '-static', '-static-libgcc', str(output / 'sources/fixture/d3d12_capability_query.c'),
         '-ld3d12', '-ldxgi', '-ldxguid', link, '-o', str(output / 'app/d3d12-capability-query.exe')],
    ]


def retain_runtime(output, compiler):
    folder = output / 'sources/compiler-runtime'; folder.mkdir()
    records = {'packages': {}, 'libraries': {}, 'scope': 'distribution notices and installed source-package identities'}
    for name in RUNTIME_PACKAGES:
        fields = subprocess.check_output(['dpkg-query', '-W', '-f',
                  '${Package}\t${Version}\t${source:Package}\t${source:Version}\n', name], text=True).strip().split('\t')
        require(len(fields) == 4 and all(fields), 'incomplete compiler/runtime package provenance')
        path = Path('/usr/share/doc') / name / 'copyright'
        require(path.is_file(), 'missing runtime notice: ' + name)
        shutil.copy2(path, folder / (name + '-copyright'))
        records['packages'][name] = {'package': fields[0], 'version': fields[1], 'source': fields[2],
                                     'source_version': fields[3], 'notice_sha256': sha(path)}
    for name in ('GPL-2', 'GPL-3', 'LGPL-2', 'LGPL-2.1', 'LGPL-3'):
        shutil.copy2(Path('/usr/share/common-licenses') / name, folder / name)
    for name in RUNTIME_LIBRARIES:
        path = Path(subprocess.check_output([compiler, '-print-file-name=' + name], text=True).strip())
        require(path.is_absolute() and path.is_file(), 'missing static compiler/runtime input: ' + name)
        records['libraries'][name] = {'path': str(path.resolve()), 'sha256': sha(path)}
    (folder / 'PROVENANCE.json').write_text(json.dumps(records, indent=2) + '\n')
    return records


def verify_fixture():
    for name, digest in FIXTURES.items():
        require(sha(ROOT / 'tests/fixtures' / name) == digest, 'sealed fixture identity changed: ' + name)
    require(sha(ROOT / 'tools/inspect_graphics_pe.py') == PE_INSPECTOR_SHA, 'PE inspector baseline changed')


def checkout_commands(path, repository, pin):
    return [['git', 'init', '--quiet', str(path)],
            ['git', '-C', str(path), 'remote', 'add', 'origin', 'https://github.com/' + repository + '.git'],
            ['git', '-C', str(path), 'fetch', '--depth=1', 'origin', pin],
            ['git', '-C', str(path), 'checkout', '--detach', 'FETCH_HEAD']]


def prepare(work, repository):
    work = work.resolve()
    require(not work.exists() and work != ROOT and ROOT not in work.parents and work not in ROOT.parents,
            'work must be a new directory outside the project source')
    require(re.fullmatch(r'https://github\.com/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', repository),
            'project repository must be a public HTTPS GitHub owner/repository URL')
    verify_fixture()
    require(not git(ROOT, 'status', '--porcelain'), 'project checkout is dirty')
    selected = {name: shutil.which(name) for name in TOOLS}
    require(all(selected.values()), 'missing build prerequisites: ' + ', '.join(name for name, path in selected.items() if not path))
    work.mkdir(parents=True)
    for name in ('sources', 'logs'):
        (work / name).mkdir()
    source = work / 'vkd3d'
    source_records = {}
    for index, (relative, (repo, pin)) in enumerate(SOURCES.items()):
        path = source / relative
        require(not path.exists() or (path.is_dir() and not path.is_symlink() and not any(path.iterdir())),
                'source checkout path already contains files')
        path.mkdir(parents=True, exist_ok=True)
        with (work / 'logs' / ('fetch-' + str(index) + '.log')).open('wb') as log:
            for argv in checkout_commands(path, repo, pin):
                subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=600)
        require(git(path, 'rev-parse', 'HEAD') == pin and not git(path, 'status', '--porcelain'), 'fetched source differs')
        archive = work / 'sources' / ('upstream-' + str(index) + '.tar')
        subprocess.run(['git', '-C', str(path), 'archive', '--format=tar', '--output=' + str(archive), 'HEAD'], check=True)
        verify_archive(path, archive)
        source_records[relative] = {'repository': 'https://github.com/' + repo, 'commit': pin,
                                    'archive': archive.name, 'sha256': sha(archive)}
    verify_sources(source)
    archive = work / 'sources/project.tar'
    subprocess.run(['git', '-C', str(ROOT), 'archive', '--format=tar', '--output=' + str(archive), 'HEAD'], check=True)
    verify_archive(ROOT, archive)
    project = {'repository': repository, 'commit': git(ROOT, 'rev-parse', 'HEAD'),
               'tree': git(ROOT, 'rev-parse', 'HEAD^{tree}'), 'archive': archive.name, 'sha256': sha(archive)}
    # The full Git archive retains project source and notices; retain the exact
    # compilable fixture separately too for a simple source-to-link record.
    fixture = work / 'sources/fixture'; fixture.mkdir()
    for name in FIXTURES:
        shutil.copy2(ROOT / 'tests/fixtures' / name, fixture / name)
    for name in ('LICENSE', 'NOTICE.md', 'THIRD_PARTY.md'):
        shutil.copy2(ROOT / name, work / 'sources' / name)
    runtime = retain_runtime(work, selected['x86_64-w64-mingw32-g++-posix'])
    tools = {name: {'path': str(Path(path).resolve()), 'sha256': sha(Path(path).resolve())} for name, path in selected.items()}
    with (work / 'logs/distribution-package-versions.txt').open('wb') as log:
        subprocess.run(['dpkg-query', '-W', '-f', '${Package}\t${Version}\t${source:Package}\t${source:Version}\n',
                        'meson', 'ninja-build', 'glslang-tools', 'mingw-w64-tools', 'binutils-mingw-w64-x86-64',
                        *RUNTIME_PACKAGES], stdout=log, stderr=subprocess.STDOUT, check=True)
    notices = source_inventory(work / 'sources', normalize=True)
    value = {'schema': 'pw-d3d12-source-checkpoint/1', 'project': project, 'upstream': source_records,
             'unused_gitlinks': UNUSED_DXIL_GITLINKS, 'fixture': FIXTURES, 'tools': tools,
             'runtime': runtime, 'source_files': notices, 'runtime_verified': False}
    (work / 'SOURCE-CHECKPOINT.json').write_text(json.dumps(value, indent=2) + '\n')
    return value


def verify_checkpoint(work):
    value = json.loads((work / 'SOURCE-CHECKPOINT.json').read_text())
    require(value['schema'] == 'pw-d3d12-source-checkpoint/1' and value['fixture'] == FIXTURES and
            value['unused_gitlinks'] == UNUSED_DXIL_GITLINKS and value['runtime_verified'] is False,
            'source checkpoint contract differs')
    require(set(value['upstream']) == set(SOURCES) and set(value['tools']) == set(TOOLS),
            'source/tool checkpoint membership differs')
    verify_fixture(); verify_sources(work / 'vkd3d')
    require(value['project']['commit'] == git(ROOT, 'rev-parse', 'HEAD') and
            value['project']['tree'] == git(ROOT, 'rev-parse', 'HEAD^{tree}') and
            not git(ROOT, 'status', '--porcelain'), 'project source identity changed')
    require(value['project']['archive'] == 'project.tar' and
            sha(work / 'sources/project.tar') == value['project']['sha256'], 'project source archive changed')
    actual = source_inventory(work / 'sources')
    require(actual == value['source_files'], 'retained source/notices changed')
    require(value['runtime'] == json.loads((work / 'sources/compiler-runtime/PROVENANCE.json').read_text()) and
            set(value['runtime']['libraries']) == set(RUNTIME_LIBRARIES) and
            set(value['runtime']['packages']) == set(RUNTIME_PACKAGES), 'compiler/runtime provenance differs')
    for name, digest in FIXTURES.items():
        require(sha(work / 'sources/fixture' / name) == digest, 'compiled fixture identity changed')
    for index, (relative, (repository, pin)) in enumerate(SOURCES.items()):
        record = value['upstream'][relative]
        require(record['repository'] == 'https://github.com/' + repository and record['commit'] == pin and
                record['archive'] == 'upstream-' + str(index) + '.tar' and
                sha(work / 'sources' / record['archive']) == record['sha256'], 'upstream checkpoint identity changed')
    for name, record in value['tools'].items():
        require(str(Path(shutil.which(name) or '').resolve()) == record['path'] and sha(record['path']) == record['sha256'],
                'build tool changed: ' + name)
    for name, record in value['runtime']['libraries'].items():
        require(sha(record['path']) == record['sha256'], 'compiler/runtime archive changed: ' + name)
    return value


def build_environment(work, selected):
    # Bind upstream's first compiler/IDL/GLSL lookups to recorded providers,
    # before inherited PATH entries, without changing system alternatives.
    wrappers = work / 'tools'; wrappers.mkdir()
    for name, provider in TOOL_ALIASES.items():
        (wrappers / name).symlink_to(selected[provider])
    env = dict(os.environ)
    for name in ('CC', 'CXX', 'CPP', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'LD_PRELOAD',
                 'MESON_ARGS', 'WINELOADER', 'WINESERVER', 'WINEPREFIX'):
        env.pop(name, None)
    env.update(PATH=str(wrappers) + os.pathsep + env.get('PATH', ''), LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1')
    return env


def build(work):
    work = work.resolve()
    checkpoint = verify_checkpoint(work)
    source = work / 'vkd3d'
    require(not any((work / name).exists() for name in ('build', 'install', 'app', 'tools', 'PE-LINK-REPORT.json')),
            'build output already exists')
    (work / 'app').mkdir()
    selected = {name: value['path'] for name, value in checkpoint['tools'].items()}
    env = build_environment(work, selected)
    script = commands(source, work)
    (work / 'COMMANDS.json').write_text(json.dumps(script, indent=2) + '\n')
    for index, argv in enumerate(script):
        with (work / 'logs' / ('build-' + str(index) + '.log')).open('wb') as log:
            subprocess.run(argv, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=2400)
    verify_checkpoint(work)
    for name in ('d3d12.dll', 'd3d12core.dll'):
        path = work / 'install/x64' / name
        require(path.is_file() and not path.is_symlink(), 'missing/linked frontend output: ' + name)
        shutil.copy2(path, work / 'app' / name)
    for path in sorted((work / 'app').iterdir()):
        with (work / 'logs' / (path.name + '-objdump.txt')).open('wb') as log:
            subprocess.run([selected['x86_64-w64-mingw32-objdump'], '-p', str(path)], stdout=log,
                           stderr=subprocess.STDOUT, check=True, timeout=60)
    report = inspect_candidate(work / 'app')
    report['source_checkpoint_sha256'] = sha(work / 'SOURCE-CHECKPOINT.json')
    report['project'] = checkpoint['project']
    (work / 'PE-LINK-REPORT.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('sources', 'build'))
    parser.add_argument('--work', type=Path, required=True, help='new external build-evidence directory')
    parser.add_argument('--repository', help='current public project URL, required for sources')
    args = parser.parse_args()
    try:
        if args.phase == 'sources':
            require(args.repository, '--repository is required for source checkpoint')
            prepare(args.work, args.repository)
        else:
            build(args.work)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, 'D3D12 build refused/failed: ' + str(error) + '\n')
