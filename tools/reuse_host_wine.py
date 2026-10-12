#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Reuse only a completed same-repository host installation, or rebuild normally.

The accepted target package, source snapshots and exact compiler/environment
identity must all agree. This never reuses target, prefix or Windows evidence.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
import zlib
import yaml

import wine_compile_cache as cache
import package_windows_child_fixture as package

REPOSITORY = 'Sleepywalker69/prospero-win'
WORKFLOW = '.github/workflows/windows-child-fixture.yml'
MAX_ZIP = 2 << 30
MAX_EXPANDED = 8 << 30
RECIPES = ('tools/build_host_wine.sh', 'tools/build_wine_ps5.sh',
           'tools/stage_vk_batch.py', 'tools/generate_vk_codecs.py',
           'tools/wine_compile_cache.py')
SUPPORT_TARGETS = ('loader/wine', 'server/wineserver', 'dlls/ntdll/ntdll.so', 'dlls/wow64/x86_64-windows/libwow64.a',
                   'dlls/ntdll/x86_64-windows/libntdll.a',
                   'libs/winecrt0/x86_64-windows/libwinecrt0.a',
                   'libs/compiler-rt/x86_64-windows/libcompiler-rt.a')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def api(path):
    require(path.startswith('repos/' + REPOSITORY + '/'), 'API destination differs')
    return json.loads(subprocess.check_output(['gh', 'api', path], timeout=90))


def source_equal(donor, current):
    require(set(donor) == set(current) == {'schema', 'project', 'wine_commit', 'patches', 'host_source', 'ps5_source'},
            'source cohort shape differs')
    require(donor['schema'] == 'pw-windows-child-source-cohort/1', 'source cohort schema differs')
    require({k: v for k, v in donor.items() if k != 'project'} ==
            {k: v for k, v in current.items() if k != 'project'},
            'Wine pin, patches or actual staged host/target source bytes differ')


def compatibility_equal(donor, current):
    require(donor.get('phase') == current.get('phase') == 'host' and
            donor.get('schema') == current.get('schema') == cache.SCHEMA, 'host compiler schema differs')
    require(cache.cache_partition(donor) == cache.cache_partition(current),
            'host compiler, flags, ABI, headers or installed environment differs')
    for name in RECIPES:
        require(donor['recipe'].get(name) == current['recipe'].get(name) and
                re.fullmatch('[0-9a-f]{64}', current['recipe'].get(name, '')),
                'host build recipe differs: ' + name)


def choose_artifacts(run, artifacts):
    require(run.get('status') == 'completed' and run.get('conclusion') == 'success',
            'donor run is not fully successful')
    require(run.get('repository', {}).get('full_name') == REPOSITORY and
            run.get('head_repository', {}).get('full_name') == REPOSITORY and
            run.get('path') == WORKFLOW and run.get('event') in ('pull_request', 'push', 'workflow_dispatch'),
            'donor is not the owned matched-runtime workflow')
    attempt = str(run.get('run_attempt'))
    selected = {}
    for role, prefix in [('package', 'windows-child-fixture-'),
                         ('host', 'windows-child-host-checkpoint-'),
                         ('evidence', 'windows-child-fixture-evidence-')]:
        expression = re.compile(re.escape(prefix) + r'([0-9a-f]{40})-' + re.escape(attempt) + r'$')
        candidates = [(a, expression.fullmatch(a.get('name', ''))) for a in artifacts]
        candidates = [(a, m) for a, m in candidates if m]
        require(len(candidates) == 1, 'donor artifact missing or ambiguous: ' + role)
        artifact, match = candidates[0]
        require(not artifact.get('expired') and 0 < artifact.get('size_in_bytes', 0) <= MAX_ZIP and
                re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.get('digest', '')),
                'donor artifact expired, oversized or lacks exact digest')
        require(artifact.get('workflow_run', {}).get('id') == run['id'], 'artifact belongs to another run')
        selected[role] = {**artifact, 'compiled_commit': match.group(1)}
    require(len({v['compiled_commit'] for v in selected.values()}) == 1, 'donor artifact commits differ')
    return selected


def download(artifact, path):
    with path.open('xb') as output:
        subprocess.run(['gh', 'api', 'repos/' + REPOSITORY + '/actions/artifacts/' +
                        str(artifact['id']) + '/zip'], stdout=output, check=True, timeout=600)
    require(path.stat().st_size == artifact['size_in_bytes'] and
            'sha256:' + cache.sha(path) == artifact['digest'], 'artifact archive bytes/digest differ')


def zip_members(path, wanted, destination):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) and len(names) <= 20000, 'duplicate or oversized ZIP index')
        for name in wanted:
            require(names.count(name) == 1, 'artifact payload absent: ' + name)
            info = archive.getinfo(name)
            require(not info.is_dir() and 0 <= info.file_size <= MAX_ZIP and
                    not stat.S_ISLNK(info.external_attr >> 16), 'invalid ZIP payload')
            target = destination / Path(name).name
            with archive.open(info) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output, 1 << 20)
            require(target.stat().st_size == info.file_size, 'truncated ZIP payload')


def tar_bytes(path, name, maximum=64 << 20):
    with tarfile.open(path, 'r:gz') as archive:
        members = [m for m in archive if m.name == name]
        require(len(members) == 1 and members[0].isfile() and members[0].size <= maximum,
                'retained archive member absent or oversized: ' + name)
        return archive.extractfile(members[0]).read()


def gzip_digest(path):
    digest = hashlib.sha256()
    total = 0
    with gzip.open(path, 'rb') as source:
        for block in iter(lambda: source.read(1 << 20), b''):
            total += len(block)
            require(total <= 512 << 20, 'retained project source exceeds expansion bound')
            digest.update(block)
    return digest.hexdigest()


def extract_checkpoint(path, output):
    total, seen = 0, set()
    with tarfile.open(path, 'r:gz') as archive:
        members = []
        for member in archive:
            members.append(member)
            require(len(members) <= 20000, 'checkpoint has too many members')
            name = member.name.removeprefix('./').rstrip('/')
            if name in ('', '.'):
                require(member.isdir(), 'checkpoint root is not a directory')
                continue
            require(not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')) and
                    name.casefold() not in seen, 'unsafe or duplicate checkpoint member')
            seen.add(name.casefold())
            require(member.isfile() or member.isdir() or member.issym(), 'checkpoint has special/hardlink member')
            require(0 <= member.size <= MAX_ZIP and not member.mode & 0o7000, 'checkpoint member bounds/mode')
            total += member.size
            require(total <= MAX_EXPANDED, 'checkpoint expansion limit exceeded')
            if member.issym():
                require(name.startswith('host-wine/') and not member.linkname.startswith('/'),
                        'checkpoint link outside installation')
                # Python data_filter additionally checks actual containment, including
                # earlier links. host_identity checks every resolved installation link.
        archive.extractall(output, members=members, filter='data')


OVERRIDES = ('CC', 'CXX', 'CPP', 'AR', 'AS', 'LD', 'NM', 'RANLIB', 'STRIP',
             'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'LIBS', 'CROSSCFLAGS',
             'i386_CC', 'x86_64_CC', 'i386_CFLAGS', 'x86_64_CFLAGS',
             'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'OBJC_INCLUDE_PATH',
             'LIBRARY_PATH', 'COMPILER_PATH', 'GCC_EXEC_PREFIX', 'LD_LIBRARY_PATH',
             'PKG_CONFIG', 'PKG_CONFIG_PATH', 'PKG_CONFIG_LIBDIR', 'PKG_CONFIG_SYSROOT_DIR',
             'CONFIG_SITE', 'CONFIG_SHELL', 'BASH_ENV', 'ENV', 'MAKEFLAGS', 'MFLAGS',
             'BISON', 'YACC', 'FLEX', 'LEX', 'WINDRES', 'RC')
HOST_STEPS = ('Initialize paths on the allocated runner',
              'Select bounded build concurrency from available resources',
              'Prepare ordinary hosted prerequisites',
              'Fetch exact public Wine and foundation source',
              'Check all private-dispatch source controls and stage the reference cohort',
              'Bind exact host Wine compiler cache inputs',
              'Build only matching host tools for early target checks',
              'Build complete matching host Wine')


def check_invocation(argv, source, work):
    require(isinstance(argv, list) and len(argv) == 10 and
            argv[:4] == ['timeout', '180m', 'sh', 'tools/build_host_wine.sh'] and
            argv[4:9] == ['--source', str(source), '--work', str(work), '--jobs'] and
            argv[9] in ('2', '4'), 'host checkpoint full-runtime invocation differs')


def workflow_contract(value):
    workflow = yaml.safe_load(value)
    job = workflow['jobs']['matched-runtime']
    selected = {}
    for name in HOST_STEPS:
        steps = [s for s in job['steps'] if s.get('name') == name]
        require(len(steps) == 1, 'host workflow step missing or ambiguous: ' + name)
        step = steps[0]
        selected[name] = {k: step[k] for k in ('run', 'env', 'shell', 'uses', 'with') if k in step}
    # Includes pinned checkout/Python actions and configuration, but not irrelevant
    # target/reference steps, labels or the new reuse step's conditional routing.
    setup = [{k: s[k] for k in ('uses', 'with', 'env') if k in s}
             for s in job['steps'] if s.get('uses', '').startswith(('actions/checkout@', 'actions/setup-python@'))]
    return {'env': workflow.get('env', {}), 'job_env': job.get('env', {}),
            'defaults': workflow.get('defaults', {}), 'job_defaults': job.get('defaults', {}),
            'runs_on': job.get('runs-on'), 'container': job.get('container'), 'setup': setup, 'steps': selected}


def configure_contract(donor_source, current_repo, old_config, old_log, host_work):
    unexpected = [name for name in OVERRIDES if os.environ.get(name) and name not in ('PKG_CONFIG_PATH', 'LD_LIBRARY_PATH')]
    require(not unexpected, 'ambient host configure/compiler overrides: ' + ', '.join(unexpected))
    pkg_path = os.environ.get('PKG_CONFIG_PATH', '')
    require(not pkg_path or re.fullmatch(r'/opt/hostedtoolcache/Python/3\.12\.[0-9]+/x64/lib/pkgconfig', pkg_path),
            'unexpected setup-python pkgconfig path')
    library_path = os.environ.get('LD_LIBRARY_PATH', '')
    require((not pkg_path and not library_path) or
            (pkg_path and library_path == pkg_path.removesuffix('/pkgconfig')),
            'setup-python dynamic library path differs from pkgconfig root')
    def precious(path):
        return sorted(line for line in path.read_text().splitlines()
                      if re.match(r'^ac_cv_env_[A-Za-z0-9_]+_(?:set|value)=', line))
    old_env, current_env = precious(old_log), precious(host_work / 'build/config.log')
    require(old_env and old_env == current_env, 'host configure precious environment differs')
    with tarfile.open(donor_source, 'r:gz') as source:
        member = source.extractfile(WORKFLOW)
        require(member is not None, 'donor host workflow unavailable')
        donor = workflow_contract(member.read())
    current = workflow_contract((current_repo / WORKFLOW).read_bytes())
    require(donor == current, 'host preparation/configure/build workflow contract differs')
    require(old_config.read_bytes() == (host_work / 'build/config.status').read_bytes(),
            'fresh and donor host configure results differ')


def check_support(work):
    for name in SUPPORT_TARGETS:
        path = work / 'build' / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0,
                'bounded host support target absent: ' + name)
    for name in ('loader/wine', 'server/wineserver'):
        require(os.access(work / 'build' / name, os.X_OK),
                'host support executable absent; full-build fallback would be unsafe: ' + name)


def runner_identity(run):
    jobs = api('repos/' + REPOSITORY + '/actions/runs/' + str(run['id']) +
               '/attempts/' + str(run['run_attempt']) + '/jobs?per_page=100')
    require(jobs.get('total_count', 101) <= 100, 'donor jobs pagination is not bounded')
    matched = [job for job in jobs['jobs'] if job.get('name') == 'matched-runtime']
    require(len(matched) == 1 and matched[0].get('conclusion') == 'success', 'successful donor runtime job absent')
    logs = subprocess.check_output(['gh', 'api', 'repos/' + REPOSITORY + '/actions/jobs/' +
                                    str(matched[0]['id']) + '/logs'], timeout=120).decode('utf-8-sig').replace('\r\n', '\n')
    lines = re.sub(r'^\d{4}-\d\d-\d\dT[^ ]+ ', '', logs, flags=re.M)
    groups = re.findall(r'##\[group\]Runner Image\n(.*?)##\[endgroup\]', lines, flags=re.S)
    require(len(groups) == 1, 'donor runner image record unavailable')
    image = re.findall(r'^Image: (.+)$', groups[0], re.M)
    version = re.findall(r'^Version: (.+)$', groups[0], re.M)
    require(image == ['ubuntu-24.04'] and len(version) == 1 and
            os.environ.get('ImageOS') == 'ubuntu24' and os.environ.get('ImageVersion') == version[0],
            'donor and current hosted runner image differ')
    blocks = re.findall(r'##\[group\]Run ([^\n]+)\n(.*?)##\[endgroup\]', lines, re.S)
    host = [body for header, body in blocks if '--stage host-runtime --' in header]
    require(len(host) == 1, 'donor full-host environment record unavailable')
    entries = re.findall(r'^  ([A-Za-z_][A-Za-z0-9_]*): (.*)$', host[0], re.M)
    require(len(entries) == len(dict(entries)), 'duplicate donor environment record')
    recorded = dict(entries)
    for name in (*OVERRIDES, 'PATH', 'pythonLocation'):
        require(recorded.get(name, '') == os.environ.get(name, ''),
                'donor/current host environment differs: ' + name)
    return {'image': image[0], 'version': version[0], 'donor_job_id': matched[0]['id'],
            'host_environment_sha256': hashlib.sha256(cache.canonical(
                {name: recorded.get(name, '') for name in (*OVERRIDES, 'PATH', 'pythonLocation')})).hexdigest()}


def restore(args):
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY, 'consumer repository differs')
    require(re.fullmatch('[1-9][0-9]*', args.run), 'invalid donor run')
    run = api('repos/' + REPOSITORY + '/actions/runs/' + args.run)
    artifacts = api('repos/' + REPOSITORY + '/actions/runs/' + args.run + '/artifacts?per_page=100')
    require(artifacts['total_count'] <= 100, 'artifact pagination must be explicit')
    selected = choose_artifacts(run, artifacts['artifacts'])
    runner = runner_identity(run)
    project = selected['package']['compiled_commit']
    current_state = json.loads((args.cache_state / 'state.json').read_text())
    current_identity = cache.checked_identity(args.cache_state, current_state)
    current_cohort = json.loads(args.cohort.read_text())
    require(current_state['project'] == current_cohort['project'], 'consumer cache/source project differs')
    with tempfile.TemporaryDirectory(prefix='pw-host-reuse-', dir=os.environ['RUNNER_TEMP']) as temporary:
        temp = Path(temporary)
        for role, artifact in selected.items():
            download(artifact, temp / (role + '.zip'))
        zip_members(temp / 'package.zip', ['windows-child-fixture.tar.gz'], temp)
        accepted = package.verify_archive(temp / 'windows-child-fixture.tar.gz')
        require(accepted['project']['commit'] == project and
                accepted['run_url'] == 'https://github.com/' + REPOSITORY + '/actions/runs/' + args.run and
                accepted.get('run_attempt') == str(run['run_attempt']), 'accepted package producer differs')
        # Establish the compiled PR merge/source identity from GitHub, not a filename alone.
        commit = api('repos/' + REPOSITORY + '/git/commits/' + project)
        require(commit['tree']['sha'] == accepted['project']['tree'] and
                (project == run['head_sha'] or run['head_sha'] in [p['sha'] for p in commit['parents']]),
                'accepted package is not the workflow source or its recorded merge')
        old_cache = temp / 'cache'; old_cache.mkdir()
        zip_members(temp / 'evidence.zip',
                    ['ccache-host/' + name for name in ('state.json', 'compatibility.json', 'partition.json', 'host-runtime.json')],
                    old_cache)
        zip_members(temp / 'evidence.zip', ['build-logs/HOST_WORK/build/' + name for name in ('config.status', 'config.log')], old_cache)
        state = json.loads((old_cache / 'state.json').read_text())
        old_identity = cache.checked_identity(old_cache, state)
        receipt = json.loads((old_cache / 'host-runtime.json').read_text())
        require(state['project'] == accepted['project'] and receipt.get('project') == accepted['project'] and
                receipt.get('stage') == 'host-runtime' and receipt.get('exit') == 0 and
                all(receipt.get(k) == state[k] for k in ('key', 'partition_key', 'partition_sha256', 'compatibility_sha256')),
                'host checkpoint lacks matching successful compiler receipt')
        check_invocation(receipt.get('argv'), args.cohort.parent / 'wine-source', args.host_work)
        compatibility_equal(old_identity, current_identity)
        zip_members(temp / 'host.zip', ['windows-child-host-checkpoint.tar.gz'], temp)
        checkpoint = temp / 'checkpoint'; checkpoint.mkdir()
        extract_checkpoint(temp / 'windows-child-host-checkpoint.tar.gz', checkpoint)
        donor_cohort = json.loads((checkpoint / 'source-cohort.json').read_text())
        require(donor_cohort['project'] == accepted['project'], 'host checkpoint source project differs')
        source_equal(donor_cohort, current_cohort)
        donor_source = temp / 'accepted-project.tar.gz'
        donor_source.write_bytes(tar_bytes(temp / 'windows-child-fixture.tar.gz', 'sources/project.tar.gz'))
        require(gzip_digest(donor_source) == gzip_digest(checkpoint / 'sources/prospero-win.tar.gz'),
                'host checkpoint source archive differs from accepted package')
        configure_contract(donor_source, args.repo, old_cache / 'config.status', old_cache / 'config.log', args.host_work)
        with tarfile.open(donor_source, 'r:gz') as source:
            for name in RECIPES:
                data = source.extractfile(name).read()
                require(hashlib.sha256(data).hexdigest() == old_identity['recipe'][name],
                        'donor host recipe differs from retained source')
        install = args.host_work / 'install'
        require(not install.exists() and not install.is_symlink(), 'host install must be absent before reuse')
        try:
            shutil.copytree(checkpoint / 'host-wine', install / 'usr', symlinks=True)
            # Keep the normal source/ABI/install inventory checks; this is not a stamp-only hit.
            from prepare_windows_child_prefix import host_identity
            identity, _ = host_identity(args.repo, args.host_work, args.cohort)
            subprocess.run([str(install / 'usr/bin/wine'), '--version'], check=True, timeout=30)
        except Exception:
            if install.exists():
                shutil.rmtree(install)
            raise
        evidence = args.report.parent / 'host-reuse-inputs'
        evidence.mkdir(exist_ok=False)
        for name in ('state.json', 'compatibility.json', 'partition.json', 'host-runtime.json', 'config.status', 'config.log'):
            shutil.copyfile(old_cache / name, evidence / name)
        shutil.copyfile(checkpoint / 'source-cohort.json', evidence / 'source-cohort.json')
    return {'schema': 'pw-verified-host-reuse/1', 'reused': True, 'donor_run': args.run,
            'donor_project': accepted['project'], 'consumer_project': current_cohort['project'],
            'artifacts': {k: {n: v[n] for n in ('id', 'name', 'digest')} for k, v in selected.items()},
            'host_install_sha256': hashlib.sha256(cache.canonical(identity['files'])).hexdigest(),
            'donor_inputs': {name: cache.sha(evidence / name) for name in
                             ('compatibility.json', 'partition.json', 'host-runtime.json', 'config.status', 'config.log', 'source-cohort.json')},
            'runner': runner, 'source_and_compiler_inputs_equal': True, 'target_prefix_reference_reused': False,
            'support_targets_required': list(SUPPORT_TARGETS), 'donor_attempt': run['run_attempt']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'host-work', 'cohort', 'cache-state', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    install = args.host_work / 'install'
    had_install = install.exists() or install.is_symlink()
    try:
        result = restore(args)
    except Exception as error:
        # Reuse is optional. Malformed or unavailable evidence never weakens the
        # required build; the ordinary full host path remains the only fallback.
        if not had_install and install.is_dir() and not install.is_symlink():
            shutil.rmtree(install)
        result = {'schema': 'pw-verified-host-reuse/1', 'reused': False,
                  'reason': type(error).__name__ + ': ' + str(error), 'fallback': 'unchanged full host build'}
    args.report.write_bytes(cache.canonical(result))
    print(json.dumps(result, sort_keys=True))
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('reused=' + str(result['reused']).lower() + '\n')


if __name__ == '__main__':
    main()
