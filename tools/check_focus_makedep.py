#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Real pinned Wine configure/makedep regression; no Wine runtime or target execution."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import wine_focus_neutral as focus


def dependencies(text, target):
    """Read actual makedep continuation rules, without inventing include paths."""
    logical = text.replace('\\\n', ' ')
    rows = re.findall(r'^' + re.escape(target) + r'[ \t]*:([^\n]*)$', logical, re.M)
    if not rows:
        raise AssertionError('missing generated object rule: ' + target)
    return set(' '.join(rows).split())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wine-source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    source = args.wine_source.resolve(strict=True)
    work, out = args.work.absolute(), args.out.absolute()
    if work.exists() or work.is_symlink() or out.exists() or out.is_symlink():
        parser.error('regression work and evidence must be fresh')
    work.mkdir(parents=True)
    out.mkdir(parents=True)
    rows = []
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'TMPDIR', 'XDG_CACHE_HOME') if k in os.environ}
    env.update(LC_ALL='C', TZ='UTC', CONFIG_SITE='/dev/null', CC='gcc', CXX='g++',
               PYTHONDONTWRITEBYTECODE='1', CCACHE_DISABLE='1')
    def run(label, command, *, cwd=None, fail=False, contains=None, pattern=None):
        command = list(map(str, command))
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=240)
        log = result.stdout + result.stderr
        (out/(label+'.log')).write_text(log)
        rows.append({'label': label, 'argv': command, 'exit': result.returncode,
                     'expected_failure': fail})
        (out/'COMMANDS.json').write_text(json.dumps(rows, indent=2)+'\n')
        if bool(result.returncode) != fail:
            raise AssertionError((label, result.returncode, log[-5000:]))
        if contains and contains not in log:
            raise AssertionError((label, 'missing specific diagnostic', contains, log[-5000:]))
        if pattern and not re.search(pattern, log):
            raise AssertionError((label, 'wrong failure boundary', pattern, log[-5000:]))
        return result.stdout.strip()

    assert run('pin', ['git', '-C', source, 'rev-parse', 'HEAD']) == focus.WINE_COMMIT
    assert not run('clean', ['git', '-C', source, 'status', '--porcelain', '--untracked-files=normal'])
    contract = focus.contract(ROOT)  # Includes fixed hashes of accepted 0001/0002.
    graph = {}
    for neutral in (False, True):
        name = 'neutral963' if neutral else 'default962'
        tree, build = work/(name+'-source'), work/(name+'-build')
        run(name+'-clone', ['git', 'clone', '--quiet', '--shared', source, tree])
        for i, patch in enumerate(sorted((ROOT/'wine/patches').glob('*.patch'))):
            run(name+'-patch-%03d'%i, ['git', '-C', tree, 'apply', '--index', patch])
        focus.verify_default_source(ROOT, tree)
        if neutral:
            assert focus.stage(ROOT, tree, out/'focus-neutral.json') == contract
            focus.verify_headers(tree, contract)
        else:
            assert 'pw_focus_' not in (tree/'include/Makefile.in').read_text()
            for header in focus.HEADERS:
                assert not (tree/'include'/header).exists()
        assert re.findall(r'^#define SERVER_PROTOCOL_VERSION\s+(\d+)\s*$',
                          (tree/'include/wine/server_protocol.h').read_text(), re.M) == [str(963 if neutral else 962)]
        # Same owned-source staging used by the real host/target driver.
        run(name+'-stage-vulkan', [sys.executable, ROOT/'tools/stage_vk_batch.py', '--source', tree, '--repo', ROOT])
        for origin, destination in (
                ('wine/ps5/time/pw_qpc_clock.h', 'dlls/ntdll/pw_qpc_clock.h'),
                ('wine/ps5/input/pw_key_shared.h', 'dlls/win32u/pw_key_shared.h'),
                *((('wine/ps5/'+unit), ('dlls/win32u/'+unit)) for unit in
                  ('pw_d3d9_window.c', 'pw_d3d9_window.h', 'pw_d3d9_window_driver.c', 'pw_d3d9_window_driver.h'))):
            shutil.copyfile(ROOT/origin, tree/destination)
        build.mkdir()
        run(name+'-configure', [tree/'configure', '--enable-win64', '--without-mingw',
            '--without-x', '--without-freetype', '--without-vulkan', '--disable-tests'], cwd=build)
        assert (build/'tools/makedep').is_file()
        run(name+'-config-status', ['sh', './config.status', 'Makefile'], cwd=build)
        makefile = (build/'Makefile').read_text()
        (out/(name+'-Makefile')).write_text(makefile)
        graph[name] = {}
        if not neutral:
            assert 'pw_focus_' not in makefile
            continue
        for target, headers in (
                ('dlls/ntdll/unix/server.o', focus.HEADERS),
                ('server/pw_focus_requests.o', ('wine/pw_focus_build.h', 'wine/pw_focus_protocol.h'))):
            deps = dependencies(makefile, target)
            selected = []
            for header in headers:
                matches = [entry for entry in deps if entry.endswith('/include/'+header)]
                assert len(matches) == 1, (target, header, sorted(deps))
                selected.extend(matches)
            graph[name][target] = selected
        # Ordinary source headers must not acquire a generated-header recipe.
        assert not re.search(r'^[^\n:]*\bpw_focus_build\.h(?:[ \t]+[^\n:]*)?[ \t]*:',
                             makefile.replace('\\\n', ' '), re.M)
        registry = tree/'include/Makefile.in'
        original = registry.read_text()
        for header in focus.HEADERS:
            basename = Path(header).name
            row = '\t' + header + ' \\\n'
            assert original.count(row) == 1
            # Missing registration with the physical header still present.
            try:
                registry.write_text(original.replace(row, ''))
                assert (tree/'include'/header).is_file()
                run('missing-registration-'+basename, ['sh', './config.status', 'Makefile'],
                    cwd=build, fail=True, contains=header, pattern=r'\.[ch]:\d+: error:')
            finally:
                registry.write_text(original)
            # Missing physical file with its original registration intact.
            path = tree/'include'/header
            data = path.read_bytes()
            try:
                path.unlink()
                run('missing-file-'+basename, ['sh', './config.status', 'Makefile'],
                    cwd=build, fail=True, contains='open ' + header)
            finally:
                path.write_bytes(data)
        focus.verify_headers(tree, contract)
        run(name+'-restored-config-status', ['sh', './config.status', 'Makefile'], cwd=build)
        assert (build/'Makefile').read_text() == makefile
    (out/'RESULT.json').write_text(json.dumps({
        'schema': 'pw-focus-makedep-regression/1', 'wine_commit': focus.WINE_COMMIT,
        'source_sha256': contract['source_sha256'], 'generated_dependencies': graph,
        'accepted_patch_sha256': list(focus.ACCEPTED), 'optional_patches': list(focus.OPTIONAL),
        'missing_registration_cases': 3, 'missing_file_cases': 3,
        'configure_and_config_status': True, 'host_makedep_executed': True,
        'runtime_built': False, 'target_compiled': False, 'target_executed': False}, indent=2)+'\n')
    print('default962/neutral963 configure and real makedep dependency/negative controls passed')


if __name__ == '__main__':
    main()
