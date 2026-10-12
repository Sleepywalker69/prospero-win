#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Collect an opt-in, static-only preview build after replaying both mode gates.

This is not the fixture deployment packager. It does not admit a new runtime
capability, export a prefix, or execute target code. The existing off-mode
packager and its admission remain unchanged.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

import build_wine_service_child as child
import package_windows_child_fixture as package

prefix = package.prefix
require = package.require
SCHEMA = 'pw-child-ui-preview-static-validation/1'


def replay_preview_title(args):
    # Control replay has already imported validators from the original checkout.
    # A different --work or sys.path cannot relocate those cached modules. Run
    # the preview checkout's entry point in a fresh interpreter, keeping its
    # exact module-origin and all source/compiler/cohort checks intact.
    require(args.child_ui is True, 'preview replay requires explicit child UI')
    script = args.work / 'tools/build_wine_service_child.py'
    prefix.ordinary(script)
    command = [sys.executable, '-B', str(script), '--check-title', '--child-ui']
    for name in ('work', 'sdk', 'foundation', 'runtime', 'llvm_bindir', 'service_work',
                 'app', 'build', 'sdk_source_archive', 'fixture', 'user_fixture',
                 'network_fixture', 'run_id', 'run_attempt', 'out'):
        command.extend(('--' + name.replace('_', '-'), str(getattr(args, name))))
    subprocess.run(command, cwd=args.work, check=True, shell=False, timeout=1800)
    return package.read_json(args.out / 'native-wine-child-title.json')


def exact_contract(value, enabled):
    # JSON comparison also rejects bool/int and int/float substitutions.
    require(json.dumps(value, sort_keys=True) ==
            json.dumps(child.child_ui_contract(enabled), sort_keys=True),
            'child UI static-validation mode contract differs')


def paired_contract(control, preview, control_title, preview_title, project):
    """Additional mode and same-runtime assertions after full producer replay."""
    for enabled, manifest, title in ((False, control, control_title), (True, preview, preview_title)):
        require(manifest.get('schema') == 'pw-wine-service-child/2' and
                title.get('schema') == 'pw-windows-child-title/2', 'preview/control schema differs')
        require(manifest.get('project') == title.get('project') == project,
                'preview/control project differs')
        require(manifest.get('console_execution_verified') is False and
                title.get('console_execution_verified') is False, 'static evidence claims execution')
        exact_contract(manifest.get('child_ui'), enabled)
        exact_contract(title.get('build_inputs', {}).get('child_ui'), enabled)
        exact_contract(title.get('title_compile_inputs', {}).get('child_ui'), enabled)
        require(title.get('runtime') == manifest.get('runtime') and
                isinstance(manifest.get('runtime'), dict) and manifest['runtime'],
                'title/worker runtime differs')
    require(control.get('sources') == preview.get('sources') and
            isinstance(preview.get('sources'), dict) and preview['sources'],
            'preview/control worker sources differ')
    require(control['runtime'] == preview['runtime'], 'preview/control reused runtime differs')
    require(control['worker']['build_id'] != preview['worker']['build_id'] and
            control['worker']['sha256'] != preview['worker']['sha256'],
            'preview/control worker artifact collision')
    require(control_title['files']['eboot.bin']['sha256'] != preview_title['files']['eboot.bin']['sha256'],
            'preview/control title artifact collision')


def collect(config, args):
    require(config.get('schema') == 'pw-windows-child-package-inputs/1', 'wrong checked control inputs')
    run_url = config.get('run_url', '')
    require(re.fullmatch(r'https://github\.com/Sleepywalker69/prospero-win/actions/runs/[1-9][0-9]*', run_url),
            'actual producer run URL required')
    run, attempt = run_url.rsplit('/', 1)[-1], config.get('run_attempt')
    require(isinstance(attempt, str) and re.fullmatch(r'[1-9][0-9]*', attempt), 'producer attempt required')
    p = {name: Path(value).absolute() for name, value in config['paths'].items()}
    required = {'repo', 'sdk', 'foundation', 'wine_work', 'llvm_bindir', 'service_work', 'title',
                'title_build', 'title_report', 'sdk_source_archive', 'fixture', 'user_fixture',
                'network_fixture', 'wine_archive'}
    require(required <= set(p), 'control replay paths incomplete')
    for name in required:
        prefix.ordinary(p[name], name not in {'title_report', 'sdk_source_archive', 'wine_archive'})
    project = prefix.project(p['repo'])
    repo = Path(args.repo).absolute()
    prefix.ordinary(repo, True)
    require(repo != p['repo'] and prefix.project(repo) == project, 'preview checkout is not separate same-source HEAD')
    build, app, report, sources, source_report = (
        Path(getattr(args, name)).absolute() for name in ('build', 'app', 'report', 'sources', 'sources_report'))
    for path in (build, app, sources):
        prefix.ordinary(path, True)
    for path in (report, source_report):
        prefix.ordinary(path)
    require(build != p['title_build'] and app != p['title'] and report != p['title_report'],
            'preview must have separate build/title/inspection paths')
    originals = (*p.values(), repo, build, app, report, sources, source_report)
    out = prefix.absent(Path(args.out).absolute(), originals)
    scratch = prefix.absent(out.with_name(out.name + '-rechecks'), (*originals,))
    scratch.mkdir(mode=0o755)
    control_path, preview_path = (p['service_work'] / 'native-wine-child-build.json',
                                 build / 'wine-child/native-wine-child-build.json')
    # Capture receipts before replay, rather than accepting new bytes which
    # arrive between their validation and later packaging.
    before = {path: package.record(path) for path in
              (p['title_report'], report, control_path, preview_path, source_report,
               p['title_build'] / 'wine-child-title-compile.json', build / 'wine-child-title-compile.json')}

    # Re-run the full existing off-mode admission and explicitly opt in only the
    # separate preview check. Reports or a caller-selected capability flag do
    # not substitute for the actual ELF/source/compiler/helper validators.
    expected_control, expected_preview = package.read_json(p['title_report']), package.read_json(report)
    control_title = package.validate_title(p, expected_control, scratch / 'control', run, attempt)
    preview_args = argparse.Namespace(work=repo, sdk=p['sdk'], foundation=p['foundation'],
        runtime=p['wine_work'], llvm_bindir=p['llvm_bindir'], service_work=build / 'wine-child',
        app=app, build=build, sdk_source_archive=p['sdk_source_archive'], fixture=p['fixture'],
        user_fixture=p['user_fixture'], network_fixture=p['network_fixture'], run_id=run,
        run_attempt=attempt, child_ui=True, out=scratch / 'preview')
    preview_title = replay_preview_title(preview_args)
    require(preview_title == expected_preview, 'replayed preview title receipt differs')
    control, preview = package.read_json(control_path), package.read_json(preview_path)
    paired_contract(control, preview, control_title, preview_title, project)
    retained = package.retained_sources(repo, sources, source_report, project, p['wine_archive'],
                                       preview, p['sdk'], p['foundation'], p['wine_work'])
    require(all(package.record(path) == value for path, value in before.items()),
            'preview/control receipt changed during replay')
    app_inventory = prefix.inventory(app)
    app_files = {name: {key: value[key] for key in ('bytes', 'sha256', 'mode')}
                 for name, value in app_inventory.items() if value['type'] == 'file'}
    require(app_files == preview_title['files'], 'preview title changed after replay')

    # No output bundle exists until both exact-mode gates and complete retained
    # source provenance have passed. No console/ prefix, profiles or install
    # manifest are created; target images are inert review inputs only.
    out.mkdir(mode=0o755)
    package.put_bytes(out, 'README.txt', (
        'OPT-IN CHILD PREVIEW: STATIC TARGET-BUILD VALIDATION ONLY\n'
        'Not a deployment package or an approved installation. No target code was executed.\n'
        'Default-off control and enabled preview share the checked source/runtime cohort.\n'
        'Preview uses bootstrap v3 with two rights; child input remains disabled.\n'
        'Console socket/ancillary behavior, visible presentation and resource settlement remain unverified.\n'
        'Do not feed this artifact into the fixture deployment workflow.\n').encode())
    package.copy_tree(out, 'target-images', app, expected=app_inventory)
    package.copy_tree(out, 'inspection', scratch / 'preview')
    package.copy_tree(out, 'sources', sources, expected=retained['inventory'])
    for name, path in (('control-title.json', p['title_report']), ('control-worker.json', control_path),
                       ('preview-worker.json', preview_path), ('retained-sources.json', source_report),
                       ('preview-title-compile.json', build / 'wine-child-title-compile.json')):
        package.put(out, 'provenance/' + name, path)
    require(all(package.record(path) == value for path, value in before.items()),
            'preview/control receipt changed during collection')
    require(prefix.inventory(app) == app_inventory and prefix.inventory(sources) == retained['inventory'] and
            prefix.project(p['repo']) == prefix.project(repo) == project, 'preview input cohort changed during collection')
    package.normalize_directories(out)
    result = {'schema': SCHEMA, 'project': project, 'run_url': run_url, 'run_attempt': attempt,
              'child_ui': child.child_ui_contract(True), 'control_child_ui': child.child_ui_contract(False),
              'control_worker_build_id': control['worker']['build_id'],
              'preview_worker_build_id': preview['worker']['build_id'],
              'same_runtime': preview['runtime'], 'deployment_package': False, 'release_ready': False,
              'console_execution_verified': False, 'runtime_validated': False, 'child_input_enabled': False,
              'inventory': package.inventory(out),
              'scope': 'replayed same-source target build/static checks only; no console capability admission'}
    package.put_bytes(out, 'STATIC-VALIDATION.json', package.json_bytes(result))
    package.put_bytes(out, 'SHA256SUMS', package.checksums(package.inventory(out)))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inputs', 'repo', 'build', 'app', 'report', 'sources', 'sources-report', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = collect(package.read_json(args.inputs.absolute()), args)
    print(json.dumps({'schema': result['schema'], 'project': result['project'],
                      'deployment_package': False, 'runtime_validated': False}))


if __name__ == '__main__':
    main()
