#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fail-closed host installation reuse and bounded support-build contracts."""
from __future__ import annotations
import copy
import gzip
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import reuse_host_wine as reuse


class HostReuse(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = {'id': 123, 'run_attempt': 1, 'status': 'completed', 'conclusion': 'success',
                    'path': reuse.WORKFLOW, 'event': 'pull_request',
                    'repository': {'full_name': reuse.REPOSITORY},
                    'head_repository': {'full_name': reuse.REPOSITORY}}
        self.artifacts = [
            {'id': i, 'name': prefix + 'a' * 40 + '-1', 'expired': False,
             'size_in_bytes': 128, 'digest': 'sha256:' + 'b' * 64, 'workflow_run': {'id': 123}}
            for i, prefix in enumerate(('windows-child-fixture-', 'windows-child-host-checkpoint-',
                                        'windows-child-fixture-evidence-'), 1)]

    def test_only_complete_owned_success_is_admitted(self):
        self.assertEqual(set(reuse.choose_artifacts(self.run, self.artifacts)), {'package', 'host', 'evidence'})
        for field, value in [('conclusion', 'failure'), ('status', 'in_progress'), ('run_attempt', 2),
                             ('path', '.github/workflows/other.yml'), ('event', 'pull_request_target'),
                             ('head_repository', {'full_name': 'fork/prospero-win'}),
                             ('repository', {'full_name': 'fork/prospero-win'})]:
            run = copy.deepcopy(self.run); run[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                reuse.choose_artifacts(run, self.artifacts)

    def test_artifact_ambiguity_expiry_provenance_digest_and_cohort(self):
        for index, field, value in [(0, 'expired', True), (0, 'digest', ''),
                                    (1, 'workflow_run', {'id': 999}), (1, 'size_in_bytes', 0),
                                    (2, 'name', 'windows-child-fixture-evidence-' + 'c' * 40 + '-1')]:
            artifacts = copy.deepcopy(self.artifacts); artifacts[index][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                reuse.choose_artifacts(self.run, artifacts)
        for artifacts in (self.artifacts[:2], self.artifacts + [self.artifacts[0]]):
            with self.assertRaises(ValueError):
                reuse.choose_artifacts(self.run, artifacts)

    def test_source_project_can_change_but_no_other_input(self):
        value = {'schema': 'pw-windows-child-source-cohort/1', 'project': {'commit': 'old'},
                 'wine_commit': 'wine', 'patches': {'a': 'hash'}, 'host_source': {'x': 'one'},
                 'ps5_source': {'x': 'two'}}
        changed = copy.deepcopy(value); changed['project'] = {'commit': 'new'}
        reuse.source_equal(value, changed)
        for name in ('wine_commit', 'patches', 'host_source', 'ps5_source', 'schema'):
            changed = copy.deepcopy(value); changed[name] = 'different'
            with self.subTest(name=name), self.assertRaises(ValueError):
                reuse.source_equal(value, changed)

    def test_every_opaque_compiler_input_and_recipe_invalidates(self):
        value = {'schema': reuse.cache.SCHEMA, 'phase': 'host',
                 'recipe': {n: 'a' * 64 for n in reuse.RECIPES},
                 'flags': {}, 'compilers': {}, 'system_headers': {}, 'packages': 'same', 'abi_contracts': {}}
        reuse.compatibility_equal(value, copy.deepcopy(value))
        for name in ('flags', 'compilers', 'system_headers', 'packages', 'abi_contracts'):
            changed = copy.deepcopy(value); changed[name] = 'different'
            with self.subTest(name=name), self.assertRaises(ValueError):
                reuse.compatibility_equal(value, changed)
        for name in reuse.RECIPES:
            changed = copy.deepcopy(value); changed['recipe'][name] = 'b' * 64
            with self.subTest(name=name), self.assertRaises(ValueError):
                reuse.compatibility_equal(value, changed)
        changed = copy.deepcopy(value); changed['recipe']['.github/workflows/windows-child-fixture.yml'] = 'b' * 64
        reuse.compatibility_equal(value, changed)  # The isolated host workflow contract is checked separately.

    def test_full_host_invocation_has_no_optional_flags_or_conflicting_paths(self):
        source, work = Path('/source'), Path('/work')
        args = ['timeout', '180m', 'sh', 'tools/build_host_wine.sh', '--source', str(source),
                '--work', str(work), '--jobs', '4']
        reuse.check_invocation(args, source, work)
        for changed in (args + ['--tools-only'], args[:4], args[:-1] + ['999'], None,
                        args[:5] + ['/different'] + args[6:],
                        args[:7] + ['/different'] + args[8:]):
            with self.subTest(args=changed), self.assertRaises(ValueError):
                reuse.check_invocation(changed, source, work)

    def test_host_workflow_contract_ignores_only_routing_not_build_environment(self):
        text = (ROOT / reuse.WORKFLOW).read_text()
        expected = reuse.workflow_contract(text)
        workflow = reuse.yaml.safe_load(text)
        steps = workflow['jobs']['matched-runtime']['steps']
        target = next(s for s in steps if s.get('name') == 'Build complete matching host Wine')
        target['if'] = 'arbitrary routing'
        self.assertEqual(expected, reuse.workflow_contract(reuse.yaml.safe_dump(workflow)))
        target['run'] += '\nexport CONFIG_SITE=/different\n'
        self.assertNotEqual(expected, reuse.workflow_contract(reuse.yaml.safe_dump(workflow)))
        workflow = reuse.yaml.safe_load(text); workflow['env']['CPATH'] = '/different'
        self.assertNotEqual(expected, reuse.workflow_contract(reuse.yaml.safe_dump(workflow)))

    def test_missing_loader_or_server_cannot_trigger_a_hidden_full_build(self):
        build = self.root / 'build'
        for name in reuse.SUPPORT_TARGETS:
            path = build / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'compiled'); path.chmod(0o755)
        reuse.check_support(self.root)
        for name in ('loader/wine', 'server/wineserver'):
            path = build / name; path.chmod(0o644)
            with self.assertRaises(ValueError):
                reuse.check_support(self.root)
            path.chmod(0o755); value = path.read_bytes(); path.unlink()
            with self.assertRaises(ValueError):
                reuse.check_support(self.root)
            path.write_bytes(value); path.chmod(0o755)
        workflow = (ROOT / reuse.WORKFLOW).read_text()
        for name in reuse.SUPPORT_TARGETS:
            self.assertIn(name, workflow)
        self.assertIn('check_support(pathlib.Path(sys.argv[1]))', workflow)

    def archive(self, items):
        path = self.root / 'checkpoint.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name, kind, data in items:
                member = tarfile.TarInfo(name); member.mode = 0o644
                if kind == 'file':
                    member.size = len(data); archive.addfile(member, io.BytesIO(data))
                else:
                    member.type = kind; member.linkname = data; archive.addfile(member)
        return path

    def test_safe_archive_rejects_traversal_duplicates_special_and_escaping_links(self):
        for entries in [
            [('../escape', 'file', b'x')],
            [('host-wine/x', 'file', b'x'), ('host-wine/X', 'file', b'y')],
            [('host-wine/link', tarfile.SYMTYPE, '/etc/passwd')],
            [('host-wine/link', tarfile.SYMTYPE, '../../../escape')],
            [('host-wine/link', tarfile.LNKTYPE, 'host-wine/x')],
            [('host-wine/fifo', tarfile.FIFOTYPE, '')],
        ]:
            path = self.archive(entries)
            out = self.root / 'out'; out.mkdir(exist_ok=True)
            with self.subTest(entries=entries), self.assertRaises((ValueError, tarfile.TarError)):
                reuse.extract_checkpoint(path, out)

    def test_safe_archive_allows_bounded_regular_installation(self):
        path = self.archive([('host-wine/regular', 'file', b'host bytes')])
        out = self.root / 'out'; out.mkdir()
        reuse.extract_checkpoint(path, out)
        self.assertEqual((out / 'host-wine/regular').read_bytes(), b'host bytes')

    def test_selected_zip_members_ignore_unselected_paths_and_check_exact_bytes(self):
        path = self.root / 'payload.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('proof/state.json', b'{}')
            archive.writestr('../not-selected', b'never extracted')
        out = self.root / 'out'; out.mkdir()
        reuse.zip_members(path, ['proof/state.json'], out)
        self.assertEqual((out / 'state.json').read_bytes(), b'{}')
        self.assertFalse((self.root / 'not-selected').exists())
        with self.assertRaises(ValueError):
            reuse.zip_members(path, ['missing'], out)

    def test_download_rejects_artifact_digest_changes(self):
        destination = self.root / 'payload.zip'
        def write(*args, stdout, **kwargs):
            stdout.write(b'zip')
        artifact = {'id': 1, 'size_in_bytes': 3, 'digest': 'sha256:' + '0' * 64}
        with mock.patch.object(reuse.subprocess, 'run', side_effect=write), self.assertRaises(ValueError):
            reuse.download(artifact, destination)

    def test_malformed_data_cleanly_falls_back_without_claiming_reuse(self):
        for error in (ValueError('JSON'), TypeError('shape'), EOFError('gzip'), reuse.zlib.error('deflate')):
            report, output = self.root / 'report.json', self.root / 'output'
            argv = ['reuse', '--repo', str(self.root), '--host-work', str(self.root / 'host'),
                    '--cohort', str(self.root / 'cohort'), '--cache-state', str(self.root / 'cache'),
                    '--report', str(report), '--run', '123']
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(reuse, 'restore', side_effect=error), \
                 mock.patch.dict(os.environ, {'GITHUB_OUTPUT': str(output)}):
                reuse.main()
            value = json.loads(report.read_text())
            self.assertFalse(value['reused'])
            self.assertEqual(value['fallback'], 'unchanged full host build')

    def test_runner_image_identity_is_bound_to_successful_attempt(self):
        logs = ('2026-10-12T09:00:00.000Z ##[group]Runner Image\n'
                '2026-10-12T09:00:00.000Z Image: ubuntu-24.04\n'
                '2026-10-12T09:00:00.000Z Version: 20261004.327.1\n'
                '2026-10-12T09:00:00.000Z ##[endgroup]\n'
                '##[group]Run command --stage host-runtime --\n'
                'env:\n  PATH: /usr/bin\n  pythonLocation: /opt/python\n##[endgroup]\n').encode()
        jobs = {'total_count': 1, 'jobs': [{'name': 'matched-runtime', 'id': 456, 'conclusion': 'success'}]}
        with mock.patch.object(reuse, 'api', return_value=jobs), \
             mock.patch.object(reuse.subprocess, 'check_output', return_value=logs), \
             mock.patch.dict(os.environ, {'ImageOS': 'ubuntu24', 'ImageVersion': '20261004.327.1',
                                          'PATH': '/usr/bin', 'pythonLocation': '/opt/python'}, clear=True):
            self.assertEqual(reuse.runner_identity(self.run)['donor_job_id'], 456)
            with mock.patch.object(reuse.subprocess, 'check_output', return_value=logs.replace(b'\n', b'\r\n')):
                self.assertEqual(reuse.runner_identity(self.run)['donor_job_id'], 456)
            with mock.patch.dict(os.environ, {'ImageVersion': 'different'}), self.assertRaises(ValueError):
                reuse.runner_identity(self.run)


    def test_runner_parser_rejects_ambiguous_or_changed_evidence(self):
        header = '##[group]Runner Image\nImage: ubuntu-24.04\nVersion: same\n##[endgroup]\n'
        body = '##[group]Run command --stage host-runtime --\nenv:\n  PATH: /usr/bin\n##[endgroup]\n'
        jobs = {'total_count': 1, 'jobs': [{'name': 'matched-runtime', 'id': 456, 'conclusion': 'success'}]}
        with mock.patch.dict(os.environ, {'ImageOS': 'ubuntu24', 'ImageVersion': 'same', 'PATH': '/usr/bin'}, clear=True):
            for logs in (body, header + header + body, header, header + body + body,
                         header + body.replace('PATH: /usr/bin', 'PATH: /different'),
                         header + body.replace('  PATH: /usr/bin', '  PATH: /usr/bin\n  PATH: /usr/bin')):
                with mock.patch.object(reuse, 'api', return_value=jobs), \
                     mock.patch.object(reuse.subprocess, 'check_output', return_value=logs.encode()), \
                     self.subTest(logs=logs), self.assertRaises(ValueError):
                    reuse.runner_identity(self.run)
            for malformed in ({'total_count': 0, 'jobs': []},
                              {'total_count': 2, 'jobs': jobs['jobs'] * 2},
                              {'total_count': 1, 'jobs': [{'name': 'matched-runtime', 'id': 456, 'conclusion': 'failure'}]}):
                with mock.patch.object(reuse, 'api', return_value=malformed), self.assertRaises(ValueError):
                    reuse.runner_identity(self.run)

    def test_configure_output_environment_and_workflow_are_exact(self):
        workflow = (ROOT / reuse.WORKFLOW).read_bytes()
        donor = self.archive([(reuse.WORKFLOW, 'file', workflow)])
        repo = self.root / 'repo'; target = repo / reuse.WORKFLOW
        target.parent.mkdir(parents=True); target.write_bytes(workflow)
        work = self.root / 'host'; (work / 'build').mkdir(parents=True)
        config, log = self.root / 'config.status', self.root / 'config.log'
        config.write_bytes(b'exact configure'); (work / 'build/config.status').write_bytes(config.read_bytes())
        log.write_text("ac_cv_env_CFLAGS_set=\nac_cv_env_CFLAGS_value=\n")
        (work / 'build/config.log').write_bytes(log.read_bytes())
        with mock.patch.dict(os.environ, {}, clear=True):
            reuse.configure_contract(donor, repo, config, log, work)
            python_root = '/opt/hostedtoolcache/Python/3.12.15/x64/lib'
            with mock.patch.dict(os.environ, {'PKG_CONFIG_PATH': python_root + '/pkgconfig', 'LD_LIBRARY_PATH': python_root}):
                reuse.configure_contract(donor, repo, config, log, work)
            for bad in ('/unrelated', python_root + ':/unrelated'):
                with mock.patch.dict(os.environ, {'PKG_CONFIG_PATH': python_root + '/pkgconfig', 'LD_LIBRARY_PATH': bad}), self.assertRaises(ValueError):
                    reuse.configure_contract(donor, repo, config, log, work)
            with mock.patch.dict(os.environ, {'CPATH': '/unbound'}), self.assertRaises(ValueError):
                reuse.configure_contract(donor, repo, config, log, work)
            with mock.patch.dict(os.environ, {'PKG_CONFIG_PATH': '/unbound'}), self.assertRaises(ValueError):
                reuse.configure_contract(donor, repo, config, log, work)
            (work / 'build/config.status').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                reuse.configure_contract(donor, repo, config, log, work)


if __name__ == '__main__':
    unittest.main()
