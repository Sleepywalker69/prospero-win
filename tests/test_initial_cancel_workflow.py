#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Source-only checks for the gated same-repository static-build workflow."""
from pathlib import Path
import subprocess
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class StaticWorkflow(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / '.github/workflows/initial-cancel-static.yml').read_text()
        self.workflow = yaml.load(self.text, Loader=yaml.BaseLoader)
        self.steps = self.workflow['jobs']['static-only']['steps']
        self.runs = [step['run'] for step in self.steps if 'run' in step]

    def test_same_repository_opt_in_and_read_only_permissions(self):
        self.assertEqual(set(self.workflow['on']), {'workflow_dispatch', 'pull_request'})
        self.assertEqual(self.workflow['permissions'], {'contents': 'read'})
        gate = self.workflow['jobs']['static-only']['if']
        self.assertIn("github.repository == 'Sleepywalker69/prospero-win'", gate)
        self.assertIn('github.event.pull_request.head.repo.full_name == github.repository', gate)
        self.assertIn('build-initial-cancel-static', gate)

    def test_full_host_gates_and_exact_producer_routes_retained(self):
        combined = '\n'.join(self.runs)
        self.assertIn('make -j2 all', combined)
        self.assertIn('make sanitize', combined)
        for recipe in ('build_owned_helper.py', 'build_initial_cancel.py'):
            for action in ('build', 'verify'):
                self.assertIn('python3 tools/' + recipe + ' ' + action, combined)
        self.assertNotIn('fetch_lapy_helper.py', combined)
        self.assertNotIn('tools/build_native.sh', combined)
        self.assertNotIn('gh release', combined)
        self.assertNotIn('scp ', combined)
        self.assertIn("'target_ready': False", combined)
        self.assertIn("'no_reboot_lifecycle_verified': False", combined)

    def test_existing_action_pins_and_unexpanded_artifact_audience(self):
        allowed = {'actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
                   'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065',
                   'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'}
        self.assertEqual({s['uses'] for s in self.steps if 'uses' in s}, allowed)
        upload = [s for s in self.steps if s.get('uses', '').startswith('actions/upload-artifact@')][0]
        self.assertIn('static-only-no-console', upload['with']['name'])
        self.assertEqual(upload['with']['retention-days'], '7')
        checkout = [s for s in self.steps if s.get('uses', '').startswith('actions/checkout@')][0]
        self.assertEqual(checkout['with']['persist-credentials'], 'false')

    def test_every_shell_block_parses_without_execution(self):
        for index, script in enumerate(self.runs):
            with self.subTest(index=index):
                result = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
