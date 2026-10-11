# SPDX-License-Identifier: LGPL-2.1-or-later
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('splitter', Path(__file__).parents[1] / 'tools/split_verified_artifact.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class SplitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.data = bytes(range(256)) * 3 + b'last'
        self.source = self.root / 'source.zip'
        self.source.write_bytes(self.data)
        self.out = self.root / 'parts'
        self.sha = hashlib.sha256(self.data).hexdigest()

    def run_split(self, **kw):
        args = dict(size=len(self.data), digest=self.sha, part_bytes=200)
        args.update(kw)
        return m.split_verified(self.source, self.out, **args)

    def test_exact_roundtrip(self):
        report = self.run_split()
        self.assertEqual([x['bytes'] for x in report['parts']], [200, 200, 200, 172])
        self.assertEqual(b''.join((self.out / x['name']).read_bytes() for x in report['parts']), self.data)
        for x in report['parts']:
            self.assertEqual(hashlib.sha256((self.out / x['name']).read_bytes()).hexdigest(), x['sha256'])

    def test_wrong_size(self):
        with self.assertRaises(ValueError): self.run_split(size=2)
        self.assertFalse(self.out.exists())

    def test_wrong_hash_retains_unadmitted_parts(self):
        with self.assertRaises(ValueError): self.run_split(digest='0' * 64)
        self.assertTrue(list(self.out.glob('*.part*')))
        self.assertFalse((self.out / 'MANIFEST.json').exists())

    def test_existing_destination(self):
        self.out.mkdir()
        with self.assertRaises(ValueError): self.run_split()

    def test_symlink_source(self):
        link = self.root / 'link'
        link.symlink_to(self.source)
        self.source = link
        with self.assertRaises(ValueError): self.run_split()

    def test_invalid_part_bounds(self):
        for size in (0, -1, m.PART_BYTES + 1):
            with self.assertRaises(ValueError): self.run_split(part_bytes=size)


class NetworkOriginTests(unittest.TestCase):
    """Exact corrected PR92 identity checks, using inert bytes and inline source only."""
    setUp = SplitTests.setUp
    run_split = SplitTests.run_split
    def test_production_pins_and_exact_part_bounds(self):
        self.assertEqual(m.EXPECTED_BYTES, 753752815)
        self.assertEqual(m.EXPECTED_SHA256,
                         'f9329dceb8037d8aafbac782c6e525e4f2fbb013f0a9380a0522c51943e021b7')
        self.assertEqual(m.PART_BYTES, 209715200)
        sizes = [min(m.PART_BYTES, m.EXPECTED_BYTES - i) for i in range(0, m.EXPECTED_BYTES, m.PART_BYTES)]
        self.assertEqual(sizes, [209715200, 209715200, 209715200, 124607215])

    def test_original_and_transport_identities_are_separate(self):
        with patch.dict(os.environ, {'GITHUB_RUN_ID': 'transport-only',
                                     'GITHUB_RUN_ATTEMPT': '3',
                                     'GITHUB_SHA': 'transport-merge'}):
            report = self.run_split()
        self.assertEqual(report['source_artifact_id'], 11708847047)
        self.assertEqual(report['source_run_id'], 38154132915)
        self.assertEqual(report['source_run_attempt'], 1)
        self.assertEqual(report['source_candidate_commit'],
                         '3144a113de87d003c6747c4530abd435d4c9781a')
        self.assertEqual(report['source_compiled_commit'],
                         '2d4854e06f904366be6a78cffd38b23deb9e8c2e')
        self.assertEqual(report['transport'], {'run_id': 'transport-only',
                         'run_attempt': '3', 'commit': 'transport-merge'})
        self.assertEqual(json.loads((self.out / 'MANIFEST.json').read_text()), report)

    def workflow(self):
        return (Path(__file__).parents[1] /
                '.github/workflows/transfer-user-runtime.yml').read_text()

    def test_workflow_exact_transfer_routes_and_no_rebuild(self):
        value = self.workflow()
        self.assertIn('name: Transfer exact existing startup runtime\n', value)
        self.assertIn("github.event.label.name == 'transfer-existing-startup-runtime'", value)
        self.assertIn('permissions:\n  contents: read\n  actions: read\n', value)
        self.assertIn('persist-credentials: false', value)
        self.assertIn('types: [labeled]', value)
        self.assertEqual(value.count('actions/checkout@11d5960a326750d5838078e36cf38b85af677262'), 1)
        self.assertEqual(value.count('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'), 5)
        for i in range(1, 5):
            self.assertIn('name: startup-runtime-byte-part%02d-${{ github.run_id }}' % i, value)
            self.assertIn('path: ${{ runner.temp }}/byte-parts/runtime.zip.part%02d' % i, value)
        self.assertIn('name: startup-runtime-byte-manifest-${{ github.run_id }}', value)
        self.assertEqual(value.count('compression-level: 0'), 4)
        self.assertEqual(value.count('if-no-files-found: error'), 5)
        for forbidden in ('make ', 'unzip ', 'tar ', 'workflow_call:', 'always()',
                          'actions: write', 'contents: write', 'build-windows-child-fixture'):
            self.assertNotIn(forbidden, value)

    def test_workflow_and_splitter_have_no_historical_origin_pins(self):
        value = self.workflow() + (Path(__file__).parents[1] /
                                  'tools/split_verified_artifact.py').read_text()
        for old in ('11698782540', '38128144584', '305bae8546ab52cca97b50fdf3eebe1a9f4f1627', '259cfdbc6f6ff4ef1dcedd32a6a02c4b4c97332e', '1c359aea306d7c029e4532f5aeaa65abf076a22ad04530908a4090093c5fe921', 'transfer-existing-network-runtime', 'network-runtime-byte', '11695207767', '38120712135', '630656649',
                    '4b802bea97f4a4414c632eb5a017218b712f7122',
                    'f3b51781edb94d630dd682af430309f6c5ba59a8',
                    '81cccfdf9300789eaf707ee544e6059682ca147853394a53efba3df4bf281e20',
                    'transfer-existing-user-runtime', 'user-runtime-byte'):
            self.assertNotIn(old, value)
        endpoint = 'gh api repos/Sleepywalker69/prospero-win/actions/artifacts/11708847047'
        self.assertEqual(self.workflow().count(endpoint), 2)

    def test_actual_inline_check_refuses_every_mismatched_origin_field(self):
        raw = self.workflow().split("<<'PYCODE'\n", 1)[1].split('\n          PYCODE', 1)[0]
        code = textwrap.dedent(raw)
        good = {'id': 11708847047, 'workflow_run': {'id': 38154132915,
                'head_sha': '3144a113de87d003c6747c4530abd435d4c9781a'},
                'name': 'windows-child-fixture-2d4854e06f904366be6a78cffd38b23deb9e8c2e-1',
                'expired': False, 'size_in_bytes': 753752815,
                'digest': 'sha256:' + m.EXPECTED_SHA256}
        cases = [good, good | {'id': 11695207767},
                 good | {'workflow_run': good['workflow_run'] | {'id': 38120712135}},
                 good | {'workflow_run': good['workflow_run'] | {'head_sha': '0' * 40}},
                 good | {'name': good['name'][:-1] + '2'}, good | {'expired': True},
                 good | {'size_in_bytes': 630656649},
                 good | {'digest': 'sha256:' + '0' * 64}, {}]
        path = self.root / 'metadata.json'
        for i, item in enumerate(cases):
            path.write_text(json.dumps(item))
            result = subprocess.run([sys.executable, '-B', '-c', code, str(path)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode == 0, i == 0, (i, result.stderr))

    def test_production_cli_refuses_scaled_input_before_output(self):
        script = Path(__file__).parents[1] / 'tools/split_verified_artifact.py'
        result = subprocess.run([sys.executable, '-B', str(script), str(self.source),
                                 str(self.out)], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('exact-size regular file', result.stderr)
        self.assertFalse(self.out.exists())


if __name__ == '__main__':
    unittest.main()
