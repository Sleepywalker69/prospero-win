# SPDX-License-Identifier: LGPL-2.1-or-later
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import zipfile
import yaml
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).parents[1] / 'tools'))
import export_host_compiler_cache as m

class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proof = m.strict_json(m.PROOF.read_bytes())

    def entry(self, **changes):
        return dict(id=123, key=self.proof['key'], ref=m.REF, version='opaque-version',
                    created_at='2026-10-12T12:16:18Z', size_in_bytes=1024) | changes

    def test_exact_unique_scope_and_save_window(self):
        good = self.entry()
        self.assertEqual(m.cache_entry([good, self.entry(key=good['key'] + '-prefix')], self.proof)['id'], 123)
        for entries in ([], [good, good], [self.entry(ref='refs/heads/main')],
                        [self.entry(created_at='2026-10-12T12:16:13Z')],
                        [self.entry(created_at='2026-10-12T12:16:21Z')],
                        [self.entry(size_in_bytes=0)], [self.entry(version='')]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                m.cache_entry(entries, self.proof)
        self.assertEqual(m.cache_entry([self.entry(created_at='2026-10-12T12:16:20.342645Z')],
                                       self.proof)['id'], 123)

    def fixtures(self):
        p = self.proof
        run = dict(id=p['run_id'], run_attempt=1, head_sha=p['head'], status='completed',
                   conclusion='success', repository={'full_name': m.REPO},
                   head_repository={'full_name': m.REPO},
                   path='.github/workflows/windows-child-fixture.yml', event='pull_request')
        job = dict(id=p['job_id'], run_id=p['run_id'], run_attempt=1, head_sha=p['head'],
                   name='matched-runtime', status='completed', conclusion='success',
                   steps=[s | {'status': 'completed', 'conclusion': 'success'} for s in p['steps']])
        return run, job

    def test_component_success_separate_from_distribution(self):
        run, job = self.fixtures()
        result = m.component(run, [job], self.proof)
        self.assertTrue(result['host_component_accepted'])
        self.assertFalse(result['runtime_distribution_accepted'])
        run['conclusion'] = job['conclusion'] = 'failure'
        job['steps'].append(dict(number=28, name='later target', conclusion='failure'))
        self.assertEqual(m.component(run, [job], self.proof)['later_failed_steps'], ['later target'])
        for state in ('cancelled', 'timed_out', 'in_progress'):
            bad = run | {'conclusion': state}
            with self.assertRaises(ValueError):
                m.component(bad, [job], self.proof)

    def test_attempt_stage_and_timestamp_mismatch(self):
        run, job = self.fixtures()
        variants = []
        bad = copy.deepcopy(job); bad['run_attempt'] = 2; variants.append(bad)
        bad = copy.deepcopy(job); bad['head_sha'] = '0' * 40; variants.append(bad)
        for field, value in (('conclusion', 'skipped'), ('completed_at', '2026-10-12T12:16:22Z'),
                             ('number', 123), ('name', 'other')):
            bad = copy.deepcopy(job); bad['steps'][1][field] = value; variants.append(bad)
        for bad in variants:
            with self.subTest(job=bad), self.assertRaises(ValueError):
                m.component(run, [bad], self.proof)

    def test_pages_complete_or_fail(self):
        with patch.object(m, 'api', side_effect=[{'total_count': 101, 'items': list(range(100))},
                                                {'total_count': 101, 'items': [100]}]):
            self.assertEqual(len(m.pages('repos/' + m.REPO + '/test', 'items')), 101)
        with patch.object(m, 'api', return_value={'total_count': 10, 'items': []}), self.assertRaises(ValueError):
            m.pages('repos/' + m.REPO + '/test', 'items')
        with patch.object(m, 'api', return_value={'total_count': 2000, 'items': list(range(100))}), self.assertRaises(ValueError):
            m.pages('repos/' + m.REPO + '/test', 'items')

    def cache_tree(self):
        root = self.root / 'cache'
        root.mkdir()
        (root / 'a').mkdir()
        (root / 'a' / 'object').write_bytes(b'opaque object')
        return root

    def test_pack_exact_bytes_without_execution(self):
        root = self.cache_tree()
        target = self.root / 'cache.tar.gz'
        files = m.pack(root, target)
        with tarfile.open(target) as archive:
            member = archive.getmember('a/object')
            self.assertEqual(archive.extractfile(member).read(), b'opaque object')
            self.assertEqual(member.mode, 0o644)
        self.assertEqual(files['a/object']['bytes'], 13)
        with self.assertRaises(ValueError):
            m.pack(root, target)

    def test_links_specials_empty_and_bounds(self):
        root = self.cache_tree()
        (root / 'link').symlink_to(root / 'a' / 'object')
        with self.assertRaises(ValueError): m.inventory(root)
        (root / 'link').unlink()
        os.link(root / 'a' / 'object', root / 'hard')
        with self.assertRaises(ValueError): m.inventory(root)
        (root / 'hard').unlink()
        with patch.object(m, 'MAX_FILE', 1), self.assertRaises(ValueError): m.inventory(root)
        with patch.object(m, 'MAX_BYTES', 1), self.assertRaises(ValueError): m.inventory(root)
        with patch.object(m, 'MAX_FILES', 0), self.assertRaises(ValueError): m.inventory(root)
        link = self.root / 'root-link'; link.symlink_to(root, target_is_directory=True)
        with self.assertRaises(ValueError): m.inventory(link)
        with patch.object(m, 'MAX_ENTRIES', 1), self.assertRaises(ValueError): m.inventory(root)
        (root / 'a' / 'object').unlink()
        with self.assertRaises(ValueError): m.inventory(root)

    def test_restore_miss_stops_before_pack(self):
        out = self.root / 'out'; out.mkdir()
        (out / 'admission.json').write_text('{}')
        with patch.dict(os.environ, {'CACHE_HIT': 'false', 'CACHE_MATCHED_KEY': self.proof['key']}), \
             patch.object(m, 'pack') as pack, self.assertRaises(ValueError):
            m.export(self.root / 'cache', out, self.proof)
        pack.assert_not_called()

    def test_strict_json_and_fixed_proof(self):
        for text in ('{"x":1,"x":2}', '{"x":NaN}'):
            with self.assertRaises(ValueError): m.strict_json(text)
        self.assertEqual(self.proof['run_id'], 38241186538)
        self.assertEqual(self.proof['job_id'], 114783912333)
        self.assertIn('Not an original HTTP-byte digest', self.proof['capture']['representation'])
        self.assertEqual(self.proof['save_line'].split('Cache saved with key: ')[1], self.proof['key'])

    def test_receipt_hash_key_stage_and_project_binding(self):
        directory = self.root / 'receipts'; directory.mkdir()
        identity = {'schema': m.cache.SCHEMA, 'phase': 'host', 'recipe': {}}
        partition, prefix, key = m.cache.cache_keys(identity)
        proof = self.proof | {'key': key}
        (directory / 'compatibility.json').write_bytes(m.canonical(identity))
        (directory / 'partition.json').write_bytes(m.canonical(m.cache.cache_partition(identity)))
        state = dict(schema=m.cache.SCHEMA, phase='host', key=key, partition_key=partition,
                     restore_prefix=prefix, project={'commit': proof['compiled'], 'tree': proof['tree']},
                     partition_sha256=m.cache.sha(directory / 'partition.json'),
                     compatibility_sha256=m.cache.sha(directory / 'compatibility.json'),
                     cache_dir='/home/runner/work/_temp/ccache-host')
        stage = {k: state[k] for k in ('key', 'project', 'partition_key', 'partition_sha256',
                                      'compatibility_sha256', 'restore_prefix', 'phase')}
        stage.update(schema='pw-wine-cache-stage/2', stage='host-runtime', exit=0,
                     argv=['timeout', '180m', 'sh', 'tools/build_host_wine.sh', '--source',
                           '/home/runner/work/_temp/wine-source', '--work',
                           '/home/runner/work/_temp/wine-host', '--jobs', '4'])
        (directory / 'state.json').write_bytes(m.canonical(state))
        def write_stage(value):
            (directory / 'host-runtime.json').write_bytes(m.canonical(value))
        write_stage(stage)
        with patch.object(m, 'PARTITION', state['partition_sha256']):
            self.assertEqual(m.receipts(directory, proof)['partition_sha256'], state['partition_sha256'])
            for field, value in (('exit', 1), ('project', {}), ('key', 'wrong'), ('stage', 'early-host-tools'),
                                  ('partition_sha256', '0' * 64), ('argv', [])):
                write_stage(stage | {field: value})
                with self.subTest(field=field), self.assertRaises(ValueError):
                    m.receipts(directory, proof)
            write_stage(stage)
            (directory / 'partition.json').write_bytes(b'{}')
            with self.assertRaises(ValueError):
                m.receipts(directory, proof)

    def test_exact_hit_with_wrong_matched_key_stops(self):
        out = self.root / 'out'; out.mkdir()
        (out / 'admission.json').write_text('{}')
        with patch.dict(os.environ, {'CACHE_HIT': 'true', 'CACHE_MATCHED_KEY': 'other'}), \
             patch.object(m, 'pack') as pack, self.assertRaises(ValueError):
            m.export(self.root / 'cache', out, self.proof)
        pack.assert_not_called()

    def test_changed_cache_id_stops_before_pack(self):
        out = self.root / 'out'; out.mkdir()
        old = self.entry()
        (out / 'admission.json').write_bytes(m.canonical({'proof': self.proof, 'cache': old}))
        with patch.dict(os.environ, {'CACHE_HIT': 'true', 'CACHE_MATCHED_KEY': self.proof['key']}), \
             patch.object(m, 'current_cache', return_value=old | {'id': 124}), \
             patch.object(m, 'pack') as pack, self.assertRaises(ValueError):
            m.export(self.root / 'cache', out, self.proof)
        pack.assert_not_called()

    def test_prepare_success_orchestration(self):
        run, job = self.fixtures()
        artifacts = [v | {'expired': False, 'workflow_run': {'id': self.proof['run_id'],
                     'head_sha': self.proof['head']}} for v in self.proof['artifacts'].values()]
        commit = {'tree': {'sha': self.proof['tree']}, 'parents': [{'sha': self.proof['head']}]}
        out = self.root / 'prepared'
        def download(artifact, path):
            path.write_bytes(b'pinned download mock')
        with patch.object(m, 'api', side_effect=[run, commit]), \
             patch.object(m, 'pages', side_effect=[[job], artifacts]), \
             patch.object(m.reuse, 'download', side_effect=download), \
             patch.object(m, 'selected_receipts') as selected, \
             patch.object(m, 'receipts', return_value={'partition_sha256': m.PARTITION}), \
             patch.object(m, 'current_cache', return_value=self.entry()):
            m.prepare(out, self.proof)
        selected.assert_called_once_with(out / 'evidence.zip', out / 'receipts')
        decision = m.strict_json((out / 'admission.json').read_bytes())
        self.assertTrue(decision['host_component_accepted'])
        self.assertFalse(decision['runtime_distribution_accepted'])
        self.assertGreaterEqual(decision['prepare_seconds'], 0)

    def export_fixture(self):
        root = self.root / 'ccache-host'; root.mkdir()
        (root / 'object').write_bytes(b'opaque object')
        out = self.root / 'export'; out.mkdir()
        entry = self.entry()
        (out / 'admission.json').write_bytes(m.canonical({
            'proof': self.proof, 'cache': entry, 'started_monotonic': time.monotonic(),
            'host_component_accepted': True, 'runtime_distribution_accepted': False}))
        return root, out, entry

    def test_export_success_and_after_pack_cache_change(self):
        root, out, entry = self.export_fixture()
        env = {'CACHE_HIT': 'true', 'CACHE_MATCHED_KEY': self.proof['key'],
               'RUNNER_TEMP': str(self.root)}
        with patch.dict(os.environ, env), patch.object(m, 'current_cache', side_effect=[entry, entry]):
            m.export(root, out, self.proof)
        receipt = m.strict_json((out / 'EXPORT-RECEIPT.json').read_bytes())
        self.assertFalse(receipt['compilation_performed'])
        self.assertTrue(receipt['consumer_partition_verification_required'])
        self.assertGreaterEqual(receipt['restore_seconds_including_step_overhead'], 0)
        self.assertGreaterEqual(receipt['export_seconds'], 0)
        (out / 'EXPORT-RECEIPT.json').unlink()
        (out / 'compiler-cache.tar.gz').unlink()
        with patch.dict(os.environ, env), \
             patch.object(m, 'current_cache', side_effect=[entry, entry | {'id': 124}]), \
             self.assertRaises(ValueError):
            m.export(root, out, self.proof)
        self.assertFalse((out / 'EXPORT-RECEIPT.json').exists())

    def test_zip_receipts_reject_special_modes(self):
        archive = self.root / 'evidence.zip'
        for index, mode in enumerate((0o020600, 0o010600, 0o140600, 0o120600)):
            with zipfile.ZipFile(archive, 'w') as z:
                for name in ('state.json', 'compatibility.json', 'partition.json', 'host-runtime.json'):
                    item = zipfile.ZipInfo('ccache-host/' + name)
                    item.external_attr = mode << 16
                    z.writestr(item, b'{}')
            with self.assertRaises(ValueError):
                m.selected_receipts(archive, self.root / ('receipts-' + str(index)))

    def test_empty_directory_entry_overflow(self):
        root = self.root / 'cache'; root.mkdir()
        for index in range(3):
            (root / str(index)).mkdir()
        with patch.object(m, 'MAX_ENTRIES', 2), self.assertRaisesRegex(ValueError, 'entry bound'):
            m.inventory(root)

    def test_same_cache_output_root_rejected(self):
        root = self.root / 'ccache-host'; root.mkdir()
        entry = self.entry()
        (root / 'admission.json').write_bytes(m.canonical({'proof': self.proof, 'cache': entry}))
        with patch.dict(os.environ, {'CACHE_HIT': 'true', 'CACHE_MATCHED_KEY': self.proof['key'],
                                    'RUNNER_TEMP': str(self.root)}), \
             patch.object(m, 'current_cache', return_value=entry), \
             patch.object(m, 'pack') as pack, self.assertRaises(ValueError):
            m.export(root, root, self.proof)
        pack.assert_not_called()

    def test_workflow_yaml_and_wheel_only_command(self):
        path = Path(__file__).parents[1] / '.github/workflows/export-host-compiler-cache.yml'
        workflow = yaml.safe_load(path.read_text())
        steps = workflow['jobs']['export']['steps']
        install = [s for s in steps if s.get('name') == 'Install only reader dependency']
        self.assertEqual(len(install), 1)
        self.assertEqual(install[0]['run'], 'python -m pip install --only-binary=:all: PyYAML==6.0.1')
        restore = [s for s in steps if s.get('id') == 'restore'][0]
        self.assertEqual(restore['with']['key'], self.proof['key'])
        self.assertTrue(restore['with']['fail-on-cache-miss'])
        self.assertNotIn('restore-keys', restore['with'])

if __name__ == '__main__':
    unittest.main()
