#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Actual join/YAML controls with inert API replies; no network or payload runs."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import yaml

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('network_join_control',ROOT/'tools/wine_workflow_join.py')
join=importlib.util.module_from_spec(spec);spec.loader.exec_module(join)


class NetworkJoin(unittest.TestCase):
    def invoke(self,jobs,*,clock=None,reply=None):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'join.json';requests=[]
            def request(endpoint):
                requests.append(endpoint)
                return reply() if reply else {'jobs':jobs,'total_count':len(jobs)}
            try:
                result=join.wait_for_reference('owner/repo','123','2',output,
                    request_json=request,job_name='original-network-x64-reference',
                    monotonic=clock or (lambda:0),timeout=10,
                    sleep=lambda _:(_ for _ in ()).throw(ValueError('still pending')))
                self.assertTrue(result['success']);return result
            except ValueError:
                self.assertIs(json.loads(output.read_text())['success'],False)
                raise
            finally:
                self.assertEqual(requests,['https://api.github.com/repos/owner/repo/actions/runs/123/attempts/2/jobs?per_page=100'])

    def job(self,**changes):
        return {'id':5,'name':'original-network-x64-reference','run_id':123,'run_attempt':2,
                'status':'completed','conclusion':'success',**changes}
    def others(self):return [self.job(name=name) for name in ('original-x64-reference','original-user-x64-reference')]
    def test_exact_attempt_includes_all_reference_jobs(self):
        result=self.invoke(self.others()+[self.job()]);self.assertEqual(result['job_name'],'original-network-x64-reference')
    def test_original_and_user_success_do_not_substitute(self):
        with self.assertRaises(ValueError):self.invoke(self.others())
    def test_network_terminal_failures_refused_with_false_receipt(self):
        for status in ('failure','cancelled','timed_out','skipped','neutral',None):
            with self.subTest(status=status),self.assertRaises(ValueError):
                self.invoke(self.others()+[self.job(conclusion=status)])
    def test_prior_attempt_success_refused(self):
        with self.assertRaises(ValueError):self.invoke(self.others()+[self.job(run_attempt=1)])
    def test_other_run_success_refused(self):
        with self.assertRaises(ValueError):self.invoke(self.others()+[self.job(run_id=124)])
    def test_duplicate_network_job_refused(self):
        with self.assertRaises(ValueError):self.invoke(self.others()+[self.job(),self.job(id=6)])
    def test_pending_network_never_publishes_success(self):
        with self.assertRaises(ValueError):self.invoke(self.others()+[self.job(status='in_progress',conclusion=None)])
    def test_partial_job_inventory_refused(self):
        with self.assertRaises(ValueError):self.invoke([],reply=lambda:{'jobs':[self.job()],'total_count':4})
    def test_success_at_absolute_deadline_refused(self):
        times=iter((0,0,10))
        with self.assertRaises(ValueError):self.invoke([self.job()],clock=lambda:next(times))
    def test_rollback_during_success_response_refused(self):
        times=iter((2,3,2.5))
        with self.assertRaises(ValueError):self.invoke([self.job()],clock=lambda:next(times))


class NetworkWorkflow(unittest.TestCase):
    def setUp(self):
        self.jobs=yaml.load((ROOT/'.github/workflows/windows-child-fixture.yml').read_text(),Loader=yaml.BaseLoader)['jobs']
        self.steps=self.jobs['matched-runtime']['steps']
    def test_same_trusted_trigger_and_fresh_network_msvc(self):
        reference=self.jobs['original-network-x64-reference'];runtime=self.jobs['matched-runtime']
        self.assertEqual(''.join(reference['if'].split()),''.join(runtime['if'].split()))
        self.assertEqual(reference['runs-on'],'windows-2022')
        self.assertNotIn('original-network-x64-reference',runtime.get('needs',[]))
        runs=[s['run'] for s in reference['steps'] if 'run' in s]
        self.assertEqual(runs,['./tools/build_windows_child_network.ps1 -ProjectRoot "$env:GITHUB_WORKSPACE" -Out "$env:RUNNER_TEMP/network-x64" -RunReference'])
        for s in reference['steps']:
            self.assertNotIn('actions/cache',s.get('uses',''));self.assertNotIn('download-artifact',s.get('uses',''))
        upload=reference['steps'][-1]
        self.assertEqual(upload['with']['name'],'original-network-x64-${{ github.sha }}-${{ github.run_attempt }}')
        self.assertEqual(upload['with']['if-no-files-found'],'error')
    def test_six_ordered_joins_and_exact_late_network_preflight(self):
        joins=[i for i,s in enumerate(self.steps) if 'tools/wine_workflow_join.py' in s.get('run','')]
        self.assertEqual(len(joins),6)
        def role(i):
            run=self.steps[i]['run']
            return 'network' if '--job original-network-x64-reference' in run else 'user' if '--job original-user-x64-reference' in run else 'original'
        self.assertEqual([role(i) for i in joins],['original','user','network']*2)
        early,late=[i for i in joins if role(i)=='network']
        host=next(i for i,s in enumerate(self.steps) if '--stage host-runtime --' in s.get('run',''))
        self.assertEqual(early+1,host)
        for i,output in ((early,'early-network-reference-join'),(late,'network-reference-join')):
            step=self.steps[i];self.assertNotIn('if',step);self.assertNotIn('continue-on-error',step)
            self.assertEqual(step['env'],{'GH_TOKEN':'${{ github.token }}'})
            command=' '.join(step['run'].replace('\\\n',' ').split())
            self.assertEqual(command,'python3 tools/wine_workflow_join.py --job original-network-x64-reference --output "$RUNNER_TEMP/fixture-evidence/'+output+'.json"')
        download=self.steps[late+1]
        self.assertTrue(download['uses'].startswith('actions/download-artifact@'))
        self.assertEqual(download['with'],{'name':'original-network-x64-${{ github.sha }}-${{ github.run_attempt }}','path':'${{ runner.temp }}/network-x64'})
        preflight=self.steps[late+2]
        command=' '.join(preflight['run'].replace('\\\n',' ').split())
        self.assertEqual(command,'python3 tools/windows_child_network_contract.py --directory "$RUNNER_TEMP/network-x64" --repo "$GITHUB_WORKSPACE" --report "$RUNNER_TEMP/fixture-evidence/network-preflight.json" --run "$GITHUB_RUN_ID" --attempt "$GITHUB_RUN_ATTEMPT"')
        for step in (download,preflight):self.assertNotIn('if',step);self.assertNotIn('continue-on-error',step)
        consumers=[i for i,s in enumerate(self.steps) if ' export-network ' in s.get('run','') or
                   'PW_WINDOWS_CHILD_NETWORK_DIR' in s.get('env',{}) or 'package_windows_child_fixture.py assemble' in s.get('run','')]
        self.assertTrue(consumers);self.assertEqual(min(consumers),late+3)
        self.assertTrue(all(i>late+2 for i in consumers))
    def test_distinct_prefix_and_source_retention_inputs(self):
        prepare=next(s['run'] for s in self.steps if ' export-network ' in s.get('run',''))
        for text in ('initialize-network','export-network','network-prefix-work','network-console','network-prefix.json'):
            self.assertIn(text,prepare)
        self.assertNotIn('user-prefix-work',prepare);self.assertNotIn('user-console',prepare)
        config=next(s['run'] for s in self.steps if "'network_prefix':" in s.get('run',''))
        for field in ('network_prefix','network_prefix_report','network_fixture','user_prefix','user_fixture'):
            self.assertIn("'"+field+"':",config)
        self.assertIn("'network_enabled': True",config);self.assertIn("'user_enabled': True",config)
        title=next(s['run'] for s in self.steps if 'build_wine_service_child.py --check-title' in s.get('run',''))
        self.assertIn('--network-fixture "$RUNNER_TEMP/network-x64"',title)
        self.assertIn('--user-fixture "$RUNNER_TEMP/user-x64"',title)
        self.assertIn('--run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT"',title)
        self.assertIn('package_windows_child_fixture.py retain-sources',config)
        self.assertLess(config.index('package_windows_child_fixture.py retain-sources'),
                        config.index('package_windows_child_fixture.py assemble'))


if __name__=='__main__':unittest.main(verbosity=2)
