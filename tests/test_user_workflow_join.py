#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Inert same-attempt USER reference join controls; no network or payload runs."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(os.environ.get('PW_USER_PRODUCER_ROOT', Path(__file__).resolve().parents[1]))
spec = importlib.util.spec_from_file_location('join_test', ROOT / 'tools/wine_workflow_join.py')
join = importlib.util.module_from_spec(spec)
spec.loader.exec_module(join)

class UserJoin(unittest.TestCase):
    def invoke(self, jobs, name='original-user-x64-reference'):
        with tempfile.TemporaryDirectory() as tmp:
            return join.wait_for_reference('owner/repo', '123', '2', Path(tmp)/'join.json',
                request_json=lambda _: {'jobs':jobs,'total_count':len(jobs)}, job_name=name,
                monotonic=lambda: 0, sleep=lambda _: (_ for _ in ()).throw(ValueError('still pending')))
    def job(self, **changes):
        return {'id':5,'name':'original-user-x64-reference','run_id':123,'run_attempt':2,
                'status':'completed','conclusion':'success',**changes}
    def test_own_job_same_attempt(self):
        result=self.invoke([self.job(name='original-x64-reference'),self.job()])
        self.assertTrue(result['success']);self.assertEqual(result['job_name'],'original-user-x64-reference')
    def test_old_success_cannot_substitute(self):
        with self.assertRaises(ValueError):self.invoke([self.job(name='original-x64-reference')])
    def test_failed_user_is_not_old_success(self):
        with self.assertRaises(ValueError):self.invoke([self.job(name='original-x64-reference'),self.job(conclusion='failure')])
    def test_wrong_attempt(self):
        with self.assertRaises(ValueError):self.invoke([self.job(run_attempt=1)])
    def test_wrong_run(self):
        with self.assertRaises(ValueError):self.invoke([self.job(run_id=124)])
    def test_ambiguous(self):
        with self.assertRaises(ValueError):self.invoke([self.job(),self.job()])
    def test_unreviewed_job(self):
        with self.assertRaises(ValueError):self.invoke([self.job()], 'arbitrary-job')
    def test_default_legacy_still_exact(self):
        result=self.invoke([self.job(name='original-x64-reference')], 'original-x64-reference')
        self.assertTrue(result['success']);self.assertEqual(result['job_name'],'original-x64-reference')

if __name__=='__main__':unittest.main()
