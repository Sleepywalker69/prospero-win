#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Join the successful Windows reference in this exact Actions run attempt."""
import argparse
import json
import os
from pathlib import Path
import re
import time
import urllib.request


def wait_for_reference(repository, run_id, attempt, output, *, request_json,
                       monotonic=time.monotonic, sleep=time.sleep, timeout=900):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('invalid repository')
    if not all(re.fullmatch(r'[1-9][0-9]*', str(x)) for x in (run_id, attempt)):
        raise ValueError('invalid run identity')
    if not 0 < timeout <= 900:
        raise ValueError('invalid join timeout')
    endpoint = f'https://api.github.com/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100'
    started = last = monotonic()
    def sample():
        nonlocal last
        now = monotonic()
        if now < last or now - started >= timeout:
            raise ValueError('Windows reference join expired or clock moved backwards')
        last = now
        return now
    record = {'schema': 'pw-windows-reference-join/1', 'repository': repository,
              'run_id': str(run_id), 'run_attempt': str(attempt), 'endpoint': endpoint,
              'job_name': 'original-x64-reference', 'observations': [], 'success': False}
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        while True:
            sample()
            reply = request_json(endpoint)
            if not isinstance(reply, dict) or not isinstance(reply.get('jobs'), list):
                raise ValueError('malformed jobs response')
            jobs = reply['jobs']
            if reply.get('total_count') != len(jobs) or len(jobs) > 100:
                raise ValueError('incomplete jobs response')
            matches = [j for j in jobs if j.get('name') == record['job_name']]
            if len(matches) > 1:
                raise ValueError('ambiguous reference job')
            if matches:
                job = matches[0]
                if str(job.get('run_id')) != str(run_id) or str(job.get('run_attempt')) != str(attempt):
                    raise ValueError('reference job identity mismatch')
                record['observations'].append({k: job.get(k) for k in
                    ('id', 'run_id', 'run_attempt', 'status', 'conclusion', 'started_at', 'completed_at')})
                if job.get('status') == 'completed':
                    if job.get('conclusion') != 'success':
                        raise ValueError('Windows reference job did not succeed: ' + str(job.get('conclusion')))
                    # A slow response cannot grant success after the absolute budget.
                    sample()
                    record['success'] = True
                    return record
                if job.get('status') not in ('queued', 'in_progress', 'waiting', 'pending'):
                    raise ValueError('unknown reference job status')
            sleep(min(5, timeout - (sample() - started)))
    except Exception as error:
        record['error'] = str(error)
        raise
    finally:
        record['elapsed_seconds'] = last - started
        output.write_text(json.dumps(record, indent=2) + '\n')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('unexpected GitHub API redirect')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    token = os.environ['GH_TOKEN']
    opener = urllib.request.build_opener(NoRedirect)
    def request_json(url):
        request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token,
            'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
        with opener.open(request, timeout=30) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError('oversized jobs response')
        return json.loads(raw)
    result = wait_for_reference(os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_RUN_ID'],
                                os.environ['GITHUB_RUN_ATTEMPT'], args.output, request_json=request_json)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
