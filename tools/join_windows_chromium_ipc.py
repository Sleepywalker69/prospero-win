#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fetch completed exact-attempt IPC references with external Actions digest anchors.

Only read-only GitHub API requests and fresh local bounded ZIP writes occur.
Never execute or extract a downloaded member. No failure starts/retries a build.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request
import urllib.parse
from windows_chromium_ipc_contract import REPOSITORY, MAX_ZIP, identity, require, record, validate_bundle


def select_artifacts(reply, project, run, attempt):
    identity(project, run, attempt)
    require(type(reply) is dict and type(reply.get('artifacts')) is list and
            reply.get('total_count') == len(reply['artifacts']) <= 100, 'incomplete artifact API response')
    result = {}
    for arch in ('x64', 'x86'):
        name = f'windows-chromium-ipc-reference-{arch}-{project["commit"]}-{attempt}'
        matches = [item for item in reply['artifacts'] if item.get('name') == name]
        require(len(matches) == 1, 'missing or ambiguous architecture artifact')
        item = matches[0]
        require(item.get('expired') is False and type(item.get('id')) is int and item['id'] > 0 and
                type(item.get('size_in_bytes')) is int and 0 < item['size_in_bytes'] <= MAX_ZIP and
                re.fullmatch('sha256:[0-9a-f]{64}', item.get('digest', '')) and
                str(item.get('workflow_run', {}).get('id')) == run,
                'artifact API identity/digest/availability differs')
        result[arch] = {'id': str(item['id']), 'name': name, 'bytes': item['size_in_bytes'], 'sha256': item['digest'][7:]}
    require(result['x64']['id'] != result['x86']['id'], 'duplicate artifact identity')
    return {'schema': 'pw-chromium-ipc-artifact-anchors/1', 'repository': REPOSITORY, 'project': project,
            'run_id': run, 'run_attempt': attempt, 'artifacts': result}


def join(project, run, attempt, out, *, request_json, request_bytes, monotonic=time.monotonic, sleep=time.sleep):
    identity(project, run, attempt)
    out = Path(out).absolute()
    require(not out.exists() and not out.is_symlink() and out.parent.is_dir(), 'IPC join requires fresh output')
    require(all(not p.is_symlink() for p in out.parents), 'IPC join output has linked ancestor')
    endpoint = f'https://api.github.com/repos/{REPOSITORY}/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100'
    started = last = monotonic()
    while True:
        now = monotonic()
        require(last <= now < started + 900, 'IPC reference join expired or clock regressed'); last = now
        reply = request_json(endpoint)
        require(type(reply) is dict and type(reply.get('jobs')) is list and
                reply.get('total_count') == len(reply['jobs']) <= 100, 'incomplete reference jobs API response')
        done = True
        for arch in ('x64', 'x86'):
            names = {f'windows-reference ({arch})', f'chromium-ipc-reference / windows-reference ({arch})'}
            matches = [job for job in reply['jobs'] if job.get('name') in names]
            require(len(matches) <= 1, 'ambiguous IPC reference job')
            if not matches: done = False; continue
            job = matches[0]
            require(str(job.get('run_id')) == run and str(job.get('run_attempt')) == attempt,
                    'IPC job run/attempt differs')
            if job.get('status') == 'completed':
                require(job.get('conclusion') == 'success', 'IPC reference job failed; no artifact admitted')
            else:
                require(job.get('status') in ('queued', 'in_progress', 'waiting', 'pending'), 'unknown IPC job state')
                done = False
        now = monotonic()
        require(last <= now < started + 900, 'IPC reference join expired or clock regressed'); last = now
        if done: break
        sleep(min(5, started + 900 - now))
    expected = select_artifacts(request_json(f'https://api.github.com/repos/{REPOSITORY}/actions/runs/{run}/artifacts?per_page=100'),
                                project, run, attempt)
    # Fetch and verify all bytes before creating a bundle; failure is never a partial success.
    archives = {}
    for arch, anchor in expected['artifacts'].items():
        data = request_bytes(f'https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{anchor["id"]}/zip')
        require(type(data) is bytes and record(data) == {k: anchor[k] for k in ('bytes', 'sha256')},
                'download differs from Actions artifact API digest')
        archives[arch] = data
    out.mkdir()
    for arch, data in archives.items():
        with (out / (arch + '.zip')).open('xb') as stream: stream.write(data)
    with (out / 'anchors.json').open('x') as stream:
        json.dump(expected, stream, sort_keys=True, indent=2); stream.write('\n')
    return expected


class DownloadRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        require(target.scheme == 'https' and target.hostname and not target.username and not target.password,
                'unsafe artifact redirect')
        result = super().redirect_request(req, fp, code, msg, headers, newurl)
        # Signed artifact URLs do not need and must never receive the GitHub token.
        result.remove_header('Authorization')
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True); parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY, 'IPC join is restricted to the original repository')
    def git(*parts): return subprocess.check_output(['git', '-C', str(args.repo), *parts], text=True, timeout=60).strip()
    require(not git('status', '--porcelain', '--untracked-files=no'), 'IPC join requires clean complete project source')
    project = {'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}')}
    token = os.environ['GH_TOKEN']; opener = urllib.request.build_opener(DownloadRedirect)
    def request(url, maximum):
        req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token,
            'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
        with opener.open(req, timeout=30) as response: raw = response.read(maximum + 1)
        require(len(raw) <= maximum, 'oversized GitHub response')
        return raw
    run, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
    join(project, run, attempt, args.out, request_json=lambda url: json.loads(request(url, 4 << 20)),
         request_bytes=lambda url: request(url, MAX_ZIP))
    result = validate_bundle(args.out, project, args.repo, run, attempt)
    print(json.dumps({'schema': result['schema'], 'project': project, 'run_id': run, 'run_attempt': attempt,
                      'runtime_validated': False, 'console_validated': False}))


if __name__ == '__main__': main()
