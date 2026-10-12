#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Opaque, fail-closed export of one reviewed host compiler cache. No compilation."""
import argparse
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPRedirectHandler, Request
import zipfile
import wine_compile_cache as cache
import reuse_host_wine as reuse

REPO = 'Sleepywalker69/prospero-win'
REF = 'refs/pull/113/merge'
PROOF = Path(__file__).parents[1] / 'docs/host-cache-113-save.json'
MAX_JSON = 16 << 20
MAX_FILES = 250000
MAX_ENTRIES = 300000
MAX_BYTES = 4 << 30
MAX_FILE = 256 << 20
PARTITION = 'b00746243624c07795511efe030575672cc9a3f18458b93705cb126fac7d6d8a'

def require(ok, message):
    if not ok:
        raise ValueError(message)

def canonical(value):
    return cache.canonical(value)

def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('nonfinite JSON value')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('unexpected JSON API redirect')

def api(path):
    require(path.startswith('repos/' + REPO + '/'), 'unexpected API destination')
    request = Request('https://api.github.com/' + path,
                      headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                               'Accept': 'application/vnd.github+json',
                               'X-GitHub-Api-Version': '2022-11-28'})
    with build_opener(NoRedirect).open(request, timeout=60) as response:
        raw = response.read(MAX_JSON + 1)
    require(len(raw) <= MAX_JSON, 'API response exceeds bound')
    return strict_json(raw)

def pages(path, field):
    result = []
    for page in range(1, 21):
        response = api(path + ('&' if '?' in path else '?') + 'per_page=100&page=' + str(page))
        items = response[field]
        require(isinstance(items, list) and len(items) <= 100, 'invalid API page')
        result.extend(items)
        if len(items) < 100:
            require(response.get('total_count', len(result)) == len(result), 'API inventory changed')
            return result
    raise ValueError('API pagination bound exceeded')

def instant(value):
    require(isinstance(value, str) and value.endswith('Z'), 'UTC timestamp required')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))

def component(run, jobs, proof):
    require(run['id'] == proof['run_id'] and run['run_attempt'] == proof['run_attempt'] and
            run['head_sha'] == proof['head'] and run['status'] == 'completed' and
            run['conclusion'] in ('success', 'failure'), 'donor run identity/state differs')
    require(run['repository']['full_name'] == run['head_repository']['full_name'] == REPO and
            run['path'] == '.github/workflows/windows-child-fixture.yml' and
            run['event'] == 'pull_request', 'donor workflow differs')
    matches = [j for j in jobs if j['id'] == proof['job_id']]
    require(len(matches) == 1, 'donor job missing or duplicate')
    job = matches[0]
    require(job['run_id'] == proof['run_id'] and job['run_attempt'] == proof['run_attempt'] and
            job['head_sha'] == proof['head'] and job['name'] == 'matched-runtime' and
            job['status'] == 'completed' and job['conclusion'] in ('success', 'failure'),
            'donor job attempt/state differs')
    for expected in proof['steps']:
        found = [s for s in job['steps'] if s['number'] == expected['number']]
        require(len(found) == 1 and all(found[0].get(k) == v for k, v in expected.items()) and
                found[0]['status'] == 'completed' and found[0]['conclusion'] == 'success',
                'required host component stage differs')
    failed = [s['name'] for s in job['steps'] if s['conclusion'] == 'failure']
    require(all(s['number'] > proof['steps'][-1]['number'] for s in job['steps']
                if s['conclusion'] not in ('success', 'skipped', None)),
            'failure occurred before host checkpoint completed')
    return {'host_component_accepted': True, 'runtime_distribution_accepted': False,
            'donor_run_conclusion': run['conclusion'], 'later_failed_steps': failed}

def cache_entry(entries, proof):
    exact = [v for v in entries if v['key'] == proof['key']]
    require(len(exact) == 1, 'exact cache missing or globally ambiguous')
    value = exact[0]
    require(value['ref'] == REF and isinstance(value['id'], int) and value['id'] > 0 and
            isinstance(value['version'], str) and bool(value['version']) and
            0 < value['size_in_bytes'] <= MAX_BYTES, 'cache scope/version/size differs')
    save = proof['steps'][1]
    created = instant(value['created_at'])
    # API step timestamps have second precision. Treat the final second as
    # [completed_at, completed_at + 1 second), matching the captured .3426455Z log.
    require(instant(save['started_at']) <= created <
            instant(save['completed_at']) + timedelta(seconds=1), 'cache creation outside save window')
    return {k: value[k] for k in ('id', 'key', 'ref', 'version', 'created_at', 'size_in_bytes')}

def current_cache(proof):
    return cache_entry(pages('repos/' + REPO + '/actions/caches?' +
                            urlencode({'key': proof['key']}), 'actions_caches'), proof)

def selected_receipts(archive, destination):
    destination.mkdir()
    names = ('state.json', 'compatibility.json', 'partition.json', 'host-runtime.json')
    with zipfile.ZipFile(archive) as z:
        members = z.infolist()
        require(len(members) <= 20000 and len({m.filename for m in members}) == len(members),
                'evidence ZIP index differs')
        for name in names:
            matches = [m for m in members if m.filename == 'ccache-host/' + name]
            require(len(matches) == 1, 'cache receipt missing')
            item = matches[0]
            require(not item.is_dir() and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG) and
                    0 < item.file_size <= MAX_JSON, 'cache receipt size/type differs')
            with z.open(item) as stream:
                data = stream.read(MAX_JSON + 1)
            require(len(data) == item.file_size, 'cache receipt read differs')
            strict_json(data)
            (destination / name).write_bytes(data)

def receipts(directory, proof):
    state = strict_json((directory / 'state.json').read_bytes())
    identity = cache.checked_identity(directory, state)
    stage = strict_json((directory / 'host-runtime.json').read_bytes())
    project = {'commit': proof['compiled'], 'tree': proof['tree']}
    require(identity['schema'] == state['schema'] == cache.SCHEMA and identity['phase'] == 'host' and
            state['phase'] == 'host' and state['project'] == project and state['key'] == proof['key'] and
            state['partition_sha256'] == PARTITION and
            state['cache_dir'] == '/home/runner/work/_temp/ccache-host', 'host identity differs')
    for key in ('key', 'project', 'partition_key', 'partition_sha256', 'compatibility_sha256', 'restore_prefix', 'phase'):
        require(stage[key] == state[key], 'stage identity differs')
    require(stage['schema'] == 'pw-wine-cache-stage/2' and stage['stage'] == 'host-runtime' and
            stage['exit'] == 0, 'host component receipt not successful')
    reuse.check_invocation(stage['argv'], '/home/runner/work/_temp/wine-source',
                           '/home/runner/work/_temp/wine-host')
    return {'state_sha256': cache.sha(directory / 'state.json'),
            'stage_sha256': cache.sha(directory / 'host-runtime.json'),
            'partition_sha256': state['partition_sha256'],
            'compatibility_sha256': state['compatibility_sha256']}

def inventory(root):
    require(root.is_dir() and not root.is_symlink(), 'cache root is not independent directory')
    result, total, count = {}, 0, 0
    pending = [root]
    paths = []
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                require(count <= MAX_ENTRIES, 'cache entry bound')
                mode = entry.stat(follow_symlinks=False)
                require(not stat.S_ISLNK(mode.st_mode), 'cache link')
                if stat.S_ISDIR(mode.st_mode):
                    pending.append(Path(entry.path))
                else:
                    paths.append(Path(entry.path))
    for path in sorted(paths):
        mode = path.lstat()
        require(not stat.S_ISLNK(mode.st_mode), 'cache link')
        if stat.S_ISDIR(mode.st_mode):
            continue
        name = path.relative_to(root).as_posix()
        require(stat.S_ISREG(mode.st_mode) and mode.st_nlink == 1 and
                re.fullmatch(r'[A-Za-z0-9_./+-]+', name) and
                all(x not in ('', '.', '..') for x in name.split('/')), 'unsafe cache entry')
        require(0 <= mode.st_size <= MAX_FILE and len(result) < MAX_FILES, 'cache file bound')
        total += mode.st_size
        require(total <= MAX_BYTES, 'cache total bound')
        result[name] = {'bytes': mode.st_size, 'sha256': cache.sha(path)}
    require(result and total > 0, 'empty cache')
    return result

def pack(root, destination):
    require(not destination.exists(), 'cache archive exists')
    before = inventory(root)
    with tarfile.open(destination, 'x:gz', format=tarfile.PAX_FORMAT) as archive:
        for name, record in before.items():
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.mtime = record['bytes'], 0o644, 0
            with (root / name).open('rb') as source:
                archive.addfile(item, source)
    require(inventory(root) == before, 'cache changed while exporting')
    # Independently hash each archived member, so read/revert races cannot
    # leave different bytes inside the archive from its recorded inventory.
    with tarfile.open(destination, 'r:gz') as archive:
        seen = {}
        for item in archive:
            require(item.isfile() and item.name in before and item.name not in seen,
                    'archive member differs')
            h = hashlib.sha256()
            with archive.extractfile(item) as source:
                for block in iter(lambda: source.read(1 << 20), b''):
                    h.update(block)
            seen[item.name] = {'bytes': item.size, 'sha256': h.hexdigest()}
    require(seen == before, 'archive bytes differ')
    return before

def prepare(output, proof):
    started = time.monotonic()
    require(not output.exists(), 'export directory exists')
    output.mkdir()
    run = api('repos/' + REPO + '/actions/runs/' + str(proof['run_id']))
    jobs = pages('repos/' + REPO + '/actions/runs/' + str(proof['run_id']) +
                 '/attempts/' + str(proof['run_attempt']) + '/jobs', 'jobs')
    decision = component(run, jobs, proof)
    commit = api('repos/' + REPO + '/git/commits/' + proof['compiled'])
    require(commit['tree']['sha'] == proof['tree'] and
            proof['head'] in [p['sha'] for p in commit['parents']], 'compiled merge identity differs')
    artifacts = pages('repos/' + REPO + '/actions/runs/' + str(proof['run_id']) + '/artifacts', 'artifacts')
    for role, expected in proof['artifacts'].items():
        candidates = [a for a in artifacts if a['id'] == expected['id']]
        require(len(candidates) == 1, 'artifact missing')
        item = candidates[0]
        require(all(item.get(k) == v for k, v in expected.items()) and not item['expired'] and
                item['workflow_run']['id'] == proof['run_id'] and
                item['workflow_run']['head_sha'] == proof['head'], 'artifact identity differs')
        reuse.download(item, output / (role + '.zip'))
    selected_receipts(output / 'evidence.zip', output / 'receipts')
    receipt = {**decision, 'identity': receipts(output / 'receipts', proof),
               'cache': current_cache(proof), 'proof': proof, 'prepare_seconds': time.monotonic() - started,
               'started_monotonic': time.monotonic()}
    (output / 'admission.json').write_bytes(canonical(receipt))

def export(root, output, proof):
    started = time.monotonic()
    admission = strict_json((output / 'admission.json').read_bytes())
    require(os.environ.get('CACHE_HIT') == 'true' and os.environ.get('CACHE_MATCHED_KEY') == proof['key'],
            'exact cache restore required; no compilation fallback')
    require(admission['proof'] == proof and current_cache(proof) == admission['cache'],
            'cache entry changed across restore')
    require(root.resolve() == Path(os.environ['RUNNER_TEMP']) / 'ccache-host' and
            root.resolve() != output.resolve() and root.resolve() not in output.resolve().parents and
            output.resolve() not in root.resolve().parents,
            'cache/export path differs')
    files = pack(root, output / 'compiler-cache.tar.gz')
    require(current_cache(proof) == admission['cache'], 'cache entry changed during export')
    (output / 'inventory.json').write_bytes(canonical(files))
    receipt = {**admission, 'schema': 'pw-host-compiler-cache-export/1',
               'exporter': {k: os.environ.get(k) for k in
                            ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'GITHUB_HEAD_REF', 'GITHUB_REF')},
               'archive': {'bytes': (output / 'compiler-cache.tar.gz').stat().st_size,
                           'sha256': cache.sha(output / 'compiler-cache.tar.gz')},
               'inventory_sha256': cache.sha(output / 'inventory.json'),
               'restore_seconds_including_step_overhead': started - admission['started_monotonic'],
               'export_seconds': time.monotonic() - started,
               'provenance': 'service-mediated donor association; inventory hashes are exporter-observed bytes',
               'consumer_partition_verification_required': True, 'compilation_performed': False}
    (output / 'EXPORT-RECEIPT.json').write_bytes(canonical(receipt))
    print(json.dumps({'export_complete': True, 'archive': receipt['archive'],
                      'host_component_accepted': True, 'runtime_distribution_accepted': False}))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('prepare', 'export'))
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_REPOSITORY') == REPO and
            os.environ.get('GITHUB_EVENT_NAME') == 'pull_request' and
            os.environ.get('GITHUB_REF') == REF, 'same-PR merge-ref execution required')
    proof = strict_json(PROOF.read_bytes())
    if args.action == 'prepare':
        prepare(args.out, proof)
    else:
        export(Path(os.environ['RUNNER_TEMP']) / 'ccache-host', args.out, proof)

if __name__ == '__main__':
    main()
