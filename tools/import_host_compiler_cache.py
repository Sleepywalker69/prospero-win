#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Admit one measured compiler-cache export into a fresh disposable cache root."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time
import zipfile
import export_host_compiler_cache as exporter
import wine_compile_cache as cache
import reuse_host_wine as reuse

RUN = 38252843457
HEAD = 'f683b8ff0d2813db4ec0c45b7f61b8fad3bac5b9'
MERGE = '4c16c46b05e1921fbb73d93810d69d3770ae3640'
MERGE_TREE = '2e65e101d05c0b1c869f1acebe6027bca7a6bf08'
JOB = 114823254165
ARTIFACT = {'id': 11748513001,
            'name': 'host-compiler-cache-export-' + MERGE + '-1',
            'size_in_bytes': 730577098,
            'digest': 'sha256:4cf7f471589904e8833fbbf44f83c7d4ac8e5e3536b2e21b4323751c822f5fdf'}
ARCHIVE = {'bytes': 508274483,
           'sha256': 'ed4521a4638057c80686935c2ab4b1872fb90aa26944c0f202b0898734b6c0ec'}
JSON_LIMIT = 32 << 20
FILE_LIMIT = 256 << 20
TOTAL_LIMIT = 4 << 30
COUNT_LIMIT = 250000
MEMBERS = {'compiler-cache.tar.gz', 'inventory.json', 'EXPORT-RECEIPT.json', 'host.zip',
           *('receipts/' + n + '.json' for n in ('state', 'compatibility', 'partition', 'host-runtime'))}

require = exporter.require
canonical = cache.canonical
strict_json = exporter.strict_json

def safe_name(name):
    require(isinstance(name, str) and 0 < len(name) <= 256 and len(name.split('/')) <= 8 and
            re.fullmatch(r'[A-Za-z0-9_./+-]+', name) and not name.startswith('/') and
            all(p not in ('', '.', '..') and not p.endswith('.') for p in name.split('/')),
            'unsafe cache path')
    return name

def fresh_directory(path):
    require(not path.exists() and not path.is_symlink(), 'destination already exists')
    require(path.parent.is_dir() and not path.parent.is_symlink(), 'destination parent differs')
    require(path.parent.resolve() == path.parent.absolute(), 'destination parent alias')
    path.mkdir()

def artifact_admission(run, jobs, artifacts):
    require(run['id'] == RUN and run['run_attempt'] == 1 and run['head_sha'] == HEAD and
            run['status'] == 'completed' and run['conclusion'] == 'success' and
            run['repository']['full_name'] == run['head_repository']['full_name'] == exporter.REPO and
            run['path'] == '.github/workflows/export-host-compiler-cache.yml' and
            run['event'] == 'pull_request', 'export run differs')
    matches = [j for j in jobs if j['id'] == JOB]
    require(len(matches) == 1, 'export job missing')
    job = matches[0]
    require(job['run_id'] == RUN and job['run_attempt'] == 1 and job['head_sha'] == HEAD and
            job['name'] == 'export' and job['status'] == 'completed' and job['conclusion'] == 'success',
            'export job differs')
    for number in (5, 6, 7, 8, 9):
        selected = [s for s in job['steps'] if s['number'] == number]
        require(len(selected) == 1 and selected[0]['conclusion'] == 'success',
                'export stage did not succeed')
    found = [a for a in artifacts if a['id'] == ARTIFACT['id']]
    require(len(found) == 1, 'export artifact absent')
    item = found[0]
    require(all(item.get(k) == v for k, v in ARTIFACT.items()) and not item['expired'] and
            item['workflow_run']['id'] == RUN and item['workflow_run']['head_sha'] == HEAD,
            'export artifact differs')
    return item

def unpack_export(path, output):
    require(path.is_file() and not path.is_symlink() and
            path.stat().st_size == ARTIFACT['size_in_bytes'] and
            'sha256:' + cache.sha(path) == ARTIFACT['digest'], 'export ZIP bytes differ')
    with zipfile.ZipFile(path) as z:
        members = z.infolist()
        require(len(members) == len(MEMBERS) and {m.filename for m in members} == MEMBERS,
                'export ZIP members differ')
        for item in members:
            require(stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG) and
                    not item.is_dir() and not item.flag_bits & 1, 'ZIP member is not regular')
            limit = ARCHIVE['bytes'] if item.filename == 'compiler-cache.tar.gz' else (
                209799066 if item.filename == 'host.zip' else JSON_LIMIT)
            require(0 < item.file_size <= limit, 'ZIP member bound')
        fresh_directory(output)
        for item in members:
            target = output / item.filename
            target.parent.mkdir(exist_ok=True)
            total = 0
            with z.open(item) as source, target.open('xb') as destination:
                for block in iter(lambda: source.read(1 << 20), b''):
                    total += len(block)
                    require(total <= item.file_size, 'ZIP expanded beyond member bound')
                    destination.write(block)
            require(total == item.file_size, 'ZIP member truncated')

def read_receipt(output):
    receipt = strict_json((output / 'EXPORT-RECEIPT.json').read_bytes())
    require(receipt['schema'] == 'pw-host-compiler-cache-export/1' and
            receipt['host_component_accepted'] is True and
            receipt['runtime_distribution_accepted'] is False and
            receipt['compilation_performed'] is False and
            receipt['consumer_partition_verification_required'] is True and
            receipt['archive'] == ARCHIVE, 'export receipt claims differ')
    expected = {'GITHUB_RUN_ID': str(RUN), 'GITHUB_RUN_ATTEMPT': '1',
                'GITHUB_SHA': MERGE, 'GITHUB_REF': exporter.REF,
                'GITHUB_HEAD_REF': 'review/child-net-targets-host-reuse-20261012'}
    require(receipt['exporter'] == expected, 'export receipt producer differs')
    proof = strict_json(exporter.PROOF.read_bytes())
    require(receipt['proof'] == proof, 'original reviewed donor proof differs')
    require(receipt['identity'] == exporter.receipts(output / 'receipts', proof),
            'donor receipt hashes differ')
    require(exporter.cache_entry([receipt['cache']], proof) == receipt['cache'],
            'exported cache metadata differs')
    require(re.fullmatch('[0-9a-f]{64}', receipt['cache']['version']), 'cache version format differs')
    host = proof['artifacts']['host']
    require((output / 'host.zip').stat().st_size == host['size_in_bytes'] and
            'sha256:' + cache.sha(output / 'host.zip') == host['digest'],
            'original host/source envelope differs')
    require((output / 'compiler-cache.tar.gz').stat().st_size == ARCHIVE['bytes'] and
            cache.sha(output / 'compiler-cache.tar.gz') == ARCHIVE['sha256'],
            'compiler archive bytes differ')
    require(cache.sha(output / 'inventory.json') == receipt['inventory_sha256'],
            'inventory hash differs')
    return receipt

def manifest(value):
    require(isinstance(value, dict) and 0 < len(value) <= COUNT_LIMIT, 'inventory count/type differs')
    folded, prefixes, total = set(), {}, 0
    for name, item in value.items():
        safe_name(name)
        require(name.casefold() not in folded, 'case-colliding cache path')
        folded.add(name.casefold())
        parts = name.split('/')
        for length in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:length])
            folded_prefix = prefix.casefold()
            require(prefixes.get(folded_prefix, prefix) == prefix, 'case-aliased path component')
            prefixes[folded_prefix] = prefix
        require(isinstance(item, dict) and set(item) == {'bytes', 'sha256'} and
                type(item['bytes']) is int and 0 <= item['bytes'] <= FILE_LIMIT and
                isinstance(item['sha256'], str) and re.fullmatch('[0-9a-f]{64}', item['sha256']),
                'inventory record differs')
        total += item['bytes']
        require(total <= TOTAL_LIMIT, 'inventory byte bound')
    for name in value:
        require(all(str(p) not in value for p in PurePosixPath(name).parents if str(p) != '.'),
                'file/directory path alias')
    require(total > 0, 'empty inventory')
    return total

def scan_cache(path, expected, destination=None):
    manifest(expected)
    seen = set()
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            name = safe_name(member.name)
            require(name in expected and name not in seen and len(seen) < COUNT_LIMIT and
                    member.type == tarfile.REGTYPE and not member.linkname and not member.pax_headers and
                    member.mode == 0o644 and member.uid == member.gid == member.mtime == 0 and
                    not member.uname and not member.gname and member.size == expected[name]['bytes'],
                    'cache TAR member differs')
            seen.add(name)
            h, count = hashlib.sha256(), 0
            destination_file = None
            if destination is not None:
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                destination_file = target.open('xb')
            try:
                with archive.extractfile(member) as source:
                    for block in iter(lambda: source.read(1 << 20), b''):
                        count += len(block)
                        require(count <= member.size, 'cache TAR member overflow')
                        h.update(block)
                        if destination_file:
                            destination_file.write(block)
            finally:
                if destination_file:
                    destination_file.close()
            require(count == member.size and h.hexdigest() == expected[name]['sha256'],
                    'cache member hash differs')
    require(seen == set(expected), 'cache TAR missing member')

def bind_fresh_identity(output, fresh):
    old = strict_json((output / 'receipts/state.json').read_bytes())
    new = strict_json((fresh / 'state.json').read_bytes())
    donor = cache.checked_identity(output / 'receipts', old)
    current = cache.checked_identity(fresh, new)
    require(current == donor, 'fresh compiler, config, flags, headers or source recipe differs')
    require(new['phase'] == 'host' and new['partition_sha256'] == old['partition_sha256'] ==
            exporter.PARTITION and new['cache_dir'] == old['cache_dir'],
            'fresh host partition or absolute cache path differs')
    return new

def import_cache(output, fresh):
    started = time.monotonic()
    receipt = read_receipt(output)
    expected = strict_json((output / 'inventory.json').read_bytes())
    total = manifest(expected)
    scan_cache(output / 'compiler-cache.tar.gz', expected)
    state = bind_fresh_identity(output, fresh)
    root = Path(state['cache_dir'])
    require(root.resolve() != output.resolve() and root.resolve() not in output.resolve().parents and
            output.resolve() not in root.resolve().parents, 'cache/output overlap')
    fresh_directory(root)
    scan_cache(output / 'compiler-cache.tar.gz', expected, root)
    record = {'schema': 'pw-host-cache-import/1', 'source_artifact': ARTIFACT, 'source_archive': ARCHIVE,
              'source_run': RUN, 'source_head': HEAD, 'source_merge': MERGE,
              'cache': receipt['cache'], 'files': len(expected), 'bytes': total,
              'fresh_partition_sha256': state['partition_sha256'],
              'recipe_identity_equal': True, 'elapsed_seconds': time.monotonic() - started,
              'original_runtime_installed': False, 'compilation_performed': False}
    (output / 'IMPORT-RECEIPT.json').write_bytes(canonical(record))
    require(len(canonical(record)) <= 16 << 10, 'public import receipt exceeds log bound')
    print('PW_CACHE_IMPORT ' + json.dumps(record, sort_keys=True))
    return record

def download_export(path):
    base = 'repos/' + exporter.REPO + '/actions/runs/' + str(RUN)
    run = exporter.api(base)
    jobs = exporter.pages(base + '/attempts/1/jobs', 'jobs')
    artifacts = exporter.pages(base + '/artifacts', 'artifacts')
    item = artifact_admission(run, jobs, artifacts)
    merge = exporter.api('repos/' + exporter.REPO + '/git/commits/' + MERGE)
    require(merge['tree']['sha'] == MERGE_TREE and HEAD in [p['sha'] for p in merge['parents']], 'export merge does not contain reviewed head')
    reuse.download(item, path)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('download', 'import'))
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--fresh', type=Path)
    args = parser.parse_args()
    if args.action == 'download':
        archive = args.out.with_suffix('.zip')
        download_export(archive)
        unpack_export(archive, args.out)
        read_receipt(args.out)
    else:
        require(args.fresh is not None, 'fresh compiler identity required')
        import_cache(args.out, args.fresh)

if __name__ == '__main__':
    main()
