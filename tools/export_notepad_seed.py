#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Verify fixed producer inputs and export one fresh original Notepad prefix.

No network, Wine invocation, vendor executable, console connection or overwrite.
The separate hosted workflow performs genuine initialization before export.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile
import zipfile

sys.dont_write_bytecode = True
REPOSITORY = 'Sleepywalker69/prospero-win'
RUN = 37861508535
HEAD = '5319496afdd0b6db4a6f742633b9d4e77d959547'
PROJECT = '578c593f7d8588c529f0c12413f71c8692817224'
TREE = '93a62a15aff0376316b7504aba4e3dd35779750b'
WINE = '490f6d5dcbb2a5047345b8af88d114bbcaad69a8'
SLUG = 'diagnostic-notepad'
INPUTS = {
    'checkpoint': (11587963904, '4d4360761d8fcd24259ec50cf1616ed855f6e79dee7d90c0c106ae985b97cd1f',
                   'host-wine-checkpoint.tar.gz', 'host-checkpoint'),
    'kit': (11588549010, 'fcdbc6b853150618df471dac460744e40aab83dd7c0289963afa9ac0067a6cc0',
            'prospero-software-gdi-diagnostic.tar.gz', 'software-gdi-kit'),
}
BOUND_FILES = {
    'pc/tools/pw_prefix.py': 'f374f7eac0f58592151479c3f783f4bf4eb8170d9678901cc97ea6334689c574',
    'pc/tools/pw_install.py': 'af36f281d4806c1add5b7eb5a3a9fa12a7a5c6b60c908b707e5e924fef7733b2',
    'pc/recipes/diagnostic-notepad.yml': 'cf2c9a13b5cf7cd7b74901183570635e6d23c6d0654f8eb15372ba5e8f1b62e9',
    'sources/prospero-win.tar.gz': '2e421c35c2b5ff21346b93ed065aae85cfcf455f2918f9fd849dbd82de847864',
    'sources/wine.tar.gz': 'f0f29664a35550b0e221ac203427079cf2a090feb7f2c25fde003615dfa8dbf9',
}
CPU_SHA = '7fdd490b6a1eeff78f8de585f7f5624d03a11239520287fc61ff12abb4c13226'
MAX_FILES, MAX_BYTES, MAX_FILE = 16000, 4 << 30, 256 << 20
REGISTRIES = {'system.reg', 'user.reg', 'userdef.reg'}
GENERATED_TEXT = {'drive_c/windows/win.ini', 'drive_c/windows/system.ini'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda: stream.read(1 << 20), b''):
            digest.update(data)
    return digest.hexdigest()


def safe_relative(name):
    require(isinstance(name, str) and name and '\\' not in name and
            not any(ord(c) < 32 or ord(c) == 127 for c in name), 'invalid relative name')
    while name.startswith('./'):
        name = name[2:]
    parts = name.split('/')
    require(name and not name.startswith('/') and all(p not in ('', '.', '..') for p in parts),
            'unsafe relative name')
    return PurePosixPath(name)


def read_json(path):
    require(path.is_file() and path.stat().st_size <= 16 << 20, 'missing/oversized JSON')
    return json.loads(path.read_text())


def metadata(run, artifacts):
    require(run.get('id') == RUN and run.get('head_sha') == HEAD and
            run.get('status') == 'completed' and run.get('conclusion') == 'success' and
            run.get('run_attempt') == 1 and run.get('path') == '.github/workflows/diagnostic-kit.yml' and
            run.get('repository', {}).get('full_name') == REPOSITORY, 'wrong producer run')
    records = {a['id']: a for a in artifacts.get('artifacts', [])}
    for artifact_id, digest, _, _ in INPUTS.values():
        a = records.get(artifact_id, {})
        require(a.get('digest') == 'sha256:' + digest and not a.get('expired', True) and
                a.get('workflow_run', {}).get('id') == RUN and
                a.get('workflow_run', {}).get('head_sha') == HEAD and
                a.get('workflow_run', {}).get('repository_id') == 1410835302 and
                a.get('workflow_run', {}).get('head_repository_id') == 1410835302,
                'wrong/expired bound artifact')


def unpack(archive, output, digest, member):
    require(sha(archive) == digest, 'outer artifact SHA256 mismatch')
    require(not output.exists(), 'extraction output already exists')
    output.mkdir()
    with zipfile.ZipFile(archive) as zipped:
        entries = zipped.infolist()
        require(len(entries) == 1 and entries[0].filename == member and
                entries[0].file_size <= MAX_BYTES, 'unexpected outer artifact layout')
        # Keep tar bytes local to the owned input directory; never execute them.
        tar_path = output.parent / (output.name + '.tar.gz')
        with zipped.open(entries[0]) as source, tar_path.open('xb') as dest:
            shutil.copyfileobj(source, dest, 1 << 20)
    with tarfile.open(tar_path, 'r:gz') as tar:
        entries = tar.getmembers()
        require(len(entries) <= MAX_FILES, 'too many archive entries')
        seen, total = set(), 0
        for entry in entries:
            if entry.name.rstrip('/') in ('.', ''):
                require(entry.isdir(), 'bad archive root')
                continue
            rel = str(safe_relative(entry.name.rstrip('/')))
            require(rel not in seen, 'duplicate archive path')
            seen.add(rel)
            require(entry.isdir() or entry.isfile() or entry.issym(), 'special/hardlink archive member')
            require(not entry.mode & 0o7000, 'special file permission bits')
            require(0 <= entry.size <= MAX_FILE, 'oversized archive member')
            total += entry.size
            require(total <= MAX_BYTES, 'oversized archive')
            if entry.issym():
                require(not entry.linkname.startswith('/') and '\\' not in entry.linkname,
                        'absolute archive symlink')
                target = (output / rel).parent / entry.linkname
                require(target.resolve().is_relative_to(output.resolve()), 'archive symlink escape')
        tar.extractall(output, filter='data')
    for path in output.rglob('*'):
        if path.is_symlink():
            require(path.resolve(strict=True).is_relative_to(output.resolve()), 'extracted symlink escape')


def verify_tree(root, scope):
    manifest = read_json(root / 'KIT-MANIFEST.json')
    require(manifest.get('schema') == 'pw-diagnostic-kit/1' and manifest.get('scope') == scope and
            manifest.get('project') == {'repository': 'https://github.com/' + REPOSITORY,
                                        'commit': PROJECT, 'tree': TREE} and
            manifest.get('wine_commit') == WINE and manifest.get('prefix_included') is False,
            'producer manifest/source identity mismatch')
    files = read_json(root / 'FILES.json')
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    require(actual == set(files) | {'FILES.json', 'SHA256SUMS'}, 'manifest coverage differs')
    for name, record in files.items():
        rel = safe_relative(name)
        path = root / rel
        require(path.resolve(strict=True).is_relative_to(root.resolve()) and path.is_file(), 'manifest file escape')
        require(sha(path) == record['sha256'] and oct(stat.S_IMODE(path.stat().st_mode)) == record['mode'],
                'manifest content/mode mismatch: ' + name)
    for name, digest in BOUND_FILES.items():
        require(sha(root / name) == digest, 'bound original source changed: ' + name)
    return manifest, files


def prepare(args):
    metadata(read_json(args.run_json), read_json(args.artifacts_json))
    require(not args.work.exists(), 'work directory must be absent')
    args.work.mkdir()
    for kind, (_, digest, member, scope) in INPUTS.items():
        unpack(getattr(args, kind + '_zip'), args.work / kind, digest, member)
        verify_tree(args.work / kind, scope)
    require(sha(args.work / 'kit/pc/wowprospero.dll') == CPU_SHA, 'wrong CPU DLL')
    checkpoint = args.work / 'checkpoint'
    host = checkpoint / 'pc/host-wine/usr'
    # The later kit must carry the exact host runtime retained in the checkpoint.
    checkpoint_files = read_json(checkpoint / 'FILES.json')
    kit_files = read_json(args.work / 'kit/FILES.json')
    for name, record in checkpoint_files.items():
        if name.startswith('pc/host-wine/usr/'):
            require(kit_files.get(name) == record, 'checkpoint/kit host runtime mismatch')
    for relative in ['sterile/home', 'sterile/cache', 'sterile/config', 'sterile/data', 'sterile/tmp']:
        (args.work / relative).mkdir(parents=True, exist_ok=False)
    # Only shipped Wine fonts are exposed through fontconfig. No host-home config.
    from xml.sax.saxutils import escape
    fonts = '<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd"><fontconfig>'
    fonts += '<dir>' + escape(str(host.resolve() / 'share/wine/fonts')) + '</dir>'
    fonts += '<cachedir>' + escape(str((args.work / 'sterile/cache/fontconfig').resolve())) + '</cachedir></fontconfig>'
    (args.work / 'sterile/fonts.conf').write_text(fonts)
    (args.work / 'INPUTS-VERIFIED.json').write_text(json.dumps({
        'run': RUN, 'producer_head': HEAD, 'project_commit': PROJECT, 'project_tree': TREE,
        'artifacts': {k: {'id': v[0], 'sha256': v[1]} for k, v in INPUTS.items()}}, indent=2) + '\n')


class FilesystemRemote:
    """Only a fresh owned export root, never a console or existing prefix."""
    def __init__(self, root):
        self.root = Path(root).resolve()
        require(not self.root.exists(), 'export root already exists')
        self.root.mkdir()

    def path(self, remote):
        require(remote == '/data/prospero-win' or remote.startswith('/data/prospero-win/'), 'remote root escape')
        rel = safe_relative(remote.lstrip('/'))
        path = self.root / rel
        require(path.resolve().is_relative_to(self.root), 'filesystem remote escape')
        cursor = self.root
        for part in rel.parts:
            cursor /= part
            require(not cursor.is_symlink(), 'filesystem remote symlink')
        return path

    def exists(self, remote):
        return self.path(remote).exists()

    def size(self, remote):
        path = self.path(remote)
        return path.stat().st_size if path.is_file() else None

    def makedirs(self, remote):
        self.path(remote).mkdir(parents=True, exist_ok=True)

    def write(self, remote, data):
        with self.path(remote).open('xb') as stream:
            stream.write(data)

    def write_stream(self, remote, stream):
        with self.path(remote).open('xb') as dest:
            shutil.copyfileobj(stream, dest, 1 << 20)

    def read(self, remote):
        return self.path(remote).read_bytes()

    def listdir(self, remote):
        return {p.name: ('dir' if p.is_dir() else 'file', p.stat().st_size if p.is_file() else 0)
                for p in self.path(remote).iterdir()}

    def delete(self, remote):
        raise ValueError('deletion is never supported by seed export')


def load_converter(root):
    path = root / 'pc/tools/pw_prefix.py'
    require(sha(path) == BOUND_FILES['pc/tools/pw_prefix.py'], 'converter hash mismatch')
    spec = importlib.util.spec_from_file_location('original_pw_prefix', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def audit_text(data, name):
    require(len(data) <= 16 << 20, 'oversized generated text: ' + name)
    text = data.decode('utf-8')
    # Registry backslashes are doubled. Normalize solely for inspection.
    folded = text.replace('\\', '/').lower()
    folded = re.sub('/+', '/', folded)
    require(not any(x in folded for x in ('/home/', '/root/', '/tmp/', '/run/', '/opt/', '/usr/', '/etc/',
                                          '/mnt/', '/workspace/', '/github/', 'github_token', 'runner_temp')),
            'host path/environment in generated text: ' + name)
    require('\x00' not in text, 'NUL in generated text')


def wine_resources(path):
    """Read only bounded WINE_DATA_FILE and WINE_MANIFEST resource bytes.

    Matches pinned Wine setupapi/queue.c:do_file_copy and
    setupapi/fakedll.c:register_manifest. No PE execution or general loading.
    """
    data = path.read_bytes()
    if len(data) < 64 or data[:2] != b'MZ':
        return []
    def integer(at, size):
        require(0 <= at <= len(data) - size, 'truncated PE resource input')
        return int.from_bytes(data[at:at + size], 'little')
    pe = integer(60, 4)
    if pe > len(data) - 24 or data[pe:pe + 4] != b'PE\0\0':
        return []
    sections, optional_size = integer(pe + 6, 2), integer(pe + 20, 2)
    require(0 < sections <= 96, 'invalid PE section count')
    optional = pe + 24
    magic = integer(optional, 2)
    require(magic in (0x10b, 0x20b), 'unsupported PE resource format')
    directory = optional + (96 if magic == 0x10b else 112)
    require(directory + 24 <= optional + optional_size, 'missing PE resource directory')
    resource_rva, resource_size = integer(directory + 16, 4), integer(directory + 20, 4)
    if not resource_rva or not resource_size:
        return []
    require(resource_size <= 16 << 20, 'oversized PE resources')
    ranges = []
    for index in range(sections):
        at = optional + optional_size + 40 * index
        ranges.append((integer(at + 12, 4), integer(at + 20, 4), integer(at + 16, 4)))
    def rva(at, size):
        matches = [raw + at - va for va, raw, length in ranges if va <= at and size <= length - (at - va)]
        require(len(matches) == 1 and matches[0] <= len(data) - size, 'unmapped/ambiguous PE resource')
        return matches[0]
    base = rva(resource_rva, resource_size)
    def resource_integer(offset, size):
        require(0 <= offset <= resource_size - size, 'resource directory escape')
        return integer(base + offset, size)
    def resource_name(value):
        if not value & 0x80000000:
            return value
        offset = value & 0x7fffffff
        length = resource_integer(offset, 2)
        require(length <= 128 and offset + 2 + 2 * length <= resource_size, 'bad resource name')
        return data[base + offset + 2:base + offset + 2 + 2 * length].decode('utf-16le')
    found, visited = [], set()
    def walk(offset, keys):
        require(len(keys) <= 2 and offset not in visited, 'cyclic/deep resource directory')
        visited.add(offset)
        count = resource_integer(offset + 12, 2) + resource_integer(offset + 14, 2)
        require(count <= 4096, 'oversized resource directory')
        for index in range(count):
            entry = offset + 16 + 8 * index
            name = resource_name(resource_integer(entry, 4))
            child = resource_integer(entry + 4, 4)
            path_keys = keys + [name]
            if not keys and name not in ('WINE_DATA_FILE', 24):
                continue
            if len(path_keys) == 2 and path_keys[0] == 24 and not (
                    isinstance(name, str) and name.startswith('WINE_MANIFEST')):
                continue
            if child & 0x80000000:
                walk(child & 0x7fffffff, path_keys)
            else:
                require(len(path_keys) == 3, 'unexpected resource leaf depth')
                payload_rva = resource_integer(child, 4)
                payload_size = resource_integer(child + 4, 4)
                require(payload_size <= 4 << 20, 'oversized copied resource')
                start = rva(payload_rva, payload_size)
                found.append((path_keys[0], data[start:start + payload_size]))
    walk(0, [])
    return found


def resource_hashes(host, host_files):
    allowed = {}
    for name in sorted(host_files):
        if not name.startswith('pc/host-wine/usr/lib/wine/'):
            continue
        relative = name.removeprefix('pc/host-wine/usr/')
        path = host / relative
        if path.suffix.lower() not in ('.dll', '.exe', '.sys', '.drv', '.ocx', '.cpl'):
            continue
        architecture = 'amd64' if '/x86_64-windows/' in name else 'x86'
        for kind, content in wine_resources(path):
            candidates = [content]
            if kind == 24:
                # Pinned register_manifest inserts the current architecture
                # only when processorArchitecture is empty; retain all bytes.
                candidates.append(re.sub(rb'processorArchitecture=([\'"])\1',
                    lambda m: b'processorArchitecture=' + m[1] + architecture.encode() + m[1], content, count=1))
            for candidate in candidates:
                digest = hashlib.sha256(candidate).hexdigest()
                allowed.setdefault(digest, {'module': relative, 'resource_type': str(kind)})
    return allowed


def audit_source(converter, prefix, host, host_files, resources=None):
    files, directories, links = converter.local_tree(prefix)
    require(len(files) <= MAX_FILES and len(directories) <= MAX_FILES, 'prefix too large')
    approved = {record['sha256'] for name, record in host_files.items() if name.startswith('pc/host-wine/usr/')}
    resources = resources or {}
    audit, total, folded_paths = {}, 0, set()
    for path in prefix.rglob('*'):
        if '.wineserver' in path.relative_to(prefix).parts:
            continue
        require(path.is_symlink() or path.is_dir() or stat.S_ISREG(path.lstat().st_mode),
                'special object in fresh prefix')
    virtual_paths = {str(PurePosixPath(directory) / name)
                     for directory, table in links.items() for name in table}
    for name in sorted(set(files) | (set(directories) - {''}) | virtual_paths):
        safe_relative(name)
        require(name.casefold() not in folded_paths, 'case-colliding prefix path')
        folded_paths.add(name.casefold())
    folded_paths.clear()
    for name, path in sorted(files.items()):
        safe_relative(name)
        require(name.casefold() not in folded_paths, 'case-colliding prefix files')
        folded_paths.add(name.casefold())
        resolved = path.resolve(strict=True)
        require(resolved.is_relative_to(prefix.resolve()) or resolved.is_relative_to(host.resolve()),
                'unapproved dereferenced file: ' + name)
        mode = resolved.stat().st_mode
        require(stat.S_ISREG(mode) and resolved.stat().st_size <= MAX_FILE, 'nonregular/oversized prefix file')
        total += resolved.stat().st_size
        require(total <= MAX_BYTES, 'prefix byte limit')
        digest = sha(resolved)
        if name in REGISTRIES:
            data = resolved.read_bytes()
            require(data.startswith(b'WINE REGISTRY Version 2'), 'invalid registry header')
            audit_text(data, name)
            source = 'generated-registry'
        elif name == '.update-timestamp':
            require(re.fullmatch(rb'[0-9]+\n?', resolved.read_bytes()), 'invalid initialization timestamp')
            source = 'generated-timestamp'
        elif name in GENERATED_TEXT:
            audit_text(resolved.read_bytes(), name)
            source = 'generated-ini'
        else:
            # Every copied PE/font/data file must match the hash-bound runtime.
            require(digest in approved or digest in resources, 'unapproved generated/copied file: ' + name)
            source = 'bound-host-runtime' if digest in approved else 'bound-runtime-resource'
        audit[name] = {'sha256': digest, 'bytes': resolved.stat().st_size, 'source': source}
        if source == 'bound-runtime-resource':
            audit[name]['origin'] = resources[digest]
    require(REGISTRIES <= set(files), 'missing initialized registry')
    core = {'drive_c/windows/system32/notepad.exe': 'x86_64-windows/notepad.exe',
            'drive_c/windows/system32/kernel32.dll': 'x86_64-windows/kernel32.dll',
            'drive_c/windows/syswow64/kernel32.dll': 'i386-windows/kernel32.dll'}
    for required, original in core.items():
        require(required in files, 'missing initialized module: ' + required)
        record = host_files.get('pc/host-wine/usr/lib/wine/' + original, {})
        require(audit[required]['sha256'] == record.get('sha256'), 'wrong initialized core module: ' + required)
    for directory in directories:
        if directory:
            safe_relative(directory)
    require(sum(len(t) for t in links.values()) <= 64, 'virtual link count exceeds runtime limit')
    for directory, table in links.items():
        formatted = ''.join(f'{name}\t{target}\n' for name, target in table.items()).encode()
        require(len(formatted) < 4096, 'virtual link table exceeds runtime buffer')
        for name, target in table.items():
            safe_relative(str(PurePosixPath(directory) / name))
            require(not any(ord(c) < 32 or ord(c) == 127 for c in target), 'control byte in link target')
            require(target == '/' and directory == 'dosdevices' and name == 'z:' or
                    not target.startswith('/') and (prefix / directory / target).resolve().is_relative_to(prefix.resolve()),
                    'unapproved virtual link target')
    require(links.get('dosdevices', {}).get('c:') == '../drive_c' and
            links.get('dosdevices', {}).get('z:') == '/', 'missing canonical DOS mappings')
    return audit


def export(args):
    checkpoint, kit = args.work / 'checkpoint', args.work / 'kit'
    _, host_files = verify_tree(checkpoint, 'host-checkpoint')
    verify_tree(kit, 'software-gdi-kit')
    require(sha(kit / 'pc/wowprospero.dll') == CPU_SHA, 'CPU DLL changed')
    require(not args.out.exists(), 'seed output already exists')
    library = args.library.resolve(strict=True)
    require(not args.library.is_symlink() and library == (args.work / 'library').resolve() and
            library.is_relative_to(args.work.resolve()), 'library must be the owned sterile-work output')
    prefix = library / 'prefixes' / SLUG
    require(prefix.is_dir() and not prefix.is_symlink() and
            not (library / 'prefixes').is_symlink() and prefix.resolve().is_relative_to(library) and
            not (library / '.pw').exists(), 'prefix is not a fresh unsynced input')
    profile = library / 'profiles' / (SLUG + '.profile')
    require(profile.is_file() and not profile.is_symlink(), 'missing fresh diagnostic profile')
    text = profile.read_text()
    require('prefix = diagnostic-notepad' in text and
            'executable = C:\\windows\\system32\\notepad.exe' in text and 'architecture = pe64' in text,
            'unexpected diagnostic profile')
    audit_text(profile.read_bytes(), 'diagnostic profile')
    converter = load_converter(checkpoint)
    host = checkpoint / 'pc/host-wine/usr'
    audit = audit_source(converter, prefix, host, host_files, resource_hashes(host, host_files))
    # Ensure conversion actually changes the expected existing backend section.
    system = (prefix / 'system.reg').read_bytes()
    require(converter.CPU_KEY in system and converter.to_console('system.reg', system) != system,
            'missing host Wow64 backend selection')
    require((prefix / 'drive_c/windows/winsxs').is_dir(), 'missing initialized WinSxS')
    args.out.mkdir()
    try:
        remote = FilesystemRemote(args.out / 'console')
        rc = converter.main(['push', SLUG, '--library', str(library), '--cpu-dll', str(kit / 'pc/wowprospero.dll')], remote)
        require(rc == 0, 'original conversion failed')
        exported = args.out / 'console/data/prospero-win'
        require(not (exported / 'profiles/profiles.lst').exists(), 'seed must not replace an existing profile index')
        require(sha(exported / 'prefixes' / SLUG / converter.CPU_DLL) == CPU_SHA, 'exported CPU differs')
        for path in exported.rglob('*'):
            require(not path.is_symlink() and (path.is_dir() or path.is_file()), 'nonportable exported object')
        for name in ['LICENSE', 'NOTICE.md', 'LICENSING.md', 'THIRD_PARTY.md']:
            shutil.copy2(checkpoint / name, args.out / name)
        shutil.copytree(checkpoint / 'LICENSES', args.out / 'LICENSES', symlinks=False)
        (args.out / 'sources').mkdir()
        for name in ['prospero-win.tar.gz', 'wine.tar.gz']:
            shutil.copy2(checkpoint / 'sources' / name, args.out / 'sources' / name)
        shutil.copy2(Path(__file__), args.out / 'sources/export_notepad_seed.py')
        shutil.copy2(args.instructions, args.out / 'README.md')
        (args.out / 'SOURCE-AUDIT.json').write_text(json.dumps(audit, indent=2, sort_keys=True) + '\n')
        manifest = {'schema': 'pw-clean-notepad-seed/1', 'slug': SLUG,
                    'origin': 'fresh hosted Wine initialization, then original pw_prefix conversion',
                    'on_console_wineboot': False, 'console_execution_verified': False,
                    'vendor_or_account_state': False, 'windows_children_supported': False,
                    'producer_run': RUN, 'project_commit': PROJECT, 'project_tree': TREE, 'wine_commit': WINE,
                    'bound_artifacts': {k: {'id': v[0], 'sha256': v[1]} for k, v in INPUTS.items()},
                    'converter_sha256': BOUND_FILES['pc/tools/pw_prefix.py'], 'cpu_sha256': CPU_SHA,
                    'exporter_sha256': sha(Path(__file__)), 'copy_mode': 'fresh prefix only; never replace profiles.lst'}
        (args.out / 'SEED-MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
        (args.out / 'EXPORT-COMPLETE').write_text('pw-clean-notepad-seed/1\n')
        hashes = {p.relative_to(args.out).as_posix(): sha(p) for p in args.out.rglob('*') if p.is_file()}
        (args.out / 'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name, digest in sorted(hashes.items())))
    except BaseException:
        # Keep a failed owned export local for diagnosis, without a publish marker.
        (args.out / 'EXPORT-COMPLETE').unlink(missing_ok=True)
        raise


def diagnostics(args):
    """Retain only a bounded filtered log of the fixed sterile initializer."""
    require(not args.out.exists(), 'diagnostic output already exists')
    args.out.mkdir()
    log = args.work / 'initialization.log'
    report = {'schema': 'pw-clean-notepad-seed-diagnostics/1',
              'producer_run': RUN, 'raw_prefix_or_registry_included': False,
              'initialization_log': 'not available'}
    if log.is_file() and not log.is_symlink():
        report['log_bytes'] = log.stat().st_size
        report['log_sha256'] = sha(log)
        with log.open('rb') as stream:
            raw = stream.read(128 << 10)
        report['log_truncated'] = len(raw) < log.stat().st_size
        text = raw.decode('utf-8', errors='replace')
        sensitive = re.compile(r'password|passwd|authorization|bearer\s|api[_-]?key|github_token|'
                               r'access[_-]?token|refresh[_-]?token|cookie|'
                               r'hkey_(local_machine|current_user)|WINE REGISTRY Version|'
                               r'://[^/\s]+:[^/\s]+@', re.I)
        if sensitive.search(text) or any(ord(c) < 32 and c not in '\r\n\t' for c in text):
            report['initialization_log'] = 'withheld: secret/registry/binary-pattern check'
        else:
            text = text.replace(str(args.work.resolve()), '<seed-work>')
            text = text.replace('/home/runner/', '<runner>/')
            (args.out / 'initialization.filtered.log').write_text(text)
            report['initialization_log'] = 'bounded and filtered'
    (args.out / 'DIAGNOSTICS.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['prepare', 'export', 'diagnostics'])
    parser.add_argument('--work', type=Path, required=True)
    for name in ['checkpoint-zip', 'kit-zip', 'run-json', 'artifacts-json', 'library', 'out', 'instructions']:
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    needed = {'prepare': ['checkpoint_zip', 'kit_zip', 'run_json', 'artifacts_json'],
              'export': ['library', 'out', 'instructions'], 'diagnostics': ['out']}[args.mode]
    require(all(getattr(args, name) is not None for name in needed), 'missing mode arguments')
    if args.mode == 'prepare': prepare(args)
    elif args.mode == 'export': export(args)
    else: diagnostics(args)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, tarfile.TarError) as error:
        raise SystemExit('notepad seed: ' + str(error))
