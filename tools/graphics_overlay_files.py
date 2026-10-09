#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Verify fixed public kit files and assemble a new graphics diagnostic copy.

No console access, prefix initialization, binary execution or in-place changes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat

BASE_COMMIT = '578c593f7d8588c529f0c12413f71c8692817224'
BASE_TREE = '93a62a15aff0376316b7504aba4e3dd35779750b'
BASE_SUMS_SHA = '2299276f8a32199bb241e75970203f5ed00e619ba1ca7cb42365fa2320b51e5c'
BASE_TOPOLOGY_SHA = '5d4e52f3d7e47bbbc4c8919b1ef066f62216659142c0cc73add187564df035ca'
BASE_FILES_SHA = '99bbe981e237720bca0a19e02befcd684f25ab24e05b811a831e222cf387e6eb'
WINE = '490f6d5dcbb2a5047345b8af88d114bbcaad69a8'
DRIVER_COMMIT = '9de8e28b9944b72ac6dd0fd2da094f83be4f43b2'
DRIVER_TREE = '3de8259f2eb0dfa0ec1c0b66a1b9db8f16797f49'
DXVK = '9d6f54a1ade20d1d27dd421024717a636f3d8c68'
DRIVER_SHA = '341318d3d89ddc78c56abd5666495e90ae44dbe6edfbdea7161c4446569d0183'
DRIVER_DEST = 'PPSA99995/win/wine/lib/wine/x86_64-unix/libvulkan.prx'
PAYLOAD = {DRIVER_DEST, 'pc/graphics-smoke/x64/d3d11.dll', 'pc/graphics-smoke/x64/dxgi.dll',
           'pc/graphics-smoke/x64/d3d11-clear.exe', 'pc/recipes/diagnostic-d3d11.yml'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def relative(name):
    require(isinstance(name, str) and name and '\\' not in name and
            not any(ord(x) < 32 or ord(x) == 127 for x in name), 'unsafe file name')
    path = PurePosixPath(name)
    require(not path.is_absolute() and all(x not in ('', '.', '..') for x in name.split('/')),
            'unsafe relative path')
    return path


def read_json(path):
    require(path.is_file() and path.stat().st_size <= 16 << 20, 'missing/oversized JSON')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(path.read_text(), object_pairs_hook=unique)


def inventory(root):
    root = root.resolve(strict=True)
    result = {}
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        require(not mode & 0o7000 and (stat.S_ISDIR(mode) or stat.S_ISREG(mode) or stat.S_ISLNK(mode)),
                'special artifact entry')
        if path.is_symlink():
            require(path.resolve(strict=True).is_relative_to(root), 'artifact symlink escape')
        if path.is_file():
            result[path.relative_to(root).as_posix()] = {'sha256': sha(path),
                                                       'mode': oct(stat.S_IMODE(path.stat().st_mode))}
    return result


def topology(root):
    root = root.resolve(strict=True)
    result = {}
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        name = path.relative_to(root).as_posix()
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            require(not Path(target).is_absolute() and path.resolve(strict=True).is_relative_to(root),
                    'artifact link must be relative and internal')
            result[name] = {'kind': 'symlink', 'target': target, 'mode': oct(stat.S_IMODE(mode))}
        elif stat.S_ISDIR(mode):
            result[name] = {'kind': 'directory', 'mode': oct(stat.S_IMODE(mode))}
        else:
            require(stat.S_ISREG(mode), 'special artifact topology')
    return result


def topology_sha(root):
    encoded = json.dumps(topology(root), sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def ordinary_parents(root, name):
    path = root
    for component in relative(name).parts[:-1]:
        path = path / component
        require(not path.is_symlink(), 'destination/source parent is a symlink')
        if not path.exists():
            break
        require(path.is_dir(), 'destination/source parent is not a directory')


def verify_base(root):
    require(topology_sha(root) == BASE_TOPOLOGY_SHA, 'base directory/link topology differs')
    require(sha(root / 'FILES.json') == BASE_FILES_SHA, 'base file manifest is not the fixed accepted kit')
    require(sha(root / 'SHA256SUMS') == BASE_SUMS_SHA and
            stat.S_IMODE((root / 'FILES.json').stat().st_mode) == 0o644 and
            stat.S_IMODE((root / 'SHA256SUMS').stat().st_mode) == 0o644, 'base metadata differs')
    records = read_json(root / 'FILES.json')
    actual = inventory(root)
    require(set(actual) == set(records) | {'FILES.json', 'SHA256SUMS'}, 'base kit file coverage differs')
    require(all(actual[name] == records[name] for name in records), 'base kit bytes/modes changed')
    manifest = read_json(root / 'KIT-MANIFEST.json')
    require(manifest.get('schema') == 'pw-diagnostic-kit/1' and manifest.get('scope') == 'software-gdi-kit' and
            manifest.get('project') == {'repository': 'https://github.com/Sleepywalker69/prospero-win',
                                        'commit': BASE_COMMIT, 'tree': BASE_TREE} and
            manifest.get('wine_commit') == WINE and manifest.get('prefix_included') is False,
            'base kit identity differs')
    require(not (root / DRIVER_DEST).exists(), 'base unexpectedly contains a graphics driver')
    return manifest, records


def verify_overlay(root, manifest_sha):
    require(len(manifest_sha) == 64 and sha(root / 'GRAPHICS-MANIFEST.json') == manifest_sha,
            'graphics manifest does not match the externally supplied digest')
    value = read_json(root / 'GRAPHICS-MANIFEST.json')
    require(value.get('schema') == 'pw-graphics-overlay/1' and value.get('scope') == 'x64-d3d11-diagnostic' and
            value.get('base_tree') == BASE_TREE and value.get('driver_tree') == DRIVER_TREE and
            value.get('dxvk_commit') == DXVK and value.get('runtime_verified') is False and
            value.get('prefix_included') is False, 'wrong graphics overlay identity/scope')
    require(value.get('topology') == topology(root), 'overlay directory/link topology differs')
    actual = inventory(root)
    files = value['files']
    require(set(actual) == set(files) | {'GRAPHICS-MANIFEST.json', 'GRAPHICS-SHA256SUMS'},
            'graphics overlay coverage differs')
    require(all(actual[name] == files[name] for name in files), 'graphics overlay bytes/modes changed')
    expected_sums = ''.join(f"{actual[name]['sha256']}  {name}\n" for name in sorted(actual) if name != 'GRAPHICS-SHA256SUMS')
    require((root / 'GRAPHICS-SHA256SUMS').read_text() == expected_sums, 'graphics checksum list differs')
    payload = {name[len('overlay/'):] for name in files if name.startswith('overlay/')}
    require(payload == PAYLOAD, 'unexpected overlay payload')
    require(all(not (root / 'overlay' / name).is_symlink() for name in PAYLOAD), 'payload links are forbidden')
    for name in PAYLOAD:
        ordinary_parents(root / 'overlay', name)
    require(files['overlay/' + DRIVER_DEST]['mode'] == '0o755' and
            files['overlay/' + DRIVER_DEST]['sha256'] == DRIVER_SHA, 'driver bytes/mode differ')
    return value


def assemble(base, overlay, output, manifest_sha):
    require(not output.exists(), 'output must be a new directory')
    base, overlay = base.resolve(strict=True), overlay.resolve(strict=True)
    require(not output.resolve().is_relative_to(base) and not output.resolve().is_relative_to(overlay),
            'output cannot be inside an input')
    verify_base(base)
    value = verify_overlay(overlay, manifest_sha)
    for name in PAYLOAD | {'graphics-evidence'}:
        ordinary_parents(base, name)
        require(not (base / name).exists() and not (base / name).is_symlink(), 'overlay would overwrite base entry')
    # All source files and internal links are checked before either copy.
    shutil.copytree(base, output, symlinks=True)
    verify_base(output)
    shutil.copytree(overlay, output / 'graphics-evidence', symlinks=True)
    for name in sorted(PAYLOAD):
        ordinary_parents(output, name)
        target = output / name
        require(not target.exists() and not target.is_symlink(), 'copied base would be overwritten')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(overlay / 'overlay' / name, target)
        require(sha(target) == value['files']['overlay/' + name]['sha256'], 'copied payload hash differs')
    # Preserve the original manifests as records of the unchanged base files.
    verify_overlay(output / 'graphics-evidence', manifest_sha)
    copied = inventory(output)
    records = read_json(base / 'FILES.json')
    for name, record in records.items():
        require(copied[name] == record, 'base file changed during assembly')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--overlay', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True,
                        help='digest reported by the independently verified producer, not read from an untrusted file')
    args = parser.parse_args()
    result = assemble(args.base, args.overlay, args.out, args.manifest_sha256)
    print('Created graphics diagnostic copy: ' + str(result))
    print('Prefix preparation and console loading/presentation remain unverified.')


if __name__ == '__main__':
    main()
