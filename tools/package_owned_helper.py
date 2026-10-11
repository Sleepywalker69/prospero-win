#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Source-bound helper admission/retention for the general release packager.

No target code runs. This is integrity/static build evidence, never console
or helper-process lifecycle admission.
"""
import argparse
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
import build_owned_helper as helper
from native_probe_elf import Elf, extract_self
from check_native_suite import compiled_identity


def admit(directory, title, repo, sdk):
    result = helper.validate_owned_helper(directory, repo, sdk=sdk)
    helper.require(result.get('toolchain_reverified') is True and
                   result.get('runtime_validated') is False and
                   result.get('source_to_binary_reproducibility_verified') is False,
                   'release helper lacks source/toolchain admission')
    helper.require(helper.record(title / 'lapy.elf') == result['elf'],
                   'release title helper differs from admitted actual ELF')
    image = Elf(extract_self(helper.raw(title / 'eboot.bin')))
    compiled_identity(image, result['elf']['sha256'])
    compiled_identity(image, result['project']['commit'])
    return result


def retain(directory, title, repo, sdk, app):
    expected = admit(directory, title, repo, sdk)
    helper.require(helper.record(app / 'lapy.elf') == expected['elf'] and
                   helper.record(app / 'eboot.bin') == helper.record(title / 'eboot.bin'),
                   'copied release title/helper differs from admitted bytes')
    target = app / 'provenance/owned-helper'
    helper.require(not target.exists(), 'release helper evidence destination already exists')
    target.mkdir(parents=True)
    (target / 'obj').mkdir()
    for name in (*helper.OUTPUTS, 'owned_identity.h', 'lapy.map',
                 *('obj/' + unit + '.o' for unit in helper.UNITS)):
        (target / name).write_bytes(helper.raw(directory / name))
    # Preserve exact source bytes, including per-file mixed-license notices.
    source = helper.read_json(directory / 'lapy-source.json', output=True)
    for name, recorded in source['files'].items():
        path = Path(name)
        helper.require(not path.is_absolute() and '..' not in path.parts,
                       'unsafe release helper source path')
        helper.require(helper.record(repo / path) == recorded, 'release helper source changed')
        destination = app / 'provenance/owned-helper-source' / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(helper.raw(repo / path))
    notices = app / 'LICENSES/owned-helper'; notices.mkdir(parents=True)
    for source_name, destination in ((helper.DIRECTORY + '/LICENSE', 'MIT.txt'),
                                    (helper.DIRECTORY + '/lapy_elevation_protocol.h', 'protocol.h'),
                                    ('LICENSE', 'LGPL-2.1.txt')):
        (notices / destination).write_bytes(helper.raw(repo / source_name))
    helper.require(helper.validate_owned_helper(target, repo, sdk=sdk) == expected and
                   admit(directory, title, repo, sdk) == expected and
                   helper.record(app / 'lapy.elf') == expected['elf'] and
                   helper.record(app / 'eboot.bin') == helper.record(title / 'eboot.bin'),
                   'release helper changed during retention')
    (app / 'provenance/owned-helper-admission.json').write_bytes(helper.canonical(expected))
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('verify', 'retain'))
    for name in ('helper', 'title', 'repo', 'sdk'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--app', type=Path)
    args = parser.parse_args()
    if args.action == 'retain':
        helper.require(args.app is not None, 'helper retention requires --app')
        result = retain(args.helper, args.title, args.repo, args.sdk, args.app)
    else:
        result = admit(args.helper, args.title, args.repo, args.sdk)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
