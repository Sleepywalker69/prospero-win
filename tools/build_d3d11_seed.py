#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Derive one fresh D3D11 prefix from accepted immutable diagnostic artifacts.

Only file verification/copying and the original pure profile generator run.
No Wine, PE executable, console client, registry rewrite or installer is run.
"""
import argparse
import configparser
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import stat
import sys
import zipfile
from types import SimpleNamespace

sys.dont_write_bytecode = True
from graphics_overlay_files import (BASE_TREE, DRIVER_SHA, DXVK, WINE,
    read_json, relative, require, sha, verify_base, verify_overlay, DRIVER_DEST)
from package_graphics_overlay import INPUTS as RUNTIME_INPUTS
from package_diagnostic_kit import archive, git, repository
from prepare_radv_prx import unpack_tar, verify_checksums
from inspect_graphics_pe import Image

ROOT = Path(__file__).resolve().parents[1]
REPO = 'Sleepywalker69/prospero-win'
SLUG = 'diagnostic-d3d11'
SEED_SLUG = 'diagnostic-notepad'
SEED_INVENTORY = 'bf5608d5fca81c626b0c5d0aea1c50744a14f78264e0ffc3777b6fef3e64017d'
SEED_MANIFEST = 'ce1e5b1a2ee0d0b48899198dd72b139df16590790b6a91eb4a629e6a8d778171'
SEED_EXPORTER = 'b29eaf8f282fe77c8571e0018ebcd07629a2b7020d73e34aeeadec7ec05ce5c6'
INSTALLER_SHA = 'af36f281d4806c1add5b7eb5a3a9fa12a7a5c6b60c908b707e5e924fef7733b2'
CPU_SHA = '7fdd490b6a1eeff78f8de585f7f5624d03a11239520287fc61ff12abb4c13226'
# Independently accepted mode-corrected graphics run; no fallback input.
GRAPHICS_MANIFEST = 'e5770735b7f8c9001de867900f02dda9c49aaa35a5f7f289f515c2a3c462fb29'
INPUTS = {
    'kit': RUNTIME_INPUTS['kit'],
    'seed': {'run': 37878126672, 'head': 'e317bacdefbb5ec17b85212648309cb40cd68fcd',
             'workflow': '.github/workflows/notepad-seed.yml', 'artifact': 11593440576,
             'sha256': 'f93e8cf113c0954560f56c5d8fb7862d8d9193ce98c43f025965ad74f04eb71d',
             'member': 'clean-notepad-seed.tar.gz'},
    'graphics': {'run': 37887109548, 'head': '85be192f1cc8125b426617d5db313f18954d8bf9',
                 'workflow': '.github/workflows/graphics-overlay.yml', 'artifact': 11596543191,
                 'sha256': 'df75b14375b070311c96d82f1463365b4ff9904aeb4161fdb30b57574dee7b7e', 'member': 'graphics-overlay.tar.gz'},
}
APP = {'d3d11.dll', 'dxgi.dll', 'd3d11-clear.exe'}
PREFIX = 'console/data/prospero-win/prefixes/'
PROFILE = 'console/data/prospero-win/profiles/'


def canonical(records):
    return hashlib.sha256(json.dumps(records, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def regular_inventory(root):
    """Complete bytes, modes and directory topology; no followed links."""
    require(root.is_dir() and not root.is_symlink(), 'inventory root must be an owned directory')
    records = {}; total = 0
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix(); relative(name)
        mode = path.lstat().st_mode
        require(not mode & 0o7000 and (stat.S_ISREG(mode) or stat.S_ISDIR(mode)),
                'derived seed contains a link or special object')
        record = {'kind': 'file' if stat.S_ISREG(mode) else 'directory', 'mode': oct(stat.S_IMODE(mode))}
        if stat.S_ISREG(mode):
            size = path.stat().st_size; total += size
            require(size <= 512 << 20 and total <= 4 << 30, 'derived inventory byte limit')
            record['sha256'] = sha(path)
        require(len(records) < 16000, 'derived inventory entry limit')
        records[name] = record
    return records


def bound_module(path, digest, name):
    require(not path.is_symlink() and sha(path) == digest, 'bound helper source differs')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def metadata(kind, run, item):
    fixed = INPUTS[kind]
    require(re.fullmatch('[0-9a-f]{64}', fixed['sha256']) and re.fullmatch('[0-9a-f]{40}', fixed['head']),
            'graphics acceptance binding is not complete')
    require(run.get('id') == fixed['run'] and run.get('head_sha') == fixed['head'] and
            run.get('run_attempt') == 1 and run.get('status') == 'completed' and
            run.get('conclusion') == 'success' and run.get('path') == fixed['workflow'] and
            run.get('repository', {}).get('full_name') == REPO, 'wrong successful input run')
    require(item.get('id') == fixed['artifact'] and item.get('digest') == 'sha256:' + fixed['sha256'] and
            item.get('expired') is False and item.get('workflow_run', {}).get('id') == fixed['run'] and
            item['workflow_run'].get('head_sha') == fixed['head'] and
            item['workflow_run'].get('repository_id') == 1410835302 and
            item['workflow_run'].get('head_repository_id') == 1410835302, 'wrong bound input artifact')


def unpack(path, output, fixed, sidecar=False):
    require(sha(path) == fixed['sha256'], 'bound ZIP bytes differ')
    tar_path = output.parent / (output.name + '.tar.gz')
    require(not output.exists() and not tar_path.exists(), 'input extraction already exists')
    with zipfile.ZipFile(path) as zipped:
        members = zipped.infolist(); names = [x.filename for x in members]
        expected = [fixed['member']] + ([fixed['member'] + '.sha256'] if sidecar else [])
        require(len(names) == len(expected) and set(names) == set(expected), 'unexpected bound ZIP layout')
        member = zipped.getinfo(fixed['member'])
        require(0 < member.file_size <= 4 << 30, 'oversized input tar')
        with zipped.open(member) as source, tar_path.open('xb') as dest:
            shutil.copyfileobj(source, dest, 1 << 20)
        if sidecar:
            check = zipped.getinfo(fixed['member'] + '.sha256')
            require(check.file_size <= 1024, 'oversized tar checksum')
            text = zipped.read(check).decode('ascii')
            require(re.fullmatch(r'[0-9a-f]{64}  [^\r\n]+\n', text) and
                    text[:64] == sha(tar_path), 'inner tar checksum differs')
    unpack_tar(tar_path, output)


def verify_seed(seed, kit):
    records = regular_inventory(seed)
    require(canonical(records) == SEED_INVENTORY, 'accepted seed bytes/modes/topology differ')
    require(sha(seed / 'SEED-MANIFEST.json') == SEED_MANIFEST, 'accepted seed manifest differs')
    verify_checksums(seed)
    manifest = read_json(seed / 'SEED-MANIFEST.json')
    require(manifest['schema'] == 'pw-clean-notepad-seed/1' and manifest['slug'] == SEED_SLUG and
            manifest['project_tree'] == BASE_TREE and manifest['wine_commit'] == WINE and
            manifest['cpu_sha256'] == CPU_SHA and not manifest['console_execution_verified'], 'seed binding differs')
    exporter = bound_module(seed / 'sources/export_notepad_seed.py', SEED_EXPORTER, 'accepted_seed_exporter')
    prefix = seed / PREFIX / SEED_SLUG
    for name in sorted(exporter.REGISTRIES | exporter.GENERATED_TEXT):
        path = prefix / name
        if name in exporter.REGISTRIES: require(path.is_file(), 'missing initialized registry')
        if path.is_file(): exporter.audit_text(path.read_bytes(), name)
    converter = exporter.load_converter(kit)
    system = (prefix / 'system.reg').read_bytes()
    require(converter.to_console('system.reg', system) == system and
            converter.to_pc('system.reg', system) != system, 'converted CPU selection differs')
    require(sha(prefix / converter.CPU_DLL) == CPU_SHA, 'converted CPU bytes differ')
    require((prefix / 'dosdevices/.pw-symlinks').read_bytes() == b'c:\t../drive_c\nz:\t/\n',
            'portable DOS mappings differ')
    require((prefix / 'drive_c/windows/winsxs').is_dir(), 'missing initialized WinSxS')
    fonts = read_json(seed / 'FONT-ASSETS.json')
    require(len(fonts) == 6, 'portable font membership differs')
    for record in fonts.values():
        require(sha(prefix / record['destination']) == record['sha256'], 'portable font bytes differ')
    return manifest, exporter, converter


def generate_profile(kit, recipe, library):
    """Use only the bound original parser/constructor/pure profile() method."""
    import yaml
    installer_module = bound_module(kit / 'pc/tools/pw_install.py', INSTALLER_SHA, 'accepted_pw_install')
    document = yaml.safe_load(recipe.read_text())
    args = SimpleNamespace(slug=None, library=str(library), wine=str(kit / 'pc/host-wine/usr/bin/wine'),
                           resolution='1920x1080', file=[], input=[], disc=None, mesa_zink=None)
    installer = installer_module.Installer(document, recipe, args)
    # Never call install(), directive(), create_prefix(), Wine or a downloader.
    executable = Image(library / 'prefixes' / SLUG / 'drive_c/graphics-smoke/d3d11-clear.exe')
    require(not executable.characteristics & 0x2000 and executable.entry and executable.executable(executable.entry),
            'diagnostic executable header/entry differs')
    profile = installer.profile([])
    parser = configparser.RawConfigParser(strict=True); parser.read_string(profile)
    require(set(parser.sections()) == {'application', 'display'}, 'unexpected profile sections')
    require(dict(parser['application']) == {'id': SLUG, 'name': 'Original x64 D3D11 diagnostic',
        'executable': r'C:\graphics-smoke\d3d11-clear.exe', 'working_directory': r'C:\graphics-smoke',
        'dll_overrides': 'd3d11,dxgi=n', 'prefix': SLUG, 'runtime': 'wine-wow64',
        'architecture': 'pe64', 'graphics': 'auto'}, 'derived application profile differs')
    require(dict(parser['display']) == {'desktop': '1920x1080', 'scaling': 'fit',
        'view': 'desktop', 'show_fps': 'false'}, 'derived display profile differs')
    return profile


def verify_delta(original, derived, app_records):
    require(stat.S_IMODE(original.stat().st_mode) == stat.S_IMODE(derived.stat().st_mode),
            'derived prefix root mode differs')
    before = regular_inventory(original); after = regular_inventory(derived)
    additions = {'drive_c/graphics-smoke': {'kind': 'directory', 'mode': '0o755'}}
    additions.update({'drive_c/graphics-smoke/' + name: record for name, record in app_records.items()})
    require(not set(before) & set(additions), 'diagnostic application already exists')
    require(after == before | additions, 'derived prefix changed original bytes/modes/topology or added unbound data')
    return {'unchanged_entries': len(before), 'root_mode': oct(stat.S_IMODE(original.stat().st_mode)),
            'original_inventory_sha256': canonical(before), 'additions': additions}


def assemble(seed, graphics, kit, output):
    require(not output.exists() and not output.is_symlink(), 'output must be fresh')
    for source in (seed, graphics, kit):
        require(not output.resolve().is_relative_to(source.resolve()), 'output cannot be inside an input')
    before_seed = regular_inventory(seed)
    before_graphics = regular_inventory(graphics)
    verify_base(kit); seed_manifest, exporter, converter = verify_seed(seed, kit)
    overlay = verify_overlay(graphics, GRAPHICS_MANIFEST)
    require(overlay['base_tree'] == seed_manifest['project_tree'] and
            overlay['files']['overlay/' + DRIVER_DEST]['sha256'] == DRIVER_SHA,
            'graphics/runtime binding differs')
    app = graphics / 'overlay/pc/graphics-smoke/x64'
    require({p.name for p in app.iterdir()} == APP and all(not p.is_symlink() and p.is_file() for p in app.iterdir()),
            'unexpected graphics application files')
    app_records = regular_inventory(app)
    output.mkdir(parents=True)
    original = seed / PREFIX / SEED_SLUG
    derived = output / PREFIX / SLUG
    shutil.copytree(original, derived)
    target = derived / 'drive_c/graphics-smoke'; require(not target.exists(), 'app destination already exists')
    shutil.copytree(app, target)
    delta = verify_delta(original, derived, app_records)
    library = output / 'console/data/prospero-win'
    profile = generate_profile(kit, graphics / 'overlay/pc/recipes/diagnostic-d3d11.yml', library)
    exporter.audit_text(profile.encode(), 'derived diagnostic profile')
    profiles = library / 'profiles'; profiles.mkdir()
    (profiles / (SLUG + '.profile')).write_text(profile)
    require(not (profiles / 'profiles.lst').exists(), 'profile index must not be replaced')
    # Preserve corresponding source/licences and original sealed provenance.
    provenance = output / 'provenance'; provenance.mkdir()
    for source, label, excluded in [(seed, 'notepad-seed', {'console'}), (graphics, 'graphics-overlay', set())]:
        dest = provenance / label; dest.mkdir()
        for path in sorted(source.iterdir()):
            if path.name in excluded: continue
            if path.is_dir(): shutil.copytree(path, dest / path.name)
            else: shutil.copy2(path, dest / path.name)
    verify_base(kit)
    require(regular_inventory(seed) == before_seed and regular_inventory(graphics) == before_graphics,
            'input changed during derivation')
    require(verify_delta(original, derived, app_records) == delta, 'derived prefix changed during packaging')
    return {'schema': 'pw-derived-d3d11-seed/1', 'slug': SLUG, 'bound_inputs': INPUTS,
        'source_seed_manifest_sha256': SEED_MANIFEST, 'graphics_manifest_sha256': GRAPHICS_MANIFEST,
        'runtime_tree': BASE_TREE, 'wine_commit': WINE, 'dxvk_commit': DXVK, 'driver_sha256': DRIVER_SHA,
        'initializer': 'reused exact already initialized and converted Notepad seed; no new Wine run',
        'registry_changes': 0, 'original_prefix': delta, 'app_files': app_records,
        'profile_sha256': hashlib.sha256(profile.encode()).hexdigest(),
        'profile_generator_sha256': INSTALLER_SHA, 'original_exporter_sha256': SEED_EXPORTER,
        'prefix_included': True, 'graphics_executed': False, 'console_verified': False,
        'builtin_runtime_selection_verified': False,
        'limitations': ['Preserved host builtin PE copies rely on Wine builtin-first runtime selection with fallback',
                        'Actual patched runtime binding and GPU presentation remain console checks',
                        'No D3D12, vendor installer, account or Retail compatibility claim'],
        'copy_mode': 'fresh diagnostic-d3d11 prefix/profile only; never replace profiles.lst'}


def prepare(args):
    require(not args.work.exists(), 'work directory already exists'); args.work.mkdir(parents=True)
    for kind, fixed in INPUTS.items():
        metadata(kind, read_json(args.inputs / (kind + '-run.json')), read_json(args.inputs / (kind + '-artifact.json')))
        unpack(args.inputs / (kind + '.zip'), args.work / kind, fixed, sidecar=kind == 'seed')
    verify_base(args.work / 'kit'); verify_seed(args.work / 'seed', args.work / 'kit')
    verify_overlay(args.work / 'graphics', GRAPHICS_MANIFEST)
    (args.work / 'INPUTS-VERIFIED.json').write_text(json.dumps(INPUTS, indent=2) + '\n')


def package(args):
    require(read_json(args.work / 'INPUTS-VERIFIED.json') == INPUTS, 'prepared inputs changed')
    require(not git(ROOT, 'status', '--porcelain'), 'producer source is dirty')
    value = assemble(args.work / 'seed', args.work / 'graphics', args.work / 'kit', args.out)
    (args.out / 'sources').mkdir()
    source_archive = args.out / 'sources/d3d11-seed-producer.tar.gz'; archive(ROOT, source_archive)
    value['producer'] = {'repository': repository(args.repository), 'commit': git(ROOT, 'rev-parse', 'HEAD'),
                         'tree': git(ROOT, 'rev-parse', 'HEAD^{tree}'), 'archive_sha256': sha(source_archive)}
    shutil.copy2(ROOT / 'docs/D3D11_SEED.md', args.out / 'README.md')
    (args.out / 'DERIVED-MANIFEST.json').write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    (args.out / 'FILES.json').write_text(json.dumps(regular_inventory(args.out), indent=2, sort_keys=True) + '\n')
    (args.out / 'SHA256SUMS').write_text(''.join(f'{sha(path)}  {path.relative_to(args.out)}\n'
        for path in sorted(args.out.rglob('*')) if path.is_file() and path != args.out / 'SHA256SUMS'))
    verify_checksums(args.out)
    print('D3D11_SEED_MANIFEST_SHA256=' + sha(args.out / 'DERIVED-MANIFEST.json'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'package'))
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--inputs', type=Path); parser.add_argument('--out', type=Path)
    parser.add_argument('--repository')
    args = parser.parse_args()
    require(args.inputs is not None if args.mode == 'prepare' else
            args.out is not None and args.repository is not None, 'missing mode arguments')
    if args.mode == 'prepare': prepare(args)
    else: package(args)


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        raise SystemExit('D3D11 seed: ' + str(error))
