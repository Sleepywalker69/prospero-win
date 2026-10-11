#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Inert real-file package controls; no compiler, Wine, PE or target execution."""
import copy
import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import package_windows_child_fixture as package
import prepare_windows_child_prefix as prefix
import windows_child_network_package as network
import windows_child_user_package as user
import test_package_windows_child_fixture as original

PROFILE = b'''[application]
name=Original network control
id=windows-child-net-v1
prefix=windows-child-net-v1
executable=C:\\windows-child-net\\net-parent.exe
working_directory=C:\\windows-child-net
runtime=wine-wow64
architecture=pe64
graphics=auto
[display]
desktop=800x600
view=desktop
show_fps=false
'''


def source_archive(copies, duplicate=None):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as archive:
        for name, data in list(copies.items()) + ([duplicate] if duplicate else []):
            entry = tarfile.TarInfo(name); entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    return out.getvalue()


class PureControls(unittest.TestCase):
    def test_optional_off_original_directory_and_archive(self):
        for battle in (False, True):
            with self.subTest(battle=battle):
                fixture = original.ArchiveControls(); fixture.setUp()
                try:
                    manifest = fixture.prepared_battle() if battle else fixture.prepared()
                    result = package.verify_directory(fixture.root)
                    self.assertEqual(result, manifest)
                    self.assertNotIn('network_enabled', result)
                    self.assertFalse(any('windows-child-net' in x for x in result['inventory']))
                    archive = fixture.temp / 'off.tar.gz'
                    package.write_archive(fixture.root, archive)
                    self.assertEqual(package.verify_archive(archive), result)
                finally: fixture.doCleanups()

    def test_optional_off_rejects_payload_or_roles(self):
        combined = {'.': {'type': 'directory', 'mode': 0o755}}
        for name in (network.PROFILE, network.PREFIX, network.APP + '/net-child.exe', network.REFERENCE):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'disabled network'):
                package.validate_network({}, {name: {'type': 'file'}}, None, None, None, None, None, combined)
        for enabled in (None, 0, 1, 'false'):
            with self.subTest(enabled=enabled), self.assertRaises(ValueError):
                package.validate_network({'network_enabled': enabled}, {}, None, None, None, None, None, combined)
        with self.assertRaisesRegex(ValueError, 'optional consumer roles'):
            package.validate_network({'optional_roles': network.ROLES}, {}, None, None, None, None, None, combined)
        self.assertIs(package.validate_network({}, {}, None, None, None, None, None, combined), combined)

    def test_profile_exact_fields(self):
        parsed = network.profile_fields(PROFILE)
        self.assertEqual((parsed['cpu'], parsed['architecture'], parsed['args']), ('default', 'pe64', []))
        self.assertEqual((parsed['desktop'], parsed['view'], parsed['show_fps']), ('800x600', 'desktop', False))
        for before, after in ((b'architecture=pe64', b'architecture=pe32'),
            (b'800x600', b'1920x1080'), (b'show_fps=false', b'show_fps=true'),
            (b'view=desktop', b'view=window'), (b'net-parent.exe', b'child.exe'),
            (b'runtime=wine-wow64', b'runtime=native'), (b'graphics=auto', b'graphics=dxvk'),
            (b'prefix=windows-child-net-v1', b'prefix=windows-child-fixture-v1'),
            (b'graphics=auto', b'graphics=auto\ncpu=box64'),
            (b'graphics=auto', b'graphics=auto\narguments=--child')):
            with self.subTest(after=after), self.assertRaises(ValueError): network.profile_fields(PROFILE.replace(before, after))
        for data in (PROFILE + b'\n[other]\nx=1\n', b'[DEFAULT]\nx=y\n' + PROFILE,
                     PROFILE.replace(b'graphics=auto', b'graphics=auto\ngraphics=auto'), b'', b'x' * 16385):
            with self.assertRaises((ValueError, configparser.Error)): network.profile_fields(data)

    def test_original_recipes_unchanged_and_network_recipe_exact(self):
        # Complete original recipe values are preserved, including the no-DXVK choice.
        for battle,slug,name,exe,cwd in [(False,'windows-child-fixture-v1','Original Windows child-process fixture','drive_c/windows-child-fixture/parent.exe','$GAMEDIR/drive_c/windows-child-fixture'),
                                       (True,'battlenet-experimental-v1','Battle.net experimental installer','drive_c/installer/Battle.net-Setup.exe','$GAMEDIR/drive_c/installer')]:
            self.assertEqual(prefix.recipe(battle),{'name':name,'game_slug':slug,'runner':'wine',
                'prospero':{'graphics':'auto'},'script':{'game':{'exe':exe,'working_dir':cwd},'wine':{'dxvk':False}}})
        new = prefix.recipe(network=True)
        self.assertEqual(new['game_slug'], network.SLUG)
        self.assertEqual(new['prospero']['display'], {'desktop': '800x600', 'view': 'desktop', 'show_fps': False})
        self.assertEqual(new['script']['game']['exe'], 'drive_c/windows-child-net/net-parent.exe')
        self.assertIs(new['script']['wine']['dxvk'], False)
        with self.assertRaises(ValueError): prefix.recipe(True, False, True)

    def test_network_prefix_fresh_output_no_overwrite_or_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = root / 'original'; original.mkdir()
            sentinel = original / 'sentinel'; sentinel.write_bytes(b'old-data')
            fresh = root / 'third'
            self.assertEqual(prefix.absent(fresh, (original,)), fresh)
            self.assertFalse(fresh.exists())
            for target in (original, original / 'nested', sentinel):
                with self.subTest(target=target), self.assertRaises(ValueError): prefix.absent(target, (original,))
            link = root / 'link'; link.symlink_to(original, target_is_directory=True)
            for target in (link, link / 'fresh'):
                with self.assertRaises(ValueError): prefix.absent(target, (original,))
            self.assertEqual(sentinel.read_bytes(), b'old-data')

    def test_inventory_scopes_collision_and_casefold(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); console = root / 'console'; console.mkdir()
            for name in network.IMAGES:
                path = console / network.APP.removeprefix('console/') / name
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(name.encode())
            p = console / network.PROFILE.removeprefix('console/'); p.parent.mkdir(parents=True); p.write_bytes(PROFILE)
            extra = prefix.inventory(console); baseline = {'.': extra['.']}
            merged = network.merge_inventory(baseline, extra); self.assertEqual(merged, extra)
            with self.assertRaisesRegex(ValueError, 'overwrites'): network.merge_inventory(extra, extra)
            for name in ('../escape', '/abs', 'data\\escape', 'data//escape',
                         'data/prospero-win/prefixes/windows-child-fixture-v1/evil',
                         'data/prospero-win/profiles/other.profile'):
                mutated = copy.deepcopy(extra); mutated[name] = {'type':'file','sha256':'a'*64,'bytes':0}
                with self.subTest(name=name), self.assertRaises(ValueError): network.merge_inventory(baseline, mutated)
            same = console / network.APP.removeprefix('console/') / 'NET-CHILD.EXE'; same.write_bytes(b'alias')
            with self.assertRaisesRegex(ValueError, 'case-colliding'): prefix.inventory(console)

    def test_capability_exact_bytes_and_conservative_claims(self):
        project = {'commit':'a'*40,'tree':'b'*40}; result = network.capability(project, PROFILE, b'prefix', b'ref', 'c'*40, 'd'*64)
        self.assertEqual(result['profile']['sha256'], hashlib.sha256(PROFILE).hexdigest())
        self.assertEqual(result['child']['maximum_direct_generations'], 1)
        self.assertEqual((result['native_child_budget_ms'],result['attempt_budget_ms']), (120000,180000))
        for key in ('runtime_validated','console_validated','child_presentation','child_input','descendant_admission','network_validated'):
            self.assertIs(result[key], False)
        self.assertNotEqual(result, network.capability(project, PROFILE, b'prefix ', b'ref', 'c'*40, 'd'*64))
        for worker, child in (('c'*39,'d'*64), ('c'*40,'d'*63)):
            with self.assertRaises(ValueError): network.capability(project,PROFILE,b'p',b'r',worker,child)

    def test_source_copies_exact_retained_bytes(self):
        copies = {name: ('inert '+name).encode() for name in network.SOURCE_FILES.values()}
        archive = source_archive(copies)
        expected = {key:hashlib.sha256(copies[path]).hexdigest() for key,path in network.SOURCE_FILES.items()}
        self.assertEqual(network.source_copies(archive,copies), expected)
        for name in copies:
            wrong = dict(copies); wrong[name] += b'changed'
            with self.subTest(name=name), self.assertRaises(ValueError): network.source_copies(archive, wrong)
        with self.assertRaisesRegex(ValueError,'duplicate'):
            network.source_copies(source_archive(copies,next(iter(copies.items()))), copies)
        with self.assertRaisesRegex(ValueError,'missing'):
            network.source_copies(source_archive(dict(list(copies.items())[1:])), copies)


class EnabledPackageControls(unittest.TestCase):
    def setUp(self):
        # This helper manufactures inert PE headers and synthetic MSVC/log receipts.
        # The production validator still parses every byte; no validator is mocked.
        from test_windows_child_network_contract import make_bundle
        self.files, self.reference, self.project, self.source_hashes, self.validator = make_bundle()
        self.fixture = original.ArchiveControls(); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.project = self.project
        self.battle = False

    def get(self, name): return package.read_json(self.fixture.root / name)
    def put_json(self, name, value): self.fixture.json(name, value)
    def put(self, name, value): self.fixture.put(name, value)

    def prepare(self, battle=False):
        self.battle = battle
        f = self.fixture
        f.prepared_battle() if battle else f.prepared()
        for name, data in self.files.items(): self.put(network.REFERENCE_ROOT + '/' + name, data)
        copies = {network.SOURCE_FILES['source_sha256']: self.files['windows_child_network.c'],
                  network.SOURCE_FILES['recipe_sha256']: self.files['build_windows_child_network.ps1'],
                  network.SOURCE_FILES['validator_sha256']: self.validator,
                  network.SOURCE_FILES['header_sha256']: self.files['windows_child_network_contract.h']}
        for name, data in copies.items(): self.put(network.SOURCE_ROOT + '/' + name, data)
        self.put('sources/project.tar.gz', source_archive(copies))
        sources = self.get('provenance/retained-sources.json')
        sources['roles']['project'] = {'path': 'project.tar.gz', 'revision': self.project['commit']}
        sources['inventory'] = prefix.inventory(f.root / 'sources')
        self.put_json('provenance/retained-sources.json', sources)
        # Retain the original two profiles exactly; create only the dedicated fourth scope.
        for p in (f.root / package.CONSOLE_PREFIX).rglob('*'):
            rel = p.relative_to(f.root / package.CONSOLE_PREFIX).as_posix()
            if p.is_file() and rel.startswith('drive_c/windows/'):
                self.put(network.PREFIX + '/' + rel, p.read_bytes())
        for name in network.IMAGES: self.put(network.APP + '/' + name, self.files[name])
        self.put(network.PROFILE, PROFILE)
        all_console = prefix.inventory(f.root / 'console')
        path = network.PREFIX.removeprefix('console/')
        ancestors = {'.', 'data', 'data/prospero-win', 'data/prospero-win/prefixes', 'data/prospero-win/profiles'}
        self.extra = {n:v for n,v in all_console.items() if n in ancestors or n == path or
                      n.startswith(path + '/') or n == network.PROFILE.removeprefix('console/')}
        baseline = self.get('provenance/prefix.json')
        self.prepared = {'schema':'pw-windows-child-network-prefix/1', 'project':self.project,
            'wine_commit':prefix.WINE, 'patches':{}, 'private_dispatcher':self.get(package.ABI_REPORT),
            'cpu':baseline['cpu'], 'fixture':self.reference, 'inventory':self.extra,
            'patched_pe_delta':baseline['patched_pe_delta'], 'fixture_executed':False,
            'console_execution_verified':False, 'child_presentation':False, 'child_input':False, 'network_validated':False}
        self.put_json(network.REPORT, self.prepared)
        worker = self.get('PPSA99995/native-wine-child-build.json')
        worker['worker']['build_id'] = 'f'*40
        worker['candidate_capabilities'] = [
            {'mode':1,'prefix':package.SLUG,'guest_machine':'AMD64','backend':'native-amd64','runtime_validated':False},
            {'mode':2,'prefix':package.BATTLE_SLUG,'guest_machine':'I386','backend':'wowprospero','runtime_validated':False},
            {'mode':3,'prefix':'windows-child-user-v1','guest_machine':'AMD64','backend':'native-amd64','runtime_validated':False},
            {'mode':4,'prefix':network.SLUG,'guest_machine':'AMD64','backend':'native-amd64','runtime_validated':False}]
        self.put_json('PPSA99995/native-wine-child-build.json', worker)
        self.put_json(network.CAPABILITY, network.capability(self.project,PROFILE,
            (f.root/network.REPORT).read_bytes(),self.files['network-source.json'],worker['worker']['build_id'],
            self.reference['files']['net-child.exe']['sha256']))
        title = self.get('provenance/title.json')
        compile_receipt=b'{"scope":"synthetic compile receipt, no compiler execution"}\n'
        self.put('provenance/title-compile.json',compile_receipt)
        title['title_compile_receipt']={'bytes':len(compile_receipt),'sha256':hashlib.sha256(compile_receipt).hexdigest()}
        title.update(network_enabled=True,network_child_sha256=self.reference['files']['net-child.exe']['sha256'],
                     network_reference_sha256=hashlib.sha256(self.files['network-source.json']).hexdigest())
        self.put_json('provenance/title.json',title)
        self.finish()

    def finish(self):
        manifest = self.fixture.finish(self.battle)
        manifest.update(network_enabled=True,run_attempt='1',
            network_reference_inventory=prefix.inventory(self.fixture.root / network.REFERENCE_ROOT))
        manifest.setdefault('optional_roles',{}).update(network.ROLES)
        if (self.fixture.root/user.PROFILE).is_file():
            manifest.update(user_enabled=True,
                user_reference_inventory=prefix.inventory(self.fixture.root/user.REFERENCE_ROOT))
            manifest['optional_roles'].update(user.ROLES)
        self.put_json(package.MANIFEST,manifest)
        self.put(package.SUMS,package.checksums(package.inventory(self.fixture.root)))
        return manifest

    def verify(self): return package.verify_directory(self.fixture.root)
    def reject(self, pattern=None):
        self.finish()
        with self.assertRaisesRegex(ValueError,pattern or '.'):
            self.verify()

    def test_enabled_real_directory_and_archive(self):
        self.prepare()
        manifest = self.verify()
        self.assertTrue(manifest['network_enabled'])
        self.assertEqual(manifest['optional_roles'],network.ROLES)
        archive = self.fixture.temp/'enabled.tar.gz';package.write_archive(self.fixture.root,archive)
        self.assertEqual(package.verify_archive(archive),manifest)
        self.assertEqual(len(self.get(network.REPORT)['patched_pe_delta']),24)
        self.assertEqual((self.fixture.root/network.APP/'net-child.exe').read_bytes(),self.files['net-child.exe'])

    def test_network_profile_with_battle_keeps_original_scopes(self):
        self.prepare(True)
        manifest = self.verify()
        self.assertEqual(set(manifest['optional_roles']),{'network_profile','network_capability','battlenet_profile','battlenet_capability'})
        self.assertEqual((self.fixture.root/package.FIXTURE/'parent.exe').read_bytes(),b'original same fixture image')
        self.assertTrue((self.fixture.root/package.BATTLE_PROFILE).is_file())

    def test_disabled_selection_refuses_enabled_payload(self):
        self.prepare();manifest=self.finish();manifest['network_enabled']=False;manifest['optional_roles']={}
        self.put_json(package.MANIFEST,manifest);self.put(package.SUMS,package.checksums(package.inventory(self.fixture.root)))
        with self.assertRaisesRegex(ValueError,'disabled network'):self.verify()

    def test_exact_source_copies_must_match_retained_archive(self):
        self.prepare();self.put(network.SOURCE_ROOT+'/'+network.SOURCE_FILES['source_sha256'],b'other source')
        self.reject('source copy differs')

    def test_missing_retained_source_refused(self):
        self.prepare();copies={network.SOURCE_FILES['source_sha256']:self.files['windows_child_network.c'],
            network.SOURCE_FILES['recipe_sha256']:self.files['build_windows_child_network.ps1']}
        self.put('sources/project.tar.gz',source_archive(copies));self.reject('source missing')

    def test_original_reference_run_attempt_and_project_bound(self):
        self.prepare()
        for key,value in (('run_id','124'),('run_attempt','2'),('project',{'commit':'d'*40,'tree':'e'*40})):
            meta=copy.deepcopy(self.reference);meta[key]=value
            self.put_json(network.REFERENCE,meta);self.finish()
            with self.subTest(key=key),self.assertRaises(ValueError):self.verify()
            self.put(network.REFERENCE,self.files['network-source.json'])

    def test_original_pe_machine_and_role_bytes_bound(self):
        self.prepare();data=bytearray(self.files['net-child.exe']);data[0x84:0x86]=b'\x4c\x01'
        # Rehash the synthetic reference: the actual PE parser must still reject it.
        self.put(network.REFERENCE_ROOT+'/net-child.exe',bytes(data));meta=copy.deepcopy(self.reference)
        meta['files']['net-child.exe'].update(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
        self.put_json(network.REFERENCE,meta);self.reject()

    def test_packaged_child_bytes_must_equal_reference(self):
        self.prepare();self.put(network.APP+'/net-child.exe',b'wrong role image');self.reject('packaged role image differs')

    def test_all_24_pe_bytes_and_overlay_records_required(self):
        self.prepare();name=network.PREFIX+'/drive_c/windows/syswow64/dnsapi.dll'
        data=(self.fixture.root/name).read_bytes();self.put(name,data+b'changed');self.reject('matched PE overlay')
        self.put(name,data);report=self.get(network.REPORT);report['patched_pe_delta'].pop('drive_c/windows/syswow64/dnsapi.dll')
        self.put_json(network.REPORT,report);self.reject('matched PE overlay|complete PE overlay')

    def test_cpu_and_abi_exact_binding(self):
        self.prepare();name=network.PREFIX+'/drive_c/windows/system32/wowprospero.dll'
        self.put(name,b'changed translator');self.reject('CPU PE differs')

    def test_prepared_abi_and_worker_binding(self):
        self.prepare();report=self.get(network.REPORT);report['private_dispatcher']['mode']=0
        self.put_json(network.REPORT,report);self.reject('prefix/source/ABI/reference differs')

    def test_worker_generation_and_title_digest_bound(self):
        self.prepare();worker=self.get('PPSA99995/native-wine-child-build.json');worker['worker']['build_id']='e'*40
        self.put_json('PPSA99995/native-wine-child-build.json',worker);self.reject('capability differs')
        worker['worker']['build_id']='f'*40;self.put_json('PPSA99995/native-wine-child-build.json',worker)
        title=self.get('provenance/title.json');title['network_child_sha256']='e'*64
        self.put_json('provenance/title.json',title);self.reject('title original network child/reference differs')

    def test_capability_cannot_claim_execution_input_or_descendants(self):
        self.prepare();baseline=self.get(network.CAPABILITY)
        for key in ('console_validated','runtime_validated','child_presentation','child_input','descendant_admission','network_validated'):
            changed=copy.deepcopy(baseline);changed[key]=True;self.put_json(network.CAPABILITY,changed)
            with self.subTest(key=key): self.reject('capability differs')
        self.put_json(network.CAPABILITY,baseline)

    def test_profile_escape_cannot_be_rehashed_into_package(self):
        self.prepare();self.put(network.PROFILE,PROFILE.replace(b'prefix=windows-child-net-v1',b'prefix=windows-child-fixture-v1'))
        self.reject('application configuration differs')

    def test_reference_inventory_extra_file_refused_by_real_core(self):
        self.prepare();self.put(network.REFERENCE_ROOT+'/unclaimed.exe',b'inert');self.reject()

    def test_prefix_input_admission_uses_real_reference_and_inventory(self):
        self.prepare()
        root = self.fixture.temp / 'admission'; root.mkdir()
        repo = root / 'repo'; exported = root / 'exported'
        copies = {network.SOURCE_FILES['source_sha256']: self.files['windows_child_network.c'],
                  network.SOURCE_FILES['recipe_sha256']: self.files['build_windows_child_network.ps1'],
                  network.SOURCE_FILES['validator_sha256']: self.validator,
                  network.SOURCE_FILES['header_sha256']: self.files['windows_child_network_contract.h']}
        for name, data in copies.items():
            target = repo/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        for name, entry in self.extra.items():
            target=exported/name
            if entry['type']=='directory':target.mkdir(parents=True,exist_ok=True);target.chmod(entry['mode'])
            else:target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((self.fixture.root/'console'/name).read_bytes());target.chmod(entry['mode'])
        prepared = copy.deepcopy(self.prepared);prepared['host_stamp']='exact-host-stamp'
        report=root/'report.json';report.write_bytes(package.json_bytes(prepared))
        paths={'repo':repo,'network_fixture':self.fixture.root/network.REFERENCE_ROOT,
               'network_prefix':exported,'network_prefix_report':report}
        old=self.get('provenance/prefix.json');abi=self.get(package.ABI_REPORT)
        env=mock.patch.dict(os.environ,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1');env.start();self.addCleanup(env.stop)
        admitted=package.check_network_inputs(paths,self.project,old,abi,'exact-host-stamp')
        self.assertEqual(admitted['pair'],self.reference)
        self.assertEqual(admitted['profile'],PROFILE)
        for key,value in [('GITHUB_RUN_ID','124'),('GITHUB_RUN_ATTEMPT','2')]:
            with mock.patch.dict(os.environ,{key:value}),self.assertRaises(ValueError):
                package.check_network_inputs(paths,self.project,old,abi,'exact-host-stamp')
        with self.assertRaisesRegex(ValueError,'source/reference'):
            package.check_network_inputs(paths,self.project,old,abi,'other-host-stamp')
        (exported/network.APP.removeprefix('console/')/'net-child.exe').write_bytes(b'modified')
        with self.assertRaisesRegex(ValueError,'prefix bytes changed'):
            package.check_network_inputs(paths,self.project,old,abi,'exact-host-stamp')

    def test_retained_project_role_cannot_redirect(self):
        self.prepare();sources=self.get('provenance/retained-sources.json')
        sources['roles']['project']['path']='other.tar.gz';self.put_json('provenance/retained-sources.json',sources)
        self.reject('project source archive path')

    def test_archive_rejects_oversized_new_inspection_header_before_read(self):
        # A real truncated tar header is sufficient: refusal must happen before attempting its body.
        archive=self.fixture.temp/'oversized.tar.gz'
        with tarfile.open(archive,'w:gz') as stream:
            item=tarfile.TarInfo(network.SOURCE_ROOT+'/tests/fixtures/windows_child_network.c')
            item.mode=0o644;item.size=package.MAX_JSON+1;stream.addfile(item)
        with self.assertRaisesRegex(ValueError,'oversized inspection input'):
            package.verify_archive(archive)

    def test_title_compile_raw_receipt_is_mandatory_and_byte_bound(self):
        self.prepare();path=self.fixture.root/'provenance/title-compile.json';saved=path.read_bytes()
        path.unlink();self.reject('network raw title compiler receipt differs')
        self.put('provenance/title-compile.json',saved+b'changed');self.reject('network raw title compiler receipt differs')
        self.put('provenance/title-compile.json',saved)
        self.finish();self.verify()

    def test_exact_four_worker_capabilities_no_claim_inflation(self):
        self.prepare();baseline=self.get('PPSA99995/native-wine-child-build.json')
        mutations=[]
        for count in (0,2,3):
            x=copy.deepcopy(baseline);x['candidate_capabilities']=x['candidate_capabilities'][:count];mutations.append(x)
        x=copy.deepcopy(baseline);x['candidate_capabilities'].append(dict(x['candidate_capabilities'][-1]));mutations.append(x)
        for field,value in [('guest_machine','I386'),('backend','wowprospero'),('prefix',package.SLUG),('mode',5),('runtime_validated',True)]:
            for index in (2,3):
                x=copy.deepcopy(baseline);x['candidate_capabilities'][index][field]=value;mutations.append(x)
        for x in mutations:
            with self.subTest(capabilities=x['candidate_capabilities']):
                self.put_json('PPSA99995/native-wine-child-build.json',x);self.reject('worker capability cohort differs')

    def test_optional_title_must_be_enabled(self):
        self.prepare();title=self.get('provenance/title.json');title['network_enabled']=False
        self.put_json('provenance/title.json',title);self.reject('title network admission')

    def test_network_prefix_cannot_overwrite_original_inventory(self):
        self.prepare();report=self.get(network.REPORT)
        report['inventory']['data/prospero-win/prefixes/windows-child-fixture-v1/drive_c/windows-child-fixture/parent.exe']={
            'type':'file','bytes':1,'sha256':'e'*64,'mode':0o644}
        self.put_json(network.REPORT,report);self.reject('escapes its dedicated')

    def test_both_optional_profiles_with_battle_keep_separate_originals(self):
        from test_windows_child_user_package import EnabledPackageControls as UserControls
        self.prepare(True)
        other=UserControls();other.setUp();self.addCleanup(other.doCleanups);other.prepare(True)
        for path in other.fixture.root.rglob('*'):
            name=path.relative_to(other.fixture.root).as_posix()
            if path.is_file() and (name==user.PROFILE or name.startswith(user.PREFIX+'/') or
                                  name.startswith('provenance/windows-child-user')):
                self.put(name,path.read_bytes())
        copies={}
        for module in (user,network):
            copies.update({name:(self.fixture.root/module.SOURCE_ROOT/name).read_bytes()
                           for name in module.SOURCE_FILES.values()})
        self.put('sources/project.tar.gz',source_archive(copies))
        retained=self.get('provenance/retained-sources.json')
        retained['inventory']=prefix.inventory(self.fixture.root/'sources')
        self.put_json('provenance/retained-sources.json',retained)
        title=self.get('provenance/title.json');other_title=other.get('provenance/title.json')
        title.update({key:value for key,value in other_title.items() if key.startswith('user_')})
        self.put_json('provenance/title.json',title)
        manifest=self.finish();self.assertEqual(self.verify(),manifest)
        self.assertEqual(len(manifest['optional_roles']),6)
        self.assertEqual((self.fixture.root/network.APP/'net-child.exe').read_bytes(),self.files['net-child.exe'])
        self.assertEqual((self.fixture.root/user.APP/'user-child.exe').read_bytes(),other.files['user-child.exe'])
        archive=self.fixture.temp/'all-four.tar.gz';package.write_archive(self.fixture.root,archive)
        self.assertEqual(package.verify_archive(archive),manifest)
        report=self.get(network.REPORT)
        report['inventory'].update({user.APP.removeprefix('console/')+'/user-child.exe':
            {'type':'file','bytes':1,'sha256':'a'*64,'mode':0o644}})
        self.put_json(network.REPORT,report);self.reject('escapes its dedicated')

    def test_fourth_source_header_exact_and_mandatory_in_archive(self):
        self.prepare()
        path=self.fixture.root/network.SOURCE_ROOT/network.SOURCE_FILES['header_sha256']
        original_bytes=path.read_bytes();path.write_bytes(original_bytes+b'changed')
        self.reject('source copy differs')
        path.write_bytes(original_bytes)
        copies={name:(self.fixture.root/network.SOURCE_ROOT/name).read_bytes()
                for key,name in network.SOURCE_FILES.items() if key!='header_sha256'}
        self.put('sources/project.tar.gz',source_archive(copies));self.reject('source missing')

    def test_optional_dns_failures_do_not_inflate_network_claim(self):
        from test_windows_child_network_contract import make_bundle
        for options in ({'dns':'missing'},{'dns':'directory'},{'dns':'export'},
                        {'fqdn_code':-1},{'config_code':50}):
            with self.subTest(options=options):
                case=EnabledPackageControls();case.setUp();self.addCleanup(case.doCleanups)
                case.files,case.reference,case.project,case.source_hashes,case.validator=make_bundle(**options)
                case.prepare();case.verify()
                self.assertIs(case.get(network.CAPABILITY)['network_validated'],False)

    def test_mandatory_local_contract_failure_cannot_be_rehashed(self):
        self.prepare()
        name='net-child-21-200.log'
        value=self.files[name].replace(b'domain=winsock created=1 code=0',
                                      b'domain=winsock created=0 code=10022')
        self.assertNotEqual(value,self.files[name])
        self.put(network.REFERENCE_ROOT+'/'+name,value)
        reference=copy.deepcopy(self.reference)
        reference['reference']['role_logs'][name]={'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest()}
        self.put_json(network.REFERENCE,reference);self.reject()

    def test_network_declared_runtime_success_is_refused(self):
        self.prepare();baseline=self.get(network.REPORT)
        for field in ('network_validated','fixture_executed','console_execution_verified','child_input'):
            changed=copy.deepcopy(baseline);changed[field]=True;self.put_json(network.REPORT,changed)
            with self.subTest(field=field):self.reject('prefix/source/ABI/reference')

    def test_original_headless_reference_remains_mandatory(self):
        self.prepare();(self.fixture.root/'provenance/fixture-source.json').unlink()
        self.reject()


class AssemblyControls(unittest.TestCase):
    """Actual assemble/verify path; external Git/SDK/compiler checks mocked.

    The NET reference validator, prefix merge, retained source reads, title
    receipt copy, manifest and both directory/tar verification remain real.
    """
    def test_network_assembly_with_and_without_battle(self):
        import gzip
        import subprocess
        for battle in (False,True):
            with self.subTest(battle=battle):
                flow=original.FullAssembleControls();self.addCleanup(flow.doCleanups)
                flow.setup_inputs(battle)
                seed=EnabledPackageControls();seed.setUp();self.addCleanup(seed.doCleanups)
                seed.project=flow.project;seed.fixture.project=flow.project
                seed.reference['project']=flow.project
                seed.files['network-source.json']=package.json_bytes(seed.reference)
                seed.prepare(battle)
                flow.config.update(network_enabled=True,run_attempt='1')
                for key in ('network_prefix','network_fixture'):
                    flow.p[key]=flow.temp/'inputs'/key;flow.p[key].mkdir()
                flow.p['network_prefix_report']=flow.temp/'inputs/network-prefix.json'
                flow.config['paths'].update({k:str(flow.p[k]) for k in
                    ('network_prefix','network_fixture','network_prefix_report')})
                flow.materialize_inventory(flow.p['network_prefix'],seed.extra,seed.fixture.root/'console')
                prepared=copy.deepcopy(seed.prepared);prepared['host_stamp']='inert-stamp'
                flow.save(flow.p['network_prefix_report'],prepared)
                for name,value in seed.files.items():flow.put(flow.p['network_fixture']/name,value)
                copies={name:(seed.fixture.root/network.SOURCE_ROOT/name).read_bytes()
                        for name in network.SOURCE_FILES.values()}
                for name,value in copies.items():flow.put(flow.p['repo']/name,value)
                project_archive=source_archive(copies)
                flow.put(flow.p['sources_root']/'project.tar.gz',project_archive)
                flow.sources['inventory']=prefix.inventory(flow.p['sources_root'])
                flow.save(flow.p['sources_manifest'],flow.sources)
                worker=seed.get('PPSA99995/native-wine-child-build.json')
                flow.service['candidate_capabilities']=worker['candidate_capabilities']
                flow.service['worker']['build_id']='f'*40
                for key in ('title','service_work'):
                    flow.save(flow.p[key]/'native-wine-child-build.json',flow.service)
                flow.title.update({k:v for k,v in seed.get('provenance/title.json').items()
                                   if k.startswith('network_') or k=='title_compile_receipt'})
                flow.put(flow.p['title_build']/'wine-child-title-compile.json',
                         (seed.fixture.root/'provenance/title-compile.json').read_bytes())
                flow.title['service_manifest_sha256']=package.digest_file(flow.p['service_work']/'native-wine-child-build.json')
                flow.title['files']=package.title_files(prefix.inventory(flow.p['title']))
                flow.save(flow.p['title_report'],flow.title)
                before=prefix.inventory(flow.temp/'inputs')
                with flow.external_validators(),mock.patch.dict(os.environ,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1'):
                    prior=package.subprocess.run
                    def git_or_external(command,**kwargs):
                        if command[:3]==['git','-C',str(flow.p['repo'])] and command[3]=='archive':
                            return subprocess.CompletedProcess(command,0,stdout=gzip.decompress(project_archive))
                        return prior(command,**kwargs)
                    with mock.patch.object(package.subprocess,'run',side_effect=git_or_external):
                        result=package.assemble(flow.config,flow.out)
                directory=flow.out/'windows-child-fixture';archive=flow.out/'windows-child-fixture.tar.gz'
                accepted=package.verify_directory(directory)
                self.assertEqual(package.verify_archive(archive),accepted)
                self.assertEqual(result['archive'],package.record(archive))
                self.assertTrue(accepted['network_enabled']);self.assertNotIn('user_enabled',accepted)
                self.assertEqual((directory/network.APP/'net-child.exe').read_bytes(),seed.files['net-child.exe'])
                self.assertEqual((directory/'sources/project.tar.gz').read_bytes(),project_archive)
                self.assertEqual(prefix.inventory(flow.temp/'inputs'),before)


if __name__ == '__main__': unittest.main(verbosity=2)
