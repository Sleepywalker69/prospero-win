#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Owned filesystem and pure profile controls; no Wine/PE/network execution."""
import hashlib
import json
from pathlib import Path
import shutil
import stat
import struct
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import build_d3d11_seed as seed
import package_graphics_overlay as overlay
from test_graphics_overlay import image_bytes


def pe_bytes(machine=0x8664):
    value=image_bytes();struct.pack_into('<H',value,0x84,machine);struct.pack_into('<H',value,0x96,0x0002)
    return bytes(value)


def app(root):
    root.mkdir(parents=True)
    for name in seed.APP:
        path=root/name;path.write_bytes(pe_bytes() if name.endswith('.exe') else name.encode());path.chmod(0o755)


def kit(root):
    (root/'pc/tools').mkdir(parents=True)
    shutil.copy2(ROOT/'tools/pw_install.py',root/'pc/tools/pw_install.py')
    (root/'pc/host-wine/usr/bin').mkdir(parents=True)
    for name in ('wine','wineserver'):(root/'pc/host-wine/usr/bin'/name).write_bytes(b'inert not executed')


class SeedTests(unittest.TestCase):
    def test_input_binding_refuses_other_runs_heads_digests_and_expired_artifacts(self):
        fixed=seed.INPUTS['seed']
        run={'id':fixed['run'],'head_sha':fixed['head'],'run_attempt':1,'status':'completed','conclusion':'success',
             'path':fixed['workflow'],'repository':{'full_name':seed.REPO}}
        item={'id':fixed['artifact'],'digest':'sha256:'+fixed['sha256'],'expired':False,
              'workflow_run':{'id':fixed['run'],'head_sha':fixed['head'],'repository_id':1410835302,'head_repository_id':1410835302}}
        seed.metadata('seed',run,item)
        for key,value in [('id',1),('head_sha','0'*40),('conclusion','failure'),('run_attempt',2)]:
            with self.subTest(key=key),self.assertRaises(ValueError):seed.metadata('seed',dict(run,**{key:value}),item)
        for key,value in [('id',1),('digest','sha256:'+'0'*64),('expired',True)]:
            with self.subTest(key=key),self.assertRaises(ValueError):seed.metadata('seed',run,dict(item,**{key:value}))

    def test_original_profile_generator_emits_actual_overrides_paths_and_amd64(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);base=root/'kit';kit(base);application=root/'library/prefixes'/seed.SLUG/'drive_c/graphics-smoke';app(application)
            recipe=root/'recipe.yml';recipe.write_text(overlay.recipe(application))
            # Any accidental call through the install/initialization path fails.
            with patch('subprocess.run',side_effect=AssertionError('no subprocess')),\
                 patch('subprocess.Popen',side_effect=AssertionError('no subprocess')):
                profile=seed.generate_profile(base,recipe,root/'library')
            self.assertIn('dll_overrides = d3d11,dxgi=n\n',profile)
            self.assertIn('architecture = pe64\n',profile)
            self.assertIn('working_directory = C:\\graphics-smoke\n',profile)
            self.assertFalse((root/'library/.cache').exists())
            (application/'d3d11-clear.exe').write_bytes(pe_bytes(0x14c))
            with self.assertRaises(ValueError):seed.generate_profile(base,recipe,root/'library')

    def test_original_profile_guard_refuses_missing_overrides_and_wrong_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);base=root/'kit';kit(base);application=root/'library/prefixes'/seed.SLUG/'drive_c/graphics-smoke';app(application)
            recipe=root/'recipe.yml';original=overlay.recipe(application)
            for change in [original.replace('dxgi: n','dxgi: b'),original.replace('graphics: auto','graphics: gdi'),
                           original.replace('1920x1080','800x600')]:
                recipe.write_text(change)
                with self.assertRaisesRegex(ValueError,'profile differs'):seed.generate_profile(base,recipe,root/'library')

    def test_full_inventory_refuses_links_and_tracks_directory_and_file_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);folder=root/'tree';folder.mkdir();(folder/'empty').mkdir();(folder/'file').write_text('original')
            before=seed.regular_inventory(folder);(folder/'empty').chmod(0o700)
            self.assertNotEqual(seed.canonical(before),seed.canonical(seed.regular_inventory(folder)))
            (folder/'link').symlink_to('file')
            with self.assertRaisesRegex(ValueError,'link or special'):seed.regular_inventory(folder)

    def test_delta_detects_any_original_byte_mode_or_extra_path_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);original=root/'original';original.mkdir();(original/'drive_c').mkdir();(original/'system.reg').write_text('original registry')
            derived=root/'derived';shutil.copytree(original,derived);application=derived/'drive_c/graphics-smoke';app(application)
            records=seed.regular_inventory(application);seed.verify_delta(original,derived,records)
            (derived/'system.reg').write_text('changed')
            with self.assertRaisesRegex(ValueError,'changed original'):seed.verify_delta(original,derived,records)
            shutil.copy2(original/'system.reg',derived/'system.reg');(derived/'system.reg').chmod(0o600)
            with self.assertRaises(ValueError):seed.verify_delta(original,derived,records)
            shutil.copy2(original/'system.reg',derived/'system.reg');(derived/'extra').write_text('unbound')
            with self.assertRaises(ValueError):seed.verify_delta(original,derived,records)

    def test_delta_refuses_changed_prefix_root_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);original=root/'original';original.mkdir(mode=0o700);(original/'drive_c').mkdir()
            derived=root/'derived';shutil.copytree(original,derived);application=derived/'drive_c/graphics-smoke';app(application)
            records=seed.regular_inventory(application);seed.verify_delta(original,derived,records)
            derived.chmod(0o755)
            with self.assertRaisesRegex(ValueError,'root mode'):
                seed.verify_delta(original,derived,records)

    def test_zip_layout_hash_and_inner_tar_sidecar_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'input';source.mkdir();(source/'file').write_text('owned')
            archive=root/'seed.tar.gz'
            with tarfile.open(archive,'w:gz') as tar:tar.add(source,arcname='.')
            def zipped(name,sidecar,extra=False):
                path=root/name
                with zipfile.ZipFile(path,'w') as z:
                    z.write(archive,'seed.tar.gz');z.writestr('seed.tar.gz.sha256',sidecar)
                    if extra:z.writestr('../escape','no')
                return path,{'sha256':seed.sha(path),'member':'seed.tar.gz'}
            path,fixed=zipped('good.zip',seed.sha(archive)+'  seed.tar.gz\n')
            seed.unpack(path,root/'good',fixed,sidecar=True)
            self.assertEqual((root/'good/file').read_text(),'owned')
            with self.assertRaises(ValueError):seed.unpack(path,root/'wrong',dict(fixed,sha256='0'*64),sidecar=True)
            path,fixed=zipped('bad.zip','0'*64+'  seed.tar.gz\n')
            with self.assertRaisesRegex(ValueError,'inner tar'):seed.unpack(path,root/'bad',fixed,sidecar=True)
            path,fixed=zipped('extra.zip',seed.sha(archive)+'  seed.tar.gz\n',True)
            with self.assertRaisesRegex(ValueError,'ZIP layout'):seed.unpack(path,root/'extra',fixed,sidecar=True)

    def test_fresh_derivation_preserves_inputs_and_has_no_profile_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);original=root/'seed';prefix=original/seed.PREFIX/seed.SEED_SLUG
            (prefix/'drive_c').mkdir(parents=True);(prefix/'system.reg').write_text('owned original registry')
            (original/'sources').mkdir();(original/'sources/source.txt').write_text('original source')
            graphics=root/'graphics';application=graphics/'overlay/pc/graphics-smoke/x64';app(application)
            recipe=graphics/'overlay/pc/recipes/diagnostic-d3d11.yml';recipe.parent.mkdir();recipe.write_text(overlay.recipe(application))
            base=root/'kit';kit(base);before=seed.regular_inventory(original);before_graphics=seed.regular_inventory(graphics)
            manifest={'base_tree':seed.BASE_TREE,'files':{'overlay/'+seed.DRIVER_DEST:{'sha256':seed.DRIVER_SHA}}}
            exporter=SimpleNamespace(audit_text=lambda data,name:None)
            with patch.object(seed,'verify_base'),patch.object(seed,'verify_seed',return_value=({'project_tree':seed.BASE_TREE},exporter,None)),\
                 patch.object(seed,'verify_overlay',return_value=manifest):
                result=seed.assemble(original,graphics,base,root/'out')
                self.assertEqual(result['registry_changes'],0)
                self.assertEqual(seed.regular_inventory(original),before)
                self.assertEqual(seed.regular_inventory(graphics),before_graphics)
                self.assertFalse((root/'out'/seed.PROFILE/'profiles.lst').exists())
                self.assertEqual({p.name for p in (root/'out'/seed.PROFILE).iterdir()},{seed.SLUG+'.profile'})
                with self.assertRaisesRegex(ValueError,'fresh'):seed.assemble(original,graphics,base,root/'out')
                with self.assertRaisesRegex(ValueError,'inside an input'):seed.assemble(original,graphics,base,original/'nested')


if __name__=='__main__':unittest.main()
