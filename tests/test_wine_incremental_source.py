#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Policy contracts plus an actual small compiler/Make DAG, not a Wine benchmark."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("incremental", ROOT / "tools/wine_incremental_source.py")
policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)

def context(source, build):
    return {"toolchain_partition": "a"*64, "configuration": "b"*64,
            "recipes": {"builder": "c"*64, "stager": "d"*64},
            "source_path": str(source), "build_path": str(build)}
def manifest(source, ctx):
    return {"schema": policy.SCHEMA, "context": copy.deepcopy(ctx), "files": policy.inventory(source)}

class Policy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root/"source"; self.source.mkdir()
        for p in ["server/process.c", "server/process.h", "include/global.h",
                  "tools/makedep.c", "tools/widl/parser.c", "tools/winebuild/main.c",
                  "configure", "include/config.h.in", "server/Makefile.in",
                  "libs/ffmpeg/config.h", "libs/jpeg/jconfig.h", "libs/vkd3d/config.h"]:
            target = self.source/p; target.parent.mkdir(parents=True, exist_ok=True); target.write_text("old\n")
        self.ctx = context(self.source, self.root/"build")
        self.old = manifest(self.source, self.ctx)

    def test_classifier_boundary_and_file_membership(self):
        for name in self.old["files"]:
            changed = copy.deepcopy(self.old); changed["files"][name]["sha256"] = "f"*64
            result = policy.classify(self.old, changed)
            self.assertEqual(result["eligible"], name in ("server/process.c", "server/process.h"), name)
        for kind in ("delete", "rename", "add"):
            changed = copy.deepcopy(self.old)
            if kind != "add": record = changed["files"].pop("server/process.c")
            if kind != "delete": changed["files"]["server/new.c"] = self.old["files"]["server/process.c"]
            self.assertFalse(policy.classify(self.old, changed)["eligible"])
        for key in self.ctx:
            changed = copy.deepcopy(self.old)
            changed["context"][key] = {"builder": "f"*64, "stager": "d"*64} if key == "recipes" else (
                "/different/path" if key.endswith("_path") else "f"*64)
            self.assertFalse(policy.classify(self.old, changed)["eligible"], key)

    def test_modes_manifest_types_and_staged_roots(self):
        changed = copy.deepcopy(self.old)
        changed["files"]["server/process.c"]["mode"] = 0o755
        self.assertFalse(policy.classify(self.old, changed)["eligible"])
        for key in ("context", "files"):
            malformed = copy.deepcopy(self.old); malformed[key] = None
            with self.assertRaises(ValueError): policy.validate(malformed)
        malformed = copy.deepcopy(self.old); malformed["context"]["recipes"] = {"other":"a"*64}
        with self.assertRaises(ValueError): policy.validate(malformed)
        malformed = copy.deepcopy(self.old); malformed["context"]["source_path"] += "/../source"
        with self.assertRaises(ValueError): policy.validate(malformed)
        staged = self.root/"staged"; shutil.copytree(self.source, staged)
        current = manifest(staged, self.ctx)
        barrier = max(r["mtime_ns"] for r in self.old["files"].values())
        link = self.root/"root-link"; link.symlink_to(staged, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "real directory"):
            policy.inventory(link)
        with self.assertRaisesRegex(ValueError, "real directory"):
            policy.prepare_staged_timestamps(self.old, current, link, barrier, now_ns=barrier+1)
        with self.assertRaisesRegex(ValueError, "distinct"):
            policy.prepare_staged_timestamps(self.old, self.old, self.source, barrier, now_ns=barrier+1)
        (staged/"directory-link").symlink_to(self.source/"server", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "regular"):
            policy.inventory(staged)

    def test_hardlinked_staging_cannot_mutate_donor_timestamp(self):
        staged = self.root/"staged"; shutil.copytree(self.source, staged)
        target = staged/"server/process.c"; target.unlink()
        donor = self.source/"server/process.c"; before = donor.stat().st_mtime_ns
        os.link(donor, target)
        current = copy.deepcopy(self.old)
        barrier = max(r["mtime_ns"] for r in self.old["files"].values())
        with self.assertRaisesRegex(ValueError, "hardlinks"):
            policy.prepare_staged_timestamps(self.old, current, staged, barrier, now_ns=barrier+1)
        self.assertEqual(donor.stat().st_mtime_ns, before)

    def test_reconcile_exact_bytes_modes_clock_and_membership(self):
        staged = self.root/"staged"; shutil.copytree(self.source, staged)
        current = manifest(staged, self.ctx)
        barrier = max(x["mtime_ns"] for x in self.old["files"].values())
        result = policy.prepare_staged_timestamps(self.old, current, staged, barrier, now_ns=barrier+1)
        self.assertTrue(result["eligible"])
        for p, old in self.old["files"].items():
            self.assertEqual((staged/p).stat().st_mtime_ns, old["mtime_ns"])
        self.assertFalse(policy.prepare_staged_timestamps(self.old, current, staged, barrier, now_ns=barrier)["eligible"])
        (staged/"unexpected").write_text("cannot overlay stale files")
        with self.assertRaisesRegex(ValueError, "membership"):
            policy.prepare_staged_timestamps(self.old, current, staged, barrier, now_ns=barrier+1)
        (staged/"unexpected").unlink()
        (staged/"server/process.c").write_text("unrecorded")
        with self.assertRaisesRegex(ValueError, "bytes"):
            policy.prepare_staged_timestamps(self.old, current, staged, barrier, now_ns=barrier+1)

    def test_filesystem_timestamp_rounding_refuses_incremental(self):
        staged = self.root/"staged"; shutil.copytree(self.source, staged)
        (staged/"server/process.c").write_text("changed")
        current = manifest(staged, self.ctx)
        barrier = max(r["mtime_ns"] for r in self.old["files"].values())
        real = os.utime
        def rounded(path, *, ns, follow_symlinks):
            real(path, ns=(barrier, barrier) if str(path).endswith("process.c") else ns,
                 follow_symlinks=follow_symlinks)
        with mock.patch("os.utime", side_effect=rounded):
            result = policy.prepare_staged_timestamps(self.old, current, staged, barrier, now_ns=barrier+1)
        self.assertFalse(result["eligible"])
        self.assertIn("rounded", result["reason"])

    def test_unsafe_paths_symlinks_and_donor_time(self):
        changed = copy.deepcopy(self.old)
        changed["files"]["../escape.c"] = changed["files"].pop("server/process.c")
        with self.assertRaises(ValueError): policy.classify(self.old, changed)
        (self.source/"linked.h").symlink_to(self.source/"server/process.h")
        with self.assertRaisesRegex(ValueError, "regular"): policy.inventory(self.source)
        (self.source/"linked.h").unlink()
        with self.assertRaisesRegex(ValueError, "barrier"):
            policy.prepare_staged_timestamps(self.old, self.old, self.source, 0, now_ns=1)

    def test_pinned_wine_exposes_explicit_dependency_refresh(self):
        source = os.environ.get("PROSPERO_WINE_SOURCE")
        if not source:
            self.skipTest("pinned Wine makedep source is supplied by the dedicated workflow")
        text = (Path(source)/"tools/makedep.c").read_text()
        self.assertIn('output( "depend: %s\\n", makedep );', text)
        self.assertIn('strarray_add( &make->phony_targets, "depend" );', text)
        self.assertIn('output( "Makefile: config.status %s\\n", makedep );', text)
        self.assertIn('root_src_dir_path( "include/config.h.in" )', text)

@unittest.skipUnless(shutil.which("cc") and shutil.which("make"), "real C compiler and make required")
class RealDag(unittest.TestCase):
    def test_scenarios(self):
        records = []
        for scenario, expected in [("cold",3), ("unchanged",0), ("native-only",0),
                                   ("one-C",1), ("local-header",2), ("deleted-source",2),
                                   ("renamed-source",3), ("configuration",3),
                                   ("toolchain",3), ("flags",3)]:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); source = root/"source"; units = source/"server"
                units.mkdir(parents=True)
                (units/"process.h").write_text("#define VALUE 7\n")
                (units/"process.c").write_text('#include "process.h"\nint a(void) { return VALUE; }\n')
                (units/"thread.c").write_text('#include "process.h"\nint b(void) { return VALUE + 1; }\n')
                (units/"file.c").write_text('int c(void) { return 9; }\n')
                (source/"configure").write_text("original configure input\n")
                build = root/"build"; build.mkdir()
                ctx = context(source, build)
                flags = "-O2 -fPIC"
                def write_make(directory):
                    names = sorted(p.stem for p in (source/"server").glob("*.c"))
                    objects = " ".join(n+".o" for n in names)
                    lines = [".DEFAULT_GOAL := all", "CC := cc", "CFLAGS := "+flags,
                             "SRC := "+str(source/"server"), "OBJECTS := "+objects,
                             ".PHONY: all depend", "all: fixture.so",
                             "fixture.so: $(OBJECTS)", "\t@echo LINK",
                             "\t@$(CC) -shared $(OBJECTS) -o $@",
                             "%.o: $(SRC)/%.c", "\t@echo COMPILE $*",
                             "\t@$(CC) $(CFLAGS) -c $< -o $@"]
                    lines += ["depend:"] + [
                        "\t@$(CC) $(CFLAGS) -MM -MP -MT "+n+".o $(SRC)/"+n+".c > "+n+".d"
                        for n in names]
                    lines += ["-include "+" ".join(n+".d" for n in names)]
                    (directory/"Makefile").write_text("\n".join(lines)+"\n")
                def make(directory):
                    started = time.monotonic()
                    subprocess.run(["make","-s","depend"], cwd=directory, check=True, capture_output=True)
                    run = subprocess.run(["make","-s","-j2"], cwd=directory, check=True, text=True, capture_output=True)
                    return run.stdout.count("COMPILE "), run.stdout.count("LINK"), time.monotonic()-started
                write_make(build); initial = make(build)
                self.assertEqual(initial[0], 3)
                old = manifest(source, ctx)
                barrier = max(p.stat().st_mtime_ns for p in list(source.rglob("*"))+list(build.rglob("*")) if p.is_file())
                staged = root/"staged"; shutil.copytree(source, staged)
                if scenario == "one-C": (staged/"server/process.c").write_text('int a(void) { return 17; }\n')
                elif scenario == "local-header": (staged/"server/process.h").write_text("#define VALUE 8\n")
                elif scenario == "deleted-source": (staged/"server/file.c").unlink()
                elif scenario == "renamed-source": (staged/"server/file.c").rename(staged/"server/renamed_file.c")
                elif scenario == "configuration": (staged/"configure").write_text("new configure input\n")
                elif scenario == "toolchain": ctx["toolchain_partition"] = "e"*64
                elif scenario == "flags": ctx["configuration"] = "e"*64; flags = "-O0 -fPIC"
                elif scenario == "native-only": (root/"native-only.c").write_text("outside Wine source cohort\n")
                current = manifest(staged, ctx)
                started = time.monotonic()
                decision = policy.prepare_staged_timestamps(old, current, staged, barrier)
                reconcile_seconds = time.monotonic()-started
                cold = scenario == "cold" or not decision["eligible"]
                # Complete replacement, never an overlay retaining deleted source.
                retired = root/"retired"; source.rename(retired); staged.rename(source)
                if cold:
                    shutil.rmtree(build); build.mkdir()
                write_make(build)
                actual = make(build)
                self.assertEqual(actual[0], expected, (scenario,decision))
                self.assertEqual(actual[1], 0 if scenario in ("unchanged","native-only") else 1)
                self.assertEqual(set(policy.inventory(source)), set(current["files"]))
                # Independent clean rebuild from exactly the same current bytes/flags.
                clean = root/"clean"; clean.mkdir(); write_make(clean); make(clean)
                self.assertEqual(policy.digest(build/"fixture.so"), policy.digest(clean/"fixture.so"))
                records.append({"scenario":scenario, "eligible":decision["eligible"], "cold":cold,
                                "compiled_units":actual[0], "links":actual[1],
                                "dag_seconds":actual[2], "reconcile_seconds":reconcile_seconds,
                                "clean_output_equal":True})
        report = {"schema":"pw-synthetic-incremental-dag/1", "wine_speedup_claim":False,
                  "checkpoint_transfer_measured":False, "scenarios":records}
        destination = os.environ.get("PW_INCREMENTAL_REPORT")
        if destination: Path(destination).write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps(report))

class EarlyDecision(unittest.TestCase):
    def test_mocked_admission_and_workflow_order(self):
        module = importlib.util.spec_from_file_location("receipt", ROOT/"tools/wine_reuse_decision.py")
        receipt = importlib.util.module_from_spec(module); module.loader.exec_module(receipt)
        cache = {"exact_hit":False, "any_hit":False, "restore_step_elapsed_seconds":0.25}
        for reused in (False, True):
            result = receipt.decision({"reused":reused, "reason":"artifact digest differs"}, cache,
                                      elapsed_seconds=0.5)
            self.assertEqual(result["fallback_required"], not reused)
            self.assertFalse(result["runtime_build_complete"])
            self.assertEqual(result["reason"], "artifact digest differs")
            self.assertEqual(result["cache_restore"], cache)
        result = receipt.decision({"reason":"download https://example.invalid/a?secret=hidden failed"},
                                  cache, elapsed_seconds=0)
        self.assertNotIn("hidden", json.dumps(result))
        workflow = (ROOT/".github/workflows/windows-child-fixture.yml").read_text()
        names = ["Start host cache restore clock", "Restore host compiler results only",
                 "Retain host cache restore decision", "Start host admission clock",
                 "Reuse an exactly matched accepted host runtime when available",
                 "Publish concise host admission decision",
                 "Upload host decision before any full build fallback",
                 "Build complete matching host Wine"]
        positions = [workflow.index("- name: "+name) for name in names]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("if: ${{ steps.host-reuse.outputs.reused != 'true' }}", workflow)
        # Exercise all three receipt CLI commands using temporary files only.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); clock = root/"clock"; cache_path = root/"cache.json"
            reuse = root/"reuse.json"; out = root/"decision.json"
            script = str(ROOT/"tools/wine_reuse_decision.py")
            import sys
            def call(*args):
                subprocess.run([sys.executable,script,*args],check=True,capture_output=True,
                               env=dict(os.environ, PW_CACHE_RESTORE_HIT="", PW_CACHE_MATCHED_KEY=""))
            call("start","--clock",str(clock))
            call("cache","--clock",str(clock),"--output",str(cache_path))
            reuse.write_text('{"reused":false,"reason":"mock guard rejected"}')
            call("start","--clock",str(clock))
            call("admission","--clock",str(clock),"--reuse",str(reuse),
                 "--cache",str(cache_path),"--output",str(out))
            result = json.loads(out.read_text())
            self.assertTrue(result["fallback_required"])
            self.assertEqual(result["reason"], "mock guard rejected")
            self.assertFalse(result["cache_restore"]["any_hit"])
            destination = os.environ.get("PW_ADMISSION_REPORT")
            if destination: Path(destination).write_text(out.read_text())

if __name__ == "__main__":
    unittest.main()
