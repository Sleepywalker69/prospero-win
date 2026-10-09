#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Keep CI fail-closed, source-backed, read-only, and explicit about its artifacts."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import os
import re
import subprocess
import sys
import tempfile
import yaml

ROOT = Path(__file__).resolve().parents[1]
# BaseLoader preserves YAML's `on` key, rather than treating it as YAML 1.1 True.
workflow = yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
assert workflow["permissions"] == {"contents": "read"}
assert workflow["defaults"]["run"]["shell"] == "bash", "pipelines must retain pipefail"
assert set(workflow["on"]) == {"pull_request", "push", "workflow_dispatch"}
assert workflow["on"]["push"]["branches"] == ["main"]
assert set(workflow["on"]["pull_request"]["types"]) == {"opened", "synchronize", "reopened", "labeled", "unlabeled"}
assert workflow["on"]["workflow_dispatch"]["inputs"]["build_native_title"]["default"] == "false"
assert workflow["on"]["workflow_dispatch"]["inputs"]["build_tls_dependencies"]["default"] == "false"
assert workflow["on"]["workflow_dispatch"]["inputs"]["build_wine_prxs"]["default"] == "false"
assert workflow["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
assert workflow["concurrency"]["cancel-in-progress"] == "true"

jobs = workflow["jobs"]
assert set(jobs) == {"host-contracts", "wine-source-contracts", "native-title", "tls-dependencies", "wine-prxs"}
for name, job in jobs.items():
    assert job["runs-on"] == "ubuntu-24.04", name
    assert 0 < int(job["timeout-minutes"]) <= 60, name
    assert "permissions" not in job and "continue-on-error" not in job, name
    for step in job["steps"]:
        assert "continue-on-error" not in step, name
        if "uses" not in step:
            continue
        assert re.fullmatch(r"actions/(checkout|setup-python|upload-artifact)@[0-9a-f]{40}", step["uses"]), step["uses"]
        if step["uses"].startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] == "false"
        if step["uses"].startswith("actions/upload-artifact@"):
            assert step["with"]["retention-days"] == "7"
            assert "runner.temp" in step["with"]["path"]

host = jobs["host-contracts"]["steps"]
assert any("make -j2 all" in step.get("run", "") for step in host)
sanitize = next(step for step in host if "make -j2 sanitize" in step.get("run", ""))
assert "!cancelled()" in sanitize["if"] and "steps.prerequisites.outcome == 'success'" in sanitize["if"]
assert "detect_leaks=0" not in str(workflow)

source = jobs["wine-source-contracts"]
assert "PROSPERO_WINE_SOURCE" in source["env"]
assert source["env"]["XDG_CACHE_HOME"].startswith("${{ github.workspace }}/"), "generator changes directory; cache path must be absolute"
source_runs = "\n".join(step.get("run", "") for step in source["steps"])
for command in ("tools/build_wine_ps5.sh", "tools/build_wine_runtime.sh", "rev-parse HEAD",
                "git -C \"$tree\" apply --check", "git -C \"$tree\" apply \"",
                "tools/stage_vk_batch.py", "tests/test_wowprospero_contract.py",
                "tests/test_ws2_fqdn.py", "tests/test_wine_lookup_misses.py"):
    assert command in source_runs, command

native = jobs["native-title"]
for guard in ("github.event_name == 'workflow_dispatch'", "inputs.build_native_title",
              "github.event.pull_request.head.repo.full_name == github.repository",
              "contains(github.event.pull_request.labels.*.name, 'build-native-title')"):
    assert guard in native["if"], guard
assert native["needs"] == ["host-contracts", "wine-source-contracts"]
native_runs = "\n".join(step.get("run", "") for step in native["steps"])
for required in ("tools/build_native.sh", "readelf -h build/native/eboot.elf",
                 "test ! -e dist/PPSA99995/dev.conf", "git archive HEAD", "SHA256SUMS",
                 "tar -czf", "Native-title-only", "No console execution"):
    assert required in native_runs, required
bundle = native["steps"][-1]
assert bundle["with"]["if-no-files-found"] == "error"
assert "if" not in bundle, "binary upload must require prior steps to succeed"

tls = jobs["tls-dependencies"]
for guard in ("github.event_name == 'workflow_dispatch'", "inputs.build_tls_dependencies",
              "github.event.pull_request.head.repo.full_name == github.repository",
              "contains(github.event.pull_request.labels.*.name, 'build-tls-dependencies')"):
    assert guard in tls["if"], guard
assert tls["needs"] == ["host-contracts", "wine-source-contracts"]
assert tls["env"]["LLVM_CONFIG"] == "/usr/bin/llvm-config-18"
tls_runs = "\n".join(step.get("run", "") for step in tls["steps"])
for required in ("llvm-18-dev", "tools/setup-native-dependencies.sh", "tools/build_tls_ps5.sh",
                 "tls_manifest.py verify", "-D__PROSPERO__", "__FreeBSD__", "__x86_64__",
                 "pw_gnutls_libc", "pw_ws2_32_libc", "sceNetResolverStartNtoa",
                 "HAVE_KERN_ARND 1", "sysrng-netbsd", "llvm-readelf", "llvm-ar",
                 "nettle-*.tar.gz", "gnutls-*.tar.xz", "cacert-*.pem",
                 "nettle-3.10.1-ed448-canonical.patch", "gnutls-3.8.13-kern-arnd-headers.patch",
                 "git archive HEAD", "THIRD_PARTY.md",
                 "configure.log", "make.log", "install.log", "SHA256SUMS",
                 "No console execution", "No Wine PRXs"):
    assert required in tls_runs, required
assert "|| true" not in tls_runs and "gnutls_cv_" not in tls_runs and "! grep" not in tls_runs
# Execute the real patch-staging command with original fixture bytes. Both
# patches must accompany their source archives, and absence must fail.
patch_copy = "cp tools/patches/" + tls_runs.split("cp tools/patches/", 1)[1].split(
    "cp tools/build_tls_ps5.sh", 1)[0].strip()
with tempfile.TemporaryDirectory(prefix="pw-ci-source-patches-") as directory:
    root = Path(directory)
    (root / "tools/patches").mkdir(parents=True)
    (root / "bundle/sources").mkdir(parents=True)
    names = ("nettle-3.10.1-ed448-canonical.patch", "gnutls-3.8.13-kern-arnd-headers.patch")
    for name in names:
        (root / "tools/patches" / name).write_text("synthetic source patch " + name)
    def stage_patches():
        return subprocess.run(["bash", "-e", "-o", "pipefail", "-c", patch_copy], cwd=root,
                              env=dict(os.environ, stage=str(root / "bundle")), capture_output=True, text=True)
    assert stage_patches().returncode == 0
    for name in names:
        assert (root / "bundle/sources" / name).read_bytes() == (root / "tools/patches" / name).read_bytes()
        (root / "tools/patches" / name).unlink()
        assert stage_patches().returncode != 0, "a missing source patch must stop publication"
        (root / "tools/patches" / name).write_text("synthetic source patch " + name)
collect = next(step for step in tls["steps"] if step.get("name", "").startswith("Collect raw"))
assert "always()" in collect["if"]
tls_bundle = tls["steps"][-1]
assert "if" not in tls_bundle and tls_bundle["with"]["if-no-files-found"] == "error"
# Execute both real rejection blocks under the runner's Bash options. An
# inverted standalone grep is exempt from errexit and used to let these
# forbidden conditions pass; match, nonmatch and read errors all matter.
target_run = next(step["run"] for step in tls["steps"] if step.get("name") ==
                  "Cross-compile native adapters and check target outputs")
probe = next(line for line in target_run.splitlines() if " -dM " in line)
assert "-D__PROSPERO__" not in probe, "target predefines must be observed, not supplied"
# Original fixture for the public SDK v0.42 wrapper policy: -E alone
# appends crt1.o, and the active '-x c' would parse it as C. The real SDK
# defines target macros; this fixture tests only invocation/CRT handling.
with tempfile.TemporaryDirectory(prefix="pw-ci-sdk-probe-") as directory:
    root = Path(directory)
    (root / "sdk/bin").mkdir(parents=True)
    (root / "tls-evidence").mkdir()
    wrapper = root / "sdk/bin/prospero-clang"
    wrapper.write_text("#!/bin/sh\ncrt=crt1.o\n"
                       "for arg in \"$@\"; do\n"
                       " case $arg in -c|-nostartfiles|-shared) crt= ;; esac\ndone\n"
                       "printf '%s\\n' \"$@\" \"$crt\" > \"$PW_ARGUMENT_LOG\"\n"
                       "if [ -n \"$crt\" ]; then echo 'CRT object passed to C preprocessor' >&2; exit 41; fi\n"
                       "printf '#define __FreeBSD__ 9\\n#define __x86_64__ 1\\n#define __PROSPERO__ 1\\n'\n")
    wrapper.chmod(0o755)
    arguments = root / "arguments.txt"
    env = dict(os.environ, sdk=str(root / "sdk"), RUNNER_TEMP=directory, PW_ARGUMENT_LOG=str(arguments))
    def run_probe(command):
        return subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", command],
                              env=env, capture_output=True, text=True)
    good = run_probe(probe)
    assert good.returncode == 0, good.stderr
    forwarded = arguments.read_text().splitlines()
    assert all(flag in forwarded for flag in ("-c", "-dM", "-E", "-x", "c", "/dev/null"))
    assert "crt1.o" not in forwarded
    assert not any(arg.startswith("-D") for arg in forwarded), "do not fabricate observed target macros"
    bad = run_probe(probe.replace(" -c ", " "))
    assert bad.returncode == 41 and "CRT object" in bad.stderr
    assert "crt1.o" in arguments.read_text().splitlines()
with tempfile.TemporaryDirectory(prefix="pw-ci-rejection-") as directory:
    root = Path(directory)
    (root / "tls-evidence/objects").mkdir(parents=True)
    (root / "source").mkdir()
    env = dict(os.environ, RUNNER_TEMP=directory, source=str(root / "source"))
    for label, relative, forbidden, allowed in (
            ("shared-time", "tls-evidence/objects/pw_gnutls_libc.symbols", "                 U gmtime\n", "T gmtime_r\n"),
            ("entropy-backend", "source/config.h", "#define HAVE_GETENTROPY 1\n", "/* #undef HAVE_GETENTROPY */\n")):
        block = target_run.split(f"# Begin {label} rejection.", 1)[1].split(f"# End {label} rejection.", 1)[0]
        path = root / relative
        for content, expected in ((forbidden, 1), (allowed, 0), (None, 2)):
            if content is None:
                path.unlink()
            else:
                path.write_text(content)
            result = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", block],
                                    env=env, capture_output=True, text=True)
            assert result.returncode == expected, (label, expected, result.returncode, result.stderr)
    # The actual parser requires one valid header per object, not merely
    # one matching member somewhere in an otherwise mixed archive.
    parser = target_run.split("# Begin archive-header validation.", 1)[1].split(
        "# End archive-header validation.", 1)[0].split("<<'PY'\n", 1)[1].split("\nPY", 1)[0]
    objects = root / "headers"
    objects.mkdir()
    header = "  Class: ELF64\n  Machine: Advanced Micro Devices X86-64\n"
    for name in ("pw_gnutls_libc", "pw_ws2_32_libc", "libgnutls", "libnettle", "libhogweed"):
        (objects / f"{name}.headers").write_text(header)
        if name.startswith("lib"):
            (objects / f"{name}.members").write_text("one.o\n")
    def parse_headers():
        return subprocess.run([sys.executable, "-c", parser, str(objects)], capture_output=True, text=True)
    assert parse_headers().returncode == 0
    (objects / "libgnutls.members").write_text("one.o\ntwo.o\n")
    mixed = objects / "libgnutls.headers"
    mixed.write_text(header + "  Class: ELF32\n  Machine: ARM\n")
    assert parse_headers().returncode != 0, "a valid member must not hide a wrong-target member"
    mixed.write_text(header)
    assert parse_headers().returncode != 0, "every archive member needs a target header"
    mixed.write_text(header * 2)
    assert parse_headers().returncode == 0
    (objects / "pw_gnutls_libc.headers").unlink()
    assert parse_headers().returncode != 0, "a missing adapter object/header must fail"
prxs = jobs["wine-prxs"]
for guard in ("github.event_name == 'workflow_dispatch'", "inputs.build_wine_prxs",
              "github.event.pull_request.head.repo.full_name == github.repository",
              "contains(github.event.pull_request.labels.*.name, 'build-wine-prxs')"):
    assert guard in prxs["if"], guard
assert prxs["needs"] == ["host-contracts", "wine-source-contracts"]
assert prxs["env"]["LLVM_CONFIG"] == "/usr/bin/llvm-config-18"
assert prxs["env"]["XDG_CACHE_HOME"].startswith("${{ github.workspace }}/")
prx_runs = "\n".join(step.get("run", "") for step in prxs["steps"])
for token in ("30597512539e7edfde079cbcaf4a626bc0a948c5", "tools/setup-native-dependencies.sh",
              "native_app_builder.cpp", "sce_module_writer.cpp", "self_container.cpp", "elf_object.cpp",
              "tools/makedep", "tools/winebuild/winebuild", "tools/winegcc/winegcc", "tools/widl/widl",
              "tools/wrc/wrc", "tools/wmc/wmc", "--without-x", "--without-freetype",
              "tools/build_tls_ps5.sh", "HAVE_KERN_ARND 1", "sysrng-netbsd", "-c -dM -E", "PROSPERO_TLS_ROOT=", "tools/build_wine_ps5.sh --source",
              "--host-tools", "--prx-foundation", "tools/check_wine_prx_build.py", "--llvm-bindir",
              "git archive HEAD", "freetype-*.tar.xz", "zlib-*.tar.gz", "THIRD_PARTY.md", "SHA256SUMS",
              "No console execution", "Converted export NID correctness and native module loading remain unverified"):
    assert token in prx_runs, token
assert "|| true" not in prx_runs
assert not any(arg in prx_runs for arg in ("--radv ", "--ps5vk-sdk ", "--ps5-opengl-sdk "))
assert "always()" in next(step["if"] for step in prxs["steps"] if step.get("name", "").startswith("Collect raw"))
assert "if" not in prxs["steps"][-1] and prxs["steps"][-1]["with"]["if-no-files-found"] == "error"
assert "tests/test_check_wine_prx_build.py" in (ROOT / "Makefile").read_text()
metadata = next(step for step in prxs["steps"] if step.get("name") ==
                "Retain actual module metadata even after acceptance failure")
assert "always()" in metadata["if"]
metadata_code = metadata["run"].split("<<'PY'\n", 1)[1].split("\nPY", 1)[0]
with tempfile.TemporaryDirectory(prefix="pw-ci-module-evidence-") as directory:
    root = Path(directory)
    artifacts, tools, evidence = root / "prx", root / "tools", root / "evidence"
    artifacts.mkdir(); tools.mkdir()
    for name in ("broken.shared.elf", "later.shared.elf", "later.elf"):
        (artifacts / name).write_text("synthetic artifact")
    config = tools / "llvm-config"
    config.write_text(f"#!/bin/sh\nprintf '%s\\n' '{tools}'\n")
    config.chmod(0o755)
    for name in ("llvm-readelf", "llvm-objdump"):
        tool = tools / name
        tool.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\"\n"
                        "case \"$*\" in *broken.shared.elf*) exit 9 ;; esac\n")
        tool.chmod(0o755)
    result = subprocess.run([sys.executable, "-c", metadata_code, str(artifacts), str(config),
                             str(tools / "unused-converter"), str(evidence)], capture_output=True, text=True)
    assert result.returncode == 1
    assert 'EXIT=9' in (evidence / 'broken.shared.elf.log').read_text()
    assert 'EXIT=0' in (evidence / 'later.shared.elf.log').read_text()
    assert '--dyn-syms -r -W' in (evidence / 'later.shared.elf.log').read_text()
    assert (evidence / 'later.shared.elf-disassembly.log').is_file()
    assert (evidence / 'later.elf.log').is_file()
watchdog = next(step for step in prxs['steps'] if step.get('name') ==
                'Check actual compiled watchdog source and object')
assert 'check_wine_prx_build.py' in prx_runs and 'watchdog-build.json' in prx_runs
code = watchdog['run'].split("<<'PY'\n", 1)[1].split('\nPY', 1)[0]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('watchdog_fixture', ROOT/'tests/test_wine_watchdog_process_guard.py')
guard = importlib.util.module_from_spec(spec); spec.loader.exec_module(guard)
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory); work = root/'work'; output = root/'watchdog.json'; readelf = root/'readelf'
    source, obj, linked = work/'source/server/thread.c', work/'build/server/thread.o', work/'build/server/wineserver'
    source.parent.mkdir(parents=True); obj.parent.mkdir(parents=True)
    patched = 'static void wait_watchdog( void *arg )\n{\n'+guard.patch_sides()[2]+'\n}\nstatic void start_wait_watchdog(void) {}\n'
    source.write_text(patched); linked.write_bytes(b'original linked fixture')
    header = bytearray(64); header[:7] = b'\x7fELF\x02\x01\x01'; struct.pack_into('<HH', header, 16, 1, 62)
    obj.write_bytes(header)
    row = '1: 00000000 19 FUNC LOCAL DEFAULT 1 wait_watchdog'
    def analyzer(text=row, status=0):
        readelf.write_text("#!/bin/sh\ncat <<'END'\n"+text+"\nEND\nexit "+str(status)+"\n")
        readelf.chmod(0o755)
    analyzer()
    report = {'prx': {'status': '0'}, 'patches': [guard.PATCH.name], 'targets': {
        'server/wineserver': {'built': True, 'sha256': hashlib.sha256(linked.read_bytes()).hexdigest()}}}
    def run():
        (work/'report.json').write_text(json.dumps(report))
        return subprocess.run([sys.executable, '-c', code, str(work), str(readelf), str(output)],
                              cwd=ROOT, capture_output=True, text=True)
    assert run().returncode == 0
    recorded = json.loads(output.read_text()); assert recorded['executed'] is False
    assert recorded['object_sha256'] == hashlib.sha256(header).hexdigest()
    for bad in ('', row.replace('FUNC', 'OBJECT'), row.replace('DEFAULT 1', 'DEFAULT UND'), row.replace(' 19 ', ' 0 '), row+'\n'+row):
        analyzer(bad); assert run().returncode != 0
    analyzer(status=7); assert run().returncode != 0; analyzer()
    obj.unlink(); assert run().returncode != 0; obj.write_bytes(header)
    for offset, value in ((4, 1), (16, 2), (18, 3)):
        bad = bytearray(header); bad[offset] = value; obj.write_bytes(bad); assert run().returncode != 0
    obj.write_bytes(header)
    source.write_text(patched.replace(guard.condition(guard.patch_sides()[2])[0], guard.condition(guard.patch_sides()[1])[0]))
    assert run().returncode != 0; source.write_text(patched)
    report['patches'] = []; assert run().returncode != 0; report['patches'] = [guard.PATCH.name]
    report['prx']['status'] = 'skipped'; assert run().returncode != 0; report['prx']['status'] = '0'
    linked.write_bytes(b'changed after report'); assert run().returncode != 0

print("CI build contract passed: preserved gates, source checks, opt-in title, TLS and checked Wine PRX build artifacts")
