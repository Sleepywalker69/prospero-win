#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Keep CI fail-closed, source-backed, read-only, and explicit about its artifacts."""
from pathlib import Path
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
assert workflow["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
assert workflow["concurrency"]["cancel-in-progress"] == "true"

jobs = workflow["jobs"]
assert set(jobs) == {"host-contracts", "wine-source-contracts", "native-title", "tls-dependencies"}
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
                 "nettle-3.10.1-ed448-canonical.patch", "git archive HEAD", "THIRD_PARTY.md",
                 "configure.log", "make.log", "install.log", "SHA256SUMS",
                 "No console execution", "No Wine PRXs"):
    assert required in tls_runs, required
assert "|| true" not in tls_runs and "gnutls_cv_" not in tls_runs and "! grep" not in tls_runs
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
print("CI build contract passed: preserved gates, source checks, opt-in title and real TLS cross-build artifacts")
