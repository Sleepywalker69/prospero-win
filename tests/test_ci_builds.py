#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Keep CI fail-closed, source-backed, read-only, and explicit about its artifacts."""
from pathlib import Path
import re
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
assert workflow["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
assert workflow["concurrency"]["cancel-in-progress"] == "true"

jobs = workflow["jobs"]
assert set(jobs) == {"host-contracts", "wine-source-contracts", "native-title"}
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
print("CI build contract passed: pinned read-only actions, preserved gates, actual patch checks, optional title-only artifacts")
