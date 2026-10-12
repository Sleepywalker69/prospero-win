#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Conservative source eligibility and timestamp preparation for Wine checkpoints.

This module does not authenticate/download checkpoints or skip the build.
The future adapter must verify a successful same-repository donor and full
checkpoint digests first, then regenerate dependencies and run normal make.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import re
import stat
import time

SCHEMA = "pw-wine-incremental-source/1"
# Configuration, generators, source membership and global include headers stay
# cold in this first policy. Existing local C/header changes use fresh makedep.
ORDINARY_INPUTS = {
    "server/process.c", "server/thread.c", "server/ptrace.c", "server/file.c",
    "server/process.h", "server/thread.h", "server/object.h",
    "dlls/ntdll/unix/virtual.c", "dlls/ntdll/unix/unix_private.h",
}
CONTEXT = {"toolchain_partition", "configuration", "recipes", "source_path", "build_path"}

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def inventory(root):
    root = Path(root)
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("source inventory requires regular files: " + str(relative))
        result[relative.as_posix()] = {
            "sha256": digest(path), "mode": stat.S_IMODE(info.st_mode),
            "mtime_ns": info.st_mtime_ns,
        }
    return result

def validate(value):
    if not isinstance(value, dict) or set(value) != {"schema", "context", "files"}:
        raise ValueError("source manifest shape differs")
    if value["schema"] != SCHEMA or set(value["context"]) != CONTEXT:
        raise ValueError("source manifest context differs")
    context = value["context"]
    for name in ("toolchain_partition", "configuration"):
        if not re.fullmatch("[0-9a-f]{64}", context[name]):
            raise ValueError("missing exact context digest")
    if not context["recipes"] or any(not re.fullmatch("[0-9a-f]{64}", v)
                                     for v in context["recipes"].values()):
        raise ValueError("missing build/staging recipe identity")
    for name in ("source_path", "build_path"):
        if not Path(context[name]).is_absolute():
            raise ValueError("build paths must be exact absolute paths")
    for name, record in value["files"].items():
        p = Path(name)
        if not name or p.is_absolute() or any(x in ("", ".", "..", ".git") for x in name.split("/")):
            raise ValueError("unsafe source path")
        if set(record) != {"sha256", "mode", "mtime_ns"} or not re.fullmatch("[0-9a-f]{64}", record["sha256"]):
            raise ValueError("invalid source record")
        if type(record["mode"]) is not int or record["mode"] not in (0o644, 0o755):
            raise ValueError("unsupported source mode")
        if type(record["mtime_ns"]) is not int or record["mtime_ns"] < 0:
            raise ValueError("invalid source timestamp")

def classify(previous, current):
    validate(previous); validate(current)
    if previous["context"] != current["context"]:
        return {"eligible": False, "reason": "toolchain/configuration/recipe/path change", "changed": []}
    before, after = previous["files"], current["files"]
    if set(before) != set(after):
        return {"eligible": False, "reason": "source file added/deleted/renamed",
                "changed": sorted(set(before) ^ set(after))}
    changed = [p for p in before if (before[p]["sha256"], before[p]["mode"]) !=
                                      (after[p]["sha256"], after[p]["mode"])]
    for name in changed:
        path = Path(name)
        if before[name]["mode"] != after[name]["mode"] or name not in ORDINARY_INPUTS:
            return {"eligible": False, "reason": "configuration/generator/global-header/non-C input change",
                    "changed": sorted(changed)}
    return {"eligible": True, "reason": "unchanged" if not changed else "ordinary C/local-header edit",
            "changed": sorted(changed), "dependency_refresh_required": True,
            "full_make_required": True}

def prepare_staged_timestamps(previous, current, staged, build_barrier_ns, *, now_ns=None):
    """Prepare a FULL freshly staged source tree before an adapter swaps it in.

    No overlay/copy into an old tree; file membership and bytes are independently
    checked. Existing objects must all predate build_barrier_ns, verified by the
    checkpoint adapter. This helper does not establish that obligation.
    """
    plan = classify(previous, current)
    if not plan["eligible"]:
        return plan
    if type(build_barrier_ns) is not int or build_barrier_ns < 0:
        raise ValueError("invalid build timestamp barrier")
    now_ns = time.time_ns() if now_ns is None else now_ns
    if type(now_ns) is not int or now_ns <= build_barrier_ns:
        return {"eligible": False, "reason": "clock cannot order new source after donor objects", "changed": plan["changed"]}
    if any(r["mtime_ns"] > build_barrier_ns for r in previous["files"].values()):
        raise ValueError("donor source timestamp exceeds verified checkpoint barrier")
    actual = inventory(staged)
    if set(actual) != set(current["files"]) or any(
        (actual[p]["sha256"], actual[p]["mode"]) !=
        (current["files"][p]["sha256"], current["files"][p]["mode"]) for p in actual):
        raise ValueError("fresh staged source bytes/membership differ from current manifest")
    import os
    changed = set(plan["changed"])
    for name in actual:
        timestamp = now_ns if name in changed else previous["files"][name]["mtime_ns"]
        os.utime(Path(staged) / name, ns=(timestamp, timestamp), follow_symlinks=False)
    # Verify actual filesystem precision; requested nanoseconds are not proof.
    for name in actual:
        observed = (Path(staged) / name).stat().st_mtime_ns
        if name in changed:
            if observed <= build_barrier_ns:
                return {"eligible": False, "reason": "filesystem rounded changed timestamp behind donor objects",
                        "changed": plan["changed"]}
        elif observed != previous["files"][name]["mtime_ns"]:
            return {"eligible": False, "reason": "filesystem cannot preserve unchanged source timestamp",
                    "changed": plan["changed"]}
    return dict(plan, changed_mtime_ns=now_ns, unchanged_timestamps_preserved=True)
