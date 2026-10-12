#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Small public decision receipt, emitted before the expensive host fallback."""
import argparse
import json
import os
from pathlib import Path
import re
import time

def decision(reuse, cache, *, elapsed_seconds):
    # Do not copy environment, signed download URLs, headers or arbitrary logs.
    reason = str(reuse.get("reason", "verified donor accepted" if reuse.get("reused") is True else "missing admission result"))
    reason = re.sub(r"https?://\S+", "[URL omitted]", reason)
    return {"schema": "pw-host-admission-decision/1",
            "reused": reuse.get("reused") is True,
            "reason": reason[:1024],
            "fallback_required": reuse.get("reused") is not True,
            "runtime_build_complete": False,
            "admission_seconds": elapsed_seconds,
            "cache_restore": cache}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("start", "cache", "admission"))
    parser.add_argument("--clock", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--reuse", type=Path)
    parser.add_argument("--cache", type=Path)
    args = parser.parse_args()
    if args.command == "start":
        args.clock.write_text(str(time.monotonic_ns()))
        return
    elapsed = (time.monotonic_ns() - int(args.clock.read_text())) / 1e9
    if elapsed < 0:
        raise ValueError("monotonic clock moved backwards")
    if args.command == "cache":
        matched = os.environ.get("PW_CACHE_MATCHED_KEY", "")
        result = {"schema": "pw-host-cache-restore/1",
                  "exact_hit": os.environ.get("PW_CACHE_RESTORE_HIT", "") == "true",
                  "any_hit": bool(matched), "matched_key": matched,
                  "restore_step_elapsed_seconds": elapsed,
                  "timing_includes_actions_step_overhead": True}
    else:
        result = decision(json.loads(args.reuse.read_text()), json.loads(args.cache.read_text()),
                          elapsed_seconds=elapsed)
    args.output.write_text(json.dumps(result, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
