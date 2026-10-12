#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Hosted, actual-source mouse-button lifecycle tests with explicit Wine mocks.

Requires the pristine pinned Wine Git checkout. It never accepts missing source
as a successful skip. The generated C contains verbatim composed function bodies,
not a second implementation of the focus core or queue completion lifecycle.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import wine_focus_neutral as focus

QUEUE_FUNCTIONS = (
    "focus_now", "focus_context", "focus_operation", "focus_claim",
    "focus_sync_timer", "focus_complete_tag", "focus_observe",
    "focus_abort_pending", "focus_cancel_unsubmitted",
    "pw_focus_queue_abandon", "pw_focus_queue_quiesce",
    "pw_focus_queue_begin", "pw_focus_queue_poll", "pw_focus_queue_ack",
    "pw_focus_queue_settle", "pw_focus_queue_watchdog",
    "alloc_hardware_message", "free_result", "remove_result_from_sender",
    "store_message_result", "free_message", "result_timeout",
    "alloc_message_result", "set_input_key_state", "update_key_state",
    "update_thread_input_key_state", "update_desktop_key_state",
    "queue_hardware_message", "send_hook_ll_message",
    "queue_mouse_message_impl", "queue_mouse_message", "pw_focus_queue_mouse_button",
)
REQUEST_FUNCTIONS = ("focus_owned", "focus_retire", "focus_has_work",
                     "pw_focus_requests_thread_dead", "focus_refuse",
                     "focus_normalized_key", "req_focus_input", "req_focus_control")


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def c_mask(source):
    """Blank comments and quoted text, preserving offsets and brace positions."""
    pattern = r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(pattern, lambda m: "".join("\n" if c == "\n" else " " for c in m[0]),
                  source, flags=re.S)


def function(source, name):
    """Return one whole definition; refuse duplicates or a missing definition."""
    masked = c_mask(source)
    if name.startswith("req_"):
        pattern = r"^DECL_HANDLER\(\s*" + re.escape(name[4:]) + r"\s*\)"
    else:
        pattern = (r"^(?:static\s+)?(?:inline\s+)?"
                   r"(?:void|int|unsigned(?:\s+int)?|uint64_t|PwFocusContext|PwFocusOperation|"
                   r"struct\s+message(?:_result)?)\s+\*?\s*" + re.escape(name) + r"\s*\(")
    found = []
    for match in re.finditer(pattern, masked, re.M):
        start = match.start()
        opening = masked.find("{", match.end())
        semicolon = masked.find(";", match.end())
        if opening < 0 or (0 <= semicolon < opening):
            continue
        depth = 1
        end = opening + 1
        while end < len(masked) and depth:
            depth += (masked[end] == "{") - (masked[end] == "}")
            end += 1
        need(depth == 0, "unterminated function: " + name)
        found.append(source[start:end] + "\n")
    # Request stubs intentionally have the same macro name; select only the
    # enabled section before the final #else containing all disabled stubs.
    need(len(found) == 1, "missing or ambiguous function: " + name)
    return found[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wine-source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--sanitize", choices=("", "undefined", "address,undefined"), default="")
    args = parser.parse_args()
    source = args.wine_source.resolve(strict=True)
    out = args.out.absolute()
    need(not out.exists() and not out.is_symlink(), "output must be a new directory")
    need(not any(p.is_symlink() for p in out.parents), "linked output parent")
    out.mkdir(parents=True)
    rows = []

    def run(label, argv, **kwargs):
        argv = list(map(str, argv))
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1",
                   UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        result = subprocess.run(argv, text=True, capture_output=True, timeout=180,
                                env=env, **kwargs)
        (out / (label + ".log")).write_text(
            json.dumps(argv) + "\n" + result.stdout + result.stderr +
            "\nEXIT=" + str(result.returncode) + "\n")
        rows.append({"label": label, "argv": argv, "exit": result.returncode})
        (out / "RESULT.json").write_text(json.dumps(rows, indent=2) + "\n")
        need(result.returncode == 0, label + " failed; see " + str(out / (label + ".log")))
        return result.stdout.strip()

    need(run("wine-head", ["git", "-C", source, "rev-parse", "HEAD"]) == focus.WINE_COMMIT,
         "Wine source is not the reviewed pin")
    need(not run("wine-clean", ["git", "-C", source, "status", "--porcelain",
                                "--untracked-files=all"]), "Wine source must be pristine")
    contract = focus.contract(ROOT)
    need(len(focus.OPTIONAL) == 4 and focus.OPTIONAL[-1].startswith("0004-"),
         "mouse tests require the separately reviewed additive fourth patch")
    tree = out / "composed"
    for name in ("server", "include"):
        need((source / name).is_dir(), "missing pinned source directory: " + name)
        shutil.copytree(source / name, tree / name)
    run("compose-init", ["git", "init", "-q", tree])
    run("compose-add", ["git", "-C", tree, "add", "."])
    patches = sorted((ROOT / "wine/patches").glob("*.patch"))
    patches += [ROOT / "wine/focus-neutral" / name for name in focus.OPTIONAL]
    for number, patch in enumerate(patches):
        run("apply-" + str(number).zfill(3), [
            "git", "-C", tree, "apply", "--allow-empty", "--index",
            "--include=server/*", "--include=include/*", patch])
    queue = (tree / "server/queue.c").read_text()
    requests = (tree / "server/pw_focus_requests.c").read_text()
    disabled_marker = "#else\nvoid pw_focus_requests_init(void) {}"
    need(requests.count(disabled_marker) == 1, "disabled request boundary changed")
    enabled, disabled = requests.split(disabled_marker)
    disabled = "void pw_focus_requests_init(void) {}" + disabled
    need(disabled.endswith("#endif\n"), "disabled request section changed")
    disabled = disabled[:-len("#endif\n")]
    bodies = {name: function(queue, name) for name in QUEUE_FUNCTIONS}
    bodies.update({name: function(enabled, name) for name in REQUEST_FUNCTIONS})
    generated = out / "actual_mouse_functions.inc"
    generated.write_text("\n".join(bodies.values()))
    # Core is copied byte for byte, not reduced to selected test-facing functions.
    for name in ("pw_focus_core.c", "pw_focus_core.h", "pw_focus_adapter.h"):
        shutil.copyfile(tree / "server" / name, out / name)
    shutil.copyfile(tree / "include/wine/pw_focus_protocol.h", out / "pw_focus_protocol.h")
    (out / "actual_disabled_requests.inc").write_text(disabled)
    boundary = {
        "schema": "pw-focus-mouse-source-test/1",
        "review_base": "694231519773e528ff52a3563d5e00238ddf898e",
        "wine_commit": focus.WINE_COMMIT,
        "cohort_source_sha256": contract["source_sha256"],
        "patches": {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in patches},
        "composed_sources": {
            p: digest((tree / p).read_bytes()) for p in (
                "server/queue.c", "server/pw_focus_requests.c",
                "server/pw_focus_core.c", "server/pw_focus_core.h",
                "server/pw_focus_adapter.h", "include/wine/pw_focus_protocol.h")
        },
        "verbatim_function_sha256": {name: digest(body.encode()) for name, body in bodies.items()},
        "compiled_actual_code": [
            "complete pw_focus_core.c",
            "whole listed queue and enabled INPUT/CONTROL request functions",
            "actual disabled request implementation section",
        ],
        "mocks": [
            "Wine data structures and constants are shape-compatible host fixtures, not ABI proof",
            "provider, request-header authorization, registration and ownership setup",
            "clock, object references, allocators, timeouts and intrusive queue lists",
            "shared-write synchronization macro only; key-state mutations and serial increments are actual Wine code",
            "window routing, raw-input dispatch, keyboard emitter and unrelated queue services",
        ],
        "not_proven": [
            "full Wine translation-unit linkage or target compilation",
            "PS5 runtime execution, real focus routing, native provider, application delivery",
            "live hooks, kernel scheduling, cross-process shared-memory synchronization",
        ],
        "execution": "pending",
    }
    (out / "SOURCE-BOUNDARY.json").write_text(json.dumps(boundary, indent=2) + "\n")
    flags = shlex.split(args.cc) + [
        "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-I" + str(out),
    ]
    if args.sanitize:
        flags += ["-fsanitize=" + args.sanitize, "-fno-sanitize-recover=all",
                  "-fno-omit-frame-pointer"]
    for name in ("mouse", "disabled"):
        test = ROOT / "tests/focus_mouse_fixture" / (name + ".c")
        binary = out / name
        units = [test, out / "pw_focus_core.c"] if name == "mouse" else [test]
        run("compile-" + name, flags + units + ["-o", binary])
        run("run-" + name, [binary])
    boundary["execution"] = "strict passed" if not args.sanitize else args.sanitize + " passed"
    (out / "SOURCE-BOUNDARY.json").write_text(json.dumps(boundary, indent=2) + "\n")
    print("Actual-source mouse lifecycle and disabled request controls passed;"
          " mocked boundaries and individual commands are recorded.")


if __name__ == "__main__":
    main()
