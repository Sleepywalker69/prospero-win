#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Static contract for the portable core and the PS5 title.

The title cannot be compiled by `make test`: it needs the pinned Prospero
toolchain. These checks therefore hold the properties that a host compiler
would not catch anyway, and that the porting playbook says decide whether a
port survives its first boot.

The central rule is principle 1: on this firmware a platform symbol that is
merely exported is not a working one. The portable core (the DBT, profiles,
presentation) is written to import almost nothing.
"""

from __future__ import annotations

import re
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Headers the portable core is allowed to include. Anything else is a new
# dependency on the platform and must be argued for, not slipped in.
CORE_HEADERS = {"<stddef.h>", "<stdint.h>", "<string.h>", "<limits.h>"}

# Symbols the core must never reference.
#   strcasestr: its FW 12.02 provider is unusable (playbook post-mortem).
#   getcwd/chdir/access/opendir: measured EPERM or faulting from a title.
#   malloc family: the libc heap is ~8 MiB and cannot be grown.
#   snprintf/printf: the core formats nothing; the title does its own logging.
#   dlopen/execve: unavailable, and no part of this design needs them.
FORBIDDEN_CORE = (
    "strcasestr", "strcasecmp", "strncasecmp", "getcwd", "chdir", "access",
    "opendir", "readdir", "getdents", "malloc", "calloc", "realloc", "free",
    "snprintf", "sprintf", "printf", "fopen", "dlopen", "dlsym", "execve",
    "setlocale", "tolower", "toupper",
)

CORE_SOURCES = sorted(path.name for path in (ROOT / "src").glob("*.c"))


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def includes(text: str) -> list[str]:
    return re.findall(r'^\s*#include\s+(<[^>]+>)', text, re.M)


def code_without_literals_or_comments(text: str) -> str:
    """Lexical call check: documentation and string contents are not calls."""
    tokens = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*'
    return re.sub(tokens, lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]),
                  text, flags=re.S)


def test_forbidden_call_lexing() -> None:
    pattern = r'\bmalloc\s*\('
    for source in ('/* malloc(4) */', '// malloc(4)\n', '"malloc(4)"',
                   '"\\\"/* malloc(4) */"'):
        assert not re.search(pattern, code_without_literals_or_comments(source))
    for source in ('malloc(4)', '"/*"; malloc(4)', '/* docs */ malloc /* gap */ (4)'):
        assert re.search(pattern, code_without_literals_or_comments(source))


def test_core_imports_nothing_surprising() -> None:
    for name in CORE_SOURCES + [path.name for path in (ROOT / "src").glob("*.h")]:
        relative = f"src/{name}"
        text = read(relative)
        if name in ("pw_vm_posix.c", "pw_vm_posix.h"):
            continue                    # the one deliberate POSIX backend
        for header in includes(text):
            assert header in CORE_HEADERS, f"{relative} includes {header}"
        code = code_without_literals_or_comments(text)
        for symbol in FORBIDDEN_CORE:
            assert not re.search(rf"\b{symbol}\s*\(", code), \
                f"{relative} calls {symbol}"


def test_x87_never_uses_host_floating_point_state() -> None:
    code = code_without_literals_or_comments(read("src/pw_x87.c"))
    assert not re.search(r"\b(float|double)\b", code)
    assert not re.search(r"\b(__asm__|asm)\b", code)
    for symbol in ("sqrt", "sin", "cos", "fenv", "fesetround"):
        assert not re.search(rf"\b{symbol}\s*\(", code), symbol


def test_posix_backend_is_narrow() -> None:
    text = read("src/pw_vm_posix.c")
    assert set(includes(text)) <= {"<sys/mman.h>", "<unistd.h>"}, \
        includes(text)
    # It must never fall back to a file-backed mapping: PS5 mmap of a file
    # returns ENOTSUP, so an accidental dependency would only fail on target.
    assert "MAP_ANONYMOUS" in text
    assert "MAP_SHARED" not in text
    assert "open(" not in text


def test_builder_builds_the_wine64_title() -> None:
    builder = read("tools/build_native.sh")
    sources = builder[builder.index("sources=("):]
    sources = sources[:sources.index(")")]
    listed = re.findall(r"[\w/]+\.c", sources)
    assert listed[0] == "native/wine64_main.c"
    for name in listed:
        assert (ROOT / name).is_file(), f"tools/build_native.sh compiles missing {name}"
    for name in ("native/pw_audio_ps5.c", "native/pw_agc_submit_lifecycle.c",
                 "native/pw_data_mount.c", "native/pw_wine_library.c"):
        assert name in sources, name
    # The banned import is rejected by the build, not merely documented.
    assert "strcasestr" in builder
    # The console refuses to exec an eboot or load a PRX without execute permission.
    assert 'chmod 755 "$dist/eboot.bin" "$dist/sce_module/libc.prx"' in builder

def test_agc_submit_establishes_a_suspend_point() -> None:
    adapter = read("native/pw_agc_ps5.c")
    stub = read("native/stubs/libSceAgc.c")
    assert "sceAgcSuspendPoint" in adapter
    assert "pw_agc_submit_and_suspend(&submit,sceAgcDriverSubmitDcb," in adapter
    assert "sceAgcSuspendPoint);" in adapter
    assert "int32_t sceAgcSuspendPoint(void)" in stub


def test_native_suite_routes_only_selected_native_tests() -> None:
    # Preprocess the actual title in both modes, without linking or executing it.
    compiler = shutil.which("cc")
    assert compiler, "host C preprocessor is required"
    def source(multi: int) -> str:
        result = subprocess.run([compiler, "-E", "-P", "-DPW_NATIVE_CHILD_PROBE=1",
                                 f"-DPW_NATIVE_MULTI_PROBE={multi}", "-Iinclude", "-Isrc", "-Inative",
                                 "native/wine64_main.c"], cwd=ROOT, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        return result.stdout.split("static void run_launcher(void)", 1)[1].split("int main(", 1)[0]
    suite, legacy = source(1), source(0)
    for call in ("pw_native_suite_start((unsigned)chosen)", "pw_native_suite_available(i)",
                 "pw_native_suite_cancel()", "pw_native_suite_tick()", "pw_native_suite_item(i)"):
        assert call in suite, call
        assert call not in legacy, call
    assert "pw_native_child_probe_start()" in legacy
    assert "pw_native_child_probe_start()" not in suite
    assert "items[0].available = 0" not in suite
    assert "items[0].available = 0" in legacy
    # Execute the real preprocessed refresh block with Options help open.
    # A successful presentation, rather than status text updates, supplies ticks.
    for text, multi in ((suite, 1), (legacy, 0)):
        end = text.index("uint32_t before = scene.selected;")
        begin = (text.rindex("for (unsigned i = 0; i < PW_SUITE_COUNT; i++)", 0, end) if multi
                 else text.rindex("if (!report_help)", 0, end))
        block = text[begin:end]
        prefix = """#include <assert.h>
#include <stddef.h>
enum { PW_SUITE_COUNT = 3 };
static int calls;
static int pw_native_suite_available(unsigned i) { return i != 1; }
static void pw_native_suite_status(char *p, size_t n) { (void)p; (void)n; calls++; }
static void pw_native_child_probe_status(char *p, size_t n) { (void)p; (void)n; calls++; }
int main(void) {
struct { int available; } items[3] = {{0},{0},{0}};
char log_status[80];
const int help_sequence[] = {1, 0, 1, 1};
for (unsigned step = 0; step < 4; step++) {
int dirty = 0, report_help = help_sequence[step], prior_calls = calls;
"""
        suffix = (f"assert(dirty == ({multi} || !report_help)); "
                  "assert(calls == prior_calls + !report_help); } (void)items; return 0; }\n")
        with tempfile.TemporaryDirectory(prefix="pw-native-help-") as directory:
            binary = Path(directory) / "control"
            result = subprocess.run([compiler, "-x", "c", "-o", str(binary), "-"],
                                    input=prefix + block + suffix, capture_output=True, text=True)
            assert result.returncode == 0, result.stderr
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            assert result.returncode == 0, (multi, result.stderr)


def test_suite_build_requires_explicit_manual_isolation() -> None:
    build = read("tools/build_native.sh")
    early = build[build.index("native_mode="):build.index("helper_download=")]
    cases = (("hello", 0, "", 0, 0), ("suite", 0, "-suite", 0, 2),
             ("suite", 1, "", 0, 2), ("suite", 1, "-suite", 1, 2),
             ("suite", 1, "-suite", 0, 0), ("peer-exit", 1, "-peer", 0, 0),
             ("fd", 1, "-fd", 0, 0))
    for mode, enabled, suffix, scripted, expected in cases:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PW_NATIVE_CHILD_MODE": mode,
               "PW_NATIVE_CHILD_PROBE": str(enabled), "PW_OUTPUT_SUFFIX": suffix,
               "PW_WINE64_SCRIPT": str(scripted)}
        result = subprocess.run(["bash", "-e", "-c", early], env=env, capture_output=True, text=True)
        assert result.returncode == expected, (mode, result.stderr)


def main() -> int:
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"native contract passed: {len(tests)} checks, "
          f"{len(CORE_SOURCES)} core sources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
