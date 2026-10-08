#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""tools/build_tls_ps5.sh without a console toolchain: its pins are well
formed and agree with each other (tools/package_release.sh prints them in
SOURCES.txt), it names a missing SDK and an unknown argument, and a
download that does not match its pinned SHA-256 stops it before anything
is built."""

from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "build_tls_ps5.sh"


def pin(name: str) -> str:
    match = re.search(rf"^{name}=(\S+)$", SCRIPT.read_text(), re.M)
    assert match, name
    return match.group(1)


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", str(SCRIPT), *args], capture_output=True, text=True)


def main() -> int:
    # The pins: a version and a 64-hex SHA-256 for each tarball, the URL
    # naming the version; a dated bundle from curl's store.
    for name in ("NETTLE", "GNUTLS"):
        assert re.fullmatch(r"\d+\.\d+(\.\d+)?", pin(f"{name}_VERSION")), name
        assert re.fullmatch(r"[0-9a-f]{64}", pin(f"{name}_SHA256")), name
        url = pin(f"{name}_URL")
        assert url.startswith("https://") and f"${name}_VERSION" in url, url
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", pin("CA_BUNDLE_DATE"))
    assert re.fullmatch(r"[0-9a-f]{64}", pin("CA_BUNDLE_SHA256"))
    assert pin("CA_BUNDLE_URL") == "https://curl.se/ca/cacert-$CA_BUNDLE_DATE.pem"

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        # No SDK: named, before any download.
        bad = run("--sdk", str(root / "nowhere"), "--work", str(root / "work"))
        assert bad.returncode == 1 and "no PS5 payload SDK" in bad.stderr, bad.stderr
        assert not (root / "work").exists()
        bad = run("--frobnicate")
        assert bad.returncode == 1 and "unknown argument --frobnicate" in bad.stderr, bad.stderr
        # A fake SDK and a tarball already "downloaded" with other contents:
        # the pin check refuses it and nothing is configured or built.
        sdk = root / "sdk"
        (sdk / "bin").mkdir(parents=True)
        clang = sdk / "bin" / "prospero-clang"
        clang.write_text("#!/bin/sh\nexit 0\n")
        clang.chmod(0o755)
        work = root / "work"
        work.mkdir()
        (work / f"nettle-{pin('NETTLE_VERSION')}.tar.gz").write_bytes(b"not nettle")
        bad = run("--sdk", str(sdk), "--work", str(work))
        assert bad.returncode == 1, bad.stderr
        assert f"nettle-{pin('NETTLE_VERSION')}.tar.gz does not match its pinned SHA-256" in bad.stderr, bad.stderr
        names = sorted(p.name for p in work.iterdir())
        assert not any(name.startswith("gnutls") for name in names), names   # never reached
        assert f"nettle-{pin('NETTLE_VERSION')}" not in names, names          # not extracted
        assert not (work / "root" / "lib" / "libhogweed.a").exists()
    print("tls build script passed: pins well formed, SDK and arguments checked, "
          "a tarball off its SHA-256 refused before building")
    return 0



import hashlib
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(os.environ.get("PW_TLS_SCRIPT", ROOT / "tools/build_tls_ps5.sh"))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_toolchain_fixture(sdk: Path, host: Path) -> Path:
    """Original shell fixtures modeling SDK dispatch to a host LLVM install."""
    binary, resource = host / "bin", host / "lib/clang/18"
    binary.mkdir(parents=True)
    resource.joinpath("include").mkdir(parents=True)
    resource.joinpath("include/stddef.h").write_text("synthetic compiler resource header\n")
    config = binary / "llvm-config"
    config.write_text("#!/bin/sh\ncase $1 in\n"
                      f" --bindir) printf '%s\\n' '{binary}' ;;\n"
                      " --version) echo 18.1.8 ;;\n *) exit 2 ;;\nesac\n")
    config.chmod(0o755)
    (binary / "llvm-config-18").symlink_to("llvm-config")
    for name in ("clang", "clang++", "ld.lld", "llvm-ar", "llvm-nm", "llvm-ranlib"):
        path = binary / name
        path.write_text("#!/bin/sh\ncase $1 in\n"
                        f" -print-resource-dir) printf '%s\\n' '{resource}' ;;\n"
                        " --version) echo 'clang version 18.1.8 (synthetic LLVM)' ;;\n"
                        + (" rcs) : > \"$2\" ;;\n" if name == "llvm-ar" else "") +
                        " *) exit 0 ;;\nesac\n")
        path.chmod(0o755)
    sdk.joinpath("bin").mkdir(parents=True, exist_ok=True)
    dispatcher = sdk / "bin/prospero-llvm-config"
    dispatcher.write_text(f'#!/bin/sh\nexec "${{LLVM_CONFIG:-{config}}}" "$@"\n')
    dispatcher.chmod(0o755)
    for name, backend in (("prospero-clang", "clang"), ("prospero-clang++", "clang++"),
                          ("llvm-ar", "llvm-ar"), ("llvm-nm", "llvm-nm"),
                          ("llvm-ranlib", "llvm-ranlib")):
        path = sdk / "bin" / name
        path.write_text(f'#!/bin/sh\nbindir=$("{dispatcher}" --bindir) || exit\n'
                        f'exec "$bindir/{backend}" "$@"\n')
        path.chmod(0o755)
    return config


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        self.work = root / "work"
        self.sdk = root / "sdk"
        self.script = root / "tools/build_tls_ps5.sh"
        self.work.mkdir()
        self.sdk.joinpath("bin").mkdir(parents=True)
        self.script.parent.mkdir()
        self.original = SCRIPT.read_text()
        self.script.with_name("tls_manifest.py").write_text(SCRIPT.with_name("tls_manifest.py").read_text())
        patch = Path("patches/nettle-3.10.1-ed448-canonical.patch")
        (self.script.parent / patch).parent.mkdir()
        (self.script.parent / patch).write_bytes((SCRIPT.parent / patch).read_bytes())
        self.versions = {name: re.search(rf"^{name}_VERSION=([^\n]+)", self.original,
                                         re.M).group(1) for name in ("NETTLE", "GNUTLS")}
        self.llvm_config = make_toolchain_fixture(self.sdk, root / "host-llvm")
        self.bundle = self.work / ("cacert-" + re.search(r"^CA_BUNDLE_DATE=([^\n]+)",
                                                        self.original, re.M).group(1) + ".pem")
        self.bundle.write_text("synthetic public certificate bundle fixture\n")
        self.pins: dict[str, str] = {"CA_BUNDLE": digest(self.bundle)}
        self.archive("NETTLE", "first")
        self.archive("GNUTLS", "first")
        self.update_script()
        # All input archives exist; any accidental network attempt fails.
        self.no_network = root / "no-network"
        self.no_network.mkdir()
        curl = self.no_network / "curl"
        curl.write_text("#!/bin/sh\necho 'unexpected fixture network access' >&2\nexit 97\n")
        curl.chmod(0o755)

    def archive(self, name: str, generation: str) -> None:
        version = self.versions[name]
        directory = self.root / (name.lower() + "-source-" + generation)
        directory.mkdir()
        stem = name.lower() + "-" + version
        libraries = ["libnettle.a", "libhogweed.a"] if name == "NETTLE" else ["libgnutls.a"]
        marker = f"synthetic {name} {version} {generation}"
        install = "\n".join(f"\tprintf '%s\\n' {shlex.quote(marker)} > $(PREFIX)/lib/{lib}"
                            for lib in libraries)
        if name == "GNUTLS":
            install += "\n\tmkdir -p $(PREFIX)/include/gnutls\n"
            install += f"\tprintf '%s\\n' {shlex.quote(marker)} > $(PREFIX)/include/gnutls/gnutls.h"
        configure = directory / "configure"
        configure.write_text("#!/bin/sh\nset -eu\nprefix=\nfor arg in \"$@\"; do\n"
                             " case $arg in --prefix=*) prefix=${arg#--prefix=} ;; esac\ndone\n"
                             "test -n \"$prefix\"\ntest -z \"${ac_cv_injected:-}\"\n"
                             "test -z \"$CPPFLAGS\"\ntest -z \"$LIBS\"\n"
                             "test \"$CONFIG_SITE\" = /dev/null\n"
                             "printf '%s\\n' \"$LLVM_CONFIG\" > selected-llvm.txt\n"
                             "\"$CC\" --version > selected-compiler.txt\n"
                             "printf 'PREFIX := %s\\n' \"$prefix\" > Makefile\n"
                             "cat >> Makefile <<'MAKE'\nall:\n\t@:\ninstall:\n"
                             "\tmkdir -p $(PREFIX)/lib $(PREFIX)/include $(PREFIX)/lib/pkgconfig\n"
                             + install + "\nMAKE\n")
        configure.chmod(0o755)
        notices = ["COPYING.LESSERv3", "COPYINGv2", "COPYINGv3", "AUTHORS"] if name == "NETTLE" else [
            "COPYING.LESSERv2", "COPYING", "AUTHORS", "lib/inih/LICENSE.txt"]
        for notice in notices:
            path = directory / notice
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(marker + " notice " + notice + "\n")
        if name == "NETTLE":
            # Minimal original hunk contexts let the real patch run in this
            # cache fixture. The actual cryptographic test lives in the patch.
            patch = (SCRIPT.parent / "patches/nettle-3.10.1-ed448-canonical.patch").read_text()
            for section in patch.split("diff --git ")[1:]:
                target = section.splitlines()[0].split(" b/", 1)[1]
                original = []
                for hunk in re.split(r"(?m)^@@ ", section)[1:]:
                    header, *lines = hunk.splitlines()
                    offset = int(re.match(r"-(\d+)", header).group(1)) - 1
                    while len(original) < offset:
                        original.append("")
                    old = [line[1:] for line in lines if line.startswith((" ", "-"))]
                    original[offset:offset + len(old)] = old
                path = directory / target
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(original) + "\n")
        archive = self.work / (stem + (".tar.gz" if name == "NETTLE" else ".tar.xz"))
        with tarfile.open(archive, "w:gz" if name == "NETTLE" else "w:xz") as out:
            out.add(directory, arcname=stem)
        self.pins[name] = digest(archive)

    def update_script(self) -> None:
        text = self.original
        for name, sha in self.pins.items():
            text, count = re.subn(rf"^{name}_SHA256=[^\n]+", f"{name}_SHA256={sha}", text, flags=re.M)
            assert count == 1
        self.script.write_text(text)

    def run(self, llvm_config: str | None = None) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, PATH=os.pathsep.join((str(self.no_network), str(self.llvm_config.parent),
                                                     os.environ["PATH"])))
        env.update(CPPFLAGS="unexpected preprocessor options", LIBS="unexpected libraries",
                   CONFIG_SITE="unexpected site file", ac_cv_injected="unexpected cache override",
                   LLVM_CONFIG=llvm_config if llvm_config is not None else str(self.llvm_config))
        return subprocess.run(["sh", str(self.script), "--work", str(self.work),
                               "--sdk", str(self.sdk), "--jobs", "1"], env=env,
                              capture_output=True, text=True, timeout=30)


class TlsCacheContracts(unittest.TestCase):
    def test_selected_llvm_survives_the_clean_build_environment(self):
        with tempfile.TemporaryDirectory(prefix="pw-tls-llvm-select-") as directory:
            fixture = Fixture(Path(directory))
            alternate = make_toolchain_fixture(fixture.root / "unused-sdk", fixture.root / "other-llvm")
            result = fixture.run(str(alternate))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for name, version in fixture.versions.items():
                selected = fixture.work / f"{name.lower()}-{version}/selected-llvm.txt"
                self.assertEqual(selected.read_text().strip(), str(alternate.resolve()))
            # Bare supported names are normalized before entering SDK wrappers.
            result = fixture.run("llvm-config-18")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            selected = fixture.work / f"gnutls-{fixture.versions['GNUTLS']}/selected-llvm.txt"
            self.assertEqual(selected.read_text().strip(), str(fixture.llvm_config.resolve()))

    def test_invalid_or_unsupported_explicit_selection_never_falls_back(self):
        with tempfile.TemporaryDirectory(prefix="pw-tls-llvm-refuse-") as directory:
            fixture = Fixture(Path(directory))
            result = fixture.run(str(fixture.root / "missing-config"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("LLVM 18", result.stderr)
            self.assertFalse((fixture.work / "root/lib/libgnutls.a").exists())
            fixture.llvm_config.write_text(fixture.llvm_config.read_text().replace("18.1.8", "21.0.0"))
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("got 21.0.0", result.stderr)
            self.assertFalse((fixture.work / "root/lib/libgnutls.a").exists())

    def test_changed_clang_resource_headers_rebuild(self):
        with tempfile.TemporaryDirectory(prefix="pw-tls-llvm-headers-") as directory:
            fixture = Fixture(Path(directory))
            first = fixture.run()
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            header = fixture.root / "host-llvm/lib/clang/18/include/stddef.h"
            header.write_text(header.read_text() + "changed resource header\n")
            second = fixture.run()
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertIn("built GnuTLS", second.stdout)

    def test_mixed_linker_version_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="pw-tls-llvm-mixed-") as directory:
            fixture = Fixture(Path(directory))
            linker = fixture.llvm_config.parent / "ld.lld"
            linker.write_text(linker.read_text().replace("18.1.8", "19.1.0"))
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("selected ld.lld does not match LLVM 18", result.stderr)
            self.assertFalse((fixture.work / "root/lib/libgnutls.a").exists())

    def test_changed_host_llvm_cannot_reuse_wrapper_only_identity(self):
        with tempfile.TemporaryDirectory(prefix="pw-tls-host-llvm-") as directory:
            fixture = Fixture(Path(directory))
            first = fixture.run()
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            compiler = fixture.llvm_config.parent / "clang"
            compiler.write_text(compiler.read_text() + "# changed actual host backend\n")
            second = fixture.run()
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertIn("built GnuTLS", second.stdout,
                          "unchanged SDK wrappers must not hide a changed host compiler")

    def test_sdk_and_installed_file_changes_rebuild(self):
        with tempfile.TemporaryDirectory(prefix="pw-tls-identity-") as directory:
            fixture = Fixture(Path(directory))
            first = fixture.run()
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            compiler = fixture.sdk / "bin/prospero-clang"
            compiler.write_text(compiler.read_text() + "# a different compiler build\n")
            rebuilt = fixture.run()
            self.assertEqual(rebuilt.returncode, 0, rebuilt.stdout + rebuilt.stderr)
            self.assertIn("built GnuTLS", rebuilt.stdout)
            output = fixture.work / "root/lib/libgnutls.a"
            expected = output.read_bytes()
            output.write_bytes(expected + b"corrupt")
            repaired = fixture.run()
            self.assertEqual(repaired.returncode, 0, repaired.stdout + repaired.stderr)
            self.assertEqual(output.read_bytes(), expected)
            notice = fixture.work / "root/licenses/gnutls/AUTHORS"
            notice.write_text("stale notice")
            repaired = fixture.run()
            self.assertEqual(repaired.returncode, 0, repaired.stdout + repaired.stderr)
            self.assertIn("synthetic GNUTLS", notice.read_text())

    def test_changed_verified_source_cannot_keep_old_archive(self):
        with tempfile.TemporaryDirectory(prefix="pw-tls-cache-") as directory:
            fixture = Fixture(Path(directory))
            first = fixture.run()
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            output = fixture.work / "root/lib/libgnutls.a"
            self.assertIn("first", output.read_text())
            cached = fixture.run()
            self.assertEqual(cached.returncode, 0, cached.stdout + cached.stderr)
            self.assertIn("first", output.read_text())
            self.assertNotIn("built GnuTLS", cached.stdout)
            fixture.archive("GNUTLS", "changed")
            fixture.update_script()
            changed = fixture.run()
            self.assertEqual(changed.returncode, 0, changed.stdout + changed.stderr)
            self.assertIn("changed", output.read_text(),
                          "builder succeeded with changed verified source pin but retained old GnuTLS")
            self.assertIn("changed", (fixture.work / "root/licenses/gnutls/AUTHORS").read_text(),
                          "licenses must come from the sources behind the new artifact")

    def test_missing_companion_archive_cannot_be_accepted(self):
        with tempfile.TemporaryDirectory(prefix="pw-tls-missing-") as directory:
            fixture = Fixture(Path(directory))
            first = fixture.run()
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            output = fixture.work / "root/lib/libnettle.a"
            output.unlink()
            rerun = fixture.run()
            self.assertEqual(rerun.returncode, 0, rerun.stdout + rerun.stderr)
            self.assertTrue(output.is_file(), "libhogweed alone must not validate nettle's cache")



if __name__ == "__main__":
    main()
    unittest.main()
