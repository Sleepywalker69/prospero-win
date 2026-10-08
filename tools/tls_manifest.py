#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Bind the TLS cache and packaged modules to the inputs actually built.

Hashes detect stale or changed local artifacts; this is not a signature or a
claim that a cross-build has been validated on hardware.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

MANIFEST = "tls-build-manifest.json"
ARCHIVES = ("lib/libgnutls.a", "lib/libnettle.a", "lib/libhogweed.a")
NOTICES = tuple("licenses/gnutls/" + name for name in
                ("COPYING.LESSERv2", "COPYING", "AUTHORS", "lib-inih-LICENSE.txt")) + tuple(
                    "licenses/nettle/" + name for name in
                    ("COPYING.LESSERv3", "COPYINGv2", "COPYINGv3", "AUTHORS"))
MODULES = ("sce_module/libgnutls.prx", "sce_module/secur32.prx")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def tree_files(root: Path) -> dict[str, str]:
    """Hash regular inputs, following SDK symlinks but refusing cycles."""
    files = {}
    visited = set()
    for directory, dirs, names in os.walk(root, followlinks=True):
        parent = Path(directory)
        identity = parent.resolve()
        if identity in visited:
            dirs.clear()
            continue
        visited.add(identity)
        for child in dirs:
            path = parent / child
            if path.is_symlink() and path.resolve() in (parent.resolve(), *parent.resolve().parents):
                raise ValueError(f"cyclic input directory: {path}")
        for name in sorted(names):
            path = parent / name
            if not path.is_file():
                raise ValueError(f"not a regular input: {path}")
            files[str(path.relative_to(root))] = digest(path)
    return files


def inputs(script: Path, sdk: Path) -> dict:
    text = script.read_text()

    def pin(name):
        match = re.search(rf"^{name}=(\S+)$", text, re.M)
        if not match:
            raise ValueError(f"missing TLS pin: {name}")
        return match.group(1)

    sources = {}
    for name in ("NETTLE", "GNUTLS", "CA_BUNDLE"):
        field = "DATE" if name == "CA_BUNDLE" else "VERSION"
        version = pin(f"{name}_{field}")
        sha = pin(f"{name}_SHA256")
        if not re.fullmatch("[0-9a-f]{64}", sha):
            raise ValueError(f"invalid TLS source hash: {name}")
        sources[name.lower()] = {field.lower(): version, "sha256": sha,
                                "url": pin(f"{name}_URL").replace(f"${name}_{field}", version)}
    sdk_files = {}
    # The compiler wrappers and tools, target headers and libraries, plus
    # compiler resources when the SDK keeps them outside target/.
    for directory in ("bin", "target", "lib", "libexec"):
        path = sdk / directory
        if path.is_dir():
            sdk_files.update((f"{directory}/{name}", sha) for name, sha in tree_files(path).items())
    if not sdk_files or not (sdk / "bin/prospero-clang").is_file():
        raise ValueError(f"missing SDK inputs: {sdk}")
    return {"schema": "pw-tls-inputs/1", "sources": sources,
            "patches": {"tools/patches/nettle-3.10.1-ed448-canonical.patch": digest(
                script.parent / "patches/nettle-3.10.1-ed448-canonical.patch")},
            "recipe_sha256": digest(script), "helper_sha256": digest(Path(__file__)),
            "sdk_path": str(sdk.resolve()), "sdk_files": sdk_files,
            "host_path": os.environ.get("PATH", "")}


def artifacts(root: Path) -> dict[str, str]:
    for name in (*ARCHIVES, *NOTICES, "include/gnutls/gnutls.h", "ca-certificates.crt"):
        if not (root / name).is_file():
            raise ValueError(f"missing TLS artifact: {name}")
    result = tree_files(root)
    result.pop(MANIFEST, None)
    return result


def verify(root: Path, expected: dict | None = None) -> dict:
    manifest = json.loads((root / MANIFEST).read_text())
    if manifest.get("schema") != "pw-tls-build/1" or not isinstance(manifest.get("inputs"), dict):
        raise ValueError("unsupported TLS build manifest")
    if expected is not None and manifest["inputs"] != expected:
        raise ValueError("TLS build inputs changed; rerun tools/build_tls_ps5.sh")
    if manifest.get("artifacts") != artifacts(root):
        raise ValueError("TLS artifacts changed or are incomplete; rerun tools/build_tls_ps5.sh")
    return manifest


def record(root: Path, expected: dict) -> None:
    manifest = {"schema": "pw-tls-build/1", "inputs": expected, "artifacts": artifacts(root)}
    temporary = root / (MANIFEST + ".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    temporary.replace(root / MANIFEST)


def runtime_record(root: Path, prx: Path) -> dict:
    manifest = verify(root)
    names = [*MODULES, "ca-certificates.crt", *NOTICES]
    files = {}
    for name in names:
        path = prx / name
        if not path.is_file():
            raise ValueError(f"missing TLS runtime input: {name}")
        files[name] = digest(path)
        if name in NOTICES and files[name] != manifest["artifacts"][name]:
            raise ValueError(f"TLS runtime notice differs from the built source: {name}")
    return {"schema": "pw-tls-runtime/1", "build": manifest, "files": files}


def verify_runtime(wine: Path, report: dict | None = None) -> dict | None:
    prx = wine / "prx"
    if report is None:
        report = json.loads((wine / "report.json").read_text())
    entry = report.get("tls")
    if (not any((prx / name).exists() for name in MODULES) and not entry and
            not report.get("tls_error") and not report.get("tls_configured")):
        return None
    if not isinstance(entry, dict) or entry.get("schema") != "pw-tls-runtime/1":
        raise ValueError("TLS modules have no recorded build provenance in report.json")
    build = entry.get("build", {})
    sources = build.get("inputs", {}).get("sources", {})
    if build.get("schema") != "pw-tls-build/1" or any(name not in sources for name in
                                                     ("gnutls", "nettle", "ca_bundle")):
        raise ValueError("incomplete TLS build provenance in report.json")
    files = entry.get("files", {})
    for name in (*MODULES, "ca-certificates.crt", *NOTICES):
        if not (prx / name).is_file() or files.get(name) != digest(prx / name):
            raise ValueError(f"TLS runtime file missing or changed: {name}")
    return entry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inputs", "verify", "record", "verify-runtime"))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--script", type=Path)
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--inputs", type=Path)
    args = parser.parse_args()
    try:
        expected = json.loads(args.inputs.read_text()) if args.inputs else None
        if args.script and args.sdk:
            current = inputs(args.script, args.sdk)
            if expected is not None and current != expected:
                raise ValueError("TLS source recipe or SDK changed during the build")
            expected = current
        if args.action == "inputs":
            if expected is None:
                raise ValueError("--script and --sdk are required")
            print(json.dumps(expected, indent=2, sort_keys=True))
        elif args.root is None:
            raise ValueError("--root is required")
        elif args.action == "record":
            if expected is None:
                raise ValueError("--inputs is required")
            record(args.root, expected)
        elif args.action == "verify":
            verify(args.root, expected)
        else:
            verify_runtime(args.root)
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"tls_manifest: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
