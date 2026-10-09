#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Bind an original diagnostic suite to its source and inspected native bytes.

Only host Git/LLVM analyzers run. No packaged code, converter or target image
is executed. Owned input/output directories must have no concurrent writers.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import tarfile

sys.dont_write_bytecode = True
import build_native_child_probe as worker_builder
from check_wine_prx_build import Commands, provider_index
from native_service_converter import inspect_service_preload, WRITER_SHA256
from native_probe_elf import Elf, extract_self, nid, decode_id, require, sha
from tls_manifest import tree_files
from fetch_lapy_helper import validate_helper_manifest

ROOT = Path(__file__).resolve().parents[1]
SDK_COMMIT = "4eb701204fc3f8d31e84cf8ca272974e2be9c867"
SDK_TREE = "c1c921118e5a86fa270babea2e0ab2eced32626a"
SERVICE_WRITER_SHA256 = "1ef7ff06a5ac2cf243b9d0b04304e2a293aa49819d4aa97e56097ba5a02a880e"
SERVICE_CALLS = {"sceSystemServiceGetAppStatus", "sceSystemServiceGetLocalProcessStatusList",
                 "sceSystemServiceAddLocalProcess", "sceSystemServiceKillLocalProcess"}
ROLES = {"title": "eboot.bin", "peer_worker": "native-child.self",
         "peer_manifest": "native-child-build.json", "service_worker": "native-service.self",
         "service_manifest": "native-service-build.json", "libc": "sce_module/libc.prx",
         "lapy": "lapy.elf"}
ROLE_MODES = {name: "0755" if name in {"title", "peer_worker", "service_worker", "libc"}
              else "0644" for name in ROLES}
TITLE_FOUNDATION = "9c0b994a048521af6fb84c73ded364504fe250e9"
LAPY_SHA256 = "43fab6d8045b525403f025a7b15e313aeaeac174bba6bff19a32b0000293c647"


def read(path, limit=32 * 1024 * 1024):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= limit,
            f"missing, linked or oversized suite input: {path.name}")
    return path.read_bytes()


def record(path, published):
    data = read(path)
    return {"path": published, "bytes": len(data), "sha256": sha(data),
            "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}"}


def json_file(path):
    return json.loads(read(path, 4 * 1024 * 1024))


def role_records(app):
    roles = {role: record(app / name, "PPSA99995/" + name) for role, name in ROLES.items()}
    require(all(value["mode"] == ROLE_MODES[role] for role, value in roles.items()),
            "unexpected packaged role mode")
    return roles


def index_sdk_providers(sdk, output, bindir, commands):
    empty = output / "no-prxs"
    empty.mkdir()
    return provider_index(sdk, empty, bindir, commands)


def git_hash(kind, data):
    return hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()


def source_archive(path, expected_commit=SDK_COMMIT, expected_tree=SDK_TREE):
    """Reconstruct the Git tree from an unextracted public source archive."""
    raw = read(path, 128 * 1024 * 1024)
    nodes, names, total = {}, set(), 0
    with tarfile.open(path, "r:gz") as archive:
        require(archive.pax_headers.get("comment") == expected_commit, "SDK source commit marker disagrees")
        for member in archive:
            name = member.name.rstrip("/")
            parts = PurePosixPath(name).parts
            require(name and name == PurePosixPath(name).as_posix() and not name.startswith("/") and all(p not in ("", ".", "..") for p in parts)
                    and name not in names and len(names) < 20000, "unsafe or duplicate SDK source member")
            names.add(name)
            if member.isdir():
                continue
            require(member.isfile() or member.issym(), "unsupported SDK source member")
            total += member.size
            require(total <= 256 * 1024 * 1024 and member.size <= 32 * 1024 * 1024,
                    "SDK source archive exceeds bounds")
            content = archive.extractfile(member).read() if member.isfile() else member.linkname.encode()
            mode = "120000" if member.issym() else "100755" if member.mode & 0o111 else "100644"
            tree = nodes
            for component in parts[:-1]:
                require(not isinstance(tree.get(component), tuple), "SDK file/directory collision")
                tree = tree.setdefault(component, {})
            require(parts[-1] not in tree, "SDK source path collision")
            tree[parts[-1]] = (mode, git_hash("blob", content))

    def tree_hash(tree):
        entries = []
        for name, value in tree.items():
            mode, digest = ("40000", tree_hash(value)) if isinstance(value, dict) else value
            entries.append((name.encode() + (b"/" if mode == "40000" else b""),
                            mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(digest)))
        return git_hash("tree", b"".join(data for _, data in sorted(entries)))
    require(nodes and tree_hash(nodes) == expected_tree, "SDK source archive does not reproduce pinned Git tree")
    return {"commit": expected_commit, "tree": expected_tree, "bytes": len(raw), "sha256": sha(raw),
            "compiled_provenance_claim": False}


def provider(path, bindir, commands):
    dynamic = commands.run(bindir / "llvm-readelf", "-dW", path)
    sonames = re.findall(r"Library soname: \[([^\]]+)\]", dynamic)
    require(len(sonames) == 1 and re.fullmatch(r"[A-Za-z0-9_.+-]+", sonames[0]), "ambiguous provider SONAME")
    definitions = {}
    for line in commands.run(bindir / "llvm-readelf", "--dyn-syms", "-W", path).splitlines():
        fields = line.split()
        if (len(fields) >= 8 and re.fullmatch(r"\d+:", fields[0]) and fields[6] != "UND" and
                fields[4] in ("GLOBAL", "WEAK") and fields[5] in ("DEFAULT", "PROTECTED")):
            require(fields[7] not in definitions, "duplicate visible provider definition")
            definitions[fields[7]] = fields[3]
    require(definitions, "provider has no visible definitions")
    return {"soname": sonames[0], "sha256": sha(read(path)), "definitions": definitions}


def inspect_bindings(linked, converted, providers, required_functions=()):
    """Follow the pinned converter's ordered DT_NEEDED selection and NID IDs."""
    require(linked.kind == 3 and converted.kind == 0xFE10, "wrong linked/converted identities")
    normalized = [n[:-5] + ".prx" if n.endswith(".sprx") else n for n in linked.needed]
    require(converted.needed == normalized and len(linked.symbols) == len(converted.symbols),
            "title conversion changed dependency order or dynamic symbol count")
    require(all(name in providers for name in linked.needed), "missing actual title provider")
    stems = [name.split(".", 1)[0] for name in linked.needed]
    require(converted.modules == {i + 1: name for i, name in enumerate(stems)} and
            converted.libraries == dict(enumerate(stems)), "converted provider IDs differ from pinned converter ordering")
    imports, result = {}, {}
    for index, symbol in enumerate(linked.symbols[1:], 1):
        name = symbol["name"]
        require(name and name not in imports and symbol["section"] == 0,
                "unexpected or repeated linked dynamic symbol")
        imports[name] = symbol
        selected = next((n for n in linked.needed if name in providers[n]["definitions"]), None)
        require(selected is not None, f"unresolved actual title import: {name}")
        actual = converted.symbols[index]
        require(all(actual[k] == symbol[k] for k in ("type", "binding", "visibility", "section", "value", "size")),
                "conversion changed an import symbol contract")
        pieces = actual["name"].split("#")
        require(len(pieces) == 3 and pieces[0] == nid(name), "wrong converted import NID")
        library, module = decode_id(pieces[1]), decode_id(pieces[2])
        stem = selected.split(".", 1)[0]
        rank = linked.needed.index(selected)
        require(library == rank and module == rank + 1 and
                converted.libraries.get(library) == stem and converted.modules.get(module) == stem,
                f"wrong converted first provider: {name}")
        before = [r for r in linked.relocations if r["symbol"] == index]
        after = [r for r in converted.relocations if r["symbol"] == index]
        require(before and before == after, f"conversion changed import relocations: {name}")
        if name in required_functions:
            require(symbol["type"] == 2 and symbol["binding"] == 1 and symbol["visibility"] == 0 and
                    selected == "libSceSystemService.sprx" and providers[selected]["definitions"][name] == "FUNC",
                    f"service call does not use the actual visible FUNC provider: {name}")
            require(all(r["type"] in (6, 7) and r["addend"] == 0 for r in before),
                    "unsupported service function relocation")
            for relocation in before:
                linked.offset(relocation["address"], 8, 6)
                converted.offset(relocation["address"], 8, 6)
        result[name] = {"provider": selected, "provider_sha256": providers[selected]["sha256"],
                        "nid": actual["name"], "relocations": after}
    require(set(required_functions) <= imports.keys(), "title lacks required service imports")
    return result


def embedded_image(title, image):
    hits = []
    for p in title.programs:
        if p[0] != 1 or p[1] != 4:
            continue
        block = title.data[p[2]:p[2] + p[5]]
        start = block.find(image)
        while start >= 0:
            title.offset(p[3] + start, len(image), 4)
            hits.append(p[3] + start)
            start = block.find(image, start + 1)
    require(len(hits) == 1 and title.data.count(image) == 1, "worker image is absent, repeated or outside read-only title storage")
    return {"address": hits[0], "bytes": len(image), "sha256": sha(image)}


def compiled_identity(image, identity):
    needle = identity.encode("ascii") + b"\0"
    hits = []
    for p in image.programs:
        if p[0] != 1 or p[1] != 4:
            continue
        start = image.data.find(needle, p[2], p[2] + p[5])
        if start >= 0:
            address = p[3] + start - p[2]
            image.offset(address, len(needle), 4)
            hits.append(address)
    require(hits, "compiled source identity is missing from read-only image storage")
    return {"identity": identity, "addresses": hits}


def worker_identity(manifest, mode, sources, build_id):
    require(manifest["schema"] == ("pw-native-service-build/1" if mode == "service" else "pw-native-child-build/1") and
            manifest["mode"] == mode and manifest["sources"] == sources and manifest["build_id"] == build_id and
            manifest["foundation_commit"] == worker_builder.FOUNDATION, "mixed worker source/build identity")
    require(all(manifest[field] is False for field in ("console_execution_verified", "windows_process_support", "platform_authentication_verified")),
            "worker manifest makes an unsupported runtime claim")


def default_comparison(build):
    comparison = json_file(build / "default-mode-comparison.json")
    require(set(comparison) == {"worker.linked.elf", "worker.elf", "native-child.self"}, "unexpected default comparison roles")
    for name, measured in comparison.items():
        original = read(build / "child" / name)
        require(original == read(build / "default-control" / name) and
                measured == {"bytes": len(original), "sha256": sha(original)}, "default-mode comparison is stale")
    return comparison


def check_worker(app, directory, mode, sdk, bindir, commands, output):
    prefix = "native-service" if mode == "service" else "native-child"
    name = prefix + "-build.json"
    manifest_bytes = read(directory / name, 4 * 1024 * 1024)
    require(read(app / name, 4 * 1024 * 1024) == manifest_bytes, "packaged worker manifest differs from build")
    manifest = json.loads(manifest_bytes)
    sources, build_id = worker_builder.mode_inputs(mode)
    worker_identity(manifest, mode, sources, build_id)
    image = read(directory / (prefix + ".self"), 4 * 1024 * 1024)
    require(read(app / (prefix + ".self"), 4 * 1024 * 1024) == image and
            manifest["worker"]["sha256"] == sha(image) and manifest["worker"]["stream_extent"] == len(image) and
            struct.unpack_from("<Q", image, 16)[0] == len(image), "mixed worker SELF identity or framing")
    recovered = extract_self(image)
    require(sha(recovered) == manifest["worker"]["extracted_elf_sha256"] and
            recovered == read(directory / (prefix + ".after.elf")), "worker recovered ELF differs from checked output")
    reconstructed = output / (prefix + ".recovered.elf"); reconstructed.write_bytes(recovered)
    reconstruction = worker_builder.verify_reconstruction(directory / "worker.elf", reconstructed)
    require(reconstruction == manifest["reconstruction"], "worker reconstruction report is stale")
    graph = worker_builder.validate_link(directory / "worker.linked.elf", sdk, bindir, commands, mode)
    require(graph == manifest["linkage"], "worker import graph is stale")
    kernel = provider(sdk / "target/lib/libkernel.so", bindir, commands)
    bindings = inspect_bindings(Elf(read(directory / "worker.linked.elf")), Elf(recovered), {kernel["soname"]: kernel})
    require(set(bindings) == (worker_builder.SERVICE_IMPORTS if mode == "service" else worker_builder.PEER_IMPORTS),
            "unexpected worker import set")
    identity = compiled_identity(Elf(recovered), build_id)
    require(manifest["sdk_headers"] == tree_files(sdk / "target/include") and
            manifest["sdk_wrappers"] == tree_files(sdk / "bin"), "mixed worker SDK inputs")
    require(manifest["converter_sha256"] == sha(read(directory / "ps5-native-tool")),
            "worker converter bytes differ from recorded build")
    report = {"build_id": build_id, "sources": sources, "image_sha256": sha(image),
              "recovered_sha256": sha(recovered), "imports": bindings, "compiled_identity": identity}
    if mode == "service":
        before = inspect_service_preload(read(directory / "worker.elf"))
        after = inspect_service_preload(recovered)
        worker_builder.compare_service_preload(before, after)
        require(manifest["preload_before_signing"] == before and manifest["preload"] == after and
                manifest["entry_descriptor"] == 3 and manifest["native_exit_code_observed"] is False,
                "service preload/descriptor report is stale")
        specialization = manifest["converter_specialization"]
        selected = read(directory / "sce_module_writer.service.cpp")
        require(specialization["service"] is True and specialization["selected_sha256"] == sha(selected) and
                sha(selected) == SERVICE_WRITER_SHA256 and
                specialization["original_sha256"] == manifest["converter_sources"]["sce_module_writer.cpp"] == WRITER_SHA256,
                "service converter provenance disagrees")
        report.update({"preload_before_signing": before, "preload_after_recovery": after,
                       "converter_specialization": specialization})
    return report, image


def validate(args):
    build, app, sdk, output = (Path(x).resolve() for x in (args.build, args.app, args.sdk, args.out))
    bindir = Path(args.llvm_bindir).resolve()
    require(not output.exists() or not any(output.iterdir()), "suite evidence directory must be new or empty")
    require(all(not output.is_relative_to(p) for p in (app, sdk, build / "child", build / "service")),
            "suite evidence would overwrite an input tree")
    output.mkdir(parents=True, exist_ok=True)
    # Preserve bounded actual provider/title bytes before analyzer refusals.
    for relative, source in (("libSceSystemService.so", sdk / "target/lib/libSceSystemService.so"),
                             ("libkernel.so", sdk / "target/lib/libkernel.so"),
                             ("title.linked.elf", build / "llvm-pie.elf"),
                             ("title.converted.elf", build / "eboot.elf"),
                             ("title.self", app / "eboot.bin")):
        (output / relative).write_bytes(read(source))
    commands = Commands(output / "inspection")
    readelf_version = commands.run(bindir / "llvm-readelf", "--version")
    require(re.search(r"LLVM version 18(?:\.|\b)", readelf_version), "suite inspection requires LLVM 18")
    require(not commands.run("git", "-C", ROOT, "status", "--porcelain", "--untracked-files=normal").strip(),
            "suite requires clean committed project source")
    commit = commands.run("git", "-C", ROOT, "rev-parse", "HEAD").strip()
    tree = commands.run("git", "-C", ROOT, "rev-parse", "HEAD^{tree}").strip()
    require(re.fullmatch(r"[0-9a-f]{40}", commit) and re.fullmatch(r"[0-9a-f]{40}", tree), "invalid project identity")
    roles = role_records(app)
    require(sdk.name == "ps5-payload-sdk" and sdk.parent.name == "native" and sdk.parent.parent.name == ".deps",
            "SDK is outside the supported title-foundation layout")
    foundation = sdk.parent.parent.parent
    require(commands.run("git", "-C", foundation, "rev-parse", "HEAD").strip() == TITLE_FOUNDATION,
            "wrong title foundation identity")
    require(read(app / "sce_module/libc.prx") == read(foundation / "runtime/libc.prx"),
            "packaged libc differs from the title foundation output")
    require(roles["lapy"]["sha256"] == LAPY_SHA256, "packaged Lapy identity differs from the pinned existing helper")
    validate_helper_manifest(json_file(build / "lapy-helper-manifest.json"), app / "lapy.elf",
                             ROOT / "native/lapy_elevation_protocol.h", "PPSA99995")
    sdk_source = source_archive(Path(args.sdk_source_archive))
    index = index_sdk_providers(sdk, output, bindir, commands)
    for path in sorted((build / "import-stubs").glob("*.so")):
        item = provider(path, bindir, commands)
        require(item["soname"] not in index, "duplicate generated title provider")
        index[item["soname"]] = path
    linked, converted = Elf(read(build / "llvm-pie.elf")), Elf(read(build / "eboot.elf"))
    providers = {name: provider(index[name], bindir, commands) for name in linked.needed if name in index}
    require(index.get("libSceSystemService.sprx") == (sdk / "target/lib/libSceSystemService.so").resolve() and
            index.get("libkernel.sprx") == (sdk / "target/lib/libkernel.so").resolve(), "wrong actual system-provider files")
    imports = inspect_bindings(linked, converted, providers, SERVICE_CALLS)
    title_recovered = extract_self(read(app / "eboot.bin"))
    recovered_path = output / "title.recovered.elf"; recovered_path.write_bytes(title_recovered)
    worker_builder.verify_reconstruction(build / "eboot.elf", recovered_path)
    recovered_title = Elf(title_recovered)
    title_identity = compiled_identity(recovered_title, commit)
    peer, peer_image = check_worker(app, build / "child", "peer-exit", sdk, bindir, commands, output)
    service, service_image = check_worker(app, build / "service", "service", sdk, bindir, commands, output)
    comparison = default_comparison(build)
    embedded = {"peer": embedded_image(recovered_title, peer_image), "service": embedded_image(recovered_title, service_image)}
    require(peer["build_id"] != service["build_id"] and peer_image != service_image, "worker modes share an identity")
    # Recheck all packaged bytes after the complete inspection, before publishing a manifest.
    require(roles == role_records(app),
            "packaged roles changed during inspection")
    require(not commands.run("git", "-C", ROOT, "status", "--porcelain", "--untracked-files=normal").strip() and
            commands.run("git", "-C", ROOT, "rev-parse", "HEAD").strip() == commit, "project source changed during inspection")
    report = {"schema": "pw-native-probe-suite/1", "project": {"commit": commit, "tree": tree},
              "roles": roles, "workers": {"peer": peer, "service": service}, "embedded_images": embedded,
              "default_mode_comparison": comparison, "title_imports": imports,
              "title_compiled_identity": title_identity, "title_foundation_commit": TITLE_FOUNDATION,
              "system_service_calls": sorted(SERVICE_CALLS), "sdk_source": sdk_source,
              "providers": {name: {k: v for k, v in data.items() if k != "definitions"}
                            for name, data in providers.items()},
              "console_execution_verified": False, "windows_process_support": False,
              "platform_authentication_verified": False, "native_exit_code_observed": False}
    (output / "native-probe-suite.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("build", "app", "sdk", "llvm-bindir", "out", "sdk-source-archive"):
        parser.add_argument("--" + name, type=Path, required=True)
    try:
        validate(parser.parse_args())
    except (ValueError, OSError, KeyError, TypeError, struct.error, tarfile.TarError) as error:
        raise SystemExit(str(error)) from error
