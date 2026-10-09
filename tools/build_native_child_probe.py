#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Build the original finite native SELF worker without the payload SDK CRT.

Requires existing pinned public foundation/SDK inputs and LLVM 18. This tool
does not download, install, launch or submit a worker to a console.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
from check_wine_prx_build import Commands, elf, require
from tls_manifest import digest, llvm_identity, tree_files

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION = "30597512539e7edfde079cbcaf4a626bc0a948c5"
SOURCES = ("native/pw_native_child_worker.c", "native/pw_native_child_protocol.c",
           "native/pw_native_child_protocol.h", "tools/build_native_child_probe.py")
WORKER_FLAGS = ("--no-default-config", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                "-ffreestanding", "-fno-builtin", "-fPIE", "-fasynchronous-unwind-tables")
IMPORTS = {"_exit", "getpid", "getppid", "clock_gettime", "fcntl", "poll", "read", "write", "setsockopt"}
MAX_WORKER = 4 * 1024 * 1024


def entry_mapped(value):
    entry, offset = struct.unpack_from("<QQ", value, 24)
    size, count = struct.unpack_from("<HH", value, 54)
    return any(kind == 1 and flags & 1 and address <= entry < address + length for
               kind, flags, _, address, _, length, _, _ in
               (struct.unpack_from("<IIQQQQQQ", value, offset + size * i) for i in range(count)))


def self_inspect(tool, path, commands):
    text = commands.run(tool, "self", "--inspect", "--file", path)
    require(re.search(r"^container: signed, plaintext$", text, re.M) and
            re.search(r"^integrity: valid$", text, re.M) and "INVALID" not in text,
            "worker SELF structure or reconstructed digest is invalid")
    hashes = re.findall(r"^digest: ([0-9a-f]{64})$", text, re.M)
    require(len(hashes) == 1, "worker SELF has no unique reconstructed digest")
    return hashes[0]


def streamable_self(source, target, tool, commands):
    """Worker-only correction for selfldr's header.file_size stream framing.

    The pinned signer appends PT_VERSION bytes after its declared size. Keep
    those bytes and every other field; update only that length. The converter
    must prove unchanged extracted ELF and digest before and after the change.
    This checks format integrity, not official platform authentication.
    """
    value = source.read_bytes()
    require(32 <= len(value) <= MAX_WORKER and value[:4] == b"\x4f\x15\x3d\x1d",
            "worker is not a bounded native SELF")
    declared = struct.unpack_from("<Q", value, 16)[0]
    require(32 <= declared <= len(value), "invalid SELF declared extent")
    before_digest = self_inspect(tool, source, commands)
    before = target.with_suffix(".before.elf")
    after = target.with_suffix(".after.elf")
    commands.run(tool, "self", "--extract", "--file", source, "--out", before)
    changed = bytearray(value)
    struct.pack_into("<Q", changed, 16, len(changed))
    target.write_bytes(changed)
    require(target.read_bytes()[:16] == value[:16] and target.read_bytes()[24:] == value[24:],
            "SELF normalization modified bytes outside its declared extent")
    after_digest = self_inspect(tool, target, commands)
    commands.run(tool, "self", "--extract", "--file", target, "--out", after)
    extracted = before.read_bytes()
    require(extracted == after.read_bytes() and before_digest == after_digest == hashlib.sha256(extracted).hexdigest(),
            "SELF normalization changed extracted ELF or its digest")
    recovered, _ = elf(after, 0xFE10)
    require(entry_mapped(recovered), "reconstructed worker entry is not executable file-backed memory")
    target.chmod(0o755)
    return {"original_extent": declared, "stream_extent": len(value), "sha256": digest(target),
            "extracted_elf_sha256": after_digest}


def validate_link(path, sdk, bindir, commands):
    value, _ = elf(path, 3)
    require(entry_mapped(value), "worker entry is not executable file-backed memory")
    sections = commands.run(bindir / "llvm-readelf", "--section-headers", "-W", path)
    unwind = re.findall(r"^\s*\[\s*\d+\]\s+(\.eh_frame(?:_hdr)?)\s+(PROGBITS|X86_64_UNWIND)"
                        r"\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\b", sections, re.M)
    require(len(unwind) == 2 and {name for name, _, _ in unwind} == {".eh_frame", ".eh_frame_hdr"} and
            all(int(size, 16) > 0 for _, _, size in unwind), "worker lacks linked unwind records/header")
    dynamic = commands.run(bindir / "llvm-readelf", "-dW", path)
    require(re.findall(r"Shared library: \[([^\]]+)\]", dynamic) == ["libkernel.sprx"],
            "worker may depend only on the ordinary libkernel provider")
    names = {}
    for line in commands.run(bindir / "llvm-readelf", "--dyn-syms", "-W", path).splitlines():
        fields = line.split()
        if len(fields) >= 8 and re.fullmatch(r"\d+:", fields[0]) and fields[6] == "UND":
            require(fields[3] in {"FUNC", "NOTYPE"} and fields[4:6] == ["GLOBAL", "DEFAULT"],
                    "worker has an unsupported import type/binding")
            names[fields[7]] = fields[3]
    require(set(names) == IMPORTS, f"unexpected worker imports: {sorted(names)}")
    provider = sdk / "target/lib/libkernel.so"
    require(re.findall(r"Library soname: \[([^\]]+)\]",
                       commands.run(bindir / "llvm-readelf", "-dW", provider)) == ["libkernel.sprx"],
            "ordinary kernel stub has an unexpected identity")
    exports = set()
    for line in commands.run(bindir / "llvm-readelf", "--dyn-syms", "-W", provider).splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[3:6] == ["FUNC", "GLOBAL", "DEFAULT"] and fields[6] != "UND":
            exports.add(fields[7])
    require(IMPORTS <= exports, "ordinary kernel provider lacks required function imports")
    disassembly = commands.run(bindir / "llvm-objdump", "-d", "--no-show-raw-insn", path)
    require(re.search(r"^\s*[0-9a-f]+:\s+\S", disassembly, re.M), "worker disassembly is empty")
    require(not re.search(r"^\s*[0-9a-f]+:\s+syscall(?:\s|$)", disassembly, re.M), "worker contains a raw syscall")
    functions = dict(re.findall(r"^[0-9a-f]+ <([^>]+)>:\n(.*?)(?=^[0-9a-f]+ <|\Z)",
                                disassembly, re.M | re.S))
    for name in ("memcpy", "memset", "memcmp"):
        require(name in functions and not re.search(r"\bcallq?\b", functions[name]),
                f"freestanding {name} is absent or lowers into another call")
    symbols = commands.run(bindir / "llvm-readelf", "-sW", path)
    entries = [fields for line in symbols.splitlines() if len(fields := line.split()) >= 8 and fields[7] == "_start"]
    require(entries and all(fields[3] == "FUNC" and fields[6] != "UND" and
                            int(fields[1], 16) == struct.unpack_from("<Q", value, 24)[0] for fields in entries),
            "worker entry does not identify its original _start")
    require(not re.search(r"\b(?:__patch_init|_init_env|kernel_get_proc|kernel_set_ucred_caps)\b", symbols),
            "worker unexpectedly contains payload or libc initialization")
    return {"needed": ["libkernel.sprx"], "imports": sorted(names), "provider_sha256": digest(provider),
            "unwind_bytes": {name: int(size, 16) for name, _, size in unwind}}


def build(args):
    output = args.out.resolve()
    require(not output.exists() or not any(output.iterdir()), "worker output must be new or empty")
    commands = Commands(output / "inspection")
    foundation, sdk = args.foundation.resolve(), args.sdk.resolve()
    require(commands.run("git", "-C", foundation, "rev-parse", "HEAD").strip() == FOUNDATION,
            "native worker requires the pinned public foundation")
    require(not commands.run("git", "-C", foundation, "status", "--porcelain", "--untracked-files=all",
                             "--", "tooling/native").strip(), "native converter sources or layout are modified")
    native = foundation / "tooling/native"
    llvm = llvm_identity(sdk)
    bindir = Path(llvm["bindir"])
    sources = {name: digest(ROOT / name) for name in SOURCES}
    build_id = hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest()[:40]
    environment = ["env", "-i", "PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C",
                   "LLVM_CONFIG=" + llvm["config"], "PS5_PAYLOAD_SDK=" + str(sdk)]
    # Build this exact converter from the checked source. An existing binary
    # with a familiar pathname is not proof of its source provenance.
    zroot = foundation / ".deps/native/zlib/root"
    archives = sorted(zroot.rglob("libz.a"))
    require(len(archives) == 1 and (zroot / "usr/include/zlib.h").is_file(),
            "one prepared public zlib archive and headers are required")
    tool = output / "ps5-native-tool"
    converter_sources = [native / name for name in
                         ("native_app_builder.cpp", "self_container.cpp", "elf_object.cpp", "sce_module_writer.cpp")]
    commands.run(*environment, bindir / "clang++", "--no-default-config", "-std=c++20", "-O2",
                 "-Wall", "-Wextra", "-Werror", "-I", zroot / "usr/include", *converter_sources, archives[0], "-o", tool)
    predefines = commands.run(*environment, sdk / "bin/prospero-clang", "--no-default-config",
                              "-c", "-dM", "-E", "-x", "c", "/dev/null")
    for name in ("__PROSPERO__", "__FreeBSD__", "__x86_64__"):
        require(re.search(r"^#define " + name + r" [1-9][0-9]*$", predefines, re.M),
                f"worker compiler lacks genuine target macro {name}")
    objects = []
    for source in SOURCES[:2]:
        obj = output / (Path(source).stem + ".o")
        commands.run(*environment, sdk / "bin/prospero-clang", *WORKER_FLAGS,
                     "-DPW_NATIVE_CHILD_FREESTANDING", '-DPW_NATIVE_CHILD_BUILD_ID="' + build_id + '"',
                     "-c", ROOT / source, "-o", obj)
        objects.append(obj)
    linked = output / "worker.linked.elf"
    commands.run(*environment, sdk / "bin/prospero-lld", "-T", native / "ps5-pie.ld", "--eh-frame-hdr",
                 "-e", "_start", "-z", "defs", "-o", linked, *objects, sdk / "target/lib/libkernel.so")
    graph = validate_link(linked, sdk, bindir, commands)
    converted, original, final = output / "worker.elf", output / "worker.original.self", output / "native-child.self"
    commands.run(tool, "link", "--in", linked, "--out", converted, "--stub", sdk / "target/lib/libkernel.so",
                 "--module-sdk", "0x02000009", "--file-name", "native-child.elf", "--component", "pw_native_child_worker")
    converted_bytes, _ = elf(converted, 0xFE10)
    require(entry_mapped(converted_bytes) and converted_bytes[24:32] == linked.read_bytes()[24:32],
            "conversion changed the original worker entry")
    commands.run(tool, "self", "--sign", "--in", converted, "--out", original, "--magic", "0x1D3D154F")
    framing = streamable_self(original, final, tool, commands)
    # The signer reconstructs the native ELF; require the complete actual
    # conversion output rather than silently dropping its version records.
    require(final.with_suffix(".after.elf").read_bytes() == converted.read_bytes(),
            "SELF reconstruction differs from the complete converted executable")
    manifest = {"schema": "pw-native-child-build/1", "build_id": build_id, "sources": sources,
                "foundation_commit": FOUNDATION, "converter_sha256": digest(tool), "host_llvm": llvm,
                "converter_sources": {path.name: digest(path) for path in sorted(native.iterdir()) if path.is_file()},
                "layout_sha256": digest(native / "ps5-pie.ld"), "zlib_archive_sha256": digest(archives[0]),
                "zlib_headers": tree_files(zroot / "usr/include"),
                "sdk_wrappers": tree_files(sdk / "bin"), "sdk_headers": tree_files(sdk / "target/include"),
                "linkage": graph, "worker": framing, "console_execution_verified": False,
                "windows_process_support": False, "platform_authentication_verified": False}
    (output / "native-child-build.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    (output / "native-child-build.h").write_text('#define PW_NATIVE_CHILD_BUILD_ID "' + build_id + '"\n' +
                                                '#define PW_NATIVE_CHILD_SELF_SHA256 "' + framing["sha256"] + '"\n' +
                                                '#define PW_NATIVE_CHILD_SELF_BYTES ' + str(framing["stream_extent"]) + '\n')
    image = final.read_bytes()
    with (output / "native-child-image.c").open("w") as stream:
        stream.write('/* Generated from the verified original worker SELF. */\n#include <stddef.h>\n'
                     'const unsigned char pw_native_child_image[] = {\n')
        for start in range(0, len(image), 16):
            stream.write(','.join(str(byte) for byte in image[start:start + 16]) + ',\n')
        stream.write('};\nconst size_t pw_native_child_image_size = sizeof(pw_native_child_image);\n')
    print(json.dumps({"build_id": build_id, "worker": framing}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sdk", "foundation", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    try:
        build(parser.parse_args())
    except (ValueError, OSError) as error:
        raise SystemExit(str(error)) from error
