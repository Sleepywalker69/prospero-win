#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Service-worker-only preload metadata for the exact pinned native converter.

This does not execute, sign or load an ELF. Existing modes select the original
source unchanged. The service copy preserves that source's license and notices.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct

FOUNDATION = "30597512539e7edfde079cbcaf4a626bc0a948c5"
WRITER_SHA256 = "7c7a8e24d04309dd57e9c70c26ca1cdec7458451ef7877a1de7a41d8d93addcf"
TITLE_FOUNDATION = "9c0b994a048521af6fb84c73ded364504fe250e9"
TITLE_WRITER_SHA256 = "e217ed0974fffcfd25f3d0fc300f1371f067f52c49a2b61bab7c429896cf4f48"
PRELOAD_MASK = 0x8000000000000002
EDITS = (
    (b"    const ParameterBlocks blocks = build_parameter_blocks();\n",
     b"    ParameterBlocks blocks = build_parameter_blocks();\n"
     b"    const std::size_t preload_offset = blocks.data.size();\n"
     b"    blocks.data.resize(preload_offset + 8);\n"
     b"    write_u64(blocks.data, preload_offset, 0x8000000000000002ULL);\n"),
    (b"    relocations.insert(relocations.end(), relative.begin(), relative.end());\n",
     b"    relocations.push_back(\n"
     b"        {process_address + 0x50, kRelRelative, blocks_address + preload_offset});\n"
     b"    relocations.insert(relocations.end(), relative.begin(), relative.end());\n"),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def service_writer_bytes(original, *, foundation=FOUNDATION):
    """Two deterministic literal edits; no regex, fuzzy patch or fallback."""
    require(foundation in (FOUNDATION, TITLE_FOUNDATION), "unsupported converter foundation")
    expected = TITLE_WRITER_SHA256 if foundation == TITLE_FOUNDATION else WRITER_SHA256
    require(sha256(original) == expected, "unexpected pinned converter source hash")
    changed = original
    for before, after in EDITS:
        require(changed.count(before) == 1, "converter source marker is not unique")
        changed = changed.replace(before, after, 1)
    return changed


def service_converter_provenance(original, *, foundation=FOUNDATION):
    changed = service_writer_bytes(original, foundation=foundation)
    return {"schema": "pw-native-service-converter/1", "service": True,
            "foundation_commit": foundation, "original_sha256": sha256(original),
            "selected_sha256": sha256(changed), "preload_mask": hex(PRELOAD_MASK),
            "procparam_pointer_offset": 0x50, "edits": len(EDITS)}


def prepare_converter_source(source, output, *, service=False, foundation=FOUNDATION):
    """Return (selected source path, provenance); never modify the input.

    The caller compiles the returned path. Use an owned output directory with
    no concurrent writers, then retain the copied source with the build record.
    """
    require(type(service) is bool, "service selection must be an explicit boolean")
    require(foundation == FOUNDATION or (service and foundation == TITLE_FOUNDATION),
            "unsupported converter source selection")
    source, output = Path(source), Path(output)
    require(source.is_file() and not source.is_symlink(), "converter source must be a regular file")
    original = source.read_bytes()
    record = {"schema": "pw-native-service-converter/1", "service": service,
              "foundation_commit": foundation, "original_sha256": sha256(original)}
    if not service:
        record["selected_sha256"] = record["original_sha256"]
        return source, record
    changed = service_writer_bytes(original, foundation=foundation)
    require(output.parent.is_dir() and not output.parent.is_symlink(), "converter output needs an owned directory")
    require(source.resolve() != output.resolve(), "converter copy cannot replace the original")
    # Exclusive creation refuses old files and symlinks, including dangling ones.
    with output.open("xb") as stream:
        stream.write(changed)
    require(source.read_bytes() == original, "converter input changed during source copy")
    return output, service_converter_provenance(original, foundation=foundation)


def inspect_service_preload(data):
    """Validate the pointer, relocation and pointed-to mask in converted ELF bytes."""
    require(isinstance(data, bytes) and 64 <= len(data) <= 4 * 1024 * 1024,
            "service ELF has invalid extent")
    require(data[:7] == b"\x7fELF\x02\x01\x01" and data[7] in (0, 3, 9),
            "service ELF must be ELF64 little endian")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    require((kind, machine, version) == (0xFE10, 62, 1), "unexpected converted service ELF identity")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    ehsize, phsize, count = struct.unpack_from("<HHH", data, 52)
    require(ehsize == 64 and phsize == 56 and 1 <= count <= 64 and phoff >= 64 and
            phoff + phsize * count <= len(data), "invalid service program headers")
    headers = [struct.unpack_from("<IIQQQQQQ", data, phoff + phsize * i) for i in range(count)]
    for h in headers:
        require(h[2] <= len(data) and h[5] <= len(data) - h[2] and
                h[3] + h[6] <= 2**64, "invalid service segment extent")
        if h[0] == 1:
            require(h[5] <= h[6], "service LOAD file extent exceeds memory")

    def single(kind):
        values = [h for h in headers if h[0] == kind]
        require(len(values) == 1, "missing or duplicate service metadata segment")
        return values[0]

    def file_at(address, size, flags=0):
        require(0 <= address < 2**64 and 0 < size <= 2**64 - address, "invalid service virtual extent")
        # Include partial and zero-fill aliases before checking the selected
        # mapping's permissions. An overlapping RO/BSS LOAD cannot be ignored.
        matches = [h for h in headers if h[0] == 1 and h[3] < address + size and
                   address < h[3] + h[6]]
        require(len(matches) == 1, "service metadata is not uniquely file-backed")
        require(matches[0][1] & flags == flags and matches[0][3] <= address and
                address + size <= matches[0][3] + matches[0][5],
                "service metadata lacks required file backing or permissions")
        return matches[0][2] + address - matches[0][3]

    proc = single(0x61000001)
    require(proc[1] == 4 and proc[5:7] == (0x60, 0x60) and proc[7] == 8 and proc[3] % 8 == 0,
            "unexpected service process-parameter layout")
    require(file_at(proc[3], 0x60, 6) == proc[2], "process parameters are outside their writable LOAD")
    require(struct.unpack_from("<Q4sIII", data, proc[2]) ==
            (0x60, b"ORBI", 5, 0x08050001, 0x02000009), "unexpected service process-parameter header")
    pointer_address = proc[3] + 0x50
    require(struct.unpack_from("<Q", data, proc[2] + 0x50)[0] == 0 and
            struct.unpack_from("<Q", data, proc[2] + 0x58)[0] == 1,
            "service preload pointer must use the pinned RELA representation")
    dyn = single(2)
    require(dyn[5] > 0 and dyn[5] % 16 == 0 and file_at(dyn[3], dyn[5]) == dyn[2],
            "invalid service dynamic table")
    entries = [struct.unpack_from("<QQ", data, at) for at in range(dyn[2], dyn[2] + dyn[5], 16)]
    require(entries[-1] == (0, 0) and all(tag for tag, _ in entries[:-1]), "invalid dynamic terminator")
    # Exact executable-writer formats: DT_RELA plus optional RELA DT_JMPREL.
    # Refuse unexamined REL/RELR/packed or vendor relocation table formats.
    supported_tags = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 20, 21, 23,
                      25, 26, 27, 28, 32, 33, 0x6FFFFFF9, 0x61000011, 0x61000019,
                      0x6100003D, 0x6100003F, 0x61000041, 0x61000043, 0x61000045,
                      0x61000049}
    require(all(tag in supported_tags for tag, _ in entries), "unsupported service dynamic tag")
    tags = {}
    for tag in (7, 8, 9, 0x6FFFFFF9, 23, 2, 20):
        matches = [value for key, value in entries if key == tag]
        require(len(matches) == 1, "missing or duplicate service relocation tag")
        tags[tag] = matches[0]
    require(tags[9] == 24 and 0 < tags[8] <= len(data) and tags[8] % 24 == 0,
            "invalid service relocation table")
    relfile = file_at(tags[7], tags[8])
    rels = [struct.unpack_from("<QQq", data, at) for at in range(relfile, relfile + tags[8], 24)]
    require(tags[20] == 7 and tags[2] <= len(data) and tags[2] % 24 == 0,
            "invalid service jump relocation table")
    jumps = []
    if tags[2]:
        jumpfile = file_at(tags[23], tags[2])
        require(jumpfile + tags[2] <= relfile or relfile + tags[8] <= jumpfile,
                "service relocation tables overlap")
        jumps = [struct.unpack_from("<QQq", data, at)
                 for at in range(jumpfile, jumpfile + tags[2], 24)]
        require(all(info & 0xFFFFFFFF == 7 and info >> 32 and addend == 0
                    for _, info, addend in jumps), "unsupported service jump relocation")
    all_relocations = rels + jumps
    require(all(info & 0xFFFFFFFF in (1, 6, 7, 8) for _, info, _ in all_relocations),
            "unsupported service relocation write size")
    relative_count = tags[0x6FFFFFF9]
    require(0 < relative_count <= len(rels) and
            all(info == 8 for _, info, _ in rels[:relative_count]) and
            all(info & 0xFFFFFFFF != 8 for _, info, _ in rels[relative_count:]),
            "service relative relocation count/order disagrees")
    matches = [r for r in all_relocations if r[0] < pointer_address + 8 and r[0] + 8 > pointer_address]
    require(len(matches) == 1 and matches[0][0:2] == (pointer_address, 8),
            "missing, duplicate or wrong service preload pointer relocation")
    target = matches[0][2]
    require(target >= 0 and target % 8 == 0 and not (target < proc[3] + 0x60 and target + 8 > proc[3]),
            "invalid service preload mask address")
    maskfile = file_at(target, 8, 6)
    relro = single(0x6474E552)
    require(relro[1] == 4 and relro[6] >= relro[5] and
            relro[3] <= proc[3] and proc[3] + 0x60 <= relro[3] + relro[5] and
            relro[3] <= target and target + 8 <= relro[3] + relro[5] and
            relro[2] + target - relro[3] == maskfile,
            "service preload metadata is outside file-backed RELRO")
    require(all(not (offset < target + 8 and offset + 8 > target)
                for offset, _, _ in all_relocations),
            "service preload mask is modified by another relocation")
    mask = struct.unpack_from("<Q", data, maskfile)[0]
    require(mask == PRELOAD_MASK, "unexpected service preload mask")
    return {"schema": "pw-native-service-preload/1", "elf_sha256": sha256(data),
            "procparam_address": proc[3], "procparam_file_offset": proc[2],
            "pointer_address": pointer_address, "relocation_type": 8,
            "mask_address": target, "mask_file_offset": maskfile,
            "preload_mask": hex(mask), "relative_relocation_count": relative_count,
            "jump_relocation_count": len(jumps)}
