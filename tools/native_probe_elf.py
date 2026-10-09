#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Bounded static readers for the pinned original native diagnostic images."""
from __future__ import annotations
import base64
import hashlib
import struct


def require(value, message):
    if not value:
        raise ValueError(message)


def unpack(fmt, data, offset):
    require(0 <= offset <= len(data) - struct.calcsize(fmt), "truncated native metadata")
    return struct.unpack_from(fmt, data, offset)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def nid(name):
    value = hashlib.sha1(name.encode("ascii") + bytes.fromhex("518d64a635ded8c1e6b039b1c3e55230")).digest()[:8][::-1]
    return base64.b64encode(value).decode().rstrip("=").replace("/", "-")


def decode_id(text):
    require(0 < len(text) <= 4, "invalid native provider ID")
    value = 0
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"
    for char in text:
        require(char in alphabet, "invalid native provider ID digit")
        value = value * 64 + alphabet.index(char)
    require(value <= 0xFFFF, "native provider ID is too large")
    return value


class Elf:
    def __init__(self, data, *, module=False):
        require(64 <= len(data) <= 32 * 1024 * 1024 and data[:7] == b"\x7fELF\x02\x01\x01",
                "not a bounded ELF64 little-endian image")
        self.data = data
        self.kind, machine, version = unpack("<HHI", data, 16)
        require(machine == 62 and version == 1 and self.kind in ((3, 0xFE18) if module else (3, 0xFE10)), "wrong native ELF identity")
        self.entry, phoff = unpack("<QQ", data, 24)
        ehsize, phsize, count = unpack("<HHH", data, 52)
        require(ehsize == 64 and phsize == 56 and 0 < count <= 256 and phoff >= 64 and
                phoff + count * 56 <= len(data), "invalid native program table")
        self.programs = [unpack("<IIQQQQQQ", data, phoff + 56 * i) for i in range(count)]
        for header in self.programs:
            require(header[2] + header[5] <= len(data) and header[3] + header[6] < 2**64,
                    "native segment lies outside image")
            if header[0] == 1:
                require(header[5] <= header[6], "native LOAD has invalid extent")
        # A module/provider may have no executable entry. Callers still validate
        # every used FUNC/descriptor address through offset(..., PF_X).
        if not module or self.entry:
            self.offset(self.entry, 1, 1)
        dynamic = [p for p in self.programs if p[0] == 2]
        require(len(dynamic) == 1 and dynamic[0][5] % 16 == 0, "invalid native dynamic table")
        p = dynamic[0]
        require(self.offset(p[3], p[5]) == p[2], "dynamic table mapping disagrees")
        pairs = [unpack("<qQ", data, at) for at in range(p[2], p[2] + p[5], 16)]
        require(pairs and pairs[-1] == (0, 0) and all(tag for tag, _ in pairs[:-1]),
                "native dynamic terminator is invalid")
        self.dynamic = pairs[:-1]
        self.strings = self.offset(self.tag(5), self.tag(10))
        symbol_address = self.tag(6)
        require(self.tag(11) == 24, "wrong native symbol entry size")
        if self.has(0x6100003F):
            symbol_size = self.tag(0x6100003F)
        elif self.has(4):
            symbol_size = unpack("<II", data, self.offset(self.tag(4), 8))[1] * 24
        else:
            shoff = unpack("<Q", data, 40)[0]
            shsize, shcount = unpack("<HH", data, 58)
            require(shsize == 64 and 0 < shcount <= 4096 and shoff + shsize * shcount <= len(data),
                    "native dynamic symbols have no bounded size")
            sections = [unpack("<IIQQQQIIQQ", data, shoff + 64 * i) for i in range(shcount)]
            matches = [s for s in sections if s[1] == 11 and s[3] == symbol_address]
            require(len(matches) == 1 and matches[0][9] == 24 and
                    matches[0][4] == self.offset(symbol_address, 24), "ambiguous native dynamic symbols")
            symbol_size = matches[0][5]
        require(0 < symbol_size <= 4 * 1024 * 1024 and symbol_size % 24 == 0, "invalid native symbol extent")
        start = self.offset(symbol_address, symbol_size)
        self.symbols = []
        for at in range(start, start + symbol_size, 24):
            name, info, other, section, value, size = unpack("<IBBHQQ", data, at)
            self.symbols.append({"name": self.string(name), "type": info & 15, "binding": info >> 4,
                                 "visibility": other & 3, "section": section, "value": value, "size": size})
        self.needed = [self.string(value) for tag, value in self.dynamic if tag == 1]
        require(len(self.needed) == len(set(self.needed)), "duplicate native needed provider")
        self.modules = self.ids(0x61000045)
        self.libraries = self.ids(0x61000049)
        self.relocations = []
        for address_tag, size_tag in ((7, 8), (23, 2)):
            if not self.has(size_tag) or not self.tag(size_tag):
                continue
            size = self.tag(size_tag)
            require(size % 24 == 0 and size <= len(data), "invalid native relocation size")
            if address_tag == 23:
                require(self.tag(20) == 7, "native PLT uses an unsupported relocation format")
            else:
                require(self.tag(9) == 24, "native RELA uses an unsupported entry size")
            start = self.offset(self.tag(address_tag), size)
            for at in range(start, start + size, 24):
                target, info, addend = unpack("<QQq", data, at)
                require(info >> 32 < len(self.symbols), "relocation references missing symbol")
                self.relocations.append({"address": target, "symbol": info >> 32,
                                         "type": info & 0xFFFFFFFF, "addend": addend})

    def has(self, tag):
        return any(key == tag for key, _ in self.dynamic)

    def tag(self, tag):
        values = [value for key, value in self.dynamic if key == tag]
        require(len(values) == 1, "missing or repeated native dynamic tag")
        return values[0]

    def ids(self, tag):
        result = {}
        for key, value in self.dynamic:
            if key == tag:
                ident = value >> 48
                require(ident not in result, "duplicate native module/library ID")
                result[ident] = self.string(value & 0xFFFFFFFF)
        return result

    def offset(self, address, size, flags=0):
        require(size > 0 and address + size < 2**64, "invalid native mapped extent")
        candidates = [p for p in self.programs if p[0] == 1 and p[3] < address + size and
                      address < p[3] + p[6]]
        require(len(candidates) == 1, "ambiguous native LOAD mapping")
        p = candidates[0]
        require(p[1] & flags == flags and p[3] <= address and address + size <= p[3] + p[5],
                "native data is not in required file-backed mapping")
        return p[2] + address - p[3]

    def string(self, index):
        require(index < self.tag(10), "native string offset is out of bounds")
        end = self.data.find(b"\0", self.strings + index, self.strings + self.tag(10))
        require(end >= 0, "unterminated native string")
        return self.data[self.strings + index:end].decode("ascii")


def extract_self(data, *, module=False):
    """Recover and verify plaintext segments using the pinned signer's digest."""
    require(32 <= len(data) <= 32 * 1024 * 1024 and data[:4] == b"\x4f\x15\x3d\x1d",
            "not a bounded original native SELF")
    count = unpack("<H", data, 24)[0]
    require(0 < count <= 256, "invalid native SELF segment count")
    elf_offset = 32 + 32 * count
    require(data[elf_offset:elf_offset + 7] == b"\x7fELF\x02\x01\x01", "SELF has no embedded ELF header")
    phoff = unpack("<Q", data, elf_offset + 32)[0]
    phsize, phcount = unpack("<HH", data, elf_offset + 54)
    require(phoff == 64 and phsize == 56 and 0 < phcount <= 256, "unexpected SELF embedded program table")
    header_size = 64 + 56 * phcount
    require(elf_offset + header_size <= len(data), "truncated SELF embedded headers")
    headers = data[elf_offset:elf_offset + header_size]
    programs = [unpack("<IIQQQQQQ", headers, 64 + 56 * i) for i in range(phcount)]
    extent = max([len(headers)] + [p[2] + p[5] for p in programs])
    require(extent <= 32 * 1024 * 1024, "SELF reconstruction is too large")
    output = bytearray(extent)
    seen, ranges, tail = set(), [], 0
    for i in range(count):
        flags, start, size, _ = unpack("<QQQQ", data, 32 + 32 * i)
        require(start + size <= len(data), "SELF segment exceeds its container")
        tail = max(tail, start + size)
        if not flags & 0x800:
            continue
        require(not flags & 0xA, "compressed/encrypted SELF data is unsupported")
        index = (flags >> 20) & 0xFFFF
        require(index < phcount and index not in seen, "duplicate or invalid SELF segment mapping")
        seen.add(index); p = programs[index]
        require(size == p[5] and p[2] >= header_size and all(
            p[2] + size <= low or high <= p[2] for low, high in ranges), "overlapping SELF segment output")
        ranges.append((p[2], p[2] + size))
        output[p[2]:p[2] + size] = data[start:start + size]
    require({i for i, p in enumerate(programs) if p[0] == 1 and p[5]} <= seen,
            "SELF omits a nonempty LOAD segment")
    versions = [p for p in programs if p[0] == 0x6FFFFF01]
    require(len(versions) == 1 and tail + versions[0][5] == len(data), "unexpected SELF version tail")
    require(32 <= unpack("<Q", data, 16)[0] <= len(data), "SELF declared extent is invalid")
    p = versions[0]
    require(p[2] >= header_size and all(p[2] + p[5] <= low or high <= p[2] for low, high in ranges),
            "SELF version tail overlaps another output")
    output[p[2]:p[2] + p[5]] = data[tail:tail + p[5]]
    output[:header_size] = headers
    extended = (elf_offset + header_size + 15) & ~15
    require(extended + 64 <= len(data) and sha(output) == data[extended + 32:extended + 64].hex(),
            "SELF reconstructed digest mismatch")
    Elf(bytes(output), module=module)
    return bytes(output)
