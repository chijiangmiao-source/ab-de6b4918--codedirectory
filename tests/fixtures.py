"""构造合成 Mach-O 切片（含 LC_CODE_SIGNATURE + SuperBlob + CodeDirectory）。

``build_payload`` 产出结构与摘要均正确的合法载荷；测试可借助返回的
``info`` 中的偏移对字节做定向破坏，或让 ``tamper_slot`` 在指定页内翻转
一个字节以制造摘要不符。
"""

from __future__ import annotations

import hashlib
import struct

_HASH_NAMES = {1: "sha1", 2: "sha256", 3: "sha256", 4: "sha384", 5: "sha512"}


def _code_bytes(n: int, seed: bytes = b"seal-audit-fixture") -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:n])


def _cd_header_size(version: int) -> int:
    size = 44
    if version >= 0x20100:
        size += 4
    if version >= 0x20200:
        size += 4
    if version >= 0x20300:
        size += 12
    if version >= 0x20400:
        size += 24
    return size


def build_payload(*, n_pages: int = 5, page_exp: int = 12,
                  ident: bytes = b"com.vendor.payload.fw",
                  version: int = 0x20200, hash_type: int = 2,
                  hash_size: int = 32, n_special: int = 0,
                  flags: int = 0, platform: int = 0,
                  tamper_slot: int | None = None,
                  bits: int = 64, endian: str = "<") -> tuple[bytes, dict]:
    page_size = 1 << page_exp
    code_limit = n_pages * page_size - 37  # 故意让末页为部分页
    n_code = (code_limit + page_size - 1) // page_size

    hdr_size = _cd_header_size(version)
    ident_field = ident + b"\x00"
    # 布局：定长头 | ident | 特殊槽（位于 hashOffset 之前）| 代码槽
    hash_offset = hdr_size + len(ident_field) + n_special * hash_size
    cd_length = hash_offset + n_code * hash_size
    sb_length = 12 + 8 + cd_length
    datasize = sb_length
    dataoff = (code_limit + 15) // 16 * 16

    if bits == 64:
        header = struct.pack(endian + "8I", 0xFEEDFACF, 0x0100000C, 0, 2,
                             1, 16, 0, 0)
    else:
        header = struct.pack(endian + "7I", 0xFEEDFACE, 0x0100000C, 0, 2,
                             1, 16, 0)
    lc = struct.pack(endian + "4I", 0x1D, 16, dataoff, datasize)

    code_region = bytearray(_code_bytes(code_limit))
    code_region[0:len(header) + len(lc)] = header + lc
    file_bytes = bytes(code_region) + b"\x00" * (dataoff - code_limit)

    hash_name = _HASH_NAMES.get(hash_type, "sha256")
    digests = []
    for i in range(n_code):
        start = i * page_size
        end = min(start + page_size, code_limit)
        d = hashlib.new(hash_name, file_bytes[start:end]).digest()
        digests.append(d[:hash_size].ljust(hash_size, b"\x00"))

    cd = struct.pack(">9I4BI", 0xFADE0C02, cd_length, version, flags,
                     hash_offset, hdr_size, n_special, n_code, code_limit,
                     hash_size, hash_type, platform, page_exp, 0)
    if version >= 0x20100:
        cd += struct.pack(">I", 0)          # scatterOffset
    if version >= 0x20200:
        cd += struct.pack(">I", 0)          # teamOffset
    if version >= 0x20300:
        cd += struct.pack(">IQ", 0, 0)      # spare3 + codeLimit64
    if version >= 0x20400:
        cd += struct.pack(">3Q", 0, 0, 0)   # execSeg*
    cd += ident_field
    cd += bytes(n_special * hash_size)
    cd += b"".join(digests)
    assert len(cd) == cd_length

    sb = struct.pack(">3I", 0xFADE0CC0, sb_length, 1)
    sb += struct.pack(">2I", 0, 20)  # type=CSSLOT_CODEDIRECTORY, offset
    payload = file_bytes + sb + cd

    if tamper_slot is not None:
        buf = bytearray(payload)
        flip = tamper_slot * page_size + 7
        buf[flip] ^= 0xFF
        payload = bytes(buf)

    info = {
        "dataoff": dataoff,
        "datasize": datasize,
        "sb_file_offset": dataoff,
        "cd_file_offset": dataoff + 20,
        "code_limit": code_limit,
        "page_size": page_size,
        "page_exp": page_exp,
        "n_code_slots": n_code,
        "n_special_slots": n_special,
        "hash_offset": hash_offset,
        "hash_size": hash_size,
        "cd_length": cd_length,
        "sb_length": sb_length,
        "ident": ident.decode(),
        "header_size": 32 if bits == 64 else 28,
        "lc_file_offset": 32 if bits == 64 else 28,
    }
    return payload, info
