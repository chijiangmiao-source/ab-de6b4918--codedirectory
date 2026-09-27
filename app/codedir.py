"""严格校验 Mach-O 内嵌签封（SuperBlob -> CodeDirectory）并逐页复算代码槽。

只接受单个大端 SuperBlob 中的 SHA-256 CodeDirectory。所有长度、索引、
偏移、哈希槽边界与 codeLimit 都会被严格校验；代码槽按声明页长从原始
字节复算。只有全部页都匹配时才判定为 ``pass``；任何结构错误、不支持
的散列类型/槽数/页指数，或任一页不符，都判定为 ``fail`` 并给出首个
失败槽或失败原因，绝不把部分结果记为通过。
"""

from __future__ import annotations

import hashlib
import struct

MAX_PAYLOAD_BYTES = 2 * 1024 * 1024  # 2 MiB

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0  # 嵌入式 SuperBlob（大端）
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSSLOT_CODEDIRECTORY = 0
CS_HASHTYPE_SHA256 = 2
SHA256_DIGEST_SIZE = 32

LC_CODE_SIGNATURE = 0x1D

MIN_PAGE_EXPONENT = 9   # 最小页 512 B
MAX_PAGE_EXPONENT = 16  # 最大页 64 KiB
MAX_SPECIAL_SLOTS = 32
# 2 MiB 载荷在最小页长下的槽数上界
MAX_CODE_SLOTS = MAX_PAYLOAD_BYTES // (1 << MIN_PAGE_EXPONENT)

CD_VERSION_MIN = 0x00020000
CD_VERSION_MAX = 0x00020400


class AuditError(Exception):
    """载荷的任何结构性/不支持的问题。"""


def _cd_header_size(version: int) -> int:
    """CodeDirectory 定长头长度（随版本增长）。"""
    size = 44  # 到 spare2 为止
    if version >= 0x20100:
        size += 4   # scatterOffset
    if version >= 0x20200:
        size += 4   # teamOffset
    if version >= 0x20300:
        size += 12  # spare3 + codeLimit64
    if version >= 0x20400:
        size += 24  # execSegBase + execSegLimit + execSegFlags
    return size


def _find_code_signature(raw: bytes) -> tuple[int, int]:
    """解析 Mach-O 头与 load commands，返回 (dataoff, datasize)。"""
    if len(raw) < 28:
        raise AuditError("Mach-O 头被截断（不足 28 字节）")
    magic = raw[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        endian, is64 = "<", True
    elif magic == b"\xfe\xed\xfa\xcf":
        endian, is64 = ">", True
    elif magic == b"\xce\xfa\xed\xfe":
        endian, is64 = "<", False
    elif magic == b"\xfe\xed\xfa\xce":
        endian, is64 = ">", False
    else:
        raise AuditError("不是 Mach-O（magic 0x%s 无法识别）" % magic.hex())
    header_size = 32 if is64 else 28
    if len(raw) < header_size:
        raise AuditError("Mach-O 头被截断（不足 %d 字节）" % header_size)
    fields = struct.unpack_from(endian + "7I", raw, 0)
    ncmds, sizeofcmds = fields[4], fields[5]
    cmds_end = header_size + sizeofcmds
    if cmds_end > len(raw):
        raise AuditError("load commands 超出切片末尾")
    sigs = []
    off = header_size
    for i in range(ncmds):
        if off + 8 > cmds_end:
            raise AuditError("load command #%d 被截断" % i)
        cmd, cmdsize = struct.unpack_from(endian + "2I", raw, off)
        if cmdsize < 8 or off + cmdsize > cmds_end:
            raise AuditError("load command #%d 的 cmdsize 非法" % i)
        if cmd == LC_CODE_SIGNATURE:
            if cmdsize < 16:
                raise AuditError("LC_CODE_SIGNATURE 长度不足")
            dataoff, datasize = struct.unpack_from(endian + "2I", raw, off + 8)
            sigs.append((dataoff, datasize))
        off += cmdsize
    if off != cmds_end:
        raise AuditError("load commands 与 sizeofcmds 不一致")
    if not sigs:
        raise AuditError("缺少 LC_CODE_SIGNATURE load command")
    if len(sigs) > 1:
        raise AuditError("存在多个 LC_CODE_SIGNATURE load command")
    return sigs[0]


def verify_payload(raw: bytes) -> dict:
    """核验原始字节，返回审计结论与逐页证据（永不抛出）。"""
    try:
        return _verify(raw)
    except AuditError as exc:
        return {
            "verdict": "fail",
            "reason": str(exc),
            "first_failing_slot": None,
            "code_directory": None,
            "coverage": None,
            "pages": [],
        }


def _verify(raw: bytes) -> dict:
    if not raw:
        raise AuditError("载荷为空")
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise AuditError("载荷超过 2 MiB 上限")

    dataoff, datasize = _find_code_signature(raw)
    if dataoff > len(raw):
        raise AuditError("代码签名偏移超出切片末尾")
    if datasize < 12:
        raise AuditError("代码签名区域过小，容不下 SuperBlob 头")
    if dataoff + datasize > len(raw):
        raise AuditError("代码签名区域超出切片末尾")
    sb = raw[dataoff:dataoff + datasize]

    magic, sb_len, count = struct.unpack_from(">3I", sb, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        raise AuditError(
            "只接受大端嵌入式 SuperBlob（magic 应为 0xfade0cc0，实际 0x%08x）" % magic)
    if count < 1:
        raise AuditError("SuperBlob 不含任何 blob")
    if sb_len < 12 + 8 * count:
        raise AuditError("SuperBlob 长度小于索引表")
    if sb_len > datasize:
        raise AuditError("SuperBlob 长度超出代码签名区域")

    cd_offsets = []
    for i in range(count):
        btype, boff = struct.unpack_from(">2I", sb, 12 + 8 * i)
        if boff < 12 + 8 * count or boff + 8 > sb_len:
            raise AuditError("SuperBlob 索引 #%d 的偏移越界" % i)
        if btype == CSSLOT_CODEDIRECTORY:
            cd_offsets.append(boff)
    if not cd_offsets:
        raise AuditError("SuperBlob 中没有 CodeDirectory 槽")
    if len(cd_offsets) > 1:
        raise AuditError("SuperBlob 中存在多个 CodeDirectory 槽")
    cd_off = cd_offsets[0]

    if cd_off + 44 > sb_len:
        raise AuditError("CodeDirectory 头被截断")
    (cd_magic, cd_len, version, flags, hash_offset, ident_offset,
     n_special, n_code, code_limit) = struct.unpack_from(">9I", sb, cd_off)
    hash_size, hash_type, platform, page_exp = struct.unpack_from(
        ">4B", sb, cd_off + 36)

    if cd_magic != CSMAGIC_CODEDIRECTORY:
        raise AuditError(
            "CodeDirectory magic 非法（应为 0xfade0c02，实际 0x%08x）" % cd_magic)
    if cd_len < 44:
        raise AuditError("CodeDirectory 长度小于定长头")
    if cd_off + cd_len > sb_len:
        raise AuditError("CodeDirectory 长度超出 SuperBlob")
    if not (CD_VERSION_MIN <= version <= CD_VERSION_MAX):
        raise AuditError("不支持的 CodeDirectory 版本 0x%x" % version)
    header_size = _cd_header_size(version)
    if cd_len < header_size:
        raise AuditError("CodeDirectory 长度小于该版本的头长度")

    if hash_type != CS_HASHTYPE_SHA256:
        raise AuditError("不支持的散列类型 %d（仅接受 SHA-256）" % hash_type)
    if hash_size != SHA256_DIGEST_SIZE:
        raise AuditError("散列槽长度 %d 与 SHA-256（32 字节）不符" % hash_size)
    if not (MIN_PAGE_EXPONENT <= page_exp <= MAX_PAGE_EXPONENT):
        raise AuditError("不支持的页指数 2^%d" % page_exp)
    page_size = 1 << page_exp
    if n_code == 0:
        raise AuditError("nCodeSlots 为零")
    if n_code > MAX_CODE_SLOTS:
        raise AuditError("不支持的代码槽数 %d" % n_code)
    if n_special > MAX_SPECIAL_SLOTS:
        raise AuditError("不支持的特殊槽数 %d" % n_special)
    if code_limit == 0:
        raise AuditError("codeLimit 为零")
    if code_limit > len(raw):
        raise AuditError("codeLimit 超出切片末尾")
    if code_limit > dataoff:
        raise AuditError("codeLimit 与代码签名区域重叠")
    expected_slots = (code_limit + page_size - 1) // page_size
    if n_code != expected_slots:
        raise AuditError(
            "nCodeSlots=%d 与 codeLimit=%d、页长=%d 不一致（应为 %d）"
            % (n_code, code_limit, page_size, expected_slots))

    if ident_offset < header_size or ident_offset >= cd_len:
        raise AuditError("identOffset 越界")
    ident_region = sb[cd_off + ident_offset:cd_off + cd_len]
    nul = ident_region.find(b"\x00")
    if nul < 0:
        raise AuditError("ident 字符串未在 CodeDirectory 内终止")
    ident = ident_region[:nul].decode("utf-8", "replace")

    if hash_offset < header_size:
        raise AuditError("hashOffset 与 CodeDirectory 头重叠")
    slots_base = hash_offset - n_special * hash_size
    if slots_base < header_size:
        raise AuditError("特殊哈希槽与 CodeDirectory 头重叠")
    if ident_offset + nul + 1 > slots_base:
        raise AuditError("ident 字符串与哈希槽区重叠")
    if hash_offset + n_code * hash_size > cd_len:
        raise AuditError("代码哈希槽超出 CodeDirectory 长度")

    pages = []
    first_failing = None
    for slot in range(n_code):
        start = slot * page_size
        end = min(start + page_size, code_limit)
        actual = hashlib.sha256(raw[start:end]).hexdigest()
        slot_off = cd_off + hash_offset + slot * hash_size
        expected = sb[slot_off:slot_off + hash_size].hex()
        match = actual == expected
        if not match and first_failing is None:
            first_failing = slot
        pages.append({
            "slot": slot,
            "offset": start,
            "length": end - start,
            "expected_sha256": expected,
            "actual_sha256": actual,
            "match": match,
        })

    summary = {
        "ident": ident,
        "version": "0x%x" % version,
        "flags": flags,
        "platform": platform,
        "hash_type": "sha256",
        "hash_size": hash_size,
        "page_exponent": page_exp,
        "page_size": page_size,
        "n_special_slots": n_special,
        "n_code_slots": n_code,
        "code_limit": code_limit,
        "hash_offset": hash_offset,
        "cd_length": cd_len,
        "superblob_length": sb_len,
        "superblob_blobs": count,
        "signature_offset": dataoff,
        "signature_size": datasize,
    }
    coverage = {
        "start": 0,
        "end": code_limit,
        "page_size": page_size,
        "n_pages": n_code,
        "covered_bytes": code_limit,
    }
    if first_failing is not None:
        return {
            "verdict": "fail",
            "reason": "第 %d 槽（页）摘要不符" % first_failing,
            "first_failing_slot": first_failing,
            "code_directory": summary,
            "coverage": coverage,
            "pages": pages,
        }
    return {
        "verdict": "pass",
        "reason": None,
        "first_failing_slot": None,
        "code_directory": summary,
        "coverage": coverage,
        "pages": pages,
    }
