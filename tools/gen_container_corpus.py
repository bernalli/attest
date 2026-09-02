#!/usr/bin/env python3
"""Generate the hostile-container corpus both importers are judged against.

A `.attest` file is a ZIP archive, and "which members does this archive hold"
is a question two widely used ZIP readers answer differently: one trusts the
end-of-central-directory record's entry counter and its declared offset, the
other walks the directory backwards from the end of the file and ignores both.
An archive that stays inside the canonical form described in the corpus README
cannot be read two ways; this generator writes the archives that leave it.

The writer here is deliberately its own: it exposes every field of the three
ZIP structures as an overridable parameter, so a case can lie about exactly one
thing and stay honest about everything else. It never imports the reader it
exists to break -- a bench derived from the thing it proves cannot find the
hole that thing has, and a test in `tests/test_gen_container_corpus.py` keeps
that mechanical rather than aspirational.

Usage:

    python3 tools/gen_container_corpus.py --out tests/container-corpus
    python3 tools/gen_container_corpus.py --check
    python3 tools/gen_container_corpus.py --fuzz 200 --seed 20260902 --out /tmp/f
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import struct
import sys
import tempfile
import zlib
from dataclasses import dataclass, field, replace
from pathlib import Path

LFH_SIG = 0x04034B50
CD_SIG = 0x02014B50
EOCD_SIG = 0x06054B50
DD_SIG = 0x08074B50
ZIP64_LOCATOR_SIG = 0x07064B50

#: The closed error taxonomy, in the order the canonical reader checks for it.
#: Duplicated on purpose in `src/attest/container.py` and `site/src/container.ts`;
#: `codes.json` in the corpus is what pins all three together.
CODES: tuple[str, ...] = (
    "too-short",
    "eocd-not-last",
    "eocd-comment-length",
    "multi-disk",
    "zip64",
    "entry-counters-disagree",
    "too-many-entries",
    "directory-misplaced",
    "directory-record-signature",
    "directory-record-overrun",
    "directory-trailing-bytes",
    "record-comment",
    "record-multi-disk",
    "record-encrypted",
    "record-method",
    "record-zip64",
    "record-name-empty",
    "record-name-encoding",
    "duplicate-name",
    "record-stored-size",
    "local-header-out-of-range",
    "local-header-signature",
    "local-name-mismatch",
    "member-data-out-of-range",
    "declared-member-over-cap",
    "declared-total-over-cap",
    "member-over-cap",
    "total-over-cap",
    "member-size-mismatch",
    "member-crc-mismatch",
    "member-inflate-error",
)

_NOT_CANONICAL = "container is not in canonical form — "

MESSAGES: dict[str, str] = {
    "too-short": "not a readable zip archive — shorter than an end-of-central-directory record",
    "eocd-not-last": _NOT_CANONICAL
    + "the end-of-central-directory record is not the last 22 bytes of the file",
    "eocd-comment-length": _NOT_CANONICAL
    + "the end-of-central-directory record declares a comment",
    "multi-disk": _NOT_CANONICAL + "multi-disk archive fields are set",
    "zip64": _NOT_CANONICAL + "ZIP64 structures are present",
    "entry-counters-disagree": _NOT_CANONICAL + "the two entry counters disagree",
    "too-many-entries": "bundle declares over {max_entries} entries — refusing a possible zip bomb",
    "directory-misplaced": _NOT_CANONICAL
    + "the central directory does not end where the end-of-central-directory record begins",
    "directory-record-signature": _NOT_CANONICAL
    + "a central-directory record is missing its signature",
    "directory-record-overrun": _NOT_CANONICAL
    + "a central-directory record runs past the directory",
    "directory-trailing-bytes": _NOT_CANONICAL
    + "the central directory holds bytes after its last record",
    "record-comment": _NOT_CANONICAL + "a central-directory record declares a comment",
    "record-multi-disk": _NOT_CANONICAL + "a member is declared on another disk",
    "record-encrypted": _NOT_CANONICAL + "a member is encrypted",
    "record-method": _NOT_CANONICAL
    + "a member uses a compression method other than stored or deflate",
    "record-zip64": _NOT_CANONICAL + "a member carries ZIP64 sentinel values",
    "record-name-empty": _NOT_CANONICAL + "a member has an empty name",
    "record-name-encoding": _NOT_CANONICAL
    + "a member name is not valid UTF-8, or is non-ASCII without the UTF-8 flag",
    "duplicate-name": "bundle central directory repeats member name(s) — refusing to import: "
    "duplicated members shadow each other",
    "record-stored-size": _NOT_CANONICAL + "a stored member declares two different sizes",
    "local-header-out-of-range": _NOT_CANONICAL
    + "a member's local header lies outside the member area",
    "local-header-signature": _NOT_CANONICAL + "a member's local header is missing its signature",
    "local-name-mismatch": _NOT_CANONICAL
    + "a member's local header names a different file than the directory does",
    "member-data-out-of-range": _NOT_CANONICAL + "a member's data runs into the central directory",
    "declared-member-over-cap": "a member is over the per-member decompression cap — "
    "refusing a possible zip bomb",
    "declared-total-over-cap": "bundle is over the aggregate decompression cap — "
    "refusing a possible zip bomb",
    "member-over-cap": "a member inflated past the per-member cap — refusing a possible zip bomb",
    "total-over-cap": "bundle inflated past the aggregate cap — refusing a possible zip bomb",
    "member-size-mismatch": "a member inflated to a different size than its directory record "
    "declares",
    "member-crc-mismatch": "a member failed its CRC-32 check",
    "member-inflate-error": "a member is not a valid deflate stream",
}

#: The browser verifier's caps — the tighter of the two implementations, so a
#: corpus case that passes here passes under the reference importer's caps too.
DEFAULT_CAPS: dict[str, int] = {
    "max_entries": 10_000,
    "max_member_bytes": 64 * 1024 * 1024,
    "max_total_bytes": 256 * 1024 * 1024,
}


@dataclass(frozen=True)
class Entry:
    """One member, with every structural field of §4.1 overridable.

    `None` on an override means "honest, computed from the layout". The fields
    prefixed `local_` write the local file header only, so a case can make the
    two headers disagree; `csize`/`usize`/`crc` write BOTH headers, which is how
    a directory that lies about a member stays internally consistent.
    """

    name: bytes
    data: bytes = b""
    method: int = 0
    flags: int = 0
    extra: bytes = b""
    comment: bytes = b""
    crc: int | None = None
    csize: int | None = None
    usize: int | None = None
    lho: int | None = None
    raw_compressed: bytes | None = None
    descriptor: bool = False
    gap_before: int = 0
    disk_start: int = 0
    ver_made: int = 20
    ver_need: int = 20
    mtime: int = 0
    mdate: int = 33  # 1980-01-01, the epoch of the MS-DOS date field
    int_attr: int = 0
    ext_attr: int = 0
    central_sig: int = CD_SIG
    name_len: int | None = None
    extra_len: int | None = None
    comment_len: int | None = None
    local_sig: int = LFH_SIG
    local_name: bytes | None = None
    local_extra: bytes | None = None
    local_flags: int | None = None
    local_method: int | None = None
    local_ver_need: int | None = None
    local_mtime: int | None = None
    local_mdate: int | None = None
    local_crc: int | None = None
    local_csize: int | None = None
    local_usize: int | None = None
    local_name_len: int | None = None
    local_extra_len: int | None = None


@dataclass(frozen=True)
class Archive:
    """A whole file: members, then the central directory, then the EOCD."""

    entries: list[Entry]
    n_disk: int | None = None
    n_total: int | None = None
    size_cd: int | None = None
    off_cd: int | None = None
    eocd_sig: int = EOCD_SIG
    eocd_comment: bytes = b""
    eocd_comment_len: int | None = None
    disk_no: int = 0
    cd_disk: int = 0
    prefix: bytes = b""
    suffix: bytes = b""
    extra_records: bytes = b""
    zip64_locator: bool = False
    truncate_at: int | None = None
    byte_patches: tuple[tuple[int, int], ...] = ()


def _real_deflate(data: bytes) -> bytes:
    """A genuinely compressed stream, for the fuzzer only. The COMMITTED corpus
    never uses this: its bytes must not depend on which zlib is installed."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def _deflate(data: bytes) -> bytes:
    """Encode raw DEFLATE using deterministic, uncompressed stored blocks."""
    blocks = [data[offset : offset + 0xFFFF] for offset in range(0, len(data), 0xFFFF)]
    if not blocks:
        blocks = [b""]
    encoded = bytearray()
    for index, block in enumerate(blocks):
        # BTYPE=00 starts on a byte boundary here. The five high bits are the
        # required alignment padding; only the final block carries BFINAL.
        encoded.append(1 if index == len(blocks) - 1 else 0)
        encoded += struct.pack("<HH", len(block), len(block) ^ 0xFFFF)
        encoded += block
    return bytes(encoded)


def _payload(entry: Entry) -> bytes:
    if entry.raw_compressed is not None:
        return entry.raw_compressed
    if entry.method == 8:
        return _deflate(entry.data)
    return entry.data


def _crc(entry: Entry) -> int:
    return zlib.crc32(entry.data) & 0xFFFFFFFF if entry.crc is None else entry.crc


def _local_header(entry: Entry, payload: bytes) -> bytes:
    name = entry.name if entry.local_name is None else entry.local_name
    extra = b"" if entry.local_extra is None else entry.local_extra
    flags = entry.flags if entry.local_flags is None else entry.local_flags
    method = entry.method if entry.local_method is None else entry.local_method
    ver_need = entry.ver_need if entry.local_ver_need is None else entry.local_ver_need
    mtime = entry.mtime if entry.local_mtime is None else entry.local_mtime
    mdate = entry.mdate if entry.local_mdate is None else entry.local_mdate
    crc = _crc(entry) if entry.local_crc is None else entry.local_crc
    central_csize = len(payload) if entry.csize is None else entry.csize
    central_usize = len(entry.data) if entry.usize is None else entry.usize
    csize = central_csize if entry.local_csize is None else entry.local_csize
    usize = central_usize if entry.local_usize is None else entry.local_usize
    # A data descriptor moves the three size fields out of the local header,
    # which is exactly what a writer that cannot seek does.
    crc_field, csize_field, usize_field = (0, 0, 0) if entry.descriptor else (crc, csize, usize)
    name_len = len(name) if entry.local_name_len is None else entry.local_name_len
    extra_len = len(extra) if entry.local_extra_len is None else entry.local_extra_len
    return (
        struct.pack(
            "<IHHHHHIIIHH",
            entry.local_sig,
            ver_need,
            flags,
            method,
            mtime,
            mdate,
            crc_field,
            csize_field,
            usize_field,
            name_len,
            extra_len,
        )
        + name
        + extra
    )


def _central_record(entry: Entry, payload: bytes, offset: int) -> bytes:
    csize = len(payload) if entry.csize is None else entry.csize
    usize = len(entry.data) if entry.usize is None else entry.usize
    lho = offset if entry.lho is None else entry.lho
    name_len = len(entry.name) if entry.name_len is None else entry.name_len
    extra_len = len(entry.extra) if entry.extra_len is None else entry.extra_len
    comment_len = len(entry.comment) if entry.comment_len is None else entry.comment_len
    return (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            entry.central_sig,
            entry.ver_made,
            entry.ver_need,
            entry.flags,
            entry.method,
            entry.mtime,
            entry.mdate,
            _crc(entry),
            csize,
            usize,
            name_len,
            extra_len,
            comment_len,
            entry.disk_start,
            entry.int_attr,
            entry.ext_attr,
            lho,
        )
        + entry.name
        + entry.extra
        + entry.comment
    )


def build(archive: Archive) -> bytes:
    """Serialise `archive`. Honest by default; every declared override wins."""
    body = bytearray()
    placed: list[tuple[Entry, bytes, int]] = []
    for entry in archive.entries:
        body += b"\x00" * entry.gap_before
        offset = len(body)
        payload = _payload(entry)
        body += _local_header(entry, payload)
        body += payload
        if entry.descriptor:
            body += struct.pack("<IIII", DD_SIG, _crc(entry), len(payload), len(entry.data))
        placed.append((entry, payload, offset))

    off_cd_real = len(body)
    directory = bytearray()
    for entry, payload, offset in placed:
        directory += _central_record(entry, payload, offset)
    directory += archive.extra_records
    body += directory
    if archive.zip64_locator:
        # A ZIP64 end-of-central-directory locator, 20 bytes, where a reader
        # that enters ZIP64 on presence alone will find it.
        body += struct.pack("<IIQI", ZIP64_LOCATOR_SIG, 0, 0, 1)

    count = len(archive.entries)
    n_disk = count if archive.n_disk is None else archive.n_disk
    n_total = count if archive.n_total is None else archive.n_total
    size_cd = len(directory) if archive.size_cd is None else archive.size_cd
    off_cd = off_cd_real if archive.off_cd is None else archive.off_cd
    comment_len = (
        len(archive.eocd_comment) if archive.eocd_comment_len is None else archive.eocd_comment_len
    )
    body += struct.pack(
        "<IHHHHIIH",
        archive.eocd_sig,
        archive.disk_no,
        archive.cd_disk,
        n_disk,
        n_total,
        size_cd,
        off_cd,
        comment_len,
    )
    body += archive.eocd_comment

    raw = bytearray(archive.prefix + bytes(body) + archive.suffix)
    if archive.truncate_at is not None:
        del raw[archive.truncate_at :]
    for position, value in archive.byte_patches:
        raw[position] = value
    return bytes(raw)


@dataclass(frozen=True)
class Case:
    """One corpus leaf: an archive plus what the canonical reader must say."""

    name: str
    archive: Archive
    verdict: str
    code: str | None = None
    member: str | None = None
    caps: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_CAPS))
    members: list[dict[str, object]] | None = None

    def expectation(self) -> dict[str, object]:
        if self.verdict == "reject":
            return {
                "caps": self.caps,
                "verdict": "reject",
                "code": self.code,
                "member": self.member,
            }
        members = self.members
        if members is None:
            members = [
                {
                    "name": entry.name.decode("utf-8"),
                    "method": entry.method,
                    "size": len(entry.data),
                    "sha256": hashlib.sha256(entry.data).hexdigest(),
                }
                for entry in self.archive.entries
            ]
        return {"caps": self.caps, "verdict": "accept", "members": members}


RECEIPT_ID = "01JBXYZ0000000000000000000"
RECEIPT_NAME = f"receipts/{RECEIPT_ID}.attest.json".encode()
MANIFEST_NAME = b"manifests/h.json"
SALTS_NAME = b"salts.json"
MANIFEST_JSON = b'{"issuer":"h.example","key_manifests":[]}'
SALTS_JSON = f'{{"{RECEIPT_ID}":"AAAA"}}'.encode()


def _receipt(tag: str) -> bytes:
    return f'{{"payload":{{"receipt_id":"{RECEIPT_ID}","tag":"{tag}"}}}}'.encode()


def _pair(method: int = 0) -> list[Entry]:
    """The honest two-member model every single-lie case starts from."""
    return [
        Entry(name=MANIFEST_NAME, data=MANIFEST_JSON, method=method),
        Entry(name=RECEIPT_NAME, data=_receipt("A"), method=method),
    ]


def _caps(**overrides: int) -> dict[str, int]:
    caps = dict(DEFAULT_CAPS)
    caps.update(overrides)
    return caps


def _exhibit_ab() -> tuple[bytes, bytes]:
    """`A-honest` and `B2-counter`: three stored members, one name repeated, and
    the same file with the entries-on-this-disk counter lowered by one byte."""
    entries = [
        Entry(name=MANIFEST_NAME, data=MANIFEST_JSON),
        Entry(name=RECEIPT_NAME, data=_receipt("A")),
        Entry(name=RECEIPT_NAME, data=_receipt("B")),
    ]
    honest = build(Archive(entries=entries))
    lied = build(Archive(entries=entries, n_disk=2))
    return honest, lied


def _exhibit_c() -> tuple[bytes, bytes]:
    """`C-salts-honest` and `C2-salts`: a receipt beside the buyer's salts, and
    the same file with the counter hiding the salts from one of the readers."""
    entries = [
        Entry(name=RECEIPT_NAME, data=_receipt("C")),
        Entry(name=SALTS_NAME, data=SALTS_JSON),
    ]
    honest = build(Archive(entries=entries))
    lied = build(Archive(entries=entries, n_disk=1))
    return honest, lied


def _exhibit_d_prefix() -> bytes:
    """`D-prefix`: one file, TWO valid central directories, no counter touched.

    The declared offset points at the first directory (where a reader that
    trusts it lands); the second sits immediately before the EOCD (where a
    reader that walks back from the end lands). Both directories are internally
    consistent, so nothing inside either one is a lie — the file is.
    """
    decoy_data = _receipt("browser-sees")
    decoy_entry = Entry(name=RECEIPT_NAME, data=decoy_data)
    decoy_payload = _payload(decoy_entry)
    decoy_block = _local_header(decoy_entry, decoy_payload) + decoy_payload

    real_receipt = Entry(name=RECEIPT_NAME, data=_receipt("reference-sees"))
    real_salts = Entry(name=SALTS_NAME, data=SALTS_JSON)
    real_blocks = [_local_header(e, _payload(e)) + _payload(e) for e in (real_receipt, real_salts)]

    # The decoy directory must sit far enough in that every local-header offset
    # the tail directory stores stays non-negative once the prefix compensation
    # is subtracted; the margin keeps the arithmetic away from that boundary.
    padding = b"\x00" * (max(0, sum(len(b) for b in real_blocks) - len(decoy_block)) + 16)
    decoy_cd_offset = len(decoy_block) + len(padding)
    decoy_cd = _central_record(decoy_entry, decoy_payload, 0)

    real_lfh_offset = decoy_cd_offset + len(decoy_cd)
    salts_lfh_offset = real_lfh_offset + len(real_blocks[0])
    real_cd_offset = salts_lfh_offset + len(real_blocks[1])
    concat = real_cd_offset - decoy_cd_offset

    prefix = decoy_block + padding + decoy_cd
    return build(
        Archive(
            entries=[
                Entry(name=RECEIPT_NAME, data=real_receipt.data, lho=real_lfh_offset - concat),
                Entry(name=SALTS_NAME, data=real_salts.data, lho=salts_lfh_offset - concat),
            ],
            prefix=prefix,
            off_cd=decoy_cd_offset,
        )
    )


def _exhibit_d_prefix_inverse() -> bytes:
    """The inverse addressing split: ``size_cd`` starts before ``off_cd``.

    A size-based reader sees two adjacent directory records. An offset-and-count
    reader starts at the second record and sees only that member. The second
    local header is duplicated at the displacement between those starts so
    both readers also reach coherent member bytes after applying their own
    local-header addressing model.
    """
    earlier = Entry(name=b"receipts/earlier.attest.json", data=b"size-sees")
    later = Entry(name=b"receipts/later.attest.json", data=b"offset-sees")
    earlier_payload = _payload(earlier)
    later_payload = _payload(later)
    earlier_block = _local_header(earlier, earlier_payload) + earlier_payload
    later_block = _local_header(later, later_payload) + later_payload

    earlier_record_size = len(_central_record(earlier, earlier_payload, 0))
    earlier_lho = 0
    later_size_lho = len(earlier_block)
    if len(later_block) > earlier_record_size:
        raise AssertionError("inverse D-prefix member must fit inside the directory displacement")
    padding = b"\x00" * (earlier_record_size - len(later_block))
    later_offset_lho = later_size_lho + earlier_record_size

    member_area = earlier_block + later_block + padding + later_block
    earlier_cd_offset = len(member_area)
    earlier_cd = _central_record(
        replace(earlier, lho=earlier_lho + earlier_record_size), earlier_payload, 0
    )
    later_cd_offset = earlier_cd_offset + len(earlier_cd)
    later_cd = _central_record(replace(later, lho=later_offset_lho), later_payload, 0)
    directory = earlier_cd + later_cd
    eocd = struct.pack(
        "<IHHHHIIH",
        EOCD_SIG,
        0,
        0,
        1,
        1,
        len(directory),
        later_cd_offset,
        0,
    )
    return member_area + directory + eocd


@dataclass(frozen=True)
class _RawCase:
    """A case whose bytes are assembled outside the `Archive` model."""

    name: str
    raw: bytes
    verdict: str
    code: str | None = None
    member: str | None = None
    caps: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_CAPS))
    members: list[dict[str, object]] | None = None

    def expectation(self) -> dict[str, object]:
        if self.verdict == "reject":
            return {
                "caps": self.caps,
                "verdict": "reject",
                "code": self.code,
                "member": self.member,
            }
        return {"caps": self.caps, "verdict": "accept", "members": self.members or []}


def _member(name: bytes, data: bytes, method: int = 0) -> dict[str, object]:
    return {
        "name": name.decode("utf-8"),
        "method": method,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _accept_cases() -> list[Case]:
    big = b"the deal this receipt preserves. " * 64
    trailing_payload = _deflate(big) + b"\x00\x00\x00\x00"
    return [
        Case("honest-stored", Archive(entries=_pair()), "accept"),
        Case("honest-deflate", Archive(entries=_pair(method=8)), "accept"),
        Case("honest-empty", Archive(entries=[]), "accept"),
        Case(
            "honest-extra-field",
            Archive(
                entries=[
                    Entry(
                        name=MANIFEST_NAME,
                        data=MANIFEST_JSON,
                        extra=b"\x99\x99\x04\x00abcd",
                        local_extra=b"\x99\x99\x08\x00abcdefgh",
                    )
                ]
            ),
            "accept",
        ),
        Case(
            "honest-utf8-name-with-flag",
            Archive(entries=[Entry(name="legal/café-eula.txt".encode(), data=b"x", flags=0x0800)]),
            "accept",
        ),
        Case(
            "honest-gap-between-members",
            Archive(
                entries=[
                    Entry(name=MANIFEST_NAME, data=MANIFEST_JSON),
                    Entry(name=RECEIPT_NAME, data=_receipt("A"), gap_before=7),
                ]
            ),
            "accept",
        ),
        Case(
            "honest-directory-entry",
            Archive(
                entries=[
                    Entry(name=b"receipts/", data=b""),
                    Entry(name=RECEIPT_NAME, data=_receipt("A")),
                ]
            ),
            "accept",
        ),
        Case(
            # A leading U+FEFF is part of the name, not a text-stream marker to
            # be sniffed off: one decoder used to drop it and the other keep it,
            # which is two member lists — and, with `salts.json`, two different
            # answers about whether the archive holds the buyer's secrets.
            "honest-bom-in-name",
            Archive(
                entries=[
                    Entry(name="\ufeffa.txt".encode(), data=b"one", flags=0x0800),
                    Entry(name=b"a.txt", data=b"two"),
                    Entry(name=RECEIPT_NAME, data=_receipt("A")),
                ]
            ),
            "accept",
        ),
        Case(
            "honest-proto-name",
            Archive(
                entries=[
                    Entry(name=b"__proto__", data=b"not a prototype"),
                    Entry(name=b"constructor", data=b"not a constructor"),
                    Entry(name=RECEIPT_NAME, data=_receipt("A")),
                ]
            ),
            "accept",
        ),
        Case(
            "honest-deflate-trailing-inside-csize",
            Archive(
                entries=[
                    Entry(
                        name=b"legal/eula.txt",
                        data=big,
                        method=8,
                        raw_compressed=trailing_payload,
                    )
                ]
            ),
            "accept",
        ),
        Case(
            "honest-data-descriptor-flag",
            Archive(
                entries=[
                    Entry(name=MANIFEST_NAME, data=MANIFEST_JSON, flags=0x0008, descriptor=True),
                    Entry(name=RECEIPT_NAME, data=_receipt("A"), flags=0x0008, descriptor=True),
                ]
            ),
            "accept",
        ),
        Case(
            "central-ver-made",
            Archive(entries=[Entry(name=b"legal/ver-made.txt", data=b"x", ver_made=21)]),
            "accept",
        ),
        Case(
            "central-ver-need",
            Archive(
                entries=[
                    Entry(
                        name=b"legal/ver-need.txt",
                        data=b"x",
                        ver_need=21,
                        local_ver_need=20,
                    )
                ]
            ),
            "accept",
        ),
        Case(
            "central-mtime",
            Archive(entries=[Entry(name=b"legal/mtime.txt", data=b"x", mtime=1, local_mtime=0)]),
            "accept",
        ),
        Case(
            "central-mdate",
            Archive(entries=[Entry(name=b"legal/mdate.txt", data=b"x", mdate=34, local_mdate=33)]),
            "accept",
        ),
        Case(
            "central-int-attr",
            Archive(entries=[Entry(name=b"legal/int-attr.txt", data=b"x", int_attr=1)]),
            "accept",
        ),
        Case(
            "central-ext-attr",
            Archive(entries=[Entry(name=b"legal/ext-attr.txt", data=b"x", ext_attr=1)]),
            "accept",
        ),
        Case(
            "local-flags",
            Archive(entries=[Entry(name=b"legal/local-flags.txt", data=b"x", local_flags=8)]),
            "accept",
        ),
        Case(
            "local-method",
            Archive(entries=[Entry(name=b"legal/local-method.txt", data=b"x", local_method=8)]),
            "accept",
        ),
        Case(
            "local-ver-need",
            Archive(entries=[Entry(name=b"legal/local-ver.txt", data=b"x", local_ver_need=21)]),
            "accept",
        ),
        Case(
            "local-mtime",
            Archive(entries=[Entry(name=b"legal/local-mtime.txt", data=b"x", local_mtime=1)]),
            "accept",
        ),
        Case(
            "local-mdate",
            Archive(entries=[Entry(name=b"legal/local-mdate.txt", data=b"x", local_mdate=34)]),
            "accept",
        ),
        Case(
            "local-crc",
            Archive(entries=[Entry(name=b"legal/local-crc.txt", data=b"x", local_crc=0)]),
            "accept",
        ),
        Case(
            "local-csize",
            Archive(entries=[Entry(name=b"legal/local-csize.txt", data=b"x", local_csize=0)]),
            "accept",
        ),
        Case(
            "local-usize",
            Archive(entries=[Entry(name=b"legal/local-usize.txt", data=b"x", local_usize=0)]),
            "accept",
        ),
        Case(
            "honest-at-max-entries",
            Archive(
                entries=[
                    Entry(name=MANIFEST_NAME, data=MANIFEST_JSON),
                    Entry(name=RECEIPT_NAME, data=_receipt("A")),
                    Entry(name=b"legal/eula.txt", data=b"terms"),
                ]
            ),
            "accept",
            caps=_caps(max_entries=3),
        ),
    ]


def _archive_level_reject_cases() -> list[Case]:
    honest = _pair()
    honest_size_cd = sum(len(_central_record(entry, _payload(entry), 0)) for entry in honest)
    return [
        Case("too-short", Archive(entries=honest, truncate_at=10), "reject", "too-short"),
        Case(
            "eocd-sig",
            Archive(entries=honest, eocd_sig=EOCD_SIG + 1),
            "reject",
            "eocd-not-last",
        ),
        Case(
            "eocd-trailing-byte", Archive(entries=honest, suffix=b"\x00"), "reject", "eocd-not-last"
        ),
        Case(
            "eocd-with-comment",
            Archive(entries=honest, eocd_comment=b"hi"),
            "reject",
            "eocd-not-last",
        ),
        Case(
            "eocd-comment-length-without-comment",
            Archive(entries=honest, eocd_comment_len=5),
            "reject",
            "eocd-comment-length",
        ),
        Case("multi-disk", Archive(entries=honest, disk_no=1), "reject", "multi-disk"),
        Case("eocd-cd-disk", Archive(entries=honest, cd_disk=1), "reject", "multi-disk"),
        Case(
            "zip64-locator-present",
            Archive(entries=honest, zip64_locator=True),
            "reject",
            "zip64",
        ),
        Case(
            "zip64-sentinel-count",
            Archive(entries=honest, n_disk=0xFFFF, n_total=0xFFFF),
            "reject",
            "zip64",
        ),
        Case(
            # The pair above sets both counters, so a reader that only looked at
            # one of them would still pass it: each sentinel needs a leaf of its
            # own or the check that reads it is never the check that fires.
            "zip64-sentinel-total-count",
            Archive(entries=honest, n_total=0xFFFF),
            "reject",
            "zip64",
        ),
        Case("zip64-sentinel-size", Archive(entries=honest, size_cd=0xFFFFFFFF), "reject", "zip64"),
        Case(
            "zip64-sentinel-offset", Archive(entries=honest, off_cd=0xFFFFFFFF), "reject", "zip64"
        ),
        Case(
            "counter-disk-low",
            Archive(entries=honest, n_disk=1),
            "reject",
            "entry-counters-disagree",
        ),
        Case(
            "counter-disk-high",
            Archive(entries=honest, n_disk=3),
            "reject",
            "entry-counters-disagree",
        ),
        Case(
            "counter-total-low",
            Archive(entries=honest, n_total=1),
            "reject",
            "entry-counters-disagree",
        ),
        Case(
            "counter-total-high",
            Archive(entries=honest, n_total=3),
            "reject",
            "entry-counters-disagree",
        ),
        Case(
            "counters-both-low",
            Archive(entries=honest, n_disk=1, n_total=1),
            "reject",
            "directory-trailing-bytes",
        ),
        Case(
            "counters-both-high",
            Archive(entries=honest, n_disk=3, n_total=3),
            "reject",
            "directory-record-signature",
        ),
        Case(
            "too-many-entries",
            Archive(entries=honest),
            "reject",
            "too-many-entries",
            caps=_caps(max_entries=1),
        ),
        Case(
            "prefix-honest",
            Archive(entries=honest, prefix=b"MZ\x90\x00 self-extracting stub "),
            "reject",
            "directory-misplaced",
        ),
        Case(
            "size-cd-short",
            Archive(entries=honest, size_cd=honest_size_cd - 1),
            "reject",
            "directory-misplaced",
        ),
        Case(
            "size-cd-long",
            Archive(entries=honest, size_cd=0x10000),
            "reject",
            "directory-misplaced",
        ),
        Case("off-cd-shifted", Archive(entries=honest, off_cd=1), "reject", "directory-misplaced"),
        Case(
            "directory-trailing-record-bytes",
            Archive(entries=honest, extra_records=b"\x00\x00\x00\x00"),
            "reject",
            "directory-trailing-bytes",
        ),
    ]


def _record_level_reject_cases() -> list[Case]:
    manifest = Entry(name=MANIFEST_NAME, data=MANIFEST_JSON)
    receipt_data = _receipt("A")
    return [
        Case(
            "record-signature-altered",
            Archive(
                entries=[
                    manifest,
                    Entry(name=RECEIPT_NAME, data=receipt_data, central_sig=0x02014B51),
                ]
            ),
            "reject",
            "directory-record-signature",
        ),
        Case(
            "record-name-len-overrun",
            Archive(
                entries=[manifest, Entry(name=RECEIPT_NAME, data=receipt_data, name_len=0x7000)]
            ),
            "reject",
            "directory-record-overrun",
        ),
        Case(
            "central-extra-len",
            Archive(entries=[Entry(name=RECEIPT_NAME, data=receipt_data, extra=b"x", extra_len=0)]),
            "reject",
            "directory-trailing-bytes",
        ),
        Case(
            "record-comment",
            Archive(entries=[manifest, Entry(name=RECEIPT_NAME, data=receipt_data, comment=b"c")]),
            "reject",
            "record-comment",
        ),
        Case(
            "record-disk-start",
            Archive(entries=[manifest, Entry(name=RECEIPT_NAME, data=receipt_data, disk_start=1)]),
            "reject",
            "record-multi-disk",
        ),
        Case(
            "record-encrypted-bit0",
            Archive(entries=[Entry(name=RECEIPT_NAME, data=receipt_data, flags=0x0001)]),
            "reject",
            "record-encrypted",
        ),
        Case(
            "record-encrypted-bit6",
            Archive(entries=[Entry(name=RECEIPT_NAME, data=receipt_data, flags=0x0040)]),
            "reject",
            "record-encrypted",
        ),
        Case(
            "record-method-bzip2",
            Archive(entries=[Entry(name=RECEIPT_NAME, data=receipt_data, method=12)]),
            "reject",
            "record-method",
        ),
        Case(
            "record-zip64-csize",
            Archive(entries=[Entry(name=RECEIPT_NAME, data=receipt_data, csize=0xFFFFFFFF)]),
            "reject",
            "record-zip64",
        ),
        Case(
            "record-zip64-lho",
            Archive(entries=[Entry(name=RECEIPT_NAME, data=receipt_data, lho=0xFFFFFFFF)]),
            "reject",
            "record-zip64",
        ),
        Case(
            "record-zip64-usize",
            Archive(
                entries=[
                    Entry(
                        name=RECEIPT_NAME,
                        data=receipt_data,
                        usize=0xFFFFFFFF,
                        local_usize=len(receipt_data),
                    )
                ]
            ),
            "reject",
            # No member name: the name is decoded at S16, after this check.
            "record-zip64",
        ),
        Case(
            "record-name-empty",
            Archive(entries=[Entry(name=b"", data=receipt_data)]),
            "reject",
            "record-name-empty",
        ),
        Case(
            "record-name-invalid-utf8",
            Archive(entries=[Entry(name=b"legal/\xff\xfe.txt", data=b"x", flags=0x0800)]),
            "reject",
            "record-name-encoding",
        ),
        Case(
            "record-name-high-bytes-no-flag",
            Archive(entries=[Entry(name="legal/café.txt".encode(), data=b"x")]),
            "reject",
            "record-name-encoding",
        ),
        Case(
            "duplicate-name",
            Archive(
                entries=[
                    Entry(name=RECEIPT_NAME, data=_receipt("A")),
                    Entry(name=RECEIPT_NAME, data=_receipt("B")),
                ]
            ),
            "reject",
            "duplicate-name",
            member=RECEIPT_NAME.decode(),
        ),
        Case(
            "stored-size-mismatch",
            Archive(
                entries=[Entry(name=RECEIPT_NAME, data=receipt_data, usize=len(receipt_data) + 1)]
            ),
            "reject",
            "record-stored-size",
            member=RECEIPT_NAME.decode(),
        ),
        Case(
            "local-header-beyond-directory",
            Archive(entries=[Entry(name=RECEIPT_NAME, data=receipt_data, lho=0x10000)]),
            "reject",
            "local-header-out-of-range",
            member=RECEIPT_NAME.decode(),
        ),
        Case(
            "local-header-signature",
            Archive(entries=[Entry(name=RECEIPT_NAME, data=receipt_data, local_sig=0x04034B51)]),
            "reject",
            "local-header-signature",
            member=RECEIPT_NAME.decode(),
        ),
        Case(
            "local-name-differs",
            Archive(
                entries=[
                    Entry(
                        name=RECEIPT_NAME,
                        data=receipt_data,
                        local_name=b"receipts/" + b"Z" * (len(RECEIPT_NAME) - 9),
                    )
                ]
            ),
            "reject",
            "local-name-mismatch",
            member=RECEIPT_NAME.decode(),
        ),
        Case(
            "local-name-length-differs",
            Archive(
                entries=[Entry(name=RECEIPT_NAME, data=receipt_data, local_name=b"short.json")]
            ),
            "reject",
            "local-name-mismatch",
            member=RECEIPT_NAME.decode(),
        ),
        Case(
            "local-name-len",
            Archive(
                entries=[
                    Entry(
                        name=RECEIPT_NAME,
                        data=receipt_data,
                        local_name_len=len(RECEIPT_NAME) - 1,
                    )
                ]
            ),
            "reject",
            "local-name-mismatch",
            member=RECEIPT_NAME.decode(),
        ),
        Case(
            "local-extra-len",
            Archive(
                entries=[
                    Entry(
                        name=RECEIPT_NAME,
                        data=receipt_data,
                        local_extra=b"\xff",
                        local_extra_len=0,
                    )
                ]
            ),
            "reject",
            "member-crc-mismatch",
            member=RECEIPT_NAME.decode(),
        ),
        Case(
            "data-runs-into-directory",
            Archive(entries=[Entry(name=RECEIPT_NAME, data=receipt_data, method=8, csize=0x1000)]),
            "reject",
            "member-data-out-of-range",
            member=RECEIPT_NAME.decode(),
        ),
    ]


def _stored_deflate_block(payload: bytes, *, nlen: int | None = None) -> bytes:
    """A raw-DEFLATE stream holding one stored block (RFC 1951 §3.2.4). `nlen`
    overrides the complement field the two decoders disagree about."""
    length = len(payload)
    complement = (~length & 0xFFFF) if nlen is None else nlen
    return (
        bytes([0b001]) + length.to_bytes(2, "little") + complement.to_bytes(2, "little") + payload
    )


def _read_level_reject_cases() -> list[Case]:
    receipt_data = _receipt("A")
    over_member_cap = b"12345"
    first_member = Entry(name=b"legal/a.txt", data=b"1234")
    second_member = b"5678"
    return [
        Case(
            "declared-member-over-cap",
            Archive(entries=[Entry(name=RECEIPT_NAME, data=receipt_data, method=8, usize=5000)]),
            "reject",
            "declared-member-over-cap",
            member=RECEIPT_NAME.decode(),
            caps=_caps(max_member_bytes=1024, max_total_bytes=4096),
        ),
        Case(
            "declared-total-over-cap",
            Archive(
                entries=[
                    Entry(name=b"legal/a.txt", data=b"x" * 900),
                    Entry(name=b"legal/b.txt", data=b"y" * 900),
                ]
            ),
            "reject",
            "declared-total-over-cap",
            member=b"legal/b.txt".decode(),
            caps=_caps(max_member_bytes=1024, max_total_bytes=1500),
        ),
        Case(
            "inflate-lies-low",
            Archive(
                entries=[
                    Entry(
                        name=b"legal/bomb.txt",
                        data=over_member_cap,
                        method=8,
                        usize=1,
                        crc=zlib.crc32(over_member_cap),
                    )
                ]
            ),
            "reject",
            "member-over-cap",
            member=b"legal/bomb.txt".decode(),
            caps=_caps(max_member_bytes=4, max_total_bytes=8),
        ),
        Case(
            "total-over-cap-across-members",
            Archive(
                entries=[
                    first_member,
                    Entry(
                        name=b"legal/b.txt",
                        data=second_member,
                        method=8,
                        usize=1,
                        crc=zlib.crc32(second_member),
                    ),
                ]
            ),
            "reject",
            "total-over-cap",
            member=b"legal/b.txt".decode(),
            caps=_caps(max_member_bytes=4, max_total_bytes=6),
        ),
        Case(
            "usize-too-large",
            Archive(entries=[Entry(name=RECEIPT_NAME, data=receipt_data, method=8, usize=5000)]),
            "reject",
            "member-size-mismatch",
            member=RECEIPT_NAME.decode(),
            caps=_caps(max_member_bytes=8192, max_total_bytes=8192),
        ),
        Case(
            "crc-wrong",
            Archive(entries=[Entry(name=RECEIPT_NAME, data=receipt_data, crc=0xDEADBEEF)]),
            "reject",
            "member-crc-mismatch",
            member=RECEIPT_NAME.decode(),
        ),
        Case(
            "deflate-garbage",
            Archive(
                entries=[
                    Entry(
                        name=b"legal/eula.txt",
                        data=b"terms",
                        method=8,
                        raw_compressed=b"\xff\xff\xff\xff",
                    )
                ]
            ),
            "reject",
            "member-inflate-error",
            member=b"legal/eula.txt".decode(),
        ),
        Case(
            "deflate-truncated",
            Archive(
                entries=[
                    Entry(
                        name=b"legal/eula.txt",
                        data=b"terms " * 40,
                        method=8,
                        raw_compressed=_deflate(b"terms " * 40)[:-3],
                    )
                ]
            ),
            "reject",
            "member-inflate-error",
            member=b"legal/eula.txt".decode(),
        ),
        Case(
            # Measured 2026-09-02: of every malformed deflate stream tried, the
            # two decoders disagree on exactly one — a stored block whose
            # complement field is wrong. One refuses it, the other never reads
            # that field. The canonical form refuses it on both sides.
            "deflate-stored-block-bad-complement",
            Archive(
                entries=[
                    Entry(
                        name=RECEIPT_NAME,
                        data=receipt_data,
                        method=8,
                        raw_compressed=_stored_deflate_block(receipt_data, nlen=0x1234),
                    )
                ]
            ),
            "reject",
            "member-inflate-error",
            member=RECEIPT_NAME.decode(),
        ),
        Case(
            # Measured 2026-09-02: the browser verifier's decoder gives the
            # reserved literal codes working bases and produces 261 bytes from
            # this stream; the reference decoder refuses it. The canonical form
            # refuses it on both sides.
            "deflate-reserved-literal-code",
            Archive(
                entries=[
                    Entry(
                        name=RECEIPT_NAME,
                        data=b"A" * 261,
                        method=8,
                        raw_compressed=bytes.fromhex("731c0300"),
                    )
                ]
            ),
            "reject",
            "member-inflate-error",
            member=RECEIPT_NAME.decode(),
        ),
        Case(
            "deflate-stored-block-honest-complement",
            Archive(
                entries=[
                    Entry(
                        name=RECEIPT_NAME,
                        data=receipt_data,
                        method=8,
                        raw_compressed=_stored_deflate_block(receipt_data),
                    )
                ]
            ),
            "accept",
        ),
        Case(
            # Measured 2026-09-02: an empty compressed payload is the one input
            # on which the two decoders disagree by default — CPython reports a
            # stream that never reached its final block, fflate reports nothing
            # at all. Both readers name it explicitly rather than inferring it.
            "deflate-empty-stream",
            Archive(
                entries=[
                    Entry(
                        name=b"legal/eula.txt",
                        data=b"",
                        method=8,
                        raw_compressed=b"",
                        crc=0,
                    )
                ]
            ),
            "reject",
            "member-inflate-error",
            member=b"legal/eula.txt".decode(),
        ),
    ]


def _exhibit_cases() -> list[_RawCase]:
    a_honest, b2_counter = _exhibit_ab()
    c_honest, c2_salts = _exhibit_c()
    salts_payload = SALTS_JSON
    return [
        _RawCase(
            "exhibit-A-honest",
            a_honest,
            "reject",
            "duplicate-name",
            member=RECEIPT_NAME.decode(),
        ),
        _RawCase("exhibit-B2-counter", b2_counter, "reject", "entry-counters-disagree"),
        _RawCase(
            "exhibit-C-salts-honest",
            c_honest,
            "accept",
            members=[_member(RECEIPT_NAME, _receipt("C")), _member(SALTS_NAME, salts_payload)],
        ),
        _RawCase("exhibit-C2-salts", c2_salts, "reject", "entry-counters-disagree"),
        _RawCase("exhibit-D-prefix", _exhibit_d_prefix(), "reject", "directory-misplaced"),
        _RawCase(
            "exhibit-D-prefix-inverse",
            _exhibit_d_prefix_inverse(),
            "reject",
            "directory-misplaced",
        ),
    ]


def cases() -> list[Case | _RawCase]:
    """Every corpus leaf, named after the lie it tells, not the check it hits."""
    out: list[Case | _RawCase] = []
    out.extend(_accept_cases())
    out.extend(_archive_level_reject_cases())
    out.extend(_record_level_reject_cases())
    out.extend(_read_level_reject_cases())
    out.extend(_exhibit_cases())
    names = [case.name for case in out]
    if len(names) != len(set(names)):
        raise SystemExit("corpus case names must be unique")
    return out


README = """\
# Container corpus

Archives that make the question "which members does this file hold?" hard, and
the answer the canonical container reader MUST give for each of them. The same
leaves are read by `tests/test_container_corpus.py` and by
`site/test/container-corpus.test.ts`: one bench, two implementations, so a
disagreement between them is a failing test rather than a field report.

Each leaf is a directory holding `archive.zip` and `expected.json`:

    {"caps": {"max_entries": …, "max_member_bytes": …, "max_total_bytes": …},
     "verdict": "accept",
     "members": [{"name": …, "method": 0|8, "size": …, "sha256": …}]}

    {"caps": {…}, "verdict": "reject", "code": "<code>", "member": "<name>|null"}

`codes.json` carries the closed error taxonomy — the code list in the order the
reader checks for it, and the message each code renders. Both implementations
assert their own tables against that file, which is how the three copies stay
one table.

Leaves are named after the field the archive lies about, never after the check
that catches it: a rename of a check must not silently orphan its case.

## Regenerating

    python3 tools/gen_container_corpus.py --out tests/container-corpus
    python3 tools/gen_container_corpus.py --check      # exits 1 on any drift

`--check` regenerates into a temporary directory and compares byte for byte, so
an edit made by hand inside this directory is a failure, not a surprise. The
generator never imports `attest`: a bench derived from the code it judges
shares that code's blind spots, and this corpus exists precisely where those
blind spots were.

## Fuzzing

    python3 tools/gen_container_corpus.py --fuzz 500 --seed 20260902 --out /tmp/f

writes archives only, with no expectation attached, for
`tools/container_differential.py` to feed to both readers and compare. The
stream cycles through one diagnostic fault for every S1--S23 target,
intentional multi-fault precedence probes, and unclassified raw byte mutations.
The enumerated leaves above are a floor and share their author's blind spots;
the fuzzer and the in-language property suites exist because of that.
"""


def _write_case(directory: Path, raw: bytes, expectation: dict[str, object]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "archive.zip").write_bytes(raw)
    (directory / "expected.json").write_text(
        json.dumps(expectation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def write_corpus(out: Path) -> None:
    """Write every leaf, `codes.json` and the README under `out`."""
    out.mkdir(parents=True, exist_ok=True)
    for case in cases():
        raw = case.raw if isinstance(case, _RawCase) else build(case.archive)
        _write_case(out / case.name, raw, case.expectation())
    (out / "codes.json").write_text(
        json.dumps({"codes": list(CODES), "messages": MESSAGES}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "README.md").write_text(README, encoding="utf-8")


def _tree(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def check_corpus(out: Path) -> int:
    """Regenerate into a temporary directory and compare byte for byte."""
    if not out.is_dir():
        print(f"corpus directory {out} does not exist", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp) / "corpus"
        write_corpus(fresh)
        committed, produced = _tree(out), _tree(fresh)
        drift = sorted(set(committed) ^ set(produced))
        drift += sorted(
            name for name in set(committed) & set(produced) if committed[name] != produced[name]
        )
    if drift:
        print("corpus drift:", file=sys.stderr)
        for name in drift:
            print(f"  {name}", file=sys.stderr)
        return 1
    return 0


# A fourth stratum, honest archives, is what makes the differential runner
# compare the READ path and not only the refusals: a stream of hostile files
# proves the two readers refuse together, never that they agree on what an
# acceptable archive holds.
FUZZ_STRATA = ("single", "precedence", "raw", "honest")
FUZZ_SINGLE_STEPS = tuple(f"s{step:02d}" for step in range(1, 24))


#: Names that make the two readers DECODE something, rather than compare ASCII.
#: An ASCII-only alphabet leaves the whole UTF-8 path unmeasured, and that is
#: how a leading U+FEFF — dropped by one decoder, kept by the other — survived a
#: differential run of thousands of archives (measured 2026-09-02).
_FUZZ_NAME_SHAPES = (
    "legal/fuzz-{index}.bin",
    "legal/\ufefffuzz-{index}.bin",
    "legal/fuzz-{index}\ufeff.bin",
    "\ufeff",
    "legal/caf\u00e9-{index}.bin",
    "legal/\U0001f600-{index}.bin",
    "legal/\uffff-{index}.bin",
)


def _fuzz_entry(rng: random.Random, *, index: int = 0) -> Entry:
    data = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 200)))
    name = rng.choice(_FUZZ_NAME_SHAPES).format(index=index)
    non_ascii = any(ord(character) >= 0x80 for character in name)
    return Entry(
        name=name.encode(),
        data=data,
        method=rng.choice((0, 8)),
        flags=0x0800 if non_ascii else rng.choice((0, 0, 0x0800, 0x0008)),
        extra=b"\x99\x99\x02\x00zz" if rng.random() < 0.2 else b"",
        local_extra=b"\x77\x77\x02\x00yy" if rng.random() < 0.2 else None,
        gap_before=rng.choice((0, 0, 0, 3)),
    )


def _single_lie_archive(rng: random.Random, target: str) -> bytes:
    """Build one diagnostic shape whose intended first gate is ``target``."""
    data = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 32)))
    entry = Entry(name=b"legal/fuzz.bin", data=data)
    archive = Archive(entries=[entry])
    step = int(target[1:])
    if step == 1:
        return build(archive)[: rng.randint(0, 21)]
    if step == 2:
        archive = replace(archive, eocd_sig=EOCD_SIG + 1)
    elif step == 3:
        archive = replace(archive, eocd_comment_len=1)
    elif step == 4:
        archive = replace(archive, cd_disk=1)
    elif step == 5:
        archive = replace(archive, zip64_locator=True)
    elif step == 6:
        archive = replace(archive, n_disk=0)
    elif step == 7:
        archive = Archive(entries=[], n_disk=10_001, n_total=10_001)
    elif step == 8:
        archive = replace(archive, size_cd=0)
    elif step == 9:
        archive = replace(archive, entries=[replace(entry, central_sig=CD_SIG + 1)])
    elif step == 10:
        archive = replace(archive, entries=[replace(entry, comment=b"c")])
    elif step == 11:
        archive = replace(archive, entries=[replace(entry, disk_start=1)])
    elif step == 12:
        archive = replace(archive, entries=[replace(entry, flags=1, local_flags=0)])
    elif step == 13:
        archive = replace(archive, entries=[replace(entry, method=12, local_method=0)])
    elif step == 14:
        archive = replace(
            archive,
            entries=[replace(entry, csize=0xFFFFFFFF, local_csize=len(data))],
        )
    elif step == 15:
        archive = replace(archive, entries=[replace(entry, name=b"")])
    elif step == 16:
        archive = replace(archive, entries=[replace(entry, name=b"legal/\xff.bin")])
    elif step == 17:
        archive = replace(archive, entries=[entry, replace(entry, data=data[::-1])])
    elif step == 18:
        archive = replace(
            archive,
            entries=[replace(entry, usize=len(data) + 1, local_usize=len(data))],
        )
    elif step == 19:
        archive = replace(archive, entries=[replace(entry, lho=0x10000)])
    elif step == 20:
        archive = replace(archive, entries=[replace(entry, local_sig=LFH_SIG + 1)])
    elif step == 21:
        archive = replace(
            archive,
            entries=[replace(entry, local_name=b"legal/fuzz.bad")],
        )
    elif step == 22:
        archive = replace(
            archive,
            entries=[replace(entry, method=8, csize=len(_deflate(data)) + 0x100)],
        )
    elif step == 23:
        archive = replace(
            archive,
            entries=[
                replace(
                    entry,
                    method=8,
                    usize=DEFAULT_CAPS["max_member_bytes"] + 1,
                    local_usize=len(data),
                )
            ],
        )
    else:  # pragma: no cover - FUZZ_SINGLE_STEPS is the closed caller set
        raise AssertionError(f"unknown fuzz target: {target}")
    return build(archive)


def _random_entry_lie(rng: random.Random, entry: Entry) -> Entry:
    """Apply one field-level mutation from the writer's full fixed-field space."""
    field_name = rng.choice(
        (
            "central_sig",
            "ver_made",
            "ver_need",
            "flags",
            "method",
            "mtime",
            "mdate",
            "crc",
            "csize",
            "usize",
            "name_len",
            "extra_len",
            "comment_len",
            "disk_start",
            "int_attr",
            "ext_attr",
            "lho",
            "local_sig",
            "local_ver_need",
            "local_flags",
            "local_method",
            "local_mtime",
            "local_mdate",
            "local_crc",
            "local_csize",
            "local_usize",
            "local_name_len",
            "local_extra_len",
        )
    )
    if field_name in {"central_sig", "local_sig"}:
        value = rng.choice((0, CD_SIG + 1, LFH_SIG + 1))
    elif field_name in {
        "crc",
        "csize",
        "usize",
        "ext_attr",
        "lho",
        "local_crc",
        "local_csize",
        "local_usize",
    }:
        value = rng.choice((0, 1, 0xFFFF, 0xFFFFFFFF, rng.randint(0, 1 << 20)))
    elif field_name in {"method", "local_method"}:
        value = rng.choice((0, 8, 12, 99))
    elif field_name in {"flags", "local_flags"}:
        value = rng.choice((1, 0x40, 0x800, 8))
    else:
        value = rng.choice((0, 1, 2, 0xFFFF, rng.randint(0, 300)))
    return replace(entry, **{field_name: value})


def _precedence_archive(rng: random.Random) -> tuple[str, bytes]:
    """Combine a known early archive fault with later record/local faults."""
    entry = replace(_fuzz_entry(rng), local_sig=LFH_SIG + 1)
    for _ in range(rng.randint(1, 3)):
        entry = _random_entry_lie(rng, entry)
    archive = Archive(entries=[entry])
    early = rng.choice(("s02", "s03", "s04", "s05", "s06", "s08"))
    if early == "s02":
        archive = replace(archive, eocd_sig=EOCD_SIG + 1)
    elif early == "s03":
        archive = replace(archive, eocd_comment_len=1)
    elif early == "s04":
        archive = replace(archive, disk_no=1)
    elif early == "s05":
        archive = replace(archive, zip64_locator=True)
    elif early == "s06":
        archive = replace(archive, n_disk=0)
    else:
        archive = replace(archive, size_cd=0)
    return early, build(archive)


def _raw_mutation_archive(rng: random.Random) -> bytes:
    """Mutate serialized bytes without classifying the resulting failure."""
    entries = [_fuzz_entry(rng, index=index) for index in range(rng.randint(0, 4))]
    raw = bytearray(build(Archive(entries=entries)))
    for _ in range(rng.randint(1, 4)):
        if raw:
            raw[rng.randrange(len(raw))] ^= rng.randint(1, 0xFF)
    if rng.random() < 0.25:
        raw[:0] = b"\x00" * rng.randint(1, 16)
    if rng.random() < 0.25:
        raw += b"\x00" * rng.randint(1, 8)
    if rng.random() < 0.15 and len(raw) > 4:
        del raw[rng.randrange(len(raw)) :]
    return bytes(raw)


def write_fuzz(out: Path, count: int, seed: int) -> None:
    """Write a balanced, reproducible stream of differential inputs."""
    out.mkdir(parents=True, exist_ok=True)
    # Not a security primitive: a reproducible stream of hostile shapes.
    rng = random.Random(seed)  # noqa: S311
    for index in range(count):
        stratum = FUZZ_STRATA[index % len(FUZZ_STRATA)]
        if stratum == "single":
            target = FUZZ_SINGLE_STEPS[(index // len(FUZZ_STRATA)) % len(FUZZ_SINGLE_STEPS)]
            raw = _single_lie_archive(rng, target)
            name = f"single-{target}-fuzz-{index:05d}.zip"
        elif stratum == "precedence":
            target, raw = _precedence_archive(rng)
            name = f"precedence-{target}-fuzz-{index:05d}.zip"
        elif stratum == "raw":
            raw = _raw_mutation_archive(rng)
            name = f"raw-fuzz-{index:05d}.zip"
        else:
            raw = build(
                Archive(entries=[_fuzz_entry(rng, index=i) for i in range(rng.randint(0, 4))])
            )
            name = f"honest-fuzz-{index:05d}.zip"
        (out / name).write_bytes(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out", type=Path, default=Path("tests/container-corpus"))
    parser.add_argument("--check", action="store_true", help="fail on any drift from --out")
    parser.add_argument("--fuzz", type=int, default=0, metavar="N")
    parser.add_argument("--seed", type=int, default=20260902)
    args = parser.parse_args(argv)

    if args.check:
        return check_corpus(args.out)
    if args.fuzz:
        write_fuzz(args.out, args.fuzz, args.seed)
        return 0
    if args.out.exists():
        shutil.rmtree(args.out)
    write_corpus(args.out)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
