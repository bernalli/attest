"""One canonical reading of a `.attest` container (v0.1 §14.1).

A `.attest` file is a ZIP archive, and "which members does this archive hold"
has more than one answer. Two widely used readers address the central directory
differently: one takes the end-of-central-directory record's declared offset
literally and iterates its 16-bit entry counter; the other ignores both and
places the directory immediately before that record. An archive can therefore
present one member list to one conforming verifier and a different member list
to another — same bytes, two receipts — and no guard built on top of either
reader can see it, because each reader measures the archive in its own model.

This module removes the choice of model instead of picking one. It reads the
container itself, in a fixed order, and refuses every archive in which the two
models could disagree: the end-of-central-directory record must be the last 22
bytes and declare no comment, the archive must be single-disk and free of ZIP64
structures, the two entry counters must agree, and the central directory must
occupy exactly the bytes ending where that record begins. Inside the directory
the walk is exact, and every record must be backed by a local file header that
names the same member and by data that lies before the directory.

The canonical form is not a new restriction on honest producers: every archive
this project writes or ships is already inside it. What it forbids is precisely
the class of file that could be read two ways.

`site/src/container.ts` is the same algorithm, step for step, with the same
codes and the same messages: the `# S1` … `# S23` comments here and the `// S1`
… `// S23` comments there mark the correspondence, and the shared corpus in
`tests/container-corpus/` is what keeps the two honest.
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Buffer
from dataclasses import dataclass

from attest import deflate

#: Slice of compressed input fed to the decoder at a time. Identical on both
#: sides so the worst burst before a cap fires is the same in both languages.
INFLATE_SLICE = 65536

_LFH_SIG = 0x04034B50
_CD_SIG = 0x02014B50
_EOCD_SIG = 0x06054B50
_ZIP64_LOCATOR_SIG = 0x07064B50
_EOCD_SIZE = 22
_CD_FIXED = 46
_LFH_FIXED = 30
_ZIP64_LOCATOR_SIZE = 20
_U16_SENTINEL = 0xFFFF
_U32_SENTINEL = 0xFFFFFFFF

#: The closed error taxonomy, in the order the reader checks for it.
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

#: Message per code. A message never carries attacker-supplied text: the member
#: name travels as a structured field, and the wrapping layer decides how to
#: render it (these strings reach a buyer's screen verbatim).
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


class ContainerError(Exception):
    """An archive outside the canonical form, or a member that fails its own
    directory record. `code` is one of `CODES`; `member` is the decoded member
    name when the fault belongs to one, `None` when it belongs to the file."""

    def __init__(self, code: str, member: str | None = None, *, max_entries: int | None = None):
        message = MESSAGES[code]
        if max_entries is not None:
            message = message.replace("{max_entries}", str(max_entries))
        super().__init__(message)
        self.code = code
        self.member = member


@dataclass(frozen=True, slots=True)
class Member:
    """One member, as the central directory declares it. `data_start` is where
    its bytes begin; nothing else from the record is kept, and `extra` is
    skipped by length and never parsed."""

    name: str
    method: int
    crc32: int
    compressed_size: int
    uncompressed_size: int
    data_start: int


class ReadBudget:
    """The decompression budget for one import. Shared across every member and,
    in the reference importer, across a `.attest` and its `.private.attest`
    sibling, so a hostile pair cannot each spend the aggregate cap."""

    __slots__ = ("max_member_bytes", "max_total_bytes", "spent")

    def __init__(self, max_member_bytes: int, max_total_bytes: int) -> None:
        self.max_member_bytes = max_member_bytes
        self.max_total_bytes = max_total_bytes
        self.spent = 0


def crc32(data: Buffer, value: int = 0) -> int:
    """CRC-32 of `data`, resumable through `value`. Named the same on both sides."""
    return zlib.crc32(data, value) & 0xFFFFFFFF


def _u16(buf: memoryview, offset: int) -> int:
    return int(struct.unpack_from("<H", buf, offset)[0])


def _u32(buf: memoryview, offset: int) -> int:
    return int(struct.unpack_from("<I", buf, offset)[0])


def canonical_members(
    buf: Buffer,
    *,
    max_entries: int,
    max_member_bytes: int,
    max_total_bytes: int,
) -> list[Member]:
    """The member list of `buf`, in central-directory order, or `ContainerError`.

    Every step below has a numbered twin in `site/src/container.ts`. The order
    is part of the contract: two readers that check the same things in a
    different order can still disagree about WHICH complaint an archive earns,
    and a corpus that pins codes would then be unshareable between them.
    """
    # The view is released on every path, exception included: when the buffer
    # is a memory-mapped file, an export still alive in a traceback frame keeps
    # the mapping from closing, and the caller's refusal turns into a
    # BufferError about bookkeeping.
    with memoryview(buf).cast("B") as view:
        return _canonical_members(view, max_entries, max_member_bytes, max_total_bytes)


def _canonical_members(
    view: memoryview, max_entries: int, max_member_bytes: int, max_total_bytes: int
) -> list[Member]:
    length = len(view)

    # S1
    if length < _EOCD_SIZE:
        raise ContainerError("too-short")
    eocd = length - _EOCD_SIZE
    # S2
    if _u32(view, eocd) != _EOCD_SIG:
        raise ContainerError("eocd-not-last")
    disk_no = _u16(view, eocd + 4)
    cd_disk = _u16(view, eocd + 6)
    n_disk = _u16(view, eocd + 8)
    n_total = _u16(view, eocd + 10)
    size_cd = _u32(view, eocd + 12)
    off_cd = _u32(view, eocd + 16)
    comment_len = _u16(view, eocd + 20)
    # S3
    if comment_len != 0:
        raise ContainerError("eocd-comment-length")
    # S4
    if disk_no != 0 or cd_disk != 0:
        raise ContainerError("multi-disk")
    # S5 — ZIP64 on presence OR on sentinel: one reader enters it on the
    # locator alone, the other on the sentinel values, so the canonical form
    # refuses both rather than choose which reader is right.
    if (
        length >= _EOCD_SIZE + _ZIP64_LOCATOR_SIZE
        and _u32(view, length - _EOCD_SIZE - _ZIP64_LOCATOR_SIZE) == _ZIP64_LOCATOR_SIG
    ):
        raise ContainerError("zip64")
    if (
        n_disk == _U16_SENTINEL
        or n_total == _U16_SENTINEL
        or size_cd == _U32_SENTINEL
        or off_cd == _U32_SENTINEL
    ):
        raise ContainerError("zip64")
    # S6
    if n_disk != n_total:
        raise ContainerError("entry-counters-disagree")
    # S7 — before any walking, so the cap bounds the work: this is what makes
    # the entry cap a real pre-read gate on both sides.
    if n_total > max_entries:
        raise ContainerError("too-many-entries", max_entries=max_entries)
    # S8 — the line that refuses a file carrying two valid directories: the
    # directory must END where the end-of-central-directory record begins.
    if off_cd + size_cd != eocd:
        raise ContainerError("directory-misplaced")

    # S9
    position = off_cd
    end = eocd
    seen: set[str] = set()
    declared_total = 0
    members: list[Member] = []
    for _ in range(n_total):
        if end - position < _CD_FIXED or _u32(view, position) != _CD_SIG:
            raise ContainerError("directory-record-signature")
        flags = _u16(view, position + 8)
        method = _u16(view, position + 10)
        crc = _u32(view, position + 16)
        csize = _u32(view, position + 20)
        usize = _u32(view, position + 24)
        name_len = _u16(view, position + 28)
        extra_len = _u16(view, position + 30)
        record_comment_len = _u16(view, position + 32)
        disk_start = _u16(view, position + 34)
        lho = _u32(view, position + 42)
        record_end = position + _CD_FIXED + name_len + extra_len + record_comment_len
        if record_end > end:
            raise ContainerError("directory-record-overrun")

        # S10
        if record_comment_len != 0:
            raise ContainerError("record-comment")
        # S11
        if disk_start != 0:
            raise ContainerError("record-multi-disk")
        # S12
        if flags & 0x0001 or flags & 0x0040:
            raise ContainerError("record-encrypted")
        # S13
        if method not in (0, 8):
            raise ContainerError("record-method")
        # S14
        if csize == _U32_SENTINEL or usize == _U32_SENTINEL or lho == _U32_SENTINEL:
            raise ContainerError("record-zip64")
        # S15
        if name_len == 0:
            raise ContainerError("record-name-empty")
        # S16 — no path grammar here: `..`, a leading slash, a NUL and
        # `__proto__` are member names like any other at this level. The member
        # families own their own grammar, and the reference importer's hostile
        # proof-path tests depend on this layer not pre-empting them.
        name_bytes = bytes(view[position + _CD_FIXED : position + _CD_FIXED + name_len])
        if any(byte >= 0x80 for byte in name_bytes) and not flags & 0x0800:
            raise ContainerError("record-name-encoding")
        try:
            name = name_bytes.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise ContainerError("record-name-encoding") from None
        # S17
        if name in seen:
            raise ContainerError("duplicate-name", name)
        seen.add(name)
        # S18
        if method == 0 and csize != usize:
            raise ContainerError("record-stored-size", name)
        # S19
        if lho + _LFH_FIXED > off_cd:
            raise ContainerError("local-header-out-of-range", name)
        # S20
        if _u32(view, lho) != _LFH_SIG:
            raise ContainerError("local-header-signature", name)
        # S21
        local_name_len = _u16(view, lho + 26)
        local_extra_len = _u16(view, lho + 28)
        data_start = lho + _LFH_FIXED + local_name_len + local_extra_len
        if data_start > off_cd:
            raise ContainerError("local-header-out-of-range", name)
        local_name = bytes(view[lho + _LFH_FIXED : lho + _LFH_FIXED + local_name_len])
        if local_name_len != name_len or local_name != name_bytes:
            raise ContainerError("local-name-mismatch", name)
        # S22
        if data_start + csize > off_cd:
            raise ContainerError("member-data-out-of-range", name)
        # S23 — declared sizes can lie low, and the streamed count below is what
        # catches that; these two gates catch the archive that is honestly huge.
        if usize > max_member_bytes:
            raise ContainerError("declared-member-over-cap", name)
        declared_total += usize
        if declared_total > max_total_bytes:
            raise ContainerError("declared-total-over-cap", name)

        members.append(
            Member(
                name=name,
                method=method,
                crc32=crc,
                compressed_size=csize,
                uncompressed_size=usize,
                data_start=data_start,
            )
        )
        position = record_end

    if position != end:
        raise ContainerError("directory-trailing-bytes")
    return members


def read_member(buf: Buffer, member: Member, budget: ReadBudget) -> bytes:
    """The bytes of `member`, under `budget`, verified against its record.

    The streamed length — not the declared one — is authoritative, which is what
    catches a header that lies low about a bomb; the CRC-32 is what catches
    bytes that were replaced after the archive was written.
    """
    with memoryview(buf).cast("B") as view:
        return _read_member(view, member, budget)


def _read_member(view: memoryview, member: Member, budget: ReadBudget) -> bytes:
    got = 0

    def count(produced: int) -> None:
        nonlocal got
        got += produced
        if got > budget.max_member_bytes:
            raise ContainerError("member-over-cap", member.name)
        if budget.spent + got > budget.max_total_bytes:
            raise ContainerError("total-over-cap", member.name)

    start = member.data_start
    stop = start + member.compressed_size
    if member.method == 0:
        out = bytes(view[start:stop])
        count(len(out))
    else:
        # An empty payload is the one input on which the two decoders disagree
        # by default: one reports a stream that never reached its final block,
        # the other reports nothing at all. Both readers name it here rather
        # than let each library's silence decide (measured 2026-09-02).
        if member.compressed_size == 0:
            raise ContainerError("member-inflate-error", member.name)
        # The stream is validated here, against the format, rather than by
        # whichever library is doing the decompressing: the two libraries were
        # measured refusing different streams (see `deflate`).
        if deflate.deflate_error(view[start:stop], budget.max_member_bytes) is not None:
            raise ContainerError("member-inflate-error", member.name)
        # A limit measured and left open (2026-09-02): the two decoders do not
        # hand back the same number of bytes at the same input offset — one
        # returns everything decoded so far, the other only completed blocks —
        # so a stream that is BOTH over the cap and invalid can earn
        # `member-over-cap` on one side and `member-inflate-error` on the other.
        # Both refuse it; the codes differ. Closing that means deciding the cap
        # on the length the validator above computes rather than on what each
        # decoder has produced, which is a change to the shared algorithm and
        # not to this file.
        decompressor = zlib.decompressobj(-15)
        chunks: list[bytes] = []
        position = start
        while position < stop:
            slice_end = min(position + INFLATE_SLICE, stop)
            try:
                produced = decompressor.decompress(bytes(view[position:slice_end]))
            except zlib.error:
                raise ContainerError("member-inflate-error", member.name) from None
            count(len(produced))
            chunks.append(produced)
            position = slice_end
        # Trailing bytes inside the declared compressed size are ignored by both
        # decoders, so they are not inspected here: a check only one side can
        # perform would be a new divergence, not a defence.
        if not decompressor.eof:
            raise ContainerError("member-inflate-error", member.name)
        out = b"".join(chunks)

    if got != member.uncompressed_size:
        raise ContainerError("member-size-mismatch", member.name)
    if crc32(out) != member.crc32:
        raise ContainerError("member-crc-mismatch", member.name)
    budget.spent += got
    return out
