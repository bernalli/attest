"""Parser for detached OpenTimestamps proof files.

The parser is intentionally pure: it accepts bytes, performs no I/O or network
access, and returns a typed immutable view of each timestamp leaf. Malformed
input raises `OtsError` with a message tied to the violated wire rule.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from attest import anchor

_MAGIC: Final = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
_VERSION: Final = 0x01
_MAX_UINT64: Final = (1 << 64) - 1
# Real detached `.ots` examples measured for V-H.7 were below 20KB; this keeps
# hostile parser input bounded well before any tree materialization.
_MAX_OTS_FILE_BYTES: Final = 1_000_000
# Depth counts nested forks, not op-chain length: real paths can carry 100 ops,
# while fork depth is attacker-controlled structure that must not recurse open-ended.
_MAX_DEPTH: Final = 64
# Bound total tree dispatches so a wide timestamp cannot force unbounded work
# before leaf/op caps are reached. Sized so the two caps around it stay
# REACHABLE: `_MAX_LEAVES` paths of the longest real op-chain measured for
# these caps -- 100 ops, the largest real Bitcoin path recorded in `anchor.py`'s
# own cap-sizing comment, a measurement with no symbol of its own and NOT
# `anchor._MAX_OPS_PER_PROOF`, which is the structural cap at 256 -- cost
# `_MAX_LEAVES * (100 + 2)` dispatches counting each leaf's fork marker and
# attestation. At 4096 the node cap bound before them instead, admitting only
# 40 leaves at that length -- below the 64 proofs `anchor` accepts per
# evidence, so real multi-calendar material was refused by the wrong cap and
# named the wrong reason.
_MAX_NODES: Final = 26_112
# Conversion emits one proof per leaf; cap leaves at the same scale as the
# downstream per-evidence proof ceiling plus explicit headroom for skipped paths.
_MAX_LEAVES: Final = 256
_MAX_OPS_PER_PROOF: Final = anchor._MAX_OPS_PER_PROOF
_MAX_OP_HEX_LEN: Final = anchor._MAX_OP_HEX_LEN
_MAX_TOTAL_OP_HEX_LEN: Final = anchor._MAX_TOTAL_OP_HEX_LEN

_TAG_ATTESTATION: Final = 0x00
_TAG_FORK: Final = 0xFF

_OPS_WITHOUT_OPERANDS: Final[dict[int, str]] = {
    0x02: "sha1",
    0x03: "ripemd160",
    0x08: "sha256",
    0x67: "keccak256",
    0xF2: "reverse",
    0xF3: "hexlify",
}
_OPS_WITH_OPERANDS: Final[dict[int, str]] = {
    0xF0: "append",
    0xF1: "prepend",
}
_DIGEST_LENGTHS: Final[dict[str, int]] = {
    "sha1": 20,
    "ripemd160": 20,
    "sha256": 32,
    "keccak256": 32,
}
_PATH_OPS: Final = frozenset({"append", "prepend", "sha256"})
_HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")

_ATTESTATION_KINDS: Final[dict[bytes, str]] = {
    bytes.fromhex("0588960d73d71901"): "bitcoin",
    bytes.fromhex("83dfe30d2ef90c8e"): "pending",
    bytes.fromhex("06869a0d73d71b45"): "litecoin",
    bytes.fromhex("30fe8087b5c7ead7"): "ethereum",
}
_BITCOIN_ATTESTATION_TAG: Final = bytes.fromhex("0588960d73d71901")


class OtsError(ValueError):
    """A detached OpenTimestamps file violates the supported wire profile."""


class OtsConversionError(OtsError):
    """No OpenTimestamps path could be converted into an anchor proof."""

    def __init__(self, message: str, report: tuple[OtsConversionReportEntry, ...]) -> None:
        super().__init__(message)
        self.report = report


@dataclass(frozen=True)
class OtsOp:
    """One operation on the accumulator along a timestamp leaf path."""

    name: str
    operand: bytes | None = None


@dataclass(frozen=True)
class OtsAttestation:
    """A leaf attestation carried by a detached OpenTimestamps file."""

    kind: str
    tag: bytes
    payload: bytes
    height: int | None = None


@dataclass(frozen=True)
class OtsPath:
    """One immutable path from the file digest to a leaf attestation."""

    ops: tuple[OtsOp, ...]
    attestation: OtsAttestation


@dataclass(frozen=True)
class OtsFile:
    """The parsed contents of a detached OpenTimestamps proof file."""

    file_digest: bytes
    file_hash_op: str
    paths: tuple[OtsPath, ...]


@dataclass(frozen=True)
class OperatorHeader:
    """Bitcoin block header facts supplied by the operator's own node."""

    height: int
    header_hash: str
    merkle_root: str
    time: int


@dataclass(frozen=True)
class ConvertedOtsProof:
    """One converted OTS path in the JSON shape accepted by `log anchor`."""

    path_index: int
    height: int
    proof: dict[str, Any]


@dataclass(frozen=True)
class OtsConversionReportEntry:
    """Report row for one parsed OTS path, converted or skipped."""

    path_index: int
    attestation_kind: str
    attestation_tag: str
    height: int | None
    converted: bool
    reason: str | None


@dataclass(frozen=True)
class ConversionResult:
    """Converted anchor proofs plus the mandatory per-path conversion report."""

    proofs: tuple[ConvertedOtsProof, ...]
    report: tuple[OtsConversionReportEntry, ...]
    pinned_headers: dict[str, dict[str, Any]]


class _Reader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def at_end(self) -> bool:
        return self._offset == len(self._data)

    def read_u8(self, context: str) -> int:
        if self._offset >= len(self._data):
            raise OtsError(f"truncated ots file at offset {self._offset}: expected {context}")
        value = self._data[self._offset]
        self._offset += 1
        return value

    def read_exact(self, length: int, context: str) -> bytes:
        start = self._offset
        end = start + length
        if end > len(self._data):
            remaining = len(self._data) - start
            raise OtsError(
                f"truncated ots file at offset {start}: expected {length} bytes for "
                f"{context}, found {remaining}"
            )
        self._offset = end
        return self._data[start:end]

    def read_varuint(self, context: str) -> int:
        start = self._offset
        value = 0
        shift = 0
        for byte_index in range(10):
            if self._offset >= len(self._data):
                raise OtsError(f"{context} varint not terminated at offset {start}")
            byte = self._data[self._offset]
            self._offset += 1
            value |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                if byte_index > 0 and value < (1 << (7 * byte_index)):
                    raise OtsError(f"{context} varint is non-minimal at offset {start}")
                if value > _MAX_UINT64:
                    raise OtsError(f"{context} varint exceeds 64 bits at offset {start}")
                return value
            shift += 7
        raise OtsError(f"{context} varint exceeds 64 bits at offset {start}")

    def read_varbytes(self, context: str) -> bytes:
        start = self._offset
        length = self.read_varuint(f"{context} length")
        if length > len(self._data) - self._offset:
            remaining = len(self._data) - self._offset
            raise OtsError(
                f"{context} varbytes at offset {start} declares {length} bytes, "
                f"but only {remaining} remain"
            )
        return self.read_exact(length, context)


class _Parser:
    def __init__(self, data: bytes) -> None:
        self._reader = _Reader(data)
        self._nodes = 0
        self._leaves = 0

    def parse(self) -> OtsFile:
        magic = self._reader.read_exact(len(_MAGIC), "OpenTimestamps magic")
        if magic != _MAGIC:
            raise OtsError("invalid OpenTimestamps magic at offset 0")

        version_offset = self._reader.offset
        version = self._reader.read_u8("OpenTimestamps major version")
        if version != _VERSION:
            raise OtsError(
                f"unsupported OpenTimestamps version 0x{version:02x} at offset {version_offset}"
            )

        file_op_offset = self._reader.offset
        file_hash_op = self._read_file_hash_op()
        if file_hash_op != "sha256":
            raise OtsError(f"unsupported file hash op {file_hash_op} at offset {file_op_offset}")
        file_digest = self._reader.read_exact(
            _DIGEST_LENGTHS[file_hash_op], f"{file_hash_op} file digest"
        )

        paths = self._parse_tree((), 0, 0)
        if not self._reader.at_end:
            raise OtsError(f"trailing bytes after ots tree at offset {self._reader.offset}")
        return OtsFile(file_digest=file_digest, file_hash_op=file_hash_op, paths=paths)

    def _read_file_hash_op(self) -> str:
        offset = self._reader.offset
        tag = self._reader.read_u8("file hash op tag")
        name = _OPS_WITHOUT_OPERANDS.get(tag)
        if name is None:
            if tag in _OPS_WITH_OPERANDS:
                name = _OPS_WITH_OPERANDS[tag]
            else:
                raise OtsError(f"unknown file hash op tag 0x{tag:02x} at offset {offset}")
        if name not in _DIGEST_LENGTHS:
            raise OtsError(f"unsupported file hash op {name} at offset {offset}")
        return name

    def _parse_tree(
        self, ops: tuple[OtsOp, ...], depth: int, total_operand_hex: int
    ) -> tuple[OtsPath, ...]:
        if depth > _MAX_DEPTH:
            raise OtsError(
                f"ots tree exceeds maximum depth {_MAX_DEPTH} at offset {self._reader.offset}"
            )
        paths: list[OtsPath] = []
        current_ops = ops
        current_total_operand_hex = total_operand_hex
        while True:
            offset = self._reader.offset
            tag = self._reader.read_u8("timestamp item")
            self._count_node(offset)
            if tag == _TAG_FORK:
                paths.extend(self._parse_tree(current_ops, depth + 1, current_total_operand_hex))
                continue
            if tag == _TAG_ATTESTATION:
                self._count_leaf(offset)
                paths.append(OtsPath(ops=current_ops, attestation=self._read_attestation()))
                return tuple(paths)

            op = self._read_path_op(tag, offset)
            if op.operand is not None:
                operand_hex_len = len(op.operand) * 2
                if operand_hex_len > _MAX_OP_HEX_LEN:
                    raise OtsError(
                        f"{op.name} operand exceeds {_MAX_OP_HEX_LEN} hex chars at offset {offset}"
                    )
                current_total_operand_hex += operand_hex_len
                if current_total_operand_hex > _MAX_TOTAL_OP_HEX_LEN:
                    message = (
                        f"ots path operands exceed {_MAX_TOTAL_OP_HEX_LEN} "
                        f"total hex chars at offset {offset}"
                    )
                    raise OtsError(message)
            current_ops = (*current_ops, op)
            if len(current_ops) > _MAX_OPS_PER_PROOF:
                raise OtsError(
                    f"ots path has more than {_MAX_OPS_PER_PROOF} ops at offset {offset}"
                )

    def _read_path_op(self, tag: int, offset: int) -> OtsOp:
        if tag in _OPS_WITH_OPERANDS:
            name = _OPS_WITH_OPERANDS[tag]
            operand = self._reader.read_varbytes(f"{name} operand")
        elif tag in _OPS_WITHOUT_OPERANDS:
            name = _OPS_WITHOUT_OPERANDS[tag]
            operand = None
        else:
            raise OtsError(f"unknown ots op tag 0x{tag:02x} at offset {offset}")

        if name not in _PATH_OPS:
            raise OtsError(f"unsupported ots op {name} at offset {offset}")
        return OtsOp(name=name, operand=operand)

    def _read_attestation(self) -> OtsAttestation:
        tag = self._reader.read_exact(8, "attestation tag")
        payload = self._reader.read_varbytes("attestation payload")
        payload_offset = self._reader.offset - len(payload)
        kind = _ATTESTATION_KINDS.get(tag, "unknown")
        if tag == _BITCOIN_ATTESTATION_TAG:
            height = _decode_bitcoin_height(payload, payload_offset)
        else:
            height = None
        return OtsAttestation(kind=kind, tag=tag, payload=payload, height=height)

    def _count_node(self, offset: int) -> None:
        self._nodes += 1
        if self._nodes > _MAX_NODES:
            raise OtsError(f"ots tree has more than {_MAX_NODES} nodes at offset {offset}")

    def _count_leaf(self, offset: int) -> None:
        self._leaves += 1
        if self._leaves > _MAX_LEAVES:
            raise OtsError(f"ots tree has more than {_MAX_LEAVES} leaves at offset {offset}")


def _decode_bitcoin_height(payload: bytes, payload_offset: int) -> int:
    reader = _Reader(payload)
    try:
        height = reader.read_varuint("bitcoin attestation height")
    except OtsError as exc:
        raise OtsError(f"{exc} in payload starting at offset {payload_offset}") from exc
    if reader.offset != len(payload):
        trailing_offset = payload_offset + reader.offset
        raise OtsError(
            f"bitcoin attestation payload has trailing bytes at offset {trailing_offset}"
        )
    return height


def parse_ots(data: bytes) -> OtsFile:
    """Parse a detached OpenTimestamps file into immutable path objects."""

    if not isinstance(data, bytes):
        raise OtsError("ots input must be bytes")
    # Copy through `bytes` BEFORE any cap decision: a `bytes` subclass may
    # override `__len__`/`__getitem__`, so every size and index below would
    # otherwise be the subclass's answer rather than the file's.
    data = bytes(data)
    if len(data) > _MAX_OTS_FILE_BYTES:
        raise OtsError(f"ots file exceeds {_MAX_OTS_FILE_BYTES} bytes")
    return _Parser(data).parse()


def _copy_digest(value: object, *, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise OtsError(f"{label} must be bytes")
    digest = bytes(value)
    if len(digest) != 32:
        raise OtsError(f"{label} must be a SHA-256 digest")
    return digest


def _validate_operator_headers(headers: Sequence[OperatorHeader]) -> dict[int, OperatorHeader]:
    if not isinstance(headers, Sequence) or isinstance(headers, (bytes, str)):
        raise OtsError("operator headers must be a sequence")

    by_height: dict[int, OperatorHeader] = {}
    seen_heights: set[int] = set()
    seen_hashes: set[str] = set()
    for index, header in enumerate(headers):
        if not isinstance(header, OperatorHeader):
            raise OtsError(f"operator header {index} must be an OperatorHeader")
        if (
            not isinstance(header.height, int)
            or isinstance(header.height, bool)
            or header.height < 0
        ):
            raise OtsError(f"operator header {index} height must be a non-negative int")
        if header.height in seen_heights:
            raise OtsError(f"duplicate operator header height {header.height}")
        seen_heights.add(header.height)

        if not isinstance(header.header_hash, str) or not _HEX64_RE.fullmatch(header.header_hash):
            raise OtsError(f"operator header {index} header_hash must be 64 lowercase hex chars")
        if header.header_hash in seen_hashes:
            raise OtsError(f"duplicate operator header hash {header.header_hash}")
        seen_hashes.add(header.header_hash)

        if not isinstance(header.merkle_root, str) or not _HEX64_RE.fullmatch(header.merkle_root):
            raise OtsError(f"operator header {index} merkle_root must be 64 lowercase hex chars")
        if (
            not isinstance(header.time, int)
            or isinstance(header.time, bool)
            or not 0 < header.time <= anchor._MAX_RENDERABLE_UNIX_TIME
        ):
            raise OtsError(
                "operator header "
                f"{index} time must be a positive int no later than "
                f"{anchor._MAX_RENDERABLE_UNIX_TIME}"
            )

        by_height[header.height] = header
    return by_height


def _skip_report(path_index: int, path: OtsPath, reason: str) -> OtsConversionReportEntry:
    return OtsConversionReportEntry(
        path_index=path_index,
        attestation_kind=path.attestation.kind,
        attestation_tag=path.attestation.tag.hex(),
        height=path.attestation.height,
        converted=False,
        reason=reason,
    )


def _converted_report(path_index: int, path: OtsPath) -> OtsConversionReportEntry:
    return OtsConversionReportEntry(
        path_index=path_index,
        attestation_kind=path.attestation.kind,
        attestation_tag=path.attestation.tag.hex(),
        height=path.attestation.height,
        converted=True,
        reason=None,
    )


def _translate_path_ops(path: OtsPath, *, height: int) -> tuple[list[list[str]] | None, str | None]:
    converted: list[list[str]] = []
    for op in path.ops:
        if op.name == "sha256":
            if op.operand is not None:
                return None, f"sha256 op carries an operand on Bitcoin height {height}"
            converted.append(["sha256"])
            continue
        if op.name in {"append", "prepend"}:
            if not isinstance(op.operand, bytes):
                return None, f"{op.name} op lacks a bytes operand on Bitcoin height {height}"
            converted.append([op.name, bytes(op.operand).hex()])
            continue
        return None, f"unsupported ots op {op.name} on Bitcoin height {height}"
    return converted, None


def _non_bitcoin_skip_reason(attestation: OtsAttestation) -> str:
    if attestation.kind == "pending":
        return "pending attestation is not upgraded yet; run `ots upgrade` first"
    return f"unsupported attestation kind {attestation.kind} tag {attestation.tag.hex()}"


def _zero_survivors_message(report: tuple[OtsConversionReportEntry, ...]) -> str:
    reasons = "; ".join(
        f"path {entry.path_index}: {entry.reason}"
        for entry in report
        if not entry.converted and entry.reason is not None
    )
    return f"no convertible Bitcoin paths found: {reasons}"


def convert_ots(
    parsed: OtsFile, expected_seed: bytes, headers: Sequence[OperatorHeader]
) -> ConversionResult:
    """Convert parsed detached OTS paths into signed-note-v2 anchor proofs.

    `expected_seed` is `SHA256(checkpoint.signed_note_bytes)` from the
    evidence produced by `log prove`; the parsed `.ots` file digest must match
    that seed before any path is considered. Each returned proof is already in
    the JSON object shape accepted by `attest log anchor --ots-proof`.
    """

    if not isinstance(parsed, OtsFile):
        raise OtsError("convert_ots requires OtsFile parsed by parse_ots")
    expected_seed = _copy_digest(expected_seed, label="expected_seed")
    file_digest = _copy_digest(parsed.file_digest, label="ots file digest")
    if parsed.file_hash_op != "sha256":
        raise OtsError(f"ots file hash op {parsed.file_hash_op} is not sha256")
    if not hmac.compare_digest(file_digest, expected_seed):
        raise OtsError(
            "ots file digest "
            f"{file_digest.hex()} does not match expected "
            f"SHA256(signed_note_bytes) {expected_seed.hex()}"
        )

    headers_by_height = _validate_operator_headers(headers)
    proofs: list[ConvertedOtsProof] = []
    report: list[OtsConversionReportEntry] = []
    pinned_headers: dict[str, dict[str, Any]] = {}

    for path_index, path in enumerate(parsed.paths):
        if path.attestation.kind != "bitcoin":
            report.append(
                _skip_report(path_index, path, _non_bitcoin_skip_reason(path.attestation))
            )
            continue
        height = path.attestation.height
        if not isinstance(height, int) or isinstance(height, bool):
            report.append(
                _skip_report(
                    path_index,
                    path,
                    "bitcoin attestation has no usable block height",
                )
            )
            continue

        proof_ops, reason = _translate_path_ops(path, height=height)
        if reason is not None:
            report.append(_skip_report(path_index, path, reason))
            continue
        assert proof_ops is not None

        header = headers_by_height.get(height)
        if header is None:
            report.append(
                _skip_report(
                    path_index, path, f"missing operator header for Bitcoin height {height}"
                )
            )
            continue

        accumulator, warning = anchor.replay_ots_op_chain(expected_seed, proof_ops)
        if warning is not None:
            report.append(_skip_report(path_index, path, f"{warning} on Bitcoin height {height}"))
            continue
        assert accumulator is not None
        if not hmac.compare_digest(accumulator.hex(), header.merkle_root):
            reason = (
                f"operator header merkle_root does not match OTS replay at Bitcoin height {height}"
            )
            report.append(
                _skip_report(
                    path_index,
                    path,
                    reason,
                )
            )
            continue

        proof = {
            "ops": proof_ops,
            "header_merkle_root": header.merkle_root,
            "header_hash": header.header_hash,
            "header_time": header.time,
        }
        proofs.append(ConvertedOtsProof(path_index=path_index, height=height, proof=proof))
        pinned_headers[header.header_hash] = {
            "header_hash": header.header_hash,
            "merkle_root": header.merkle_root,
            "time": header.time,
        }
        report.append(_converted_report(path_index, path))

    frozen_report = tuple(report)
    if not proofs:
        raise OtsConversionError(_zero_survivors_message(frozen_report), frozen_report)
    return ConversionResult(
        proofs=tuple(proofs),
        report=frozen_report,
        pinned_headers=pinned_headers,
    )
