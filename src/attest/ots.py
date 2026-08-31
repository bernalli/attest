"""Parser for detached OpenTimestamps proof files.

The parser is intentionally pure: it accepts bytes, performs no I/O or network
access, and returns a typed immutable view of each timestamp leaf. Malformed
input raises `OtsError` with a message tied to the violated wire rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

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
# before leaf/op caps are reached.
_MAX_NODES: Final = 4096
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

_ATTESTATION_KINDS: Final[dict[bytes, str]] = {
    bytes.fromhex("0588960d73d71901"): "bitcoin",
    bytes.fromhex("83dfe30d2ef90c8e"): "pending",
    bytes.fromhex("06869a0d73d71b45"): "litecoin",
    bytes.fromhex("30fe8087b5c7ead7"): "ethereum",
}
_BITCOIN_ATTESTATION_TAG: Final = bytes.fromhex("0588960d73d71901")


class OtsError(ValueError):
    """A detached OpenTimestamps file violates the supported wire profile."""


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


class _Reader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    @property
    def offset(self) -> int:
        return self._offset

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

    @property
    def offset(self) -> int:
        return self._reader.offset

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
        digest_length = _DIGEST_LENGTHS[file_hash_op]
        file_digest = self._reader.read_exact(digest_length, f"{file_hash_op} file digest")
        if file_hash_op != "sha256":
            raise OtsError(f"unsupported file hash op {file_hash_op} at offset {file_op_offset}")

        paths = self._parse_tree((), 0, 0)
        if self._reader.offset != len(self._reader._data):
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
        payload_offset = self._reader.offset
        payload = self._reader.read_varbytes("attestation payload")
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
    if len(data) > _MAX_OTS_FILE_BYTES:
        raise OtsError(f"ots file exceeds {_MAX_OTS_FILE_BYTES} bytes")
    return _Parser(data).parse()
