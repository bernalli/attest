"""Detached OpenTimestamps parser tests.

The positive fixture below is assembled byte-by-byte inside the test, not by
round-tripping through a generator. A generator with the same wire-format bug
as the parser would make a false agreement look like coverage.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from attest import anchor, ots

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
TAG_SHA256 = b"\x08"
TAG_APPEND = b"\xf0"
TAG_PREPEND = b"\xf1"
TAG_ATTESTATION = b"\x00"
TAG_FORK = b"\xff"
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_UNKNOWN_ATTESTATION = b"\x99\x88\x77\x66\x55\x44\x33\x22"


def _varuint(value: int) -> bytes:
    assert value >= 0
    encoded = bytearray()
    remaining = value
    while True:
        byte = remaining & 0x7F
        remaining >>= 7
        if remaining:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def _varbytes(value: bytes) -> bytes:
    return _varuint(len(value)) + value


def _attestation(tag: bytes, payload: bytes) -> bytes:
    return TAG_ATTESTATION + tag + _varbytes(payload)


def _bitcoin_attestation(height: int) -> bytes:
    return _attestation(TAG_BITCOIN, _varuint(height))


def _pending_attestation(payload: bytes = b"https://calendar.example/") -> bytes:
    return _attestation(TAG_PENDING, payload)


def _ots_with_tree(tree: bytes, *, digest: bytes = bytes(range(32))) -> bytes:
    return MAGIC + b"\x01" + TAG_SHA256 + digest + tree


def _valid_ots_bytes() -> bytes:
    return _ots_with_tree(
        b"".join(
            [
                TAG_FORK,
                TAG_APPEND,
                _varbytes(b"a"),
                TAG_SHA256,
                TAG_PREPEND,
                _varbytes(b"b"),
                TAG_SHA256,
                _bitcoin_attestation(42),
                TAG_FORK,
                TAG_PREPEND,
                _varbytes(b"c"),
                TAG_SHA256,
                TAG_APPEND,
                _varbytes(b"d"),
                TAG_SHA256,
                _bitcoin_attestation(43),
                TAG_APPEND,
                _varbytes(b"pending"),
                TAG_SHA256,
                _pending_attestation(),
            ]
        )
    )


def _nested_fork(depth: int) -> bytes:
    if depth == 0:
        return _pending_attestation(b"leaf")
    return TAG_FORK + _nested_fork(depth - 1) + _pending_attestation(b"sibling")


def _many_leaves(count: int, *, ops_per_leaf: int = 0) -> bytes:
    leaf = TAG_SHA256 * ops_per_leaf + _pending_attestation(b"leaf")
    return b"".join(TAG_FORK + leaf for _ in range(count - 1)) + leaf


def _duplicate_height_ots_bytes() -> bytes:
    return _ots_with_tree(
        b"".join(
            [
                TAG_FORK,
                TAG_APPEND,
                _varbytes(b"first"),
                TAG_SHA256,
                _bitcoin_attestation(42),
                TAG_PREPEND,
                _varbytes(b"second"),
                TAG_SHA256,
                _bitcoin_attestation(42),
            ]
        )
    )


@st.composite
def _mutated_ots_bytes(draw: st.DrawFn) -> bytes:
    base = _valid_ots_bytes()
    mutation = draw(st.sampled_from(["replace", "insert", "delete", "truncate"]))
    if mutation == "replace":
        offset = draw(st.integers(min_value=0, max_value=len(base) - 1))
        value = draw(st.integers(min_value=0, max_value=255))
        return base[:offset] + bytes([value]) + base[offset + 1 :]
    if mutation == "insert":
        offset = draw(st.integers(min_value=0, max_value=len(base)))
        payload = draw(st.binary(min_size=1, max_size=8))
        return base[:offset] + payload + base[offset:]
    if mutation == "delete":
        offset = draw(st.integers(min_value=0, max_value=len(base) - 1))
        width = draw(st.integers(min_value=1, max_value=8))
        return base[:offset] + base[offset + width :]
    end = draw(st.integers(min_value=0, max_value=len(base)))
    return base[:end]


def _assert_well_formed(parsed: ots.OtsFile) -> None:
    assert parsed.file_hash_op == "sha256"
    assert isinstance(parsed.file_digest, bytes)
    assert len(parsed.file_digest) == 32
    assert isinstance(parsed.paths, tuple)
    assert len(parsed.paths) <= 256
    for path in parsed.paths:
        assert isinstance(path.ops, tuple)
        assert len(path.ops) <= anchor._MAX_OPS_PER_PROOF
        total_operand_hex = 0
        for op in path.ops:
            assert op.name in {"append", "prepend", "sha256"}
            if op.name == "sha256":
                assert op.operand is None
            else:
                assert isinstance(op.operand, bytes)
                assert len(op.operand) * 2 <= anchor._MAX_OP_HEX_LEN
                total_operand_hex += len(op.operand) * 2
        assert total_operand_hex <= anchor._MAX_TOTAL_OP_HEX_LEN
        assert path.attestation.kind in {"bitcoin", "pending", "litecoin", "ethereum", "unknown"}
        assert isinstance(path.attestation.tag, bytes)
        assert len(path.attestation.tag) == 8
        assert isinstance(path.attestation.payload, bytes)
        if path.attestation.kind == "bitcoin":
            assert isinstance(path.attestation.height, int)
            assert not isinstance(path.attestation.height, bool)
        else:
            assert path.attestation.height is None


def test_parse_ots_minimal_detached_timestamp_preserves_leaf_walk_order() -> None:
    file_digest = bytes(range(32))

    data = b"".join(
        [
            # 31-byte OpenTimestamps detached-proof magic.
            MAGIC,
            # Raw major version byte, not a varint.
            b"\x01",
            # File hash op tag: sha256, followed by its fixed 32-byte digest.
            TAG_SHA256,
            file_digest,
            # First forked branch. Fork markers prefix every branch except the
            # final one at the same node.
            TAG_FORK,
            # Path 0: append("a"), sha256, prepend("b"), sha256.
            TAG_APPEND,
            b"\x01",
            b"a",
            TAG_SHA256,
            TAG_PREPEND,
            b"\x01",
            b"b",
            TAG_SHA256,
            # Bitcoin attestation: 8-byte tag, varbytes payload, height 42.
            TAG_ATTESTATION,
            TAG_BITCOIN,
            b"\x01",
            b"\x2a",
            # Second forked branch at the root.
            TAG_FORK,
            # Path 1: prepend("c"), sha256, append("d"), sha256.
            TAG_PREPEND,
            b"\x01",
            b"c",
            TAG_SHA256,
            TAG_APPEND,
            b"\x01",
            b"d",
            TAG_SHA256,
            # Bitcoin attestation at a different height, 43.
            TAG_ATTESTATION,
            TAG_BITCOIN,
            b"\x01",
            b"\x2b",
            # Final root branch, without a fork marker.
            # Path 2: append("pending"), sha256.
            TAG_APPEND,
            b"\x07",
            b"pending",
            TAG_SHA256,
            # Pending calendar attestation: payload is opaque to the parser.
            TAG_ATTESTATION,
            TAG_PENDING,
            b"\x19",
            b"https://calendar.example/",
        ]
    )

    parsed = ots.parse_ots(data)

    assert parsed.file_hash_op == "sha256"
    assert parsed.file_digest == file_digest
    assert isinstance(parsed.paths, tuple)
    assert len(parsed.paths) == 3
    assert [[(op.name, op.operand) for op in path.ops] for path in parsed.paths] == [
        [("append", b"a"), ("sha256", None), ("prepend", b"b"), ("sha256", None)],
        [("prepend", b"c"), ("sha256", None), ("append", b"d"), ("sha256", None)],
        [("append", b"pending"), ("sha256", None)],
    ]
    assert [path.attestation.kind for path in parsed.paths] == ["bitcoin", "bitcoin", "pending"]
    assert [path.attestation.height for path in parsed.paths] == [42, 43, None]
    assert [path.attestation.payload for path in parsed.paths] == [
        b"\x2a",
        b"\x2b",
        b"https://calendar.example/",
    ]


def test_parse_ots_rejects_bad_magic() -> None:
    data = b"X" + _valid_ots_bytes()[1:]

    with pytest.raises(ots.OtsError, match="invalid OpenTimestamps magic at offset 0"):
        ots.parse_ots(data)


def test_parse_ots_rejects_unsupported_version_byte() -> None:
    data = bytearray(_valid_ots_bytes())
    data[len(MAGIC)] = 0x02

    with pytest.raises(ots.OtsError, match="unsupported OpenTimestamps version 0x02"):
        ots.parse_ots(bytes(data))


def test_parse_ots_rejects_truncation_at_every_prefix() -> None:
    data = _valid_ots_bytes()

    for end in range(len(data)):
        with pytest.raises(ots.OtsError):
            ots.parse_ots(data[:end])


def test_parse_ots_rejects_unterminated_varint() -> None:
    data = _ots_with_tree(TAG_APPEND + b"\x80")

    with pytest.raises(ots.OtsError, match="append operand length varint not terminated"):
        ots.parse_ots(data)


def test_parse_ots_rejects_non_minimal_varint() -> None:
    data = _ots_with_tree(TAG_APPEND + b"\x81\x00" + b"a" + _pending_attestation())

    with pytest.raises(ots.OtsError, match="append operand length varint is non-minimal"):
        ots.parse_ots(data)


def test_parse_ots_rejects_varint_beyond_64_bits() -> None:
    data = _ots_with_tree(TAG_APPEND + (b"\xff" * 10))

    with pytest.raises(ots.OtsError, match="append operand length varint exceeds 64 bits"):
        ots.parse_ots(data)


def test_parse_ots_rejects_varbytes_past_eof() -> None:
    data = _ots_with_tree(TAG_APPEND + b"\x05ab")

    with pytest.raises(ots.OtsError, match=r"append operand varbytes .* declares 5 bytes"):
        ots.parse_ots(data)


def test_parse_ots_rejects_unknown_op_tag() -> None:
    data = _ots_with_tree(b"\x7e" + _pending_attestation())

    with pytest.raises(ots.OtsError, match="unknown ots op tag 0x7e"):
        ots.parse_ots(data)


def test_parse_ots_rejects_non_sha256_file_hash_op_by_name() -> None:
    data = MAGIC + b"\x01" + b"\x02" + (b"\x00" * 20) + _pending_attestation()

    with pytest.raises(ots.OtsError, match="unsupported file hash op sha1"):
        ots.parse_ots(data)


def test_parse_ots_names_the_unsupported_file_hash_op_before_reading_its_digest() -> None:
    """The op is refused on its own terms, not as a side effect of running out of bytes.

    The test above carries a FULL sha1 digest, so it passes whichever order the
    parser uses. Truncate that digest and the two orders diverge: reading first
    reports a truncation and never names the op the file actually declared,
    which is the one thing the operator needs to know.
    """
    data = MAGIC + b"\x01" + b"\x02" + (b"\x00" * 4)

    with pytest.raises(ots.OtsError, match="unsupported file hash op sha1"):
        ots.parse_ots(data)


def test_parse_ots_rejects_bitcoin_attestation_payload_with_trailing_bytes() -> None:
    data = _ots_with_tree(_attestation(TAG_BITCOIN, _varuint(42) + b"x"))

    with pytest.raises(ots.OtsError, match="bitcoin attestation payload has trailing bytes"):
        ots.parse_ots(data)


def test_parse_ots_rejects_trailing_bytes_after_tree() -> None:
    data = _valid_ots_bytes() + b"x"

    with pytest.raises(ots.OtsError, match="trailing bytes after ots tree at offset"):
        ots.parse_ots(data)


def test_parse_ots_rejects_file_over_input_cap() -> None:
    valid = _valid_ots_bytes()
    data = valid + (b"x" * (1_000_001 - len(valid)))

    with pytest.raises(ots.OtsError, match="ots file exceeds 1000000 bytes"):
        ots.parse_ots(data)


def test_parse_ots_rejects_nested_forks_beyond_depth_cap() -> None:
    data = _ots_with_tree(_nested_fork(65))

    with pytest.raises(ots.OtsError, match="ots tree exceeds maximum depth"):
        ots.parse_ots(data)


def test_parse_ots_rejects_more_than_max_leaves() -> None:
    data = _ots_with_tree(_many_leaves(257))

    with pytest.raises(ots.OtsError, match="ots tree has more than 256 leaves"):
        ots.parse_ots(data)


def test_parse_ots_rejects_more_than_max_nodes() -> None:
    data = _ots_with_tree(_many_leaves(256, ops_per_leaf=101))

    with pytest.raises(ots.OtsError, match="ots tree has more than 26112 nodes"):
        ots.parse_ots(data)


def test_parse_ots_rejects_operand_over_anchor_operand_cap() -> None:
    oversized = b"a" * (anchor._MAX_OP_HEX_LEN // 2 + 1)
    data = _ots_with_tree(TAG_APPEND + _varbytes(oversized) + _pending_attestation())

    with pytest.raises(ots.OtsError, match="append operand exceeds 16384 hex chars"):
        ots.parse_ots(data)


def test_parse_ots_rejects_path_over_anchor_op_count_cap() -> None:
    data = _ots_with_tree((TAG_SHA256 * (anchor._MAX_OPS_PER_PROOF + 1)) + _pending_attestation())

    with pytest.raises(ots.OtsError, match="ots path has more than 256 ops"):
        ots.parse_ots(data)


def test_parse_ots_rejects_total_operands_over_anchor_chain_cap() -> None:
    max_operand_bytes = anchor._MAX_OP_HEX_LEN // 2
    chunks = [b"a" * max_operand_bytes, b"b" * max_operand_bytes, b"c" * max_operand_bytes]
    chunks += [b"d" * max_operand_bytes, b"e"]
    tree = b"".join(TAG_APPEND + _varbytes(chunk) for chunk in chunks) + _pending_attestation()
    data = _ots_with_tree(tree)

    assert anchor._MAX_TOTAL_OP_HEX_LEN == 65536
    with pytest.raises(
        ots.OtsError,
        match=rf"ots path operands exceed {anchor._MAX_TOTAL_OP_HEX_LEN} total hex chars",
    ):
        ots.parse_ots(data)


def test_parse_ots_rejects_legacy_ripemd160_path_op_by_name() -> None:
    data = _ots_with_tree(b"\x03" + _pending_attestation())

    with pytest.raises(ots.OtsError, match="unsupported ots op ripemd160"):
        ots.parse_ots(data)


def test_parse_ots_preserves_unknown_attestation_payload() -> None:
    data = _ots_with_tree(_attestation(TAG_UNKNOWN_ATTESTATION, b"opaque"))

    parsed = ots.parse_ots(data)

    assert len(parsed.paths) == 1
    assert parsed.paths[0].attestation.kind == "unknown"
    assert parsed.paths[0].attestation.tag == TAG_UNKNOWN_ATTESTATION
    assert parsed.paths[0].attestation.payload == b"opaque"
    assert parsed.paths[0].attestation.height is None


def test_parse_ots_preserves_duplicate_bitcoin_heights_as_ordered_paths() -> None:
    parsed = ots.parse_ots(_duplicate_height_ots_bytes())

    assert isinstance(parsed.paths, tuple)
    assert len(parsed.paths) == 2
    assert [path.attestation.height for path in parsed.paths] == [42, 42]
    assert [[op.name for op in path.ops] for path in parsed.paths] == [
        ["append", "sha256"],
        ["prepend", "sha256"],
    ]
    assert [parsed.paths[0].ops[0].operand, parsed.paths[1].ops[0].operand] == [b"first", b"second"]


@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(_mutated_ots_bytes())
def test_parse_ots_mutations_return_typed_result_or_typed_error(data: bytes) -> None:
    try:
        parsed = ots.parse_ots(data)
    except ots.OtsError:
        return

    _assert_well_formed(parsed)


def _shared_prefix_ots_bytes() -> bytes:
    return _ots_with_tree(
        b"".join(
            [
                TAG_APPEND,
                _varbytes(b"PREFIX"),
                TAG_SHA256,
                TAG_FORK,
                TAG_APPEND,
                _varbytes(b"L"),
                TAG_SHA256,
                _bitcoin_attestation(42),
                TAG_PREPEND,
                _varbytes(b"R"),
                TAG_SHA256,
                _bitcoin_attestation(43),
            ]
        )
    )


def test_parse_ots_gives_every_forked_path_the_ops_read_before_the_fork() -> None:
    parsed = ots.parse_ots(_shared_prefix_ots_bytes())

    assert [[(op.name, op.operand) for op in path.ops] for path in parsed.paths] == [
        [("append", b"PREFIX"), ("sha256", None), ("append", b"L"), ("sha256", None)],
        [("append", b"PREFIX"), ("sha256", None), ("prepend", b"R"), ("sha256", None)],
    ]


def test_parse_ots_charges_the_operand_budget_read_before_a_fork_to_each_branch() -> None:
    maximal = b"a" * (anchor._MAX_OP_HEX_LEN // 2)
    budget = anchor._MAX_TOTAL_OP_HEX_LEN // anchor._MAX_OP_HEX_LEN
    prefix = b"".join(TAG_APPEND + _varbytes(maximal) for _ in range(budget))
    branch = TAG_APPEND + _varbytes(b"x") + _bitcoin_attestation(1)
    data = _ots_with_tree(prefix + TAG_FORK + branch + _bitcoin_attestation(2))

    with pytest.raises(ots.OtsError, match="ots path operands exceed"):
        ots.parse_ots(data)


def test_parse_ots_keeps_byte_identical_sibling_branches_as_distinct_paths() -> None:
    branch = TAG_APPEND + _varbytes(b"same") + TAG_SHA256 + _bitcoin_attestation(42)

    parsed = ots.parse_ots(_ots_with_tree(TAG_FORK + branch + branch))

    assert len(parsed.paths) == 2
    assert parsed.paths[0] == parsed.paths[1]


def test_parse_ots_rejects_terminated_varint_whose_value_exceeds_64_bits() -> None:
    data = _ots_with_tree(TAG_APPEND + (b"\xff" * 9) + b"\x7f")

    with pytest.raises(ots.OtsError, match="append operand length varint exceeds 64 bits"):
        ots.parse_ots(data)


@pytest.mark.parametrize(
    ("tag", "name"),
    [
        (b"\x02", "sha1"),
        (b"\x03", "ripemd160"),
        (b"\x67", "keccak256"),
        (b"\xf2", "reverse"),
        (b"\xf3", "hexlify"),
    ],
)
def test_parse_ots_rejects_alphabet_ops_outside_the_path_profile(tag: bytes, name: str) -> None:
    data = _ots_with_tree(tag + _pending_attestation())

    with pytest.raises(ots.OtsError, match=f"unsupported ots op {name}"):
        ots.parse_ots(data)


@pytest.mark.parametrize(
    ("label", "tree"),
    [
        ("depth at the cap", _nested_fork(64)),
        ("leaves at the cap", _many_leaves(256)),
        ("ops at the cap", TAG_SHA256 * anchor._MAX_OPS_PER_PROOF + _pending_attestation()),
        (
            "operand at the cap",
            TAG_APPEND + _varbytes(b"a" * (anchor._MAX_OP_HEX_LEN // 2)) + _pending_attestation(),
        ),
    ],
)
def test_parse_ots_accepts_material_sitting_exactly_on_each_cap(label: str, tree: bytes) -> None:
    _assert_well_formed(ots.parse_ots(_ots_with_tree(tree)))


def test_parse_ots_names_the_true_offset_of_a_trailing_bitcoin_payload_byte() -> None:
    data = _ots_with_tree(_attestation(TAG_BITCOIN, _varuint(42) + b"x"))
    # magic, version, file-op tag, digest, attestation marker, attestation tag,
    # one-byte payload length varint -- then the one-byte height, then the byte
    # that must not be there.
    payload_start = len(MAGIC) + 1 + 1 + 32 + 1 + len(TAG_BITCOIN) + 1

    with pytest.raises(ots.OtsError, match=f"trailing bytes at offset {payload_start + 1}$"):
        ots.parse_ots(data)


def test_parse_ots_measures_a_bytes_subclass_by_its_real_length() -> None:
    class Understating(bytes):
        def __len__(self) -> int:
            return 0

    data = Understating(_valid_ots_bytes() + b"x" * ots._MAX_OTS_FILE_BYTES)

    with pytest.raises(ots.OtsError, match="ots file exceeds"):
        ots.parse_ots(data)
