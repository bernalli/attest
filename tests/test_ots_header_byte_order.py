"""Which byte order an operator's block header must carry, pinned against a real block.

A merkle root read forwards and the same root read backwards are the same 32 bytes, so a root
supplied in the wrong order is indistinguishable from the right one by inspection. Every other
fixture in this suite uses a synthetic root — the SHA-256 of some seed — which looks equally
plausible in both directions and therefore cannot tell the two apart. These cases use the
Bitcoin genesis block, where the two orders are different published values, so the distinction
becomes observable.

The `.ots` input goes through the real parser rather than an `OtsFile` assembled by hand, so
what is pinned is the path a converted timestamp actually takes.
"""

from __future__ import annotations

import hashlib

import pytest

from attest import ots
from tests.helpers_bitcoin import (
    GENESIS_COINBASE_TX_HEX,
    GENESIS_HEADER_HASH_DISPLAY,
    GENESIS_HEADER_HEX,
    GENESIS_MERKLE_ROOT_DISPLAY,
    GENESIS_MERKLE_ROOT_INTERNAL,
    GENESIS_TIME,
)
from tests.test_ots_convert import (
    TAG_APPEND,
    TAG_PREPEND,
    TAG_SHA256,
    _bitcoin_attestation,
    _ots_with_tree,
    _varbytes,
)
from tools import bitcoin_header

SEED_START = 60
SEED_END = 92


def _genesis_ots() -> tuple[bytes, ots.OtsFile]:
    """Build the genesis block as a detached OTS file and parse it with the real parser.

    The seed is the 32-byte window of the coinbase transaction that holds the newspaper
    headline. Prepending everything before it, appending everything after it and hashing twice
    rebuilds the transaction's own double SHA-256, which in a block with one transaction is the
    merkle root the header carries — so this is the shortest op-chain a real client could
    produce for this block, not a shape invented for the test.
    """

    tx = bytes.fromhex(GENESIS_COINBASE_TX_HEX)
    seed = tx[SEED_START:SEED_END]
    tree = (
        TAG_PREPEND
        + _varbytes(tx[:SEED_START])
        + TAG_APPEND
        + _varbytes(tx[SEED_END:])
        + TAG_SHA256
        + TAG_SHA256
        + _bitcoin_attestation(0)
    )
    return seed, ots.parse_ots(_ots_with_tree(tree, digest=seed))


def _genesis_header(*, merkle_root: str, header_hash: str | None = None) -> ots.OperatorHeader:
    """The operator header for the genesis block, with the field under test left to the caller."""

    raw = bitcoin_header.require_raw_header(GENESIS_HEADER_HEX)
    if header_hash is None:
        header_hash = bitcoin_header.header_hash_display(raw)
    return ots.OperatorHeader(
        height=0,
        header_hash=header_hash,
        merkle_root=merkle_root,
        time=bitcoin_header.header_time(raw),
    )


def test_genesis_fixture_is_self_consistent() -> None:
    """The fixture agrees with the published block, and its two merkle orders really differ."""

    raw = bitcoin_header.require_raw_header(GENESIS_HEADER_HEX)
    tx = bytes.fromhex(GENESIS_COINBASE_TX_HEX)

    assert bitcoin_header.header_hash_display(raw) == GENESIS_HEADER_HASH_DISPLAY
    assert bitcoin_header.merkle_root_internal(raw) == GENESIS_MERKLE_ROOT_INTERNAL
    assert (
        bytes.fromhex(GENESIS_MERKLE_ROOT_DISPLAY)
        == bytes.fromhex(GENESIS_MERKLE_ROOT_INTERNAL)[::-1]
    )
    assert bitcoin_header.header_time(raw) == GENESIS_TIME

    coinbase_double_sha256 = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
    assert coinbase_double_sha256.hex() == GENESIS_MERKLE_ROOT_INTERNAL
    assert tx[SEED_START:SEED_END] == b"03/Jan/2009 Chancellor on brink "


def test_convert_ots_lands_on_the_headers_own_byte_order() -> None:
    """A root taken from bytes 36-68 of the raw header converts, and is stored unchanged."""

    expected_seed, parsed = _genesis_ots()
    raw = bitcoin_header.require_raw_header(GENESIS_HEADER_HEX)

    result = ots.convert_ots(
        parsed,
        expected_seed,
        [_genesis_header(merkle_root=bitcoin_header.merkle_root_internal(raw))],
    )

    assert len(result.proofs) == 1
    assert [entry for entry in result.report if not entry.converted] == []
    assert result.proofs[0].proof["header_merkle_root"] == GENESIS_MERKLE_ROOT_INTERNAL
    assert result.pinned_headers[GENESIS_HEADER_HASH_DISPLAY]["time"] == GENESIS_TIME


def test_convert_ots_names_the_byte_order_when_the_root_is_supplied_as_printed() -> None:
    """The root a block explorer prints is refused, and the refusal says why it is wrong.

    This is the whole point of the fixture: the skip decision is the same either way, so only
    the wording tells an operator that the bytes are reversed rather than the header wrong.
    """

    expected_seed, parsed = _genesis_ots()

    with pytest.raises(ots.OtsConversionError) as excinfo:
        ots.convert_ots(
            parsed,
            expected_seed,
            [_genesis_header(merkle_root=GENESIS_MERKLE_ROOT_DISPLAY)],
        )

    message = str(excinfo.value)
    assert "byte-reversed" in message
    assert "display order" in message
    assert "height 0" in message
    assert "does not match OTS replay" not in message
    assert excinfo.value.report[0].converted is False


def test_convert_ots_keeps_the_generic_message_for_a_root_that_is_simply_wrong() -> None:
    """A root that is neither order keeps the old wording: the new diagnosis is not a catch-all."""

    expected_seed, parsed = _genesis_ots()
    unrelated_root = hashlib.sha256(b"not the genesis root").hexdigest()

    with pytest.raises(ots.OtsConversionError) as excinfo:
        ots.convert_ots(parsed, expected_seed, [_genesis_header(merkle_root=unrelated_root)])

    message = str(excinfo.value)
    assert "does not match OTS replay at Bitcoin height 0" in message
    assert "byte-reversed" not in message


def test_convert_ots_does_not_check_the_header_hash_at_all() -> None:
    """Conversion copies `header_hash` through without comparing it to anything.

    The operator header is only checked for shape — 64 lowercase hex characters — so a hash in
    the wrong byte order, or one that belongs to no block at all, converts exactly like the
    right one and ends up pinned. The convention for that field is therefore enforced only by
    whatever builds the policy, never by conversion, and that gap is deliberate here rather
    than covered.

    This case is also what keeps the assertion on `pinned_headers` in the converting test from
    being vacuous: pinning happens by copying, so on its own it distinguishes no convention.
    """

    raw = bitcoin_header.require_raw_header(GENESIS_HEADER_HEX)
    unreversed_hash = hashlib.sha256(hashlib.sha256(raw).digest()).digest().hex()
    assert unreversed_hash != GENESIS_HEADER_HASH_DISPLAY

    for header_hash in (unreversed_hash, "ab" * 32):
        expected_seed, parsed = _genesis_ots()

        result = ots.convert_ots(
            parsed,
            expected_seed,
            [
                _genesis_header(
                    merkle_root=bitcoin_header.merkle_root_internal(raw),
                    header_hash=header_hash,
                )
            ],
        )

        assert len(result.proofs) == 1
        assert [entry for entry in result.report if not entry.converted] == []
        assert set(result.pinned_headers) == {header_hash}


@pytest.mark.parametrize(
    ("raw_hex", "length"),
    [
        (GENESIS_HEADER_HEX[:158], 158),
        (GENESIS_HEADER_HEX + "0", 161),
        (GENESIS_HEADER_HEX + "\n", 161),
        ("", 0),
    ],
    ids=["truncated", "one char too long", "trailing newline", "empty"],
)
def test_require_raw_header_refuses_a_wrong_length_and_names_it(raw_hex: str, length: int) -> None:
    """A header that is not 160 characters is refused with the count it actually had."""

    with pytest.raises(ValueError) as excinfo:
        bitcoin_header.require_raw_header(raw_hex)
    assert str(excinfo.value) == (
        f"raw header must be 160 lowercase hex chars (80 bytes), got {length}"
    )


@pytest.mark.parametrize(
    "raw_hex",
    [
        GENESIS_HEADER_HEX.upper(),
        GENESIS_HEADER_HEX[:73] + "B" + GENESIS_HEADER_HEX[74:],
        "0x" + GENESIS_HEADER_HEX[:158],
        " " + GENESIS_HEADER_HEX[:159],
        "z" + GENESIS_HEADER_HEX[1:],
    ],
    ids=["uppercase", "one uppercase digit", "0x prefix", "leading space", "non-hex letter"],
)
def test_require_raw_header_says_the_length_is_right_when_only_the_alphabet_is_wrong(
    raw_hex: str,
) -> None:
    """A header pasted from a tool that prints uppercase has the right count and the wrong bytes.

    Naming the length there sends an operator to recount 160 characters that are already correct,
    which is the one thing the message must not do.
    """

    assert len(raw_hex) == 160
    with pytest.raises(ValueError) as excinfo:
        bitcoin_header.require_raw_header(raw_hex)
    message = str(excinfo.value)
    assert "the length is right" in message
    assert "got 160" not in message


@pytest.mark.parametrize("value", [None, 1, 1.0, b"a" * 160, ["a"], {"a": 1}])
def test_require_raw_header_refuses_a_non_string_as_a_value_error(value: object) -> None:
    """A JSON source hands back `None` and numbers, and callers catch `ValueError`."""

    with pytest.raises(ValueError):
        bitcoin_header.require_raw_header(value)  # type: ignore[arg-type]


@pytest.mark.parametrize("raw", [b"", b"\x00" * 79, b"\x00" * 81], ids=["empty", "79", "81"])
@pytest.mark.parametrize(
    "derive",
    [
        bitcoin_header.header_hash_display,
        bitcoin_header.merkle_root_internal,
        bitcoin_header.header_time,
    ],
    ids=["header_hash_display", "merkle_root_internal", "header_time"],
)
def test_the_derivations_refuse_bytes_that_are_not_a_whole_header(
    derive: object, raw: bytes
) -> None:
    """Each derivation indexes a fixed window, so a short buffer must be refused, not sliced.

    Without the guard `merkle_root_internal(b"")` returns the empty string and `header_time(b"")`
    returns 0 — both plausible enough to travel into a policy.
    """

    with pytest.raises(ValueError, match="raw header must be 80 bytes"):
        derive(raw)  # type: ignore[operator]
