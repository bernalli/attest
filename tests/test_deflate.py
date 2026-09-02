"""The stored-block check, against streams both decoders were measured on.

The walker exists for one measured disagreement and must not invent others: a
stream any decoder accepts has to walk clean here, and the walk has to keep
following real archives — the shipped sample's members are deflated by zlib and
are the only proof that the Huffman path is walked, not merely written.
"""

from __future__ import annotations

import zlib
from pathlib import Path

import pytest

from attest import container, deflate

LIMIT = 1 << 20
REPO_ROOT = Path(__file__).resolve().parents[1]


class _Bits:
    def __init__(self) -> None:
        self.data = bytearray()
        self.bit = 0

    def put(self, value: int, count: int) -> None:
        for index in range(count):
            if self.bit == 0:
                self.data.append(0)
            if (value >> index) & 1:
                self.data[-1] |= 1 << self.bit
            self.bit = (self.bit + 1) % 8


def stored_stream(payload: bytes, *, nlen: int | None = None, final: int = 1) -> bytes:
    bits = _Bits()
    bits.put(final, 1)
    bits.put(0, 2)
    bits.bit = 0
    length = len(payload)
    bits.data += length.to_bytes(2, "little")
    bits.data += (nlen if nlen is not None else (~length & 0xFFFF)).to_bytes(2, "little")
    bits.data += payload
    return bytes(bits.data)


def deflated(data: bytes, level: int = 9) -> bytes:
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def test_an_honest_stored_block_walks_clean() -> None:
    assert deflate.deflate_error(stored_stream(b"hello world"), LIMIT) is None


def test_a_stored_block_with_a_bad_complement_is_named() -> None:
    """zlib refuses this stream and the browser's decoder accepts it: the
    verdict moves here so both implementations give the same one."""
    stream = stored_stream(b"hello world", nlen=0x1234)
    assert deflate.deflate_error(stream, LIMIT) == "stored-block-lengths"
    with pytest.raises(zlib.error):
        zlib.decompressobj(-15).decompress(stream)


def test_a_bad_complement_in_a_later_block_is_still_named() -> None:
    """The walk does not stop at the first block: a stream can be honest right
    up to the block that is not."""
    stream = stored_stream(b"first", final=0) + stored_stream(b"second", nlen=0)
    assert deflate.deflate_error(stream, LIMIT) == "stored-block-lengths"


@pytest.mark.parametrize(
    "payload",
    [b"", b"x", b"terms " * 400, bytes(range(256)) * 8, b"\x00" * 5000],
)
def test_every_zlib_stream_walks_clean(payload: bytes) -> None:
    """A validator that refused a stream zlib produces would refuse ordinary
    bundles: this is the property that keeps the check from becoming a bug."""
    for level in (0, 1, 6, 9):
        assert deflate.deflate_error(deflated(payload, level), LIMIT) is None


def test_level_zero_output_is_stored_blocks_and_still_walks_clean() -> None:
    """`level=0` is how zlib writes stored blocks, which is exactly the shape
    the check inspects — the honest version of the hostile case."""
    stream = deflated(b"incompressible" * 100, level=0)
    assert deflate.deflate_error(stream, LIMIT) is None


def test_the_shipped_sample_walks_clean() -> None:
    sample = REPO_ROOT / "site" / "public" / "sample" / "demo.attest"
    raw = sample.read_bytes()
    members = container.canonical_members(
        raw, max_entries=10_000, max_member_bytes=LIMIT, max_total_bytes=1 << 28
    )
    deflated_members = [m for m in members if m.method == 8]
    assert deflated_members, "the sample is expected to carry deflated members"
    for member in deflated_members:
        window = raw[member.data_start : member.data_start + member.compressed_size]
        assert deflate.deflate_error(window, LIMIT) is None


def test_everything_it_cannot_follow_is_refused() -> None:
    """Fail-closed: the earlier version stayed silent here, on the assumption
    that the two decoders agreed on whatever it could not follow. They do not —
    a reserved literal code is accepted by one and refused by the other — so
    silence is no longer an answer."""
    for stream in (b"", b"\xff\xff\xff\xff", deflated(b"abc")[:2], bytes([0b111])):
        assert deflate.deflate_error(stream, LIMIT) is not None


def test_the_reserved_literal_code_the_other_decoder_accepts_is_refused() -> None:
    """Measured: this stream produces 261 bytes under the browser verifier's
    decoder and is refused by this one as an invalid literal/length code. The
    verdict is now made here, so both give the same one."""
    reserved = bytes.fromhex("731c0300")
    assert deflate.deflate_error(reserved, LIMIT) == "reserved-length-symbol"
    with pytest.raises(zlib.error):
        zlib.decompressobj(-15).decompress(reserved)


def test_length_codes_are_counted_from_the_normative_table() -> None:
    """The DEFLATE length table is not linear: code 285 alone means 258 bytes,
    where counting `3 + index` would report 31. Under-counting does not show up
    as a wrong answer — it shows up as the walk running PAST the limit it claims
    to stop at, which is the work an attacker gets to choose.

    The stream below produces 600 bytes and is followed by a stored block whose
    complement is wrong. Under the real table the limit of 300 stops the walk
    before that block is ever reached, and the answer is silence. Under a linear
    count the walk believes it has produced about a hundred bytes, keeps going,
    and finds the block — so a wrong table turns this assertion red.
    """
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    # Z_SYNC_FLUSH closes the block WITHOUT setting BFINAL, so the walk carries
    # on into the block appended after it.
    unterminated = compressor.compress(b"A" * 600) + compressor.flush(zlib.Z_SYNC_FLUSH)
    stream = unterminated + stored_stream(b"second", nlen=0)
    assert deflate.deflate_error(stream, 10_000) == "stored-block-lengths"
    assert deflate.deflate_error(stream, 300) is None


def test_the_walk_stops_at_the_limit() -> None:
    """Past the cap both decoders refuse anyway; walking further would be work
    an attacker chose."""
    assert deflate.deflate_error(deflated(b"\x00" * 100_000), 10) is None
