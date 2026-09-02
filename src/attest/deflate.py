"""A member's compressed stream, judged here instead of by two decoders.

The container reader decides which members an archive holds; the decompression
itself is still done by each language's library. Those libraries do not refuse
the same streams. Two disagreements were measured directly (2026-09-02):

* a *stored* block whose `NLEN` is not the one's complement of its `LEN` —
  refused by zlib, accepted by fflate, which never reads that field;
* a literal/length code of 286, reserved by RFC 1951 and emitted by no encoder —
  refused by zlib, accepted by fflate, which gives the reserved codes working
  bases and produces output from them.

Either one is the defect the canonical container form exists to remove, one
layer down: same bytes, one verifier accepting and the other refusing. An
earlier version of this module refused only the first and stayed silent on
anything it could not follow, on the assumption that the decoders agreed
everywhere else. The second measurement is what that assumption was worth.

So this module validates the stream against RFC 1951 and is **fail-closed**:
anything it cannot follow, or that the format does not allow, is refused, and
only a stream walked to its final block is handed on. `deflate_error` returns a
reason or `None`; the caller turns any reason into the single
`member-inflate-error` code, because which structure was wrong is not the
buyer's business.

The one thing it does not do is walk past the caller's output cap: past that
point both implementations refuse the member for the same reason anyway, and
walking further would be work an attacker sized. That exit is the only one that
returns `None` without having seen a final block.

`site/src/deflate.ts` is the same walk, step for step, with the same reasons.
The strictness follows the reference decoder's own rules (RFC 1951 §3.2.5-3.2.7):
reserved symbols, over-subscribed tables, incomplete tables other than the one
degenerate case the format allows, a distance reaching before the start of the
output, and a stream that ends before its final block.
"""

from __future__ import annotations

from collections.abc import Buffer

#: Order in which the code-length code lengths are written (RFC 1951 §3.2.7).
_CLEN_ORDER = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15)

#: Extra bits carried by length codes 257-285 and distance codes 0-29.
_LENGTH_EXTRA = (
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
)  # fmt: skip
_DIST_EXTRA = (
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
)  # fmt: skip

#: Base output length per length code 257-285 (RFC 1951 §3.2.5). The table is
#: not linear — code 285 alone means 258 bytes — so counting `3 + index` would
#: under-report the output by more than eight times at the top of the range,
#: and the cap below would not be a cap.
_LENGTH_BASE = (
    3, 4, 5, 6, 7, 8, 9, 10,
    11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115,
    131, 163, 195, 227, 258,
)  # fmt: skip
_DIST_BASE = (
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
)  # fmt: skip

_MAX_LITERAL_SYMBOLS = 286  # 0-285 are usable; 286 and 287 are reserved
_MAX_DISTANCE_SYMBOLS = 30  # 0-29 are usable; 30 and 31 are reserved


class _Invalid(Exception):
    """The stream is not a well-formed raw DEFLATE stream."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _PastCap(Exception):
    """The walk reached the caller's output cap; the caps decide from here."""


class _Bits:
    """Least-significant-bit-first reader over a byte range.

    Bit positions are kept in plain arithmetic rather than shifts: a stream may
    be hundreds of megabytes, and in one of the two languages a shift would
    silently wrap the offset into a negative number.
    """

    __slots__ = ("data", "position")

    def __init__(self, data: memoryview) -> None:
        self.data = data
        self.position = 0  # in bits

    def take(self, count: int) -> int:
        value = 0
        for index in range(count):
            absolute = self.position + index
            byte_index = absolute // 8
            if byte_index >= len(self.data):
                raise _Invalid("truncated")
            value |= ((self.data[byte_index] >> (absolute % 8)) & 1) << index
        self.position += count
        return value

    def align(self) -> int:
        """Advance to the next byte boundary and return that byte offset."""
        self.position = -(-self.position // 8) * 8
        return self.position // 8

    def seek_byte(self, offset: int) -> None:
        self.position = offset * 8


def _build(lengths: list[int], *, what: str, degenerate_ok: bool) -> tuple[list[int], list[int]]:
    """Canonical Huffman decoding tables (counts per length, symbols in order).

    Over-subscribed tables are refused. So are incomplete ones, with the single
    exception the format allows and the reference decoder accepts: an alphabet
    carrying at most one code, which is how an encoder says "unused". Refusing
    that case would refuse ordinary archives; accepting any other incomplete
    table would accept streams the reference decoder does not.
    """
    counts = [0] * 16
    for length in lengths:
        counts[length] += 1
    left = 1
    for length in range(1, 16):
        left <<= 1
        left -= counts[length]
        if left < 0:
            raise _Invalid(f"{what}-oversubscribed")
    used = len(lengths) - counts[0]
    if left > 0 and not (degenerate_ok and used <= 1):
        raise _Invalid(f"{what}-incomplete")
    offsets = [0] * 16
    for length in range(1, 15):
        offsets[length + 1] = offsets[length] + counts[length]
    symbols = [0] * len(lengths)
    for symbol, length in enumerate(lengths):
        if length:
            symbols[offsets[length]] = symbol
            offsets[length] += 1
    return counts, symbols


def _decode(bits: _Bits, table: tuple[list[int], list[int]]) -> int:
    counts, symbols = table
    code = first = index = 0
    for length in range(1, 16):
        code |= bits.take(1)
        count = counts[length]
        if code - first < count:
            return symbols[index + (code - first)]
        index += count
        first = (first + count) << 1
        code <<= 1
    raise _Invalid("code-not-in-table")


_FIXED_LITERALS = _build(
    [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8, what="literal", degenerate_ok=False
)
# The fixed distance alphabet is 32 five-bit codes, two of them reserved: the
# tree is complete, and codes 30 and 31 are refused where they are USED.
_FIXED_DISTANCES = _build([5] * 32, what="distance", degenerate_ok=False)


def _dynamic_tables(bits: _Bits) -> tuple[tuple[list[int], list[int]], tuple[list[int], list[int]]]:
    literal_count = bits.take(5) + 257
    distance_count = bits.take(5) + 1
    code_count = bits.take(4) + 4
    if literal_count > _MAX_LITERAL_SYMBOLS or distance_count > _MAX_DISTANCE_SYMBOLS:
        raise _Invalid("dynamic-counts")
    code_lengths = [0] * 19
    for index in range(code_count):
        code_lengths[_CLEN_ORDER[index]] = bits.take(3)
    code_table = _build(code_lengths, what="code-length", degenerate_ok=False)

    total = literal_count + distance_count
    lengths: list[int] = []
    while len(lengths) < total:
        symbol = _decode(bits, code_table)
        if symbol < 16:
            lengths.append(symbol)
        elif symbol == 16:
            if not lengths:
                raise _Invalid("repeat-without-previous")
            lengths.extend([lengths[-1]] * (3 + bits.take(2)))
        elif symbol == 17:
            lengths.extend([0] * (3 + bits.take(3)))
        else:
            lengths.extend([0] * (11 + bits.take(7)))
    if len(lengths) > total:
        raise _Invalid("code-lengths-overrun")
    return (
        _build(lengths[:literal_count], what="literal", degenerate_ok=True),
        _build(lengths[literal_count:], what="distance", degenerate_ok=True),
    )


def _walk_huffman_block(
    bits: _Bits,
    tables: tuple[tuple[list[int], list[int]], tuple[list[int], list[int]]],
    produced: int,
    limit: int,
) -> int:
    literals, distances = tables
    while True:
        symbol = _decode(bits, literals)
        if symbol < 256:
            produced += 1
        elif symbol == 256:
            return produced
        else:
            index = symbol - 257
            if index >= len(_LENGTH_EXTRA):
                raise _Invalid("reserved-length-symbol")
            length = _LENGTH_BASE[index] + bits.take(_LENGTH_EXTRA[index])
            distance_symbol = _decode(bits, distances)
            if distance_symbol >= len(_DIST_EXTRA):
                raise _Invalid("reserved-distance-symbol")
            distance = _DIST_BASE[distance_symbol] + bits.take(_DIST_EXTRA[distance_symbol])
            if distance > produced:
                raise _Invalid("distance-before-output")
            produced += length
        if produced > limit:
            raise _PastCap


def deflate_error(data: Buffer, limit: int) -> str | None:
    """A reason if `data` is not a well-formed raw DEFLATE stream, else `None`.

    `None` also means "the walk reached `limit` output bytes and stopped": past
    the caller's cap both implementations refuse the member for the same reason,
    so there is nothing left for this check to decide.
    """
    view = memoryview(data).cast("B")
    bits = _Bits(view)
    produced = 0
    try:
        while True:
            final = bits.take(1)
            block_type = bits.take(2)
            if block_type == 0:
                start = bits.align()
                if start + 4 > len(view):
                    raise _Invalid("truncated-stored-header")
                length = view[start] | (view[start + 1] << 8)
                nlength = view[start + 2] | (view[start + 3] << 8)
                if nlength != (~length & 0xFFFF):
                    raise _Invalid("stored-block-lengths")
                if start + 4 + length > len(view):
                    raise _Invalid("truncated-stored-data")
                bits.seek_byte(start + 4 + length)
                produced += length
            elif block_type == 1:
                produced = _walk_huffman_block(
                    bits, (_FIXED_LITERALS, _FIXED_DISTANCES), produced, limit
                )
            elif block_type == 2:
                produced = _walk_huffman_block(bits, _dynamic_tables(bits), produced, limit)
            else:
                raise _Invalid("reserved-block-type")
            if final:
                return None
            if produced > limit:
                return None
    except _Invalid as invalid:
        return invalid.reason
    except _PastCap:
        return None
