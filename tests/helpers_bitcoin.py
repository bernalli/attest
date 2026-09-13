"""The Bitcoin genesis block as test data, and the three values it is checked against.

Data only: no derivation lives here, so the module cannot quietly agree with the code it is
used to test.

The header is the six fields Bitcoin Core fixes in `CreateGenesisBlock(1231006505, 2083236893,
0x1d00ffff, 1, 50 * COIN)`, laid out in the order the wire format puts them: version 1, a
previous-block hash of 32 zero bytes, the merkle root in the header's own byte order, the time
1231006505, the difficulty bits 0x1d00ffff, and the nonce 2083236893.

The block holds exactly one transaction, so the double SHA-256 of that coinbase transaction is
itself the merkle root and no Merkle branch has to be simulated. Bytes 60 to 92 of the coinbase
fall inside its input script and are readable ASCII — `b"03/Jan/2009 Chancellor on brink "` —
which makes a corrupted fixture visible at a glance instead of only through a failing hash.

The genesis block was chosen because it is the most reproduced piece of public data in the
domain: its fields are in the Bitcoin Core source, in every book and on every explorer, so a
mistranscription here is immediately checkable against something outside this repository.

`GENESIS_HEADER_HASH_DISPLAY`, `GENESIS_MERKLE_ROOT_INTERNAL`, `GENESIS_MERKLE_ROOT_DISPLAY` and
`GENESIS_TIME` are the expected values, written from the published description of the block and
the specification of the header format. They are not computed from the code under test, which is
what lets a test compare one against the other and mean something. The two merkle constants are
the same 32 bytes in opposite orders: the internal one is what the header carries, the display
one is what `getblockheader` and block explorers print.
"""

from __future__ import annotations

# The 80 raw header bytes, split field by field. Every multi-byte integer is little-endian on
# the wire, so `time`, `bits` and `nonce` read backwards compared to how they are usually
# written; the merkle root is not an integer and is stored as-is.
GENESIS_HEADER_HEX = (
    "01000000"  # version 1
    "0000000000000000000000000000000000000000000000000000000000000000"  # previous block: none
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"  # merkle root, internal
    "29ab5f49"  # time 1231006505
    "ffff001d"  # bits 0x1d00ffff
    "1dac2b7c"  # nonce 2083236893
)

# The single coinbase transaction of the genesis block, split field by field. The newspaper
# headline sits inside the input script, which is why bytes 60 to 92 of the whole transaction
# are text rather than hashes.
GENESIS_COINBASE_TX_HEX = (
    "01000000"  # version 1
    "01"  # one input
    "0000000000000000000000000000000000000000000000000000000000000000"  # no previous output
    "ffffffff"  # previous output index, unused in a coinbase
    "4d"  # input script length: 77 bytes
    "04ffff001d"  # a push of the difficulty bits
    "0104"  # a push of the single byte 0x04
    "45"  # a push of the 69 bytes below, the newspaper headline
    "5468652054696d65732030332f4a616e2f3230303920"  # "The Times 03/Jan/2009 "
    "4368616e63656c6c6f72206f6e206272696e6b206f6620"  # "Chancellor on brink of "
    "7365636f6e64206261696c6f757420666f722062616e6b73"  # "second bailout for banks"
    "ffffffff"  # sequence
    "01"  # one output
    "00f2052a01000000"  # value: 50 BTC
    "43"  # output script length: 67 bytes
    "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb64"
    "9f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
    "00000000"  # lock time
)

# The block hash as everything that names a block names it: the double SHA-256 of the header,
# read in reverse.
GENESIS_HEADER_HASH_DISPLAY = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

# The merkle root as the header itself carries it, which is the order a timestamp replay lands
# on.
GENESIS_MERKLE_ROOT_INTERNAL = "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"

# The same 32 bytes reversed, which is what `getblockheader` and block explorers print for
# `merkleroot`. Supplying this where the internal order is expected is the mistake the tests
# using this module exist to catch.
GENESIS_MERKLE_ROOT_DISPLAY = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

# 2009-01-03T18:15:05Z.
GENESIS_TIME = 1231006505
