"""Produce this witness's cosignature lines for a checkpoint it has accepted.

Contract: given the note bytes of an authenticated checkpoint and a timestamp,
emit the two C2SP signature lines this witness contributes — the interoperable
Ed25519 type-`0x04` leg and attest's namespaced ML-DSA-65 leg (v0.2 §9.2) —
over the byte-identical payload, at the byte-identical timestamp.

Nothing cryptographic is implemented here. The signed message comes from
`attest.witness.cosignature_message`, the key ids from
`attest.witness.cosignature_key_id` and `attest.tlog.key_hash`, and the
signatures from `attest.keys.sign` / `attest.pq.sign`. What this module owns is
the BLOB LAYOUT — key id, big-endian timestamp, signature — and the line
framing, which is why its tests check the result through the verifier cores
rather than against a constant written here: the core is the authority on
whether these bytes are a cosignature, and it is the only oracle that cannot
drift away from itself.

One property worth stating because it is invisible in the code: both legs
carry the SAME timestamp. §11.4's activation quorum counts a pin only when its
Ed25519 and ML-DSA-65 legs verify "over the same payload and timestamp", so
two legs signed a millisecond apart are not a hybrid vote — they are two
unrelated signatures, and the quorum silently declines to count them.
"""

from __future__ import annotations

import base64
import struct
from dataclasses import dataclass
from typing import Final

from attest import keys, pq, tlog
from attest import witness as witness_policy

# C2SP signed-note line framing (v0.2 §9.1): em dash U+2014, one space, the
# key name, one space, standard base64 WITH padding, newline-terminated.
_LINE_PREFIX: Final = "— "
_TIMESTAMP_STRUCT: Final = struct.Struct(">Q")


class CosignError(Exception):
    """A cosignature could not be produced for the given inputs."""


@dataclass(frozen=True, slots=True)
class Cosignature:
    """The two signature lines this witness adds to a note, and their time."""

    timestamp: int
    ed25519_line: str
    mldsa_65_line: str

    @property
    def lines(self) -> str:
        """Both lines, in the order they are appended to the note."""
        return self.ed25519_line + self.mldsa_65_line


def _line(name: str, blob: bytes) -> str:
    return f"{_LINE_PREFIX}{name} {base64.b64encode(blob).decode('ascii')}\n"


def cosign(
    note_bytes: bytes,
    *,
    name: str,
    signing_keys: pq.HybridSigningKeys,
    timestamp: int,
) -> Cosignature:
    """Cosign `note_bytes` at `timestamp` (seconds since the Unix epoch).

    `note_bytes` must be the checkpoint's THREE HEADER LINES — what
    `tlog.Checkpoint.note_bytes` holds — not the full signed note: a
    cosignature commits to the checkpoint, not to who else has signed it
    (v0.2 §9.2).
    """
    # `cosignature_message` accepts any non-negative integer, but a verifier
    # refuses a cosignature whose timestamp is past MAX_COSIGNATURE_TIMESTAMP
    # (v0.2 §9.2: the two cores must agree on the bound). Signing one anyway
    # would produce a line nobody can ever count — a failure visible only in
    # somebody else's verifier — so the ceiling is enforced HERE, before the
    # key is used.
    if timestamp > witness_policy.MAX_COSIGNATURE_TIMESTAMP:
        raise CosignError(
            f"timestamp {timestamp} is past the maximum cosignature timestamp "
            f"{witness_policy.MAX_COSIGNATURE_TIMESTAMP}"
        )
    try:
        message = witness_policy.cosignature_message(note_bytes, timestamp)
    except witness_policy.WitnessError as exc:
        # Raised for a non-bytes note or a negative timestamp: caller bugs,
        # since the note comes from an already-authenticated checkpoint and
        # the timestamp is ours. Reported, never signed around.
        raise CosignError(str(exc)) from exc
    stamp = _TIMESTAMP_STRUCT.pack(timestamp)
    ed25519_blob = (
        witness_policy.cosignature_key_id(name, signing_keys.ed.pub)
        + stamp
        + keys.sign(message, signing_keys.ed)
    )
    mldsa_blob = (
        tlog.key_hash(name, witness_policy.PQ_COSIGNATURE_SIG_TYPE, signing_keys.mldsa.pub)
        + stamp
        + pq.sign(message, signing_keys.mldsa)
    )
    return Cosignature(
        timestamp=timestamp,
        ed25519_line=_line(name, ed25519_blob),
        mldsa_65_line=_line(name, mldsa_blob),
    )
