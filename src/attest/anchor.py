"""OpenTimestamps-style Bitcoin block-header anchoring — Stage 2 (design
doc "transparency/corroboration layer", CRQC-horizon gating).

Scope: this module lets a verifier check that a `tlog.Checkpoint` was
timestamped into a Bitcoin block header pinned in its own trust store
(`AnchorPolicy`), and gate on whether that anchor lands early enough to
still count as post-quantum-surviving evidence once a future
cryptographically-relevant quantum computer (CRQC) horizon is reached.

- `verify_anchor` first parses the required full signed-note text in
  `evidence["checkpoint"]` and binds its `note_bytes` to the trusted
  `checkpoint` argument. It then walks each proof: an `ots` proof replays a
  non-empty hash op-chain (`sha256`/`append`/`prepend`) starting from an
  `evidence["anchor_profile"]`-selected commitment (G4, attest-v0.2.md
  §11.1) — `SHA256(checkpoint.signed_note_bytes)` (the full signed note,
  header AND signature lines) for `"signed-note-v2"`, or
  `SHA256(checkpoint.note_bytes)` (the unsigned header alone — the legacy
  gap TM-33's residual risk documents: a chosen note can be pre-anchored
  before it is ever signed) for absent/`None`/`"note-v1"` — and checks the
  result lands on a Bitcoin merkle root pinned, by header hash, in
  `policy.pinned_headers`; an `rfc3161` proof is accepted only as opaque
  classical corroboration (never parsed) and can never set an anchor time.
  `AnchorVerdict.note_only` records which profile was used (eternal
  verifiability, attest-versioning.md §3: `note-v1` evidence remains fully
  verifiable, never rejected for being legacy — only classified). This
  function NEVER raises on malformed evidence — `evidence` arrives from an
  untrusted bundle, so any shape violation (wrong types, missing fields, bad
  hex, unknown ops, an unrecognized `anchor_profile`, an oversized proof/op
  list) degrades to a warning and that proof simply contributes nothing,
  rather than aborting verification of the rest of the bundle or leaking a
  bare Python exception.
- `checkpoint` and `policy` are the trusted, verifier-config side of the
  call (mirrors `tlog.verify_checkpoint`'s `log_key`/`expected_origin`
  arguments): a non-`tlog.Checkpoint` `checkpoint` or a malformed `AnchorPolicy`
  raises `AnchorError` instead, since that signals a caller bug, not
  adversarial input.
- `verify_seeded_anchor` answers the other half of the question. Where
  `verify_anchor` asks "was THIS checkpoint timestamped?",
  `verify_seeded_anchor` asks "has real time reached date T?": the op-chain
  starts from `SHA256(seed)` for an arbitrary caller-supplied `seed` (the
  canonical bytes of some public document), no checkpoint is involved
  anywhere, and the anchor-profile dimension does not exist — a profile only
  distinguishes WHICH of a checkpoint's two byte-strings an accumulator
  committed to. Everything else is shared with `verify_anchor`, down to the
  ceilings and the warning strings. Because the two ask opposite questions,
  the verdict carries BOTH reductions over the verified proofs —
  `anchored_before` (minimum, "did this exist no later than T?") and
  `anchored_after` (maximum, "has real time reached T?") — see
  `AnchorVerdict` for why one cannot stand in for the other.
- `passes_horizon` is a pure function of `(verdict, policy)`: `AnchorError`
  only on a malformed `policy`, never on `verdict` content (even a
  hand-built `AnchorVerdict` with wrong field types degrades to `False`
  rather than raising).

Hex fields throughout are validated lowercase-only and, where the schema
fixes a length (a 32-byte SHA-256 digest, 64 hex chars), exactly that
length, BEFORE any `bytes.fromhex` call — `bytes.fromhex` itself happily
accepts uppercase and would silently normalize an out-of-schema encoding.
List and hex-operand sizes on untrusted evidence are capped (see the
`_MAX_*` constants below) so a hostile bundle cannot force unbounded work.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any

from attest import tlog

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_RE = re.compile(r"^[0-9a-f]*$")

# Caps bounding attacker-controlled work while walking untrusted evidence.
# The op-chain caps below are sized from MEASURED real OpenTimestamps
# attestations, not from a guess about what "a handful" means: over four
# upstream example files (2026-08-31) the largest Bitcoin path carries 100
# ops, the largest single operand is 3432 bytes (a Bitcoin transaction prefix
# ahead of the commitment output), and the largest per-chain operand total is
# 7388 hex chars. The pre-2026-08-31 values (64 ops, 2048 hex) turned the
# first of those away outright, so no real attestation could be attached at
# all — the synthetic four-op chains in this repo's own tests were the only
# material these caps had ever seen.
_MAX_PROOFS_PER_EVIDENCE = 64
_MAX_OPS_PER_PROOF = 256
# A legitimate full note is ~400KB worst case (64 signature lines, ML-DSA-65
# blobs ~4.4KB base64 each) — cap the evidence checkpoint text BEFORE it
# reaches `tlog.parse_checkpoint`, so a hostile multi-megabyte string cannot
# force large parse-time allocations.
_MAX_CHECKPOINT_TEXT_LEN = 500_000
_MAX_OP_HEX_LEN = 16384  # hex chars (8192 bytes) per append/prepend operand
# The per-chain operand TOTAL, and the reason the two caps above could be
# raised at all. `verify`'s outer evidence ceiling is normative
# (`canon.MAX_ADMISSION_BYTES`, v0.2 §6.3) and so cannot be raised to meet
# them: without this cap, `_MAX_PROOFS_PER_EVIDENCE * _MAX_OPS_PER_PROOF *
# _MAX_OP_HEX_LEN` would admit 268,435,456 operand characters against a
# 10,000,000-character ceiling, and evidence this module accepts would be
# refused before it ever arrived. With it, the worst case is
# 64 * 65_536 = 4,194,304 operand characters plus 1,500,000 characters of
# checkpoint text — inside the 10,000,000-character ceiling with room to spare.
#
# It also tightens the aggregate rather than loosening it: the old regime
# admitted `_MAX_OPS_PER_PROOF * _MAX_OP_HEX_LEN` = 131_072 hex chars of
# attacker-chosen bytes per proof, twice what this allows. What genuinely does
# grow is the op COUNT per bundle (4x) and the peak single concatenation (8x).
_MAX_TOTAL_OP_HEX_LEN = 65536
# `datetime` can render through 9999-12-31T23:59:59Z, but no later Unix
# timestamp. Keep pinned and untrusted proof times inside that shared bound.
_MAX_RENDERABLE_UNIX_TIME = 253402300799

_KNOWN_OTS_OPS = frozenset({"sha256", "append", "prepend"})

# Anchor profile (G4, attest-v0.2.md §11.1): which checkpoint bytes an `ots`
# proof's accumulator starts from. Absent or `"note-v1"` is the legacy path
# (starts from `checkpoint.note_bytes`, the unsigned header alone — eternal
# verifiability, attest-versioning.md §3: still fully verifiable, forever,
# just classified `note_only=True` for the caller to warn on).
# `"signed-note-v2"` starts from `checkpoint.signed_note_bytes` (the full
# signed note, header AND signature lines) and is what newly-produced
# anchors MUST use going forward.
_ANCHOR_PROFILE_NOTE_V1 = "note-v1"
_ANCHOR_PROFILE_SIGNED_NOTE_V2 = "signed-note-v2"
_KNOWN_ANCHOR_PROFILES = frozenset({_ANCHOR_PROFILE_NOTE_V1, _ANCHOR_PROFILE_SIGNED_NOTE_V2})

_RFC3161_WARNING = (
    "rfc3161 token accepted as opaque classical evidence, carries no post-horizon weight"
)


class AnchorError(ValueError):
    """A trusted anchor-verifier argument (`AnchorPolicy` or `checkpoint`) is malformed.

    Never raised for malformed `evidence` — that boundary reports through
    `AnchorVerdict.warnings` instead, see `verify_anchor`.
    """


@dataclass(frozen=True)
class PinnedHeader:
    """A Bitcoin block header pinned out-of-band into the verifier's trust
    store — never taken from the untrusted evidence bundle itself."""

    header_hash: str
    merkle_root: str
    time: int


@dataclass(frozen=True)
class AnchorPolicy:
    """The verifier's anchor trust store and CRQC cutoff.

    `pinned_headers` is keyed by `header_hash` (each value's own
    `header_hash` field must match its key — see `_validate_policy`).
    `crqc_horizon` is a unix-seconds cutoff; `None` means no cutoff is
    configured (every PQ-anchored checkpoint passes).
    """

    pinned_headers: dict[str, PinnedHeader]
    crqc_horizon: int | None


@dataclass(frozen=True)
class AnchorVerdict:
    """The outcome of `verify_anchor` or `verify_seeded_anchor` over one
    evidence bundle.

    `anchored_before` and `anchored_after` are the two ends of the same set
    of verified `ots` (PQ-surviving) proofs — `rfc3161` proofs set neither,
    even when `anchored` is `True` from `rfc3161` corroboration alone, and
    both are `None` when no `ots` proof verified. They exist as a PAIR
    because a caller can ask two opposite questions of one bundle and only
    one reduction is sound for each:

    - `anchored_before` is the MINIMUM pinned header time. It answers "did
      this exist no later than T?" — the oldest verified anchor is the
      strongest claim of prior existence, and taking the maximum there would
      overclaim.
    - `anchored_after` is the MAXIMUM pinned header time. It answers "has
      real time reached T?" — a pinned header's time is a lower bound on
      real time, so the most recent verified anchor is the strongest such
      evidence. Taking the minimum there produces false negatives the moment
      a bundle carries two valid proofs: an old one would veto a new one,
      and a caller handed only the minimum cannot recover the maximum.

    Neither reduction is derivable from the other, which is why the verdict
    carries both rather than picking one. `anchored_after` defaults to `None`
    so that every pre-existing construction site — including the
    early-return verdicts below and callers that never heard of it — keeps
    working untouched.

    `note_only` is `True` iff the evidence's `anchor_profile` is absent,
    `None`, or `"note-v1"` (G4, attest-v0.2.md §11.1): the accumulator
    started from `checkpoint.note_bytes` alone rather than the full signed
    note, so any resulting anchor proves existence of the unsigned header
    text only, not of the signature that was eventually attached to it.
    `False` for `"signed-note-v2"` evidence. Defaults `False` so every
    early-return `AnchorVerdict` (evidence too malformed to even reach
    profile dispatch) doesn't claim a profile it never determined.
    `transparency.py` is the one that turns this into the caller-facing
    `anchor_note_only` warning — `verify_anchor`'s own `warnings` never
    mention it, exactly like `verify_anchor` never itself decides whether an
    anchor establishes standing.
    """

    anchored: bool
    anchored_before: int | None
    pq_surviving: bool
    warnings: list[str]
    note_only: bool = False
    anchored_after: int | None = None


def _trunc(value: object, limit: int = 60) -> str:
    """Safely render an untrusted value for a bounded warning message.

    Never call ``ascii`` on arbitrary evidence values: rendering a hostile
    integer or a user-defined object can itself raise or allocate an
    unbounded temporary. Strings are sliced *before* rendering; only small
    integers and the two scalar singletons are rendered directly.
    """
    if type(value) is str:
        text = ascii(value[:limit])
        return text if len(text) <= limit else text[: limit - 3] + "..."
    if value is None or type(value) is bool:
        return ascii(value)
    if type(value) is int and value.bit_length() <= 256:
        return ascii(value)
    type_name = type(value).__name__
    return f"<{type_name[: limit - 2]}>"


def _validate_policy(policy: object) -> AnchorPolicy:
    """Validate every `AnchorPolicy` field before it's trusted. Raises
    `AnchorError` — `policy` is assembled by the verifier's own config, not
    adversarial evidence, so a malformed policy is a caller bug to surface
    loudly, not degrade gracefully."""
    if not isinstance(policy, AnchorPolicy):
        raise AnchorError(f"policy must be an AnchorPolicy, got {type(policy).__name__}")
    if not isinstance(policy.pinned_headers, dict):
        raise AnchorError("policy.pinned_headers must be a dict")
    for header_hash, header in policy.pinned_headers.items():
        if not isinstance(header_hash, str) or not _HEX64_RE.fullmatch(header_hash):
            raise AnchorError(f"pinned_headers key must be 64 lowercase hex chars: {header_hash!r}")
        if not isinstance(header, PinnedHeader):
            raise AnchorError(f"pinned_headers[{header_hash!r}] must be a PinnedHeader")
        if not isinstance(header.header_hash, str) or not _HEX64_RE.fullmatch(header.header_hash):
            raise AnchorError(
                f"PinnedHeader.header_hash must be 64 lowercase hex chars: {header.header_hash!r}"
            )
        if header.header_hash != header_hash:
            raise AnchorError(
                f"pinned_headers key {header_hash!r} != "
                f"PinnedHeader.header_hash {header.header_hash!r}"
            )
        if not isinstance(header.merkle_root, str) or not _HEX64_RE.fullmatch(header.merkle_root):
            raise AnchorError(
                f"PinnedHeader.merkle_root must be 64 lowercase hex chars: {header.merkle_root!r}"
            )
        if (
            not isinstance(header.time, int)
            or isinstance(header.time, bool)
            or not 0 < header.time <= _MAX_RENDERABLE_UNIX_TIME
        ):
            raise AnchorError(
                "PinnedHeader.time must be a positive int no later than "
                f"{_MAX_RENDERABLE_UNIX_TIME}: {header.time!r}"
            )
    if policy.crqc_horizon is not None and (
        not isinstance(policy.crqc_horizon, int) or isinstance(policy.crqc_horizon, bool)
    ):
        raise AnchorError(f"policy.crqc_horizon must be an int or None: {policy.crqc_horizon!r}")
    return policy


def _hex64(value: object) -> bytes | None:
    """Decode a strict 64-char lowercase-hex (32-byte SHA-256) field, or
    `None` if `value` doesn't have exactly that shape. Charset/length are
    checked BEFORE `bytes.fromhex`, which accepts uppercase on its own."""
    if not isinstance(value, str) or not _HEX64_RE.fullmatch(value):
        return None
    return bytes.fromhex(value)


def _op_hex(value: object) -> bytes | None:
    """Decode a bounded, even-length, lowercase-hex op operand, or `None`."""
    if (
        not isinstance(value, str)
        or len(value) > _MAX_OP_HEX_LEN
        or len(value) % 2 != 0
        or not _HEX_RE.fullmatch(value)
    ):
        return None
    return bytes.fromhex(value)


def replay_ots_op_chain(accumulator_start: bytes, ops: object) -> tuple[bytes | None, str | None]:
    """Validate and replay an untrusted `ots` proof's `ops` op-chain,
    starting from `accumulator_start`.

    Returns `(final_accumulator, None)` on success, or `(None, warning)`
    naming the first shape violation encountered. Shared by
    `_verify_ots_proof` (verification, walks the op-chain against the
    caller-selected profile seed) and `cli._cmd_log_anchor` (attachment-time
    seed diagnosis, G4/I2) so op-chain shape validation and replay live in
    exactly one place — callers must never reimplement this loop.
    """
    if not isinstance(ops, list):
        return None, "ots proof 'ops' must be a list"
    if not ops:
        return None, "ots proof has empty op-chain"
    if len(ops) > _MAX_OPS_PER_PROOF:
        return None, f"ots proof has more than {_MAX_OPS_PER_PROOF} ops"

    accumulator = accumulator_start
    total_operand_hex = 0
    for op in ops:
        if not isinstance(op, list) or not op or not isinstance(op[0], str):
            return None, "ots op must be a non-empty list with a string opcode"
        opcode = op[0]
        if opcode not in _KNOWN_OTS_OPS:
            return None, f"unknown ots op {_trunc(opcode)}"
        if opcode == "sha256":
            if len(op) != 1:
                return None, "ots 'sha256' op takes no operand"
            accumulator = hashlib.sha256(accumulator).digest()
        else:
            if len(op) != 2:
                return None, f"ots {_trunc(opcode)} op needs exactly one hex operand"
            operand = _op_hex(op[1])
            if operand is None:
                return (
                    None,
                    f"ots {_trunc(opcode)} operand must be bounded, even-length lowercase hex",
                )
            # Bound the operand TOTAL, not just each operand: the per-op cap
            # alone lets a chain of many maximal operands grow the material
            # without limit, and it is the total that has to stay inside
            # `verify`'s normative outer ceiling. Checked BEFORE the
            # concatenation, so refused material is never materialized.
            total_operand_hex += len(op[1])
            if total_operand_hex > _MAX_TOTAL_OP_HEX_LEN:
                return (
                    None,
                    f"ots proof operands exceed {_MAX_TOTAL_OP_HEX_LEN} total hex chars",
                )
            accumulator = accumulator + operand if opcode == "append" else operand + accumulator
    return accumulator, None


def _verify_ots_proof(
    proof: dict[str, Any],
    accumulator_start: bytes,
    policy: AnchorPolicy,
    *,
    legacy_accumulator_start: bytes | None = None,
) -> tuple[bool, int, str | None]:
    """Evaluate one `ots` proof: replay its op-chain from `accumulator_start`
    and cross-check the result against a header pinned in `policy`.

    Returns `(verified, header_time, warning)`. `header_time` is only
    meaningful when `verified` is `True` (it's the PINNED header's own
    time, not the proof's untrusted claim — the two are required to match
    before `verified` can be `True` at all, see the final check below).
    `warning` names the failure reason and is `None` only when `verified`
    is `True`.

    `legacy_accumulator_start` (G4/I2, attest-v0.2.md §11.1.1) carries the
    anchor-profile dimension, and `None` means the call has no such
    dimension — either a declared `note-v1` profile or a seed that is not a
    checkpoint's bytes at all (`verify_seeded_anchor`), both of which get the
    plain mismatch warning. When it IS supplied (a declared `signed-note-v2`
    profile), an op-chain mismatch also replays the SAME `ops` from the
    legacy `note-v1` seed — purely diagnostic, never changes `verified` — so
    the warning can name which seed the declared profile actually requires
    and flag the common mistake of presenting a v1-shaped commitment as v2.
    """
    ops = proof.get("ops")
    accumulator, warning = replay_ots_op_chain(accumulator_start, ops)
    if warning is not None:
        return False, 0, warning

    root_bytes = _hex64(proof.get("header_merkle_root"))
    if root_bytes is None:
        return False, 0, "ots proof 'header_merkle_root' must be 64 lowercase hex chars"
    header_hash = proof.get("header_hash")
    if not isinstance(header_hash, str) or not _HEX64_RE.fullmatch(header_hash):
        return False, 0, "ots proof 'header_hash' must be 64 lowercase hex chars"
    header_time = proof.get("header_time")
    if (
        not isinstance(header_time, int)
        or isinstance(header_time, bool)
        or not 0 < header_time <= _MAX_RENDERABLE_UNIX_TIME
    ):
        return (
            False,
            0,
            "ots proof 'header_time' must be a positive int no later than "
            f"{_MAX_RENDERABLE_UNIX_TIME}",
        )

    assert accumulator is not None  # `warning is None` above guarantees this
    if not hmac.compare_digest(accumulator, root_bytes):
        if legacy_accumulator_start is None:
            return False, 0, "ots op-chain result does not match header_merkle_root"
        message = (
            "ots op-chain result does not match header_merkle_root; anchor_profile "
            "signed-note-v2 requires the accumulator to start from "
            "SHA256(checkpoint.signed_note_bytes)"
        )
        legacy_accumulator, legacy_warning = replay_ots_op_chain(legacy_accumulator_start, ops)
        if (
            legacy_warning is None
            and legacy_accumulator is not None
            and hmac.compare_digest(legacy_accumulator, root_bytes)
        ):
            message += (
                " — this evidence looks like a note-v1 commitment presented as signed-note-v2"
            )
        return False, 0, message

    pinned = policy.pinned_headers.get(header_hash)
    if pinned is None:
        return False, 0, "header_hash is not in policy.pinned_headers"
    if pinned.merkle_root != proof.get("header_merkle_root"):
        return False, 0, "pinned header merkle_root does not match proof"
    if pinned.time != header_time:
        return False, 0, "pinned header time does not match proof"

    return True, pinned.time, None


def _walk_proofs(
    proofs: list[Any],
    accumulator_start: bytes,
    policy: AnchorPolicy,
    warnings: list[str],
    *,
    legacy_accumulator_start: bytes | None = None,
) -> tuple[bool, bool, int | None, int | None]:
    """Evaluate every proof in an already-shape-checked, already-capped
    `proofs` list, appending any diagnostics to `warnings` in place.

    Returns `(anchored, pq_surviving, anchored_before, anchored_after)` —
    the last two being the minimum and maximum pinned time over the proofs
    that actually VERIFIED (see `AnchorVerdict` for which question each
    answers). Both reductions are computed here, once, from the same walk:
    a proof that failed for any reason contributes to neither. Shared by
    both entry points so the proof-kind dispatch, the forward-compat
    "unknown kind is ignored, not fatal" rule and both aggregations exist in
    exactly one place — the only thing the two callers differ on is which
    bytes seed the accumulator, and whether the anchor-profile diagnostic
    (`legacy_accumulator_start`) applies at all.
    """
    anchored = False
    pq_surviving = False
    anchored_before: int | None = None
    anchored_after: int | None = None

    for i, proof in enumerate(proofs):
        if not isinstance(proof, dict):
            warnings.append(f"proof[{i}]: must be an object, got {type(proof).__name__}")
            continue
        kind = proof.get("kind")
        if kind == "ots":
            verified, header_time, warning = _verify_ots_proof(
                proof,
                accumulator_start,
                policy,
                legacy_accumulator_start=legacy_accumulator_start,
            )
            if warning is not None:
                warnings.append(f"proof[{i}]: {warning}")
            if verified:
                anchored = True
                pq_surviving = True
                if anchored_before is None or header_time < anchored_before:
                    anchored_before = header_time
                if anchored_after is None or header_time > anchored_after:
                    anchored_after = header_time
        elif kind == "rfc3161":
            token_b64 = proof.get("token_b64")
            if not isinstance(token_b64, str):
                warnings.append(
                    f"proof[{i}]: rfc3161 token_b64 must be a str, got {type(token_b64).__name__}"
                )
                continue
            anchored = True
            warnings.append(_RFC3161_WARNING)
        else:
            warnings.append(f"proof[{i}]: unknown proof kind {_trunc(kind)}, ignored")

    return anchored, pq_surviving, anchored_before, anchored_after


def verify_anchor(
    evidence: dict[str, Any], checkpoint: tlog.Checkpoint, policy: AnchorPolicy
) -> AnchorVerdict:
    """Verify an anchor-evidence bundle against `checkpoint` and `policy`.

    `evidence` is untrusted (comes from wherever the bundle was fetched) and
    this function NEVER raises because of it: any malformation — not a
    dict, missing/non-string/unparseable/mismatched `checkpoint`, `proofs`
    not a list, an oversized proof/op list, a non-dict proof, bad hex, an
    unknown op, a header not pinned — degrades to an
    `AnchorVerdict(anchored=False, ...)` with a warning naming the problem,
    and per-proof malformations simply drop that one proof rather than
    aborting the whole bundle (forward-compat: an unrecognized `kind` must
    not brick an old verifier reading a bundle produced by a newer one).

    `checkpoint` and `policy` are the trusted, verifier-config side: a
    non-`tlog.Checkpoint` `checkpoint` or a malformed `policy` raises
    `AnchorError` instead of degrading, since that's a caller bug.
    """
    if not isinstance(checkpoint, tlog.Checkpoint):
        raise AnchorError(f"checkpoint must be a tlog.Checkpoint, got {type(checkpoint).__name__}")
    policy = _validate_policy(policy)

    warnings: list[str] = []
    if not isinstance(evidence, dict):
        warnings.append(f"evidence must be an object, got {type(evidence).__name__}")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )

    if "checkpoint" not in evidence:
        warnings.append("evidence.checkpoint is required")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )
    checkpoint_text = evidence["checkpoint"]
    if not isinstance(checkpoint_text, str):
        warnings.append("evidence.checkpoint must be a str")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )
    if len(checkpoint_text) > _MAX_CHECKPOINT_TEXT_LEN:
        warnings.append(f"evidence.checkpoint exceeds max length {_MAX_CHECKPOINT_TEXT_LEN}")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )
    try:
        evidence_checkpoint = tlog.parse_checkpoint(checkpoint_text)
    except tlog.TlogError:
        warnings.append("evidence.checkpoint is not a valid signed checkpoint")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )
    if evidence_checkpoint.note_bytes != checkpoint.note_bytes:
        warnings.append("evidence.checkpoint does not match checkpoint argument")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )

    proofs = evidence.get("proofs")
    if not isinstance(proofs, list):
        warnings.append(f"evidence.proofs must be a list, got {type(proofs).__name__}")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )
    if len(proofs) > _MAX_PROOFS_PER_EVIDENCE:
        warnings.append(f"evidence.proofs exceeds max length {_MAX_PROOFS_PER_EVIDENCE}")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )

    anchor_profile = evidence.get("anchor_profile", _ANCHOR_PROFILE_NOTE_V1)
    if anchor_profile is None:  # explicit JSON null: treated the same as absent
        anchor_profile = _ANCHOR_PROFILE_NOTE_V1
    if not isinstance(anchor_profile, str) or anchor_profile not in _KNOWN_ANCHOR_PROFILES:
        warnings.append(
            "evidence.anchor_profile must be 'note-v1' or 'signed-note-v2', "
            f"got {_trunc(anchor_profile)}"
        )
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )
    note_only = anchor_profile != _ANCHOR_PROFILE_SIGNED_NOTE_V2
    # Both seeds are computed unconditionally (cheap — two SHA-256 calls):
    # `legacy_accumulator_start` is only used diagnostically, on a v2
    # op-chain mismatch, to name the common mistake of presenting a v1-shaped
    # commitment as v2 (`_verify_ots_proof`, G4/I2).
    legacy_accumulator_start = hashlib.sha256(checkpoint.note_bytes).digest()
    v2_accumulator_start = hashlib.sha256(checkpoint.signed_note_bytes).digest()
    accumulator_start = legacy_accumulator_start if note_only else v2_accumulator_start
    anchored, pq_surviving, anchored_before, anchored_after = _walk_proofs(
        proofs,
        accumulator_start,
        policy,
        warnings,
        legacy_accumulator_start=None if note_only else legacy_accumulator_start,
    )

    return AnchorVerdict(
        anchored=anchored,
        anchored_before=anchored_before,
        pq_surviving=pq_surviving,
        warnings=warnings,
        note_only=note_only,
        anchored_after=anchored_after,
    )


def verify_seeded_anchor(
    evidence: dict[str, Any], seed: bytes, policy: AnchorPolicy
) -> AnchorVerdict:
    """Verify an anchor-evidence bundle whose op-chains start from `seed`.

    Answers a different question from `verify_anchor`. That one asks "was
    THIS checkpoint timestamped?" and therefore binds every op-chain to a
    checkpoint's own bytes. This one asks "has real time reached date T?":
    the caller holds an OpenTimestamps attestation over the canonical bytes
    of some public document, and the only thing that matters is whether that
    document's op-chain climbs to a Bitcoin header the verifier has pinned.
    A pinned header's time is a lower bound on real time, so a verified
    anchor is evidence that the world has already passed it.

    `seed` is that document's bytes, and the accumulator starts from
    `SHA256(seed)` — exactly as `verify_anchor`'s legacy path starts from
    `SHA256(checkpoint.note_bytes)`. Passing a checkpoint's `note_bytes`
    therefore replays the identical chain, and the two entry points return
    the same anchor facts for the same `proofs`.

    There is no checkpoint on this path: `evidence["checkpoint"]` is neither
    required nor read, and an incoherent one changes nothing. There is no
    anchor profile either — profiles say which of a checkpoint's two
    byte-strings an accumulator committed to, a distinction that has no
    meaning once the seed is an arbitrary document, so
    `evidence["anchor_profile"]` is likewise not read and
    `AnchorVerdict.note_only` stays `False`.

    The verdict carries BOTH reductions over the verified `ots` proofs,
    because this entry point's caller asks the opposite question from
    `verify_anchor`'s and neither reduction answers both:

    - `anchored_before` stays the MINIMUM, byte-for-byte the semantics
      `verify_anchor` has always had. It is kept identical so two twin
      functions never answer the same evidence differently — a caller that
      moves a bundle between them must not see the floor shift.
    - `anchored_after` is the MAXIMUM, and it is the field a "has time
      reached T?" caller wants. The minimum is the wrong reduction for that
      question as soon as a bundle carries two valid proofs: an old anchor
      and a new one both verify, the minimum reports the old one, and the
      caller concludes time has not advanced — a false negative it cannot
      undo, since the maximum is not recoverable from a verdict that
      dropped it.

    On the single-proof evidence this is usually built for, the two
    coincide; they diverge exactly when it matters.

    `evidence` is untrusted and this function NEVER raises because of it —
    any malformation degrades to a warning, exactly as in `verify_anchor`.
    `seed` and `policy` are the trusted, caller-config side: a non-`bytes`
    or empty `seed`, or a malformed `policy`, raises `AnchorError`, since
    that signals a caller bug rather than adversarial input.
    """
    if not isinstance(seed, bytes):
        raise AnchorError(f"seed must be bytes, got {type(seed).__name__}")
    if not seed:
        raise AnchorError("seed must not be empty")
    policy = _validate_policy(policy)

    warnings: list[str] = []
    if not isinstance(evidence, dict):
        warnings.append(f"evidence must be an object, got {type(evidence).__name__}")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )

    proofs = evidence.get("proofs")
    if not isinstance(proofs, list):
        warnings.append(f"evidence.proofs must be a list, got {type(proofs).__name__}")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )
    if len(proofs) > _MAX_PROOFS_PER_EVIDENCE:
        warnings.append(f"evidence.proofs exceeds max length {_MAX_PROOFS_PER_EVIDENCE}")
        return AnchorVerdict(
            anchored=False, anchored_before=None, pq_surviving=False, warnings=warnings
        )

    # Every list-shaped cap is now behind us, so the first digest of the call
    # is bounded work: `_MAX_OPS_PER_PROOF` and `_MAX_OP_HEX_LEN` bound the
    # rest inside `replay_ots_op_chain`, which checks an operand's length
    # before ever concatenating or hashing it.
    accumulator_start = hashlib.sha256(seed).digest()
    anchored, pq_surviving, anchored_before, anchored_after = _walk_proofs(
        proofs, accumulator_start, policy, warnings
    )

    return AnchorVerdict(
        anchored=anchored,
        anchored_before=anchored_before,
        pq_surviving=pq_surviving,
        warnings=warnings,
        anchored_after=anchored_after,
    )


def validate_policy(policy: object) -> AnchorPolicy:
    """Deep-validate a trusted `AnchorPolicy`, raising `AnchorError` if it is
    malformed — the public name for what `verify_anchor` does to its own
    policy argument before touching any evidence.

    Exists so a caller that must validate its trusted configuration BEFORE
    deciding whether any anchor work is worth doing (the §11.4 quorum
    primitive, whose anchor check is deliberately last) does not have to
    reach for a private helper. Mirrors the TypeScript core's already-exported
    `validatePolicy`, so the two cores expose the same surface.
    """
    return _validate_policy(policy)


def passes_horizon(verdict: AnchorVerdict, policy: AnchorPolicy) -> bool:
    """True iff `policy.crqc_horizon is None`, or `verdict` is a PQ-surviving
    anchor whose time is strictly before the horizon.

    Pure function of `(verdict, policy)`: raises `AnchorError` only on a
    malformed `policy` (trusted, verifier-config side). Never raises on
    `verdict` — even a hand-built `AnchorVerdict` with wrong field types
    degrades to `False` rather than raising, since `verdict` carries no
    caller-config trust boundary of its own to enforce here.
    """
    policy = _validate_policy(policy)
    if policy.crqc_horizon is None:
        return True
    if not isinstance(verdict, AnchorVerdict):
        return False
    anchored_before = verdict.anchored_before
    if not isinstance(anchored_before, int) or isinstance(anchored_before, bool):
        return False
    return bool(verdict.pq_surviving) and anchored_before < policy.crqc_horizon
