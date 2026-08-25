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
# A real corroboration bundle carries a handful of proofs and a handful of
# ops per OTS attestation; these are generous headroom over that, not tuned
# limits — see tlog.py's `_MAX_NOTE_SIGNATURES` for the same rationale.
_MAX_PROOFS_PER_EVIDENCE = 64
_MAX_OPS_PER_PROOF = 64
# A legitimate full note is ~400KB worst case (64 signature lines, ML-DSA-65
# blobs ~4.4KB base64 each) — cap the evidence checkpoint text BEFORE it
# reaches `tlog.parse_checkpoint`, so a hostile multi-megabyte string cannot
# force large parse-time allocations.
_MAX_CHECKPOINT_TEXT_LEN = 500_000
_MAX_OP_HEX_LEN = 2048  # hex chars (1024 bytes) per append/prepend operand
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
    """The outcome of `verify_anchor` over one evidence bundle.

    `anchored_before` is the minimum pinned header time over verified `ots`
    (PQ-surviving) proofs only — `rfc3161` proofs never set it, even when
    `anchored` is `True` from `rfc3161` corroboration alone.

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
            accumulator = accumulator + operand if opcode == "append" else operand + accumulator
    return accumulator, None


def _verify_ots_proof(
    proof: dict[str, Any],
    accumulator_start: bytes,
    legacy_accumulator_start: bytes,
    note_only: bool,
    policy: AnchorPolicy,
) -> tuple[bool, int, str | None]:
    """Evaluate one `ots` proof: replay its op-chain from `accumulator_start`
    and cross-check the result against a header pinned in `policy`.

    Returns `(verified, header_time, warning)`. `header_time` is only
    meaningful when `verified` is `True` (it's the PINNED header's own
    time, not the proof's untrusted claim — the two are required to match
    before `verified` can be `True` at all, see the final check below).
    `warning` names the failure reason and is `None` only when `verified`
    is `True`.

    `legacy_accumulator_start`/`note_only` (G4/I2, attest-v0.2.md §11.1.1):
    on an op-chain mismatch under a declared `signed-note-v2` profile, also
    replay the SAME `ops` from the legacy `note-v1` seed
    (`legacy_accumulator_start`) — purely diagnostic, never changes
    `verified` — so the warning can name which seed the declared profile
    actually requires and flag the common mistake of presenting a v1-shaped
    commitment as v2.
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
        if note_only:
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
    anchored = False
    pq_surviving = False
    anchored_before: int | None = None

    for i, proof in enumerate(proofs):
        if not isinstance(proof, dict):
            warnings.append(f"proof[{i}]: must be an object, got {type(proof).__name__}")
            continue
        kind = proof.get("kind")
        if kind == "ots":
            verified, header_time, warning = _verify_ots_proof(
                proof, accumulator_start, legacy_accumulator_start, note_only, policy
            )
            if warning is not None:
                warnings.append(f"proof[{i}]: {warning}")
            if verified:
                anchored = True
                pq_surviving = True
                if anchored_before is None or header_time < anchored_before:
                    anchored_before = header_time
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

    return AnchorVerdict(
        anchored=anchored,
        anchored_before=anchored_before,
        pq_surviving=pq_surviving,
        warnings=warnings,
        note_only=note_only,
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
