"""WitnessPolicy: closed policy documents, epoch validity, conflict predicate.

Contract: v0.2 §11.4 (P1.1b amendment). A `WitnessPolicy` is TRUSTED verifier
configuration that travels on the same rail as pinned log keys (`tlog.LogKey`):
it is packaged with the verifier release, never read off an evidence bundle.
That is why every function here RAISES on a malformed document — a bad policy
is a caller/configuration bug, not adversarial input (§10.2). Nothing in this
module parses evidence, and nothing in it verifies a signature.

The packaged default is the canonical EMPTY policy: with no epochs, no witness
is pinned, and `corroboration: "witnessed"` stays unreachable for anyone
installing the published packages until a future release pins real operators.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from attest import anchor, canon, keys, pq, tlog
from attest.dates import MAX_REPRESENTABLE_UNIX_SECONDS

# Public compatibility name for the shared timestamp bound.
MAX_COSIGNATURE_TIMESTAMP: Final = MAX_REPRESENTABLE_UNIX_SECONDS

SCHEMA_ID: Final = "attest-witness-policy-v1"

# §11.4 normative constants. Consumed by the quorum primitives; defined here
# because they are policy-level facts, not call-site choices.
MAX_WITNESS_SKEW_SECONDS: Final = 600
MAX_WITNESS_ANCHOR_DELAY_SECONDS: Final = 86400
MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE: Final = 9

ROLE_CORROBORATION: Final = "corroboration"
ROLE_SUNSET_ACTIVATION: Final = "sunset-activation"
_KNOWN_ROLES: Final = frozenset({ROLE_CORROBORATION, ROLE_SUNSET_ACTIVATION})

_DATE_FMT: Final = "%Y-%m-%dT%H:%M:%SZ"
# `\Z`, never `$`: Python's `$` also matches just before a trailing newline,
# while JavaScript's does not. The spec pins these grammars as `^...$`, but a
# `$` here would accept `"bootstrap-1\n"` in Python and reject it in the
# TypeScript core — a silent cross-core divergence in what a policy admits.
_EPOCH_ID_RE: Final = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}\Z")
_DNS_RE: Final = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\Z")

_POLICY_MEMBERS: Final = frozenset({"schema", "epochs"})
_EPOCH_MEMBERS: Final = frozenset(
    {"epoch_id", "not_before", "not_after", "log_origins", "threshold", "witnesses"}
)
_THRESHOLD_MEMBERS: Final = frozenset({"n", "m"})
_PIN_REQUIRED_MEMBERS: Final = frozenset(
    {
        "operator_id",
        "control_group",
        "name",
        "ed25519_pub_b64u",
        "mldsa_65_pub_b64u",
        "roles",
        "not_before",
        "not_after",
        "affiliated_domains",
    }
)
_PIN_OPTIONAL_MEMBERS: Final = frozenset({"compromised_after"})

CANONICAL_EMPTY_POLICY_BYTES: Final = canon.canonical_bytes({"schema": SCHEMA_ID, "epochs": []})


class WitnessError(ValueError):
    """A trusted witness policy is malformed — a configuration bug, not evidence."""


def _require_object(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WitnessError(f"{field} must be a JSON object")
    return value


def _require_exact_members(
    obj: dict[str, Any],
    required: frozenset[str],
    field: str,
    optional: frozenset[str] = frozenset(),
) -> None:
    """Closed-shape check: every required member present, nothing unknown."""
    present = set(obj)
    missing = required - present
    if missing:
        raise WitnessError(f"{field} missing member(s): {', '.join(sorted(missing))}")
    unknown = present - required - optional
    if unknown:
        raise WitnessError(f"{field} has unknown member(s): {', '.join(sorted(unknown))}")


def _require_timestamp(value: object, field: str) -> datetime:
    """Exact UTC ISO-8601 second timestamps only — no offsets, no fractions."""
    if not isinstance(value, str):
        raise WitnessError(f"{field} must be a UTC ISO-8601 second timestamp")
    try:
        parsed = datetime.strptime(value, _DATE_FMT)
    except ValueError as exc:
        raise WitnessError(f"{field} must be a UTC ISO-8601 second timestamp") from exc
    # Years 0000-0099 are refused: JavaScript's `Date.UTC` remaps them to
    # 1900-1999, so the TypeScript core cannot represent them and the same
    # document would be admissible in one core only.
    if parsed.year < 100:
        raise WitnessError(f"{field} must be a UTC ISO-8601 second timestamp")
    if parsed.strftime(_DATE_FMT) != value:
        raise WitnessError(f"{field} must be a UTC ISO-8601 second timestamp")
    return parsed.replace(tzinfo=UTC)


def _require_optional_timestamp(value: object, field: str) -> datetime | None:
    return None if value is None else _require_timestamp(value, field)


def _require_dns_name(value: object, field: str) -> str:
    if not isinstance(value, str) or not _DNS_RE.match(value):
        raise WitnessError(f"{field} must be a lowercase DNS name")
    return value


def _require_key_name(value: object, field: str) -> str:
    """The C2SP signed-note key-name grammar of §9.3, restated for policy input."""
    if (
        not isinstance(value, str)
        or not value
        or "+" in value
        or any(not "\x21" <= character <= "\x7e" for character in value)
    ):
        raise WitnessError(f"{field} must be non-empty printable ASCII without '+'")
    return value


def _require_origin(value: object, field: str) -> str:
    """Non-empty printable ASCII, the §9.3 checkpoint-origin grammar.

    Enforced here and not only at use: without it a non-ASCII origin would sort
    by code point in Python and by UTF-16 code unit in TypeScript, so the two
    cores would disagree on whether the same `log_origins` array is sorted.
    """
    if (
        not isinstance(value, str)
        or not value
        or any(not "\x20" <= character <= "\x7e" for character in value)
    ):
        raise WitnessError(f"{field} must be a non-empty printable ASCII origin")
    return value


def _require_sorted_unique(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise WitnessError(f"{field} must be an array of strings")
    items: list[str] = list(value)
    if items != sorted(items):
        raise WitnessError(f"{field} must be sorted")
    if len(set(items)) != len(items):
        raise WitnessError(f"{field} must be duplicate-free")
    return tuple(items)


_MAX_SAFE_INT: Final = 2**53 - 1


def _require_positive_int(value: object, field: str) -> int:
    # `bool` is an `int` subclass in Python and would silently pass; the
    # TypeScript core has no such hole, so reject it to keep the cores equal.
    # The upper bound is the other half of that parity: TypeScript cannot
    # represent an integer past 2^53-1 exactly, so neither core accepts one.
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise WitnessError(f"{field} must be a positive integer")
    if value > _MAX_SAFE_INT:
        raise WitnessError(f"{field} must be a positive integer")
    return value


def _require_pub(value: object, field: str, length: int) -> bytes:
    if not isinstance(value, str):
        raise WitnessError(f"{field} must be a base64url string")
    try:
        decoded = keys.b64u_decode(value)
    except ValueError as exc:
        raise WitnessError(f"{field} must be canonical base64url") from exc
    if len(decoded) != length:
        raise WitnessError(f"{field} must decode to {length} bytes")
    return decoded


@dataclass(frozen=True)
class Threshold:
    """`n` distinct activation-role control groups, `m` of them required."""

    n: int
    m: int


@dataclass(frozen=True)
class WitnessPin:
    """One pinned witness identity inside an immutable epoch.

    `compromise_declared` carries the tri-state of §11.4 that a plain
    `str | None` cannot: ABSENT (no compromise declared) is not the same as an
    explicit `null` (onset unknown — the pin contributes no standing ever).
    """

    operator_id: str
    control_group: str
    name: str
    ed25519_pub: bytes
    mldsa_65_pub: bytes | None
    roles: tuple[str, ...]
    not_before: datetime
    not_after: datetime | None
    affiliated_domains: tuple[str, ...]
    compromise_declared: bool
    compromised_after: datetime | None

    def covers(self, at: datetime) -> bool:
        """Validity window, inclusive at both declared boundaries."""
        if at < self.not_before:
            return False
        return self.not_after is None or at <= self.not_after

    def has_standing_at(self, at: datetime) -> bool:
        """Whether this pin may contribute standing for an observation at `at`."""
        if not self.covers(at):
            return False
        if not self.compromise_declared:
            return True
        if self.compromised_after is None:
            # Onset unknown: fail closed at every time, forever.
            return False
        return at <= self.compromised_after


@dataclass(frozen=True)
class WitnessEpoch:
    """An immutable epoch: a fixed committee over a fixed validity window."""

    epoch_id: str
    not_before: datetime
    not_after: datetime | None
    log_origins: tuple[str, ...]
    threshold: Threshold
    witnesses: tuple[WitnessPin, ...]

    def covers(self, at: datetime) -> bool:
        if at < self.not_before:
            return False
        return self.not_after is None or at <= self.not_after

    def is_conflicted(self, pin: WitnessPin, conflict_domain: str) -> bool:
        """§11.4's two-limb predicate, parameterized by `conflict_domain`.

        Direct: the pin itself names the domain. Transitive: some pin in this
        epoch names the domain and shares this pin's control group.

        There is deliberately no inverse of this predicate: domain inequality
        MUST NOT establish independence, and policy v1 defines no positive
        independence certificate.
        """
        if conflict_domain in pin.affiliated_domains:
            return True
        return any(
            conflict_domain in other.affiliated_domains and other.control_group == pin.control_group
            for other in self.witnesses
        )


@dataclass(frozen=True)
class WitnessPolicy:
    """A parsed, closed `attest-witness-policy-v1` document."""

    epochs: tuple[WitnessEpoch, ...]

    def epoch(self, epoch_id: str) -> WitnessEpoch | None:
        """Resolve an epoch by its identifier, or `None` when unknown.

        Evidence names an epoch explicitly (§10.2); the current epoch is never
        substituted for one that fails to resolve.
        """
        for epoch in self.epochs:
            if epoch.epoch_id == epoch_id:
                return epoch
        return None


def _parse_pin(raw: object, index: int) -> WitnessPin:
    field = f"witnesses[{index}]"
    pin = _require_object(raw, field)
    _require_exact_members(pin, _PIN_REQUIRED_MEMBERS, field, _PIN_OPTIONAL_MEMBERS)

    operator_id = _require_dns_name(pin["operator_id"], f"{field}.operator_id")
    control_group = _require_dns_name(pin["control_group"], f"{field}.control_group")
    name = _require_key_name(pin["name"], f"{field}.name")

    roles = _require_sorted_unique(pin["roles"], f"{field}.roles")
    unknown_roles = set(roles) - _KNOWN_ROLES
    if unknown_roles:
        raise WitnessError(f"{field}.roles has unknown role(s): {', '.join(sorted(unknown_roles))}")

    affiliated_domains = _require_sorted_unique(
        pin["affiliated_domains"], f"{field}.affiliated_domains"
    )
    for domain in affiliated_domains:
        _require_dns_name(domain, f"{field}.affiliated_domains member")
    if operator_id not in affiliated_domains:
        raise WitnessError(f"{field}.affiliated_domains must contain its own operator_id")

    ed25519_pub = _require_pub(pin["ed25519_pub_b64u"], f"{field}.ed25519_pub_b64u", 32)
    mldsa_raw = pin["mldsa_65_pub_b64u"]
    if mldsa_raw is None:
        # The activation leg may be absent ONLY for a pin that cannot activate.
        if ROLE_SUNSET_ACTIVATION in roles:
            raise WitnessError(
                f"{field}.mldsa_65_pub_b64u may be null only without the "
                f"{ROLE_SUNSET_ACTIVATION} role"
            )
        mldsa_65_pub = None
    else:
        mldsa_65_pub = _require_pub(mldsa_raw, f"{field}.mldsa_65_pub_b64u", pq.ML_DSA_65_PK_LEN)

    not_before = _require_timestamp(pin["not_before"], f"{field}.not_before")
    not_after = _require_optional_timestamp(pin["not_after"], f"{field}.not_after")
    if not_after is not None and not_after < not_before:
        raise WitnessError(f"{field}.not_after precedes not_before")

    compromise_declared = "compromised_after" in pin
    compromised_after = (
        _require_optional_timestamp(pin["compromised_after"], f"{field}.compromised_after")
        if compromise_declared
        else None
    )

    return WitnessPin(
        operator_id=operator_id,
        control_group=control_group,
        name=name,
        ed25519_pub=ed25519_pub,
        mldsa_65_pub=mldsa_65_pub,
        roles=roles,
        not_before=not_before,
        not_after=not_after,
        affiliated_domains=affiliated_domains,
        compromise_declared=compromise_declared,
        compromised_after=compromised_after,
    )


def _parse_threshold(raw: object, field: str) -> Threshold:
    threshold = _require_object(raw, field)
    _require_exact_members(threshold, _THRESHOLD_MEMBERS, field)
    n = _require_positive_int(threshold["n"], f"{field}.n")
    m = _require_positive_int(threshold["m"], f"{field}.m")
    if m > n:
        raise WitnessError(f"{field}.m must not exceed {field}.n")
    # §11.4's committee ceiling: a committee larger than the ceiling could
    # never be satisfied, so the policy is refused at parse time. Whether `n`
    # MATCHES the epoch's activation control groups is checked where those
    # groups are actually counted, not here.
    if n > MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE:
        raise WitnessError(f"{field}.n must not exceed {MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE}")
    return Threshold(n=n, m=m)


def _parse_epoch(raw: object, index: int) -> WitnessEpoch:
    field = f"epochs[{index}]"
    epoch = _require_object(raw, field)
    _require_exact_members(epoch, _EPOCH_MEMBERS, field)

    epoch_id = epoch["epoch_id"]
    if not isinstance(epoch_id, str) or not _EPOCH_ID_RE.match(epoch_id):
        raise WitnessError(f"{field}.epoch_id must match ^[a-z0-9][a-z0-9._-]{{0,127}}$")

    not_before = _require_timestamp(epoch["not_before"], f"{field}.not_before")
    not_after = _require_optional_timestamp(epoch["not_after"], f"{field}.not_after")
    if not_after is not None and not_after < not_before:
        raise WitnessError(f"{field}.not_after precedes not_before")

    log_origins = _require_sorted_unique(epoch["log_origins"], f"{field}.log_origins")
    for origin in log_origins:
        _require_origin(origin, f"{field}.log_origins member")
    threshold = _parse_threshold(epoch["threshold"], f"{field}.threshold")

    raw_witnesses = epoch["witnesses"]
    if not isinstance(raw_witnesses, list):
        raise WitnessError(f"{field}.witnesses must be an array")
    witnesses = tuple(_parse_pin(item, position) for position, item in enumerate(raw_witnesses))

    return WitnessEpoch(
        epoch_id=epoch_id,
        not_before=not_before,
        not_after=not_after,
        log_origins=log_origins,
        threshold=threshold,
        witnesses=witnesses,
    )


def parse_policy(document: object) -> WitnessPolicy:
    """Parse a TRUSTED `attest-witness-policy-v1` document.

    Raises `WitnessError` on anything malformed: this input is verifier
    configuration, so a defect here is a caller bug and must be loud, never a
    silent downgrade (§10.2's trusted-side discipline).
    """
    policy = _require_object(document, "witness policy")
    _require_exact_members(policy, _POLICY_MEMBERS, "witness policy")
    if policy["schema"] != SCHEMA_ID:
        raise WitnessError(f"witness policy schema must be {SCHEMA_ID!r}")

    raw_epochs = policy["epochs"]
    if not isinstance(raw_epochs, list):
        raise WitnessError("witness policy epochs must be an array")
    epochs = tuple(_parse_epoch(item, index) for index, item in enumerate(raw_epochs))

    seen: set[str] = set()
    for epoch in epochs:
        if epoch.epoch_id in seen:
            raise WitnessError(f"duplicate epoch_id: {epoch.epoch_id!r}")
        seen.add(epoch.epoch_id)

    return WitnessPolicy(epochs=epochs)


def load_policy(data: bytes) -> WitnessPolicy:
    """Parse a policy from its canonical JCS bytes — the supported entry point.

    Going through `canon.loads_strict` is what makes the two cores agree on
    NUMBERS: JSON `1.0` is rejected here as a non-integer literal, while a
    TypeScript caller who hands `parse_policy` an in-memory `{n: 1.0}` cannot
    tell it from `{n: 1}` at all (they are the same value). Loading from bytes
    removes that asymmetry instead of papering over it.
    """
    return parse_policy(canon.loads_strict(data))


def policy_bytes(document: object) -> bytes:
    """Canonical JCS bytes of a policy document (§11.4 packaged-byte assertions)."""
    return canon.canonical_bytes(document)


# --- C2SP tlog-cosignature (v0.2 §9.2) -------------------------------------

# Type `0x04` is the interoperable Ed25519 cosignature already emitted by real
# witnesses. Type `0x06` is an ML-DSA-44 signature over the DIFFERENT
# `subtree/v1` structure and MUST NOT count as either leg (§9.2).
COSIGNATURE_SIG_TYPE: Final = b"\x04"
_COSIGNATURE_HEADER: Final = b"cosignature/v1\n"
_KEY_ID_LEN: Final = 4
_TIMESTAMP_LEN: Final = 8
_ED25519_SIG_LEN: Final = 64
_COSIGNATURE_BLOB_LEN: Final = _KEY_ID_LEN + _TIMESTAMP_LEN + _ED25519_SIG_LEN

WARN_INDEPENDENCE_NOT_ESTABLISHED: Final = "witness_independence_not_established"


def cosignature_message(note_bytes: bytes, timestamp: int) -> bytes:
    """The exact bytes a witness signs: header, time line, then the note body.

    `cosignature/v1\\n` provides the domain separation that stops a signature
    made over a checkpoint body from being transported into a witness
    assertion, or the reverse (§9.2).
    """
    if not isinstance(note_bytes, bytes):
        raise WitnessError("note_bytes must be bytes")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        raise WitnessError("timestamp must be a non-negative POSIX integer")
    return _COSIGNATURE_HEADER + f"time {timestamp}\n".encode() + note_bytes


def cosignature_key_id(name: str, ed25519_pub: bytes) -> bytes:
    """`SHA-256(name || "\\n" || 0x04 || pub)[:4]` — the C2SP type-`0x04` key ID.

    Distinct from the same witness's checkpoint-type key ID by construction:
    the signature type is part of the hashed input.
    """
    return tlog.key_hash(name, COSIGNATURE_SIG_TYPE, ed25519_pub)


@dataclass(frozen=True)
class CorroborationVerdict:
    """Whether a checkpoint reached `witnessed`, and what must be reported.

    `warnings` carries `witness_independence_not_established` on EVERY
    witnessed verdict and nothing else, ever: §11.4 permits no other literal
    from this layer, so a failed cosignature is silent by construction.
    """

    witnessed: bool
    warnings: list[str]


def _counts_as_corroboration(
    blob: object, pin: WitnessPin, note_bytes: bytes, epoch: WitnessEpoch
) -> bool:
    """Whether one signature-line blob is a valid cosignature by `pin`.

    Never raises: these bytes come from an untrusted note.
    """
    if not isinstance(blob, bytes) or len(blob) != _COSIGNATURE_BLOB_LEN:
        return False
    if blob[:_KEY_ID_LEN] != cosignature_key_id(pin.name, pin.ed25519_pub):
        return False
    timestamp = int.from_bytes(blob[_KEY_ID_LEN : _KEY_ID_LEN + _TIMESTAMP_LEN], "big")
    if timestamp > MAX_COSIGNATURE_TIMESTAMP:
        return False
    observed_at = datetime.fromtimestamp(timestamp, UTC)
    # The pin must have standing AT the moment it claims to have observed —
    # not at the verifier's local clock, which would break eternal
    # verifiability for an old but valid observation.
    # §10.1 requires an epoch-VALID witness: the epoch's own inclusive window
    # bounds the observation just as the pin's does.
    if not epoch.covers(observed_at) or not pin.has_standing_at(observed_at):
        return False
    message = cosignature_message(note_bytes, timestamp)
    return keys.verify_strict(message, blob[_KEY_ID_LEN + _TIMESTAMP_LEN :], pin.ed25519_pub)


def _counts_safely(blob: object, pin: WitnessPin, note_bytes: bytes, epoch: WitnessEpoch) -> bool:
    """`_counts_as_corroboration` with per-LINE failure confinement.

    Confining the failure to one line, rather than wrapping the whole scan,
    is what stops an untrusted line from vetoing a later valid one: an
    attacker could otherwise suppress genuine corroboration just by
    prepending garbage under the witness's own name. The exception is
    swallowed rather than logged because §11.4 permits this layer no
    diagnostic beyond the independence warning.
    """
    try:
        return _counts_as_corroboration(blob, pin, note_bytes, epoch)
    except Exception:
        return False


def evaluate_corroboration(
    *,
    checkpoint: tlog.Checkpoint,
    signatures: list[tuple[str, bytes]],
    policy: WitnessPolicy,
    epoch_id: object,
) -> CorroborationVerdict:
    """Decide whether one pinned witness cosignature reaches `witnessed`.

    §10.1's one-`0x04` rule: a single valid Ed25519 cosignature by a pinned,
    epoch-resolved witness holding the `corroboration` role is sufficient.

    Every failure — unresolvable epoch, unpinned key, wrong role, expired or
    compromised pin, bad signature, wrong blob shape, `0x06` — returns
    `witnessed=False` with NO warning, leaving the caller's existing standing
    untouched. That silence is normative (§11.4), not an omission.
    """
    if not isinstance(epoch_id, str):
        return CorroborationVerdict(witnessed=False, warnings=[])
    epoch = policy.epoch(epoch_id)
    if epoch is None:
        return CorroborationVerdict(witnessed=False, warnings=[])

    # The epoch's scope is part of what makes a witness pinned FOR THIS LOG:
    # an epoch that lists other origins says nothing about this checkpoint.
    # Fail-closed, so an epoch with no origins corroborates nothing.
    if checkpoint.origin not in epoch.log_origins:
        return CorroborationVerdict(witnessed=False, warnings=[])

    for name, blob in signatures:
        for pin in epoch.witnesses:
            if pin.name != name or ROLE_CORROBORATION not in pin.roles:
                # A line naming someone else is a signed-note convention,
                # never a fatal condition (§9.2).
                continue
            if _counts_safely(blob, pin, checkpoint.note_bytes, epoch):
                return CorroborationVerdict(
                    witnessed=True, warnings=[WARN_INDEPENDENCE_NOT_ESTABLISHED]
                )

    return CorroborationVerdict(witnessed=False, warnings=[])


# --- Standalone activation-grade hybrid quorum (v0.2 §11.4) ----------------
#
# A STANDALONE primitive: §11.4 defines no grant consumer, and nothing below
# knows about receipts, result vocabularies, or grant state. It answers one
# question — did a quorum of pinned witnesses observe THIS checkpoint, and by
# when — and returns the conservative time at which that became true.

# The activation leg's own C2SP type: `0xff` (the registry's extension
# mechanism) followed by an identifier distinct from the checkpoint's own
# `attest-ml-dsa-65`. Sharing the checkpoint identifier would let a
# checkpoint signature be presented as a witness assertion.
PQ_COSIGNATURE_SIG_TYPE: Final = b"\xff" + b"attest-cosignature-ml-dsa-65-v1"
_PQ_COSIGNATURE_BLOB_LEN: Final = _KEY_ID_LEN + _TIMESTAMP_LEN + pq.ML_DSA_65_SIG_LEN


@dataclass(frozen=True)
class ActivationWitnessQuorumResult:
    """Quorum standing and conservative witness time — nothing else.

    `witness_time` is `T = min(t_i)` over the counting votes, and is `None`
    whenever `valid` is `False`: an invalid quorum has no time to report.
    """

    valid: bool
    witness_time: int | None
    counting_control_groups: tuple[str, ...]


_INVALID_QUORUM: Final = ActivationWitnessQuorumResult(
    valid=False, witness_time=None, counting_control_groups=()
)


@dataclass(frozen=True)
class _CandidatePair:
    """One pin's unambiguous `0x04`+`0xff` candidate, before any verification."""

    pin: WitnessPin
    timestamp: int
    ed25519_signature: bytes
    mldsa_signature: bytes


def _at(timestamp: int) -> datetime:
    """A POSIX second as the aware UTC instant the policy windows compare to."""
    return datetime.fromtimestamp(timestamp, UTC)


def _leg(blob: object, key_id: bytes, blob_len: int) -> tuple[int, bytes] | None:
    """Structural match of one signature-line blob against one expected key ID.

    Pure byte work — no signature is verified here, which is what lets the
    committee ceiling and the ambiguity rule bite before any crypto.
    """
    if not isinstance(blob, bytes) or len(blob) != blob_len:
        return None
    if blob[:_KEY_ID_LEN] != key_id:
        return None
    timestamp = int.from_bytes(blob[_KEY_ID_LEN : _KEY_ID_LEN + _TIMESTAMP_LEN], "big")
    if timestamp > MAX_COSIGNATURE_TIMESTAMP:
        return None
    return timestamp, blob[_KEY_ID_LEN + _TIMESTAMP_LEN :]


def _candidate_for(
    pin: WitnessPin, signatures: list[tuple[str, bytes]]
) -> _CandidatePair | None | str:
    """This pin's candidate pair, `None` if it presented none, or `"ambiguous"`.

    Ambiguity is a hard failure rather than a choice, because choosing between
    two candidate legs would mean verifying both — exactly the work §11.4
    requires to be bounded before crypto begins.
    """
    if pin.mldsa_65_pub is None:
        return None
    ed_key_id = cosignature_key_id(pin.name, pin.ed25519_pub)
    pq_key_id = tlog.key_hash(pin.name, PQ_COSIGNATURE_SIG_TYPE, pin.mldsa_65_pub)

    ed_legs: list[tuple[int, bytes]] = []
    pq_legs: list[tuple[int, bytes]] = []
    for name, blob in signatures:
        if name != pin.name:
            # A line naming someone else is a signed-note convention (§9.2).
            continue
        ed_leg = _leg(blob, ed_key_id, _COSIGNATURE_BLOB_LEN)
        if ed_leg is not None:
            ed_legs.append(ed_leg)
            continue
        pq_leg = _leg(blob, pq_key_id, _PQ_COSIGNATURE_BLOB_LEN)
        if pq_leg is not None:
            pq_legs.append(pq_leg)

    if len(ed_legs) > 1 or len(pq_legs) > 1:
        return "ambiguous"
    if not ed_legs or not pq_legs:
        return None
    (ed_time, ed_signature), (pq_time, pq_signature) = ed_legs[0], pq_legs[0]
    # Both legs sign the byte-identical payload, timestamp included: legs
    # carrying different times are not a pair at all.
    if ed_time != pq_time:
        return None
    return _CandidatePair(
        pin=pin,
        timestamp=ed_time,
        ed25519_signature=ed_signature,
        mldsa_signature=pq_signature,
    )


def _verifies(candidate: _CandidatePair, note_bytes: bytes) -> bool:
    """Fail-closed AND over both legs of one candidate pair.

    Ed25519 first, and the ML-DSA leg is never reached when it fails: an
    attacker who can put arbitrary lines in a note must not be able to buy
    post-quantum verification work with a garbage classical signature.
    """
    message = cosignature_message(note_bytes, candidate.timestamp)
    if not keys.verify_strict(message, candidate.ed25519_signature, candidate.pin.ed25519_pub):
        return False
    assert candidate.pin.mldsa_65_pub is not None  # guaranteed by `_candidate_for`
    return pq.verify_strict(message, candidate.mldsa_signature, candidate.pin.mldsa_65_pub)


def evaluate_activation_witness_quorum(
    checkpoint_text: object,
    *,
    witness_policy: WitnessPolicy,
    epoch_id: object,
    expected_origin: str,
    anchor_evidence: dict[str, Any],
    anchor_policy: anchor.AnchorPolicy,
    conflict_domain: str,
) -> ActivationWitnessQuorumResult:
    """Evaluate the reusable activation-grade hybrid quorum of §11.4.

    Trusted configuration — the witness policy, the anchor policy, the
    expected origin, the conflict domain — RAISES when malformed, on the same
    rail as pinned log keys. Everything untrusted — the checkpoint text, its
    signature lines, the anchor evidence — degrades to
    `valid=False`, never an exception.

    The evaluation order is normative, not incidental: the committee ceiling
    and the one-candidate-per-control-group rule are enforced BEFORE any
    signature verification, so a hostile policy or note cannot turn this
    primitive into a work amplifier.

    No local clock is consulted anywhere: an observation that was valid when
    it was made stays verifiable forever.
    """
    # 1. Trusted configuration.
    if not isinstance(witness_policy, WitnessPolicy):
        raise WitnessError("witness_policy must be a parsed WitnessPolicy")
    if not isinstance(anchor_policy, anchor.AnchorPolicy):
        raise WitnessError("anchor_policy must be an anchor.AnchorPolicy")
    anchor.validate_policy(anchor_policy)
    expected_origin = _require_origin(expected_origin, "expected_origin")
    conflict_domain = _require_dns_name(conflict_domain, "conflict_domain")

    # 2. The named epoch, never a substitute for one that fails to resolve.
    if not isinstance(epoch_id, str):
        return _INVALID_QUORUM
    epoch = witness_policy.epoch(epoch_id)
    if epoch is None:
        return _INVALID_QUORUM

    # 3-4. Committee form. `threshold.n` counts distinct activation-role
    # control groups, so the ceiling is a property of the epoch's MEMBERSHIP,
    # not of the number the policy declares — and it is checked first, before
    # the declared form, because it is the bound on work.
    #
    # Measured, not assumed: the ceiling here is REDUNDANT today. `n > 9` is
    # already refused at parse time, so an epoch that trips the ceiling also
    # trips the form check, and no case can distinguish the two — deleting
    # either one alone leaves every parity case green, deleting both turns
    # `committee-of-ten` red. It stays because §11.4 states it normatively
    # ("MUST be enforced before any Ed25519 or ML-DSA-65 signature
    # verification") and because a future policy revision that relaxes the
    # parser must not silently relax this.
    committee = {
        pin.control_group for pin in epoch.witnesses if ROLE_SUNSET_ACTIVATION in pin.roles
    }
    if len(committee) > MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE:
        return _INVALID_QUORUM
    if len(committee) != epoch.threshold.n:
        return _INVALID_QUORUM

    # 5. Origin scope: an epoch listing other origins says nothing about this
    # log. Fail-closed, so an epoch with no origins carries no quorum.
    if expected_origin not in epoch.log_origins:
        return _INVALID_QUORUM

    # 6-7. The checkpoint is untrusted; parse it once, and only structurally
    # (this primitive never authenticates the checkpoint — that is the
    # caller's log key, not a witness's business).
    if not isinstance(checkpoint_text, str):
        return _INVALID_QUORUM
    try:
        checkpoint = tlog.parse_checkpoint(checkpoint_text)
        signatures = tlog.note_signatures(checkpoint_text)
    except tlog.TlogError:
        return _INVALID_QUORUM
    if checkpoint.origin != expected_origin:
        return _INVALID_QUORUM

    # 8. Conflict exclusion, before crypto and before pairing.
    eligible = [
        pin
        for pin in epoch.witnesses
        if ROLE_SUNSET_ACTIVATION in pin.roles and not epoch.is_conflicted(pin, conflict_domain)
    ]

    # 9. At most one unambiguous candidate pair per control group.
    candidates: dict[str, _CandidatePair] = {}
    for pin in eligible:
        candidate = _candidate_for(pin, signatures)
        if candidate is None:
            continue
        if isinstance(candidate, str):  # "ambiguous"
            return _INVALID_QUORUM
        if candidate.pin.control_group in candidates:
            return _INVALID_QUORUM
        candidates[candidate.pin.control_group] = candidate

    # 10-11. Fail-closed AND over both legs, one pair per group at most.
    verified = [
        candidate
        for candidate in candidates.values()
        if _verifies(candidate, checkpoint.note_bytes)
    ]
    if not verified:
        return _INVALID_QUORUM

    # 12-16. `T = min(t_i)` is the conservative quorum time: taking the
    # maximum would let the latest signer stretch the anchor window every
    # earlier observation is judged by. But §11.4 defines T over COUNTING
    # votes, and standing is itself judged at T, so the two facts form a fixed
    # point. Iterating is what makes T a property of the counting set rather
    # than of the presented set.
    counting = verified
    while True:
        if not counting:
            return _INVALID_QUORUM
        quorum_time = min(candidate.timestamp for candidate in counting)
        quorum_at = _at(quorum_time)
        if not epoch.covers(quorum_at):
            return _INVALID_QUORUM
        next_counting = [
            candidate for candidate in counting if candidate.pin.has_standing_at(quorum_at)
        ]
        if next_counting == counting:
            break
        counting = next_counting

    if len(counting) < epoch.threshold.m:
        return _INVALID_QUORUM

    # 17-18. Every counting vote already refers to this checkpoint: its note
    # body is inside the payload each leg signed. What remains is the skew.
    times = [candidate.timestamp for candidate in counting]
    latest = max(times)
    if latest - min(times) > MAX_WITNESS_SKEW_SECONDS:
        return _INVALID_QUORUM

    # 19-21. A full `signed-note-v2` anchor over the complete signed note —
    # cosignature lines included — is what ties these observations to a
    # PQ-surviving time. A `note-v1` anchor commits to the unsigned header
    # alone and so says nothing about the lines being counted here.
    verdict = anchor.verify_anchor(anchor_evidence, checkpoint, anchor_policy)
    if not verdict.pq_surviving or verdict.note_only or verdict.anchored_before is None:
        return _INVALID_QUORUM
    anchored_at = verdict.anchored_before
    if not latest <= anchored_at <= quorum_time + MAX_WITNESS_ANCHOR_DELAY_SECONDS:
        return _INVALID_QUORUM

    # 22.
    return ActivationWitnessQuorumResult(
        valid=True,
        witness_time=quorum_time,
        counting_control_groups=tuple(sorted({c.pin.control_group for c in counting})),
    )
