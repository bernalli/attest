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

from attest import canon, keys, pq

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
