"""The Python half of a DELIBERATE two-core divergence (v0.2 §18.4).

A signed revocation record carried as a host-language object with the record's
members as its own data — an ORM row, a model object — is set aside by this
core and honoured by the TypeScript one. Both are conforming: §18.4 requires
own-data reconstruction. Python preserves a container subtype's base data but
cannot represent this non-container instance; TypeScript reconstructs its
enumerable own data-property descriptors.

THIS FILE IS ONE HALF OF A PAIR. The other is
`verifiers/ts/test/class-instance-divergence.test.ts`. Changes to the specified
behaviour require a joint revision of both tests and the normative paragraph.

The two defences divide the work, and neither covers the other. The text
fingerprint defends the TEXT: it makes an edit to the paragraph visible rather
than silent, and no digest can stop one. Independent review defends the
CHRONOLOGY: an author who changes a core AND its own expectation in one diff
passes every check here, by construction, because the oracle moved with the
code. A diff that touches a core and its expected outcome together is
therefore a change of MEANING, to be read as such — not a test being kept in
sync.

Each test asserts the REASON, not only the outcome: an outcome-only test stays
green the day the same outcome starts arriving from a different path.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from attest import canon, verify
from tests.test_blind_evidence_sinks import (
    _envelope,
    _refund_window_revocation_record,
    _trust_store,
    _wire,
)

_SPEC = Path(__file__).resolve().parents[1] / "docs" / "spec" / "attest-v0.2.md"
_DECLARATION = "**The cost is not paid identically by the two cores (normative).**"
_TS_TWIN = "verifiers/ts/test/class-instance-divergence.test.ts"


class OrmRow:
    """The record's members as INSTANCE attributes — own data, no `dict`.

    The shape a caller reaches for when the record arrives from a database row
    or a model object rather than from `json.loads`.
    """

    def __init__(self, record: dict[str, Any]) -> None:
        self.__dict__.update(record)


def _verify_with(record: Any) -> verify.VerificationResult:
    return verify.verify(
        _wire(_envelope(revocability="policy")), _trust_store(), revocation_view=[record]
    )


def _verify_with_revocability(revocability: str, record: Any) -> verify.VerificationResult:
    return verify.verify(
        _wire(_envelope(revocability=revocability)), _trust_store(), revocation_view=[record]
    )


def test_a_plain_record_is_honoured() -> None:
    """The control: the SAME record as a plain object revokes the receipt.

    Without this, the divergence test below could pass because the fixture
    never revoked anything.
    """
    result = _verify_with(_refund_window_revocation_record())
    assert result.revocation == "revoked"
    assert result.ok is False


def test_a_class_instance_is_set_aside_in_this_core() -> None:
    """The divergence itself: same signed record, carried as own instance data.

    The TypeScript twin asserts `revoked`/`ok: false` for this same shape.
    """
    result = _verify_with(OrmRow(_refund_window_revocation_record()))
    assert result.revocation == "unknown"
    assert result.ok is True
    # Silently: no warning marks the record as having been seen and rejected,
    # which is why the divergence is worth stating rather than discovering.
    assert list(result.warnings) == []


def test_the_reason_is_that_the_profile_cannot_represent_the_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Observe the same instance rejected by canonicalization during verify()."""
    record = _refund_window_revocation_record()
    instance = OrmRow(record)
    assert canon.canonical_bytes(record)

    with pytest.raises(canon.CanonError) as excinfo:
        canon.canonical_bytes(instance)
    expected_error = "type not representable in JSON: OrmRow"
    assert str(excinfo.value) == expected_error

    rejected: list[str] = []
    serialize = canon._serialize

    def observe(value: Any, out: list[str], depth: int = 1) -> None:
        try:
            serialize(value, out, depth)
        except canon.CanonError as exc:
            if value is instance:
                rejected.append(str(exc))
            raise

    monkeypatch.setattr(canon, "_serialize", observe)
    result = _verify_with(instance)
    assert rejected == [expected_error], "ORM_INSTANCE_MUST_REACH_CANON_REJECTION"
    assert result.revocation == "unknown"
    assert result.ok is True
    assert result.warnings == ()


def test_on_an_irrevocable_licence_the_two_cores_agree_for_opposite_reasons() -> None:
    """The `none` branch: same `ok`, and the reason is the only thing that differs.

    Outside the normative paragraph's stated preconditions, which fix
    `revocability: "policy"`. Here the class is what decides the outcome, per
    v0.1 §12.2: an irrevocable licence discards a matching record whatever its
    provenance. Both cores leave `ok` true, so the outcome alone cannot tell
    them apart — this core never ADMITS the record, and no warning marks it as
    set aside, while the TypeScript twin admits it, authenticates it, and
    discards it as irrevocable, saying so. A comparison reading only
    `revocation` and `ok` would call these two an agreement.
    """
    instance = _verify_with_revocability("none", OrmRow(_refund_window_revocation_record()))
    assert instance.revocation == "unknown"
    assert instance.ok is True
    # The distinguishing observable: nothing reports the record as set aside,
    # because it was never admitted in the first place.
    assert list(instance.warnings) == []

    # The control, and the half that makes the assertion above mean something:
    # as a plain object the SAME record IS admitted, and the irrevocable
    # licence is what discards it — a different literal, not a missing one.
    plain = _verify_with_revocability("none", _refund_window_revocation_record())
    assert plain.revocation == "invalid_revocation_ignored"
    assert any("irrevocable" in warning for warning in plain.warnings), (
        "IRREVOCABLE_DISCARD_MUST_BE_REPORTED"
    )


def test_the_divergence_is_declared_in_the_spec() -> None:
    """Pin the full normative text; a prose edit requires updating both twins."""
    spec = _SPEC.read_text(encoding="utf-8")
    assert _DECLARATION in spec, f"the normative declaration is missing from {_SPEC.name}"
    paragraph = spec[spec.index(_DECLARATION) :].split("\n", 1)[0]
    # The clause must keep naming both outcomes and both halves of the pair;
    # a paragraph that stops doing so no longer pins anything.
    assert '`revocation: "unknown"`' in paragraph
    assert '`revocation: "revoked"`' in paragraph
    assert Path(__file__).name in paragraph
    assert _TS_TWIN in paragraph
    assert sha256(paragraph.encode("utf-8")).hexdigest() == (
        "babb9cbc2032f79dedcd8f26ded79f4c351f5737a36424bd518470e46d27e9dc"
    ), "NORMATIVE_DIVERGENCE_PARAGRAPH_CHANGED"
