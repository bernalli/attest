"""Adversarial tests for the v0.2 §19 compromise floor and cutoff inputs.

These cases deliberately use valid signatures around malformed-but-JSON-shaped
manifest data. A signature authenticates its bytes; it must not turn an
ambiguous key lifecycle into a way to resurrect a compromised kid.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from attest import issue, keys, manifests, verify
from tests.helpers import make_payload

ISSUER = "store.example.com"
KID = f"{ISSUER}/keys/adversarial#ed25519-1"
DECLARER_KID = f"{ISSUER}/keys/adversarial#ed25519-2"

# Fixed test-only seeds.
KP = keys.from_seed(bytes([71]) * 32)
DECLARER_KP = keys.from_seed(bytes([72]) * 32)

VALID_FROM = "2026-01-01T00:00:00Z"


def _wire(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


def _entry(kid: str, kp: keys.SigningKeyPair, status: str = "active") -> dict[str, Any]:
    return manifests.key_entry(kid, kp.pub, VALID_FROM, None, status)


def _manifest(entries: list[dict[str, Any]], version: object = 1) -> dict[str, Any]:
    """Sign a manifest WITHOUT the public builder.

    These are hostile or already-published views, not issuance: since the
    v0.1 §7.1 amendment (2026-08-26) `build_key_manifest` refuses to sign a
    duplicated `kid`, which is exactly the shape the verifier side must still
    be tested against. The body and signature are byte-identical to what the
    builder produces for every manifest the builder still accepts.
    """
    body: dict[str, Any] = {
        "issuer": ISSUER,
        "manifest_version": version,
        "issued_at": VALID_FROM,
        "keys": entries,
    }
    body["manifest_signature"] = manifests.sign_signature_block(
        manifests._signable(body),  # type: ignore[attr-defined]
        DECLARER_KP,
        DECLARER_KID,
    )
    return body


def _trust(
    manifest: dict[str, Any], *, chain: list[dict[str, Any]] | None = None
) -> verify.TrustStore:
    return verify.TrustStore(
        manifests={ISSUER: manifest},
        provenance={ISSUER: "tls"},
        chains={} if chain is None else {ISSUER: chain},
    )


def _receipt() -> dict[str, Any]:
    return issue.issue(make_payload(), KP, KID)


def test_duplicate_trusted_kid_cannot_hide_compromise_from_status_floor() -> None:
    """v0.1 §7.1: an ambiguous manifest is refused WHEREVER it is consumed.

    Both halves below are that one rule. The trusted manifest is refused by
    `verify()`'s preflight, one layer above the status floor, so the receipt
    dies with the structural error rather than the compromise one; a HELD
    CHAIN MEMBER is refused on the same terms, because §19.3 items 3a/3b
    consume it to authenticate the floor and the cutoff.

    An earlier revision of this test asserted the opposite for the chain half
    — that the floor was left to decide "for every manifest the preflight does
    not cover" — and pinned it as correct. It was not: reading a status out of
    an ambiguous held manifest lets ONE duplicated entry marking the declaring
    signer `compromised` deny the §19 cutoff while its `active` sibling still
    supplies a valid vouching signer, and every forgery anchored after a key
    theft then verifies `ok: true`. Leaf `41x` pins the same refusal through
    the public corpus.
    """
    duplicated = [
        _entry(KID, KP, "active"),
        _entry(KID, KP, "compromised"),
        _entry(DECLARER_KID, DECLARER_KP, "active"),
    ]

    structural = verify.verify(_wire(_receipt()), _trust(_manifest(duplicated)))

    assert structural.signature == "invalid"
    assert any("duplicate kid" in error for error in structural.errors)

    # The same ambiguity held as evidence rather than as the trust anchor:
    # refused too, and BEFORE any status is read out of it.
    clean = _manifest([_entry(KID, KP, "active"), _entry(DECLARER_KID, DECLARER_KP, "active")])
    from_chain = verify.verify(
        _wire(_receipt()), _trust(clean, chain=[_manifest(duplicated), clean])
    )

    assert from_chain.signature == "invalid"
    assert any("duplicate kid" in error for error in from_chain.errors)


def test_duplicate_claim_kid_cannot_hide_compromise_from_status_floor() -> None:
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)])
    claim = _manifest(
        [
            _entry(KID, KP, "active"),
            _entry(KID, KP, "compromised"),
            _entry(DECLARER_KID, DECLARER_KP),
        ]
    )

    result = verify.verify(
        _wire(_receipt()), _trust(trusted), compromise_view=[{"manifest": claim}]
    )

    assert result.signature == "invalid"
    assert any("compromised" in error for error in result.errors)


def test_build_successor_rejects_conflicting_duplicate_for_compromised_kid() -> None:
    """An issuer must not publish a successor that lists a compromised kid
    as anything other than compromised (v0.1 §7.3).

    The final duplicate is compromised, but the first is an active
    resurrection. A last-value map must not make the builder accept it.
    """
    previous = _manifest([_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)])
    successor_entries = [
        _entry(KID, KP, "active"),
        _entry(KID, KP, "compromised"),
        _entry(DECLARER_KID, DECLARER_KP),
    ]

    with pytest.raises(ValueError):
        manifests.build_key_manifest(
            ISSUER,
            2,
            "2026-08-01T00:00:00Z",
            successor_entries,
            DECLARER_KP,
            DECLARER_KID,
            previous=previous,
        )


def test_continuity_rejects_conflicting_duplicate_for_compromised_kid() -> None:
    """Continuity itself must reject the same published ambiguity, even when
    a caller did not use ``build_key_manifest(previous=...)``.
    """
    trusted = _manifest([_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)])
    candidate = _manifest(
        [
            _entry(KID, KP, "active"),
            _entry(KID, KP, "compromised"),
            _entry(DECLARER_KID, DECLARER_KP),
        ],
        version=2,
    )
    candidate["issued_at"] = "2026-08-01T00:00:00Z"
    candidate["manifest_signature"] = manifests.sign_signature_block(
        manifests._signable(candidate),
        DECLARER_KP,
        DECLARER_KID,  # type: ignore[attr-defined]
    )

    assert manifests.check_continuity(trusted, candidate) is False


@pytest.mark.parametrize("bad_version", [True, "2", None])
def test_noninteger_claim_manifest_version_cannot_create_compromise_floor(
    bad_version: object,
) -> None:
    """§19.2 requires a v0.1 §7.1 manifest object, whose version is an
    integer. A signed object outside that shape cannot establish item 3a's
    irreversible floor merely because a held key can verify its signature.
    """
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)])
    malformed_claim = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)],
        version=bad_version,
    )

    result = verify.verify(
        _wire(_receipt()), _trust(trusted), compromise_view=[{"manifest": malformed_claim}]
    )

    assert result.signature == "valid"
    assert "compromise_cutoff_claim_ignored" in result.warnings


@pytest.mark.parametrize(
    "bad_issued_at",
    ["2026-08-01T00:00:00", "2026-08-01T02:00:00+02:00", "2026-08-01T00:00:00.000001Z"],
)
def test_non_utc_z_claim_timestamp_cannot_create_compromise_floor(bad_issued_at: str) -> None:
    """v0.1 §7.1 defines manifest ``issued_at`` as a UTC-Z timestamp.
    A timezone-less, offset, or microsecond spelling cannot become a valid
    §19.3 declaration by being signed.
    """
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)])
    malformed_claim = _manifest([_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)])
    malformed_claim["issued_at"] = bad_issued_at
    malformed_claim["manifest_signature"] = manifests.sign_signature_block(
        manifests._signable(malformed_claim),
        DECLARER_KP,
        DECLARER_KID,  # type: ignore[attr-defined]
    )

    result = verify.verify(
        _wire(_receipt()), _trust(trusted), compromise_view=[{"manifest": malformed_claim}]
    )

    assert result.signature == "valid"
    assert "compromise_cutoff_claim_ignored" in result.warnings


def test_compromise_view_processes_64_nonobject_claims_without_crashing() -> None:
    """§19.2's mandatory 64-claim acceptance floor includes hostile JSON
    members; they must be ignored rather than crash or become declarations.
    """
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)])
    hostile_view: list[object] = [None, True, 17, "claim", []] * 12 + [None, {}, [], 0]
    assert len(hostile_view) == 64

    result = verify.verify(
        _wire(_receipt()),
        _trust(trusted),
        compromise_view=hostile_view,  # type: ignore[arg-type]
    )

    assert result.signature == "valid"
    assert "compromise_cutoff_claim_ignored" in result.warnings


def test_oversize_compromise_view_fails_safe_without_changing_valid_receipt() -> None:
    """The §19.2 materialization guard must not let a giant untrusted view
    crash verification or manufacture a compromise declaration.
    """
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)])
    oversized = [{"padding": "x" * 10_000_000}]

    result = verify.verify(_wire(_receipt()), _trust(trusted), compromise_view=oversized)

    assert result.signature == "valid"


# --- v0.1 §7.3 rev 8: retraction provenance -------------------------------------
# The floor already kills the receipt. What was undecidable from the result alone
# is WHERE the marking came from: an issuer whose CURRENT trusted list no longer
# carries the marking, while a strictly OLDER signed source of its own does, has
# rewritten its own history. That fact is reported as a warning, never as a
# verdict — it accompanies both the kill and the §19 rescue unchanged.

RETRACTED = "compromise_marking_retracted"


def _warns_retracted(result: verify.VerificationResult) -> bool:
    return RETRACTED in result.warnings


def test_retraction_from_the_version_chain_is_reported() -> None:
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)], version=2)
    older = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=1
    )

    result = verify.verify(_wire(_receipt()), _trust(trusted, chain=[older]))

    assert result.signature == "invalid"
    assert _warns_retracted(result)


def test_retraction_from_an_authenticated_claim_is_reported() -> None:
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)], version=2)
    claim = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=1
    )

    result = verify.verify(
        _wire(_receipt()), _trust(trusted), compromise_view=[{"manifest": claim}]
    )

    assert result.signature == "invalid"
    assert _warns_retracted(result)


def test_trusted_manifest_carrying_the_marking_is_not_a_retraction() -> None:
    # The issuer never took anything back: its current list still says so.
    trusted = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=2
    )
    older = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=1
    )

    result = verify.verify(_wire(_receipt()), _trust(trusted, chain=[older]))

    assert result.signature == "invalid"
    assert not _warns_retracted(result)


def test_a_stale_pin_is_not_a_retraction() -> None:
    # The marking source is NEWER than what this verifier pinned: the issuer is
    # not rewriting history, the verifier is behind. The floor still kills.
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)], version=1)
    newer = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=2
    )

    result = verify.verify(_wire(_receipt()), _trust(trusted, chain=[newer]))

    assert result.signature == "invalid"
    assert any("compromised" in error for error in result.errors)
    assert not _warns_retracted(result)


def test_equal_versions_are_not_a_retraction() -> None:
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)], version=2)
    same = _manifest([_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=2)

    result = verify.verify(_wire(_receipt()), _trust(trusted, chain=[same]))

    assert result.signature == "invalid"
    assert not _warns_retracted(result)


# No float here: a float `manifest_version` is not representable in the
# attest-JCS profile, so it can never reach a verifier over the wire.
@pytest.mark.parametrize("bad_version", ["2", True, None])
def test_a_noninteger_trusted_version_cannot_establish_a_retraction(bad_version: object) -> None:
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)], version=bad_version)
    older = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=1
    )

    result = verify.verify(_wire(_receipt()), _trust(trusted, chain=[older]))

    assert not _warns_retracted(result)


@pytest.mark.parametrize("bad_version", ["1", True, None])
def test_a_noninteger_source_version_cannot_establish_a_retraction(bad_version: object) -> None:
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)], version=2)
    older = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=bad_version
    )

    result = verify.verify(_wire(_receipt()), _trust(trusted, chain=[older]))

    assert not _warns_retracted(result)


@pytest.mark.parametrize("order", ["active_first", "compromised_first"])
def test_a_duplicate_in_the_trusted_list_still_blocks_the_retraction(order: str) -> None:
    # The trusted manifest DOES carry the marking, on one of two entries for the
    # kid: whichever order they appear in, this is not a retraction. An
    # implementation reading the first matching entry gets this wrong in one of
    # the two orders.
    pair = [_entry(KID, KP, "active"), _entry(KID, KP, "compromised")]
    if order == "compromised_first":
        pair.reverse()
    trusted = _manifest([*pair, _entry(DECLARER_KID, DECLARER_KP)], version=2)
    older = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=1
    )

    result = verify.verify(_wire(_receipt()), _trust(trusted, chain=[older]))

    assert result.signature == "invalid"
    assert not _warns_retracted(result)


@pytest.mark.parametrize("order", ["active_first", "compromised_first"])
def test_a_duplicate_in_a_chain_manifest_is_refused_before_any_retraction(order: str) -> None:
    """An ambiguous chain member establishes NOTHING — not even a retraction.

    v0.1 §7.1 refuses it wherever it is consumed, and §19.3 items 3a/3b
    consume held chain members, so the refusal lands before any status is read
    out of it and no retraction is reported in either element order. The claim
    twin below still reports one: a claim manifest is a different consumption
    site with its own undecided policy, and the contrast between the two tests
    is deliberate rather than an inconsistency.
    """
    pair = [_entry(KID, KP, "active"), _entry(KID, KP, "compromised")]
    if order == "compromised_first":
        pair.reverse()
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)], version=2)
    older = _manifest([*pair, _entry(DECLARER_KID, DECLARER_KP)], version=1)

    result = verify.verify(_wire(_receipt()), _trust(trusted, chain=[older]))

    assert result.signature == "invalid"
    assert any("duplicate kid" in error for error in result.errors)
    assert not _warns_retracted(result)


@pytest.mark.parametrize("order", ["active_first", "compromised_first"])
def test_a_duplicate_in_a_claim_manifest_still_establishes_the_retraction(order: str) -> None:
    pair = [_entry(KID, KP, "active"), _entry(KID, KP, "compromised")]
    if order == "compromised_first":
        pair.reverse()
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)], version=2)
    claim = _manifest([*pair, _entry(DECLARER_KID, DECLARER_KP)], version=1)

    result = verify.verify(
        _wire(_receipt()), _trust(trusted), compromise_view=[{"manifest": claim}]
    )

    assert result.signature == "invalid"
    assert _warns_retracted(result)


def test_a_kid_the_trusted_list_omits_entirely_never_reaches_the_provenance_rule() -> None:
    """C1.1 says a kid the trusted manifest omits satisfies the no-entry
    condition. Through the public entry point that clause is UNREACHABLE: key
    resolution fails first with "no key ... in issuer manifest" and the status
    is never resolved, so no marking and no provenance exist to report. This
    pins the real behavior rather than the unreachable one — the clause is
    about the predicate's shape, not about a path a receipt can take.
    """
    trusted = _manifest([_entry(DECLARER_KID, DECLARER_KP)], version=2)
    older = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=1
    )

    result = verify.verify(_wire(_receipt()), _trust(trusted, chain=[older]))

    assert not result.ok
    assert any("no key" in error for error in result.errors)
    assert not _warns_retracted(result)


def test_the_retraction_warning_is_emitted_exactly_once() -> None:
    trusted = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)], version=3)
    older_a = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=1
    )
    older_b = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=2
    )

    result = verify.verify(
        _wire(_receipt()),
        _trust(trusted, chain=[older_a, older_b]),
        compromise_view=[{"manifest": older_a}],
    )

    assert result.warnings.count(RETRACTED) == 1


def test_the_retraction_warning_changes_no_other_component() -> None:
    # Provenance, never a verdict: the same scenario with and without the
    # retraction must agree on every field but this one warning.
    trusted_retracting = _manifest([_entry(KID, KP), _entry(DECLARER_KID, DECLARER_KP)], version=2)
    older = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=1
    )
    trusted_marking = _manifest(
        [_entry(KID, KP, "compromised"), _entry(DECLARER_KID, DECLARER_KP)], version=2
    )

    with_warning = verify.verify(_wire(_receipt()), _trust(trusted_retracting, chain=[older]))
    without = verify.verify(_wire(_receipt()), _trust(trusted_marking, chain=[older]))

    assert _warns_retracted(with_warning) and not _warns_retracted(without)
    assert with_warning.ok == without.ok
    assert with_warning.signature == without.signature
    assert with_warning.schema == without.schema
    assert with_warning.trust == without.trust
    assert with_warning.revocation == without.revocation
    assert [w for w in with_warning.warnings if w != RETRACTED] == list(without.warnings)
