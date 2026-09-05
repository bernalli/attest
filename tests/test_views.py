"""Example-based tests for `attest.views` (plan A11, T3.0-T3.3-bis).

The oracle for every parity assertion is a CHECKED-IN artifact under
`docs/spec/vectors/`, never a second call into the builder under test: a
generator derived from the thing it must prove cannot find the hole it was
written to find.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from attest import anchor, canon, keys, manifests, revocation, tlog, transfer, verify, views

VECTORS = Path(__file__).resolve().parents[1] / "docs" / "spec" / "vectors"
COMPROMISE = VECTORS / "41-compromise-cutoff"

LEAF: dict[str, Path] = {
    "41a": COMPROMISE / "a-rescued-anchored-before-cutoff",
    "41b": COMPROMISE / "b-anchored-after-cutoff-fails",
    "41c": COMPROMISE / "c-logged-only-fails",
    "41h": COMPROMISE / "h-earliest-cutoff-wins",
    "41i": COMPROMISE / "i-unvouched-declaration-ignored",
    "41j": COMPROMISE / "j-hybrid-rescued",
    "41m": COMPROMISE / "m-uncompromise-view-floor",
    "41p": COMPROMISE / "p-declaring-signer-compromised-still-floors",
    "41r": COMPROMISE / "r-compromised-signer-establishes-no-cutoff",
    "41x": COMPROMISE / "x-chain-member-duplicate-kid-refused",
    "41z": COMPROMISE / "z-stolen-key-chain-member-cannot-deny-cutoff",
    "15": VECTORS / "15-revoked-policy",
    "29c": VECTORS / "29-limits" / "c-manifest-array-overflow",
    "35a": VECTORS / "35-transfer" / "a-transferred-with-backing",
    "44a": VECTORS / "44-manifest-duplicate-kid" / "a-active-first",
    "46a": VECTORS / "46-manifest-unauthenticated" / "a-signature-corrupted",
    "47a": VECTORS / "47-oversized-view-transfer" / "a-oversized-view-hides-transfer",
}

KID_1 = "store.example.com/keys/2025-01#ed25519-1"


# --- corpus loaders (deliberately local: `tests/` has no shared vector helper,
# every consuming module declares its own — see tests/test_vectors.py:159) -----


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _trust(leaf: str) -> tuple[dict[str, Any], list[dict[str, Any]] | None]:
    """The leaf's single trusted head manifest and its chain (or None)."""
    data = _json(LEAF[leaf] / "manifests.json")
    issuer = next(iter(data["manifests"]))
    return data["manifests"][issuer], data.get("chains", {}).get(issuer)


def _claims(leaf: str) -> list[dict[str, Any]]:
    return list(_json(LEAF[leaf] / "compromise-view.json"))


def _claim(leaf: str, index: int = 0) -> dict[str, Any]:
    return _claims(leaf)[index]


def _log_keys(leaf: str) -> list[tlog.LogKey]:
    return [
        tlog.LogKey(
            origin=entry["origin"],
            name=entry["name"],
            ed25519_pub=keys.b64u_decode(entry["ed25519_pub_b64u"]),
            mldsa_pub=keys.b64u_decode(entry["mldsa_pub_b64u"]),
        )
        for entry in _json(LEAF[leaf] / "log-keys.json")
    ]


def _anchor_policy(leaf: str) -> anchor.AnchorPolicy:
    data = _json(LEAF[leaf] / "anchor-policy.json")
    pinned = {
        header_hash: anchor.PinnedHeader(
            header_hash=header["header_hash"],
            merkle_root=header["merkle_root"],
            time=header["time"],
        )
        for header_hash, header in data["pinned_headers"].items()
    }
    return anchor.AnchorPolicy(pinned_headers=pinned, crqc_horizon=data["crqc_horizon"])


def _explode(*_args: object, **_kwargs: object) -> bytes:
    raise AssertionError("canon.canonical_bytes must not be reached before the ceiling check")


# --- T3.0 — the composed trust-material preflight (regola 0-bis) --------------


def test_preflight_refuses_oversized_trusted_manifest_before_canonicalizing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """(a) 257 keys — the ceiling fires before any canonicalization happens."""
    head, _ = _trust("29c")
    assert len(head["keys"]) == manifests.MAX_MANIFEST_KEYS + 1
    monkeypatch.setattr(canon, "canonical_bytes", _explode)
    with pytest.raises(views.ViewError) as excinfo:
        views.claim_capabilities(_claim("41a"), head, None)
    assert str(manifests.MAX_MANIFEST_KEYS) in str(excinfo.value)
    assert "ambiguous or inauthentic" in str(excinfo.value)


def test_preflight_refuses_duplicate_kid_in_trusted_manifest() -> None:
    """(b) an ambiguous head is refused whole — never resolved by position."""
    head, _ = _trust("44a")
    with pytest.raises(views.ViewError) as excinfo:
        views.claim_capabilities(_claim("41a"), head, None)
    assert "duplicate kid" in str(excinfo.value)


def test_preflight_refuses_unauthenticated_trusted_manifest() -> None:
    """(c) a head whose own signature does not verify certifies nothing."""
    head, _ = _trust("46a")
    with pytest.raises(views.ViewError) as excinfo:
        views.claim_capabilities(_claim("41a"), head, None)
    assert "signature" in str(excinfo.value)


def test_preflight_refuses_chain_member_with_duplicate_kid() -> None:
    """(d) 41x reaches ViewError, never a classification nor a stray exception."""
    head, chain = _trust("41x")
    assert chain is not None
    with pytest.raises(views.ViewError) as excinfo:
        views.claim_capabilities(_claim("41x"), head, chain)
    assert "duplicate kid" in str(excinfo.value)
    assert "chain" in str(excinfo.value)


@pytest.mark.parametrize(
    "member",
    [
        pytest.param({"issuer": "other.example.org", "keys": None}, id="non-array-keys"),
        pytest.param(
            {
                "issuer": "other.example.org",
                "keys": [None] * (manifests.MAX_MANIFEST_KEYS + 1),
            },
            id="oversized-but-unambiguous-keys",
        ),
    ],
)
def test_preflight_does_not_invent_chain_refusals_the_verifier_lacks(
    member: dict[str, Any],
) -> None:
    """`verify()`'s preflight asks a chain member for `duplicate_kids` alone,
    which ignores non-list input by design. A type check or a ceiling added
    here would refuse material the verifier admits — and the classifier would
    then answer about a chain no verifier would have rejected."""
    head, _ = _trust("41a")
    report = views.claim_capabilities(_claim("41a"), head, [member])
    assert report[KID_1]["floor"] == "established"


@pytest.mark.parametrize("leaf", ["41a", "41z"])
def test_preflight_admits_well_formed_material(leaf: str) -> None:
    """(e) the negative controls: well-formed material reaches classification."""
    head, chain = _trust(leaf)
    report = views.claim_capabilities(_claim(leaf), head, chain)
    assert set(report) == {KID_1}


def test_preflight_uses_manifests_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ambiguity rule has ONE source: `manifests.py`. Sentinels prove that
    `views.py` calls it instead of re-deriving the comparison locally."""
    head, _ = _trust("41a")
    monkeypatch.setattr(manifests, "duplicate_kids", lambda entries: ["sentinel-kid"])
    with pytest.raises(views.ViewError) as excinfo:
        views.claim_capabilities(_claim("41a"), head, None)
    assert "sentinel-kid" in str(excinfo.value)


def test_preflight_duplicate_verdict_comes_only_from_duplicate_kids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other direction: with `duplicate_kids` silenced, an ambiguous head
    is no longer refused FOR AMBIGUITY — so no second spelling of the rule
    survives inside `views.py`."""
    head, _ = _trust("44a")
    monkeypatch.setattr(manifests, "duplicate_kids", lambda entries: [])
    with pytest.raises(views.ViewError) as excinfo:
        views.claim_capabilities(_claim("41a"), head, None)
    assert "duplicate kid" not in str(excinfo.value)


def test_preflight_uses_manifest_signature_is_authentic(monkeypatch: pytest.MonkeyPatch) -> None:
    head, _ = _trust("41a")
    monkeypatch.setattr(manifests, "manifest_signature_is_authentic", lambda manifest: False)
    with pytest.raises(views.ViewError) as excinfo:
        views.claim_capabilities(_claim("41a"), head, None)
    assert "signature" in str(excinfo.value)


def test_verify_private_predicates_exist() -> None:
    """Pin the private names `views` borrows, so a rename in `verify.py`,
    `revocation.py` or `transfer.py` breaks here out loud instead of in
    silence. Precedent: `cli.py:107` reads `verify._MAX_TRANSPARENCY_EVIDENCE_LEN`."""
    assert views._MAX_COMPROMISE_CLAIMS is verify._MAX_COMPROMISE_CLAIMS
    assert views._materialize_compromise_view is verify._materialize_compromise_view
    assert views._authenticated_compromise_claims is verify._authenticated_compromise_claims
    assert views._cutoff_denying_manifests is verify._cutoff_denying_manifests
    assert views._claim_has_cutoff_signer is verify._claim_has_cutoff_signer
    assert views._resolve_compromise_cutoff is verify._resolve_compromise_cutoff
    assert views._RECEIPT_ID_RE is revocation.RECEIPT_ID_RE
    assert views._valid_holder_authorization_shape is transfer._valid_holder_authorization_shape
    assert views._strict_b64u_decode is transfer._strict_b64u_decode


# --- T3.1 — parity with the checked-in compromise views ----------------------


@pytest.mark.parametrize("leaf", ["41a", "41h", "41j"])
def test_build_compromise_view_reproduces_corpus(leaf: str) -> None:
    corpus = _json(LEAF[leaf] / "compromise-view.json")
    built = views.build_compromise_view(
        [views.build_compromise_claim(c["manifest"], c["evidence"]) for c in corpus]
    )
    assert canon.canonical_bytes(built) == canon.canonical_bytes(corpus)


def test_build_compromise_claim_reproduces_a_single_corpus_claim() -> None:
    corpus = _claim("41a")
    built = views.build_compromise_claim(corpus["manifest"], corpus["evidence"])
    assert set(built) == {"manifest", "evidence"}
    assert canon.canonical_bytes(built) == canon.canonical_bytes(corpus)


def test_key_manifest_log_entry_matches_the_corpus_evidence_entry() -> None:
    corpus = _claim("41a")
    assert views.key_manifest_log_entry(corpus["manifest"]) == corpus["evidence"]["entry"]


# --- T3.2 — parity for transfer and revocation views -------------------------


def test_build_transfer_view_reproduces_corpus() -> None:
    corpus = _json(LEAF["35a"] / "transfer-view.json")
    built = views.build_transfer_view(
        [views.build_transfer_claim(c["record"], c["evidence"]) for c in corpus]
    )
    assert canon.canonical_bytes(built) == canon.canonical_bytes(corpus)


def test_build_revocation_view_wraps_a_single_corpus_record() -> None:
    record = _json(LEAF["15"] / "revocation.json")
    assert canon.canonical_bytes(views.build_revocation_view([record])) == canon.canonical_bytes(
        [record]
    )


def test_build_revocation_view_reproduces_the_real_records_of_47a() -> None:
    """`47a/revocation-view.json` is a HOSTILE artifact: 10 000 `null` fillers
    plus one real record, one element ABOVE the ceiling. The builder is a
    producer of well-formed views, so it reproduces the real record and
    refuses the padding — see `test_build_revocation_view_refuses_47a_whole`."""
    corpus = _json(LEAF["47a"] / "revocation-view.json")
    real = [record for record in corpus if record is not None]
    assert len(real) == 1
    assert canon.canonical_bytes(views.build_revocation_view(real)) == canon.canonical_bytes(real)


def test_build_revocation_view_refuses_47a_whole() -> None:
    corpus = _json(LEAF["47a"] / "revocation-view.json")
    assert len(corpus) == revocation.MAX_REVOCATION_RECORDS + 1
    with pytest.raises(views.ViewError) as excinfo:
        views.build_revocation_view(corpus)
    assert str(revocation.MAX_REVOCATION_RECORDS) in str(excinfo.value)


def test_build_revocation_view_accepts_the_transferred_status() -> None:
    """D12: the view carries `revoked` AND `transferred` records (§12 registry)."""
    record = next(r for r in _json(LEAF["47a"] / "revocation-view.json") if r is not None)
    assert record["status"] == "transferred"
    assert views.build_revocation_view([record]) == [record]


# --- T3.3 — rejection by example ---------------------------------------------


def _evidence(leaf: str = "41a") -> dict[str, Any]:
    return copy.deepcopy(_claim(leaf)["evidence"])


def _manifest(leaf: str = "41a") -> dict[str, Any]:
    return copy.deepcopy(_claim(leaf)["manifest"])


def _resign(manifest: dict[str, Any], kp: keys.SigningKeyPair, kid: str) -> dict[str, Any]:
    """Re-sign a manifest after editing it, so the refusal under test cannot be
    the stale signature. This is what makes the two tests below real: with the
    original signature retained, ANY shape guard could be deleted and the
    builder would still refuse — for the wrong reason."""
    body = {k: v for k, v in manifest.items() if k != "manifest_signature"}
    body["manifest_signature"] = manifests.sign_signature_block(
        canon.canonical_bytes(body), kp, kid
    )
    return body


def _declaration(**overrides: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """A freshly signed compromise declaration plus evidence computed FOR IT."""
    kp = keys.from_seed(bytes([7]) * 32)
    kid = "declaring.example.com/keys/2026-01#ed25519-1"
    manifest: dict[str, Any] = {
        "issuer": "declaring.example.com",
        "manifest_version": 2,
        "issued_at": "2026-01-01T00:00:00Z",
        "keys": [
            manifests.key_entry(kid, kp.pub, "2025-01-01T00:00:00Z"),
            manifests.key_entry(
                "declaring.example.com/keys/2024-01#ed25519-1",
                keys.from_seed(bytes([8]) * 32).pub,
                "2024-01-01T00:00:00Z",
                status="compromised",
            ),
        ],
    }
    for member, value in overrides.items():
        if value is _ABSENT:
            manifest.pop(member, None)
        else:
            manifest[member] = value
    manifest = _resign(manifest, kp, kid)
    evidence = copy.deepcopy(_evidence())
    evidence["entry"] = views.key_manifest_log_entry(manifest)
    return manifest, evidence


_ABSENT = object()


def test_a_freshly_signed_declaration_is_accepted() -> None:
    """The control for the two refusals below: same construction, nothing
    removed, so a refusal there cannot be blamed on the fixture."""
    manifest, evidence = _declaration()
    claim = views.build_compromise_claim(manifest, evidence)
    assert claim["manifest"] == manifest


def test_a_declaration_without_issued_at_is_refused() -> None:
    """`verify._vouching_signers` abandons a claim whose `issued_at` is not a
    string: it has no instant to check a signer's validity window against. Such
    a declaration authenticates for nobody, so it must not be built."""
    manifest, evidence = _declaration(issued_at=_ABSENT)
    with pytest.raises(views.ViewError, match="issued_at"):
        views.build_compromise_claim(manifest, evidence)


def test_a_declaration_whose_compromised_entry_names_no_key_is_refused() -> None:
    """`verify._entries_for_kid` selects entries by `kid`. An entry that says
    `compromised` without naming one marks nothing for any verifier, so the
    declaration declares nothing."""
    manifest, evidence = _declaration(
        keys=[
            manifests.key_entry(
                "declaring.example.com/keys/2026-01#ed25519-1",
                keys.from_seed(bytes([7]) * 32).pub,
                "2025-01-01T00:00:00Z",
            ),
            {"status": "compromised"},
        ]
    )
    with pytest.raises(views.ViewError, match="NAMED"):
        views.build_compromise_claim(manifest, evidence)


def test_compromise_claim_refuses_manifest_without_a_compromised_entry() -> None:
    head, _ = _trust("35a")
    with pytest.raises(views.ViewError, match="compromised"):
        views.build_compromise_claim(head, _evidence())


def test_compromise_claim_refuses_duplicate_kid_manifest() -> None:
    head, _ = _trust("44a")
    with pytest.raises(views.ViewError, match="duplicate kid"):
        views.build_compromise_claim(head, _evidence())


def test_compromise_claim_refuses_oversized_manifest_before_canonicalizing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    head, _ = _trust("29c")
    monkeypatch.setattr(canon, "canonical_bytes", _explode)
    with pytest.raises(views.ViewError, match=str(manifests.MAX_MANIFEST_KEYS)):
        views.build_compromise_claim(head, _evidence())


def test_compromise_claim_refuses_broken_manifest_signature() -> None:
    manifest = _manifest()
    manifest["manifest_signature"] = dict(manifest["manifest_signature"])
    manifest["manifest_signature"]["sig"] = "A" + manifest["manifest_signature"]["sig"][1:]
    with pytest.raises(views.ViewError, match="self-consistent"):
        views.build_compromise_claim(manifest, _evidence())


def test_compromise_claim_refuses_evidence_for_another_manifest() -> None:
    """41i's evidence commits to the rogue manifest, not to 41a's v2."""
    with pytest.raises(views.ViewError, match="entry"):
        views.build_compromise_claim(_manifest("41a"), _evidence("41i"))


def test_compromise_claim_refuses_wrong_entry_type() -> None:
    evidence = _evidence()
    evidence["entry"] = {"type": "receipt", "issuer": "store.example.com", "core_sha256": "0" * 64}
    with pytest.raises(views.ViewError, match="entry"):
        views.build_compromise_claim(_manifest(), evidence)


@pytest.mark.parametrize(
    "member", ["entry", "leaf_index", "tree_size", "inclusion_proof", "checkpoint"]
)
def test_compromise_claim_refuses_evidence_missing_a_required_member(member: str) -> None:
    evidence = _evidence()
    del evidence[member]
    with pytest.raises(views.ViewError):
        views.build_compromise_claim(_manifest(), evidence)


def test_compromise_claim_refuses_unknown_evidence_member() -> None:
    evidence = _evidence()
    evidence["surprise"] = 1
    with pytest.raises(views.ViewError, match="surprise"):
        views.build_compromise_claim(_manifest(), evidence)


def test_compromise_claim_refuses_tree_size_at_or_below_leaf_index() -> None:
    evidence = _evidence()
    evidence["tree_size"] = evidence["leaf_index"]
    with pytest.raises(views.ViewError, match="tree_size"):
        views.build_compromise_claim(_manifest(), evidence)


def test_compromise_claim_refuses_oversized_inclusion_proof() -> None:
    evidence = _evidence()
    evidence["inclusion_proof"] = ["ab" * 32] * (views.MAX_INCLUSION_PROOF_NODES + 1)
    with pytest.raises(views.ViewError, match="inclusion_proof"):
        views.build_compromise_claim(_manifest(), evidence)


def test_compromise_claim_admits_a_proof_at_the_ceiling() -> None:
    """Two-sided boundary: 64 nodes is admissible, 65 is not."""
    evidence = _evidence()
    evidence["inclusion_proof"] = ["ab" * 32] * views.MAX_INCLUSION_PROOF_NODES
    claim = views.build_compromise_claim(_manifest(), evidence)
    assert len(claim["evidence"]["inclusion_proof"]) == views.MAX_INCLUSION_PROOF_NODES


def test_compromise_claim_refuses_non_hex_inclusion_proof() -> None:
    evidence = _evidence()
    evidence["inclusion_proof"] = ["zz" * 32]
    with pytest.raises(views.ViewError, match="inclusion_proof"):
        views.build_compromise_claim(_manifest(), evidence)


@pytest.mark.parametrize(
    ("member", "value"),
    [
        ("issuer", None),
        ("issuer", 7),
        ("issuer", []),
        ("manifest_version", True),
        ("manifest_version", 2.0),
        ("manifest_version", "2"),
        ("issued_at", None),
        ("issued_at", 1754006400),
    ],
)
def test_compromise_claim_refuses_a_wrong_typed_header_before_canonicalizing(
    member: str, value: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Editing a header also breaks the signature, so a test that only asserts
    `ViewError` passes at the signature check and never exercises the guard it
    names. Exploding `canonical_bytes` proves the shape guard fires first, and
    matching the member name proves the refusal says what is actually wrong."""
    manifest = _manifest()
    manifest[member] = value
    monkeypatch.setattr(canon, "canonical_bytes", _explode)
    with pytest.raises(views.ViewError, match=member):
        views.build_compromise_claim(manifest, _evidence())


def test_compromise_claim_accepts_a_declaration_signed_by_a_compromised_signer() -> None:
    """F2/P11: §19.3 item 3a deliberately does NOT consult the signer's status.
    41p is a VALID claim that establishes the floor; whether it can also carry a
    cutoff is `claim_capabilities`' answer, not the builder's."""
    corpus = _claim("41p")
    built = views.build_compromise_claim(corpus["manifest"], corpus["evidence"])
    assert canon.canonical_bytes(built) == canon.canonical_bytes(corpus)


def test_compromise_claim_accepts_a_declaration_signed_by_its_own_compromised_key() -> None:
    """The sharp edge of F2/P11, which no corpus leaf reaches: a manifest that
    marks the very key that SIGNED it `compromised`.

    That is the ordinary shape of a real disclosure — the issuer publishes the
    news with the key it is disowning — and §19.3 item 3a admits it for the
    status floor («status deliberately NOT consulted», `attest-v0.2.md:1150`).
    A builder that added a signer-status check would refuse exactly the
    declaration the spec exists to carry, and no vector in the repo would
    notice, because in `41p` and `41r` the signer is `compromised` in the
    TRUSTED head and still `active` inside the declaration itself.
    """
    signer = keys.from_seed(bytes([13]) * 32)
    signer_kid = "shop.example.org/keys/2025-01#ed25519-1"
    manifest = manifests.build_key_manifest(
        "shop.example.org",
        2,
        "2025-02-01T00:00:00Z",
        [manifests.key_entry(signer_kid, signer.pub, "2025-01-01T00:00:00Z", status="compromised")],
        signer,
        signer_kid,
    )
    assert manifests.verify_key_manifest(manifest)
    evidence = {
        "entry": {
            "type": "key-manifest",
            "issuer": "shop.example.org",
            "manifest_version": 2,
            "manifest_sha256": hashlib.sha256(canon.canonical_bytes(manifest)).hexdigest(),
        },
        "leaf_index": 0,
        "tree_size": 1,
        "inclusion_proof": [],
        "checkpoint": "shop.example.org/log\n1\nQUJD\n",
    }
    claim = views.build_compromise_claim(manifest, evidence)
    assert claim["manifest"]["keys"][0]["status"] == "compromised"


def test_compromise_view_refuses_more_than_the_ceiling() -> None:
    corpus = _claim("41a")
    claims = [
        {"manifest": corpus["manifest"], "evidence": corpus["evidence"]}
        for _ in range(verify._MAX_COMPROMISE_CLAIMS + 1)
    ]
    with pytest.raises(views.ViewError, match=str(verify._MAX_COMPROMISE_CLAIMS)):
        views.build_compromise_view(claims)


def test_compromise_view_refuses_canonically_identical_claims() -> None:
    corpus = _claim("41a")
    with pytest.raises(views.ViewError, match="identical"):
        views.build_compromise_view([corpus, copy.deepcopy(corpus)])


def test_compromise_view_keeps_two_claims_sharing_a_manifest_with_different_evidence() -> None:
    """F9: dedup is on the CLAIM, not on the subject — two standings for one
    manifest are two different facts."""
    first = _claim("41a")
    second = copy.deepcopy(first)
    second["evidence"] = {
        key: value for key, value in second["evidence"].items() if key != "anchors"
    }
    built = views.build_compromise_view([first, second])
    assert len(built) == 2
    assert "anchors" in built[0]["evidence"]
    assert "anchors" not in built[1]["evidence"]


def test_compromise_view_refuses_a_claim_with_an_extra_member() -> None:
    corpus = copy.deepcopy(_claim("41a"))
    corpus["note"] = "hello"
    with pytest.raises(views.ViewError, match="note"):
        views.build_compromise_view([corpus])


def test_compromise_view_preserves_the_given_order() -> None:
    corpus = _json(LEAF["41h"] / "compromise-view.json")
    built = views.build_compromise_view(list(reversed(corpus)))
    assert [c["manifest"]["manifest_version"] for c in built] == [
        c["manifest"]["manifest_version"] for c in reversed(corpus)
    ]


# --- T3.3, transfer ----------------------------------------------------------


def _transfer_claim() -> dict[str, Any]:
    return copy.deepcopy(_json(LEAF["35a"] / "transfer-view.json")[0])


TRANSFER_MEMBERS = (
    "receipt_id",
    "new_receipt_id",
    "new_holder_pubkey",
    "transferred_at",
    "holder_authorization",
    "signature",
)


@pytest.mark.parametrize("member", TRANSFER_MEMBERS)
def test_transfer_claim_refuses_a_record_missing_a_member(member: str) -> None:
    claim = _transfer_claim()
    del claim["record"][member]
    with pytest.raises(views.ViewError):
        views.build_transfer_claim(claim["record"], claim["evidence"])


@pytest.mark.parametrize("member", TRANSFER_MEMBERS)
def test_transfer_claim_refuses_a_retyped_member_before_hashing(
    member: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retyped member also changes the record hash, so the claim would be
    refused later for evidence that no longer matches — with every shape guard
    deleted. Exploding `record_hash` pins that the member guard fires first."""
    claim = _transfer_claim()
    claim["record"][member] = 7
    monkeypatch.setattr(transfer, "record_hash", _explode)
    with pytest.raises(views.ViewError):
        views.build_transfer_claim(claim["record"], claim["evidence"])


def test_transfer_claim_refuses_an_extra_record_member() -> None:
    claim = _transfer_claim()
    claim["record"]["memo"] = "x"
    with pytest.raises(views.ViewError, match="memo"):
        views.build_transfer_claim(claim["record"], claim["evidence"])


def test_transfer_claim_refuses_extra_member_in_holder_authorization() -> None:
    claim = _transfer_claim()
    claim["record"]["holder_authorization"]["alg"] = "ed25519"
    with pytest.raises(views.ViewError, match="holder_authorization"):
        views.build_transfer_claim(claim["record"], claim["evidence"])


def test_transfer_claim_needs_no_anchors() -> None:
    """F11/P33: `logged` standing is enough for a transfer claim — the corpus
    evidence carries no `anchors` and the builder emits no warning for it."""
    claim = _transfer_claim()
    assert "anchors" not in claim["evidence"]
    built = views.build_transfer_claim(claim["record"], claim["evidence"])
    assert canon.canonical_bytes(built) == canon.canonical_bytes(claim)


def test_transfer_view_refuses_more_than_the_ceiling() -> None:
    claim = _transfer_claim()
    with pytest.raises(views.ViewError, match=str(transfer.MAX_TRANSFER_CLAIMS)):
        views.build_transfer_view([claim] * (transfer.MAX_TRANSFER_CLAIMS + 1))


# --- T3.3, revocation --------------------------------------------------------


def _revocation_record() -> dict[str, Any]:
    return copy.deepcopy(_json(LEAF["15"] / "revocation.json"))


def test_revocation_view_refuses_a_status_outside_the_registry() -> None:
    record = _revocation_record()
    record["status"] = "revoke"
    with pytest.raises(views.ViewError, match="status"):
        views.build_revocation_view([record])


def test_revocation_view_refuses_a_record_with_five_members() -> None:
    record = _revocation_record()
    record["reason"] = "chargeback"
    with pytest.raises(views.ViewError, match="reason"):
        views.build_revocation_view([record])


def test_revocation_view_refuses_an_unpadded_timestamp() -> None:
    """P34: `strptime` accepts `2025-8-1T0:0:0Z`; only the round-trip refuses it."""
    record = _revocation_record()
    record["revoked_at"] = "2025-8-1T0:0:0Z"
    with pytest.raises(views.ViewError, match="revoked_at"):
        views.build_revocation_view([record])


def test_revocation_view_refuses_a_non_ulid_receipt_id() -> None:
    record = _revocation_record()
    record["receipt_id"] = "not-a-ulid"
    with pytest.raises(views.ViewError, match="receipt_id"):
        views.build_revocation_view([record])


# --- the signature block: every branch of `_signature_block_kid` -------------
#
# The builders validate the members of a signature block they RECOGNIZE and
# tolerate the ones they do not, which is the rule every consumer applies:
# `manifests.verify_signature_block` authenticates a block carrying a member it
# does not know, and `transfer.verify_record_signature` does not close the block
# either. A builder that closed it would refuse records those functions
# authenticate. Nothing pinned that shape — neither the tolerance nor the
# validation that survives it — so a later reader could not tell the relaxation
# from an oversight, and no branch of the function had a test of its own.


def test_revocation_view_tolerates_an_unknown_member_in_the_signature_block() -> None:
    """The relaxation itself, pinned: a member the builder does not know is
    carried through untouched rather than refused, and the record is emitted
    exactly as given — the extra member is not dropped either, because every
    hash this module computes is taken over the whole document."""
    record = _revocation_record()
    record["signature"]["alg"] = "ed25519"

    assert canon.canonical_bytes(views.build_revocation_view([record])) == canon.canonical_bytes(
        [record]
    )


def test_revocation_view_refuses_a_signature_block_that_is_not_an_object() -> None:
    record = _revocation_record()
    record["signature"] = [KID_1]
    with pytest.raises(views.ViewError, match="'signature' must be an object"):
        views.build_revocation_view([record])


def test_revocation_view_refuses_a_signature_block_without_a_kid() -> None:
    record = _revocation_record()
    del record["signature"]["kid"]
    with pytest.raises(views.ViewError, match="missing required member"):
        views.build_revocation_view([record])


def test_revocation_view_refuses_a_signature_block_without_a_sig() -> None:
    record = _revocation_record()
    del record["signature"]["sig"]
    with pytest.raises(views.ViewError, match="missing required member"):
        views.build_revocation_view([record])


def test_revocation_view_refuses_an_empty_kid() -> None:
    """Tolerating unknown members must not soften the ones that are known: an
    empty `kid` names no key and cannot resolve to one."""
    record = _revocation_record()
    record["signature"]["kid"] = ""
    with pytest.raises(views.ViewError, match=r"'signature\.kid'"):
        views.build_revocation_view([record])


def test_revocation_view_refuses_a_malformed_sig() -> None:
    """The other half of the same rule: a builder that stopped validating `sig`
    would emit an artifact no verifier could ever authenticate."""
    record = _revocation_record()
    record["signature"]["sig"] = "not-base64url!"
    with pytest.raises(views.ViewError, match=r"'signature\.sig'"):
        views.build_revocation_view([record])


def test_revocation_view_refuses_a_malformed_post_quantum_leg() -> None:
    """`sig_ml_dsa_65` is optional and validated when present — the one member
    that is neither required nor unknown."""
    record = _revocation_record()
    record["signature"]["sig_ml_dsa_65"] = "not-base64url!"
    with pytest.raises(views.ViewError, match="sig_ml_dsa_65"):
        views.build_revocation_view([record])


def test_revocation_view_verifies_records_against_a_given_key_manifest() -> None:
    """A record signed by a key the manifest does not list as `active` is
    refused when the caller supplies the manifest, and only then."""
    signer = keys.from_seed(bytes([9]) * 32)
    retired = keys.from_seed(bytes([11]) * 32)
    signer_kid = "shop.example.org/keys/2025-01#ed25519-1"
    retired_kid = "shop.example.org/keys/2024-01#ed25519-0"
    manifest = manifests.build_key_manifest(
        "shop.example.org",
        1,
        "2025-01-01T00:00:00Z",
        [
            manifests.key_entry(signer_kid, signer.pub, "2025-01-01T00:00:00Z"),
            manifests.key_entry(retired_kid, retired.pub, "2024-01-01T00:00:00Z", status="retired"),
        ],
        signer,
        signer_kid,
    )
    record = revocation.build_record(
        "01JZ5PDHT0000G40R40M30E209", "revoked", "2025-08-01T00:00:00Z", retired, retired_kid
    )
    assert views.build_revocation_view([record]) == [record]
    with pytest.raises(views.ViewError, match="does not verify"):
        views.build_revocation_view([record], manifest)


def test_revocation_view_refuses_canonically_identical_records() -> None:
    record = _revocation_record()
    with pytest.raises(views.ViewError, match="identical"):
        views.build_revocation_view([record, copy.deepcopy(record)])


# --- T3.3-bis — the four axes of `claim_capabilities` ------------------------


def test_capabilities_of_41a_without_pins() -> None:
    head, chain = _trust("41a")
    assert views.claim_capabilities(_claim("41a"), head, chain) == {
        KID_1: {
            "floor": "established",
            "cutoff_signer": "eligible",
            "anchor_evidence": "present_unverified",
            "cutoff": "not_evaluated",
        }
    }


def test_capabilities_of_41a_with_pins_resolve_the_cutoff() -> None:
    head, chain = _trust("41a")
    report = views.claim_capabilities(
        _claim("41a"),
        head,
        chain,
        log_keys=_log_keys("41a"),
        anchor_policy=_anchor_policy("41a"),
    )
    # The cutoff is the DECLARATION's anchored_before, read off the claim's own
    # `anchors` proof (`header_time` 1754006400 = 2025-08-01T00:00:00Z, pinned in
    # the leaf's anchor-policy.json). The leaf's expected.json shows
    # `anchored_before:2025-07-10T00:00:00Z`, but that is the RECEIPT's
    # transparency (`transparency.json`, header_time 1752105600) — which is
    # exactly why 41a rescues: the receipt is anchored BEFORE the cutoff.
    assert report[KID_1]["cutoff"] == "established:2025-08-01T00:00:00Z"


@pytest.mark.parametrize("leaf", ["41p", "41r"])
def test_capabilities_of_a_compromised_signer_floor_without_cutoff(leaf: str) -> None:
    head, chain = _trust(leaf)
    report = views.claim_capabilities(_claim(leaf), head, chain)
    assert report[KID_1]["floor"] == "established"
    assert report[KID_1]["cutoff_signer"] == "ineligible"


def test_capabilities_report_absent_anchors() -> None:
    """41m's evidence carries no `anchors`; with pins, no cutoff is established."""
    head, chain = _trust("41m")
    assert "anchors" not in _claim("41m")["evidence"]
    report = views.claim_capabilities(
        _claim("41m"),
        head,
        chain,
        log_keys=_log_keys("41m"),
        anchor_policy=_anchor_policy("41m"),
    )
    assert report[KID_1]["anchor_evidence"] == "absent"
    assert report[KID_1]["cutoff"] == "not_established"


def test_capabilities_of_41c_report_the_declarations_own_anchor() -> None:
    """41c is the leaf where the two evidences must not be confused: the
    DECLARATION is anchored (its proof pins header_time 1752105600 =
    2025-07-10T00:00:00Z), so a cutoff exists; the RECEIPT is logged-only,
    which is why the leaf fails. `claim_capabilities` reports the claim's
    evidence and says nothing about the receipt."""
    head, chain = _trust("41c")
    report = views.claim_capabilities(
        _claim("41c"),
        head,
        chain,
        log_keys=_log_keys("41c"),
        anchor_policy=_anchor_policy("41c"),
    )
    assert report[KID_1]["anchor_evidence"] == "present_unverified"
    assert report[KID_1]["cutoff"] == "established:2025-07-10T00:00:00Z"


def test_capabilities_of_an_unvouched_declaration_is_ignored() -> None:
    head, chain = _trust("41i")
    report = views.claim_capabilities(_claim("41i"), head, chain)
    assert report[KID_1]["floor"] == "ignored"
    assert report[KID_1]["cutoff_signer"] == "ineligible"


def test_capabilities_under_delta_a_stolen_key_member_cannot_deny_the_cutoff() -> None:
    """41z: the chain member is signed by the very key the head marks
    compromised, so it is NOT vouched for and does not join the denying set."""
    head, chain = _trust("41z")
    report = views.claim_capabilities(_claim("41b"), head, chain)
    assert report[KID_1]["cutoff_signer"] == "eligible"


def test_capabilities_never_names_a_cutoff_without_pins() -> None:
    """P12: `anchors` in the evidence does not imply an anchored declaration."""
    head, chain = _trust("41a")
    report = views.claim_capabilities(_claim("41a"), head, chain, log_keys=_log_keys("41a"))
    assert report[KID_1]["cutoff"] == "not_evaluated"


def test_capabilities_confine_a_broken_anchor_policy_to_a_view_error() -> None:
    head, chain = _trust("41a")
    with pytest.raises(views.ViewError):
        views.claim_capabilities(
            _claim("41a"),
            head,
            chain,
            log_keys=[],
            anchor_policy=_anchor_policy("41a"),
        )


def test_capabilities_ignores_a_kid_the_trusted_manifest_does_not_list() -> None:
    manifest = _manifest()
    manifest["keys"] = copy.deepcopy(manifest["keys"])
    manifest["keys"][0] = dict(manifest["keys"][0], kid="store.example.com/keys/other#ed25519-9")
    head, chain = _trust("41a")
    claim = {"manifest": manifest, "evidence": _evidence()}
    assert views.claim_capabilities(claim, head, chain) == {}


def test_capabilities_refuses_a_claim_that_is_not_an_object() -> None:
    head, chain = _trust("41a")
    with pytest.raises(views.ViewError):
        views.claim_capabilities(["not", "a", "claim"], head, chain)
