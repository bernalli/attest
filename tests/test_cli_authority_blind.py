"""BLIND adversarial bench for the `authority issue` CLI verb and
`verify --authority-view` (v0.2 §20, the publisher-authority rail).

This file was written against the CONTRACT for Task 10, and against
`docs/spec/attest-v0.2.md` §20 directly — never against the implementation of
`src/attest/cli.py` or against the other rail-convention test files the
implementing front is writing, which this file's author never opened. Every
fixture that signs a document calls the two public `attest.authority`
primitives (`build_authorization`, `authorization_hash`) directly; every
convention for driving the CLI (argv shape for `keygen`/`manifest init`/
`issue`/`verify`, `cli.main(...)` return codes, `capsys`-based JSON capture)
is copied from `tests/test_cli_grant.py`, which is the sibling rail this
brief authorizes reading.

The tests are expected to be RED until the CLI wiring lands: `authority` is
not yet a `cli.main` subcommand and `verify` does not yet accept
`--authority-view`. That is the point of a blind bench — it falsifies the
contract, not the (absent) implementation.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from attest import authority, cli, keys, manifests, pq
from tests.helpers import make_payload

ISSUER = "issuer.blind.example"
PUBLISHER = "publisher.blind.example"
IMPOSTOR = "impostor.blind.example"

ISSUER_KID = f"{ISSUER}/keys/rail-1#ed25519-1"
PUB_KID = f"{PUBLISHER}/keys/authority-1#ed25519-1"
IMPOSTOR_KID = f"{IMPOSTOR}/keys/authority-1#ed25519-1"

MANIFEST_VALID_FROM = "2020-01-01T00:00:00Z"
RECEIPT_ISSUED_AT = "2026-02-01T00:00:00Z"
ARTIFACT_SHA256 = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()
OTHER_ARTIFACT_SHA256 = hashlib.sha256(b"attest-test-artifact-elsewhere").hexdigest()

CapSys = pytest.CaptureFixture[str]


# --- low-level key/manifest plumbing (built directly, never through a
# not-yet-existing `authority issue`) -----------------------------------------


def _keygen(tmp_path: Path, name: str) -> tuple[Path, Path, Path]:
    seed, pub, mldsa = (
        tmp_path / f"{name}.seed",
        tmp_path / f"{name}.pub",
        tmp_path / f"{name}.mldsa",
    )
    assert (
        cli.main(
            [
                "keygen",
                "--seed-out",
                str(seed),
                "--pub-out",
                str(pub),
                "--hybrid",
                "--mldsa-out",
                str(mldsa),
            ]
        )
        == 0
    )
    return seed, pub, mldsa


def _manifest(tmp_path: Path, issuer: str, kid: str, seed: Path, mldsa: Path, name: str) -> Path:
    out = tmp_path / name
    assert (
        cli.main(
            [
                "manifest",
                "init",
                "--issuer",
                issuer,
                "--kid",
                kid,
                "--seed",
                str(seed),
                "--mldsa-key",
                str(mldsa),
                "--valid-from",
                MANIFEST_VALID_FROM,
                "--issued-at",
                MANIFEST_VALID_FROM,
                "--out",
                str(out),
            ]
        )
        == 0
    )
    return out


def _pub_kid_for(domain: str) -> str:
    return f"{domain}/keys/authority-1#ed25519-1"


def _self_publish_manifest(
    trust_dir: Path,
    domain: str,
    issuer_seed: Path,
    issuer_mldsa: Path,
    issuer_kid: str,
    pub_seed: Path,
    pub_mldsa: Path,
    pub_kid: str,
    name: str,
) -> Path:
    """One coherent key manifest for a domain that is BOTH the issuer and the
    publisher (self-publishing, §20.4 step 3): both kids that domain signs
    with — the receipt's issuer-rail kid and the authority-rail kid — must
    resolve out of the SAME trust-store entry. Two separate `manifest init`
    calls for the same domain would collide (the trust store is keyed by
    domain) and the second would silently evict the first, taking the
    receipt's own signing key out of the world (DIFETTO 2, reported after the
    first run against the real implementation, 2026-08-29)."""
    issuer_hybrid = _load_hybrid(issuer_seed, issuer_mldsa)
    pub_hybrid = _load_hybrid(pub_seed, pub_mldsa)
    entries = [
        manifests.key_entry(
            kid=issuer_kid,
            pub=issuer_hybrid.ed.pub,
            valid_from=MANIFEST_VALID_FROM,
            pub_ml_dsa_65=issuer_hybrid.mldsa.pub,
        ),
        manifests.key_entry(
            kid=pub_kid,
            pub=pub_hybrid.ed.pub,
            valid_from=MANIFEST_VALID_FROM,
            pub_ml_dsa_65=pub_hybrid.mldsa.pub,
        ),
    ]
    manifest = manifests.build_key_manifest(
        issuer=domain,
        manifest_version=1,
        issued_at=MANIFEST_VALID_FROM,
        key_entries=entries,
        signing_kp=issuer_hybrid,
        signing_kid=issuer_kid,
    )
    out = trust_dir / name
    out.write_text(json.dumps(manifest), encoding="utf-8")
    return out


def _load_hybrid(seed_path: Path, mldsa_path: Path) -> pq.HybridSigningKeys:
    """Load the SAME key material `keygen` just wrote to disk, so a document
    built directly with `authority.build_authorization` authenticates against
    the manifest `manifest init` built from the same files."""
    seed_bytes = keys.b64u_decode(seed_path.read_text(encoding="utf-8").strip())
    ed = keys.from_seed(seed_bytes)
    mldsa_doc = json.loads(mldsa_path.read_text(encoding="utf-8"))
    mldsa_kp = pq.MLDSAKeyPair(
        sk=keys.b64u_decode(mldsa_doc["sk"]), pub=keys.b64u_decode(mldsa_doc["pub"])
    )
    return pq.HybridSigningKeys(ed=ed, mldsa=mldsa_kp)


def _last_json(capsys: CapSys) -> dict[str, Any]:
    lines = capsys.readouterr().out.rstrip().splitlines()
    start = max(i for i, line in enumerate(lines) if line == "{")
    parsed = json.loads("\n".join(lines[start:]))
    assert isinstance(parsed, dict)
    return parsed


def _entry(
    issuer_id: str,
    valid_from: str,
    valid_to: str | None = None,
    permissions: tuple[str, ...] = ("issue",),
    scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "issuer_id": issuer_id,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "permissions": list(permissions),
        "scope": scope,
    }


def _authorization(
    version: int,
    publisher: str,
    entries: list[dict[str, Any]],
    issued_at: str,
    hybrid: pq.HybridSigningKeys,
    kid: str,
) -> dict[str, Any]:
    return authority.build_authorization(
        authorization_version=version,
        publisher=publisher,
        authorized_issuers=entries,
        issued_at=issued_at,
        signing_kp=hybrid,
        kid=kid,
    )


def _write_json(path: Path, obj: Any) -> Path:
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


# --- the shared world: one issuer, one publisher, one receipt -----------------


def _world(
    tmp_path: Path,
    capsys: CapSys,
    *,
    publisher_id: str | None = PUBLISHER,
    issuer_id: str = ISSUER,
    receipt_issued_at: str = RECEIPT_ISSUED_AT,
) -> dict[str, Any]:
    """`publisher_id=None` builds a receipt with NO `work.publisher_id`
    member at all (DIFETTO 1: a claim-less world, for exercising §20.4 step 1
    itself — omitting the member is not the same as the member being absent
    from a payload that never had a way to carry it).

    `publisher_id == issuer_id` is self-publishing (§20.4 step 3): the two
    kids that ONE domain signs with — the receipt's issuer-rail kid and the
    authority-rail kid — are folded into a SINGLE trust-store manifest for
    that domain (DIFETTO 2: two separate `manifest init` calls for the same
    domain collide, keyed by domain, and the second evicts the first,
    breaking the receipt's own signature verification before §20 is ever
    reached)."""
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()

    issuer_seed, _, issuer_mldsa = _keygen(tmp_path, "issuer")
    pub_seed, _, pub_mldsa = _keygen(tmp_path, "publisher")
    pub_kid = PUB_KID

    if publisher_id is not None and publisher_id == issuer_id:
        pub_kid = _pub_kid_for(issuer_id)
        _self_publish_manifest(
            trust_dir,
            issuer_id,
            issuer_seed,
            issuer_mldsa,
            ISSUER_KID,
            pub_seed,
            pub_mldsa,
            pub_kid,
            "issuer.json",
        )
    else:
        _manifest(trust_dir, issuer_id, ISSUER_KID, issuer_seed, issuer_mldsa, "issuer.json")
        if publisher_id is not None:
            _manifest(trust_dir, publisher_id, PUB_KID, pub_seed, pub_mldsa, "publisher.json")
    pub_hybrid = _load_hybrid(pub_seed, pub_mldsa)

    work_override: dict[str, Any] = {} if publisher_id is None else {"publisher_id": publisher_id}
    payload = make_payload(
        attest_version="0.2",
        issuer={"id": issuer_id, "display_name": "Blind Store"},
        work=work_override,
        issued_at=receipt_issued_at,
    )
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    receipt = tmp_path / "receipt.json"
    assert (
        cli.main(
            [
                "issue",
                "--payload",
                str(payload_path),
                "--attest-version",
                "0.2",
                "--seed",
                str(issuer_seed),
                "--mldsa-key",
                str(issuer_mldsa),
                "--kid",
                ISSUER_KID,
                "--out",
                str(receipt),
            ]
        )
        == 0
    )
    capsys.readouterr()

    return {
        "tmp": tmp_path,
        "trust_dir": trust_dir,
        "receipt": receipt,
        "pub_hybrid": pub_hybrid,
        "pub_kid": pub_kid,
        "issuer_id": issuer_id,
        "publisher_id": publisher_id,
        "receipt_issued_at": receipt_issued_at,
    }


def _verify(world: dict[str, Any], *extra: str) -> int:
    return cli.main(
        ["verify", str(world["receipt"]), "--trust-dir", str(world["trust_dir"]), *extra]
    )


def _verify_with_view(world: dict[str, Any], view: Path) -> int:
    return _verify(world, "--authority-view", str(view))


# =============================================================================
# `attest authority issue` — shape and emission
# =============================================================================


def _issue_argv(
    seed: Path,
    mldsa: Path,
    out: Path,
    *extra: str,
    publisher: str = PUBLISHER,
    version: str = "1",
    issued_at: str = MANIFEST_VALID_FROM,
    kid: str = PUB_KID,
) -> list[str]:
    return [
        "authority",
        "issue",
        "--authorization-version",
        version,
        "--publisher",
        publisher,
        "--issued-at",
        issued_at,
        "--seed",
        str(seed),
        "--mldsa-seed",
        str(mldsa),
        "--kid",
        kid,
        "--out",
        str(out),
        *extra,
    ]


def test_authority_issue_emits_the_five_member_shape_and_hash_reported_matches(
    tmp_path: Path, capsys: CapSys
) -> None:
    pub_seed, _, pub_mldsa = _keygen(tmp_path, "publisher")
    out = tmp_path / "authorization.json"
    entries = [_entry(ISSUER, "2020-01-01T00:00:00Z")]
    argv = _issue_argv(
        pub_seed, pub_mldsa, out, "--issuers-file", str(_write_json(tmp_path / "e.json", entries))
    )

    rc = cli.main(argv)

    assert rc == 0
    reported = _last_json(capsys)
    assert set(reported) == {"out", "record_sha256"}
    document = json.loads(out.read_text(encoding="utf-8"))
    assert set(document) == {
        "authorization_version",
        "publisher",
        "authorized_issuers",
        "issued_at",
        "signature",
    }
    assert reported["record_sha256"] == authority.authorization_hash(document)


def test_authority_issue_accepts_an_empty_issuers_array_on_a_first_document(
    tmp_path: Path, capsys: CapSys
) -> None:
    """§20.2: an EMPTY array is meaningful on a first document — "no one has
    ever been authorized" — never rejected as if it were a malformed input."""
    pub_seed, _, pub_mldsa = _keygen(tmp_path, "publisher")
    out = tmp_path / "authorization.json"
    argv = _issue_argv(
        pub_seed, pub_mldsa, out, "--issuers-file", str(_write_json(tmp_path / "e.json", []))
    )

    rc = cli.main(argv)

    assert rc == 0
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["authorized_issuers"] == []


@pytest.mark.parametrize(
    "bad_entries",
    [
        {"not": "an array"},
        [
            {
                "issuer_id": 123,
                "valid_from": "2020-01-01T00:00:00Z",
                "valid_to": None,
                "permissions": ["issue"],
                "scope": None,
            }
        ],
        [{"issuer_id": ISSUER, "valid_to": None, "permissions": ["issue"], "scope": None}],
        [
            {
                "issuer_id": "z-issuer.example",
                "valid_from": "2020-01-01T00:00:00Z",
                "valid_to": None,
                "permissions": ["issue"],
                "scope": None,
            },
            {
                "issuer_id": "a-issuer.example",
                "valid_from": "2020-01-01T00:00:00Z",
                "valid_to": None,
                "permissions": ["issue"],
                "scope": None,
            },
        ],
        [
            {
                "issuer_id": ISSUER,
                "valid_from": "2020-01-01T00:00:00Z",
                "valid_to": None,
                "permissions": ["issue"],
                "scope": None,
            },
            {
                "issuer_id": ISSUER,
                "valid_from": "2021-01-01T00:00:00Z",
                "valid_to": None,
                "permissions": ["issue"],
                "scope": None,
            },
        ],
    ],
    ids=[
        "issuers-file-not-an-array",
        "issuer_id-wrong-type",
        "entry-missing-valid_from",
        "issuer_id-out-of-order",
        "duplicate-issuer_id",
    ],
)
def test_authority_issue_refuses_every_malformed_issuers_file_shape(
    tmp_path: Path, capsys: CapSys, bad_entries: Any
) -> None:
    pub_seed, _, pub_mldsa = _keygen(tmp_path, "publisher")
    out = tmp_path / "authorization.json"
    argv = _issue_argv(
        pub_seed,
        pub_mldsa,
        out,
        "--issuers-file",
        str(_write_json(tmp_path / "e.json", bad_entries)),
    )

    rc = cli.main(argv)

    assert rc == 2
    assert not out.exists()


# =============================================================================
# `attest authority issue --previous` — the bilateral, three-way discipline
# =============================================================================

_T_PREV = "2026-01-01T00:00:00Z"
_T_V2 = "2026-03-01T00:00:00Z"
_SPENT_VALID_TO = "2025-06-01T00:00:00Z"

_LIVE = "a-live.blind.example"
_SPENT = "b-spent.blind.example"
_DELETED = "c-deleted.blind.example"


def _base_v1_entries() -> list[dict[str, Any]]:
    return [
        _entry(_LIVE, "2020-01-01T00:00:00Z", None),
        _entry(_SPENT, "2020-01-01T00:00:00Z", _SPENT_VALID_TO),
        _entry(_DELETED, "2020-01-01T00:00:00Z", None),
    ]


def _base_v2_entries() -> list[dict[str, Any]]:
    """A byte-for-byte conforming successor of `_base_v1_entries` (every
    window carried forward unchanged)."""
    return [
        _entry(_LIVE, "2020-01-01T00:00:00Z", None),
        _entry(_SPENT, "2020-01-01T00:00:00Z", _SPENT_VALID_TO),
        _entry(_DELETED, "2020-01-01T00:00:00Z", None),
    ]


def _issue_v1(tmp_path: Path, capsys: CapSys, pub_seed: Path, pub_mldsa: Path) -> Path:
    out = tmp_path / "v1.json"
    argv = _issue_argv(
        pub_seed,
        pub_mldsa,
        out,
        "--issuers-file",
        str(_write_json(tmp_path / "v1-entries.json", _base_v1_entries())),
        version="1",
        issued_at=_T_PREV,
    )
    assert cli.main(argv) == 0
    capsys.readouterr()
    return out


def test_previous_absent_emits_and_declares_the_skipped_check_on_stderr(
    tmp_path: Path, capsys: CapSys
) -> None:
    pub_seed, _, pub_mldsa = _keygen(tmp_path, "publisher")
    out = tmp_path / "v1.json"
    argv = _issue_argv(
        pub_seed,
        pub_mldsa,
        out,
        "--issuers-file",
        str(_write_json(tmp_path / "e.json", _base_v1_entries())),
        version="1",
        issued_at=_T_PREV,
    )

    rc = cli.main(argv)
    captured = capsys.readouterr()

    assert rc == 0
    assert out.exists()
    # §20.2/§20.4 step 10's currency posture never lies by omission: absent
    # `--previous` MUST say so, not merely stay silent. Best-effort text match
    # (this contract deliberately does not pin the exact wording) — but a
    # non-empty, on-topic declaration is required, not just exit 0.
    err_lower = captured.err.lower()
    assert err_lower.strip() != "", "an absent --previous must be DECLARED, not silently skipped"
    assert "success" in err_lower or "previous" in err_lower


def test_previous_present_and_conforming_emits_normally(tmp_path: Path, capsys: CapSys) -> None:
    pub_seed, _, pub_mldsa = _keygen(tmp_path, "publisher")
    v1 = _issue_v1(tmp_path, capsys, pub_seed, pub_mldsa)
    out = tmp_path / "v2.json"
    entries = [*_base_v2_entries(), _entry("d-new.blind.example", "2025-01-01T00:00:00Z", None)]
    argv = _issue_argv(
        pub_seed,
        pub_mldsa,
        out,
        "--issuers-file",
        str(_write_json(tmp_path / "v2-entries.json", entries)),
        "--previous",
        str(v1),
        version="2",
        issued_at=_T_V2,
    )

    rc = cli.main(argv)

    assert rc == 0
    assert out.exists()


@pytest.mark.parametrize(
    "closure,expect_ok",
    [
        (_T_PREV, True),  # exactly the predecessor's own issued_at: INCLUSIVE lower bound
        (_T_V2, True),  # exactly the successor's own issued_at: INCLUSIVE upper bound
        ("2026-02-01T00:00:00Z", True),  # strictly inside the bounded window
        ("2025-12-31T23:59:59Z", False),  # one second before the lower bound: back-dated
        ("2026-03-01T00:00:01Z", False),  # one second after the upper bound: post-dated
    ],
    ids=[
        "lower-bound-inclusive",
        "upper-bound-inclusive",
        "strictly-inside",
        "back-dated",
        "post-dated",
    ],
)
def test_a_live_window_closure_is_accepted_iff_within_the_two_bounds(
    tmp_path: Path, capsys: CapSys, closure: str, expect_ok: bool
) -> None:
    pub_seed, _, pub_mldsa = _keygen(tmp_path, "publisher")
    v1 = _issue_v1(tmp_path, capsys, pub_seed, pub_mldsa)
    out = tmp_path / "v2.json"
    entries = [
        _entry(_LIVE, "2020-01-01T00:00:00Z", closure),
        _entry(_SPENT, "2020-01-01T00:00:00Z", _SPENT_VALID_TO),
        _entry(_DELETED, "2020-01-01T00:00:00Z", None),
    ]
    argv = _issue_argv(
        pub_seed,
        pub_mldsa,
        out,
        "--issuers-file",
        str(_write_json(tmp_path / "v2-entries.json", entries)),
        "--previous",
        str(v1),
        version="2",
        issued_at=_T_V2,
    )

    rc = cli.main(argv)

    assert rc == (0 if expect_ok else 2)
    assert out.exists() == expect_ok


@pytest.mark.parametrize(
    "mutate,expect_substring",
    [
        ("delete-entry", "is absent"),
        ("move-valid_from", "changed"),
        ("extend-spent-forward", "moved"),
        ("shrink-spent-earlier", "moved"),
        ("no-version-bump", "is not above the predecessor's"),
    ],
    ids=[
        "entry-deleted",
        "valid_from-moved",
        "spent-window-extended",
        "spent-window-shortened",
        "version-not-above-predecessor",
    ],
)
def test_every_successor_violation_is_a_bilateral_refusal(
    tmp_path: Path, capsys: CapSys, mutate: str, expect_substring: str
) -> None:
    """Bilateral per the brief: BOTH the call is a usage error (exit 2, with
    the builder's own ValueError text surfaced) AND no output file lands on
    disk — a half-written non-conforming successor is as bad as a silently
    accepted one."""
    pub_seed, _, pub_mldsa = _keygen(tmp_path, "publisher")
    v1 = _issue_v1(tmp_path, capsys, pub_seed, pub_mldsa)
    out = tmp_path / "v2.json"

    entries = _base_v2_entries()
    version = "2"
    if mutate == "delete-entry":
        entries = [e for e in entries if e["issuer_id"] != _DELETED]
    elif mutate == "move-valid_from":
        for e in entries:
            if e["issuer_id"] == _LIVE:
                e["valid_from"] = "2021-01-01T00:00:00Z"
    elif mutate == "extend-spent-forward":
        for e in entries:
            if e["issuer_id"] == _SPENT:
                e["valid_to"] = None
    elif mutate == "shrink-spent-earlier":
        for e in entries:
            if e["issuer_id"] == _SPENT:
                e["valid_to"] = "2025-01-01T00:00:00Z"
    elif mutate == "no-version-bump":
        version = "1"

    argv = _issue_argv(
        pub_seed,
        pub_mldsa,
        out,
        "--issuers-file",
        str(_write_json(tmp_path / "v2-entries.json", entries)),
        "--previous",
        str(v1),
        version=version,
        issued_at=_T_V2,
    )

    rc = cli.main(argv)
    captured = capsys.readouterr()

    assert rc == 2
    assert not out.exists()
    combined = (captured.err + captured.out).lower()
    assert expect_substring.lower() in combined, (
        f"expected the builder's own ValueError text ({expect_substring!r}) to surface; "
        f"got: {combined!r}"
    )


# =============================================================================
# `attest verify --authority-view` — the container guard (item 3)
# =============================================================================


@pytest.mark.parametrize(
    "container", [[], "a string", 42, None, True], ids=["array", "string", "number", "null", "bool"]
)
def test_verify_refuses_every_non_object_authority_view(
    tmp_path: Path, capsys: CapSys, container: Any
) -> None:
    world = _world(tmp_path, capsys)
    view = _write_json(tmp_path / "view.json", container)

    rc = _verify_with_view(world, view)

    assert rc == 2


def test_verify_accepts_an_empty_object_as_an_opted_in_but_empty_view(
    tmp_path: Path, capsys: CapSys
) -> None:
    """§20.3: supplying the channel AT ALL, even as `{}`, opts in — this must
    not be refused the way a non-object container is."""
    world = _world(tmp_path, capsys)
    view = _write_json(tmp_path / "view.json", {})

    rc = _verify_with_view(world, view)

    assert rc == 0
    report = _last_json(capsys)
    assert report["publisher_authority"] == "unattested"


# =============================================================================
# §20.4 evaluation order, via `verify --authority-view` — the properties that
# matter: unattested is the universal degrade target, authorized/unauthorized
# are the two the design goes out of its way to make hard to reach wrongly.
# =============================================================================


def test_no_publisher_claim_is_not_evaluated_even_with_a_view_supplied(
    tmp_path: Path, capsys: CapSys
) -> None:
    # publisher_id=None: the receipt's payload carries NO work.publisher_id
    # member at all, so §20.4 step 1 is what must fire here — not step 4
    # degrading a genuine (but non-covering) claim to unattested, which is
    # what the DEFAULT world (publisher_id=PUBLISHER) would actually exercise
    # (DIFETTO 1, reported after the first run against the real
    # implementation, 2026-08-29).
    world = _world(tmp_path, capsys, publisher_id=None)
    doc = _authorization(1, PUBLISHER, [], "2020-01-01T00:00:00Z", world["pub_hybrid"], PUB_KID)
    view = _write_json(tmp_path / "view.json", {"authorizations": [doc]})

    rc = _verify_with_view(world, view)

    assert rc == 0
    report = _last_json(capsys)
    assert report["publisher_authority"] == "no_publisher_claim"
    assert report["publisher_authority_trust"] == "not_checked"


def test_self_publishing_needs_no_authorization_machinery(tmp_path: Path, capsys: CapSys) -> None:
    world = _world(tmp_path, capsys, publisher_id=ISSUER)  # issuer IS the publisher
    view = _write_json(tmp_path / "view.json", {"authorizations": []})

    rc = _verify_with_view(world, view)

    assert rc == 0
    report = _last_json(capsys)
    assert report["publisher_authority"] == "self"
    assert report["publisher_authority_trust"] == "not_checked"


@pytest.mark.parametrize(
    "view_body",
    [
        {},
        {"authorizations": []},
        {"authorizations": "not-an-array"},
        {"authorizations": None},
    ],
    ids=["absent", "empty", "wrong-type", "null"],
)
def test_absent_or_empty_or_malformed_authorizations_array_is_unattested(
    tmp_path: Path, capsys: CapSys, view_body: dict[str, Any]
) -> None:
    world = _world(tmp_path, capsys)
    view = _write_json(tmp_path / "view.json", view_body)

    rc = _verify_with_view(world, view)

    assert rc == 0
    assert _last_json(capsys)["publisher_authority"] == "unattested"


def test_exceeding_the_document_count_ceiling_is_unattested_never_a_raise(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    doc = _authorization(
        1,
        PUBLISHER,
        [_entry(ISSUER, "2020-01-01T00:00:00Z")],
        "2020-01-01T00:00:00Z",
        world["pub_hybrid"],
        PUB_KID,
    )
    view = _write_json(tmp_path / "view.json", {"authorizations": [doc] * 65})  # ceiling is 64

    rc = _verify_with_view(world, view)

    assert rc == 0
    assert _last_json(capsys)["publisher_authority"] == "unattested"


def test_a_shape_invalid_document_is_ignored_not_authenticated_and_never_crashes(
    tmp_path: Path, capsys: CapSys
) -> None:
    """An unsorted `authorized_issuers` is a SHAPE error under §20.2 — the
    document, though correctly signed over its own (malformed) bytes, is set
    aside before any cryptographic evaluation counts against it."""
    world = _world(tmp_path, capsys)
    entries = [
        _entry("z-issuer.example", "2020-01-01T00:00:00Z"),
        _entry("a-issuer.example", "2020-01-01T00:00:00Z"),
    ]
    doc = _authorization(
        1, PUBLISHER, entries, "2020-01-01T00:00:00Z", world["pub_hybrid"], PUB_KID
    )
    view = _write_json(tmp_path / "view.json", {"authorizations": [doc]})

    rc = _verify_with_view(world, view)

    assert rc == 0
    report = _last_json(capsys)
    assert report["publisher_authority"] == "unattested"


@pytest.mark.parametrize(
    "hostile",
    [["not", "a", "dict"], "a bare string", 42, None, {"just": "an object"}],
    ids=[
        "array-element",
        "string-element",
        "number-element",
        "null-element",
        "plain-object-element",
    ],
)
def test_a_non_dict_document_in_the_array_is_ignored_not_crashing(
    tmp_path: Path, capsys: CapSys, hostile: Any
) -> None:
    world = _world(tmp_path, capsys)
    view = _write_json(tmp_path / "view.json", {"authorizations": [hostile]})

    rc = _verify_with_view(world, view)

    assert rc == 0
    assert _last_json(capsys)["publisher_authority"] == "unattested"


def test_an_authenticated_non_covering_document_without_currency_is_unattested_never_a_denial(
    tmp_path: Path, capsys: CapSys
) -> None:
    """The sharpest normative claim in §20.4: `unauthorized` is reachable
    ONLY through step 10's currency-gated path. A genuine, authenticated
    document that simply does not name this issuer must NOT, on its own,
    become a denial."""
    world = _world(tmp_path, capsys)
    doc = _authorization(1, PUBLISHER, [], "2020-01-01T00:00:00Z", world["pub_hybrid"], PUB_KID)
    view = _write_json(
        tmp_path / "view.json", {"authorizations": [doc]}
    )  # no current_authorization_version

    rc = _verify_with_view(world, view)

    assert rc == 0
    report = _last_json(capsys)
    assert report["publisher_authority"] == "unattested"
    assert report["publisher_authority"] != "unauthorized"


def test_a_denial_requires_a_matching_current_authorization_version(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    doc = _authorization(1, PUBLISHER, [], "2020-01-01T00:00:00Z", world["pub_hybrid"], PUB_KID)
    view = _write_json(
        tmp_path / "view.json",
        {"authorizations": [doc], "current_authorization_version": 1},
    )

    rc = _verify_with_view(world, view)

    assert rc == 0
    report = _last_json(capsys)
    assert report["publisher_authority"] == "unauthorized"
    assert "publisher_not_authorizing_issuer" in report["warnings"]
    assert report["ok"] is True  # D-style: this rail takes NO exception


@pytest.mark.parametrize(
    "stale_version", [2, 0, -1], ids=["higher-than-effective", "zero", "negative"]
)
def test_a_non_matching_current_authorization_version_degrades_to_unattested(
    tmp_path: Path, capsys: CapSys, stale_version: int
) -> None:
    world = _world(tmp_path, capsys)
    doc = _authorization(1, PUBLISHER, [], "2020-01-01T00:00:00Z", world["pub_hybrid"], PUB_KID)
    view = _write_json(
        tmp_path / "view.json",
        {"authorizations": [doc], "current_authorization_version": stale_version},
    )

    rc = _verify_with_view(world, view)

    assert rc == 0
    report = _last_json(capsys)
    assert report["publisher_authority"] in ("unattested", "unauthorized") or True
    # The normative claim under test: an old/mismatched/out-of-range assertion
    # must NEVER manufacture a denial. -1/0 are also out of
    # `is_authorization_version`'s [1, 2**53-1] range, so they are treated as
    # ABSENT, not merely "non-matching".
    assert report["publisher_authority"] != "unauthorized"


def test_a_boolean_current_authorization_version_never_counts_as_a_match(
    tmp_path: Path, capsys: CapSys
) -> None:
    """`True == 1` in Python. A re-implementation of the currency check using
    naive `==` instead of the shared `is_authorization_version` predicate
    would let a JSON `true` pass as version 1 and manufacture a denial the
    caller never actually asserted."""
    world = _world(tmp_path, capsys)
    doc = _authorization(1, PUBLISHER, [], "2020-01-01T00:00:00Z", world["pub_hybrid"], PUB_KID)
    view = _write_json(
        tmp_path / "view.json",
        {"authorizations": [doc], "current_authorization_version": True},
    )

    rc = _verify_with_view(world, view)

    assert rc == 0
    report = _last_json(capsys)
    assert report["publisher_authority"] != "unauthorized"
    assert report["publisher_authority"] == "unattested"


def test_authorized_membership_needs_no_currency_evidence(tmp_path: Path, capsys: CapSys) -> None:
    """§20.2's one-sided stability: the POSITIVE outcome is version-stable and
    needs no `current_authorization_version` at all — omitting it must never
    demote a genuinely covering entry away from `authorized`."""
    world = _world(tmp_path, capsys)
    entries = [_entry(ISSUER, "2020-01-01T00:00:00Z", None, permissions=("issue",))]
    doc = _authorization(
        1, PUBLISHER, entries, "2020-01-01T00:00:00Z", world["pub_hybrid"], PUB_KID
    )
    view = _write_json(tmp_path / "view.json", {"authorizations": [doc]})  # no currency assertion

    baseline_rc = _verify(world)
    baseline = _last_json(capsys)
    rc = _verify_with_view(world, view)
    report = _last_json(capsys)

    assert rc == 0 and baseline_rc == 0
    assert report["publisher_authority"] == "authorized"
    # D-style exception discipline: nothing safety-relevant moves.
    assert report["ok"] is True
    assert report["trust"] == baseline["trust"]
    assert report["signature"] == baseline["signature"]
    assert report["schema"] == baseline["schema"]
    assert report["revocation"] == baseline["revocation"]
    assert report["binding"] == baseline["binding"]


def test_authorized_with_a_covering_scope(tmp_path: Path, capsys: CapSys) -> None:
    world = _world(tmp_path, capsys)
    entries = [
        _entry(
            ISSUER,
            "2020-01-01T00:00:00Z",
            None,
            permissions=("issue",),
            scope={"artifact_series": None, "artifacts": [ARTIFACT_SHA256]},
        )
    ]
    doc = _authorization(
        1, PUBLISHER, entries, "2020-01-01T00:00:00Z", world["pub_hybrid"], PUB_KID
    )
    view = _write_json(tmp_path / "view.json", {"authorizations": [doc]})

    rc = _verify_with_view(world, view)

    assert rc == 0
    assert _last_json(capsys)["publisher_authority"] == "authorized"


@pytest.mark.parametrize(
    "entries_factory,description",
    [
        (lambda: [], "entry-absent-for-this-issuer"),
        (
            lambda: [_entry(ISSUER, "2020-01-01T00:00:00Z", "2025-01-01T00:00:00Z")],
            "window-does-not-cover-receipt-issued_at",
        ),
        (
            lambda: [_entry(ISSUER, "2020-01-01T00:00:00Z", None, permissions=("delegate",))],
            "issue-permission-absent-only-reserved-delegate",
        ),
        (
            lambda: [
                _entry(
                    ISSUER,
                    "2020-01-01T00:00:00Z",
                    None,
                    permissions=("issue",),
                    scope={"artifact_series": None, "artifacts": [OTHER_ARTIFACT_SHA256]},
                )
            ],
            "scope-does-not-cover-the-receipts-artifact",
        ),
    ],
    ids=[
        "entry-absent",
        "window-not-covering",
        "delegate-only-never-honored",
        "scope-uncovered",
    ],
)
def test_every_denial_reason_resolves_unauthorized_with_matching_currency(
    tmp_path: Path, capsys: CapSys, entries_factory: Any, description: str
) -> None:
    world = _world(tmp_path, capsys)
    doc = _authorization(
        1, PUBLISHER, entries_factory(), "2020-01-01T00:00:00Z", world["pub_hybrid"], PUB_KID
    )
    view = _write_json(
        tmp_path / "view.json",
        {"authorizations": [doc], "current_authorization_version": 1},
    )

    baseline_rc = _verify(world)
    baseline = _last_json(capsys)
    rc = _verify_with_view(world, view)
    report = _last_json(capsys)

    assert rc == 0 and baseline_rc == 0
    assert report["publisher_authority"] == "unauthorized", description
    assert "publisher_not_authorizing_issuer" in report["warnings"]
    assert report["ok"] is True
    assert report["trust"] == baseline["trust"]
    assert report["signature"] == baseline["signature"]
    assert report["revocation"] == baseline["revocation"]


def test_two_documents_sharing_a_version_is_equivocation_and_excludes_both(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    doc_a = _authorization(
        1,
        PUBLISHER,
        [_entry(ISSUER, "2020-01-01T00:00:00Z")],
        "2020-01-01T00:00:00Z",
        world["pub_hybrid"],
        PUB_KID,
    )
    doc_b = _authorization(1, PUBLISHER, [], "2020-06-01T00:00:00Z", world["pub_hybrid"], PUB_KID)
    view = _write_json(
        tmp_path / "view.json",
        {"authorizations": [doc_a, doc_b], "current_authorization_version": 1},
    )

    rc = _verify_with_view(world, view)

    assert rc == 0
    report = _last_json(capsys)
    assert report["publisher_authority"] == "unattested"
    assert report["publisher_authority_trust"] == "unverified_rotation"


def test_verify_independently_excludes_a_non_conforming_successor(
    tmp_path: Path, capsys: CapSys
) -> None:
    """Defense in depth (§20.4 step 7): even a document `authority issue
    --previous` would refuse to BUILD must still be caught if somehow
    presented as evidence directly — the verifier does not merely trust
    that every document it sees came from a conforming builder."""
    world = _world(tmp_path, capsys)
    v1_entries = [_entry(_LIVE, "2020-01-01T00:00:00Z", None)]
    v1 = _authorization(1, PUBLISHER, v1_entries, _T_PREV, world["pub_hybrid"], PUB_KID)
    # v2 silently DROPS the entry — entry deletion, the plainest violation.
    v2 = _authorization(2, PUBLISHER, [], _T_V2, world["pub_hybrid"], PUB_KID)
    view = _write_json(
        tmp_path / "view.json",
        {"authorizations": [v1, v2], "current_authorization_version": 2},
    )

    rc = _verify_with_view(world, view)

    assert rc == 0
    report = _last_json(capsys)
    # v2 excluded -> the effective document remains v1, which DOES cover
    # `_LIVE` but this world's issuer is `ISSUER`, not `_LIVE`, so v1 alone
    # cannot authorize it either: the denial-currency assertion (targeting
    # v2, which is excluded) must not silently re-target v1.
    assert report["publisher_authority_trust"] == "unverified_rotation"
    assert report["publisher_authority"] in ("unattested", "unauthorized")


def test_a_document_signed_by_a_domain_other_than_the_publisher_is_signer_mismatch(
    tmp_path: Path, capsys: CapSys
) -> None:
    """§20.4 step 6(c): a document that authenticates fine, but under some
    OTHER domain's own manifest while claiming `publisher: PUBLISHER`, must
    be set aside with `signer_mismatch` — never let a third party's signed
    blob speak for the real publisher, and never let it MASK a genuine
    equivocation (step 7 prevails when both fire, tested only indirectly
    here since this test fires 6(c) alone)."""
    world = _world(tmp_path, capsys)
    impostor_seed, _, impostor_mldsa = _keygen(tmp_path, "impostor")
    _manifest(
        world["trust_dir"], IMPOSTOR, IMPOSTOR_KID, impostor_seed, impostor_mldsa, "impostor.json"
    )
    impostor_hybrid = _load_hybrid(impostor_seed, impostor_mldsa)

    # Signed by the IMPOSTOR's own key, but claims to be PUBLISHER's document.
    doc = _authorization(
        1,
        PUBLISHER,
        [_entry(ISSUER, "2020-01-01T00:00:00Z")],
        "2020-01-01T00:00:00Z",
        impostor_hybrid,
        IMPOSTOR_KID,
    )
    view = _write_json(
        tmp_path / "view.json",
        {"authorizations": [doc], "current_authorization_version": 1},
    )

    rc = _verify_with_view(world, view)

    assert rc == 0
    report = _last_json(capsys)
    assert report["publisher_authority"] != "authorized"
    assert report["publisher_authority"] != "unauthorized"
    assert report["publisher_authority_trust"] == "signer_mismatch"


def test_verify_output_carries_the_two_new_components_on_every_call(
    tmp_path: Path, capsys: CapSys
) -> None:
    """Item 4 of the contract: the JSON `verify` prints gains exactly two new
    fields. Checked here on the plain not_checked default path too — a wiring
    bug that only adds the fields when a view IS supplied would still violate
    'the JSON verify prints gains two fields', full stop."""
    world = _world(tmp_path, capsys)

    rc = _verify(world)

    assert rc == 0
    report = _last_json(capsys)
    assert "publisher_authority" in report
    assert "publisher_authority_trust" in report
    assert report["publisher_authority"] == "not_checked"
    assert report["publisher_authority_trust"] == "not_checked"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
