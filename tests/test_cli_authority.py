"""CLI coverage for publisher authorization manifests and --authority-view."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from attest import authority, cli
from tests.helpers import make_payload

ISSUER = "store.example.com"
PUBLISHER = "pub.example"
OTHER_ISSUER = "marketplace.example"

ISSUER_KID = f"{ISSUER}/keys/authority#1"
PUB_KID = f"{PUBLISHER}/keys/authority#1"

VALID_FROM = "2026-01-01T00:00:00Z"
AUTH_ISSUED_AT = "2026-02-01T00:00:00Z"
LATER_ISSUED_AT = "2026-09-01T00:00:00Z"
RECEIPT_ART = hashlib.sha256(b"attest-test-artifact-v1").hexdigest()
RECEIPT_SERIES = "store.example.com/works/EXG-001"

CapSys = pytest.CaptureFixture[str]


def _last_json(capsys: CapSys) -> dict[str, Any]:
    lines = capsys.readouterr().out.rstrip().splitlines()
    start = max(i for i, line in enumerate(lines) if line == "{")
    parsed = json.loads("\n".join(lines[start:]))
    assert isinstance(parsed, dict)
    return parsed


def _keygen(tmp_path: Path, name: str) -> tuple[Path, Path]:
    seed = tmp_path / f"{name}.seed"
    pub = tmp_path / f"{name}.pub"
    assert cli.main(["keygen", "--seed-out", str(seed), "--pub-out", str(pub)]) == 0
    return seed, pub


def _manifest(trust_dir: Path, issuer: str, kid: str, seed: Path, name: str) -> Path:
    out = trust_dir / name
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
                "--valid-from",
                VALID_FROM,
                "--issued-at",
                VALID_FROM,
                "--out",
                str(out),
            ]
        )
        == 0
    )
    return out


def _entry(
    issuer_id: Any = ISSUER,
    valid_from: Any = VALID_FROM,
    valid_to: Any = None,
    permissions: Any = None,
    scope: Any = None,
) -> dict[str, Any]:
    return {
        "issuer_id": issuer_id,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "permissions": [authority.PERMISSION_ISSUE] if permissions is None else permissions,
        "scope": scope,
    }


def _write_json(path: Path, value: Any) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _authority_issue_argv(
    seed: Path,
    out: Path,
    *extra: str,
    version: int = 1,
    issued_at: str = AUTH_ISSUED_AT,
) -> list[str]:
    return [
        "authority",
        "issue",
        "--authorization-version",
        str(version),
        "--publisher",
        PUBLISHER,
        "--issued-at",
        issued_at,
        "--issuer",
        ISSUER,
        "--valid-from",
        VALID_FROM,
        "--seed",
        str(seed),
        "--kid",
        PUB_KID,
        "--out",
        str(out),
        *extra,
    ]


def _world(tmp_path: Path, capsys: CapSys) -> dict[str, Any]:
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()

    issuer_seed, _ = _keygen(tmp_path, "issuer")
    pub_seed, _ = _keygen(tmp_path, "publisher")

    _manifest(trust_dir, ISSUER, ISSUER_KID, issuer_seed, "issuer.json")
    _manifest(trust_dir, PUBLISHER, PUB_KID, pub_seed, "publisher.json")

    payload = make_payload(work={"publisher_id": PUBLISHER})
    payload_path = _write_json(tmp_path / "payload.json", payload)
    receipt = tmp_path / "receipt.json"
    assert (
        cli.main(
            [
                "issue",
                "--payload",
                str(payload_path),
                "--seed",
                str(issuer_seed),
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
        "trust_dir": trust_dir,
        "receipt": receipt,
        "pub_seed": pub_seed,
    }


def test_authority_issue_writes_a_document_that_authenticates_and_reports_its_hash(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    out = tmp_path / "authority.json"

    assert cli.main(_authority_issue_argv(world["pub_seed"], out)) == 0
    report = _last_json(capsys)
    document = json.loads(out.read_text(encoding="utf-8"))

    assert set(document) == {
        "authorization_version",
        "publisher",
        "authorized_issuers",
        "issued_at",
        "signature",
    }
    assert document["authorized_issuers"] == [_entry()]
    assert report == {"out": str(out), "record_sha256": authority.authorization_hash(document)}


def test_round_trip_issue_then_verify_with_authority_view_reports_authorized(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    authorization = tmp_path / "authority.json"
    assert cli.main(_authority_issue_argv(world["pub_seed"], authorization)) == 0
    capsys.readouterr()
    view = _write_json(
        tmp_path / "authority-view.json",
        {"authorizations": [json.loads(authorization.read_text(encoding="utf-8"))]},
    )

    rc = cli.main(
        [
            "verify",
            str(world["receipt"]),
            "--trust-dir",
            str(world["trust_dir"]),
            "--authority-view",
            str(view),
        ]
    )
    report = _last_json(capsys)

    assert rc == 0
    assert report["ok"] is True
    assert report["publisher_authority"] == "authorized"
    assert report["publisher_authority_trust"] == "unauthenticated_tofu"


def test_verify_refuses_an_authority_view_file_that_is_not_an_object(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    view = _write_json(tmp_path / "authority-view.json", [])

    rc = cli.main(
        [
            "verify",
            str(world["receipt"]),
            "--trust-dir",
            str(world["trust_dir"]),
            "--authority-view",
            str(view),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert f"--authority-view file {view} must contain a JSON object" in captured.err
    assert 'wrap a lone publisher authorization document as {"authorizations": [<document>]}' in (
        captured.err
    )


def test_previous_conforming_successor_emits(tmp_path: Path, capsys: CapSys) -> None:
    world = _world(tmp_path, capsys)
    previous = tmp_path / "authority-v1.json"
    successor = tmp_path / "authority-v2.json"
    assert cli.main(_authority_issue_argv(world["pub_seed"], previous)) == 0
    capsys.readouterr()

    rc = cli.main(
        _authority_issue_argv(
            world["pub_seed"],
            successor,
            "--previous",
            str(previous),
            version=2,
            issued_at=LATER_ISSUED_AT,
        )
    )
    captured = capsys.readouterr()

    assert rc == 0
    assert successor.exists()
    assert "successor discipline was not checked" not in captured.err


def test_previous_violation_is_usage_error_and_leaves_no_output(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    previous = tmp_path / "authority-v1.json"
    issuers_file = _write_json(tmp_path / "empty-issuers.json", [])
    out = tmp_path / "non-successor.json"
    assert cli.main(_authority_issue_argv(world["pub_seed"], previous)) == 0
    capsys.readouterr()

    rc = cli.main(
        [
            "authority",
            "issue",
            "--authorization-version",
            "2",
            "--publisher",
            PUBLISHER,
            "--issued-at",
            LATER_ISSUED_AT,
            "--issuers-file",
            str(issuers_file),
            "--previous",
            str(previous),
            "--seed",
            str(world["pub_seed"]),
            "--kid",
            PUB_KID,
            "--out",
            str(out),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "entry for 'store.example.com' is absent" in captured.err
    assert not out.exists()


def test_absent_previous_emits_but_declares_the_successor_check_was_not_done(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    out = tmp_path / "authority.json"

    rc = cli.main(_authority_issue_argv(world["pub_seed"], out))
    captured = capsys.readouterr()

    assert rc == 0
    assert out.exists()
    assert (
        "warning: --previous not provided; publisher authorization successor "
        "discipline was not checked"
    ) in captured.err


def test_authority_issue_from_issuers_file_accepts_heterogeneous_entries(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    entries = [
        _entry(
            issuer_id=OTHER_ISSUER,
            permissions=[authority.PERMISSION_DELEGATE, authority.PERMISSION_ISSUE],
            scope={"artifact_series": RECEIPT_SERIES, "artifacts": []},
        ),
        _entry(scope={"artifact_series": None, "artifacts": [RECEIPT_ART]}),
    ]
    issuers_file = _write_json(tmp_path / "issuers.json", entries)
    out = tmp_path / "authority.json"

    rc = cli.main(
        [
            "authority",
            "issue",
            "--authorization-version",
            "1",
            "--publisher",
            PUBLISHER,
            "--issued-at",
            AUTH_ISSUED_AT,
            "--issuers-file",
            str(issuers_file),
            "--seed",
            str(world["pub_seed"]),
            "--kid",
            PUB_KID,
            "--out",
            str(out),
        ]
    )
    document = json.loads(out.read_text(encoding="utf-8"))

    assert rc == 0
    assert document["authorized_issuers"] == entries


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ({"issuer_id": ISSUER}, "must contain a JSON array of authorized issuer entries"),
        ([None], "authorized_issuers[0] must be an object"),
        (
            [{key: value for key, value in _entry().items() if key != "valid_to"}],
            "authorized_issuers[0] is not a valid authorization entry",
        ),
        (
            [_entry(valid_to=42)],
            "authorized_issuers[0] is not a valid authorization entry",
        ),
        (
            [_entry(permissions=["issue", "delegate"])],
            "authorized_issuers[0] is not a valid authorization entry",
        ),
        (
            [_entry(issuer_id="z.example"), _entry(issuer_id="a.example")],
            "authorized_issuers must be sorted by issuer_id with no duplicates",
        ),
        (
            [_entry(), _entry()],
            "authorized_issuers must be sorted by issuer_id with no duplicates",
        ),
    ],
)
def test_authority_issue_rejects_malformed_issuers_file_inputs(
    tmp_path: Path, capsys: CapSys, content: Any, message: str
) -> None:
    world = _world(tmp_path, capsys)
    issuers_file = _write_json(tmp_path / "bad-issuers.json", content)
    out = tmp_path / "authority.json"

    rc = cli.main(
        [
            "authority",
            "issue",
            "--authorization-version",
            "1",
            "--publisher",
            PUBLISHER,
            "--issued-at",
            AUTH_ISSUED_AT,
            "--issuers-file",
            str(issuers_file),
            "--seed",
            str(world["pub_seed"]),
            "--kid",
            PUB_KID,
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert message in capsys.readouterr().err
    assert not out.exists()


def test_authority_issue_sorts_and_deduplicates_repeated_issuer_flags(
    tmp_path: Path, capsys: CapSys
) -> None:
    world = _world(tmp_path, capsys)
    out = tmp_path / "authority.json"

    rc = cli.main(
        _authority_issue_argv(
            world["pub_seed"],
            out,
            "--issuer",
            OTHER_ISSUER,
            "--issuer",
            ISSUER,
        )
    )
    document = json.loads(out.read_text(encoding="utf-8"))

    assert rc == 0
    assert [entry["issuer_id"] for entry in document["authorized_issuers"]] == sorted(
        {ISSUER, OTHER_ISSUER}
    )


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--issuer", ISSUER, "--issuers-file", "unused.json"],
        ["--issuer", "Store.Example.Com"],
        ["--issuer", ISSUER, "--valid-from", "not-a-timestamp"],
        ["--issuer", ISSUER, "--permission", ""],
        ["--issuer", ISSUER, "--artifact", "NOT-A-HASH"],
    ],
)
def test_authority_issue_rejects_bad_flag_built_entries(
    tmp_path: Path, capsys: CapSys, extra: list[str]
) -> None:
    world = _world(tmp_path, capsys)
    out = tmp_path / "authority.json"
    argv = [
        "authority",
        "issue",
        "--authorization-version",
        "1",
        "--publisher",
        PUBLISHER,
        "--issued-at",
        AUTH_ISSUED_AT,
        "--valid-from",
        VALID_FROM,
        "--seed",
        str(world["pub_seed"]),
        "--kid",
        PUB_KID,
        "--out",
        str(out),
        *extra,
    ]

    assert cli.main(argv) == 2
    assert not out.exists()


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (None, "must contain a JSON object"),
        ([], "must contain a JSON object"),
        ("a string", "must contain a JSON object"),
        (42, "must contain a JSON object"),
        (True, "must contain a JSON object"),
    ],
    ids=["null", "array", "string", "number", "bool"],
)
def test_a_previous_file_that_is_not_an_object_is_refused_never_silently_skipped(
    tmp_path: Path, capsys: CapSys, content: Any, message: str
) -> None:
    """D18 admits three outcomes for `--previous`: the check ran, the check
    refused, or the check was DECLARED undone. A file whose content is the
    JSON literal `null` parses to None and would take the builder's
    `previous=None` path — skipping the check the caller asked for while the
    stderr declaration, keyed to the flag, stays silent. Every non-object
    predecessor is refused, and the successor here DELETES an entry, so a
    check that actually ran would refuse it too: whichever way this passes,
    it never passes by emitting."""
    world = _world(tmp_path, capsys)
    previous = tmp_path / "authority-v1.json"
    assert cli.main(_authority_issue_argv(world["pub_seed"], previous)) == 0
    capsys.readouterr()
    bad_previous = _write_json(tmp_path / "bad-previous.json", content)
    issuers_file = _write_json(tmp_path / "empty-issuers.json", [])
    out = tmp_path / "successor.json"

    rc = cli.main(
        [
            "authority",
            "issue",
            "--authorization-version",
            "2",
            "--publisher",
            PUBLISHER,
            "--issued-at",
            LATER_ISSUED_AT,
            "--issuers-file",
            str(issuers_file),
            "--previous",
            str(bad_previous),
            "--seed",
            str(world["pub_seed"]),
            "--kid",
            PUB_KID,
            "--out",
            str(out),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert not out.exists()
    assert message in captured.err


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--publisher", "Pub.Example"], "--publisher must be a lowercase DNS domain"),
        (["--publisher", ""], "--publisher must be a lowercase DNS domain"),
        (["--issued-at", "2026-02-01"], "--issued-at must be an ISO-8601 UTC timestamp"),
        (["--issued-at", "2026-02-01T00:00:00+00:00"], "--issued-at must be an ISO-8601 UTC"),
        (
            ["--authorization-version", str(2**53)],
            "--authorization-version must be an integer in",
        ),
    ],
    ids=[
        "publisher-not-lowercase",
        "publisher-empty",
        "issued_at-date-only",
        "issued_at-offset-not-Z",
        "authorization_version-above-the-JCS-range",
    ],
)
def test_authority_issue_refuses_a_document_level_member_no_verifier_could_admit(
    tmp_path: Path, capsys: CapSys, extra: list[str], message: str
) -> None:
    """C-43: the verb that EMITS validates the shape before it signs, over
    the whole of section 20.2 and not only over the entries. A signed
    document whose `publisher`, `issued_at` or `authorization_version` is
    outside the shape can never authenticate anywhere, yet it costs the
    operator a real signature and a `record_sha256` they may already have
    published in a section 8 log entry."""
    world = _world(tmp_path, capsys)
    out = tmp_path / "authority.json"

    rc = cli.main(_authority_issue_argv(world["pub_seed"], out, *extra))
    captured = capsys.readouterr()

    assert rc == 2
    assert not out.exists()
    assert message in captured.err


def test_authority_issue_refuses_an_issuers_file_over_the_entry_ceiling(
    tmp_path: Path, capsys: CapSys
) -> None:
    """The 4096-entry count ceiling of section 20.2, refused on its COUNT
    before any per-entry work."""
    world = _world(tmp_path, capsys)
    entries = [
        _entry(issuer_id=f"i{index:06d}.example")
        for index in range(authority.MAX_AUTHORIZED_ISSUERS + 1)
    ]
    issuers_file = _write_json(tmp_path / "too-many.json", entries)
    out = tmp_path / "authority.json"

    rc = cli.main(
        [
            "authority",
            "issue",
            "--authorization-version",
            "1",
            "--publisher",
            PUBLISHER,
            "--issued-at",
            AUTH_ISSUED_AT,
            "--issuers-file",
            str(issuers_file),
            "--seed",
            str(world["pub_seed"]),
            "--kid",
            PUB_KID,
            "--out",
            str(out),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert not out.exists()
    assert "exceeds the publisher authorization entry ceiling" in captured.err


@pytest.mark.parametrize(
    ("flag", "text"),
    [
        ("--issuers-file", '[{"issuer_id": "store.example.com",'),
        ("--previous", '{"authorization_version": 1,'),
    ],
    ids=["issuers-file-truncated", "previous-truncated"],
)
def test_a_truncated_json_input_is_a_usage_error_and_writes_nothing(
    tmp_path: Path, capsys: CapSys, flag: str, text: str
) -> None:
    world = _world(tmp_path, capsys)
    truncated = tmp_path / "truncated.json"
    truncated.write_text(text, encoding="utf-8")
    out = tmp_path / "authority.json"
    argv = _authority_issue_argv(world["pub_seed"], out, flag, str(truncated))
    if flag == "--issuers-file":
        argv = [token for token in argv if token not in {"--issuer", ISSUER, "--valid-from"}]
        argv = [token for token in argv if token != VALID_FROM]

    rc = cli.main(argv)
    captured = capsys.readouterr()

    assert rc == 2
    assert not out.exists()
    assert "invalid JSON in" in captured.err


def test_an_entry_carrying_an_unknown_member_is_refused_never_signed(
    tmp_path: Path, capsys: CapSys
) -> None:
    """Section 20.2's entry shape is CLOSED (the log-entry discipline of
    section 8): a sixth member is a rejection, not a warning — and the
    emitting verb must not be the one place that lets one through."""
    world = _world(tmp_path, capsys)
    issuers_file = _write_json(tmp_path / "issuers.json", [{**_entry(), "note": "hello"}])
    out = tmp_path / "authority.json"

    rc = cli.main(
        [
            "authority",
            "issue",
            "--authorization-version",
            "1",
            "--publisher",
            PUBLISHER,
            "--issued-at",
            AUTH_ISSUED_AT,
            "--issuers-file",
            str(issuers_file),
            "--seed",
            str(world["pub_seed"]),
            "--kid",
            PUB_KID,
            "--out",
            str(out),
        ]
    )

    assert rc == 2
    assert not out.exists()
    assert "authorized_issuers[0] is not a valid authorization entry" in capsys.readouterr().err
