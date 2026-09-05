"""`attest verify --transfer-view / --compromise-view / --revocation-evidence`.

The verifier has accepted these three caller-side evidence rails since v0.2;
the CLI had no way to supply them, so every operator holding a compromise
declaration or a transfer claim had to write code against the library to be
heard. These tests pin the rails the way the corpus already describes them:
each leaf that ships an evidence file is verified through the command line and
compared with its own `expected.json`.

`trust` is the one field not compared. `--trust-dir` forces provenance
`bundle` for every issuer it loads (there is no channel on the command line to
say a manifest arrived over TLS), while the corpus leaves record `verified`
under a TLS provenance. That is a property of the flag, not of these rails.

Two behaviors are deliberately NOT the library's: `null` in a rail file is a
usage error rather than an opt-out, and the container is checked per rail. A
caller who supplies a file has supplied the rail; reading the parsed value
instead of the flag would silently opt them out of the very check they asked
for.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from attest import cli, verify
from tests.test_cli import CapSys

VECTORS = Path("docs/spec/vectors")
LEAF_41A = VECTORS / "41-compromise-cutoff/a-rescued-anchored-before-cutoff"
LEAF_41B = VECTORS / "41-compromise-cutoff/b-anchored-after-cutoff-fails"
LEAF_41M = VECTORS / "41-compromise-cutoff/m-uncompromise-view-floor"
LEAF_41P = VECTORS / "41-compromise-cutoff/p-declaring-signer-compromised-still-floors"
LEAF_35A = VECTORS / "35-transfer/a-transferred-with-backing"
LEAF_47A = VECTORS / "47-oversized-view-transfer/a-oversized-view-hides-transfer"
LEAF_33A = VECTORS / "33-logged-revocation/a-timely-logged-honored"


def trust_dir(tmp_path: Path, leaf: Path) -> Path:
    """Write one file per key manifest the leaf trusts, chain included.

    `_load_trust_dir` groups the directory's manifests by issuer and orders
    each issuer's versions itself, so a leaf's chain is reconstructed by
    dropping every version in as its own file — which is also how an operator
    holds a rotation history on disk.
    """
    out = tmp_path / "trust"
    out.mkdir(exist_ok=True)
    bundle = json.loads((leaf / "manifests.json").read_text(encoding="utf-8"))
    written = 0
    for issuer, manifest in bundle.get("manifests", {}).items():
        for version in bundle.get("chains", {}).get(issuer, []) or [manifest]:
            (out / f"{issuer}-{version.get('manifest_version', 0)}-{written}.json").write_text(
                json.dumps(version), encoding="utf-8"
            )
            written += 1
        if not bundle.get("chains", {}).get(issuer):
            continue
        (out / f"{issuer}-head-{written}.json").write_text(json.dumps(manifest), encoding="utf-8")
        written += 1
    return out


def single_record_revocation_view(tmp_path: Path, leaf: Path) -> Path:
    """The leaf's own revocation record, wrapped in the one-element array the
    `--revocations` flag requires.

    Writing the array here is not a substitute for the shipped producer: the
    test that the producer builds an array a verifier honors belongs with the
    producer. What this unlocks is the RAIL — `transfer_view` and
    `revocation_evidence` are only consulted once a record has matched the
    receipt, so without an array their effect on the verdict cannot be
    observed at all, and both tests would sit disabled for no reason.
    """
    record = json.loads((leaf / "revocation.json").read_text(encoding="utf-8"))
    assert isinstance(record, dict)
    out = tmp_path / f"{leaf.name}-revocation-view.json"
    out.write_text(json.dumps([record]), encoding="utf-8")
    return out


def run_verify(leaf: Path, tmp_path: Path, *rails: str, stage2: bool = False) -> list[str]:
    argv = [
        "verify",
        str(leaf / "envelope.json"),
        "--trust-dir",
        str(trust_dir(tmp_path, leaf)),
        *rails,
    ]
    if stage2:
        argv += [
            "--log-keys",
            str(leaf / "log-keys.json"),
            "--anchor-policy",
            str(leaf / "anchor-policy.json"),
        ]
    return argv


def verdict(capsys: CapSys) -> dict[str, Any]:
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err, captured.err
    return json.loads(captured.out)


def assert_matches_expected(result: dict[str, Any], leaf: Path) -> None:
    """Compare against the leaf's own `expected.json`, minus `trust`."""
    expected = json.loads((leaf / "expected.json").read_text(encoding="utf-8"))
    for field, value in expected.items():
        if field in ("trust", "errors_contains", "warnings_contains"):
            continue
        assert result[field] == value, f"{field}: {result[field]!r} != {value!r}"
    for fragment in expected.get("errors_contains", []):
        assert any(fragment in error for error in result["errors"]), result["errors"]
    for warning in expected.get("warnings_contains", []):
        assert warning in result["warnings"], result["warnings"]


# --- the compromise rail ------------------------------------------------------


def test_a_compromise_view_supplied_on_the_command_line_rescues_the_receipt(
    tmp_path: Path, capsys: CapSys
) -> None:
    """41a: the declaration is anchored before the receipt, so the receipt
    survives its issuer's key compromise. Without the rail the CLI cannot say
    so — which is the whole point of the flag."""
    capsys.readouterr()
    rc = cli.main(
        run_verify(
            LEAF_41A,
            tmp_path,
            "--transparency",
            str(LEAF_41A / "transparency.json"),
            "--compromise-view",
            str(LEAF_41A / "compromise-view.json"),
            stage2=True,
        )
    )
    result = verdict(capsys)

    assert rc == cli.EXIT_OK
    assert_matches_expected(result, LEAF_41A)
    assert result["warnings"] == ["compromise_rescue_applied"]


@pytest.mark.parametrize("leaf", [LEAF_41M, LEAF_41P], ids=["41m", "41p"])
def test_a_compromise_view_can_only_restrict(tmp_path: Path, capsys: CapSys, leaf: Path) -> None:
    """Both leaves fail WITH their view and pass without it: a claim that
    establishes only the floor still narrows the verdict, and a claim whose
    signer is itself compromised is not thereby discarded (v0.2 §19.3 item 3a
    does not consult the signer's status)."""
    capsys.readouterr()
    rc_with = cli.main(
        run_verify(
            leaf,
            tmp_path,
            "--compromise-view",
            str(leaf / "compromise-view.json"),
            stage2=True,
        )
    )
    with_view = verdict(capsys)
    rc_without = cli.main(run_verify(leaf, tmp_path, stage2=True))
    without_view = verdict(capsys)

    assert rc_with == cli.EXIT_VERIFICATION_FAILED
    assert_matches_expected(with_view, leaf)
    assert rc_without == cli.EXIT_OK
    assert without_view["ok"] is True


def test_a_receipt_anchored_after_the_cutoff_is_not_rescued(tmp_path: Path, capsys: CapSys) -> None:
    """41b: same rail, opposite outcome — the cutoff is established and the
    receipt sits after it."""
    capsys.readouterr()
    rc = cli.main(
        run_verify(
            LEAF_41B,
            tmp_path,
            "--transparency",
            str(LEAF_41B / "transparency.json"),
            "--compromise-view",
            str(LEAF_41B / "compromise-view.json"),
            stage2=True,
        )
    )
    result = verdict(capsys)

    assert rc == cli.EXIT_VERIFICATION_FAILED
    assert_matches_expected(result, LEAF_41B)


# --- the transfer rail --------------------------------------------------------


def test_a_transfer_view_backs_the_transfer_the_revocation_feed_declares(
    tmp_path: Path, capsys: CapSys
) -> None:
    """35a end to end, and it needs BOTH rails.

    Measured: `transfer_view` is inert on its own. The verifier consults it
    only once a revocation record of status `transferred` has matched this
    receipt (`verify.py`, Stage 3 §17.3) — with no revocation feed there is no
    transfer to back, and supplying the view changes nothing observable.
    """
    view = single_record_revocation_view(tmp_path, LEAF_35A)
    capsys.readouterr()
    rc = cli.main(
        run_verify(
            LEAF_35A,
            tmp_path,
            "--revocations",
            str(view),
            "--transfer-view",
            str(LEAF_35A / "transfer-view.json"),
            stage2=True,
        )
    )
    result = verdict(capsys)

    assert rc == cli.EXIT_VERIFICATION_FAILED
    assert_matches_expected(result, LEAF_35A)
    assert result["revocation"] == "transferred"


@pytest.mark.parametrize("delta", [0, 1])
def test_an_oversized_transfer_view_reaches_the_verifier_whole(
    tmp_path: Path, capsys: CapSys, delta: int
) -> None:
    """The transfer rail has a ceiling of its own, and the corpus does not
    exercise it: leaf 47's oversized array is the REVOCATION view. At the
    ceiling the real claim is still read and backs the transfer; one element
    more and the view is not evaluated at all, so the transfer stands unbacked.
    A CLI that trimmed to the ceiling would turn the second case into the
    first — silently, and in the direction that makes a receipt look better
    than the evidence supports."""
    revocations = single_record_revocation_view(tmp_path, LEAF_35A)
    claims = json.loads((LEAF_35A / "transfer-view.json").read_text(encoding="utf-8"))
    assert len(claims) == 1
    ceiling = verify._MAX_TRANSFER_CLAIMS
    supplied = [claims[0], *([None] * (ceiling - 1 + delta))]
    transfer_view = tmp_path / "transfer-view.json"
    transfer_view.write_text(json.dumps(supplied), encoding="utf-8")

    capsys.readouterr()
    rc = cli.main(
        run_verify(
            LEAF_35A,
            tmp_path,
            "--revocations",
            str(revocations),
            "--transfer-view",
            str(transfer_view),
            stage2=True,
        )
    )
    result = verdict(capsys)

    if delta == 0:
        assert rc == cli.EXIT_VERIFICATION_FAILED
        assert result["revocation"] == "transferred"
    else:
        assert rc == cli.EXIT_OK
        assert result["revocation"] == "invalid_revocation_ignored"
        assert "transferred_revocation_unbacked" in result["warnings"]


def test_an_oversized_revocation_view_does_not_hide_a_transfer(
    tmp_path: Path, capsys: CapSys
) -> None:
    """47a: the revocation view is one element over the ceiling, so it is not
    evaluated — and the transfer it would have explained cannot be ruled out.
    The CLI must forward it whole: pre-filtering or truncating an oversized
    view here would turn the leaf's refusal into a pass."""
    capsys.readouterr()
    rc = cli.main(
        run_verify(
            LEAF_47A,
            tmp_path,
            "--revocations",
            str(LEAF_47A / "revocation-view.json"),
            "--transfer-view",
            str(LEAF_47A / "transfer-view.json"),
        )
    )
    result = verdict(capsys)

    assert rc == cli.EXIT_VERIFICATION_FAILED
    assert_matches_expected(result, LEAF_47A)
    assert result["revocation"] == "unknown"


# --- the revocation-evidence rail ---------------------------------------------


def test_revocation_evidence_without_a_revocation_view_is_a_usage_error(
    tmp_path: Path, capsys: CapSys
) -> None:
    """The evidence proves a record was logged in time; with no record to
    prove anything about, supplying it is a mistake worth naming."""
    capsys.readouterr()
    rc = cli.main(
        run_verify(
            LEAF_33A,
            tmp_path,
            "--revocation-evidence",
            str(LEAF_33A / "revocation-evidence.json"),
            stage2=True,
        )
    )
    captured = capsys.readouterr()

    assert rc == cli.EXIT_USAGE_ERROR
    assert "--revocations" in captured.err
    assert "Traceback" not in captured.err


def test_a_logged_and_anchored_revocation_is_honored_through_the_cli(
    tmp_path: Path, capsys: CapSys
) -> None:
    """33a end to end: record plus evidence, both supplied by flag."""
    view = single_record_revocation_view(tmp_path, LEAF_33A)
    capsys.readouterr()
    rc = cli.main(
        run_verify(
            LEAF_33A,
            tmp_path,
            "--revocations",
            str(view),
            "--revocation-evidence",
            str(LEAF_33A / "revocation-evidence.json"),
            stage2=True,
        )
    )
    result = verdict(capsys)

    assert rc == cli.EXIT_VERIFICATION_FAILED
    assert result["revocation"] == "revoked"


# --- what the flags refuse, and what they must pass through -------------------


@pytest.mark.parametrize(
    ("flag", "text"),
    [
        ("--transfer-view", "null"),
        ("--compromise-view", "null"),
        ("--revocation-evidence", "null"),
        ("--transfer-view", "{}"),
        ("--compromise-view", '{"claims": []}'),
        ("--revocation-evidence", "[]"),
        ("--transfer-view", '"a view"'),
        ("--compromise-view", "12"),
        ("--revocation-evidence", '{"entry": {}, "entry": {}}'),
        ("--compromise-view", "[1.5]"),
        ("--transfer-view", '[{"record": '),
    ],
)
def test_a_rail_file_of_the_wrong_kind_is_a_usage_error(
    tmp_path: Path, capsys: CapSys, flag: str, text: str
) -> None:
    """`null` is not an opt-out: a caller who passed the flag asked for the
    rail, and reading the parsed value instead of the flag would silently drop
    the check they requested. The container is per rail — an array for the two
    views, one object for the evidence."""
    rail = tmp_path / "rail.json"
    rail.write_text(text, encoding="utf-8")
    extra = ["--revocations", str(LEAF_47A / "revocation-view.json")]
    capsys.readouterr()
    rc = cli.main(run_verify(LEAF_41A, tmp_path, flag, str(rail), *extra))
    captured = capsys.readouterr()

    assert rc == cli.EXIT_USAGE_ERROR
    assert flag in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    ("flag", "text"),
    [
        ("--transfer-view", "[]"),
        ("--compromise-view", "[]"),
        ("--compromise-view", "[null]"),
        ("--transfer-view", '[null, 1, "x"]'),
        ("--compromise-view", "[" + ", ".join(["null"] * 65) + "]"),
    ],
)
def test_well_formed_but_hostile_rail_content_belongs_to_the_verifier(
    tmp_path: Path, capsys: CapSys, flag: str, text: str
) -> None:
    """The CLI validates the container, never the claims: a malformed claim is
    the verifier's to refuse, and an over-ceiling view must reach it so that it
    reports its own ceiling rather than being trimmed here."""
    rail = tmp_path / "rail.json"
    rail.write_text(text, encoding="utf-8")
    capsys.readouterr()
    rc = cli.main(run_verify(LEAF_41A, tmp_path, flag, str(rail)))
    captured = capsys.readouterr()

    assert rc in (cli.EXIT_OK, cli.EXIT_VERIFICATION_FAILED)
    assert "Traceback" not in captured.err
    json.loads(captured.out)


# --- the rails reach the verifier, whatever the verdict -----------------------


def test_every_rail_the_caller_supplies_is_forwarded_to_the_verifier(
    tmp_path: Path, capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two of the three rails cannot be pinned on a verdict yet.

    `transfer_view` is only consulted once a revocation record of status
    `transferred` has matched (Stage 3, §17.3), and `revocation_evidence` only
    once a refund-window record is in play — both need a record array, and the
    verb that builds one arrives with T4. Their end-to-end tests are `xfail`
    above, which leaves the forwarding itself unpinned: drop either keyword
    from the call and nothing goes red.

    So the link is pinned where it exists — on the call — rather than on a
    verdict that cannot yet move. This is the same reasoning the site's intake
    tests use for a rail whose effect is invisible in the page.
    """
    seen: dict[str, Any] = {}
    real_verify = verify.verify

    def capturing_verify(*args: Any, **kwargs: Any) -> Any:
        seen.update(kwargs)
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(verify, "verify", capturing_verify)
    # Non-empty, ordered and hostile on purpose: empty containers would survive
    # a CLI that filtered, reordered or trimmed, so they prove only that the
    # keyword exists. These prove the caller's content arrives unchanged.
    transfer_value: list[Any] = [
        {"record": {}, "evidence": {}, "extra": "first"},
        None,
        {"record": {"receipt_id": "last"}},
    ]
    compromise_value: list[Any] = [
        {"manifest": {}, "evidence": {}, "extra": "first"},
        None,
        {"manifest": {"issuer": "last"}, "evidence": {}},
    ]
    evidence_value = {"entry": {}, "leaf_index": -1, "extra": "keep"}
    revocations = tmp_path / "revocations.json"
    revocations.write_text("[]", encoding="utf-8")
    transfer_rail = tmp_path / "transfer.json"
    transfer_rail.write_text(json.dumps(transfer_value), encoding="utf-8")
    compromise_rail = tmp_path / "compromise.json"
    compromise_rail.write_text(json.dumps(compromise_value), encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps(evidence_value), encoding="utf-8")

    capsys.readouterr()
    cli.main(
        run_verify(
            LEAF_41A,
            tmp_path,
            "--revocations",
            str(revocations),
            "--transfer-view",
            str(transfer_rail),
            "--compromise-view",
            str(compromise_rail),
            "--revocation-evidence",
            str(evidence),
            stage2=True,
        )
    )
    capsys.readouterr()

    assert seen["transfer_view"] == transfer_value
    assert seen["compromise_view"] == compromise_value
    assert seen["revocation_evidence"] == evidence_value


@pytest.mark.parametrize("delta", [0, 1])
def test_an_oversized_compromise_view_reaches_the_verifier_whole(
    tmp_path: Path, capsys: CapSys, delta: int
) -> None:
    """The ceiling belongs to the verifier, and it must be the verifier that
    applies it.

    The leaf has to be one where the view RESTRICTS, or both sides of the
    boundary collapse onto the same verdict: on a leaf the view rescues, an
    ignored oversized view and a padded one both end in `ok: true`, and a CLI
    that silently trimmed to the ceiling would look correct. On 41m the view is
    what makes the receipt fail, so at the ceiling the verdict is a refusal and
    one claim past it the view is not evaluated at all and the receipt passes.
    Trimming here would turn the second case into the first.
    """
    claims = json.loads((LEAF_41M / "compromise-view.json").read_text(encoding="utf-8"))
    assert len(claims) == 1
    ceiling = 64
    sized = tmp_path / "compromise-view.json"
    sized.write_text(json.dumps(claims * (ceiling + delta)), encoding="utf-8")

    capsys.readouterr()
    rc = cli.main(run_verify(LEAF_41M, tmp_path, "--compromise-view", str(sized), stage2=True))
    result = verdict(capsys)

    # Both sides fail, so the exit code alone proves nothing: what separates
    # them is the REASON. At the ceiling the view is read and the receipt fails
    # on the compromised key it declares; one claim more and the verifier
    # refuses to certify the signing key at all, naming the ceiling it applied.
    assert rc == cli.EXIT_VERIFICATION_FAILED
    if delta == 0:
        assert result["errors"] == ["key store.example.com/keys/2025-01#ed25519-1 is compromised"]
        assert "compromise_marking_retracted" in result["warnings"]
    else:
        assert result["errors"] == [
            f"compromise view exceeds {ceiling} claims "
            f"({ceiling + delta} supplied), cannot certify the signing key"
        ]
        assert result["warnings"] == []


# --- what each rail owes on its own -------------------------------------------


@pytest.mark.parametrize(
    ("flag", "text", "reason"),
    [
        ("--transfer-view", '[{"record": {"x": 1, "x": 2}}]', "duplicate object key"),
        ("--compromise-view", '[{"manifest": {"x": 1, "x": 2}}]', "duplicate object key"),
        ("--revocation-evidence", '{"entry": {"x": 1, "x": 2}}', "duplicate object key"),
        ("--transfer-view", "[1.5]", "floats are not allowed"),
        ("--compromise-view", "[1.5]", "floats are not allowed"),
        ("--revocation-evidence", '{"leaf_index": 1.5}', "floats are not allowed"),
    ],
)
def test_every_rail_uses_the_strict_parser(
    tmp_path: Path, capsys: CapSys, flag: str, text: str, reason: str
) -> None:
    """Each rail separately. Spreading one property across three rails leaves a
    rail-specific regression free to survive: duplicate members exercised only
    on the evidence, non-integers only on the compromise view, and either
    reader could go permissive unnoticed. The refusal must also name the
    REASON, not just the flag."""
    rail = tmp_path / "rail.json"
    rail.write_text(text, encoding="utf-8")
    revocations = tmp_path / "revocations.json"
    revocations.write_text("[]", encoding="utf-8")

    capsys.readouterr()
    rc = cli.main(
        run_verify(LEAF_41A, tmp_path, flag, str(rail), "--revocations", str(revocations))
    )
    captured = capsys.readouterr()

    assert rc == cli.EXIT_USAGE_ERROR
    assert flag in captured.err
    assert reason in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("flag", ["--transfer-view", "--compromise-view", "--revocation-evidence"])
def test_every_rail_is_byte_bounded(tmp_path: Path, capsys: CapSys, flag: str) -> None:
    """Nothing pinned the byte ceiling on any rail: the readers could have been
    given an unbounded read and the suite would not have moved."""
    limit = cli._MAX_STAGE2_INPUT_BYTES["json"]
    rail = tmp_path / "rail.json"
    padding = "x" * limit
    rail.write_text(
        f'{{"padding":"{padding}"}}' if flag == "--revocation-evidence" else f'["{padding}"]',
        encoding="utf-8",
    )
    revocations = tmp_path / "revocations.json"
    revocations.write_text("[]", encoding="utf-8")

    capsys.readouterr()
    rc = cli.main(
        run_verify(LEAF_41A, tmp_path, flag, str(rail), "--revocations", str(revocations))
    )
    captured = capsys.readouterr()

    assert rc == cli.EXIT_USAGE_ERROR
    assert f"{flag} input exceeds {limit} bytes" in captured.err
    assert "Traceback" not in captured.err


def test_revocation_evidence_warns_when_the_verifier_cannot_read_it(
    tmp_path: Path, capsys: CapSys
) -> None:
    """Without pinned log keys and an anchor policy the evidence is accepted
    and never evaluated. Saying so is the difference between an operator who
    knows their proof went unread and one who believes it counted."""
    revocations = tmp_path / "revocations.json"
    revocations.write_text("[]", encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")

    capsys.readouterr()
    rc = cli.main(
        run_verify(
            LEAF_41A,
            tmp_path,
            "--revocations",
            str(revocations),
            "--revocation-evidence",
            str(evidence),
        )
    )
    captured = capsys.readouterr()

    assert rc in (cli.EXIT_OK, cli.EXIT_VERIFICATION_FAILED)
    assert (
        "warning: --revocation-evidence is only evaluated by a Stage-2-capable verifier"
        in captured.err
    )
    assert "Traceback" not in captured.err
    json.loads(captured.out)


def test_the_dependency_is_checked_before_the_evidence_file_is_read(
    tmp_path: Path, capsys: CapSys
) -> None:
    """A missing prerequisite is not a missing file: with no --revocations the
    refusal must name the prerequisite, whether or not the evidence file could
    have been read at all."""
    missing = tmp_path / "must-not-be-read.json"
    capsys.readouterr()
    rc = cli.main(
        run_verify(LEAF_33A, tmp_path, "--revocation-evidence", str(missing), stage2=True)
    )
    captured = capsys.readouterr()

    assert rc == cli.EXIT_USAGE_ERROR
    assert "--revocation-evidence needs --revocations" in captured.err
    assert "file not found" not in captured.err
    assert "Traceback" not in captured.err
