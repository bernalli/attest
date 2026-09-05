"""Property and boundary coverage for `attest revoke`.

The example-based tests in `test_cli.py` pin the cases a human thought of.
These pin the PROPERTIES the command owes on input nobody enumerated: whatever
the mutation, the command either refuses with exit 2, writes no output file and
prints a clean `error:` line, or exits 0 with a record the shipped verifier
authenticates. There is no third outcome, and no traceback in either.

Boundaries are checked on BOTH sides, because a ceiling tested only from above
does not prove the value below it is admitted.

One boundary is worth naming. `--receipt` is bounded by
`validate.MAX_ENVELOPE_BYTES` (1 048 576), not by the wider Stage-2 input
ceiling the command's other JSON inputs use: the closing predicate hands those
same bytes to `verify.verify`, which refuses anything larger, so a file between
the two ceilings could never be accepted by both readers. The pair of tests
below is what makes that concrete — the padded-to-exactly-the-ceiling receipt
is accepted and produces a record, one byte more is refused by the reader.
"""

from __future__ import annotations

import contextlib
import datetime
import io
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from attest import canon, cli, keys, manifests, revocation, validate
from tests.test_cli import (
    ISSUER,
    KID,
    VALID_FROM,
    _issue,
    _keygen,
    _keygen_hybrid,
    _manifest_init,
    _manifest_init_hybrid,
    _write_payload,
)

# Mirrors `tests/test_blind_revocation_admission.py`: enough examples to explore
# the mutation space, deterministic so a failure is reproducible from the id
# alone, and no per-example deadline (each example signs and verifies).
PROPERTY_SETTINGS = settings(max_examples=24, deadline=None, derandomize=True)

REVOKED_AT = "2026-07-03T00:00:00Z"


@dataclass(frozen=True)
class Captured:
    """What one CLI invocation printed.

    `capsys` cannot be used here: it is function-scoped, and Hypothesis does not
    reset a function-scoped fixture between generated inputs (its health check
    refuses the combination outright). Redirecting the streams inside the call
    keeps every example isolated.
    """

    out: str
    err: str


@contextlib.contextmanager
def capturing() -> Iterator[list[Captured]]:
    sink: list[Captured] = []
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield sink
    sink.append(Captured(out.getvalue(), err.getvalue()))


class RevokeFixture:
    """One issued receipt plus the key material that can revoke it.

    Built once per module: `keygen` + `manifest init` + `issue` cost more than
    every mutation applied to their output, and none of the properties below
    depend on fresh key material.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.seed, _pub = _keygen(root, "revoke-props")
        self.manifest = _manifest_init(root, self.seed, "revoke-props-manifest.json")
        payload = _write_payload(
            root, "revoke-props-payload.json", license={"revocability": "policy"}
        )
        self.receipt = _issue(root, self.seed, payload, "revoke-props-envelope.json")
        self.counter = 0

    def scratch(self) -> Path:
        """A fresh directory for one example's mutated inputs and output."""
        self.counter += 1
        path = self.root / f"case-{self.counter:04d}"
        path.mkdir()
        return path

    def run(
        self,
        case: Path,
        *,
        receipt: Path | None = None,
        manifest: Path | None = None,
        revoked_at: str = REVOKED_AT,
        kid: str = KID,
    ) -> tuple[int, Path, Captured]:
        out = case / "record.json"
        argv = [
            "revoke",
            "--receipt",
            str(receipt if receipt is not None else self.receipt),
            "--manifest",
            str(manifest if manifest is not None else self.manifest),
            "--revoked-at",
            revoked_at,
            "--seed",
            str(self.seed),
            "--kid",
            kid,
            "--out",
            str(out),
        ]
        with capturing() as sink:
            try:
                rc = cli.main(argv)
            except SystemExit as exc:  # argparse refusals surface this way
                rc = int(exc.code or 0)
        return rc, out, sink[0]


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory) -> RevokeFixture:
    return RevokeFixture(tmp_path_factory.mktemp("revoke-properties"))


def assert_clean_outcome(rc: int, out: Path, captured: Captured, manifest_path: Path) -> None:
    """The invariant every case below shares, whatever the input was."""
    assert "Traceback" not in captured.err
    if rc == cli.EXIT_USAGE_ERROR:
        assert "error:" in captured.err
        assert not out.exists()
        return
    assert rc == cli.EXIT_OK
    record = json.loads(out.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert revocation.verify_record(record, manifest)


# --- (a) --revoked-at ---------------------------------------------------------


@PROPERTY_SETTINGS
@given(
    revoked_at=st.one_of(
        st.text(max_size=40),
        st.sampled_from(
            [
                "",
                " ",
                "2026-07-03T00:00:00",
                "2026-07-03T00:00:00+00:00",
                "2026-07-03T00:00:00.000Z",
                "2026-7-3T0:0:0Z",
                "2026-07-03 00:00:00Z",
                "2026-07-03T00:00:00Z\n",
                "2026-07-03T00:00:00Ż",
                "20260703T000000Z",
                "2026-07-03T24:00:00Z",
            ]
        ),
    )
)
def test_revoked_at_that_does_not_round_trip_is_always_refused(
    env: RevokeFixture, revoked_at: str
) -> None:
    """A timestamp is signed as written, so the only spelling this command may
    accept is the one that re-serializes to itself byte for byte."""
    case = env.scratch()
    rc, out, captured = env.run(case, revoked_at=revoked_at)

    try:
        parsed = datetime.datetime.strptime(revoked_at, revocation._DATE_FMT)
        round_trips = parsed.strftime(revocation._DATE_FMT) == revoked_at
    except ValueError:
        round_trips = False

    if not round_trips:
        assert rc == cli.EXIT_USAGE_ERROR
        assert not out.exists()
        # A malformed timestamp would also be refused later, by the closing
        # predicate, since the verifier cannot parse what was signed. Naming
        # the flag pins that the round-trip guard is what refuses it.
        assert "--revoked-at" in captured.err
    assert_clean_outcome(rc, out, captured, env.manifest)


# --- (b) license.revocability and the refund window ---------------------------


@pytest.mark.parametrize(
    ("license_block", "revocable"),
    [
        ({"revocability": "policy"}, True),
        ({"revocability": "refund_window", "revocation_window_days": 30}, True),
        ({"revocability": "none"}, False),
    ],
)
def test_exactly_the_two_revocable_classes_produce_a_record(
    env: RevokeFixture, license_block: dict[str, object], revocable: bool
) -> None:
    """v0.1 §12.2 admits three classes and makes one of them irrevocable. The
    schema will not let a fourth exist, so the registry is closed here too."""
    case = env.scratch()
    payload = _write_payload(case, "payload.json", license=license_block)
    receipt = _issue(case, env.seed, payload, "envelope.json")
    rc, out, captured = env.run(case, receipt=receipt)

    assert rc == (cli.EXIT_OK if revocable else cli.EXIT_USAGE_ERROR)
    if not revocable:
        assert "§12.2" in captured.err
    assert_clean_outcome(rc, out, captured, env.manifest)


@PROPERTY_SETTINGS
@given(
    revocability=st.one_of(
        st.text(max_size=20),
        st.sampled_from(["none", "refund_window", "POLICY", "revoked", "", "Policy "]),
        st.integers(),
        st.none(),
        st.booleans(),
        st.lists(st.just("policy"), max_size=2),
        st.dictionaries(st.just("value"), st.just("policy"), max_size=1),
    )
)
def test_any_class_outside_the_two_revocable_classes_is_refused_by_that_guard(
    env: RevokeFixture, revocability: object
) -> None:
    """The receipt schema keeps `revocability` inside a three-value enum, so a
    value outside it can only reach this command on a receipt edited after
    signing — which also breaks the signature. The class guard itself, not the
    later signature failure, must be what refuses it, so the message has to
    name the member.
    """
    assume(revocability not in ("policy", "refund_window"))
    case = env.scratch()
    envelope = json.loads(env.receipt.read_text(encoding="utf-8"))
    envelope["payload"]["license"]["revocability"] = revocability
    receipt = case / "envelope.json"
    receipt.write_text(json.dumps(envelope), encoding="utf-8")
    rc, out, captured = env.run(case, receipt=receipt)

    assert rc == cli.EXIT_USAGE_ERROR
    assert not out.exists()
    assert "license.revocability" in captured.err
    assert_clean_outcome(rc, out, captured, env.manifest)


@PROPERTY_SETTINGS
@given(
    window_days=st.integers(min_value=1, max_value=3650),
    offset_seconds=st.sampled_from([-86400, -60, -1, 0, 1, 60, 86400]),
)
def test_the_refund_window_edge_is_inclusive_and_decides_whether_a_record_exists(
    env: RevokeFixture, window_days: int, offset_seconds: int
) -> None:
    """A `refund_window` record is honored up to and including the deadline and
    ignored past it, so the producer writes one on exactly that side of the
    edge. `<=` turned into `<` in the verifier's window predicate makes the
    zero-offset examples fail.
    """
    case = env.scratch()
    payload_document = json.loads(env.receipt.read_text(encoding="utf-8"))["payload"]
    issued_at = datetime.datetime.strptime(payload_document["issued_at"], revocation._DATE_FMT)
    window_end = issued_at + datetime.timedelta(days=window_days)
    revoked_at = window_end + datetime.timedelta(seconds=offset_seconds)
    # The signer's own validity window opens at VALID_FROM and never closes;
    # anything before it would be refused for the signer, not for the deadline.
    assume(revoked_at >= datetime.datetime.strptime(VALID_FROM, revocation._DATE_FMT))

    payload = _write_payload(
        case,
        "payload.json",
        license={"revocability": "refund_window", "revocation_window_days": window_days},
    )
    receipt = _issue(case, env.seed, payload, "envelope.json")
    rc, out, captured = env.run(
        case, receipt=receipt, revoked_at=revoked_at.strftime(revocation._DATE_FMT)
    )

    assert rc == (cli.EXIT_OK if offset_seconds <= 0 else cli.EXIT_USAGE_ERROR)
    if rc == cli.EXIT_OK:
        assert "refund_window records are ignored by Stage-2 verifiers" in captured.err
    assert_clean_outcome(rc, out, captured, env.manifest)


# --- (c) receipt_id, (f) top-level container, (h) receipt/manifest mismatch ---


@PROPERTY_SETTINGS
@given(
    receipt_id=st.one_of(
        st.text(max_size=30),
        st.sampled_from(
            [
                "",
                "01J1V5B4M9Z8QWERTY1234567",  # one character short
                "01J1V5B4M9Z8QWERTY123456789",  # one character long
                "81J1V5B4M9Z8QWERTY12345678",  # out of the ULID timestamp range
                "01j1v5b4m9z8qwerty12345678",  # lowercase
                "01J1V5B4M9Z8QWERTY1234567I",  # excluded letter
            ]
        ),
        st.integers(),
        st.none(),
    )
)
def test_a_receipt_id_the_module_would_not_authenticate_is_refused_up_front(
    env: RevokeFixture, receipt_id: object
) -> None:
    """`revocation.verify_record` refuses a record whose `receipt_id` is not a
    ULID, so the producer must refuse the receipt that would yield one — before
    it signs anything."""
    case = env.scratch()
    envelope = json.loads(env.receipt.read_text(encoding="utf-8"))
    envelope["payload"]["receipt_id"] = receipt_id
    receipt = case / "envelope.json"
    receipt.write_text(json.dumps(envelope), encoding="utf-8")
    rc, out, captured = env.run(case, receipt=receipt)

    valid = isinstance(receipt_id, str) and revocation.RECEIPT_ID_RE.fullmatch(receipt_id)
    if not valid:
        assert rc == cli.EXIT_USAGE_ERROR
        assert not out.exists()
        # Naming the member matters: editing the payload also breaks the
        # signature, so an assertion on the exit code alone would pass with the
        # ULID predicate deleted — measured, the mutation survived it. The
        # reason has to be accurate too: a present-but-invalid id is not a
        # missing one.
        assert "'receipt_id' must be a ULID" in captured.err
    assert_clean_outcome(rc, out, captured, env.manifest)


@pytest.mark.parametrize(
    "text",
    ['[{"payload": {}}]', '"a receipt"', "null", "12", "true", "[]", "{}"],
)
def test_a_receipt_that_is_not_an_object_with_a_payload_is_refused(
    env: RevokeFixture, text: str
) -> None:
    case = env.scratch()
    receipt = case / "envelope.json"
    receipt.write_text(text, encoding="utf-8")
    rc, out, captured = env.run(case, receipt=receipt)

    assert rc == cli.EXIT_USAGE_ERROR
    assert_clean_outcome(rc, out, captured, env.manifest)


def test_a_manifest_from_another_issuer_is_refused(env: RevokeFixture) -> None:
    case = env.scratch()
    other_seed, _pub = _keygen(case, "other-issuer")
    other_manifest = case / "other-manifest.json"
    kp = keys.from_seed(keys.b64u_decode(other_seed.read_text(encoding="utf-8").strip()))
    other_kid = "other.example.org/keys/2026-01#ed25519-1"
    manifest = manifests.build_key_manifest(
        "other.example.org",
        1,
        VALID_FROM,
        [manifests.key_entry(other_kid, kp.pub, VALID_FROM)],
        kp,
        other_kid,
    )
    other_manifest.write_text(json.dumps(manifest), encoding="utf-8")
    rc, out, captured = env.run(case, manifest=other_manifest, kid=other_kid)

    assert rc == cli.EXIT_USAGE_ERROR
    assert "not by the receipt's issuer" in captured.err
    assert_clean_outcome(rc, out, captured, env.manifest)


# --- (d) truncation, (e) duplicate members at arbitrary depth -----------------


@PROPERTY_SETTINGS
@given(fraction=st.floats(min_value=0.0, max_value=0.999))
def test_a_truncated_receipt_is_refused_at_every_offset(
    env: RevokeFixture, fraction: float
) -> None:
    case = env.scratch()
    data = env.receipt.read_bytes()
    receipt = case / "envelope.json"
    receipt.write_bytes(data[: int(len(data) * fraction)])
    rc, out, captured = env.run(case, receipt=receipt)

    assert rc == cli.EXIT_USAGE_ERROR
    assert_clean_outcome(rc, out, captured, env.manifest)


@PROPERTY_SETTINGS
@given(depth=st.integers(min_value=0, max_value=6), which=st.sampled_from(["receipt", "manifest"]))
def test_a_duplicate_member_at_any_depth_is_refused(
    env: RevokeFixture, depth: int, which: str
) -> None:
    """A file whose meaning depends on which duplicate the parser keeps is not
    an input this command resolves by position."""
    case = env.scratch()
    source = env.receipt if which == "receipt" else env.manifest
    document = json.loads(source.read_text(encoding="utf-8"))
    # Wrap the honest document `depth` levels deep, then duplicate a member of
    # the innermost wrapper: the refusal must not depend on how deep it is.
    text = json.dumps(document)
    prefix = "".join(f'{{"level{i}": ' for i in range(depth))
    suffix = "}" * depth
    duplicated = f'{prefix}{{"dup": 1, "dup": 2, "document": {text}}}{suffix}'
    mutated = case / "mutated.json"
    mutated.write_text(duplicated, encoding="utf-8")
    if which == "receipt":
        rc, out, captured = env.run(case, receipt=mutated)
    else:
        rc, out, captured = env.run(case, manifest=mutated)

    assert rc == cli.EXIT_USAGE_ERROR
    assert "duplicate object key" in captured.err
    assert_clean_outcome(rc, out, captured, env.manifest)


# --- (g) extra members --------------------------------------------------------


def test_an_extra_top_level_payload_member_still_revokes_and_is_warned_about(
    env: RevokeFixture,
) -> None:
    """§11.2 warns about unknown members at the payload's top level. The record
    is still produced: an unknown member is not a malformed receipt."""
    case = env.scratch()
    payload = _write_payload(
        case, "payload.json", license={"revocability": "policy"}, unexpected="x"
    )
    receipt = _issue(case, env.seed, payload, "envelope.json")
    rc, out, captured = env.run(case, receipt=receipt)

    assert rc == cli.EXIT_OK
    assert_clean_outcome(rc, out, captured, env.manifest)
    result = json.loads(captured.out)
    assert result["revocability"] == "policy"


def test_an_extra_nested_license_member_revokes_without_any_required_warning(
    env: RevokeFixture,
) -> None:
    """Nested unknown members carry no warning obligation (only the payload's
    top level does), and must not become a refusal by accident."""
    case = env.scratch()
    payload = _write_payload(
        case, "payload.json", license={"revocability": "policy", "unexpected": "x"}
    )
    receipt = _issue(case, env.seed, payload, "envelope.json")
    rc, out, captured = env.run(case, receipt=receipt)

    assert rc == cli.EXIT_OK
    assert_clean_outcome(rc, out, captured, env.manifest)


# --- (i) boundaries, both sides ----------------------------------------------


@pytest.mark.parametrize("delta", [0, 1])
def test_receipt_size_boundary_is_the_envelope_ceiling_the_verifier_applies(
    env: RevokeFixture, delta: int
) -> None:
    """Exactly `validate.MAX_ENVELOPE_BYTES` is admitted; one byte more is not.

    The padding is insignificant JSON whitespace, so the receipt at the ceiling
    is still the same signed document — which is what makes the accepted side
    of this boundary a real acceptance and not an accident of some other
    refusal happening first.
    """
    case = env.scratch()
    data = env.receipt.read_bytes()
    size = validate.MAX_ENVELOPE_BYTES + delta
    padded = case / "envelope.json"
    padded.write_bytes(data + b" " * (size - len(data)))
    assert padded.stat().st_size == size
    rc, out, captured = env.run(case, receipt=padded)

    if delta == 0:
        assert rc == cli.EXIT_OK
        assert "exceeds" not in captured.err
    else:
        assert rc == cli.EXIT_USAGE_ERROR
        # `verify` refuses an oversized envelope with a message of its own that
        # also says "exceeds 1048576 bytes"; asserting on that text would pass
        # with the reader's ceiling widened. This names the READER's refusal.
        assert f"--receipt input exceeds {validate.MAX_ENVELOPE_BYTES} bytes" in captured.err
        assert "would not honor" not in captured.err
    assert_clean_outcome(rc, out, captured, env.manifest)


@pytest.mark.parametrize("delta", [0, 1])
def test_manifest_size_boundary_is_the_wider_stage2_ceiling(env: RevokeFixture, delta: int) -> None:
    """The manifest is NOT bounded by the envelope ceiling: it never reaches
    `verify.verify` as an envelope. Without this test the two readers could be
    given the same ceiling and the suite would stay green, which would quietly
    make the asymmetry the module docstring explains untrue."""
    case = env.scratch()
    limit = cli._MAX_STAGE2_INPUT_BYTES["json"]
    assert limit > validate.MAX_ENVELOPE_BYTES
    data = env.manifest.read_bytes()
    size = limit + delta
    padded = case / "manifest.json"
    padded.write_bytes(data + b" " * (size - len(data)))
    assert padded.stat().st_size == size

    rc, out, captured = env.run(case, manifest=padded)

    if delta == 0:
        assert rc == cli.EXIT_OK
    else:
        assert rc == cli.EXIT_USAGE_ERROR
        assert f"--manifest input exceeds {limit} bytes" in captured.err
        assert not out.exists()
    assert_clean_outcome(rc, out, captured, padded)


@pytest.mark.parametrize("delta", [0, 1])
def test_receipt_nesting_boundary_is_the_canonical_parser_depth(
    env: RevokeFixture, delta: int
) -> None:
    """At `canon.MAX_DEPTH` the reader admits the file and the refusal (if any)
    comes from its contents; one level deeper the reader itself refuses."""
    case = env.scratch()
    # The document is a bare nest, not a receipt: at the admitted depth it is
    # refused for its shape, which is a different message from the depth cap.
    depth = canon.MAX_DEPTH + delta
    text = "[" * depth + "]" * depth
    nested = case / "envelope.json"
    nested.write_text(text, encoding="utf-8")
    rc, out, captured = env.run(case, receipt=nested)

    assert rc == cli.EXIT_USAGE_ERROR
    depth_refused = "nesting depth" in captured.err or "depth" in captured.err
    assert depth_refused is (delta == 1), captured.err
    assert_clean_outcome(rc, out, captured, env.manifest)


def _manifest_with_key_count(case: Path, env: RevokeFixture, count: int) -> Path:
    """A self-signed manifest listing `count` keys, the real signer included."""
    signer = keys.from_seed(keys.b64u_decode(env.seed.read_text(encoding="utf-8").strip()))
    entries = [manifests.key_entry(KID, signer.pub, VALID_FROM)]
    for index in range(count - 1):
        filler = keys.from_seed(bytes([index % 251 + 1]) * 32)
        entries.append(
            manifests.key_entry(f"{ISSUER}/keys/filler-{index}#ed25519-1", filler.pub, VALID_FROM)
        )
    manifest = manifests.build_key_manifest(ISSUER, 1, VALID_FROM, entries, signer, KID)
    path = case / f"manifest-{count}.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


@pytest.mark.parametrize("delta", [0, 1])
def test_manifest_key_count_boundary_is_the_manifest_ceiling(
    env: RevokeFixture, delta: int
) -> None:
    """A manifest at `manifests.MAX_MANIFEST_KEYS` still verifies and still
    signs; one key more is not evaluated at all, so nothing may be written."""
    case = env.scratch()
    count = manifests.MAX_MANIFEST_KEYS + delta
    manifest = _manifest_with_key_count(case, env, count)
    rc, out, captured = env.run(case, manifest=manifest)

    if delta == 0:
        assert rc == cli.EXIT_OK
    else:
        assert rc == cli.EXIT_USAGE_ERROR
        assert "does not verify against its own listed keys" in captured.err
    assert_clean_outcome(rc, out, captured, manifest)


# --- the hybrid signing leg ---------------------------------------------------


def test_a_hybrid_leg_from_another_key_is_refused_by_name(env: RevokeFixture) -> None:
    """A hybrid entry names ONE ML-DSA-65 public key. Handing the command a
    well-formed key file that is not that key must be refused for what it is —
    a signer mismatch — and not left to the closing predicate to notice.

    Without this case the mismatch check can be deleted and every other test
    still passes: the record would fail to verify anyway, so the exit code does
    not move. Measured; the mutation survived until this test existed.
    """
    case = env.scratch()
    seed, _pub, mldsa_seed = _keygen_hybrid(case, "hybrid-signer")
    manifest = _manifest_init_hybrid(case, seed, mldsa_seed, "hybrid-manifest.json")
    _other_seed, _other_pub, other_mldsa = _keygen_hybrid(case, "unrelated-hybrid")
    payload = _write_payload(
        case, "payload.json", attest_version="0.2", license={"revocability": "policy"}
    )
    receipt = case / "envelope.json"
    assert (
        cli.main(
            [
                "issue",
                "--payload",
                str(payload),
                "--seed",
                str(seed),
                "--kid",
                KID,
                "--attest-version",
                "0.2",
                "--mldsa-key",
                str(mldsa_seed),
                "--out",
                str(receipt),
            ]
        )
        == cli.EXIT_OK
    )

    out = case / "record.json"
    with capturing() as sink:
        rc = cli.main(
            [
                "revoke",
                "--receipt",
                str(receipt),
                "--manifest",
                str(manifest),
                "--revoked-at",
                REVOKED_AT,
                "--seed",
                str(seed),
                "--kid",
                KID,
                "--mldsa-seed",
                str(other_mldsa),
                "--out",
                str(out),
            ]
        )
    captured = sink[0]

    assert rc == cli.EXIT_USAGE_ERROR
    assert "does not match the signing key's ML-DSA-65 public key" in captured.err
    assert not out.exists()
    assert_clean_outcome(rc, out, captured, manifest)
