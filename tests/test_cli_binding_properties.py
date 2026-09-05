"""`attest binding challenge` / `attest binding respond` — proving possession.

Both cores have evaluated the §8.2 challenge-response since v0.1: `verify()`
takes `challenge=(nonce, sig)`, and the CLI even exposes the INPUT side
(`--disclose-challenge-nonce` / `--disclose-challenge-sig`). What was missing
is the producer. `commitment.sign_challenge` had no caller in the CLI at all,
so the answer to "what if someone copies your receipt?" — the buyer signing a
fresh nonce with the key the receipt names — could only be exercised by writing
code against the library.

The nonce belongs to the VERIFIER, and `challenge` therefore takes no argument
that could fix it: a challenger who accepts a caller-supplied nonce is not
challenging anyone. `respond` proves the holder's key matches the receipt's
`buyer.pubkey` before it signs, and refuses a receipt that carries no such key
with a message that says what to ask the issuer for — that receipt cannot carry
this proof at all, and saying so is more useful than a signature nobody can
check.
"""

from __future__ import annotations

import contextlib
import io
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from attest import cli, commitment, keys

VECTORS = Path("docs/spec/vectors")
LEAF_17B = VECTORS / "17-binding-proven/b-pubkey-challenge"
LEAF_01 = VECTORS / "01-valid-minimal"

# The corpus buyer key and the nonce its disclosure was signed over. Both are
# read back from the vector rather than restated, except the seed, which is the
# generator's own `bytes([3]) * 32` and is not published in any file.
BUYER_SEED = bytes([3]) * 32

PROPERTY_SETTINGS = settings(max_examples=24, deadline=None, derandomize=True)


@dataclass(frozen=True)
class Captured:
    out: str
    err: str


@contextlib.contextmanager
def capturing() -> Iterator[list[Captured]]:
    """Stream capture that survives Hypothesis.

    `capsys` is function-scoped and Hypothesis refuses to reset it between
    generated inputs, so the properties below capture the streams themselves.
    """
    sink: list[Captured] = []
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        yield sink
    sink.append(Captured(out.getvalue(), err.getvalue()))


def run(argv: list[str]) -> tuple[int, Captured]:
    with capturing() as sink:
        try:
            rc = cli.main(argv)
        except SystemExit as exc:
            rc = int(exc.code or 0)
    return rc, sink[0]


def write_seed(path: Path, raw: bytes) -> Path:
    path.write_text(keys.b64u(raw), encoding="utf-8")
    return path


def write_nonce(path: Path, raw: bytes) -> Path:
    path.write_text(keys.b64u(raw), encoding="utf-8")
    return path


def corpus_nonce() -> bytes:
    disclosure = json.loads((LEAF_17B / "disclosure.json").read_text(encoding="utf-8"))
    return keys.b64u_decode(disclosure["nonce_b64u"])


def corpus_sig_b64u() -> str:
    disclosure = json.loads((LEAF_17B / "disclosure.json").read_text(encoding="utf-8"))
    return str(disclosure["sig_b64u"])


# --- the two verbs exist ------------------------------------------------------


def test_binding_is_a_verb_the_cli_lists() -> None:
    """The cheapest guard against a whole class of hollow test.

    `argparse` exits 2 for a verb it does not know, which is also the exit code
    of a legitimate refusal — so a refusal test written before the verb exists
    can be GREEN against nothing at all, and stay green once the verb arrives
    without ever having changed what it measures. Two of the tests in this file
    were exactly that when first written. Asserting the verb is PRESENT costs
    one line and cannot be satisfied by its absence.
    """
    rc, captured = run(["--help"])
    assert rc == 0
    assert "binding" in captured.out


@pytest.mark.parametrize("verb", ["challenge", "respond"])
def test_binding_help_exists(verb: str) -> None:
    rc, captured = run(["binding", verb, "--help"])
    assert rc == 0
    assert "--out" in captured.out


# --- respond reproduces the corpus disclosure ---------------------------------


def test_respond_reproduces_the_corpus_disclosure_signature(tmp_path: Path) -> None:
    """The strongest available oracle: the corpus disclosure was produced
    independently of this command, and Ed25519 over a fixed message is
    deterministic, so the signature must match byte for byte. A changed domain
    separator, separator byte or field order in `challenge_message` moves it."""
    seed = write_seed(tmp_path / "buyer.seed", BUYER_SEED)
    nonce = write_nonce(tmp_path / "nonce", corpus_nonce())
    out = tmp_path / "sig"

    rc, captured = run(
        [
            "binding",
            "respond",
            "--receipt",
            str(LEAF_17B / "envelope.json"),
            "--holder-seed",
            str(seed),
            "--nonce",
            str(nonce),
            "--out",
            str(out),
        ]
    )

    assert rc == cli.EXIT_OK, captured.err
    assert out.read_text(encoding="utf-8").strip() == corpus_sig_b64u()


def test_challenge_then_respond_proves_binding_to_the_verifier(tmp_path: Path) -> None:
    """The whole point, end to end and with only shipped verbs: the verifier
    generates a nonce, the holder answers it, and the verifier believes the
    answer."""
    nonce = tmp_path / "nonce"
    rc, captured = run(["binding", "challenge", "--out", str(nonce)])
    assert rc == cli.EXIT_OK, captured.err

    seed = write_seed(tmp_path / "buyer.seed", BUYER_SEED)
    sig = tmp_path / "sig"
    rc, captured = run(
        [
            "binding",
            "respond",
            "--receipt",
            str(LEAF_17B / "envelope.json"),
            "--holder-seed",
            str(seed),
            "--nonce",
            str(nonce),
            "--out",
            str(sig),
        ]
    )
    assert rc == cli.EXIT_OK, captured.err

    trust = tmp_path / "trust"
    trust.mkdir()
    bundle = json.loads((LEAF_17B / "manifests.json").read_text(encoding="utf-8"))
    for index, (issuer, manifest) in enumerate(bundle["manifests"].items()):
        (trust / f"{issuer}-{index}.json").write_text(json.dumps(manifest), encoding="utf-8")

    rc, captured = run(
        [
            "verify",
            str(LEAF_17B / "envelope.json"),
            "--trust-dir",
            str(trust),
            "--disclose-challenge-nonce",
            str(nonce),
            "--disclose-challenge-sig",
            str(sig),
        ]
    )
    result = json.loads(captured.out)

    assert rc == cli.EXIT_OK, captured.err
    assert result["binding"] == "proven"


def test_two_challenges_do_not_repeat_a_nonce(tmp_path: Path) -> None:
    """A challenger that reissues a nonce is replayable by anyone who saw the
    first answer."""
    first, second = tmp_path / "n1", tmp_path / "n2"
    assert run(["binding", "challenge", "--out", str(first)])[0] == cli.EXIT_OK
    assert run(["binding", "challenge", "--out", str(second)])[0] == cli.EXIT_OK
    assert first.read_text(encoding="utf-8") != second.read_text(encoding="utf-8")


# --- what respond refuses -----------------------------------------------------


def test_a_seed_that_is_not_the_receipts_holder_is_refused(tmp_path: Path) -> None:
    """Signing with the wrong key would produce a signature that verifies
    against nothing: the mismatch has to be named here, not discovered by the
    verifier later."""
    seed = write_seed(tmp_path / "other.seed", bytes([9]) * 32)
    nonce = write_nonce(tmp_path / "nonce", corpus_nonce())
    out = tmp_path / "sig"

    rc, captured = run(
        [
            "binding",
            "respond",
            "--receipt",
            str(LEAF_17B / "envelope.json"),
            "--holder-seed",
            str(seed),
            "--nonce",
            str(nonce),
            "--out",
            str(out),
        ]
    )

    assert rc == cli.EXIT_USAGE_ERROR
    assert "buyer.pubkey" in captured.err
    assert not out.exists()


def test_a_receipt_without_a_buyer_pubkey_says_what_to_ask_the_issuer_for(
    tmp_path: Path,
) -> None:
    """Most receipts issued today carry `buyer.pubkey: null`, so this is the
    common case, not an edge one. The refusal must explain that possession
    cannot be proven for THIS receipt and what would make it provable —
    otherwise the buyer reads it as their own mistake."""
    seed = write_seed(tmp_path / "buyer.seed", BUYER_SEED)
    nonce = write_nonce(tmp_path / "nonce", corpus_nonce())
    out = tmp_path / "sig"

    rc, captured = run(
        [
            "binding",
            "respond",
            "--receipt",
            str(LEAF_01 / "envelope.json"),
            "--holder-seed",
            str(seed),
            "--nonce",
            str(nonce),
            "--out",
            str(out),
        ]
    )

    assert rc == cli.EXIT_USAGE_ERROR
    assert "buyer.pubkey" in captured.err
    assert "re-issue" in captured.err
    assert not out.exists()


@pytest.mark.parametrize("length", [0, 1, 15])
def test_a_nonce_below_the_floor_is_refused_before_signing(tmp_path: Path, length: int) -> None:
    """`commitment.challenge_message` refuses under 16 bytes. Saying so here,
    by name, is what keeps a short nonce from reaching the signer at all."""
    seed = write_seed(tmp_path / "buyer.seed", BUYER_SEED)
    nonce = write_nonce(tmp_path / "nonce", bytes(length))
    out = tmp_path / "sig"

    rc, captured = run(
        [
            "binding",
            "respond",
            "--receipt",
            str(LEAF_17B / "envelope.json"),
            "--holder-seed",
            str(seed),
            "--nonce",
            str(nonce),
            "--out",
            str(out),
        ]
    )

    assert rc == cli.EXIT_USAGE_ERROR
    assert "--nonce" in captured.err
    assert not out.exists()
    assert "Traceback" not in captured.err


def test_challenge_takes_no_argument_that_could_fix_the_nonce() -> None:
    """A challenger that accepts a caller-supplied nonce is not challenging
    anyone: the parser itself must refuse the option."""
    rc, captured = run(["binding", "challenge", "--nonce", "AAAA", "--out", "/dev/null"])
    assert rc == cli.EXIT_USAGE_ERROR
    assert "unrecognized arguments" in captured.err or "--nonce" in captured.err


# --- properties ---------------------------------------------------------------


@PROPERTY_SETTINGS
@given(nonce_length=st.integers(min_value=0, max_value=64))
def test_a_nonce_is_accepted_exactly_at_and_above_the_floor(
    tmp_path_factory: pytest.TempPathFactory, nonce_length: int
) -> None:
    """Two-sided on the only boundary this verb has. Above the floor the
    signature must be one the verifier's own predicate accepts; below it,
    nothing is written."""
    case = tmp_path_factory.mktemp("nonce-floor")
    seed = write_seed(case / "buyer.seed", BUYER_SEED)
    nonce_bytes = bytes(range(nonce_length))
    nonce = write_nonce(case / "nonce", nonce_bytes)
    out = case / "sig"

    rc, captured = run(
        [
            "binding",
            "respond",
            "--receipt",
            str(LEAF_17B / "envelope.json"),
            "--holder-seed",
            str(seed),
            "--nonce",
            str(nonce),
            "--out",
            str(out),
        ]
    )

    assert "Traceback" not in captured.err
    if nonce_length < 16:
        assert rc == cli.EXIT_USAGE_ERROR
        assert not out.exists()
        return
    assert rc == cli.EXIT_OK, captured.err
    payload = json.loads((LEAF_17B / "envelope.json").read_text(encoding="utf-8"))["payload"]
    assert commitment.verify_challenge(
        payload["receipt_id"],
        nonce_bytes,
        keys.b64u_decode(out.read_text(encoding="utf-8").strip()),
        keys.b64u_decode(payload["buyer"]["pubkey"]),
    )


@PROPERTY_SETTINGS
@given(
    mutation=st.sampled_from(
        [
            "truncate",
            "duplicate-member",
            "float",
            "top-level-array",
            "receipt-id-not-ulid",
            "pubkey-short",
            "pubkey-not-string",
            "no-payload",
        ]
    )
)
def test_a_malformed_receipt_never_yields_a_signature(
    tmp_path_factory: pytest.TempPathFactory, mutation: str
) -> None:
    """Whatever is wrong with the receipt, there are two outcomes and no third:
    a clean exit 2 with no file written, or a signature the verifier accepts.
    Never a traceback, and never a file left behind."""
    case = tmp_path_factory.mktemp("hostile-receipt")
    raw = (LEAF_17B / "envelope.json").read_text(encoding="utf-8")
    document = json.loads(raw)

    if mutation == "truncate":
        text = raw[: len(raw) // 2]
    elif mutation == "duplicate-member":
        text = '{"payload":null,' + raw.strip()[1:]
    elif mutation == "float":
        document["payload"]["issued_at"] = 1.5
        text = json.dumps(document)
    elif mutation == "top-level-array":
        text = json.dumps([document])
    elif mutation == "receipt-id-not-ulid":
        document["payload"]["receipt_id"] = "not-a-ulid"
        text = json.dumps(document)
    elif mutation == "pubkey-short":
        document["payload"]["buyer"]["pubkey"] = keys.b64u(bytes(31))
        text = json.dumps(document)
    elif mutation == "pubkey-not-string":
        document["payload"]["buyer"]["pubkey"] = 7
        text = json.dumps(document)
    else:
        del document["payload"]
        text = json.dumps(document)

    receipt = case / "envelope.json"
    receipt.write_text(text, encoding="utf-8")
    seed = write_seed(case / "buyer.seed", BUYER_SEED)
    nonce = write_nonce(case / "nonce", corpus_nonce())
    out = case / "sig"

    rc, captured = run(
        [
            "binding",
            "respond",
            "--receipt",
            str(receipt),
            "--holder-seed",
            str(seed),
            "--nonce",
            str(nonce),
            "--out",
            str(out),
        ]
    )

    assert "Traceback" not in captured.err
    assert rc == cli.EXIT_USAGE_ERROR
    assert not out.exists()
    assert "error:" in captured.err
    # Exit 2 is also what argparse returns for a verb it does not know, so a
    # test asserting only the code would be GREEN against a command that does
    # not exist. Naming what the refusal must NOT be is what keeps this test
    # from passing for the wrong reason.
    assert "invalid choice" not in captured.err
    assert "unrecognized arguments" not in captured.err


@PROPERTY_SETTINGS
@given(text=st.text(max_size=120))
def test_a_malformed_nonce_file_is_refused_cleanly(
    tmp_path_factory: pytest.TempPathFactory, text: str
) -> None:
    """The nonce arrives as base64url text from a file the caller controls."""
    assume(text.strip() != "")
    case = tmp_path_factory.mktemp("hostile-nonce")
    nonce = case / "nonce"
    nonce.write_text(text, encoding="utf-8")
    seed = write_seed(case / "buyer.seed", BUYER_SEED)
    out = case / "sig"

    rc, captured = run(
        [
            "binding",
            "respond",
            "--receipt",
            str(LEAF_17B / "envelope.json"),
            "--holder-seed",
            str(seed),
            "--nonce",
            str(nonce),
            "--out",
            str(out),
        ]
    )

    assert "Traceback" not in captured.err
    assert "invalid choice" not in captured.err
    assert "unrecognized arguments" not in captured.err
    assert rc in (cli.EXIT_OK, cli.EXIT_USAGE_ERROR)
    if rc == cli.EXIT_USAGE_ERROR:
        assert not out.exists()


# --- the output path is guarded, and written only after every check -----------


def respond_argv(receipt: Path, seed: Path, nonce: Path, out: Path) -> list[str]:
    return [
        "binding",
        "respond",
        "--receipt",
        str(receipt),
        "--holder-seed",
        str(seed),
        "--nonce",
        str(nonce),
        "--out",
        str(out),
    ]


def test_respond_refuses_to_overwrite_a_different_file(tmp_path: Path) -> None:
    """`--out` is a path the caller types, and a typo aims it at a file they
    already have. Write-if-absent-or-identical is what the rest of this CLI
    applies to outputs it would destroy, and there is no reason for this one to
    be the exception."""
    seed = write_seed(tmp_path / "buyer.seed", BUYER_SEED)
    nonce = write_nonce(tmp_path / "nonce", corpus_nonce())
    out = tmp_path / "sig"
    out.write_text("something the caller still wants", encoding="utf-8")

    rc, captured = run(respond_argv(LEAF_17B / "envelope.json", seed, nonce, out))

    assert rc == cli.EXIT_USAGE_ERROR
    assert "already exists" in captured.err
    assert out.read_text(encoding="utf-8") == "something the caller still wants"


def test_respond_replaces_a_different_file_only_with_force(tmp_path: Path) -> None:
    seed = write_seed(tmp_path / "buyer.seed", BUYER_SEED)
    nonce = write_nonce(tmp_path / "nonce", corpus_nonce())
    out = tmp_path / "sig"
    out.write_text("stale", encoding="utf-8")

    rc, captured = run([*respond_argv(LEAF_17B / "envelope.json", seed, nonce, out), "--force"])

    assert rc == cli.EXIT_OK, captured.err
    assert out.read_text(encoding="utf-8").strip() == corpus_sig_b64u()


def test_respond_rewrites_an_identical_answer_without_force(tmp_path: Path) -> None:
    """The same question answered twice is the same bytes: a re-run must not
    need `--force` to say what it already said."""
    seed = write_seed(tmp_path / "buyer.seed", BUYER_SEED)
    nonce = write_nonce(tmp_path / "nonce", corpus_nonce())
    out = tmp_path / "sig"

    assert run(respond_argv(LEAF_17B / "envelope.json", seed, nonce, out))[0] == cli.EXIT_OK
    rc, captured = run(respond_argv(LEAF_17B / "envelope.json", seed, nonce, out))

    assert rc == cli.EXIT_OK, captured.err
    assert out.read_text(encoding="utf-8").strip() == corpus_sig_b64u()
