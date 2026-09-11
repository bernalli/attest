"""demo/witness_cosigns.py — "Somebody else saw the same head."

The third demo, and the question the first two leave open. `store_dies.py`
shows that a receipt outlives its issuer; `pledge_dies.py` shows that the file
can come back. Both rest on a signature, and a signature says who signed —
never how many different things they signed. A transparency log can prove an
entry is in a tree it published. It cannot, by itself, prove it published only
ONE tree: a log holding its own keys can maintain two self-consistent branches
and show a different one to each person, and every proof from either branch
verifies perfectly.

A witness is the answer, and it is a modest one. It reads a checkpoint, checks
that the new tree genuinely extends the last one it cosigned for that log, and
signs it with a timestamp. From then on, whoever holds that cosignature knows
this log's head was observed by somebody who would have refused to sign a fork
of it. That is timestamped observation and nothing more — which is why every
witnessed verdict this demo produces carries
`witness_independence_not_established`.

The scenario, step by step:

  1. Three parties, three key pairs: a store (Ed25519), a log operator
     (hybrid) and a witness (hybrid). They are separate on purpose — a
     witness that shares the log's keys observes nothing.
  2. The store publishes its key manifest; the log operator creates an empty
     transparency log.
  3. The store issues a receipt to Casey **into the log** (`issue --log-dir`).
     The entry is the one the CLI computes from the receipt it just signed,
     not a row written by hand beside it.
  4. The log's offline signer signs the checkpoint — the head, as a C2SP
     signed note, hybrid-signed.
  5. The witness is configured with that log pinned, and served over real
     HTTP on loopback. Its allowlist is the whole of what it trusts.
  6. The checkpoint is submitted with C2SP's `add-checkpoint` body. The
     witness answers 200 with two signature lines, which are APPENDED to the
     note; its monitoring endpoint then serves that cosigned note to anyone.
  7. `attest log prove` produces the inclusion evidence, which is re-pointed
     at the cosigned note and told which witness-policy epoch to read.
  8. `attest verify` runs TWICE over the same receipt, the same log keys and
     the same witness policy. Without the cosignature lines: `corroboration:
     "logged"`. With them: `corroboration: "witnessed"`. The note body is
     byte-identical across both, so the difference is the cosignature and
     nothing else.
  9. **The fork.** The log signs a second, different tree of the same size —
     a genuine signature over dishonest contents, which is exactly what a log
     holding its own keys can do. The witness refuses it (C2SP 422), and goes
     on vouching only for the head it actually saw.

Two joins in this chain had no usable implementation before this demo, and
they live in `demo/witness_client.py`: a C2SP submission body was built only by
test-local helpers under `witness/tests/`, which nothing outside that package
can import, and nothing at all carried the returned cosignature back into the
evidence a verifier reads. Like `demo/custodian.py`, that module is non-normative — there
is no `attest log cosign` command and it is not one.

Run it from the repository root: `.venv/bin/python -m demo.witness_cosigns`
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sys
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from wsgiref.simple_server import make_server

from attest_witness.cli import _QuietRequestHandler, _ThreadingWSGIServer
from attest_witness.config import load_config
from attest_witness.http import make_app
from attest_witness.service import WitnessService, origin_hash
from attest_witness.store import WitnessStore

from attest import issue, keys, pq, tlog
from demo import _driver, witness_client

_narrate = _driver.narrate
_run_cli_json = _driver.run_cli_json
_run_cli_capture = _driver.run_cli_capture

STORE = "store.watched.example"
STORE_KID = f"{STORE}/keys/bootstrap-1#ed25519-1"
LOG_ORIGIN = "log.watched.example"
WITNESS_NAME = "witness.watched.example/w1"
WITNESS_OPERATOR = "witness.watched.example"
EPOCH_ID = "bootstrap-1"
EPOCH_START = "2020-01-01T00:00:00Z"

BUYER_IDENTIFIER = "casey@example.com"
BUYER_IDENTIFIER_TYPE = "email"
ARTIFACT_SERIES = f"{STORE}/works/WATCHED-001"
GAME_FILENAME = "watched-game-1.0-setup.bin"
GAME_BYTES = (
    b"ATTEST-DEMO-WATCHED-BINARY\n"
    b"Its bytes are what the receipt's artifact hash commits to, and the\n"
    b"receipt is what the transparency log's entry commits to.\n"
) * 32
LEGAL_TEXT_BYTES = (
    b"attest demo standard license v1\nCasey owns this copy, perpetually, irrevocably, DRM-free.\n"
)

SUBMISSION_PREFIX = "/witness/v0"
MONITORING_PREFIX = "/witness/v0/monitoring"
SUBMISSION_PATH = f"{SUBMISSION_PREFIX}/add-checkpoint"


def _toml_string(value: object) -> str:
    """A TOML basic string. JSON's string escapes are a subset of TOML's, and
    a temporary directory's path is exactly the kind of value that should not
    be pasted into a config file unescaped."""
    return json.dumps(str(value))


def _witness_config_text(
    *,
    seed_path: Path,
    mldsa_key_path: Path,
    database_path: Path,
    log_ed25519_pub_b64u: str,
    log_mldsa_65_pub_b64u: str,
) -> str:
    """The witness's whole trusted configuration, in the shape
    `witness/examples/witness.toml` documents."""
    return "\n".join(
        [
            "[witness]",
            f"name = {_toml_string(WITNESS_NAME)}",
            f"seed_path = {_toml_string(seed_path)}",
            f"mldsa_key_path = {_toml_string(mldsa_key_path)}",
            "",
            "[storage]",
            f"database_path = {_toml_string(database_path)}",
            "",
            "[server]",
            f"submission_prefix = {_toml_string(SUBMISSION_PREFIX)}",
            f"monitoring_prefix = {_toml_string(MONITORING_PREFIX)}",
            "",
            "[[log]]",
            f"origin = {_toml_string(LOG_ORIGIN)}",
            f"name = {_toml_string(LOG_ORIGIN)}",
            f"ed25519_pub_b64u = {_toml_string(log_ed25519_pub_b64u)}",
            f"mldsa_65_pub_b64u = {_toml_string(log_mldsa_65_pub_b64u)}",
            "",
        ]
    )


def _witness_policy_document(ed25519_pub_b64u: str) -> dict[str, Any]:
    """The verifier's OWN trusted configuration (v0.2 s11.4).

    It travels on the same rail as pinned log keys — packaged with the
    verifier, never read off the evidence bundle. The evidence only names the
    epoch; this document says who that epoch pins. `log_origins` is not
    decoration: an epoch that does not list a checkpoint's origin corroborates
    nothing for it.
    """
    return {
        "schema": "attest-witness-policy-v1",
        "epochs": [
            {
                "epoch_id": EPOCH_ID,
                "not_before": EPOCH_START,
                "not_after": None,
                "log_origins": [LOG_ORIGIN],
                "threshold": {"n": 1, "m": 1},
                "witnesses": [
                    {
                        "operator_id": WITNESS_OPERATOR,
                        "control_group": WITNESS_OPERATOR,
                        "name": WITNESS_NAME,
                        "ed25519_pub_b64u": ed25519_pub_b64u,
                        # s10.1's rule is one valid type-0x04 cosignature, so
                        # the corroboration role needs no ML-DSA-65 leg pinned.
                        # The witness emits one anyway; the activation-grade
                        # quorum of s11.4 is what consumes it.
                        "mldsa_65_pub_b64u": None,
                        "roles": ["corroboration"],
                        "not_before": EPOCH_START,
                        "not_after": None,
                        "affiliated_domains": [WITNESS_OPERATOR],
                    }
                ],
            }
        ],
    }


def _load_hybrid_keys(seed_path: Path, mldsa_path: Path) -> pq.HybridSigningKeys:
    """Read back what `attest keygen --hybrid` wrote.

    Used for exactly one thing: signing the FORK in step 9. A fork has to be
    signed by the log's own keys, because a fork nobody signed is not the
    threat — the threat is a log that holds its keys and publishes two trees.
    """
    mldsa_document = json.loads(mldsa_path.read_text(encoding="utf-8"))
    return pq.HybridSigningKeys(
        ed=keys.from_seed(keys.b64u_decode(seed_path.read_text(encoding="utf-8").strip())),
        mldsa=pq.MLDSAKeyPair(
            sk=keys.b64u_decode(mldsa_document["sk"]),
            pub=keys.b64u_decode(mldsa_document["pub"]),
        ),
    )


@contextlib.contextmanager
def _served_witness(config_path: Path) -> Iterator[tuple[str, int]]:
    """Run the witness on a loopback port for as long as the block lasts.

    Real HTTP, not the WSGI app called in-process: the submission this demo
    narrates is a request over a socket, and calling a function while saying
    "submitted to the witness" would be narrating something that did not
    happen. The threading server is the one `attest-witness serve` uses, and
    everything opened here is closed on the way out — including on the error
    path, which is what the `finally` is for.
    """
    config = load_config(config_path)
    store = WitnessStore(config.database_path)
    httpd = make_server(
        "127.0.0.1",
        0,
        make_app(WitnessService(config, store), config),
        server_class=_ThreadingWSGIServer,
        handler_class=_QuietRequestHandler,
    )
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield "127.0.0.1", int(httpd.server_address[1])
    finally:
        httpd.shutdown()
        thread.join(timeout=10)
        httpd.server_close()
        store.close()


def run_demo(workspace: Path) -> dict[str, Any]:
    """Run the whole log-to-cosignature chain inside `workspace` (a fresh,
    writable directory — the pytest wrapper hands in `tmp_path`) and return
    every asserted outcome as a plain dict.

    Nothing outside `workspace` is written, nothing is deleted, and the only
    network traffic is to a loopback port this function opens and closes
    itself.
    """
    workspace = workspace.resolve()
    store_dir = workspace / "store"
    log_dir = workspace / "log"
    witness_dir = workspace / "witness"
    verifier_dir = workspace / "verifier"
    for directory in (store_dir, log_dir, witness_dir, verifier_dir):
        directory.mkdir(parents=True, exist_ok=True)

    outcomes: dict[str, Any] = {}

    # --- Step 1: three parties, three key pairs -----------------------------
    _narrate("Step 1: the store, the log operator and the witness generate their keys")
    store_seed = store_dir / "issuer.seed"
    _run_cli_json(
        ["keygen", "--seed-out", str(store_seed), "--pub-out", str(store_dir / "issuer.pub")]
    )

    log_seed = log_dir / "log.seed"
    log_pub = log_dir / "log.pub"
    log_mldsa = log_dir / "log-mldsa65.json"
    _run_cli_json(
        [
            "keygen",
            "--hybrid",
            "--seed-out",
            str(log_seed),
            "--pub-out",
            str(log_pub),
            "--mldsa-out",
            str(log_mldsa),
        ]
    )

    witness_seed = witness_dir / "witness.seed"
    witness_pub = witness_dir / "witness.pub"
    witness_mldsa = witness_dir / "witness-mldsa65.json"
    _run_cli_json(
        [
            "keygen",
            "--hybrid",
            "--seed-out",
            str(witness_seed),
            "--pub-out",
            str(witness_pub),
            "--mldsa-out",
            str(witness_mldsa),
        ]
    )

    log_ed25519_pub_b64u = log_pub.read_text(encoding="utf-8").strip()
    log_mldsa_pub_b64u = json.loads(log_mldsa.read_text(encoding="utf-8"))["pub"]
    witness_ed25519_pub_b64u = witness_pub.read_text(encoding="utf-8").strip()
    witness_mldsa_pub_b64u = json.loads(witness_mldsa.read_text(encoding="utf-8"))["pub"]

    # --- Step 2: the store's manifest, and an empty log ----------------------
    _narrate("Step 2: the store publishes its key manifest; the log operator creates the log")
    manifest_path = store_dir / "manifest.json"
    _run_cli_json(
        [
            "manifest",
            "init",
            "--issuer",
            STORE,
            "--kid",
            STORE_KID,
            "--seed",
            str(store_seed),
            "--valid-from",
            EPOCH_START,
            "--issued-at",
            EPOCH_START,
            "--out",
            str(manifest_path),
        ]
    )
    tree_dir = log_dir / "tree"
    log_init = _run_cli_json(["log", "init", "--dir", str(tree_dir), "--origin", LOG_ORIGIN])
    outcomes["log_origin"] = log_init["origin"]

    # --- Step 3: a receipt, issued INTO the log ------------------------------
    _narrate(f"Step 3: the store issues a receipt to {BUYER_IDENTIFIER}, logging it as it signs")
    game_path = store_dir / GAME_FILENAME
    game_path.write_bytes(GAME_BYTES)
    legal_path = store_dir / "legal.txt"
    legal_path.write_bytes(LEGAL_TEXT_BYTES)

    artifact_entry = {
        "role": "installer",
        "platform": "linux-x86_64",
        "filename": GAME_FILENAME,
        "size_bytes": len(GAME_BYTES),
        "sha256": hashlib.sha256(GAME_BYTES).hexdigest(),
    }
    # As in the other demos, the CLI's `issue` verb takes an already-built
    # payload: assembling one, including `buyer.commitment`, is out of its
    # scope by design.
    payload = issue.build_payload(
        issuer_id=STORE,
        display_name="The Watched Store",
        buyer_identifier=BUYER_IDENTIFIER,
        buyer_identifier_type=BUYER_IDENTIFIER_TYPE,
        buyer_salt=bytes.fromhex("5a" * 16),
        title="Indie Game",
        publisher="Indie Games Co-op",
        identifiers={"issuer_sku": "WATCHED-001"},
        artifact_series=ARTIFACT_SERIES,
        terms_uri=f"https://{STORE}/attest/license-templates/standard-v1",
        legal_text_sha256=hashlib.sha256(LEGAL_TEXT_BYTES).hexdigest(),
        artifacts=[artifact_entry],
        revocability="none",
        drm="drm-free",
    )
    payload_path = store_dir / "payload.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")

    receipt_path = store_dir / "receipt.attest.json"
    issue_report = _run_cli_json(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(store_seed),
            "--kid",
            STORE_KID,
            "--out",
            str(receipt_path),
            "--log-dir",
            str(tree_dir),
        ]
    )
    outcomes["receipt_id"] = issue_report["receipt_id"]
    outcomes["log"] = issue_report["log"]

    # --- Step 4: the offline signer signs the head ---------------------------
    _narrate("Step 4: the log's offline signer signs the checkpoint")
    sign_report = _run_cli_json(
        [
            "log",
            "sign-checkpoint",
            "--dir",
            str(tree_dir),
            "--ed25519-key",
            str(log_seed),
            "--mldsa-key",
            str(log_mldsa),
            "--name",
            LOG_ORIGIN,
        ]
    )
    checkpoint_text = Path(sign_report["checkpoint"]).read_text(encoding="utf-8")
    outcomes["checkpoint"] = checkpoint_text
    outcomes["checkpoint_size"] = sign_report["size"]

    # --- Step 5: a witness that trusts exactly this log ----------------------
    _narrate("Step 5: a witness is configured with that log pinned, and served on loopback")
    config_path = witness_dir / "witness.toml"
    config_path.write_text(
        _witness_config_text(
            seed_path=witness_seed,
            mldsa_key_path=witness_mldsa,
            database_path=witness_dir / "state.sqlite3",
            log_ed25519_pub_b64u=log_ed25519_pub_b64u,
            log_mldsa_65_pub_b64u=log_mldsa_pub_b64u,
        ),
        encoding="utf-8",
    )

    with _served_witness(config_path) as (host, port):
        outcomes["witness"] = {
            "name": WITNESS_NAME,
            "ed25519_pub_b64u": witness_ed25519_pub_b64u,
            "mldsa_65_pub_b64u": witness_mldsa_pub_b64u,
            "host": host,
            "port": port,
        }

        # --- Step 6: the submission -----------------------------------------
        _narrate("Step 6: the checkpoint is submitted; the witness cosigns it")
        # `old 0`: this witness has never seen this log, so the tree it is
        # being asked to endorse extends the empty tree, and C2SP wants no
        # consistency proof alongside a zero old size.
        submission = witness_client.build_submission(0, checkpoint_text)
        cosignature_lines = witness_client.submit(host, port, SUBMISSION_PATH, submission)
        cosigned_checkpoint = witness_client.cosigned_note(checkpoint_text, cosignature_lines)
        outcomes["cosignature_lines"] = cosignature_lines
        outcomes["cosigned_checkpoint"] = cosigned_checkpoint

        monitoring_path = f"{MONITORING_PREFIX}/{origin_hash(LOG_ORIGIN)}/checkpoint"
        outcomes["monitored_checkpoint"] = witness_client.fetch_monitored(
            host, port, monitoring_path
        )
        print(
            f"{WITNESS_NAME} returned "
            f"{len(cosignature_lines.splitlines())} cosignature lines; the note grew from "
            f"{len(checkpoint_text)} to {len(cosigned_checkpoint)} bytes, and "
            f"{monitoring_path} now serves the cosigned note to anyone who asks."
        )

        # --- Step 7: the evidence a verifier reads ---------------------------
        _narrate("Step 7: inclusion evidence, re-pointed at the cosigned note")
        evidence_path = verifier_dir / "evidence.json"
        _run_cli_json(
            [
                "log",
                "prove",
                "--dir",
                str(tree_dir),
                "--receipt",
                str(receipt_path),
                "--out",
                str(evidence_path),
            ]
        )
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        # `log prove` writes the note in LOG/checkpoint, which the witness's
        # lines never reach, and emits no `witness_policy_epoch`. Both joins
        # are this demo's own work — see demo/witness_client.py.
        unwitnessed = dict(evidence)
        unwitnessed["witness_policy_epoch"] = EPOCH_ID
        witnessed = witness_client.evidence_with_cosignature(
            evidence, cosigned_checkpoint, witness_policy_epoch=EPOCH_ID
        )
        outcomes["evidence_unwitnessed"] = unwitnessed
        outcomes["evidence_witnessed"] = witnessed
        unwitnessed_path = verifier_dir / "evidence-unwitnessed.json"
        witnessed_path = verifier_dir / "evidence-witnessed.json"
        unwitnessed_path.write_text(json.dumps(unwitnessed), encoding="utf-8")
        witnessed_path.write_text(json.dumps(witnessed), encoding="utf-8")

        # --- Step 8: the verdict, twice ---------------------------------------
        _narrate("Step 8: the same receipt verified without, then with, the cosignature")
        trust_dir = verifier_dir / "trust"
        trust_dir.mkdir(parents=True, exist_ok=True)
        (trust_dir / "manifest.json").write_text(
            manifest_path.read_text(encoding="utf-8"), encoding="utf-8"
        )
        log_keys_path = verifier_dir / "log-keys.json"
        log_keys_path.write_text(
            json.dumps(
                [
                    {
                        "origin": LOG_ORIGIN,
                        "name": LOG_ORIGIN,
                        "ed25519_pub_b64u": log_ed25519_pub_b64u,
                        "mldsa_pub_b64u": log_mldsa_pub_b64u,
                    }
                ]
            ),
            encoding="utf-8",
        )
        # Stage 2 needs an anchor policy to be CONFIGURED even when there is
        # no anchor to evaluate: `--transparency` and `--log-keys` alone leave
        # the evaluator unconfigured, and the verdict comes back
        # `transparency: "not_checked"` with `transparency_config_missing`.
        # An empty policy is the honest spelling of "no anchors pinned".
        anchor_policy_path = verifier_dir / "anchor-policy.json"
        anchor_policy_path.write_text(
            json.dumps({"pinned_headers": {}, "crqc_horizon": None}), encoding="utf-8"
        )
        witness_policy_path = verifier_dir / "witness-policy.json"
        witness_policy_path.write_text(
            json.dumps(_witness_policy_document(witness_ed25519_pub_b64u)), encoding="utf-8"
        )
        outcomes["witness_policy_epoch"] = EPOCH_ID

        def _verify(evidence_file: Path) -> tuple[int, dict[str, Any]]:
            return _run_cli_capture(
                [
                    "verify",
                    str(receipt_path),
                    "--trust-dir",
                    str(trust_dir),
                    "--transparency",
                    str(evidence_file),
                    "--log-keys",
                    str(log_keys_path),
                    "--anchor-policy",
                    str(anchor_policy_path),
                    "--witness-policy",
                    str(witness_policy_path),
                ]
            )

        rc, unwitnessed_result = _verify(unwitnessed_path)
        outcomes["verify_unwitnessed"] = unwitnessed_result
        outcomes["verify_unwitnessed_exit_code"] = rc

        rc, witnessed_result = _verify(witnessed_path)
        outcomes["verify_witnessed"] = witnessed_result
        outcomes["verify_witnessed_exit_code"] = rc

        # --- Step 9: the fork the witness will not sign -----------------------
        _narrate("Step 9: the log signs a second tree of the same size; the witness refuses it")
        log_signing_keys = _load_hybrid_keys(log_seed, log_mldsa)
        # A real tree of the same size over a different leaf: the root differs,
        # and the signature over it is genuine. This is what a log that holds
        # its own keys can do, and the only reason a witness exists.
        fork_root = tlog.build_tree([b"an entry this log never published"])
        fork_checkpoint = tlog.sign_checkpoint(
            LOG_ORIGIN, sign_report["size"], fork_root, log_signing_keys, LOG_ORIGIN
        )
        # `old` is the size the witness holds, so the conflict check passes and
        # the refusal is the consistency one: at an equal size the roots must
        # be identical, and these are not.
        fork_submission = witness_client.build_submission(sign_report["size"], fork_checkpoint)
        try:
            witness_client.submit(host, port, SUBMISSION_PATH, fork_submission)
        except witness_client.WitnessRefused as refusal:
            outcomes["fork_refusal_status"] = refusal.status
            outcomes["fork_refusal_body"] = refusal.body.strip()
        else:  # pragma: no cover - a cosigned fork is the failure this demo exists to rule out
            raise RuntimeError("the witness cosigned a fork of the head it had already endorsed")

        outcomes["monitored_after_fork"] = witness_client.fetch_monitored(
            host, port, monitoring_path
        )
        print(
            f"refused with {outcomes['fork_refusal_status']}: "
            f"{outcomes['fork_refusal_body']}. The monitoring endpoint still serves the "
            "head this witness actually saw, unchanged."
        )

    _narrate(
        "Done: the log's head was observed by somebody who would have refused "
        "a fork of it, the receipt verifies as witnessed, and the same evidence "
        "without those two lines verifies as merely logged."
    )
    return outcomes


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="attest-witness-cosigns-") as tmp:
        outcomes = run_demo(Path(tmp))

    print("\n=== Summary ===")
    print(
        json.dumps(
            {
                "receipt_id": outcomes["receipt_id"],
                "log": {
                    "origin": outcomes["log_origin"],
                    "size": outcomes["checkpoint_size"],
                    "leaf_index": outcomes["log"]["leaf_index"],
                },
                "witness": outcomes["witness"]["name"],
                "without_cosignature": {
                    "transparency": outcomes["verify_unwitnessed"]["transparency"],
                    "corroboration": outcomes["verify_unwitnessed"]["corroboration"],
                },
                "with_cosignature": {
                    "transparency": outcomes["verify_witnessed"]["transparency"],
                    "corroboration": outcomes["verify_witnessed"]["corroboration"],
                    "warnings": outcomes["verify_witnessed"]["warnings"],
                },
                "fork_refused_with": outcomes["fork_refusal_status"],
            },
            indent=2,
        )
    )

    ok = (
        outcomes["verify_unwitnessed"]["ok"] is True
        and outcomes["verify_unwitnessed"]["transparency"] == "logged"
        and outcomes["verify_unwitnessed"]["corroboration"] == "logged"
        and outcomes["verify_witnessed"]["ok"] is True
        and outcomes["verify_witnessed"]["corroboration"] == "witnessed"
        and "witness_independence_not_established" in outcomes["verify_witnessed"]["warnings"]
        and outcomes["fork_refusal_status"] == 422
        and outcomes["monitored_after_fork"] == outcomes["cosigned_checkpoint"]
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
