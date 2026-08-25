"""demo/store_dies.py — "The store dies. The receipt survives."

A narrated, end-to-end walkthrough of the attest v0.1 promise: a purchase
receipt issued by a store remains independently verifiable — offline,
without that store's cooperation or even its continued existence — because
everything a verifier needs (the issuer's signing key manifest, the
receipt's own signature, the buyer-binding proof material, and the artifact
hash the receipt points to) travels with the receipt itself rather than
staying locked inside the store's infrastructure.

The scenario, step by step:

  1. A fake store, `store.dies.example`, generates its Ed25519 signing key
     and publishes its first (self-signed, bootstrap) key manifest.
  2. It publishes a DRM-free game — a real file with real bytes — and signs
     an artifact manifest describing it.
  3. It issues an irrevocable (`revocability: "none"`) receipt to a buyer,
     Casey, embedding Casey's buyer-binding salt directly in the receipt
     (`delivery.salt`) so the file is self-contained. The salt is also
     saved to Casey's own private storage, independent of the store.
  4. It exports a shareable bundle (`.attest` + the secret-bearing
     `.private.attest`) — Casey's copy of "the deal", not just the receipt.
  5. **The store is deleted.** Its whole directory — signing keys, key
     manifest, artifact manifest, everything — is `rmtree`'d. From this
     point on, nothing in this scenario ever reads from the store again.
  6. Casey imports the bundle completely offline and verifies the receipt
     against nothing but what the bundle itself contained. The receipt is
     still `ok`, its trust is honestly reported as `unauthenticated_tofu`
     (this local bundle was never fetched fresh over TLS), and its
     revocation status is honestly reported as `unknown` (no revocation
     feed was ever consulted — the demo never claims "not revoked" when it
     only knows "no data").
  7. Casey proves the receipt is theirs by disclosing the salt they saved
     in step 3 — `binding: "proven"`.
  8. A mirror copy of the game file — held independently of the dead
     store, with identical bytes — still hashes to exactly what the
     surviving receipt says it should.

This module is driven through the `attest` CLI (`attest.cli.main`) exactly as a
real operator would use it, one call per verb; the only place it falls back
to the library directly is building the receipt *payload* itself
(`issue.build_payload`), because the CLI's `issue` verb intentionally takes
an already-built payload (see Task 14) — payload assembly, including
computing `buyer.commitment`, is out of the CLI's scope by design.

Run it from the repository root: `.venv/bin/python -m demo.store_dies`
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from attest import issue, keys
from demo import _driver

_narrate = _driver.narrate
_verb_label = _driver.verb_label
_run_cli = _driver.run_cli
_run_cli_json = _driver.run_cli_json
_run_cli_capture = _driver.run_cli_capture
_write_secret_text = _driver.write_secret_text

ISSUER = "store.dies.example"
KID = f"{ISSUER}/keys/bootstrap-1#ed25519-1"
KEY_VALID_FROM = "2020-01-01T00:00:00Z"  # deliberately far in the past, open-ended validity

BUYER_IDENTIFIER = "casey@example.com"
BUYER_IDENTIFIER_TYPE = "email"

ARTIFACT_SERIES = f"{ISSUER}/works/INDIE-001"
GAME_FILENAME = "indie-game-1.0-setup.bin"
GAME_BYTES = (
    b"ATTEST-DEMO-GAME-BINARY\n"
    b"This stands in for a real, DRM-free game installer.\n"
    b"Its bytes are what the receipt's artifact hash actually commits to.\n"
) * 64

LEGAL_TEXT_BYTES = (
    b"attest demo standard license v1\n"
    b"Casey owns this copy of Indie Game, perpetually, irrevocably, "
    b"DRM-free, transferable: no.\n"
)


def run_demo(workspace: Path) -> dict[str, Any]:
    """Run the full "store dies, receipt survives" scenario inside
    `workspace` (a fresh, writable directory — callers such as the pytest
    wrapper are expected to hand in `tmp_path`) and return the outcomes of
    every asserted step as a plain dict.

    `workspace` MUST be a fresh/dedicated directory: the demo `rmtree`s
    `workspace/store` in step 5. The `is_relative_to` guard below only
    protects the tree *boundary* (nothing outside `workspace` is ever
    deleted); it does NOT protect a caller that passes a shared directory
    with pre-existing content under `store/`, which would be wiped.

    Deletes exactly one thing: the store's own subdirectory of `workspace`
    (step 5) — never anything outside `workspace`.
    """
    workspace = workspace.resolve()
    store_dir = workspace / "store"
    buyer_dir = workspace / "buyer"
    mirror_dir = workspace / "mirror"
    export_dir = workspace / "export"
    import_dir = workspace / "import"
    for directory in (store_dir, buyer_dir, mirror_dir, export_dir, import_dir):
        directory.mkdir(parents=True, exist_ok=True)

    outcomes: dict[str, Any] = {}

    # --- Step 1: the store's identity ---------------------------------------
    _narrate("Step 1: the store generates its signing key and first key manifest")
    seed_path = store_dir / "issuer.seed"
    pub_path = store_dir / "issuer.pub"
    _run_cli_json(["keygen", "--seed-out", str(seed_path), "--pub-out", str(pub_path)])

    manifest_path = store_dir / "manifest.json"
    _run_cli_json(
        [
            "manifest",
            "init",
            "--issuer",
            ISSUER,
            "--kid",
            KID,
            "--seed",
            str(seed_path),
            "--valid-from",
            KEY_VALID_FROM,
            "--issued-at",
            KEY_VALID_FROM,
            "--out",
            str(manifest_path),
        ]
    )

    # --- Step 2: the product itself -----------------------------------------
    _narrate("Step 2: the store publishes a DRM-free game artifact and its manifest")
    game_path = store_dir / "artifacts" / GAME_FILENAME
    game_path.parent.mkdir(parents=True, exist_ok=True)
    game_path.write_bytes(GAME_BYTES)
    game_sha256 = hashlib.sha256(GAME_BYTES).hexdigest()

    # A second, independently-held copy — this is what step 8 checks against
    # once the store (and its own hosted copy) is gone.
    mirror_path = mirror_dir / GAME_FILENAME
    mirror_path.write_bytes(GAME_BYTES)

    artifact_entry = {
        "role": "installer",
        "platform": "linux-x86_64",
        "filename": GAME_FILENAME,
        "size_bytes": len(GAME_BYTES),
        "sha256": game_sha256,
    }
    artifacts_json_path = store_dir / "artifacts.json"
    artifacts_json_path.write_text(json.dumps([artifact_entry]), encoding="utf-8")

    artifact_manifest_path = store_dir / "artifact-manifest.json"
    _run_cli_json(
        [
            "manifest",
            "artifacts",
            "--in",
            str(manifest_path),
            "--issuer",
            ISSUER,
            "--series",
            ARTIFACT_SERIES,
            "--version",
            "1",
            "--manifest-version",
            "1",
            "--released-at",
            KEY_VALID_FROM,
            "--artifacts",
            str(artifacts_json_path),
            "--signing-kid",
            KID,
            "--signing-seed",
            str(seed_path),
            "--out",
            str(artifact_manifest_path),
        ]
    )

    # --- Step 3: issue an irrevocable receipt to Casey -----------------------
    _narrate(f"Step 3: the store issues an irrevocable receipt to {BUYER_IDENTIFIER}")
    salt = os.urandom(16)
    salt_path = buyer_dir / "receipt.salt"  # Casey's own copy — "save the salt"
    _write_secret_text(salt_path, keys.b64u(salt))

    legal_text_path = store_dir / "legal.txt"
    legal_text_path.write_bytes(LEGAL_TEXT_BYTES)
    legal_text_sha256 = hashlib.sha256(LEGAL_TEXT_BYTES).hexdigest()

    # `attest issue` takes an already-built payload (design: payload assembly,
    # including computing `buyer.commitment`, is out of the CLI's scope per
    # Task 14) — build it with the library, then hand it to the CLI to sign.
    payload = issue.build_payload(
        issuer_id=ISSUER,
        display_name="The Store That Dies",
        buyer_identifier=BUYER_IDENTIFIER,
        buyer_identifier_type=BUYER_IDENTIFIER_TYPE,
        buyer_salt=salt,
        title="Indie Game",
        publisher="Indie Games Co-op",
        identifiers={"issuer_sku": "INDIE-001"},
        artifact_series=ARTIFACT_SERIES,
        terms_uri=f"https://{ISSUER}/attest/license-templates/standard-v1",
        legal_text_sha256=legal_text_sha256,
        artifacts=[artifact_entry],
        revocability="none",
        drm="drm-free",
    )
    payload_path = store_dir / "payload.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")

    # `--salt` embeds `delivery.salt` in the `--out` envelope itself, making
    # it a single self-contained `.attest.json` (§9 delivery member).
    receipt_path = buyer_dir / "receipt.attest.json"
    issue_report = _run_cli_json(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(seed_path),
            "--kid",
            KID,
            "--salt",
            str(salt_path),
            "--out",
            str(receipt_path),
        ]
    )
    receipt_id = issue_report["receipt_id"]
    outcomes["receipt_id"] = receipt_id

    # --- Step 4: export the bundle -------------------------------------------
    _narrate("Step 4: the store exports a shareable bundle — Casey's copy of the deal")
    export_report = _run_cli_json(
        [
            "export",
            "--receipt",
            str(receipt_path),
            "--key-manifest",
            str(manifest_path),
            "--artifact-manifest",
            str(artifact_manifest_path),
            "--legal-text",
            str(legal_text_path),
            "--out-dir",
            str(export_dir),
            "--name",
            "casey-library",
        ]
    )
    attest_path = Path(export_report["attest"])
    private_path = Path(export_report["private"])
    outcomes["export"] = {"attest": str(attest_path), "private": str(private_path)}

    # --- Step 5: the store dies ----------------------------------------------
    _narrate("Step 5: the store is deleted — keys, manifests, everything")
    if not store_dir.is_relative_to(workspace):
        # Binding constraint: never delete anything outside this demo's own
        # temp workspace, no matter what `workspace` happens to be. `store_dir`
        # is always constructed as `workspace / "store"` above, so this can
        # only trip if that construction is ever changed carelessly later.
        raise RuntimeError(f"refusing to delete {store_dir}: it is not inside {workspace}")
    shutil.rmtree(store_dir)
    outcomes["store_dir_deleted"] = not store_dir.exists()

    # --- Step 6: offline import + verify, store-less -------------------------
    _narrate("Step 6: Casey imports the bundle offline and verifies it against the bundle alone")
    import_report = _run_cli_json(
        [
            "import",
            "--bundle",
            str(attest_path),
            "--private",
            str(private_path),
            "--out-dir",
            str(import_dir),
        ]
    )
    outcomes["import"] = import_report

    imported_receipt = next((import_dir / "receipts").glob("*.attest.json"))
    trust_dir = import_dir / "trust"

    # Deliberately no --revocations: this is the honest case where the
    # verifier has consulted no revocation feed at all.
    rc, verify_report = _run_cli_capture(
        ["verify", str(imported_receipt), "--trust-dir", str(trust_dir)]
    )
    outcomes["verify"] = verify_report
    outcomes["verify_exit_code"] = rc

    # --- Step 7: prove the binding via salt disclosure ------------------------
    _narrate("Step 7: Casey proves the receipt is theirs by disclosing the salt")
    rc, disclosure_report = _run_cli_capture(
        [
            "verify",
            str(imported_receipt),
            "--trust-dir",
            str(trust_dir),
            "--disclose-identifier",
            BUYER_IDENTIFIER,
            "--disclose-type",
            BUYER_IDENTIFIER_TYPE,
            "--disclose-salt",
            str(salt_path),
        ]
    )
    outcomes["verify_with_disclosure"] = disclosure_report
    outcomes["verify_with_disclosure_exit_code"] = rc

    # --- Step 8: the artifact itself survives, independently -----------------
    _narrate("Step 8: check a mirror copy of the game file against the surviving receipt")
    rc, check_report = _run_cli_capture(
        ["check-artifact", str(mirror_path), "--receipt", str(imported_receipt)]
    )
    outcomes["check_artifact"] = check_report
    outcomes["check_artifact_exit_code"] = rc

    _narrate(
        "Done: store.dies.example no longer exists on disk anywhere in this "
        "workspace, and the receipt it once issued still verifies, still "
        "proves it belongs to Casey, and still matches an independently "
        "mirrored copy of the game it paid for."
    )
    return outcomes


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="attest-store-dies-") as tmp:
        outcomes = run_demo(Path(tmp))

    print("\n=== Summary ===")
    print(
        json.dumps(
            {
                "receipt_id": outcomes["receipt_id"],
                "store_dir_deleted": outcomes["store_dir_deleted"],
                "verify": {
                    "ok": outcomes["verify"]["ok"],
                    "trust": outcomes["verify"]["trust"],
                    "revocation": outcomes["verify"]["revocation"],
                },
                "binding": outcomes["verify_with_disclosure"]["binding"],
                "check_artifact_match": outcomes["check_artifact"]["match"],
            },
            indent=2,
        )
    )

    ok = (
        outcomes["store_dir_deleted"]
        and outcomes["verify"]["ok"] is True
        and outcomes["verify"]["trust"] == "unauthenticated_tofu"
        and outcomes["verify"]["revocation"] == "unknown"
        and outcomes["verify_with_disclosure"]["binding"] == "proven"
        and outcomes["check_artifact"]["match"] is True
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
