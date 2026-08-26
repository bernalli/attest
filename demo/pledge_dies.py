"""demo/pledge_dies.py — "The store dies. The pledge fires. The file comes back."

`store_dies.py` answers the first question: when the seller is gone, does the
receipt still prove anything? Yes — it verifies offline, forever.

This demo answers the one that always follows: *and how do I get my file
back?* A rights holder signs a preservation pledge at the time of sale; the
store later dies; the rights holder declares the cessation; and an archive
that has held its own copy all along hands that copy over — but only to
someone who can prove, right there and then, that the receipt is theirs.

Nothing here is a component of attest. The archive gate is
`demo/custodian.py`, a non-normative reference: attest defines a receipt
format and a verifier, and never distributes content. What makes the
delivery lawful in this story is the rights holder's own explicit grant,
narrated below as a signed document, and the delivery is restricted to
holders of a receipt for that very work.

Run it from the repository root: `.venv/bin/python -m demo.pledge_dies`
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

from attest import canon, issue, keys
from demo import _driver
from demo.custodian import Custodian

PUBLISHER = "pub.dies.example"
PUB_KID = f"{PUBLISHER}/keys/bootstrap-1#ed25519-1"
STORE = "store.pledge.example"
STORE_KID = f"{STORE}/keys/bootstrap-1#ed25519-1"
ARCHIVE = "archive.holders.example"
OTHER_ARCHIVE = "other-archive.example"

KEY_VALID_FROM = "2020-01-01T00:00:00Z"
DECLARED_AT = "2027-01-01T00:00:00Z"
FIXED_DATE = "2031-01-01T00:00:00Z"

BUYER_IDENTIFIER = "casey@example.com"
BUYER_IDENTIFIER_TYPE = "email"

ARTIFACT_SERIES = f"{STORE}/works/PLEDGE-001"
GAME_FILENAME = "pledged-game-1.0-setup.bin"
GAME_BYTES = b"PLEDGED-DEMO-BINARY-" + b"\x00\x01\x02\x03" * 8
LEGAL_TEXT_BYTES = (
    b"DRAFT preservation pledge - NOT LEGAL TEXT.\n"
    b"A real pledge is prose written by a lawyer and hash-bound to the grant\n"
    b"below. This placeholder stands in its place so the mechanism can be\n"
    b"demonstrated without pretending the legal work is done.\n"
)

TRIGGER_PUBLISHER_DECLARATION = "publisher-declaration"
TRIGGER_FIXED_DATE = "fixed-date"
TRIGGERS = (TRIGGER_PUBLISHER_DECLARATION, TRIGGER_FIXED_DATE)

# Past the grant's own `fixed_date`, and comfortably before it. The demo
# pins both, because only the pair proves the backstop is the thing doing
# the work.
HEADER_TIME_AFTER = 1_924_992_001
HEADER_TIME_BEFORE = 1_600_000_000
PINNED_HEADER_HASH = "3a" * 32


def run_demo(workspace: Path, trigger: str = TRIGGER_PUBLISHER_DECLARATION) -> dict[str, Any]:
    """Run the whole "pledge fires, archive delivers" scenario inside
    `workspace` and return every asserted outcome as a plain dict.

    `workspace` MUST be a fresh, dedicated directory: step 6 deletes
    `workspace/store`. The `is_relative_to` guard below protects the tree
    boundary — nothing outside `workspace` is ever removed — but it cannot
    protect a caller who hands in a shared directory that already has
    content under `store/`.
    """
    if trigger not in TRIGGERS:
        raise ValueError(f"unsupported trigger: {trigger!r}")

    workspace = workspace.resolve()
    pub_dir = workspace / "publisher"
    store_dir = workspace / "store"
    buyer_dir = workspace / "buyer"
    archive_dir = workspace / "archive"
    export_dir = workspace / "export"
    import_dir = workspace / "import"
    gate_dir = workspace / "gate"
    delivered_dir = workspace / "delivered"
    for directory in (pub_dir, store_dir, buyer_dir, archive_dir, export_dir, import_dir):
        directory.mkdir(parents=True, exist_ok=True)

    outcomes: dict[str, Any] = {"trigger": trigger}

    # --- Step 1: the rights holder, who outlives the store -------------------
    _driver.narrate(
        "Step 1: the rights holder generates keys of its own — separate from the store's, "
        "which is the whole reason a cessation can still be signed after the store is gone"
    )
    pub_seed = pub_dir / "publisher.seed"
    pub_mldsa = pub_dir / "publisher.mldsa.json"
    _driver.run_cli_json(
        [
            "keygen",
            "--seed-out",
            str(pub_seed),
            "--pub-out",
            str(pub_dir / "publisher.pub"),
            "--hybrid",
            "--mldsa-out",
            str(pub_mldsa),
        ]
    )
    pub_manifest = pub_dir / "manifest.json"
    _driver.run_cli_json(
        [
            "manifest",
            "init",
            "--issuer",
            PUBLISHER,
            "--kid",
            PUB_KID,
            "--seed",
            str(pub_seed),
            "--valid-from",
            KEY_VALID_FROM,
            "--issued-at",
            KEY_VALID_FROM,
            "--mldsa-key",
            str(pub_mldsa),
            "--out",
            str(pub_manifest),
        ]
    )

    # --- Step 2: the store ---------------------------------------------------
    _driver.narrate("Step 2: the store generates its signing key and first key manifest")
    store_seed = store_dir / "issuer.seed"
    store_mldsa = store_dir / "issuer.mldsa.json"
    _driver.run_cli_json(
        [
            "keygen",
            "--seed-out",
            str(store_seed),
            "--pub-out",
            str(store_dir / "issuer.pub"),
            "--hybrid",
            "--mldsa-out",
            str(store_mldsa),
        ]
    )
    store_manifest = store_dir / "manifest.json"
    _driver.run_cli_json(
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
            KEY_VALID_FROM,
            "--issued-at",
            KEY_VALID_FROM,
            "--mldsa-key",
            str(store_mldsa),
            "--out",
            str(store_manifest),
        ]
    )

    # --- Step 3: the work, and an archive that keeps its own copy ------------
    _driver.narrate(
        "Step 3: the store publishes the work, and an archive keeps an independent copy — "
        "no network anywhere in this demo, the archive is a directory"
    )
    game_path = store_dir / "artifacts" / GAME_FILENAME
    game_path.parent.mkdir(parents=True, exist_ok=True)
    game_path.write_bytes(GAME_BYTES)
    game_sha256 = hashlib.sha256(GAME_BYTES).hexdigest()
    archived_copy = archive_dir / GAME_FILENAME
    archived_copy.write_bytes(GAME_BYTES)

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
    _driver.run_cli_json(
        [
            "manifest",
            "artifacts",
            "--in",
            str(store_manifest),
            "--issuer",
            STORE,
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
            STORE_KID,
            "--signing-seed",
            str(store_seed),
            "--mldsa-key",
            str(store_mldsa),
            "--out",
            str(artifact_manifest_path),
        ]
    )

    # --- Step 4: the pledge --------------------------------------------------
    _driver.narrate(
        "Step 4: the rights holder signs the sunset grant — the promise, in a document, "
        "hash-bound to prose a lawyer has to write for real"
    )
    legal_text_path = pub_dir / "legal.txt"
    legal_text_path.write_bytes(LEGAL_TEXT_BYTES)
    legal_text_sha256 = hashlib.sha256(LEGAL_TEXT_BYTES).hexdigest()
    grant_uri = f"https://{PUBLISHER}/pledge/grant-v1.json"
    grant_path = pub_dir / "grant.json"
    grant_report = _driver.run_cli_json(
        [
            "grant",
            "issue",
            "--grant-version",
            "1",
            "--publisher",
            PUBLISHER,
            "--artifact",
            game_sha256,
            "--permission",
            "deliver-to-holder",
            "--mode",
            "publisher-declaration",
            "--mode",
            "fixed-date",
            "--fixed-date",
            FIXED_DATE,
            "--legal-text-uri",
            grant_uri,
            "--legal-text-sha256",
            legal_text_sha256,
            "--jurisdiction",
            "IT",
            "--issued-at",
            KEY_VALID_FROM,
            "--seed",
            str(pub_seed),
            "--kid",
            PUB_KID,
            "--mldsa-seed",
            str(pub_mldsa),
            "--out",
            str(grant_path),
        ]
    )
    grant_sha256 = grant_report["grant_sha256"]
    grant_doc_for_bundle = json.loads(grant_path.read_text(encoding="utf-8"))

    # --- Step 5: the receipt, and the buyer's own key ------------------------
    _driver.narrate(
        f"Step 5: the store issues a receipt to {BUYER_IDENTIFIER}, who holds a signing key "
        "of their own — without it there is nobody the archive could later answer to"
    )
    buyer_seed_path = buyer_dir / "buyer.seed"
    _driver.run_cli_json(
        ["keygen", "--seed-out", str(buyer_seed_path), "--pub-out", str(buyer_dir / "buyer.pub")]
    )
    buyer_pubkey = keys.b64u_decode((buyer_dir / "buyer.pub").read_text().strip())

    salt = os.urandom(16)
    salt_path = buyer_dir / "receipt.salt"
    _driver.write_secret_text(salt_path, keys.b64u(salt))

    payload = issue.build_payload(
        issuer_id=STORE,
        display_name="The Store That Pledged",
        buyer_identifier=BUYER_IDENTIFIER,
        buyer_identifier_type=BUYER_IDENTIFIER_TYPE,
        buyer_salt=salt,
        buyer_pubkey=buyer_pubkey,
        title="Pledged Game",
        publisher="Indie Games Co-op",
        identifiers={"issuer_sku": "PLEDGE-001"},
        artifact_series=ARTIFACT_SERIES,
        terms_uri=f"https://{STORE}/attest/license-templates/standard-v1",
        legal_text_sha256=legal_text_sha256,
        artifacts=[artifact_entry],
        revocability="none",
        drm="drm-free",
        end_of_life="sunset-grant",
        # Both commitments point at the GRANT, not at the prose: a receipt
        # whose two commitment fields disagree is reported as the issuer's own
        # inconsistency, and rightly so.
        eol_commitment_uri=grant_uri,
        eol_commitment_sha256=grant_sha256,
        publisher_id=PUBLISHER,
        preservation_pledge={
            "pledge": "sunset-grant-v1",
            "grant_uri": grant_uri,
            "grant_sha256": grant_sha256,
        },
        attest_version="0.2",
    )
    payload_path = store_dir / "payload.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    receipt_path = buyer_dir / "receipt.attest.json"
    issue_report = _driver.run_cli_json(
        [
            "issue",
            "--payload",
            str(payload_path),
            "--seed",
            str(store_seed),
            "--kid",
            STORE_KID,
            "--salt",
            str(salt_path),
            "--attest-version",
            "0.2",
            "--mldsa-key",
            str(store_mldsa),
            "--out",
            str(receipt_path),
        ]
    )
    outcomes["receipt_id"] = issue_report["receipt_id"]
    outcomes["salt_path"] = str(salt_path)
    outcomes["buyer_seed_path"] = str(buyer_seed_path)

    # The receipt commits to the grant through `eol_commitment_sha256`, and a
    # bundle must carry every hash-bound document its receipts depend on — so
    # Casey's bundle physically contains the pledge, in the canonical bytes the
    # commitment is computed over, not the pretty-printed file on disk.
    grant_canonical_path = pub_dir / "grant.canonical.json"
    grant_canonical_path.write_bytes(canon.canonical_bytes(grant_doc_for_bundle))

    export_report = _driver.run_cli_json(
        [
            "export",
            "--receipt",
            str(receipt_path),
            "--key-manifest",
            str(store_manifest),
            "--artifact-manifest",
            str(artifact_manifest_path),
            "--legal-text",
            str(legal_text_path),
            "--legal-text",
            str(grant_canonical_path),
            "--out-dir",
            str(export_dir),
            "--name",
            "casey-library",
        ]
    )

    # --- Step 6: the store dies ----------------------------------------------
    _driver.narrate("Step 6: the store is deleted — keys, manifests, hosted copy, everything")
    if not store_dir.is_relative_to(workspace):
        raise RuntimeError(f"refusing to delete {store_dir}: it is not inside {workspace}")
    shutil.rmtree(store_dir)
    outcomes["store_dir_deleted"] = not store_dir.exists()

    _driver.run_cli_json(
        [
            "import",
            "--bundle",
            export_report["attest"],
            "--private",
            export_report["private"],
            "--out-dir",
            str(import_dir),
        ]
    )
    imported_receipt = next((import_dir / "receipts").glob("*.attest.json"))
    trust_dir = import_dir / "trust"
    # The rights holder is not the store: their manifest travels with the
    # buyer, not inside the store's bundle.
    shutil.copy(pub_manifest, trust_dir / f"{PUBLISHER}.json")

    # --- Step 7: the pledge exists, and has not fired ------------------------
    _driver.narrate(
        "Step 7: offline verification with the grant as evidence — the pledge is there, "
        "and it is DORMANT: nothing is owed yet"
    )
    grant_doc = json.loads(grant_path.read_text(encoding="utf-8"))
    grant_seed = canon.canonical_bytes(grant_doc)

    # The two passes differ in ONE thing: what makes the grant fire. On the
    # declaration pass the dormant view is the grant alone. On the fixed-date
    # pass it is the grant plus an anchor whose pinned header is still BEFORE
    # the backstop — the same shape of evidence that will later activate it,
    # which is what makes the later activation mean something.
    anchor_policy_path: Path | None = None
    if trigger == TRIGGER_FIXED_DATE:
        proof, policy = _seeded_time_proof(grant_seed, HEADER_TIME_BEFORE)
        anchor_policy_path = buyer_dir / "anchor-policy-before.json"
        anchor_policy_path.write_text(json.dumps(policy), encoding="utf-8")
        dormant_view: dict[str, Any] = {"grant": grant_doc, "anchor": {"proofs": [proof]}}
    else:
        dormant_view = {"grant": grant_doc}

    grant_view_dormant = buyer_dir / "grant-view-dormant.json"
    grant_view_dormant.write_text(json.dumps(dormant_view), encoding="utf-8")
    rc, verify_dormant = _driver.run_cli_capture(
        _verify_argv(imported_receipt, trust_dir, grant_view_dormant, anchor_policy_path)
    )
    if trigger == TRIGGER_FIXED_DATE:
        outcomes["anchor_before_the_date"] = verify_dormant
    outcomes["verify_dormant"] = verify_dormant
    outcomes["verify_dormant_exit_code"] = rc

    # --- Step 8: the first refusal -------------------------------------------
    _driver.narrate("Step 8: Casey turns up at the archive anyway. REFUSED: the grant is dormant")
    gate = Custodian(
        audience=ARCHIVE,
        archive_dir=archive_dir,
        trust_dir=trust_dir,
        challenge_dir=gate_dir,
        anchor_policy=anchor_policy_path,
    )
    # The archive mints the challenge and keeps it: Casey is handed its
    # contents, and the copy the gate will spend never leaves the gate.
    response_path = _answer_a_fresh_challenge(gate, imported_receipt, buyer_seed_path, buyer_dir)
    declaration_path = pub_dir / "declaration.json"
    # Recorded BEFORE the declaration is minted: a refusal narrated after the
    # trigger already exists would be theatre, not a demonstration.
    outcomes["declaration_existed_at_dormant_refusal"] = declaration_path.exists()
    outcomes["refusal_dormant"] = gate.redeem(
        receipt=imported_receipt,
        grant_view=grant_view_dormant,
        response=response_path,
        deliver_to=delivered_dir,
    ).reason

    # --- Step 9: the trigger --------------------------------------------------
    if trigger == TRIGGER_PUBLISHER_DECLARATION:
        _driver.narrate(
            "Step 9: the rights holder signs the cessation declaration — the trigger the grant "
            "named. The store is gone; the person who made the promise is not"
        )
        _driver.run_cli_json(
            [
                "grant",
                "declare",
                "--publisher",
                PUBLISHER,
                "--artifact",
                game_sha256,
                "--declared-at",
                DECLARED_AT,
                "--seed",
                str(pub_seed),
                "--kid",
                PUB_KID,
                "--mldsa-seed",
                str(pub_mldsa),
                "--out",
                str(declaration_path),
            ]
        )
        active_view: dict[str, Any] = {
            "grant": grant_doc,
            "declarations": [json.loads(declaration_path.read_text(encoding="utf-8"))],
        }
    else:
        _driver.narrate(
            "Step 9: nobody signs anything. The rights holder is gone too, and the backstop "
            "the grant named has been reached — proved by an anchor, not asserted by anyone"
        )
        proof_after, policy_after = _seeded_time_proof(grant_seed, HEADER_TIME_AFTER)
        anchor_policy_path = buyer_dir / "anchor-policy-after.json"
        anchor_policy_path.write_text(json.dumps(policy_after), encoding="utf-8")
        gate = Custodian(
            audience=ARCHIVE,
            archive_dir=archive_dir,
            trust_dir=trust_dir,
            challenge_dir=gate_dir,
            anchor_policy=anchor_policy_path,
        )
        active_view = {"grant": grant_doc, "anchor": {"proofs": [proof_after]}}

    outcomes["declaration_minted"] = declaration_path.exists()

    grant_view_active = buyer_dir / "grant-view-active.json"
    grant_view_active.write_text(json.dumps(active_view), encoding="utf-8")
    rc, verify_activated = _driver.run_cli_capture(
        _verify_argv(imported_receipt, trust_dir, grant_view_active, anchor_policy_path)
    )
    outcomes["verify_activated"] = verify_activated
    outcomes["verify_activated_exit_code"] = rc
    if trigger == TRIGGER_FIXED_DATE:
        outcomes["anchor_after_the_date"] = verify_activated

    # --- Step 10: the refusals that still stand, at an ACTIVE grant ----------
    _driver.narrate(
        "Step 10: the grant is active, and the gate still refuses four requests — "
        "an activated pledge is a promise to the HOLDER, not to whoever turns up"
    )
    outcomes.update(
        _refusals_at_an_active_grant(
            gate=gate,
            receipt=imported_receipt,
            grant_view=grant_view_active,
            response=response_path,
            buyer_dir=buyer_dir,
            buyer_seed=buyer_seed_path,
            gate_dir=gate_dir,
            archive_dir=archive_dir,
            trust_dir=trust_dir,
            delivered_dir=delivered_dir,
            salt_b64u=salt_path.read_text(encoding="utf-8").strip(),
        )
    )

    # --- Step 11: the delivery ------------------------------------------------
    _driver.narrate(
        "Step 11: a fresh challenge, Casey's own signature over it, and the archive hands "
        "the file across"
    )
    final_response = _answer_a_fresh_challenge(
        gate, imported_receipt, buyer_seed_path, buyer_dir, "final-response.json"
    )
    decision = gate.redeem(
        receipt=imported_receipt,
        grant_view=grant_view_active,
        response=final_response,
        deliver_to=delivered_dir,
    )
    outcomes["served"] = decision.reason
    outcomes["delivered"] = str(decision.delivered) if decision.delivered else ""
    outcomes["archived_copy"] = str(archived_copy)

    rc, check_report = _driver.run_cli_capture(
        ["check-artifact", str(decision.delivered), "--receipt", str(imported_receipt)]
    )
    outcomes["check_artifact"] = check_report
    outcomes["check_artifact_exit_code"] = rc

    # --- Step 12: what just happened ------------------------------------------
    _driver.narrate(
        "Done: the store no longer exists anywhere in this workspace, the rights holder's "
        "pledge fired, and an archive that never had a relationship with Casey handed over "
        "the file — against a receipt, a signed grant, and a proof only Casey could make"
    )
    return outcomes


def _verify_argv(
    receipt: Path, trust_dir: Path, grant_view: Path, anchor_policy: Path | None
) -> list[str]:
    argv = [
        "verify",
        str(receipt),
        "--trust-dir",
        str(trust_dir),
        "--grant-view",
        str(grant_view),
    ]
    if anchor_policy is not None:
        argv += ["--anchor-policy", str(anchor_policy)]
    return argv


def _seeded_time_proof(seed: bytes, header_time: int) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fabricate one seeded OpenTimestamps attestation over `seed`, plus the
    trust policy that pins the header it climbs to.

    A real attestation is obtained from a calendar and the header is one a
    verifier already trusts; here both ends are synthesised so the demo needs
    no network and no Bitcoin. The op-chain is written out by hand rather than
    taken from a shared generator: `tests/test_anchor.py` and
    `tools/gen_vectors.py` each keep their own copy for the same reason — one
    generator with a bug in it would agree with itself everywhere.

    The chain is `SHA256(seed)`, append a sibling, hash, prepend a prefix,
    hash. §18.4 reduces the resulting verdict by `anchored_after`, the MAXIMUM
    pinned time: "has real time reached T?", the opposite question from §11's.
    """
    sibling = bytes.fromhex("ab" * 32)
    prefix = bytes.fromhex("cd" * 16)
    acc = hashlib.sha256(seed).digest()
    acc = hashlib.sha256(acc + sibling).digest()
    acc = hashlib.sha256(prefix + acc).digest()
    merkle_root = acc.hex()

    proof: dict[str, Any] = {
        "kind": "ots",
        "ops": [
            ["append", sibling.hex()],
            ["sha256"],
            ["prepend", prefix.hex()],
            ["sha256"],
        ],
        "header_merkle_root": merkle_root,
        "header_time": header_time,
        "header_hash": PINNED_HEADER_HASH,
    }
    policy: dict[str, Any] = {
        "pinned_headers": {
            PINNED_HEADER_HASH: {
                "header_hash": PINNED_HEADER_HASH,
                "merkle_root": merkle_root,
                "time": header_time,
            }
        },
        "crqc_horizon": None,
    }
    return proof, policy


def _answer_a_fresh_challenge(
    gate: Custodian,
    receipt: Path,
    holder_seed: Path,
    out_dir: Path,
    name: str = "response.json",
) -> Path:
    """Ask the archive for a challenge and sign the answer to it.

    Every request that must reach the gate's redemption-proof step needs one
    of these: the custodian spends the challenge it is holding on the first
    request that uses it, whatever that request's fate. Requests refused
    earlier — a tampered receipt, the salt offered as proof — never touch it.
    """
    challenge = gate.challenge(receipt=receipt)
    response = out_dir / name
    _driver.run_cli_json(
        [
            "grant",
            "respond",
            "--challenge",
            str(challenge),
            "--holder-seed",
            str(holder_seed),
            "--out",
            str(response),
        ]
    )
    return response


def _refusals_at_an_active_grant(
    *,
    gate: Custodian,
    receipt: Path,
    grant_view: Path,
    response: Path,
    buyer_dir: Path,
    buyer_seed: Path,
    gate_dir: Path,
    archive_dir: Path,
    trust_dir: Path,
    delivered_dir: Path,
    salt_b64u: str,
) -> dict[str, Any]:
    """The four requests the gate turns away once the grant IS active."""
    refusals: dict[str, Any] = {}

    # (a) A receipt with a byte flipped in the signed payload. Refused before
    # the proof step, so Casey's standing response is enough here: a request
    # turned away this early never reaches the archive's challenge at all,
    # which is why bad requests cannot burn a challenge somebody else is
    # waiting to answer.
    tampered = buyer_dir / "tampered-receipt.attest.json"
    envelope = json.loads(receipt.read_text(encoding="utf-8"))
    envelope["payload"]["work"]["title"] = "Something Else Entirely"
    tampered.write_text(json.dumps(envelope), encoding="utf-8")
    refusals["refusal_bad_receipt"] = gate.redeem(
        receipt=tampered,
        grant_view=grant_view,
        response=response,
        deliver_to=delivered_dir,
    ).reason

    # (b) Someone who holds the PUBLIC bundle but not Casey's seed. This one
    # does reach the proof step, so it gets a challenge of its own — minted by
    # the archive, as every challenge here is.
    thief_seed = buyer_dir / "thief.seed"
    _driver.run_cli_json(
        ["keygen", "--seed-out", str(thief_seed), "--pub-out", str(buyer_dir / "thief.pub")]
    )
    forged = _answer_a_fresh_challenge(gate, receipt, thief_seed, buyer_dir, "forged-response.json")
    refusals["refusal_bad_proof"] = gate.redeem(
        receipt=receipt,
        grant_view=grant_view,
        response=forged,
        deliver_to=delivered_dir,
    ).reason

    # (c) A proof Casey legitimately made for ANOTHER archive, replayed here.
    # The audience is inside the signed preimage, which is what makes the
    # replay impossible rather than merely discouraged. The other archive has
    # a challenge directory of its own: two custodians sharing one would be
    # one custodian wearing two hats.
    elsewhere = Custodian(
        audience=OTHER_ARCHIVE,
        archive_dir=archive_dir,
        trust_dir=trust_dir,
        challenge_dir=gate_dir / "elsewhere",
    )
    replayed = _answer_a_fresh_challenge(
        elsewhere, receipt, buyer_seed, buyer_dir, "replayed-response.json"
    )
    # This archive is holding a challenge of its own at the time, so what
    # refuses the request is the proof, not the absence of anything to prove.
    gate.challenge(receipt=receipt)
    refusals["refusal_replayed_proof"] = gate.redeem(
        receipt=receipt,
        grant_view=grant_view,
        response=replayed,
        deliver_to=delivered_dir,
    ).reason

    # (d) The salt offered as proof. It would work on a verifier, and handing
    # it to a custodian is exactly how a holder gives away the ability to be
    # impersonated everywhere.
    refusals["refusal_salt"] = gate.redeem(
        receipt=receipt,
        grant_view=grant_view,
        response=response,
        deliver_to=delivered_dir,
        offered_salt=salt_b64u,
    ).reason

    return refusals


def main() -> int:
    import tempfile

    all_ok = True
    for trigger in TRIGGERS:
        _driver.narrate(f"=== pass: {trigger} ===")
        with tempfile.TemporaryDirectory(prefix=f"attest-pledge-{trigger}-") as tmp:
            outcomes = run_demo(Path(tmp), trigger=trigger)
            print(f"\n--- outcomes ({trigger}) ---")
            print(json.dumps(outcomes, indent=2, sort_keys=True))
            all_ok = all_ok and (
                outcomes["store_dir_deleted"] is True
                and outcomes["verify_dormant"]["grant"] == "dormant"
                and outcomes["refusal_dormant"] == "grant_not_activated"
                and outcomes["verify_activated"]["grant"] == "activated"
                and outcomes["served"] == "served"
                and outcomes["check_artifact"]["match"] is True
            )
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
