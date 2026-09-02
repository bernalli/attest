"""Generate the committed sample bundle for the web verifier.

Drives the reference implementation the same way demo/store_dies.py does —
in-process CLI verbs, library only for payload assembly — to produce a small,
fictional, self-checking `.attest` bundle plus its binding sidecar. The salt
is a fixed derivation so the published sidecar always matches the published
bundle; the signing key is generated fresh on each run (a regenerated sample
is a different fictional store signing the same fictional deal, which is
fine — the committed pair is what the page serves).

Given the log signing keys, this also LOGS the sample receipt in attest's own
transparency log and ships the resulting inclusion evidence inside the bundle
as a `proofs/<receipt_id>.json` member (v0.2 §14), so the page's transparency
row says something true instead of `not_checked`. Without those keys it
behaves exactly as before and the bundle carries no evidence.

Two properties of the log govern how this script may be re-run. It is
APPEND-ONLY, so a regenerated sample adds an entry and never replaces one:
the log accumulates one entry per published sample, which is the truth and
also a fair demonstration of how a log grows. And only `log sign-checkpoint`
touches the signing keys, so the keys live outside this repo and are passed
in by path — never read from the tree, never present in CI.

Run it from the repo root: `.venv/bin/python tools/gen_site_sample.py`
(writes to site/public/sample/). Regeneration is manual, never part of CI.

The bundle's `README.html` is the one member no signature covers and the one
that changes for reasons that have nothing to do with the receipt: it is the
buyer-facing page rendered by `attest.bundle`, and its wording moves when
`attest.buyer_surface` does. Re-minting a key and growing the public log to
follow a sentence would be the wrong trade, so `--refresh-readme` rewrites
ONLY that member of the committed bundle, from the current template, and
leaves every other member byte-for-byte as it was — receipt, manifest, legal
text and proof included, so the page's transparency row keeps saying what it
said. A test holds the committed README to the template, and this flag is
how it is brought back into line.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from attest import bundle, cli, issue, keys, tlog

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_DIR = REPO_ROOT / "site" / "public" / "sample"

# The log lives under site/public/ because `vite build` copies that directory
# verbatim into site/dist/, which is exactly what the Pages workflow deploys —
# so the log is served from the project's own site with no workflow change.
DEFAULT_LOG_DIR = REPO_ROOT / "site" / "public" / "log"
# Signed into every checkpoint and pinned, out of band, by every verifier that
# trusts this log. It is a NAME, not an address: nothing ever fetches it, and
# the log stays mirrorable anywhere. It cannot be changed without orphaning
# every checkpoint and every proof already issued.
LOG_ORIGIN = "attest-receipts.org/log"
LOG_KEY_NAME = LOG_ORIGIN

ISSUER = "store.nebula.example"
KID = f"{ISSUER}/keys/2026-q3#ed25519-1"
KEY_VALID_FROM = "2026-01-01T00:00:00Z"

BUYER_IDENTIFIER = "casey@example.com"
BUYER_IDENTIFIER_TYPE = "email"
# Fixed salt: the committed demo-binding.json must reproduce the commitment
# sealed in the committed demo.attest across regenerations of the sidecar.
SALT = hashlib.sha256(b"attest-site-sample-salt-v1").digest()[:16]

ARTIFACT_SERIES = f"{ISSUER}/works/STARLIGHT-001"
GAME_FILENAME = "starlight-drifter-1.0-setup.bin"
GAME_BYTES = (
    b"ATTEST-SITE-SAMPLE-BINARY\n"
    b"Stand-in for a DRM-free installer; the receipt's artifact hash commits to these bytes.\n"
) * 64
LEGAL_TEXT_BYTES = (
    b"attest sample standard license v1\n"
    b"Perpetual, irrevocable, DRM-free license for the purchased title.\n"
)


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Invoke attest.cli.main in-process, capturing stdout/stderr."""
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        rc = cli.main(argv)
    return rc, stdout.getvalue(), stderr.getvalue()


def _run_cli_json(argv: list[str]) -> dict[str, Any]:
    """Invoke a CLI verb that must succeed; parse its JSON report."""
    rc, stdout, stderr = _run_cli(argv)
    if rc != 0:
        raise RuntimeError(f"attest {argv[0]} failed rc={rc}: {stderr or stdout}")
    return dict(json.loads(stdout))


def _run_cli_capture(argv: list[str]) -> tuple[int, dict[str, Any]]:
    """Invoke a CLI verb whose exit code is part of the outcome; parse JSON."""
    rc, stdout, _stderr = _run_cli(argv)
    return rc, dict(json.loads(stdout))


def _log_keys_document(ed25519_pub_b64u: str, mldsa_pub_b64u: str) -> list[dict[str, str]]:
    """The pinned-log-key document a verifier is configured with (§9.2).

    Public material only. It is written to the KEY directory, never next to
    the log: a verifier must pin log keys out of band, and a copy served from
    the log itself would invite exactly the mistake §7.3 forbids.
    """
    return [
        {
            "origin": LOG_ORIGIN,
            "name": LOG_KEY_NAME,
            "ed25519_pub_b64u": ed25519_pub_b64u,
            "mldsa_pub_b64u": mldsa_pub_b64u,
        }
    ]


def _log_receipt(
    *,
    log_dir: Path,
    receipt_path: Path,
    ed25519_key: Path,
    mldsa_key: Path,
    workspace: Path,
) -> tuple[Path, Path]:
    """Append this receipt to the log, sign a checkpoint, emit its evidence.

    Returns (proof_dir, log_keys_path). The log is created on first use and
    appended to on every later run — it is append-only, so a regenerated
    sample never rewrites history, it extends it.
    """
    envelope = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_id = envelope["payload"]["receipt_id"]

    if not (log_dir / "config.json").exists():
        _run_cli_json(["log", "init", "--dir", str(log_dir), "--origin", LOG_ORIGIN])

    entries_path = log_dir / "entries.jsonl"
    existing = (
        entries_path.read_text(encoding="utf-8").splitlines() if entries_path.exists() else []
    )
    leaf_index = len([line for line in existing if line.strip()])

    entry_path = workspace / "log-entry.json"
    entry_path.write_text(
        json.dumps(
            {
                "type": "receipt",
                "issuer": ISSUER,
                "core_sha256": tlog.receipt_core_hash(envelope),
            }
        ),
        encoding="utf-8",
    )
    _run_cli_json(["log", "append", "--dir", str(log_dir), "--entry-json", str(entry_path)])

    # The only step that sees the signing keys. It recomputes the tree from
    # entries.jsonl and refuses to sign unless the new tree is a proven
    # append-only extension of the checkpoint it is replacing.
    _run_cli_json(
        [
            "log",
            "sign-checkpoint",
            "--dir",
            str(log_dir),
            "--ed25519-key",
            str(ed25519_key),
            "--mldsa-key",
            str(mldsa_key),
            "--name",
            LOG_KEY_NAME,
        ]
    )

    proof_dir = workspace / "proofs"
    proof_dir.mkdir(parents=True, exist_ok=True)
    _run_cli_json(
        [
            "log",
            "prove",
            "--dir",
            str(log_dir),
            "--leaf-index",
            str(leaf_index),
            "--out",
            str(proof_dir / f"{receipt_id}.json"),
        ]
    )

    mldsa_pub = json.loads(mldsa_key.read_text(encoding="utf-8"))["pub"]
    ed25519_pub = keys.b64u(keys.from_seed(keys.b64u_decode(ed25519_key.read_text().strip())).pub)
    # Written beside the private keys, OUTSIDE this repo, and kept: it is the
    # document a verifier pins, so it has to outlive this temp workspace.
    log_keys_path = ed25519_key.parent / "log-keys.pinned.json"
    log_keys_path.write_text(
        json.dumps(_log_keys_document(ed25519_pub, mldsa_pub), indent=2) + "\n",
        encoding="utf-8",
    )
    return proof_dir, log_keys_path


def refresh_readme(attest_path: Path) -> bool:
    """Rewrite `README.html` inside an existing shareable bundle, nothing else.

    The README is rendered exactly as `attest.bundle.export` renders it, from
    the bundle's stem, so the result is what a fresh export of the same name
    would carry. Every other member is copied through with its own metadata
    and content untouched. Returns True if the member changed, False if the
    committed README already matched the template.

    Refuses anything that is not a shareable `.attest`: the private half has
    no README, and rewriting a private archive is never what this is for.
    """
    if not attest_path.name.endswith(".attest") or attest_path.name.endswith(".private.attest"):
        raise RuntimeError(f"not a shareable bundle: {attest_path.name}")
    name = attest_path.name.removesuffix(".attest")
    fresh = bundle._render_readme(name)

    with zipfile.ZipFile(attest_path) as zf:
        members = [(info, zf.read(info)) for info in zf.infolist()]
    current = [data for info, data in members if info.filename == "README.html"]
    if len(current) != 1:
        raise RuntimeError(f"{attest_path.name} carries {len(current)} README.html members, not 1")
    if current[0].decode("utf-8") == fresh:
        return False

    # Written beside the original and swapped in whole: a bundle is never left
    # half-rewritten on disk if this process dies mid-way.
    replacement = attest_path.with_name(attest_path.name + ".tmp")
    with zipfile.ZipFile(replacement, "w", zipfile.ZIP_DEFLATED) as zf:
        for info, data in members:
            if info.filename == "README.html":
                zf.writestr(info.filename, fresh)
            else:
                zf.writestr(info, data)
    replacement.replace(attest_path)
    return True


def main(
    out_dir: Path = DEFAULT_OUT_DIR,
    *,
    log_dir: Path = DEFAULT_LOG_DIR,
    log_ed25519_key: Path | None = None,
    log_mldsa_key: Path | None = None,
) -> dict[str, Any]:
    """Generate demo.attest + demo-binding.json into out_dir; self-check both.

    With both log keys supplied the sample is also logged and its bundle
    carries the inclusion evidence; without them the bundle is exactly what it
    was before, and the report says so rather than failing quietly.
    """
    logging_enabled = log_ed25519_key is not None and log_mldsa_key is not None
    if (log_ed25519_key is None) != (log_mldsa_key is None):
        raise RuntimeError(
            "log signing needs BOTH --log-ed25519-key and --log-mldsa-key: "
            "a checkpoint is signed by the two together, never by one"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="attest-site-sample-") as tmp:
        ws = Path(tmp)
        store, export_dir, import_dir = ws / "store", ws / "export", ws / "import"
        for d in (store, export_dir, import_dir):
            d.mkdir(parents=True)

        seed_path, pub_path = store / "issuer.seed", store / "issuer.pub"
        _run_cli_json(["keygen", "--seed-out", str(seed_path), "--pub-out", str(pub_path)])

        manifest_path = store / "manifest.json"
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

        game_sha256 = hashlib.sha256(GAME_BYTES).hexdigest()
        artifact_entry = {
            "role": "installer",
            "platform": "linux-x86_64",
            "filename": GAME_FILENAME,
            "size_bytes": len(GAME_BYTES),
            "sha256": game_sha256,
        }
        artifacts_json_path = store / "artifacts.json"
        artifacts_json_path.write_text(json.dumps([artifact_entry]), encoding="utf-8")
        artifact_manifest_path = store / "artifact-manifest.json"
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

        legal_text_path = store / "legal.txt"
        legal_text_path.write_bytes(LEGAL_TEXT_BYTES)
        salt_path = store / "receipt.salt"
        salt_path.write_text(keys.b64u(SALT), encoding="utf-8")

        payload = issue.build_payload(
            issuer_id=ISSUER,
            display_name="Nebula Games",
            buyer_identifier=BUYER_IDENTIFIER,
            buyer_identifier_type=BUYER_IDENTIFIER_TYPE,
            buyer_salt=SALT,
            title="Starlight Drifter",
            publisher="Nebula Games Co-op",
            identifiers={"issuer_sku": "STARLIGHT-001"},
            artifact_series=ARTIFACT_SERIES,
            terms_uri=f"https://{ISSUER}/attest/license-templates/standard-v1",
            legal_text_sha256=hashlib.sha256(LEGAL_TEXT_BYTES).hexdigest(),
            artifacts=[artifact_entry],
            revocability="none",
            drm="drm-free",
        )
        payload_path = store / "payload.json"
        payload_path.write_text(json.dumps(payload), encoding="utf-8")

        receipt_path = store / "receipt.attest.json"
        _run_cli_json(
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

        # Logged BEFORE the export, because the evidence has to exist to be
        # packed into the bundle. Nothing here feeds back into what was
        # signed: the log entry commits to the receipt, never the reverse.
        proof_dir: Path | None = None
        log_keys_path: Path | None = None
        if logging_enabled:
            assert log_ed25519_key is not None and log_mldsa_key is not None
            proof_dir, log_keys_path = _log_receipt(
                log_dir=log_dir,
                receipt_path=receipt_path,
                ed25519_key=log_ed25519_key,
                mldsa_key=log_mldsa_key,
                workspace=ws,
            )

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
                "demo",
                *(["--proof-dir", str(proof_dir)] if proof_dir is not None else []),
            ]
        )
        attest_src = Path(export_report["attest"])

        # Self-check: import the bundle store-lessly and verify, then prove binding.
        _run_cli_json(["import", "--bundle", str(attest_src), "--out-dir", str(import_dir)])
        imported_receipt = next((import_dir / "receipts").glob("*.attest.json"))
        trust_dir = import_dir / "trust"
        rc_v, verify_report = _run_cli_capture(
            ["verify", str(imported_receipt), "--trust-dir", str(trust_dir)]
        )
        rc_d, disclosure_report = _run_cli_capture(
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
        if rc_v != 0 or not verify_report.get("ok"):
            raise RuntimeError(f"self-check verify failed: {verify_report}")
        if rc_d != 0 or disclosure_report.get("binding") != "proven":
            raise RuntimeError(f"self-check binding failed: {disclosure_report}")

        # The self-check that makes the logging real: verify the bundle's own
        # proofs/ member against the log's pinned keys and reach `logged`. An
        # empty anchor policy is not a placeholder — the pair logKeys+policy is
        # the capability gate, and this log has no anchors yet, which is the
        # honest state until V-H.7 lands.
        transparency_report: dict[str, Any] | None = None
        if logging_enabled:
            assert log_keys_path is not None
            anchor_policy_path = ws / "anchor-policy.json"
            anchor_policy_path.write_text(
                json.dumps({"pinned_headers": {}, "crqc_horizon": None}), encoding="utf-8"
            )
            imported_proof = next((import_dir / "proofs").glob("*.json"))
            rc_t, transparency_report = _run_cli_capture(
                [
                    "verify",
                    str(imported_receipt),
                    "--trust-dir",
                    str(trust_dir),
                    "--transparency",
                    str(imported_proof),
                    "--log-keys",
                    str(log_keys_path),
                    "--anchor-policy",
                    str(anchor_policy_path),
                ]
            )
            if rc_t != 0 or transparency_report.get("transparency") != "logged":
                raise RuntimeError(f"self-check transparency failed: {transparency_report}")
            if transparency_report.get("corroboration") != "logged":
                raise RuntimeError(f"self-check corroboration failed: {transparency_report}")

        # Publish ONLY the shareable bundle + the binding sidecar. The
        # .private.attest stays in the temp workspace and dies with it.
        attest_dst = out_dir / "demo.attest"
        shutil.copyfile(attest_src, attest_dst)
        binding_dst = out_dir / "demo-binding.json"
        binding_dst.write_text(
            json.dumps(
                {
                    "identifier": BUYER_IDENTIFIER,
                    "identifier_type": BUYER_IDENTIFIER_TYPE,
                    "salt_b64u": keys.b64u(SALT),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    return {
        "attest": str(attest_dst),
        "binding": str(binding_dst),
        "logged": logging_enabled,
        **({"log_dir": str(log_dir), "log_keys": str(log_keys_path)} if logging_enabled else {}),
        "self_check": {
            "verify": verify_report,
            "verify_with_disclosure": disclosure_report,
            **({"verify_with_transparency": transparency_report} if logging_enabled else {}),
        },
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    p.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR)
    p.add_argument(
        "--log-ed25519-key",
        type=Path,
        default=None,
        help="log signer's Ed25519 seed file, from OUTSIDE this repo; with "
        "--log-mldsa-key it logs the sample and ships its evidence in the bundle",
    )
    p.add_argument(
        "--log-mldsa-key", type=Path, default=None, help="log signer's ML-DSA-65 key file"
    )
    p.add_argument(
        "--refresh-readme",
        action="store_true",
        help="rewrite only README.html inside the committed demo.attest from the "
        "current template; mints no key, touches no log, changes no other member",
    )
    return p.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()
    if args.refresh_readme:
        target = args.out_dir / "demo.attest"
        changed = refresh_readme(target)
        print(json.dumps({"attest": str(target), "readme_refreshed": changed}, indent=2))
        sys.exit(0)
    report = main(
        args.out_dir,
        log_dir=args.log_dir,
        log_ed25519_key=args.log_ed25519_key,
        log_mldsa_key=args.log_mldsa_key,
    )
    print(
        json.dumps(
            {k: report[k] for k in ("attest", "binding", "logged") if k in report},
            indent=2,
        )
    )
    sys.exit(0)
