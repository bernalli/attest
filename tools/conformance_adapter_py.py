"""The Python-reference conformance adapter for `tools/conformance_runner.py`.

usage: conformance_adapter_py.py LEAF_DIR

Reads one conformance-corpus leaf directory (see `docs/spec/vectors/README.md`
for the corpus contract) and prints the leaf's `VerificationResult` (or, for a
`chain.json` leaf, its `ChainAuditResult`; or, for a `witness-quorum.json`
leaf, its `ActivationWitnessQuorumResult`) as ONE JSON object on stdout —
nothing else on stdout, ever. This is the adapter driven by both the
self-certification runs recorded in `docs/conformance.md` and by
`tests/tools/test_conformance_dogfood.py`, which invokes it (and the runner)
as genuine subprocesses — never in-process — so this file is exercised
exactly the way a third-party implementation's own adapter would be.

The loader functions below duplicate (never import) the ~60 lines of vector-
loading logic in `tests/test_vectors.py`, which remains the source of truth
for their semantics (envelope-bytes XOR rule, `TrustStore` construction,
`disclosure`/`revocation_view`/`transparency`/`log_keys`/`anchor_policy`/
`revocation_evidence`/`transfer_view`/`witness_policy` loaders, the group-36
`chain.json` routing to `transfer.audit_chain`, and the group-40
`witness-quorum.json` routing to
`witness.evaluate_activation_witness_quorum`). Deliberately NOT imported from `tests/`:
this adapter must work standalone, exactly like a real implementation's own
adapter would, and must never depend on the test suite being installed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from attest import anchor, keys, tlog, transfer, verify, witness


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _envelope_bytes(leaf: Path) -> bytes:
    raw_path = leaf / "envelope.raw.json"
    if raw_path.exists():
        return raw_path.read_bytes()
    envelope = _load_json(leaf / "envelope.json")
    return json.dumps(envelope).encode("utf-8")


def _trust_store(leaf: Path) -> verify.TrustStore:
    data = _load_json(leaf / "manifests.json")
    return verify.TrustStore(
        manifests=data["manifests"],
        provenance=data["provenance"],
        chains=data.get("chains", {}),
        artifact_manifests=data.get("artifact_manifests", {}),
        artifact_manifest_chains=data.get("artifact_manifest_chains", {}),
    )


def _revocation_view(leaf: Path) -> list[dict[str, Any]] | None:
    path = leaf / "revocation.json"
    if not path.exists():
        return None
    return [_load_json(path)]


def _disclosure(leaf: Path) -> verify.Disclosure | None:
    path = leaf / "disclosure.json"
    if not path.exists():
        return None
    data = _load_json(path)
    if "salt_b64u" in data:
        return verify.Disclosure(
            identifier=data["identifier"],
            identifier_type=data["identifier_type"],
            salt=keys.b64u_decode(data["salt_b64u"]),
        )
    return verify.Disclosure(
        challenge=(keys.b64u_decode(data["nonce_b64u"]), keys.b64u_decode(data["sig_b64u"]))
    )


def _log_keys(leaf: Path) -> list[tlog.LogKey] | None:
    path = leaf / "log-keys.json"
    if not path.exists():
        return None
    return [
        tlog.LogKey(
            origin=entry["origin"],
            name=entry["name"],
            ed25519_pub=keys.b64u_decode(entry["ed25519_pub_b64u"]),
            mldsa_pub=keys.b64u_decode(entry["mldsa_pub_b64u"]),
        )
        for entry in _load_json(path)
    ]


def _anchor_policy(leaf: Path) -> anchor.AnchorPolicy | None:
    path = leaf / "anchor-policy.json"
    if not path.exists():
        return None
    data = _load_json(path)
    pinned_headers = {
        header_hash: anchor.PinnedHeader(
            header_hash=header["header_hash"],
            merkle_root=header["merkle_root"],
            time=header["time"],
        )
        for header_hash, header in data["pinned_headers"].items()
    }
    return anchor.AnchorPolicy(pinned_headers=pinned_headers, crqc_horizon=data["crqc_horizon"])


def _transparency_evidence(leaf: Path) -> dict[str, Any] | None:
    path = leaf / "transparency.json"
    if not path.exists():
        return None
    return _load_json(path)  # type: ignore[no-any-return]


def _revocation_evidence(leaf: Path) -> dict[str, Any] | None:
    path = leaf / "revocation-evidence.json"
    if not path.exists():
        return None
    return _load_json(path)  # type: ignore[no-any-return]


def _transfer_view(leaf: Path) -> list[dict[str, Any]] | None:
    path = leaf / "transfer-view.json"
    if not path.exists():
        return None
    return _load_json(path)  # type: ignore[no-any-return]


def _witness_policy(leaf: Path) -> dict[str, Any] | None:
    """Group 39 only: the TRUSTED `attest-witness-policy-v1` document.

    Handed to `verify()` as the DOCUMENT, not as a parsed object — the corpus
    exercises each implementation's own policy parser, which is half of what
    `witness-policy.json` is for.
    """
    path = leaf / "witness-policy.json"
    if not path.exists():
        return None
    return _load_json(path)  # type: ignore[no-any-return]


def _sole_key_manifest(leaf: Path) -> dict[str, Any]:
    """Group 36 only: `audit_chain` takes ONE trusted `key_manifest`, not a
    full `TrustStore` — every group 36 leaf's `manifests.json` trusts exactly
    one issuer, so its sole `"manifests"` value is that manifest."""
    data = _load_json(leaf / "manifests.json")
    return next(iter(data["manifests"].values()))


def _verify_result_to_json(result: verify.VerificationResult) -> dict[str, Any]:
    return {
        "signature": result.signature,
        "schema": result.schema,
        "trust": result.trust,
        "revocation": result.revocation,
        "binding": result.binding,
        "transparency": result.transparency,
        "corroboration": result.corroboration,
        "manifest_freshness": result.manifest_freshness,
        "ok": result.ok,
        "errors": list(result.errors),
        "warnings": list(result.warnings),
    }


def _quorum_input(leaf: Path) -> dict[str, Any] | None:
    """Group 40 only: the activation-quorum call's own inputs.

    `expected_origin`/`conflict_domain` are TRUSTED call configuration;
    `epoch_id`/`checkpoint`/`anchor_evidence` are untrusted. The two trusted
    POLICIES live in their own files beside this one.
    """
    path = leaf / "witness-quorum.json"
    if not path.exists():
        return None
    return _load_json(path)  # type: ignore[no-any-return]


def _quorum_result_to_json(result: witness.ActivationWitnessQuorumResult) -> dict[str, Any]:
    return {
        "valid": result.valid,
        "witness_time": result.witness_time,
        "counting_control_groups": list(result.counting_control_groups),
    }


def _chain_result_to_json(result: transfer.ChainAuditResult) -> dict[str, Any]:
    return {
        "valid": result.valid,
        "link_status": list(result.link_status),
        "errors": list(result.errors),
        "warnings": list(result.warnings),
    }


def _run_leaf(leaf: Path) -> dict[str, Any]:
    """Route a leaf to `transfer.audit_chain` (group 36, `chain.json`
    present), `witness.evaluate_activation_witness_quorum` (group 40,
    `witness-quorum.json` present), or `verify.verify` (every other leaf),
    mirroring `tests/test_vectors.py`'s `test_chain_audit_vectors` /
    `test_witness_quorum_vectors` / `test_vector_matches_spec_intended_result`
    routing exactly."""
    quorum = _quorum_input(leaf)
    if quorum is not None:
        policy_document = _witness_policy(leaf)
        anchor_policy = _anchor_policy(leaf)
        assert policy_document is not None
        assert anchor_policy is not None
        # Parsed here, not handed over as a document: this entry point takes
        # trusted, already-parsed configuration, unlike `verify()`.
        quorum_result = witness.evaluate_activation_witness_quorum(
            quorum["checkpoint"],
            witness_policy=witness.parse_policy(policy_document),
            epoch_id=quorum["epoch_id"],
            expected_origin=quorum["expected_origin"],
            anchor_evidence=quorum["anchor_evidence"],
            anchor_policy=anchor_policy,
            conflict_domain=quorum["conflict_domain"],
        )
        return _quorum_result_to_json(quorum_result)

    chain_path = leaf / "chain.json"
    if chain_path.exists():
        chain = _load_json(chain_path)
        log_keys = _log_keys(leaf)
        anchor_policy = _anchor_policy(leaf)
        assert log_keys is not None
        assert anchor_policy is not None
        chain_result = transfer.audit_chain(
            chain["payloads"],
            chain["transfer_view"],
            chain["revocation_view"],
            _sole_key_manifest(leaf),
            log_keys,
            anchor_policy,
        )
        return _chain_result_to_json(chain_result)

    verify_result = verify.verify(
        _envelope_bytes(leaf),
        _trust_store(leaf),
        revocation_view=_revocation_view(leaf),
        disclosure=_disclosure(leaf),
        transparency=_transparency_evidence(leaf),
        log_keys=_log_keys(leaf),
        anchor_policy=_anchor_policy(leaf),
        revocation_evidence=_revocation_evidence(leaf),
        transfer_view=_transfer_view(leaf),
        witness_policy=_witness_policy(leaf),
    )
    return _verify_result_to_json(verify_result)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: conformance_adapter_py.py LEAF_DIR", file=sys.stderr)
        return 2
    output = _run_leaf(Path(args[0]))
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
