"""Run the cross-core witness parity bench against the PYTHON core.

Reads the JSON document produced by `tools/witness_parity_cases.py` on stdin
and writes one verdict per case to stdout, sorted by case id. Its twin,
`verifiers/ts/tools/witness-parity.mjs`, writes the same shape from the
TypeScript core; `diff` between the two outputs IS the parity check.

Usage:
    uv run --frozen python tools/witness_parity_cases.py > /tmp/bench.json
    uv run --frozen python tools/witness_parity_py.py < /tmp/bench.json > /tmp/py.json
    npm run build --prefix verifiers/ts
    node verifiers/ts/tools/witness-parity.mjs < /tmp/bench.json > /tmp/ts.json
    diff /tmp/py.json /tmp/ts.json

Not part of the shipped package. An exception is reported as a verdict rather
than propagated, because WHETHER a core raises is itself part of what has to
match: one core throwing where the other returns a value is a divergence, not
a crash to be silenced.
"""

from __future__ import annotations

import base64
import json
import sys
from typing import Any

from attest import anchor, tlog, witness


def _corroboration(case: dict[str, Any], checkpoint_text: str) -> Any:
    checkpoint = tlog.parse_checkpoint(checkpoint_text)
    signatures = [(name, base64.b64decode(blob_b64)) for name, blob_b64 in case["sigs"]]
    policy = witness.load_policy(witness.policy_bytes(case["policy"]))
    verdict = witness.evaluate_corroboration(
        checkpoint=checkpoint,
        signatures=signatures,
        policy=policy,
        epoch_id=case["epoch_id"],
    )
    return {"witnessed": verdict.witnessed, "warnings": list(verdict.warnings)}


def _anchor_policy(raw: dict[str, Any]) -> anchor.AnchorPolicy:
    return anchor.AnchorPolicy(
        pinned_headers={
            key: anchor.PinnedHeader(
                header_hash=header["header_hash"],
                merkle_root=header["merkle_root"],
                time=header["time"],
            )
            for key, header in raw["pinned_headers"].items()
        },
        crqc_horizon=raw["crqc_horizon"],
    )


def _quorum(case: dict[str, Any]) -> Any:
    result = witness.evaluate_activation_witness_quorum(
        case["checkpoint_text"],
        witness_policy=witness.load_policy(base64.b64decode(case["policy_b64"])),
        epoch_id=case["epoch_id"],
        expected_origin=case["expected_origin"],
        anchor_evidence=case["anchor_evidence"],
        anchor_policy=_anchor_policy(case["anchor_policy"]),
        conflict_domain=case["conflict_domain"],
    )
    return {
        "valid": result.valid,
        "witness_time": result.witness_time,
        "counting_control_groups": list(result.counting_control_groups),
    }


def main() -> None:
    bench = json.load(sys.stdin)
    out: dict[str, Any] = {"corroboration": {}, "quorum": {}}

    for case in bench["cases"]:
        try:
            out["corroboration"][case["id"]] = _corroboration(case, bench["checkpoint_text"])
        except Exception as exc:  # the exception IS the verdict, not a crash
            out["corroboration"][case["id"]] = {"raised": type(exc).__name__}

    for case in bench["quorum_cases"]:
        try:
            out["quorum"][case["id"]] = _quorum(case)
        except Exception as exc:  # the exception IS the verdict, not a crash
            out["quorum"][case["id"]] = {"raised": type(exc).__name__}

    json.dump(out, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
