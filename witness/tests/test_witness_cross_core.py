"""Do the lines this witness returns verify in the OTHER core?

Python accepting its own output proves that one implementation is
self-consistent. A witness cosigns for verifiers it will never meet, and half
of the ones this project ships are TypeScript — so the lines produced here are
fed to `verifiers/ts/tools/witness-parity.mjs`, the same bench the two cores
are held to, and both verdicts must agree.

This is the only test in the suite that shells out. It needs `node` and a
built `verifiers/ts/dist`, so it skips when they are absent rather than
failing on a machine that has not run `npm run build` — but it is never
skipped in the task's own gate, which runs the TypeScript build anyway.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from attest_witness.cosign import cosign
from witness_support import (
    BOOTSTRAP_EPOCH,
    WITNESS_NAME,
    FakeLog,
    anchor_for,
    log_keys,  # noqa: F401
    witness_keys,  # noqa: F401
    witness_pin,
    witness_policy_document,
)

from attest import pq, tlog

ORIGIN = "log.example"
TIMESTAMP = 1_700_000_000
REPO_ROOT = Path(__file__).resolve().parents[2]
TS_BENCH = REPO_ROOT / "verifiers" / "ts" / "tools" / "witness-parity.mjs"
TS_DIST = REPO_ROOT / "verifiers" / "ts" / "dist" / "index.js"
PY_BENCH = REPO_ROOT / "tools" / "witness_parity_py.py"


def _run(command: list[str], stdin: bytes) -> dict[str, object]:
    completed = subprocess.run(  # noqa: S603 -- fixed argv, repository-local scripts
        command,
        input=stdin,
        capture_output=True,
        check=True,
        cwd=REPO_ROOT,
        timeout=120,
    )
    result: dict[str, object] = json.loads(completed.stdout)
    return result


def test_the_lines_this_witness_produces_verify_in_both_cores(
    witness_keys: pq.HybridSigningKeys, log_keys: pq.HybridSigningKeys
) -> None:
    node = shutil.which("node")
    if node is None or not TS_DIST.exists():
        pytest.skip("needs node and a built verifiers/ts (npm run build --prefix verifiers/ts)")

    log = FakeLog(ORIGIN, log_keys)
    log.append(4)
    text = log.checkpoint_text()
    note = tlog.parse_checkpoint(text).note_bytes
    signature = cosign(note, name=WITNESS_NAME, signing_keys=witness_keys, timestamp=TIMESTAMP)
    cosigned = text + signature.lines

    corroboration_policy = witness_policy_document(
        [witness_pin(witness_keys)], log_origins=[ORIGIN]
    )
    quorum_policy = witness_policy_document(
        [witness_pin(witness_keys, roles=["corroboration", "sunset-activation"], with_pq=True)],
        log_origins=[ORIGIN],
    )
    anchor = anchor_for(cosigned, TIMESTAMP + 60)
    bench = {
        "checkpoint_text": cosigned,
        "cases": [
            {
                "id": "witness-service-output",
                "sigs": [
                    [name, base64.b64encode(blob).decode("ascii")]
                    for name, blob in tlog.note_signatures(cosigned)
                ],
                "policy": corroboration_policy,
                "epoch_id": BOOTSTRAP_EPOCH,
            }
        ],
        "quorum_cases": [
            {
                "id": "witness-service-hybrid-vote",
                "checkpoint_text": cosigned,
                "policy_b64": base64.b64encode(
                    json.dumps(quorum_policy, sort_keys=True, separators=(",", ":")).encode()
                ).decode("ascii"),
                "epoch_id": BOOTSTRAP_EPOCH,
                "expected_origin": ORIGIN,
                "conflict_domain": "issuer.example",
                "anchor_evidence": anchor["evidence"],
                "anchor_policy": {
                    "pinned_headers": {
                        key: {
                            "header_hash": header.header_hash,
                            "merkle_root": header.merkle_root,
                            "time": header.time,
                        }
                        for key, header in anchor["policy"].pinned_headers.items()
                    },
                    "crqc_horizon": None,
                },
            }
        ],
    }
    document = json.dumps(bench).encode("utf-8")

    python_verdicts = _run([".venv/bin/python", str(PY_BENCH)], document)
    typescript_verdicts = _run([node, str(TS_BENCH)], document)

    assert python_verdicts == typescript_verdicts, "the two cores disagree about our lines"
    corroboration = python_verdicts["corroboration"]
    quorum = python_verdicts["quorum"]
    assert isinstance(corroboration, dict) and isinstance(quorum, dict)
    assert corroboration["witness-service-output"]["witnessed"] is True  # type: ignore[index]
    assert quorum["witness-service-hybrid-vote"]["valid"] is True  # type: ignore[index]
