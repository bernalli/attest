"""Generate cross-core parity cases for witness corroboration (v0.2 §10.1).

Mirrored unit tests prove only that each core does what its author believed.
Parity is a different claim — the SAME checkpoint, cosignature and policy must
produce the SAME verdict in both cores — and it is only provable by feeding one
artifact to both. Every divergence found in this phase came from here, not from
the unit tests.

Writes a JSON document consumed by `tools/witness_parity_py.py` and
`verifiers/ts/tools/witness-parity.mjs`. Not part of the shipped package.
"""

from __future__ import annotations

import base64
import json
import struct
import sys
from typing import Any

from attest import keys, pq, tlog, witness

ORIGIN = "log.example"
WITNESS_NAME = "witness.example/w1"
TIMESTAMP = 1700000000


def _policy(pub_b64u: str, **pin_overrides: Any) -> dict[str, Any]:
    pin: dict[str, Any] = {
        "operator_id": "witness.example",
        "control_group": "witness.example",
        "name": WITNESS_NAME,
        "ed25519_pub_b64u": pub_b64u,
        "mldsa_65_pub_b64u": None,
        "roles": ["corroboration"],
        "not_before": "2020-01-01T00:00:00Z",
        "not_after": None,
        "affiliated_domains": ["witness.example"],
    }
    pin.update(pin_overrides)
    return {
        "schema": "attest-witness-policy-v1",
        "epochs": [
            {
                "epoch_id": "bootstrap-1",
                "not_before": "2020-01-01T00:00:00Z",
                "not_after": None,
                "log_origins": [ORIGIN],
                "threshold": {"n": 1, "m": 1},
                "witnesses": [pin],
            }
        ],
    }


def main() -> None:
    hk = pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())
    text = tlog.sign_checkpoint(ORIGIN, 3, bytes(32), hk, ORIGIN)
    checkpoint = tlog.parse_checkpoint(text)
    note = checkpoint.note_bytes

    wk = keys.generate()
    stranger = keys.generate()
    pub = keys.b64u(wk.pub)
    key_id = witness.cosignature_key_id(WITNESS_NAME, wk.pub)

    def blob(signer: Any, *, declared: int = TIMESTAMP, signed: int = TIMESTAMP) -> bytes:
        kid = witness.cosignature_key_id(WITNESS_NAME, signer.pub)
        sig = keys.sign(witness.cosignature_message(note, signed), signer)
        return kid + struct.pack(">Q", declared) + sig

    corrupted = bytearray(blob(wk))
    corrupted[-1] ^= 0xFF

    cases: list[dict[str, Any]] = [
        {"id": "valid", "sigs": [[WITNESS_NAME, blob(wk)]], "policy": _policy(pub)},
        {"id": "unpinned-key", "sigs": [[WITNESS_NAME, blob(stranger)]], "policy": _policy(pub)},
        {"id": "corrupted-sig", "sigs": [[WITNESS_NAME, bytes(corrupted)]], "policy": _policy(pub)},
        {
            "id": "timestamp-mismatch",
            "sigs": [[WITNESS_NAME, blob(wk, declared=TIMESTAMP + 1)]],
            "policy": _policy(pub),
        },
        {
            "id": "checkpoint-domain-sig",
            "sigs": [[WITNESS_NAME, key_id + struct.pack(">Q", TIMESTAMP) + keys.sign(note, wk)]],
            "policy": _policy(pub),
        },
        {"id": "short-blob", "sigs": [[WITNESS_NAME, blob(wk)[:-8]]], "policy": _policy(pub)},
        {"id": "long-blob", "sigs": [[WITNESS_NAME, blob(wk) + b"\x00"]], "policy": _policy(pub)},
        {"id": "empty-blob", "sigs": [[WITNESS_NAME, b""]], "policy": _policy(pub)},
        {"id": "no-signatures", "sigs": [], "policy": _policy(pub)},
        {"id": "unknown-name", "sigs": [["other/x", blob(wk)]], "policy": _policy(pub)},
        {
            "id": "wrong-role",
            "sigs": [[WITNESS_NAME, blob(wk)]],
            "policy": _policy(
                pub,
                roles=["sunset-activation"],
                mldsa_65_pub_b64u=keys.b64u(bytes(pq.ML_DSA_65_PK_LEN)),
            ),
        },
        {
            "id": "epoch-unresolvable",
            "sigs": [[WITNESS_NAME, blob(wk)]],
            "policy": _policy(pub),
            "epoch_id": "no-such-epoch",
        },
        {
            "id": "pin-expired",
            "sigs": [[WITNESS_NAME, blob(wk)]],
            "policy": _policy(pub, not_after="2021-01-01T00:00:00Z"),
        },
        {
            "id": "compromise-after-observation",
            "sigs": [[WITNESS_NAME, blob(wk)]],
            "policy": _policy(pub, compromised_after="2024-01-01T00:00:00Z"),
        },
        {
            "id": "compromise-before-observation",
            "sigs": [[WITNESS_NAME, blob(wk)]],
            "policy": _policy(pub, compromised_after="2021-01-01T00:00:00Z"),
        },
        {
            "id": "compromise-onset-unknown",
            "sigs": [[WITNESS_NAME, blob(wk)]],
            "policy": _policy(pub, compromised_after=None),
        },
        {
            "id": "boundary-exactly-at-cutoff",
            "sigs": [[WITNESS_NAME, blob(wk)]],
            "policy": _policy(pub, compromised_after="2023-11-14T22:13:20Z"),
        },
        {
            "id": "empty-policy",
            "sigs": [[WITNESS_NAME, blob(wk)]],
            "policy": {"schema": "attest-witness-policy-v1", "epochs": []},
        },
        {
            "id": "timestamp-zero",
            "sigs": [[WITNESS_NAME, blob(wk, declared=0, signed=0)]],
            "policy": _policy(pub),
        },
    ]

    out = {
        "checkpoint_text": text,
        "cases": [
            {
                "id": c["id"],
                "epoch_id": c.get("epoch_id", "bootstrap-1"),
                "policy": c["policy"],
                "sigs": [[name, base64.b64encode(bytes(b)).decode()] for name, b in c["sigs"]],
            }
            for c in cases
        ],
    }
    json.dump(out, sys.stdout, indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
