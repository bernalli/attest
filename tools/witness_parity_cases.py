"""Generate cross-core parity cases for witness corroboration and quorum.

Contract: v0.2 §10.1 (corroboration) and §11.4 (the standalone activation-grade
hybrid quorum).

Mirrored unit tests prove only that each core does what its author believed.
Parity is a different claim — the SAME checkpoint, cosignature and policy must
produce the SAME verdict in both cores — and it is only provable by feeding one
artifact to both. Every divergence found in this phase came from here, not from
the unit tests.

Writes a JSON document consumed by `tools/witness_parity_py.py` and
`verifiers/ts/tools/witness-parity.mjs`. Not part of the shipped package.

Two case families, because the two primitives take different artifacts:
`cases` feeds `evaluate_corroboration` a shared checkpoint plus loose signature
lines, while `quorum_cases` carries a whole checkpoint per case — the
cosignature lines live INSIDE the note there, and the `signed-note-v2` anchor
commits to the note with those lines in it, so no two cases can share one.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
from typing import Any

from attest import keys, pq, tlog, witness

ORIGIN = "log.example"
WITNESS_NAME = "witness.example/w1"
TIMESTAMP = 1700000000
HEADER_HASH = "3a" * 32


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


def _epoch_override(policy: dict[str, Any], **fields: Any) -> dict[str, Any]:
    """Return `policy` with its single epoch's fields overridden."""
    out = json.loads(json.dumps(policy))
    out["epochs"][0].update(fields)
    return out


# --- quorum cases (§11.4) --------------------------------------------------


class _QuorumWitness:
    """One activation witness: an identity, a control group, and both legs."""

    def __init__(self, label: str, group: str | None = None) -> None:
        self.operator = f"{label}.example"
        self.name = f"{self.operator}/w"
        self.group = group if group is not None else self.operator
        self.ed = keys.generate()
        self.mldsa = pq.generate()

    def pin(self, **overrides: Any) -> dict[str, Any]:
        pin: dict[str, Any] = {
            "operator_id": self.operator,
            "control_group": self.group,
            "name": self.name,
            "ed25519_pub_b64u": keys.b64u(self.ed.pub),
            "mldsa_65_pub_b64u": keys.b64u(self.mldsa.pub),
            "roles": ["sunset-activation"],
            "not_before": "2020-01-01T00:00:00Z",
            "not_after": None,
            "affiliated_domains": [self.operator],
        }
        pin.update(overrides)
        return pin


def _quorum_policy(pins: list[dict[str, Any]], n: int, m: int, **epoch: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "epoch_id": "bootstrap-1",
        "not_before": "2020-01-01T00:00:00Z",
        "not_after": None,
        "log_origins": [ORIGIN],
        "threshold": {"n": n, "m": m},
        "witnesses": pins,
    }
    fields.update(epoch)
    return {"schema": "attest-witness-policy-v1", "epochs": [fields]}


def _quorum_payload(note: bytes, timestamp: int) -> bytes:
    """Assembled by hand so a case can carry a timestamp the library helper
    would refuse to sign at all."""
    return b"cosignature/v1\n" + f"time {timestamp}\n".encode() + note


def _ed_leg(
    w: _QuorumWitness,
    note: bytes,
    timestamp: int,
    *,
    declared: int | None = None,
    signed_note: bytes | None = None,
) -> bytes:
    key_id = witness.cosignature_key_id(w.name, w.ed.pub)
    message = _quorum_payload(note if signed_note is None else signed_note, timestamp)
    return (
        key_id
        + struct.pack(">Q", timestamp if declared is None else declared)
        + keys.sign(message, w.ed)
    )


def _pq_leg(
    w: _QuorumWitness,
    note: bytes,
    timestamp: int,
    *,
    declared: int | None = None,
    sig_type: bytes | None = None,
) -> bytes:
    key_id = tlog.key_hash(
        w.name, witness.PQ_COSIGNATURE_SIG_TYPE if sig_type is None else sig_type, w.mldsa.pub
    )
    message = _quorum_payload(note, timestamp)
    return (
        key_id
        + struct.pack(">Q", timestamp if declared is None else declared)
        + pq.sign(message, w.mldsa)
    )


def _sig_line(name: str, blob: bytes) -> str:
    return f"— {name} {base64.b64encode(blob).decode('ascii')}\n"


def _quorum_pair(w: _QuorumWitness, note: bytes, timestamp: int, **kwargs: Any) -> str:
    return _sig_line(w.name, _ed_leg(w, note, timestamp, **kwargs)) + _sig_line(
        w.name, _pq_leg(w, note, timestamp, **kwargs)
    )


def _anchor_for(text: str, header_time: int, profile: str | None) -> dict[str, Any]:
    """A verifying OTS op-chain over this exact checkpoint, plus its trust store.

    The v2 accumulator seeds from the WHOLE signed note, cosignature lines
    included — which is why every case needs its own anchor, built after its
    lines are appended.
    """
    checkpoint = tlog.parse_checkpoint(text)
    seed_source = (
        checkpoint.signed_note_bytes if profile == "signed-note-v2" else checkpoint.note_bytes
    )
    sibling = bytes.fromhex("ab" * 32)
    prefix = bytes.fromhex("cd" * 16)
    acc = hashlib.sha256(seed_source).digest()
    acc = hashlib.sha256(acc + sibling).digest()
    acc = hashlib.sha256(prefix + acc).digest()
    root = acc.hex()
    evidence: dict[str, Any] = {
        "checkpoint": text,
        "proofs": [
            {
                "kind": "ots",
                "ops": [
                    ["append", sibling.hex()],
                    ["sha256"],
                    ["prepend", prefix.hex()],
                    ["sha256"],
                ],
                "header_merkle_root": root,
                "header_time": header_time,
                "header_hash": HEADER_HASH,
            }
        ],
    }
    if profile is not None:
        evidence["anchor_profile"] = profile
    return {
        "evidence": evidence,
        "policy": {
            "pinned_headers": {
                HEADER_HASH: {
                    "header_hash": HEADER_HASH,
                    "merkle_root": root,
                    "time": header_time,
                }
            },
            "crqc_horizon": None,
        },
    }


def _quorum_case(
    case_id: str,
    text: str,
    policy: dict[str, Any],
    *,
    anchor_time: int,
    anchor_profile: str | None = "signed-note-v2",
    epoch_id: str = "bootstrap-1",
    expected_origin: str = ORIGIN,
    conflict_domain: str = "issuer.example",
    anchor_text: str | None = None,
) -> dict[str, Any]:
    anchor = _anchor_for(text if anchor_text is None else anchor_text, anchor_time, anchor_profile)
    return {
        "id": case_id,
        "checkpoint_text": text,
        # The policy travels as canonical JCS BYTES, not as a parsed object:
        # loading from bytes is what makes the two cores agree on numbers
        # (JSON `1.0` is a float literal in one and indistinguishable from `1`
        # in the other once it is an in-memory value).
        "policy_b64": base64.b64encode(witness.policy_bytes(policy)).decode("ascii"),
        "epoch_id": epoch_id,
        "expected_origin": expected_origin,
        "conflict_domain": conflict_domain,
        "anchor_evidence": anchor["evidence"],
        "anchor_policy": anchor["policy"],
    }


def _quorum_cases(hk: pq.HybridSigningKeys) -> list[dict[str, Any]]:
    base = tlog.sign_checkpoint(ORIGIN, 4, bytes(32), hk, ORIGIN)
    note = tlog.parse_checkpoint(base).note_bytes
    other_note = tlog.parse_checkpoint(
        tlog.sign_checkpoint(ORIGIN, 9, bytes(32), hk, ORIGIN)
    ).note_bytes

    w1 = _QuorumWitness("alpha")
    w2 = _QuorumWitness("bravo")
    w3 = _QuorumWitness("charlie")
    w1_rotated = _QuorumWitness("alpha-next", group=w1.group)
    w1_rotated.operator = w1.operator
    w1_rotated.name = f"{w1.operator}/w-next"

    one = _quorum_policy([w1.pin()], 1, 1)
    two = _quorum_policy([w1.pin(), w2.pin()], 2, 2)

    solo = base + _quorum_pair(w1, note, TIMESTAMP)
    cases: list[dict[str, Any]] = [
        _quorum_case("valid-one-of-one", solo, one, anchor_time=TIMESTAMP),
        _quorum_case(
            "valid-two-of-three-conservative-time",
            base + _quorum_pair(w1, note, TIMESTAMP + 300) + _quorum_pair(w2, note, TIMESTAMP),
            _quorum_policy([w1.pin(), w2.pin(), w3.pin()], 3, 2),
            anchor_time=TIMESTAMP + 300,
        ),
        _quorum_case(
            "missing-pq-leg",
            base + _sig_line(w1.name, _ed_leg(w1, note, TIMESTAMP)),
            one,
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "missing-ed-leg",
            base + _sig_line(w1.name, _pq_leg(w1, note, TIMESTAMP)),
            one,
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "legs-with-different-timestamps",
            base
            + _sig_line(w1.name, _ed_leg(w1, note, TIMESTAMP))
            + _sig_line(w1.name, _pq_leg(w1, note, TIMESTAMP + 1)),
            one,
            anchor_time=TIMESTAMP + 1,
        ),
        _quorum_case(
            "transplanted-ed-leg",
            base
            + _sig_line(w1.name, _ed_leg(w1, note, TIMESTAMP, signed_note=other_note))
            + _sig_line(w1.name, _pq_leg(w1, note, TIMESTAMP)),
            one,
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "c2sp-type-06-as-pq-leg",
            base
            + _sig_line(w1.name, _ed_leg(w1, note, TIMESTAMP))
            + _sig_line(w1.name, _pq_leg(w1, note, TIMESTAMP, sig_type=b"\x06")),
            one,
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "checkpoint-sig-type-as-pq-leg",
            base
            + _sig_line(w1.name, _ed_leg(w1, note, TIMESTAMP))
            + _sig_line(
                w1.name, _pq_leg(w1, note, TIMESTAMP, sig_type=b"\xff" + b"attest-ml-dsa-65")
            ),
            one,
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "ambiguous-duplicate-pair",
            base + _quorum_pair(w1, note, TIMESTAMP) + _quorum_pair(w1, note, TIMESTAMP + 1),
            one,
            anchor_time=TIMESTAMP + 1,
        ),
        _quorum_case(
            "two-pairs-one-control-group",
            base + _quorum_pair(w1, note, TIMESTAMP) + _quorum_pair(w1_rotated, note, TIMESTAMP),
            _quorum_policy([w1.pin(), w1_rotated.pin(), w2.pin()], 2, 2),
            anchor_time=TIMESTAMP,
        ),
        # The three cases below exist because the mutation campaign found the
        # bench blind without them: each one is the only case that separates a
        # HARD failure from a silently-dropped vote. Without them, "ambiguity
        # fails" and "one vote per control group" could both be replaced by
        # "skip that pin" and no verdict would move.
        _quorum_case(
            "ambiguous-group-does-not-merely-drop-out",
            base
            + _quorum_pair(w1, note, TIMESTAMP)
            + _quorum_pair(w1, note, TIMESTAMP + 1)
            + _quorum_pair(w2, note, TIMESTAMP),
            _quorum_policy([w1.pin(), w2.pin()], 2, 1),
            anchor_time=TIMESTAMP + 1,
        ),
        _quorum_case(
            "duplicate-group-does-not-merely-drop-out",
            base
            + _quorum_pair(w1, note, TIMESTAMP)
            + _quorum_pair(w1_rotated, note, TIMESTAMP)
            + _quorum_pair(w2, note, TIMESTAMP),
            _quorum_policy([w1.pin(), w1_rotated.pin(), w2.pin()], 2, 2),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "compromise-cutoff-at-t-with-a-later-leg",
            base + _quorum_pair(w1, note, TIMESTAMP) + _quorum_pair(w2, note, TIMESTAMP + 300),
            _quorum_policy([w1.pin(), w2.pin(compromised_after="2023-11-14T22:13:20Z")], 2, 2),
            anchor_time=TIMESTAMP + 300,
        ),
        _quorum_case(
            "excluded-vote-does-not-set-t",
            base + _quorum_pair(w1, note, TIMESTAMP) + _quorum_pair(w2, note, TIMESTAMP + 400),
            _quorum_policy(
                [
                    w1.pin(compromised_after="2023-11-14T22:13:19Z"),
                    w2.pin(compromised_after="2023-11-14T22:16:40Z"),
                ],
                2,
                1,
            ),
            anchor_time=TIMESTAMP + 400,
        ),
        _quorum_case(
            "committee-of-ten",
            solo,
            _quorum_policy(
                [w1.pin()] + [_QuorumWitness(f"filler{i}").pin() for i in range(9)], 9, 1
            ),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "committee-of-nine",
            solo,
            _quorum_policy(
                [w1.pin()] + [_QuorumWitness(f"filler{i}").pin() for i in range(8)], 9, 1
            ),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "threshold-n-mismatch", solo, _quorum_policy([w1.pin()], 2, 2), anchor_time=TIMESTAMP
        ),
        _quorum_case(
            "direct-domain-conflict",
            base + _quorum_pair(w1, note, TIMESTAMP) + _quorum_pair(w2, note, TIMESTAMP),
            _quorum_policy(
                [w1.pin(affiliated_domains=sorted([w1.operator, "issuer.example"])), w2.pin()],
                2,
                2,
            ),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "transitive-control-group-conflict",
            base + _quorum_pair(w1, note, TIMESTAMP) + _quorum_pair(w2, note, TIMESTAMP),
            _quorum_policy(
                [
                    w1.pin(),
                    w1_rotated.pin(affiliated_domains=sorted([w1.operator, "issuer.example"])),
                    w2.pin(),
                ],
                2,
                2,
            ),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "another-conflict-domain-leaves-the-committee-whole",
            base + _quorum_pair(w1, note, TIMESTAMP) + _quorum_pair(w2, note, TIMESTAMP),
            _quorum_policy(
                [w1.pin(affiliated_domains=sorted([w1.operator, "issuer.example"])), w2.pin()],
                2,
                2,
            ),
            anchor_time=TIMESTAMP,
            conflict_domain="other.example",
        ),
        _quorum_case(
            "skew-exactly-600",
            base + _quorum_pair(w1, note, TIMESTAMP) + _quorum_pair(w2, note, TIMESTAMP + 600),
            two,
            anchor_time=TIMESTAMP + 600,
        ),
        _quorum_case(
            "skew-601",
            base + _quorum_pair(w1, note, TIMESTAMP) + _quorum_pair(w2, note, TIMESTAMP + 601),
            two,
            anchor_time=TIMESTAMP + 601,
        ),
        _quorum_case("anchor-at-max-t", solo, one, anchor_time=TIMESTAMP),
        _quorum_case("anchor-before-max-t", solo, one, anchor_time=TIMESTAMP - 1),
        _quorum_case("anchor-at-delay-bound", solo, one, anchor_time=TIMESTAMP + 86400),
        _quorum_case("anchor-past-delay-bound", solo, one, anchor_time=TIMESTAMP + 86401),
        _quorum_case(
            "note-only-anchor", solo, one, anchor_time=TIMESTAMP, anchor_profile="note-v1"
        ),
        _quorum_case(
            "absent-anchor-profile", solo, one, anchor_time=TIMESTAMP, anchor_profile=None
        ),
        _quorum_case(
            "epoch-expired-before-t",
            solo,
            _quorum_policy([w1.pin()], 1, 1, not_after="2021-01-01T00:00:00Z"),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "epoch-ends-exactly-at-t",
            solo,
            _quorum_policy([w1.pin()], 1, 1, not_after="2023-11-14T22:13:20Z"),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "pin-expired-before-t",
            solo,
            _quorum_policy([w1.pin(not_after="2021-01-01T00:00:00Z")], 1, 1),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "pin-window-ends-exactly-at-t",
            solo,
            _quorum_policy([w1.pin(not_after="2023-11-14T22:13:20Z")], 1, 1),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "compromise-cutoff-exactly-at-t",
            solo,
            _quorum_policy([w1.pin(compromised_after="2023-11-14T22:13:20Z")], 1, 1),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "compromise-cutoff-one-second-before-t",
            solo,
            _quorum_policy([w1.pin(compromised_after="2023-11-14T22:13:19Z")], 1, 1),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "compromise-onset-unknown",
            solo,
            _quorum_policy([w1.pin(compromised_after=None)], 1, 1),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "epoch-scoped-to-another-origin",
            solo,
            _quorum_policy([w1.pin()], 1, 1, log_origins=["other.example"]),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "epoch-with-no-origins",
            solo,
            _quorum_policy([w1.pin()], 1, 1, log_origins=[]),
            anchor_time=TIMESTAMP,
        ),
        _quorum_case("unresolvable-epoch", solo, one, anchor_time=TIMESTAMP, epoch_id="no-such"),
        _quorum_case(
            "unpinned-lines-ignored",
            base + _quorum_pair(w2, note, TIMESTAMP) + _quorum_pair(w1, note, TIMESTAMP),
            one,
            anchor_time=TIMESTAMP,
        ),
        # The timestamp edges that already produced a real divergence for
        # corroboration: Python's `datetime` stops at year 9999 while
        # JavaScript's `Date` does not, and `Number(2n**64n - 1n)` rounds.
        # The anchor time stays ordinary in these three: a pinned header at
        # year 9999 or at the epoch is refused by the ANCHOR policy validator,
        # and the case would then prove nothing about the cosignature
        # timestamp it exists to probe.
        _quorum_case(
            "timestamp-past-year-9999",
            base + _quorum_pair(w1, note, 253402300800),
            one,
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "timestamp-uint64-max",
            base
            + _sig_line(w1.name, _ed_leg(w1, note, 2**64 - 1))
            + _sig_line(w1.name, _pq_leg(w1, note, 2**64 - 1)),
            one,
            anchor_time=TIMESTAMP,
        ),
        _quorum_case(
            "timestamp-at-year-9999-boundary",
            base + _quorum_pair(w1, note, 253402300799),
            _quorum_policy([w1.pin(not_after=None)], 1, 1),
            anchor_time=253402300799,
        ),
        _quorum_case(
            "timestamp-zero",
            base + _quorum_pair(w1, note, 0),
            one,
            anchor_time=TIMESTAMP,
        ),
    ]

    # A malformed checkpoint must degrade, not raise, in either core — and the
    # anchor still has to be built from a well-formed note, or the case would
    # only be exercising the anchor parser.
    cases.append(
        {
            **_quorum_case("malformed-checkpoint", solo, one, anchor_time=TIMESTAMP),
            "id": "malformed-checkpoint",
            "checkpoint_text": "not a checkpoint",
        }
    )
    return cases


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
        # Built by hand rather than through `cosignature_message`, so a case
        # can carry a timestamp the helper itself would refuse to sign.
        message = b"cosignature/v1\n" + f"time {signed}\n".encode() + note
        return kid + struct.pack(">Q", declared) + keys.sign(message, signer)

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
            "id": "epoch-expired",
            "sigs": [[WITNESS_NAME, blob(wk)]],
            "policy": _epoch_override(_policy(pub), not_after="2021-01-01T00:00:00Z"),
        },
        {
            "id": "epoch-scoped-to-another-origin",
            "sigs": [[WITNESS_NAME, blob(wk)]],
            "policy": _epoch_override(_policy(pub), log_origins=["other.example"]),
        },
        {
            "id": "epoch-with-no-origins",
            "sigs": [[WITNESS_NAME, blob(wk)]],
            "policy": _epoch_override(_policy(pub), log_origins=[]),
        },
        {
            "id": "hostile-line-before-valid-one",
            "sigs": [
                [WITNESS_NAME, key_id + struct.pack(">Q", 2**64 - 1) + bytes(64)],
                [WITNESS_NAME, blob(wk)],
            ],
            "policy": _policy(pub),
        },
        {
            "id": "timestamp-past-year-9999",
            "sigs": [[WITNESS_NAME, blob(wk, declared=253402300800, signed=253402300800)]],
            "policy": _policy(pub),
        },
        {
            "id": "timestamp-uint64-max",
            "sigs": [[WITNESS_NAME, blob(wk, declared=2**64 - 1, signed=2**64 - 1)]],
            "policy": _policy(pub),
        },
        {
            "id": "timestamp-zero",
            "sigs": [[WITNESS_NAME, blob(wk, declared=0, signed=0)]],
            "policy": _policy(pub),
        },
    ]

    out = {
        "checkpoint_text": text,
        "quorum_cases": _quorum_cases(hk),
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
