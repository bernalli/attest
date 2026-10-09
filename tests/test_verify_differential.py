"""The receipt-verification differential, run under the suite so it is not optional.

`tools/verify_differential.py` feeds the same generated receipts to the Python
and the TypeScript verifier and fails on any verdict they do not share, on any
throw, and on a v0.1 receipt either side accepts under a hybrid key. The four
verdict splits fixed in 0.9.8 were all inside its families; it reports more
than two hundred findings on the tree before those fixes, at this same budget.

The budget here is a fixed seed and a few seconds of CI; long runs with other
seeds are a command away (`python3 tools/verify_differential.py --count 20000
--seed N`). It needs node and a built `verifiers/ts/dist`. Their absence is a
skip on a developer's machine and a failure in the job that promised them,
exactly as for the container differential.

The other tests pin the instrument itself, without node: that its Ed25519
cases really are the inputs a cofactored check accepts and the reference
rejects, that the hybrid-kid property case is refused, and that a seed always
produces the same bytes.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

import pytest

from attest import canon, keys, trust_material, verify
from tools import verify_differential as differential
from tools.ci_required import ci_prerequisites_required

CI_SEED = 20261009
CI_COUNT = 1500


def test_the_two_verifiers_agree_on_generated_receipts() -> None:
    missing = differential._prerequisite_missing()
    if missing is not None:
        message = f"receipt-verification differential not measured: {missing}"
        if ci_prerequisites_required():
            pytest.fail(message)
        pytest.skip(message)
    assert differential.run(count=CI_COUNT, seed=CI_SEED, quiet=True) == 0


def _cofactored_accepts(msg: bytes, sig: bytes, pub: bytes) -> bool:
    """[8](R + kA - SB) == identity: the equation the 0.9.7 TypeScript side used."""
    point_r = _decode(sig[:32])
    point_a = _decode(pub)
    s = int.from_bytes(sig[32:], "little")
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % differential._L
    neg_sb = _negate(differential._mul(s, differential._BASE))
    total = differential._add(
        differential._add(point_r, differential._mul(k, point_a)),
        neg_sb,
    )
    return differential._mul(8, total) == differential._IDENTITY


def _decode(encoding: bytes) -> differential.Point:
    value = int.from_bytes(encoding, "little")
    y = value & ((1 << 255) - 1)
    x = differential._recover_x(y, value >> 255)
    assert x is not None
    return (x, y)


def _negate(point: differential.Point) -> differential.Point:
    return ((-point[0]) % differential._P, point[1])


@pytest.mark.parametrize(
    "craft",
    [
        lambda m: (differential.ED.craft(m, r_extra=differential._T8), differential.ED.pub),
        lambda m: (differential.ED.craft_small_order_r(m), differential.ED.pub),
        lambda m: (
            differential.MIXED.craft(m, a_enc=differential.MIXED_PUB),
            differential.MIXED_PUB,
        ),
    ],
    ids=["mixed-order R", "small-order R", "mixed-order A"],
)
def test_torsion_cases_split_a_cofactored_check_from_the_reference(
    craft: Callable[[bytes], tuple[bytes, bytes]],
) -> None:
    msg = b"attest differential torsion case"
    sig, pub = craft(msg)
    assert _cofactored_accepts(msg, sig, pub)
    assert keys.verify_strict(msg, sig, pub) is False


def test_honest_crafted_signature_verifies() -> None:
    msg = b"attest differential honest case"
    assert keys.verify_strict(msg, differential.ED.craft(msg), differential.ED.pub)


def test_v01_receipt_under_a_hybrid_kid_is_refused() -> None:
    bases = differential.build_bases()
    for case in differential._property_cases(bases):
        store_doc = bases.manifests[case.store]
        result = verify.verify(
            case.envelope,
            trust_material.TrustStore.from_bytes(differential.store_bytes(store_doc)),
        )
        assert result.ok is False
        assert result.signature == "invalid"


def test_the_bases_verify() -> None:
    bases = differential.build_bases()
    for envelope, store in ((bases.env01, "ed"), (bases.env02, "hybrid"), (bases.env02, "mixed")):
        verdict = differential.python_verdict(
            differential.dumps(envelope), differential.store_bytes(bases.manifests[store])
        )
        assert verdict["verdict"] == "ok", verdict


def test_a_seed_generates_the_same_bytes() -> None:
    def digest() -> str:
        differential._DYNAMIC_STORES.clear()
        bases = differential.build_bases()
        cases = differential.generate(300, 7, bases)
        h = hashlib.sha256()
        for case in cases:
            h.update(json.dumps([case.id, case.family, case.label, case.store]).encode())
            h.update(case.envelope)
        for name, doc in sorted(differential._DYNAMIC_STORES.items()):
            h.update(name.encode() + canon.canonical_bytes(doc))
        return h.hexdigest()

    assert digest() == digest()


def test_comparison_keeps_verdicts_and_parity_messages_exact() -> None:
    def verdict(errors: list[str], *, ok: bool = False, schema: str = "not_checked") -> object:
        result = {"ok": ok, "signature": "invalid", "schema": schema}
        return differential.comparable(
            {
                "verdict": "ok" if ok else "invalid",
                "result": {**result, "errors": errors, "warnings": []},
            }
        )

    sig_failed = ["signature verification failed"]
    assert verdict(sig_failed) != verdict([], ok=True)
    assert verdict(sig_failed) != verdict(["malformed key material: x"])
    # The quoting of a non-printable value is the one rendering difference allowed.
    assert verdict(["no key 'k\\x00' in issuer manifest"]) == verdict(
        ["no key 'k\x00' in issuer manifest"]
    )
    assert verdict(["no key 'k' in issuer manifest"]) != verdict(["no key 'j' in issuer manifest"])
    # Parser diagnostics compare by class; a parity message never joins that class.
    assert verdict(["invalid JSON: Extra data"]) == verdict(["invalid JSON: trailing content"])
    assert verdict(["duplicate object key: 'a'"]) != verdict(["invalid JSON: x"])
    crash = {"verdict": "crash", "error": "TypeError: x"}
    assert differential.comparable(crash) == crash
