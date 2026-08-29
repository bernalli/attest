"""RFC 6962 Merkle tree primitives + closed transparency-log entry schemas.

Known-answer tests (KATs) for the empty/1-leaf/2-leaf/3-leaf/7-leaf roots are
hand-pinned `bytes.fromhex` literals, derived by hand from the RFC 6962
§2.1 construction (shown in the comments below) — never computed through
`attest.tlog` itself. Consistency proofs are checked via round-trip properties
against the module's own builder/verify pair, which is the only practical way
to exercise every size pair; the KATs pin the hashing scheme itself.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any, cast

import pytest

from attest import authority, canon, grant, keys, pq, tlog

LEAVES = [bytes([i]) for i in range(7)]  # b"\x00", b"\x01", ... b"\x06"


# --------------------------------------------------------------------------
# Known-answer tests, hand-computed from RFC 6962 §2.1:
#   leaf_hash(d)    = SHA-256(0x00 || d)
#   node_hash(l, r) = SHA-256(0x01 || l || r)
#   MTH({})         = SHA-256("")                              (no prefix byte)
#   MTH({d0})       = leaf_hash(d0)
#   MTH(D[n])       = node_hash(MTH(D[0:k]), MTH(D[k:n])), k = largest pow2 < n
# --------------------------------------------------------------------------


def test_empty_tree_root_is_sha256_of_empty_string() -> None:
    # MTH({}) = SHA-256() per RFC 6962 §2.1, no leaf/node prefix byte at all.
    expected = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert tlog.build_tree([]) == expected


def test_one_leaf_tree_root_is_leaf_hash() -> None:
    # MTH({d0}) = leaf_hash(d0) = SHA-256(0x00 || d0), d0 = b"\x00".
    # Hand construction: sha256(b"\x00\x00").
    expected = bytes.fromhex("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7")
    assert tlog.build_tree(LEAVES[:1]) == expected


def test_two_leaf_tree_root() -> None:
    # k = largest pow2 < 2 = 1. MTH([d0,d1]) = node_hash(leaf_hash(d0), leaf_hash(d1)).
    # Hand construction: h0 = sha256(0x00||d0), h1 = sha256(0x00||d1),
    #                     root = sha256(0x01 || h0 || h1).
    expected = bytes.fromhex("a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a")
    assert tlog.build_tree(LEAVES[:2]) == expected


def test_three_leaf_tree_root() -> None:
    # k = largest pow2 < 3 = 2. MTH([d0,d1,d2]) = node_hash(MTH([d0,d1]), MTH([d2])).
    # Hand construction: h0,h1 as above, h2 = sha256(0x00||d2),
    #                     left = sha256(0x01||h0||h1), root = sha256(0x01||left||h2).
    expected = bytes.fromhex("3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688")
    assert tlog.build_tree(LEAVES[:3]) == expected


def test_seven_leaf_tree_root() -> None:
    # Independently computed with hashlib.sha256, never attest.tlog: h0 through h6
    # are hashlib.sha256(b"\x00" + bytes([i])).digest() for i in range(7), then:
    # n01 = hashlib.sha256(b"\x01" + h0 + h1).digest()
    # n23 = hashlib.sha256(b"\x01" + h2 + h3).digest()
    # left = hashlib.sha256(b"\x01" + n01 + n23).digest()
    # n45 = hashlib.sha256(b"\x01" + h4 + h5).digest()
    # right = hashlib.sha256(b"\x01" + n45 + h6).digest()
    # root = hashlib.sha256(b"\x01" + left + right).digest()
    expected = bytes.fromhex("3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3")
    assert tlog.build_tree(LEAVES) == expected


def test_leaf_hash_matches_rfc_prefix_scheme() -> None:
    assert tlog.leaf_hash(b"\x00") == hashlib.sha256(b"\x00\x00").digest()


def test_node_hash_matches_rfc_prefix_scheme() -> None:
    left = tlog.leaf_hash(b"\x00")
    right = tlog.leaf_hash(b"\x01")
    assert tlog.node_hash(left, right) == hashlib.sha256(b"\x01" + left + right).digest()


# --------------------------------------------------------------------------
# Inclusion proof: round-trip for every index of a 7-leaf tree.
# --------------------------------------------------------------------------


def test_inclusion_round_trip_every_index_of_seven_leaf_tree() -> None:
    root = tlog.build_tree(LEAVES)
    for index in range(len(LEAVES)):
        proof = tlog.inclusion_proof(LEAVES, index)
        leaf = tlog.leaf_hash(LEAVES[index])
        assert tlog.verify_inclusion(leaf, index, len(LEAVES), proof, root)


def test_inclusion_round_trip_single_leaf_tree() -> None:
    root = tlog.build_tree(LEAVES[:1])
    proof = tlog.inclusion_proof(LEAVES[:1], 0)
    assert proof == []
    assert tlog.verify_inclusion(tlog.leaf_hash(LEAVES[0]), 0, 1, proof, root)


def test_inclusion_fails_on_wrong_root() -> None:
    proof = tlog.inclusion_proof(LEAVES, 3)
    wrong_root = bytes(32)
    assert not tlog.verify_inclusion(tlog.leaf_hash(LEAVES[3]), 3, len(LEAVES), proof, wrong_root)


def test_inclusion_fails_on_wrong_index() -> None:
    root = tlog.build_tree(LEAVES)
    proof = tlog.inclusion_proof(LEAVES, 3)
    assert not tlog.verify_inclusion(tlog.leaf_hash(LEAVES[3]), 2, len(LEAVES), proof, root)


def test_inclusion_fails_on_truncated_proof() -> None:
    root = tlog.build_tree(LEAVES)
    proof = tlog.inclusion_proof(LEAVES, 3)
    assert proof  # sanity: 7-leaf tree at index 3 has a non-empty path
    assert not tlog.verify_inclusion(tlog.leaf_hash(LEAVES[3]), 3, len(LEAVES), proof[:-1], root)


def test_inclusion_fails_on_oversized_proof() -> None:
    root = tlog.build_tree(LEAVES)
    proof = tlog.inclusion_proof(LEAVES, 3)
    bogus = [*proof, bytes(32)]
    assert not tlog.verify_inclusion(tlog.leaf_hash(LEAVES[3]), 3, len(LEAVES), bogus, root)


def test_inclusion_fails_closed_on_malformed_shapes() -> None:
    root = tlog.build_tree(LEAVES)
    leaf = tlog.leaf_hash(LEAVES[0])
    proof = tlog.inclusion_proof(LEAVES, 0)
    assert not tlog.verify_inclusion(leaf, -1, len(LEAVES), proof, root)
    assert not tlog.verify_inclusion(leaf, 0, 0, proof, root)
    assert not tlog.verify_inclusion(leaf, 99, len(LEAVES), proof, root)
    assert not tlog.verify_inclusion(leaf, 0, len(LEAVES), [b"short"], root)  # not 32 bytes
    assert not tlog.verify_inclusion(leaf, 0, len(LEAVES), ["not-bytes"], root)  # type: ignore[list-item]
    assert not tlog.verify_inclusion(leaf, "0", len(LEAVES), proof, root)  # type: ignore[arg-type]


@pytest.mark.parametrize("malformed_digest", [b"x", b"x" * 33])
def test_inclusion_rejects_short_or_long_leaf_and_root(
    malformed_digest: bytes,
) -> None:
    assert not tlog.verify_inclusion(malformed_digest, 0, 1, [], malformed_digest)


# --------------------------------------------------------------------------
# Consistency proof: round-trip for every (size1, size2 <= 7) pair.
# --------------------------------------------------------------------------


def test_consistency_round_trip_every_size_pair_up_to_seven_leaves() -> None:
    for size2 in range(0, len(LEAVES) + 1):
        leaves2 = LEAVES[:size2]
        root2 = tlog.build_tree(leaves2)
        for size1 in range(0, size2 + 1):
            root1 = tlog.build_tree(LEAVES[:size1])
            proof = tlog.consistency_proof(leaves2, size1)
            assert tlog.verify_consistency(size1, root1, size2, root2, proof)


def test_consistency_fails_on_cross_tree_roots() -> None:
    root1 = tlog.build_tree(LEAVES[:3])
    root2 = tlog.build_tree(LEAVES[:7])
    wrong_root2 = tlog.build_tree(LEAVES[:6])
    proof = tlog.consistency_proof(LEAVES[:7], 3)
    assert tlog.verify_consistency(3, root1, 7, root2, proof)
    assert not tlog.verify_consistency(3, root1, 7, wrong_root2, proof)
    wrong_root1 = tlog.build_tree(LEAVES[:2])
    assert not tlog.verify_consistency(3, wrong_root1, 7, root2, proof)


def test_consistency_fails_closed_on_malformed_shapes() -> None:
    root1 = tlog.build_tree(LEAVES[:3])
    root2 = tlog.build_tree(LEAVES[:7])
    proof = tlog.consistency_proof(LEAVES[:7], 3)
    assert not tlog.verify_consistency(7, root2, 3, root1, proof)  # size1 > size2
    assert not tlog.verify_consistency(3, root1, 7, root2, proof[:-1])  # truncated
    assert not tlog.verify_consistency(3, root1, 7, root2, [*proof, bytes(32)])  # oversized
    assert not tlog.verify_consistency(3, root1, 7, root2, [b"short"])  # not 32 bytes
    assert not tlog.verify_consistency("3", root1, 7, root2, proof)  # type: ignore[arg-type]


@pytest.mark.parametrize("malformed_digest", [b"x", b"x" * 33])
def test_consistency_rejects_short_or_long_roots(malformed_digest: bytes) -> None:
    assert not tlog.verify_consistency(1, malformed_digest, 1, malformed_digest, [])
    assert not tlog.verify_consistency(0, malformed_digest, 1, malformed_digest, [])


def test_consistency_empty_old_tree_is_vacuously_true() -> None:
    root2 = tlog.build_tree(LEAVES[:5])
    assert tlog.verify_consistency(0, bytes(32), 5, root2, [])


def test_consistency_equal_sizes_requires_matching_root_and_empty_proof() -> None:
    root = tlog.build_tree(LEAVES[:4])
    assert tlog.verify_consistency(4, root, 4, root, [])
    assert not tlog.verify_consistency(4, root, 4, root, [bytes(32)])
    assert not tlog.verify_consistency(4, root, 4, bytes(32), [])


def test_inclusion_proof_raises_on_out_of_range_index() -> None:
    with pytest.raises(ValueError, match="out of range"):
        tlog.inclusion_proof(LEAVES, len(LEAVES))
    with pytest.raises(ValueError, match="out of range"):
        tlog.inclusion_proof(LEAVES, -1)


def test_consistency_proof_raises_on_out_of_range_size1() -> None:
    with pytest.raises(ValueError, match="out of range"):
        tlog.consistency_proof(LEAVES, len(LEAVES) + 1)
    with pytest.raises(ValueError, match="out of range"):
        tlog.consistency_proof(LEAVES, -1)


# --------------------------------------------------------------------------
# encode_entry: closed schemas.
# --------------------------------------------------------------------------


def _valid_key_manifest_entry() -> dict[str, object]:
    return {
        "type": "key-manifest",
        "issuer": "shop.example.com",
        "manifest_version": 1,
        "manifest_sha256": "a" * 64,
    }


def _valid_receipt_entry() -> dict[str, object]:
    return {
        "type": "receipt",
        "issuer": "shop.example.com",
        "core_sha256": "b" * 64,
    }


def _valid_revocation_record_entry() -> dict[str, object]:
    return {
        "type": "revocation-record",
        "issuer": "shop.example.com",
        "record_sha256": "c" * 64,
    }


def test_encode_entry_accepts_valid_key_manifest_entry() -> None:
    entry = _valid_key_manifest_entry()
    encoded = tlog.encode_entry(entry)
    assert isinstance(encoded, bytes)
    # Round-trips through the canonicalizer used to produce it.
    from attest import canon

    assert encoded == canon.dumps(entry).encode("utf-8")


def test_encode_entry_accepts_valid_receipt_entry() -> None:
    entry = _valid_receipt_entry()
    encoded = tlog.encode_entry(entry)
    assert isinstance(encoded, bytes)


def test_encode_entry_accepts_valid_revocation_record_entry() -> None:
    entry = _valid_revocation_record_entry()
    encoded = tlog.encode_entry(entry)
    assert isinstance(encoded, bytes)
    assert encoded == canon.dumps(entry).encode("utf-8")


def test_encode_entry_rejects_revocation_record_missing_member() -> None:
    entry = _valid_revocation_record_entry()
    del entry["record_sha256"]
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_revocation_record_extra_member() -> None:
    entry = _valid_revocation_record_entry()
    entry["receipt_id"] = "01J1V5B4M9Z8QWERTY12345678"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_revocation_record_short_hex() -> None:
    entry = _valid_revocation_record_entry()
    entry["record_sha256"] = "c" * 63
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_revocation_record_uppercase_hex() -> None:
    entry = _valid_revocation_record_entry()
    entry["record_sha256"] = "C" * 64
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def _valid_transfer_record_entry() -> dict[str, object]:
    return {
        "type": "transfer-record",
        "issuer": "shop.example.com",
        "record_sha256": "d" * 64,
    }


def test_encode_entry_accepts_valid_transfer_record_entry() -> None:
    entry = _valid_transfer_record_entry()
    encoded = tlog.encode_entry(entry)
    assert isinstance(encoded, bytes)
    assert encoded == canon.dumps(entry).encode("utf-8")


def test_encode_entry_rejects_transfer_record_missing_member() -> None:
    entry = _valid_transfer_record_entry()
    del entry["record_sha256"]
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_transfer_record_extra_member() -> None:
    entry = _valid_transfer_record_entry()
    entry["receipt_id"] = "01J1V5B4M9Z8QWERTY12345678"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_transfer_record_short_hex() -> None:
    entry = _valid_transfer_record_entry()
    entry["record_sha256"] = "d" * 63
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_transfer_record_uppercase_hex() -> None:
    entry = _valid_transfer_record_entry()
    entry["record_sha256"] = "D" * 64
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_transfer_record_wrong_type_bad_issuer() -> None:
    entry = _valid_transfer_record_entry()
    entry["issuer"] = "NOT-A-VALID-DNS-NAME"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def _valid_cessation_declaration_entry() -> dict[str, object]:
    return {
        "type": "cessation-declaration",
        "issuer": "pub.example",
        "record_sha256": "e" * 64,
    }


def test_encode_entry_accepts_valid_cessation_declaration_entry() -> None:
    entry = _valid_cessation_declaration_entry()
    encoded = tlog.encode_entry(entry)
    assert isinstance(encoded, bytes)
    assert encoded == canon.dumps(entry).encode("utf-8")


def test_encode_entry_rejects_cessation_declaration_missing_member() -> None:
    entry = _valid_cessation_declaration_entry()
    del entry["record_sha256"]
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_cessation_declaration_extra_member() -> None:
    entry = _valid_cessation_declaration_entry()
    entry["declared_at"] = "2031-03-01T00:00:00Z"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_cessation_declaration_short_hex() -> None:
    entry = _valid_cessation_declaration_entry()
    entry["record_sha256"] = "e" * 63
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_cessation_declaration_uppercase_hex() -> None:
    entry = _valid_cessation_declaration_entry()
    entry["record_sha256"] = "E" * 64
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_cessation_declaration_bad_issuer() -> None:
    entry = _valid_cessation_declaration_entry()
    entry["issuer"] = "NOT-A-VALID-DNS-NAME"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_cessation_declaration_entry_commits_to_the_whole_signed_declaration() -> None:
    """v0.2 §8/§18.4: `record_sha256` is `SHA-256(JCS(declaration))` over the
    ENTIRE signed declaration, its own `signature` member included — the same
    canonical form `grant.py` builds and verifies the signature over, never a
    second one invented for the log."""
    kp = keys.generate()
    scope = {"artifact_series": None, "artifacts": [hashlib.sha256(b"a").hexdigest()]}
    declaration = grant.build_declaration(
        "pub.example", scope, "2031-03-01T00:00:00Z", kp, "pub.example/keys/grants#1"
    )

    entry = {
        "type": "cessation-declaration",
        "issuer": "pub.example",
        "record_sha256": grant.declaration_hash(declaration),
    }

    assert tlog.encode_entry(entry)
    assert entry["record_sha256"] == hashlib.sha256(canon.canonical_bytes(declaration)).hexdigest()


def _valid_publisher_authorization_entry() -> dict[str, object]:
    return {
        "type": "publisher-authorization",
        "issuer": "pub.example",
        "record_sha256": "f" * 64,
    }


def test_encode_entry_accepts_valid_publisher_authorization_entry() -> None:
    entry = _valid_publisher_authorization_entry()
    encoded = tlog.encode_entry(entry)
    assert isinstance(encoded, bytes)
    assert encoded == canon.dumps(entry).encode("utf-8")


def test_encode_entry_rejects_publisher_authorization_missing_member() -> None:
    entry = _valid_publisher_authorization_entry()
    del entry["record_sha256"]
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_publisher_authorization_extra_member() -> None:
    entry = _valid_publisher_authorization_entry()
    entry["authorization_version"] = 1
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_publisher_authorization_short_hex() -> None:
    entry = _valid_publisher_authorization_entry()
    entry["record_sha256"] = "f" * 63
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_publisher_authorization_uppercase_hex() -> None:
    entry = _valid_publisher_authorization_entry()
    entry["record_sha256"] = "F" * 64
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_publisher_authorization_bad_issuer() -> None:
    entry = _valid_publisher_authorization_entry()
    entry["issuer"] = "NOT-A-VALID-DNS-NAME"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_publisher_authorization_entry_commits_to_the_whole_signed_document() -> None:
    """v0.2 §8/§20.2: `record_sha256` is `SHA-256(JCS(document))` over the
    ENTIRE signed publisher authorization manifest, its own `signature` member
    included — the same canonical form `authority.py` builds and verifies the
    signature over, never a second one invented for the log."""
    kp = keys.generate()
    document = authority.build_authorization(
        1,
        "pub.example",
        [
            {
                "issuer_id": "store.example.com",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": None,
                "permissions": ["issue"],
                "scope": None,
            }
        ],
        "2026-02-01T00:00:00Z",
        kp,
        "pub.example/keys/authority#1",
    )

    entry = {
        "type": "publisher-authorization",
        "issuer": "pub.example",
        "record_sha256": authority.authorization_hash(document),
    }

    assert tlog.encode_entry(entry)
    assert entry["record_sha256"] == hashlib.sha256(canon.canonical_bytes(document)).hexdigest()


def test_encode_entry_accepts_an_at_bound_scalar() -> None:
    entry = _valid_receipt_entry()
    # Repeated one-character DNS labels plus a final two-character label make
    # this exact (even) length while remaining a valid issuer grammar.
    entry["issuer"] = "a." * ((tlog._MAX_ENTRY_SCALAR_LEN - 2) // 2) + "aa"
    assert len(entry["issuer"]) == tlog._MAX_ENTRY_SCALAR_LEN
    assert tlog.encode_entry(entry)


def test_encode_entry_rejects_an_over_bound_scalar_with_parity_literal() -> None:
    entry = _valid_receipt_entry()
    entry["issuer"] = "a" * (tlog._MAX_ENTRY_SCALAR_LEN + 1)

    with pytest.raises(tlog.TlogError) as exc_info:
        tlog.encode_entry(entry)

    assert str(exc_info.value) == f"entry scalar exceeds {tlog._MAX_ENTRY_SCALAR_LEN} chars"


def test_encode_entry_rejects_unknown_type() -> None:
    entry = _valid_receipt_entry()
    entry["type"] = "bogus"
    with pytest.raises(tlog.TlogError, match="unknown entry type"):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_extra_member() -> None:
    entry = _valid_receipt_entry()
    entry["extra_field"] = "nope"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_mixed_type_extra_keys() -> None:
    entry = _valid_receipt_entry()
    entry[1] = "nope"  # type: ignore[index]
    entry["extra_field"] = "nope"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_missing_member() -> None:
    entry = _valid_receipt_entry()
    del entry["issuer"]
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_uppercase_hex() -> None:
    entry = _valid_receipt_entry()
    entry["core_sha256"] = "B" * 64
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_non_int_manifest_version() -> None:
    entry = _valid_key_manifest_entry()
    entry["manifest_version"] = "1"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_manifest_version_below_one() -> None:
    entry = _valid_key_manifest_entry()
    entry["manifest_version"] = 0
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_accepts_largest_jcs_manifest_version() -> None:
    entry = _valid_key_manifest_entry()
    entry["manifest_version"] = 2**53 - 1
    assert tlog.encode_entry(entry)


def test_encode_entry_rejects_manifest_version_above_jcs_limit() -> None:
    entry = _valid_key_manifest_entry()
    entry["manifest_version"] = 2**53
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_bool_manifest_version() -> None:
    entry = _valid_key_manifest_entry()
    entry["manifest_version"] = True
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_uppercase_issuer() -> None:
    entry = _valid_receipt_entry()
    entry["issuer"] = "Shop.Example.com"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_issuer_with_trailing_newline() -> None:
    entry = _valid_receipt_entry()
    entry["issuer"] = "shop.example.com\n"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_non_dict_entry() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry([])  # type: ignore[arg-type]


def test_encode_entry_rejects_short_hex() -> None:
    entry = _valid_receipt_entry()
    entry["core_sha256"] = "b" * 63
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_manifest_hash_with_trailing_newline() -> None:
    entry = _valid_key_manifest_entry()
    entry["manifest_sha256"] = "a" * 64 + "\n"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


def test_encode_entry_rejects_core_hash_with_trailing_newline() -> None:
    entry = _valid_receipt_entry()
    entry["core_sha256"] = "b" * 64 + "\n"
    with pytest.raises(tlog.TlogError):
        tlog.encode_entry(entry)


# --------------------------------------------------------------------------
# Hybrid signed-note checkpoints: parse_checkpoint / verify_checkpoint /
# sign_checkpoint.
# --------------------------------------------------------------------------

ORIGIN = "log.attest.example/2026"
LOG_NAME = "attest-log-1"
ROOT = hashlib.sha256(b"checkpoint-test-root").digest()


def _hybrid_keys() -> pq.HybridSigningKeys:
    return pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())


def _log_key(hk: pq.HybridSigningKeys, origin: str = ORIGIN, name: str = LOG_NAME) -> tlog.LogKey:
    return tlog.LogKey(origin=origin, name=name, ed25519_pub=hk.ed.pub, mldsa_pub=hk.mldsa.pub)


def _signed_checkpoint(
    tree_size: int = 5, root: bytes = ROOT, origin: str = ORIGIN, name: str = LOG_NAME
) -> tuple[str, pq.HybridSigningKeys]:
    hk = _hybrid_keys()
    text = tlog.sign_checkpoint(origin, tree_size, root, hk, name)
    return text, hk


def _corrupt_line(text: str, index: int, new_line: str) -> str:
    lines = text.split("\n")
    lines[index] = new_line
    return "\n".join(lines)


# --- parse_checkpoint: structural validation only -------------------------


def test_parse_checkpoint_round_trip() -> None:
    text, _hk = _signed_checkpoint(tree_size=7, root=ROOT, origin=ORIGIN)
    checkpoint = tlog.parse_checkpoint(text)
    assert checkpoint.origin == ORIGIN
    assert checkpoint.tree_size == 7
    assert checkpoint.root == ROOT
    expected_note = f"{ORIGIN}\n7\n{base64.b64encode(ROOT).decode('ascii')}\n"
    assert checkpoint.note_bytes == expected_note.encode("utf-8")


def test_sign_checkpoint_ed25519_signature_uses_c2sp_note_boundary() -> None:
    text, hk = _signed_checkpoint()
    checkpoint = tlog.parse_checkpoint(text)
    _dash, _name, blob_b64 = text.split("\n")[4].split(" ", 2)
    signature = base64.b64decode(blob_b64)[4:]
    assert keys.verify_strict(checkpoint.note_bytes, signature, hk.ed.pub)
    assert not keys.verify_strict(checkpoint.note_bytes + b"\n", signature, hk.ed.pub)


def test_parse_checkpoint_rejects_zero_signature_lines() -> None:
    text = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


@pytest.mark.parametrize("origin", ["", "bad\x1forigin", "bad\x7forigin"])
def test_parse_checkpoint_rejects_empty_or_control_character_origin(origin: str) -> None:
    text = f"{origin}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {LOG_NAME} AA==\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


@pytest.mark.parametrize(
    ("category", "origin"),
    [
        ("zero-width format", "bad\u200borigin"),
        ("private-use", "bad\ue000origin"),
        ("non-breaking space", "bad\u00a0origin"),
        ("line separator", "bad\u2028origin"),
    ],
)
def test_parse_checkpoint_rejects_unicode_category_origin_under_ascii_grammar(
    category: str, origin: str
) -> None:
    text = f"{origin}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {LOG_NAME} AA==\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


@pytest.mark.parametrize("origin", ["🎉", "漢", "\U0002ebf0"])
def test_parse_checkpoint_rejects_non_ascii_origin_for_version_independent_grammar(
    origin: str,
) -> None:
    # Stage-2 note grammar is printable ASCII, not Unicode-category based:
    # cross-core verdicts therefore never depend on a host Unicode database.
    text = f"{origin}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {LOG_NAME} AA==\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_missing_blank_line() -> None:
    text = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\nnot-blank\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_two_line_body() -> None:
    # Root line entirely missing: only origin + size before the blank line.
    text = f"{ORIGIN}\n3\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_non_decimal_size() -> None:
    text = f"{ORIGIN}\nfive\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_negative_size() -> None:
    text = f"{ORIGIN}\n-3\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_leading_zero_size() -> None:
    text = f"{ORIGIN}\n01\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {LOG_NAME} AA==\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_accepts_uint64_max_size() -> None:
    text = f"{ORIGIN}\n{2**64 - 1}\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {LOG_NAME} AA==\n"
    assert tlog.parse_checkpoint(text).tree_size == 2**64 - 1


def test_parse_checkpoint_rejects_uint64_overflow_size() -> None:
    text = f"{ORIGIN}\n{2**64}\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {LOG_NAME} AA==\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_oversized_decimal_size() -> None:
    # A 5000-digit tree size must fail closed as TlogError, not leak the
    # bare ValueError CPython's int() raises past its digit-string limit
    # (3.11+ default 4300 digits) -- and must not pay the O(n^2) parse cost.
    huge_size = "9" * 5000
    text = f"{ORIGIN}\n{huge_size}\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_non_ascii_digit_size() -> None:
    # str.isdigit() accepts non-decimal Unicode digit-value characters
    # (e.g. superscript "²") that int() then rejects -- must fail
    # closed as TlogError, not leak a bare ValueError.
    text = f"{ORIGIN}\n²²²\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_root_not_32_bytes() -> None:
    short_root_b64 = base64.b64encode(bytes(31)).decode("ascii")
    text = f"{ORIGIN}\n3\n{short_root_b64}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_bad_base64_root() -> None:
    text = f"{ORIGIN}\n3\nnot-valid-base64!!\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_missing_trailing_newline() -> None:
    text = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text[:-1])


def test_parse_checkpoint_rejects_malformed_signature_line() -> None:
    text = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\nnot-a-signature-line\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_signature_line_with_wrong_dash() -> None:
    # Plain hyphen instead of U+2014 em dash: must be rejected, not tolerated.
    text = (
        f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
        f"- {LOG_NAME} {base64.b64encode(bytes(68)).decode('ascii')}\n"
    )
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


@pytest.mark.parametrize(
    "name",
    [
        "bad name",
        "bad+name",
        "bad\tname",
        "bad\x1fname",
        "bad\u200bname",
        "bad\ue000name",
        "bad\u00a0name",
        "bad\u2028name",
        "🎉",
        "漢",
        "\U0002ebf0",
    ],
)
def test_parse_checkpoint_rejects_invalid_c2sp_signature_name(name: str) -> None:
    text = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {name} AA==\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_lone_surrogate_origin() -> None:
    text = f"bad\ud800origin\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {LOG_NAME} AA==\n"
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


@pytest.mark.parametrize(
    ("value", "rendered"),
    [
        ("a'b", '"a\'b"'),
        ('a"b', "'a\"b'"),
        ("a'\"b", "'a\\'\"b'"),
        ("a\nb", r"'a\nb'"),
        ("a\\b", r"'a\\b'"),
        ("\u200b", r"'\u200b'"),
        ("🎉", r"'\U0001f389'"),
        ("\U0002ebf0", r"'\U0002ebf0'"),
        ("\x7f", r"'\x7f'"),
    ],
)
def test_tlog_diagnostic_renderer_matches_python_ascii(value: str, rendered: str) -> None:
    assert tlog._trunc_repr(value) == rendered


def test_parse_checkpoint_ascii_escapes_astral_diagnostic_before_truncation() -> None:
    oversized_by_one = "🎉" * 81
    text = (
        f"{ORIGIN}\n{oversized_by_one}\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
        f"— {LOG_NAME} AA==\n"
    )
    with pytest.raises(tlog.TlogError) as exc_info:
        tlog.parse_checkpoint(text)
    assert str(exc_info.value) == (
        "tree size must be ASCII decimal digits: '" + "\\U0001f389" * 80 + "'…"
    )


def test_parse_checkpoint_rejects_more_than_64_signature_lines() -> None:
    signature = f"— {LOG_NAME} {base64.b64encode(bytes(68)).decode('ascii')}\n"
    text = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n" + signature * 65
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(text)


def test_parse_checkpoint_rejects_non_str_input() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.parse_checkpoint(b"not-a-str")  # type: ignore[arg-type]


# --- verify_checkpoint: hybrid AND + origin binding ------------------------


def test_verify_checkpoint_both_legs_good_passes() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk)
    checkpoint = tlog.verify_checkpoint(text, log_key, ORIGIN)
    assert checkpoint.tree_size == 5
    assert checkpoint.root == ROOT


def test_verify_checkpoint_ed_only_fails() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk)
    # Drop the last (ML-DSA) signature line, keep the Ed25519-only one.
    lines = text.split("\n")
    truncated = "\n".join(lines[:-2]) + "\n"  # drop mldsa sig line + trailing ""
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(truncated, log_key, ORIGIN)


def test_verify_checkpoint_mldsa_only_fails() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk)
    lines = text.split("\n")
    # lines layout: [origin, size, root, "", ed_sig, mldsa_sig, ""]
    without_ed = lines[:4] + lines[5:]
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint("\n".join(without_ed), log_key, ORIGIN)


def test_verify_checkpoint_wrong_expected_origin_fails() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk)
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, log_key, "different-origin/2026")


def test_verify_checkpoint_wrong_log_key_origin_fails() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk, origin="different-origin/2026")
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, log_key, ORIGIN)


def test_verify_checkpoint_tampered_body_fails_both_legs() -> None:
    text, hk = _signed_checkpoint(tree_size=5)
    log_key = _log_key(hk)
    tampered = _corrupt_line(text, 1, "6")  # change signed tree_size 5 -> 6
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(tampered, log_key, ORIGIN)


def test_verify_checkpoint_signature_by_different_name_ignored_fails() -> None:
    text, hk = _signed_checkpoint(name="attest-log-1")
    log_key = _log_key(hk, name="attest-log-2")  # verifier expects a different name
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, log_key, ORIGIN)


def test_verify_checkpoint_wrong_key_hash_prefix_does_not_count() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk)
    lines = text.split("\n")
    # Corrupt the Ed25519 signature line's key-hash prefix (first 4 bytes of
    # the blob) so it no longer matches SHA256(name||"\n"||ed_pub)[:4], while
    # leaving the ML-DSA leg intact -- must still fail (no valid ed leg).
    dash, name, blob_b64 = lines[4].split(" ", 2)
    blob = bytearray(base64.b64decode(blob_b64))
    blob[0] ^= 0xFF
    lines[4] = f"{dash} {name} {base64.b64encode(bytes(blob)).decode('ascii')}"
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint("\n".join(lines), log_key, ORIGIN)


def test_verify_checkpoint_corrupted_mldsa_key_hash_prefix_does_not_count() -> None:
    text, hk = _signed_checkpoint()
    log_key = _log_key(hk)
    lines = text.split("\n")
    dash, name, blob_b64 = lines[5].split(" ", 2)
    blob = bytearray(base64.b64decode(blob_b64))
    blob[0] ^= 0xFF
    lines[5] = f"{dash} {name} {base64.b64encode(bytes(blob)).decode('ascii')}"
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint("\n".join(lines), log_key, ORIGIN)


def test_verify_checkpoint_no_signature_lines_fails() -> None:
    text = f"{ORIGIN}\n5\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    hk = _hybrid_keys()
    log_key = _log_key(hk)
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, log_key, ORIGIN)


def test_verify_checkpoint_rejects_short_log_key_ed25519_pub() -> None:
    text, hk = _signed_checkpoint()
    log_key = tlog.LogKey(
        origin=ORIGIN, name=LOG_NAME, ed25519_pub=b"short", mldsa_pub=hk.mldsa.pub
    )
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, log_key, ORIGIN)


def test_verify_checkpoint_rejects_short_log_key_mldsa_pub() -> None:
    text, hk = _signed_checkpoint()
    log_key = tlog.LogKey(origin=ORIGIN, name=LOG_NAME, ed25519_pub=hk.ed.pub, mldsa_pub=b"short")
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, log_key, ORIGIN)


def _malformed_log_key(field: str, value: object, hk: pq.HybridSigningKeys) -> tlog.LogKey:
    fields: dict[str, object] = {
        "origin": ORIGIN,
        "name": LOG_NAME,
        "ed25519_pub": hk.ed.pub,
        "mldsa_pub": hk.mldsa.pub,
    }
    fields[field] = value
    return tlog.LogKey(
        origin=cast(str, fields["origin"]),
        name=cast(str, fields["name"]),
        ed25519_pub=cast(bytes, fields["ed25519_pub"]),
        mldsa_pub=cast(bytes, fields["mldsa_pub"]),
    )


@pytest.mark.parametrize("field", ["origin", "name", "ed25519_pub", "mldsa_pub"])
def test_verify_checkpoint_rejects_malformed_log_key_field_types(field: str) -> None:
    text, hk = _signed_checkpoint()
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, _malformed_log_key(field, None, hk), ORIGIN)


def test_verify_checkpoint_rejects_malformed_expected_origin_type() -> None:
    text, hk = _signed_checkpoint()
    with pytest.raises(tlog.TlogError):
        tlog.verify_checkpoint(text, _log_key(hk), None)  # type: ignore[arg-type]


def test_verify_checkpoint_stops_after_hybrid_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    text, hk = _signed_checkpoint()
    lines = text.split("\n")
    lines.insert(-1, lines[5])  # an attacker-appended duplicate ML-DSA signature
    mldsa_verify = pq.verify_strict
    calls = 0

    def count_mldsa_verify(payload: bytes, signature: bytes, public_key: bytes) -> bool:
        nonlocal calls
        calls += 1
        return mldsa_verify(payload, signature, public_key)

    monkeypatch.setattr(pq, "verify_strict", count_mldsa_verify)
    tlog.verify_checkpoint("\n".join(lines), _log_key(hk), ORIGIN)
    assert calls == 1


# --- sign_checkpoint: builder side -----------------------------------------


def test_sign_checkpoint_round_trips_through_verify() -> None:
    hk = _hybrid_keys()
    text = tlog.sign_checkpoint(ORIGIN, 42, ROOT, hk, LOG_NAME)
    log_key = _log_key(hk)
    checkpoint = tlog.verify_checkpoint(text, log_key, ORIGIN)
    assert checkpoint.origin == ORIGIN
    assert checkpoint.tree_size == 42
    assert checkpoint.root == ROOT


def test_sign_checkpoint_output_ends_with_two_signature_lines() -> None:
    hk = _hybrid_keys()
    text = tlog.sign_checkpoint(ORIGIN, 1, ROOT, hk, LOG_NAME)
    lines = text.split("\n")
    assert lines[-1] == ""
    assert lines[-2].startswith("— " + LOG_NAME + " ")
    assert lines[-3].startswith("— " + LOG_NAME + " ")


def test_sign_checkpoint_rejects_wrong_length_root() -> None:
    hk = _hybrid_keys()
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint(ORIGIN, 1, b"short", hk, LOG_NAME)


def test_sign_checkpoint_rejects_newline_in_origin() -> None:
    hk = _hybrid_keys()
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint("bad\norigin", 1, ROOT, hk, LOG_NAME)


def test_sign_checkpoint_rejects_whitespace_in_name() -> None:
    hk = _hybrid_keys()
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint(ORIGIN, 1, ROOT, hk, "bad name")


@pytest.mark.parametrize("origin", ["", "bad\x1forigin", "bad\x7forigin", "🎉", "漢", "\U0002ebf0"])
def test_sign_checkpoint_rejects_empty_or_control_character_origin(origin: str) -> None:
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint(origin, 1, ROOT, _hybrid_keys(), LOG_NAME)


@pytest.mark.parametrize(
    "name", ["", "bad+name", "bad\tname", "bad\x1fname", "🎉", "漢", "\U0002ebf0"]
)
def test_sign_checkpoint_rejects_invalid_c2sp_name(name: str) -> None:
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint(ORIGIN, 1, ROOT, _hybrid_keys(), name)


def test_sign_checkpoint_rejects_uint64_overflow_tree_size() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint(ORIGIN, 2**64, ROOT, _hybrid_keys(), LOG_NAME)


def test_sign_checkpoint_rejects_lone_surrogate_origin() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.sign_checkpoint("bad\ud800origin", 1, ROOT, _hybrid_keys(), LOG_NAME)


# --- key-hash prefix: hand-pinned KAT ---------------------------------------


def test_key_hash_prefix_matches_hand_computed_sha256() -> None:
    # Hand-computed, independent of attest.tlog: C2SP's key-ID input is
    # name + "\n" + signature-type bytes + public key. Ed25519 uses the
    # assigned byte 0x01; ML-DSA-65 has no assigned byte and uses the C2SP
    # 0xff extension mechanism (0xff + a longer identifier). The ML-DSA-65
    # public key is fixed-length fixture material because this KAT covers
    # the hash format, not ML-DSA key validity. Never derive either literal
    # via tlog._key_hash, avoiding a tautological KAT.
    seed = bytes([7]) * 32
    ed_kp = keys.from_seed(seed)
    mldsa_pub = bytes(range(256)) * 7 + bytes(160)
    expected_ed_prefix = bytes.fromhex("fa60fb40")
    expected_mldsa_prefix = bytes.fromhex("5aded660")
    assert len(mldsa_pub) == pq.ML_DSA_65_PK_LEN
    assert hashlib.sha256(b"test-log\n\x01" + ed_kp.pub).digest()[:4] == expected_ed_prefix
    assert (
        hashlib.sha256(b"test-log\n\xffattest-ml-dsa-65" + mldsa_pub).digest()[:4]
        == expected_mldsa_prefix
    )

    hk = pq.HybridSigningKeys(ed=ed_kp, mldsa=pq.generate())
    text = tlog.sign_checkpoint(ORIGIN, 1, ROOT, hk, "test-log")
    ed_line = text.split("\n")[4]
    mldsa_line = text.split("\n")[5]
    _dash, _name, blob_b64 = ed_line.split(" ", 2)
    _dash, _name, mldsa_blob_b64 = mldsa_line.split(" ", 2)
    assert (
        base64.b64decode(blob_b64)[:4] == hashlib.sha256(b"test-log\n\x01" + hk.ed.pub).digest()[:4]
    )
    assert (
        base64.b64decode(mldsa_blob_b64)[:4]
        == hashlib.sha256(b"test-log\n\xffattest-ml-dsa-65" + hk.mldsa.pub).digest()[:4]
    )


# --- hostile-input bounds: error-message and allocation guards ---------------


def test_parse_checkpoint_rejects_too_many_lines_before_splitting() -> None:
    # Keep this below the total-text cap so it pins the zero-allocation
    # newline-count guard rather than the length guard.
    text = "\n" * (tlog._MAX_NOTE_LINES + 1)
    with pytest.raises(tlog.TlogError) as exc_info:
        tlog.parse_checkpoint(text)
    assert f"too many lines (max {tlog._MAX_NOTE_LINES})" in str(exc_info.value)
    assert len(str(exc_info.value)) < 200


def test_parse_checkpoint_rejects_oversized_note_text_before_splitting() -> None:
    # A long origin line reaches the aggregate cap before any line splitting.
    text = "x" * (tlog._MAX_NOTE_TEXT_LEN + 1) + "\n"
    with pytest.raises(tlog.TlogError) as exc_info:
        tlog.parse_checkpoint(text)
    assert str(tlog._MAX_NOTE_TEXT_LEN) in str(exc_info.value)
    assert len(str(exc_info.value)) < 200


def test_parse_checkpoint_accepts_maximum_number_of_signature_lines() -> None:
    signature = f"— {LOG_NAME} AA==\n"
    header = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n"
    text = header + signature * tlog._MAX_NOTE_SIGNATURES
    checkpoint = tlog.parse_checkpoint(text)
    assert checkpoint.origin == ORIGIN
    assert checkpoint.tree_size == 3
    assert checkpoint.root == ROOT


def test_parse_checkpoint_bounds_error_message_for_huge_malformed_size_line() -> None:
    # A multi-hundred-KB malformed field must not be fully rendered into the
    # TlogError message (repr amplification -> allocation DoS).
    root_b64 = base64.b64encode(ROOT).decode("ascii")
    text = f"{ORIGIN}\n{'x' * 100_000}\n{root_b64}\n\n— {LOG_NAME} AA==\n"
    with pytest.raises(tlog.TlogError) as exc_info:
        tlog.parse_checkpoint(text)
    assert len(str(exc_info.value)) < 200


def test_parse_checkpoint_rejects_oversized_signature_blob_before_decoding() -> None:
    # Base64 length is checked BEFORE b64decode so a hostile multi-megabyte
    # blob never gets decoded into a large allocation.
    huge_b64 = "A" * (tlog._MAX_SIG_B64_LEN + 4)
    text = f"{ORIGIN}\n3\n{base64.b64encode(ROOT).decode('ascii')}\n\n— {LOG_NAME} {huge_b64}\n"
    with pytest.raises(tlog.TlogError) as exc_info:
        tlog.parse_checkpoint(text)
    assert "exceeds" in str(exc_info.value)
    assert len(str(exc_info.value)) < 200


def test_parse_checkpoint_rejects_oversized_root_before_decoding() -> None:
    # Base64 length is checked BEFORE b64decode so a hostile multi-megabyte
    # root never gets decoded into a large allocation.
    huge_b64 = "A" * 100_000
    text = f"{ORIGIN}\n3\n{huge_b64}\n\n— {LOG_NAME} AA==\n"
    with pytest.raises(tlog.TlogError) as exc_info:
        tlog.parse_checkpoint(text)
    assert str(tlog._MAX_ROOT_B64_LEN) in str(exc_info.value)
    assert len(str(exc_info.value)) < 200


# --------------------------------------------------------------------------
# receipt_core_hash (Task 5): signed-receipt-core hash domain.
# --------------------------------------------------------------------------


def test_receipt_core_hash_matches_hand_pinned_kat() -> None:
    # Hand construction: SHA-256(b"attest-receipt-core-v1\x00" || b'{"a":1}'
    # || 0x00 || b'[]') — payload {"a": 1}, empty signatures array.
    expected = "1dac7a8f22603b1d77da8c71d84d5dc2e5d258f57654f76e1de0a0c304bc206e"
    envelope = {"payload": {"a": 1}, "signatures": []}
    assert tlog.receipt_core_hash(envelope) == expected


def test_receipt_core_hash_matches_domain_separated_jcs_formula() -> None:
    # Structural check against the spec formula, built from the already
    # independently-tested `canon.dumps` (test_canon.py) rather than
    # re-deriving JCS by hand — pins the domain separator, ordering (payload
    # THEN signatures), and the 0x00 field separator.
    payload = {"a": 1, "issuer": {"id": "issuer.example"}}
    signatures = [{"kid": "issuer.example/keys/x#1", "alg": "Ed25519", "sig": "c2ln"}]
    envelope = {"payload": payload, "signatures": signatures}
    expected = hashlib.sha256(
        b"attest-receipt-core-v1\x00"
        + canon.dumps(payload).encode("utf-8")
        + b"\x00"
        + canon.dumps(signatures).encode("utf-8")
    ).hexdigest()
    assert tlog.receipt_core_hash(envelope) == expected


def test_receipt_core_hash_excludes_delivery() -> None:
    base_envelope = {"payload": {"a": 1}, "signatures": []}
    with_delivery = {**base_envelope, "delivery": {"salt": "irrelevant-to-the-core-hash"}}
    assert tlog.receipt_core_hash(base_envelope) == tlog.receipt_core_hash(with_delivery)


def test_receipt_core_hash_changes_when_signature_bytes_change() -> None:
    # Design fix 4: commits to the SIGNATURE bytes too, not just payload —
    # two envelopes with identical payloads but different signatures must
    # not collide.
    base_envelope = {"payload": {"a": 1}, "signatures": [{"sig": "AAAA"}]}
    resigned_envelope = {"payload": {"a": 1}, "signatures": [{"sig": "BBBB"}]}
    assert tlog.receipt_core_hash(base_envelope) != tlog.receipt_core_hash(resigned_envelope)


def test_receipt_core_hash_is_lowercase_64_char_hex() -> None:
    result = tlog.receipt_core_hash({"payload": {}, "signatures": []})
    assert len(result) == 64
    assert result == result.lower()
    assert all(c in "0123456789abcdef" for c in result)


def test_receipt_core_hash_raises_on_missing_payload() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.receipt_core_hash({"signatures": []})


def test_receipt_core_hash_raises_on_non_object_payload() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.receipt_core_hash({"payload": "not-an-object", "signatures": []})


def test_receipt_core_hash_raises_on_missing_signatures() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.receipt_core_hash({"payload": {}})


def test_receipt_core_hash_raises_on_non_array_signatures() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.receipt_core_hash({"payload": {}, "signatures": "not-a-list"})


def test_receipt_core_hash_raises_on_non_dict_envelope() -> None:
    with pytest.raises(tlog.TlogError):
        tlog.receipt_core_hash(cast(dict[str, Any], "not-a-dict"))
