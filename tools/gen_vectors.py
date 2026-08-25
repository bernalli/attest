"""Generate the attest v0.1 language-neutral conformance vectors (design §11,
Fase 1 vectors 1-11 plus Fase 2 lifecycle/policy vectors 12-18).

Deterministic by construction: every keypair, salt, timestamp and ULID
randomness source below is a FIXED constant — no wall-clock reads
(`datetime.now`), no CSPRNG reads (`os.urandom`). Running this script twice
must produce byte-identical output under `docs/spec/vectors/`
(`git diff --exit-code docs/spec/vectors` after a second run is the
determinism gate — see the Task 10 report for the recorded check).

Each vector directory ("leaf", identified by containing `expected.json`)
holds:
  - `payload.json` — the receipt payload, for readability (not itself fed
    to `verify()`; it is embedded inside `envelope.json`).
  - `envelope.json` — the full envelope (`payload` + `signatures` + optional
    `delivery`), OR `envelope.raw.json` for vector 06, whose hand-written
    bytes intentionally cannot round-trip through a dict (duplicate JSON
    object member) — the replay test feeds that file's raw bytes straight
    to `verify()`, never through `json.load`/`json.dump`.
  - `manifests.json` — the trust material: `{"manifests": {...}, "provenance":
    {...}, "chains": {...}}`, fed straight into `verify.TrustStore`.
  - `expected.json` — the SPEC-INTENDED `VerificationResult`, hand-derived
    from design §6/§11 (not a dump of whatever `verify()` happened to
    return): `signature`, `schema`, `trust`, `revocation`, `binding`, `ok`,
    `errors` (exact list) or `errors_contains` (substrings), `warnings` or
    `warnings_contains`.
  - optional `disclosure.json` — `{"identifier", "identifier_type",
    "salt_b64u"}` (salt path) or `{"nonce_b64u", "sig_b64u"}` (challenge
    path) for the §6 step 7 binding check (vector 09, and Fase 2 vector 17).
  - optional `manifest_pristine.json` — only for vector 11 (manifest-tamper):
    the untampered, self-consistent manifest, so the replay test can also
    assert the self-consistency delta directly via
    `manifests.verify_key_manifest()`.

Fase 2 (lifecycle/policy, vectors 12-18, design §11) additions to the format
above, following the same fixed-input determinism discipline:

  - optional `revocation.json` — a single issuer-signed revocation record
    (`attest.revocation.build_record()` output), fed to the replay test as
    `revocation_view=[record]` (vectors 15, 16). Per the Task 9 hardening, a
    record only authenticates if signed by a key that is `active` in the
    issuer manifest with a `[valid_from, valid_to]` window covering the
    record's own `revoked_at` — every revocation.json shipped here satisfies
    that, checked with a generator-time `revocation.verify_record()` assert.
  - `manifests.json`'s `"chains"` member (always present, empty `{}` by
    default since Task 10) is populated for vectors 14/14b:
    `{issuer_id: [manifest_v1, manifest_v2]}`, oldest first, ending with the
    same manifest keyed under `"manifests"` for that issuer — exactly the
    shape `verify.TrustStore.chains` and the replay test's `_trust_store()`
    already consume. No new file convention needed; Task 10 already reserved
    this field, just never populated it.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dilithium_py.ml_dsa import (
    ML_DSA_65,
)  # DEV-ONLY oracle: deterministic vector material; runtime uses pqcrypto/@noble

from attest import (
    anchor,
    canon,
    commitment,
    issue,
    keys,
    manifests,
    pq,
    revocation,
    tlog,
    transfer,
    ulid,
    validate,
    witness,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "docs" / "spec" / "vectors"

# --- fixed, deterministic inputs (never wall-clock, never os.urandom) -----

ISSUER_ID = "store.example.com"
EVIL_ISSUER_ID = "evil.example.com"

ISSUER_SEED = bytes([1]) * 32
EVIL_SEED = bytes([9]) * 32
WRONG_KEY_SEED = bytes([2]) * 32  # a real key, deliberately absent from the manifest (vector 04)
BUYER_PUBKEY_SEED = bytes([3]) * 32  # populates buyer.pubkey in vector 02

ISSUER_KP = keys.from_seed(ISSUER_SEED)
EVIL_KP = keys.from_seed(EVIL_SEED)
WRONG_KP = keys.from_seed(WRONG_KEY_SEED)
BUYER_KP = keys.from_seed(BUYER_PUBKEY_SEED)

ISSUER_KID = f"{ISSUER_ID}/keys/2025-01#ed25519-1"
EVIL_KID = f"{EVIL_ISSUER_ID}/keys/2025-01#ed25519-1"
WRONG_KID = f"{ISSUER_ID}/keys/2025-01#ed25519-9"  # right domain, never listed in the manifest

SALT = bytes(range(16))
ULID_TIMESTAMP_MS = 1751464200000
ULID_RANDOMNESS = bytes(range(10))
RECEIPT_ID = ulid.generate(timestamp_ms=ULID_TIMESTAMP_MS, randomness=ULID_RANDOMNESS)
# datetime.fromtimestamp(ULID_TIMESTAMP_MS / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
# hardcoded rather than computed at generation time per the determinism brief
# (fixed inputs only, no runtime clock/timezone dependency).
ISSUED_AT = "2025-07-02T13:50:00Z"

KEY_VALID_FROM = "2025-01-01T00:00:00Z"
MANIFEST_ISSUED_AT = "2025-01-01T00:00:00Z"

LEGAL_TEXT_SHA256 = hashlib.sha256(b"attest-vectors-legal-text-v1").hexdigest()
MIRROR_POLICY_SHA256 = hashlib.sha256(b"attest-vectors-mirror-policy-v1").hexdigest()
EOL_COMMITMENT_SHA256 = hashlib.sha256(b"attest-vectors-eol-commitment-v1").hexdigest()
ARTIFACT_SHA256 = hashlib.sha256(b"attest-vectors-artifact-v1").hexdigest()

PRIOR_RECEIPT_ID = "01J1V5B4M9Z8QWERTY12345678"  # design §3.1 example, reused as `supersedes`

INT_MAX_ACCEPTED = 2**53 - 1  # I-JSON safe range boundary (design §3.1, canon.py _INT_MAX)
INT_MAX_REJECTED = 2**53

# --- Fase 2 (lifecycle/policy, vectors 12-18) additional fixed inputs ------
#
# Continuing the seed numbering already used above (1=issuer, 2=wrong-key,
# 3=buyer-pubkey, 9=evil-issuer): 4 and 5 are new keys needed only for the
# rotation-continuity vectors (12/13/15/16/17/18 all reuse ISSUER_KP/ISSUER_KID
# under a different manifest `status`, or ISSUER_KP's existing signature — no
# new key material needed for those).

ROTATED_KEY_SEED = bytes([4]) * 32  # the genuinely new key introduced by rotation (vector 14)
ROGUE_KEY_SEED = bytes([5]) * 32  # a key never active in the trusted root (vector 14b)

ROTATED_KP = keys.from_seed(ROTATED_KEY_SEED)
ROGUE_KP = keys.from_seed(ROGUE_KEY_SEED)

ROTATION_ISSUED_AT = "2025-04-01T00:00:00Z"  # v2 manifest issued_at / old key's retirement valid_to
ROTATED_KID = f"{ISSUER_ID}/keys/2025-04#ed25519-2"
# ROGUE_KID: same domain (passes the step-2 domain match) but never listed in v1.
ROGUE_KID = f"{ISSUER_ID}/keys/2025-04#ed25519-3"

# within both ROTATED_KP's and ROGUE_KP's validity window
RECEIPT_ISSUED_AFTER_ROTATION = "2025-05-01T00:00:00Z"

# revocation record timestamp (vectors 15, 16); within ISSUER_KID's open-ended validity
REVOKED_AT = "2025-08-01T00:00:00Z"

# 16 fixed bytes, distinct from SALT (bytes(range(16))) — vector 17b
CHALLENGE_NONCE = bytes(range(32, 48))


# --- 2026-07-13 regression-corpus constants (vectors 19-25) -------------------

SUBSTITUTED_KEY_SEED = (
    bytes([6]) * 32
)  # vector 19a: key the attacker swaps into the candidate manifest
SUBSTITUTED_KP = keys.from_seed(SUBSTITUTED_KEY_SEED)

SMALL_ORDER_POINT = bytes([1]) + bytes(31)  # canonical encoding of the identity element (order 1)
SMALL_ORDER_KID = (
    f"{ISSUER_ID}/keys/2025-01#ed25519-5"  # vector 20b: listed key whose pub is small-order
)

REFUND_WINDOW_DAYS = 14  # vector 23: ISSUED_AT 2025-07-02 -> window end 2025-07-16
REVOKED_INSIDE_WINDOW_AT = (
    "2025-07-10T00:00:00Z"  # vector 23a: inside the window (REVOKED_AT 2025-08-01 is outside)
)

SUPPLEMENTARY_TITLE = (
    "Music \U0001d11e Theme"  # vector 21f/g: U+1D11E, needs a surrogate pair when escaped
)


# --- vector 26 (hybrid conformance) additional fixed inputs -----------------
#
# ML-DSA-65 vector key material via `ML_DSA_65.key_derive` (deterministic, dev
# oracle only) — `bytes([26]) * 32`, continuing the seed-byte-value numbering
# scheme used for Ed25519 keys above (1/2/3/4/5/6/9 already taken).

HYBRID_MLDSA_PK, HYBRID_MLDSA_SK = ML_DSA_65.key_derive(bytes([26]) * 32)


# --- vector 28 (transparency/corroboration conformance corpus) additional
# fixed inputs -----------------------------------------------------------
#
# The transparency log's own pinned identity: an ML-DSA-65 leg via the same
# deterministic `key_derive` oracle used above (seed `bytes([28]) * 32`,
# continuing the numbering scheme), plus a genuine Ed25519 leg from seed
# `bytes([29]) * 32` — both fixed, never wall-clock/CSPRNG derived. A second,
# unrelated ML-DSA-65 keypair (`bytes([30]) * 32`) is used only by vector 28m,
# which needs its OWN hybrid issuer key distinct from the log's key material.

LOG_MLDSA_PK, LOG_MLDSA_SK = ML_DSA_65.key_derive(bytes([28]) * 32)
LOG_ED_SEED = bytes([29]) * 32
LOG_ED_KP = keys.from_seed(LOG_ED_SEED)
LOG_ORIGIN = "attest-transparency-log.example/2026"
LOG_NAME = "attest-log-2026"
WRONG_LOG_ORIGIN = "attest-transparency-log.example/rogue"  # vector 28d: origin-mismatch log key

VECTOR_28M_MLDSA_PK, VECTOR_28M_MLDSA_SK = ML_DSA_65.key_derive(bytes([30]) * 32)


# --- vector 35/36 (v0.2 Stage 3, issuer-mediated transfer) additional fixed
# inputs -----------------------------------------------------------------
#
# Continuing the seed numbering (26/28/29/30/31 already taken): every group
# 35 OLD receipt is `attest_version: "0.2"`, so — exactly like group 26 —
# its envelope/manifest MUST be hybrid (v0.2's own step-1 gate requires a
# `pub_ml_dsa_65`-carrying key entry); every transfer/revocation side-document
# that authenticates against that SAME manifest therefore needs the matching
# hybrid signature shape too (`_hybrid_sign_record` below, group 26/33's own
# oracle-sign-then-splice technique). Group 36's chain-of-title fixtures use a
# PLAIN (non-hybrid) issuer manifest instead — chain-of-title is a payload-only
# audit surface (`transfer.audit_chain` never touches an envelope's own
# signature/schema/hybrid-ness at all), so a plain manifest keeps its
# transfer/revocation records fully deterministic via `transfer.build_record`/
# `revocation.build_record` directly, no oracle needed.

TRANSFER_NEW_HOLDER_SEED = bytes([32]) * 32  # the winning incoming holder (35a/b/e/g/h, 36 R1)
TRANSFER_NEW_HOLDER_KP = keys.from_seed(TRANSFER_NEW_HOLDER_SEED)
TRANSFER_SECOND_HOLDER_SEED = bytes([33]) * 32  # 35f's second (losing) incoming holder
TRANSFER_SECOND_HOLDER_KP = keys.from_seed(TRANSFER_SECOND_HOLDER_SEED)
TRANSFER_FORGER_SEED = bytes([34]) * 32  # 35d: an unrelated key forging the holder authorization
TRANSFER_FORGER_KP = keys.from_seed(TRANSFER_FORGER_SEED)

CHAIN_HOLDER_0_SEED = bytes([35]) * 32  # group 36: R0's own buyer/holder keypair
CHAIN_HOLDER_0_KP = keys.from_seed(CHAIN_HOLDER_0_SEED)
CHAIN_HOLDER_1_SEED = bytes([36]) * 32  # R1's own buyer keypair — also signs link 2's auth
CHAIN_HOLDER_1_KP = keys.from_seed(CHAIN_HOLDER_1_SEED)
CHAIN_HOLDER_2_SEED = bytes([37]) * 32  # R2's own buyer keypair (final holder, never re-signs)
CHAIN_HOLDER_2_KP = keys.from_seed(CHAIN_HOLDER_2_SEED)
CHAIN_MISMATCH_HOLDER_SEED = bytes([38]) * 32  # 36b: a holder distinct from TR1's new_holder_pubkey
CHAIN_MISMATCH_HOLDER_KP = keys.from_seed(CHAIN_MISMATCH_HOLDER_SEED)

TRANSFERRED_AT = "2025-07-20T00:00:00Z"  # generic transferred_at, after ISSUED_AT (2025-07-02)
NOT_TRANSFERABLE_BEFORE_AFTER = "2025-08-01T00:00:00Z"  # after TRANSFERRED_AT (35g)

# ULID randomness bytes distinct from RECEIPT_ID's own (bytes(range(10))).
NEW_RECEIPT_ID = ulid.generate(timestamp_ms=ULID_TIMESTAMP_MS, randomness=bytes([32] * 10))
NEW_RECEIPT_ID_LOSING = ulid.generate(timestamp_ms=ULID_TIMESTAMP_MS, randomness=bytes([33] * 10))
CHAIN_RECEIPT_0 = ulid.generate(timestamp_ms=ULID_TIMESTAMP_MS, randomness=bytes([35] * 10))
CHAIN_RECEIPT_1 = ulid.generate(timestamp_ms=ULID_TIMESTAMP_MS, randomness=bytes([36] * 10))
CHAIN_RECEIPT_2 = ulid.generate(timestamp_ms=ULID_TIMESTAMP_MS, randomness=bytes([37] * 10))
CHAIN_PHANTOM_RECEIPT = ulid.generate(timestamp_ms=ULID_TIMESTAMP_MS, randomness=bytes([40] * 10))


# --- groups 39/40 (v0.2 §11.4, witness federation) additional fixed inputs ---
#
# Ten witness identities, each with an Ed25519 leg (seed bytes 41-50) and an
# ML-DSA-65 leg (`key_derive` seed bytes 51-60), continuing the seed numbering
# above (1-6, 9, 26, 28-30, 32-38 taken; 40 is a ULID randomness byte). Group
# 39 needs one pinned witness plus one impostor; the block is sized to ten
# because group 40's committee-ceiling leaf needs ten distinct control groups.
#
# One witness == one operator == one control group by construction, EXCEPT
# where a leaf deliberately says otherwise (40g pins two keys of one operator
# into a single control group; 40i puts a domain-conflicted sibling into
# another witness's group). Keeping the default one-to-one is what makes those
# two leaves the only place a reader has to think about the difference.

_WITNESS_SLOTS = 10
WITNESS_ED_KPS = [keys.from_seed(bytes([41 + index]) * 32) for index in range(_WITNESS_SLOTS)]
WITNESS_MLDSA_KEYS = [
    ML_DSA_65.key_derive(bytes([51 + index]) * 32) for index in range(_WITNESS_SLOTS)
]
WITNESS_NAMES = [f"attest-witness-{chr(97 + index)}-2026" for index in range(_WITNESS_SLOTS)]
WITNESS_OPERATORS = [f"witness-{chr(97 + index)}.example" for index in range(_WITNESS_SLOTS)]
WITNESS_CONTROL_GROUPS = [f"group-{chr(97 + index)}.example" for index in range(_WITNESS_SLOTS)]

# Real key material that NO epoch ever pins (39b): the impostor is genuine, it
# is simply not in the trusted policy.
UNPINNED_WITNESS_ED_KP = keys.from_seed(bytes([61]) * 32)
UNPINNED_WITNESS_NAME = "attest-witness-impostor-2026"

# Epoch windows, fixed and far apart so a leaf's intent is legible from its
# timestamps alone: the CURRENT epoch is open-ended from 2026-01-01, the
# HISTORICAL one closed in 2020 (39i/39j/39k, 40r).
WITNESS_EPOCH_ID = "bootstrap-2026"
WITNESS_EPOCH_NOT_BEFORE = "2026-01-01T00:00:00Z"
HISTORICAL_EPOCH_ID = "bootstrap-2020"
HISTORICAL_EPOCH_NOT_BEFORE = "2020-01-01T00:00:00Z"
HISTORICAL_EPOCH_NOT_AFTER = "2020-12-31T23:59:59Z"

# 2026-06-01T00:00:00Z, inside the current epoch: the instant every group
# 39/40 cosignature claims to have observed unless its leaf says otherwise.
# The two spellings are the same instant — cosignature blobs carry POSIX
# seconds, policy documents carry the §11.4 timestamp grammar — and the
# generator asserts they agree rather than trusting the comment.
WITNESS_OBSERVED_AT = 1780272000
WITNESS_OBSERVED_AT_ISO = "2026-06-01T00:00:00Z"
# 2020-06-01T00:00:00Z, inside the historical epoch.
HISTORICAL_OBSERVED_AT = 1590969600

# Group 40's `conflict_domain`: the issuer whose sunset the quorum would be
# activating — a witness affiliated with it cannot corroborate its own sunset.
WITNESS_CONFLICT_DOMAIN = ISSUER_ID

# Sentinel distinguishing "the policy declares nothing about compromise" from
# an explicit JSON `null` (§11.4's tri-state; see `_witness_pin`).
_ABSENT: Any = object()


# --- generic helpers --------------------------------------------------------


def _write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _clear_leaf_dirs(root: Path) -> None:
    """Remove only the leaf *directories* under `root`, preserving files —
    regeneration must not delete the hand-authored README.md (pre-2026-07-13
    the whole tree was rmtree'd and the README lost on every regen)."""
    if not root.exists():
        return
    for child in root.iterdir():
        if child.is_dir():
            shutil.rmtree(child)


def _text_max_depth(text: str) -> int:
    """Max bracket nesting depth of a JSON text, ignoring brackets inside
    strings — the measuring twin of `canon._check_depth`'s walk, used to
    assert the depth-boundary vectors (21b/c/d) sit exactly on 255/256/257."""
    depth = 0
    max_depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch in "]}":
            depth -= 1
    return max_depth


def _manifest_material(
    issuer_id: str, kid: str, kp: keys.SigningKeyPair, status: str = "active"
) -> dict[str, Any]:
    entries = [manifests.key_entry(kid, kp.pub, KEY_VALID_FROM, None, status)]
    return manifests.build_key_manifest(issuer_id, 1, MANIFEST_ISSUED_AT, entries, kp, kid)


def _oracle_sign(msg: bytes) -> bytes:
    """DEV-ONLY: deterministic ML-DSA-65 signing for vector generation only
    (`pq.sign`/pqcrypto is non-deterministic — verified live 2026-07-17 —
    so it can never produce byte-reproducible vector material). Runtime
    verification of these signatures still goes through `pq.verify_strict`
    (pqcrypto), cross-checked against this oracle's output at generation time."""
    return ML_DSA_65.sign(HYBRID_MLDSA_SK, msg, deterministic=True)


def _hybrid_key_entry(
    kid: str, ed_kp: keys.SigningKeyPair, status: str = "active"
) -> dict[str, Any]:
    return manifests.key_entry(
        kid, ed_kp.pub, KEY_VALID_FROM, None, status, pub_ml_dsa_65=HYBRID_MLDSA_PK
    )


def _hybrid_manifest(
    issuer_id: str,
    kid: str,
    ed_kp: keys.SigningKeyPair,
    version: int = 1,
    issued_at: str = MANIFEST_ISSUED_AT,
    status: str = "active",
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "issuer": issuer_id,
        "manifest_version": version,
        "issued_at": issued_at,
        "keys": [_hybrid_key_entry(kid, ed_kp, status)],
    }
    signable = manifests._signable(body)
    body["manifest_signature"] = {
        "kid": kid,
        "sig": keys.b64u(keys.sign(signable, ed_kp)),
        "sig_ml_dsa_65": keys.b64u(_oracle_sign(signable)),
    }
    return body


def _hybrid_envelope(
    payload: dict[str, Any], ed_kp: keys.SigningKeyPair, kid: str
) -> dict[str, Any]:
    canonical = canon.canonical_bytes(payload)
    return {
        "payload": payload,
        "signatures": [
            {"kid": kid, "alg": "Ed25519", "sig": keys.b64u(keys.sign(canonical, ed_kp))},
            {"kid": kid, "alg": pq.ML_DSA_65_ALG, "sig": keys.b64u(_oracle_sign(canonical))},
        ],
    }


def _flip_sig_byte(sig_b64u: str) -> str:
    """Corrupt a b64u-encoded signature by flipping one byte, re-encoded —
    used to build the tampered-leg vectors (26b/26c)."""
    raw = bytearray(keys.b64u_decode(sig_b64u))
    raw[0] ^= 0xFF
    return keys.b64u(bytes(raw))


def _hybrid_sign_record(body: dict[str, Any], kid: str = ISSUER_KID) -> dict[str, Any]:
    """Manually hybrid-sign a v0.2 side-document body (transfer/revocation
    record) — the same oracle-sign-then-splice technique `_hybrid_manifest`
    uses above (`ISSUER_KP`'s Ed25519 leg + the deterministic `_oracle_sign`
    ML-DSA-65 dev oracle, `HYBRID_MLDSA_SK`/`HYBRID_MLDSA_PK`), needed because
    `manifests.sign_signature_block`'s hybrid path would otherwise route the
    ML-DSA-65 leg through non-deterministic `pq.sign`/pqcrypto (this module's
    `gen_26_hybrid` docstring). Used by group 35, whose OLD receipts are
    `attest_version: "0.2"` and therefore need a hybrid issuer manifest to
    authenticate their own envelope signature (v0.2's step-1 hybrid gate) —
    every transfer/revocation side-document that must authenticate against
    that SAME manifest needs the matching hybrid signature shape."""
    signable = canon.canonical_bytes(body)
    record = dict(body)
    record["signature"] = {
        "kid": kid,
        "sig": keys.b64u(keys.sign(signable, ISSUER_KP)),
        "sig_ml_dsa_65": keys.b64u(_oracle_sign(signable)),
    }
    return record


def _transfer_record_body(
    receipt_id: str,
    new_receipt_id: str,
    new_holder_pubkey_b64u: str,
    transferred_at: str,
    holder_kp: keys.SigningKeyPair,
) -> dict[str, Any]:
    """The UNSIGNED transfer-record body (v0.2 §17.1) with a genuine holder
    authorization from `holder_kp` — the shared shape every group 35/36
    transfer record starts from, before `_hybrid_sign_record`/
    `transfer.build_record`'s own issuer-side signing."""
    auth_sig = transfer.sign_authorization(
        receipt_id, new_holder_pubkey_b64u, transferred_at, holder_kp
    )
    return {
        "receipt_id": receipt_id,
        "new_receipt_id": new_receipt_id,
        "new_holder_pubkey": new_holder_pubkey_b64u,
        "transferred_at": transferred_at,
        "holder_authorization": {"sig": keys.b64u(auth_sig)},
    }


# --- vector 28 helpers: transparency-log checkpoints ------------------------
#
# `tlog.sign_checkpoint` cannot produce reproducible vector material: like
# `pq.sign` (see `_oracle_sign` above), it signs the ML-DSA-65 leg through
# pqcrypto, which is non-deterministic. These two helpers mirror
# `tlog.sign_checkpoint`'s note-construction exactly, byte for byte, but
# substitute the deterministic dilithium_py oracle for that one leg — the
# same oracle-sign-then-splice technique `_hybrid_manifest` above already
# uses for manifest signatures. Both reach into `tlog`'s module-private
# `_key_hash`/`_ED25519_SIG_TYPE`/`_ML_DSA_65_SIG_TYPE` — the same "generator
# reaches into the reference package's private helpers" pattern already used
# elsewhere in this file (e.g. `manifests._signable` in `gen_14_rotation_
# continuity`).


def _log_oracle_sign(msg: bytes) -> bytes:
    """DEV-ONLY: deterministic ML-DSA-65 signing for the transparency log's
    own checkpoint key material (never `pq.sign`/pqcrypto — see module note
    above)."""
    return ML_DSA_65.sign(LOG_MLDSA_SK, msg, deterministic=True)


def _checkpoint_note_bytes(origin: str, tree_size: int, root: bytes) -> bytes:
    header = [origin, str(tree_size), base64.b64encode(root).decode("ascii")]
    return ("\n".join(header) + "\n").encode()


def _sign_checkpoint_oracle(origin: str, tree_size: int, root: bytes) -> str:
    """A hybrid (Ed25519 + ML-DSA-65) signed checkpoint note over
    `(origin, tree_size, root)`, signed by the fixed log key material
    (`LOG_ED_KP` / `LOG_MLDSA_SK`) — the reproducible-vector twin of
    `tlog.sign_checkpoint`."""
    note_bytes = _checkpoint_note_bytes(origin, tree_size, root)
    ed_blob = tlog._key_hash(LOG_NAME, tlog._ED25519_SIG_TYPE, LOG_ED_KP.pub) + keys.sign(
        note_bytes, LOG_ED_KP
    )
    mldsa_blob = tlog._key_hash(
        LOG_NAME, tlog._ML_DSA_65_SIG_TYPE, LOG_MLDSA_PK
    ) + _log_oracle_sign(note_bytes)
    ed_line = f"— {LOG_NAME} {base64.b64encode(ed_blob).decode('ascii')}\n"
    mldsa_line = f"— {LOG_NAME} {base64.b64encode(mldsa_blob).decode('ascii')}\n"
    return note_bytes.decode() + "\n" + ed_line + mldsa_line


def _sign_checkpoint_ed_only(origin: str, tree_size: int, root: bytes) -> str:
    """A DEGRADED checkpoint note carrying only the Ed25519 leg — used by
    vector 28c to pin that a log's checkpoint auth is hybrid, MANDATORY
    (design doc "checkpoint auth is hybrid, mandatory"): an otherwise
    well-formed, genuinely-signed Ed25519 leg alone must never grant
    standing."""
    note_bytes = _checkpoint_note_bytes(origin, tree_size, root)
    ed_blob = tlog._key_hash(LOG_NAME, tlog._ED25519_SIG_TYPE, LOG_ED_KP.pub) + keys.sign(
        note_bytes, LOG_ED_KP
    )
    ed_line = f"— {LOG_NAME} {base64.b64encode(ed_blob).decode('ascii')}\n"
    return note_bytes.decode() + "\n" + ed_line


def _log_key(origin: str = LOG_ORIGIN) -> tlog.LogKey:
    return tlog.LogKey(
        origin=origin, name=LOG_NAME, ed25519_pub=LOG_ED_KP.pub, mldsa_pub=LOG_MLDSA_PK
    )


def _log_key_json(log_key: tlog.LogKey) -> dict[str, Any]:
    return {
        "origin": log_key.origin,
        "name": log_key.name,
        "ed25519_pub_b64u": keys.b64u(log_key.ed25519_pub),
        "mldsa_pub_b64u": keys.b64u(log_key.mldsa_pub),
    }


def _empty_anchor_policy() -> anchor.AnchorPolicy:
    return anchor.AnchorPolicy(pinned_headers={}, crqc_horizon=None)


def _anchor_policy_json(policy: anchor.AnchorPolicy) -> dict[str, Any]:
    return {
        "pinned_headers": {
            header_hash: {
                "header_hash": header.header_hash,
                "merkle_root": header.merkle_root,
                "time": header.time,
            }
            for header_hash, header in policy.pinned_headers.items()
        },
        "crqc_horizon": policy.crqc_horizon,
    }


def _hex_proof(proof: list[bytes]) -> list[str]:
    return [item.hex() for item in proof]


# --- groups 39/40 witness material (v0.2 §11.4) -----------------------------
#
# Policy documents are written to `witness-policy.json` as the DOCUMENT the
# spec describes, never as a parsed object: `witness-policy.json` is TRUSTED
# verifier configuration on the same rail as `log-keys.json`/
# `anchor-policy.json`, and each core runs its OWN `parse_policy` over it.
# That is the whole point of shipping the document — the corpus exercises both
# parsers, not just both evaluators.


def _witness_pin(
    index: int,
    *,
    roles: list[str],
    not_before: str = WITNESS_EPOCH_NOT_BEFORE,
    not_after: str | None = None,
    operator_id: str | None = None,
    control_group: str | None = None,
    affiliated_domains: list[str] | None = None,
    compromised_after: Any = _ABSENT,
    with_mldsa: bool = True,
) -> dict[str, Any]:
    """One pinned witness identity, exactly as the policy document spells it.

    `compromised_after` is TRI-state (§11.4): the default sentinel omits the
    member entirely (nothing declared), an explicit `None` writes JSON `null`
    (onset unknown — the pin never carries standing), and a timestamp writes
    the declared onset. A plain `str | None` parameter cannot express that
    difference, and the difference is exactly what leaf 40t pins.
    """
    operator = operator_id if operator_id is not None else WITNESS_OPERATORS[index]
    domains = sorted({operator, *(affiliated_domains or [])})
    mldsa_pub = WITNESS_MLDSA_KEYS[index][0]
    pin: dict[str, Any] = {
        "operator_id": operator,
        "control_group": control_group
        if control_group is not None
        else WITNESS_CONTROL_GROUPS[index],
        "name": WITNESS_NAMES[index],
        "ed25519_pub_b64u": keys.b64u(WITNESS_ED_KPS[index].pub),
        "mldsa_65_pub_b64u": keys.b64u(mldsa_pub) if with_mldsa else None,
        "roles": sorted(roles),
        "not_before": not_before,
        "not_after": not_after,
        "affiliated_domains": domains,
    }
    if compromised_after is not _ABSENT:
        pin["compromised_after"] = compromised_after
    return pin


def _witness_epoch(
    witnesses: list[dict[str, Any]],
    *,
    epoch_id: str = WITNESS_EPOCH_ID,
    not_before: str = WITNESS_EPOCH_NOT_BEFORE,
    not_after: str | None = None,
    threshold: tuple[int, int] = (1, 1),
    log_origins: list[str] | None = None,
) -> dict[str, Any]:
    """One immutable epoch: a fixed committee over a fixed window."""
    return {
        "epoch_id": epoch_id,
        "not_before": not_before,
        "not_after": not_after,
        "log_origins": sorted(log_origins if log_origins is not None else [LOG_ORIGIN]),
        "threshold": {"n": threshold[0], "m": threshold[1]},
        "witnesses": witnesses,
    }


def _witness_policy_document(*epochs: dict[str, Any]) -> dict[str, Any]:
    """An `attest-witness-policy-v1` document, checked against the real parser.

    The generator-time `parse_policy` call is a narrow self-check in this
    file's existing style (cf. `_assert_schema_valid`): every policy shipped as
    trusted configuration must be one the reference parser accepts, or the leaf
    would be testing the parser's rejection path by accident instead of the
    evaluator's behavior. Leaves that WANT a rejected policy do not exist in
    groups 39/40 — a malformed trusted input raises, and `expected.json` has no
    vocabulary for an exception.
    """
    document = {"schema": witness.SCHEMA_ID, "epochs": list(epochs)}
    witness.parse_policy(document)
    return document


def _ed_cosignature_blob(
    name: str,
    kp: keys.SigningKeyPair,
    note_bytes: bytes,
    timestamp: int,
    *,
    signed_message: bytes | None = None,
    corrupt: bool = False,
) -> bytes:
    """A C2SP type-`0x04` Ed25519 cosignature blob: key ID ‖ time ‖ signature.

    `signed_message` overrides WHAT gets signed while leaving the blob's shape
    untouched — the only way to build 39e's "a signature made in the checkpoint
    domain, presented as a cosignature". `corrupt` flips a signature byte for
    39c, which needs a well-formed blob whose signature simply does not verify.
    """
    key_id = witness.cosignature_key_id(name, kp.pub)
    message = (
        witness.cosignature_message(note_bytes, timestamp)
        if signed_message is None
        else signed_message
    )
    signature = keys.sign(message, kp)
    if corrupt:
        signature = bytes([signature[0] ^ 0x01]) + signature[1:]
    return key_id + timestamp.to_bytes(8, "big") + signature


def _pq_cosignature_blob(
    name: str,
    index: int,
    note_bytes: bytes,
    timestamp: int,
    *,
    signed_message: bytes | None = None,
) -> bytes:
    """The activation leg: a `0xff`-typed ML-DSA-65 cosignature blob.

    The `0xff` extension type is NOT the checkpoint's own `attest-ml-dsa-65`:
    sharing that identifier would let a checkpoint signature be replayed as a
    witness assertion (§11.4), which is what leaf 39f pins from the other side.
    """
    mldsa_pub, mldsa_sk = WITNESS_MLDSA_KEYS[index]
    key_id = tlog.key_hash(name, witness.PQ_COSIGNATURE_SIG_TYPE, mldsa_pub)
    message = (
        witness.cosignature_message(note_bytes, timestamp)
        if signed_message is None
        else signed_message
    )
    return (
        key_id
        + timestamp.to_bytes(8, "big")
        + ML_DSA_65.sign(mldsa_sk, message, deterministic=True)
    )


def _note_line(name: str, blob: bytes) -> str:
    """One C2SP signed-note signature line (§9.2's `— <name> <base64>` form)."""
    return f"— {name} {base64.b64encode(blob).decode('ascii')}\n"


def _cosigned(checkpoint_text: str, *lines: str) -> str:
    """Append cosignature lines to an already-signed checkpoint note.

    Order matters for what an anchor commits to: a `signed-note-v2` anchor
    seeds from `signed_note_bytes`, so it must be built from the note AFTER
    these lines land — which is precisely why §11.4 requires the full-note
    profile for an activation quorum (a `note-v1` anchor commits to the header
    alone and says nothing about the votes; leaf 40q).
    """
    return checkpoint_text + "".join(lines)


def _witness_vote_lines(
    index: int,
    note_bytes: bytes,
    timestamp: int,
    *,
    ed_message: bytes | None = None,
    pq_message: bytes | None = None,
    pq_timestamp: int | None = None,
    with_ed: bool = True,
    with_pq: bool = True,
) -> list[str]:
    """One witness's hybrid vote: the `0x04` leg and the `0xff` leg together.

    Both legs sign the byte-identical payload, timestamp included — legs
    carrying different times are not a pair at all (leaf 40e uses
    `pq_timestamp` to build exactly that), and a lone leg is no vote (40c/40d).
    """
    name = WITNESS_NAMES[index]
    lines: list[str] = []
    if with_ed:
        lines.append(
            _note_line(
                name,
                _ed_cosignature_blob(
                    name, WITNESS_ED_KPS[index], note_bytes, timestamp, signed_message=ed_message
                ),
            )
        )
    if with_pq:
        pq_time = timestamp if pq_timestamp is None else pq_timestamp
        lines.append(
            _note_line(
                name,
                _pq_cosignature_blob(name, index, note_bytes, pq_time, signed_message=pq_message),
            )
        )
    return lines


def _single_hash_anchor(
    commitment_bytes: bytes, header_seed: bytes, header_time: int
) -> tuple[dict[str, Any], anchor.AnchorPolicy]:
    """A one-op OTS proof over `commitment_bytes`, plus the policy pinning it.

    The same shape `gen_32_anchor_v2` builds inline; lifted here because groups
    39 and 40 both need it, and group 40 needs it at a dozen different
    `header_time` values to walk the anchor-window boundaries.
    """
    header_hash = hashlib.sha256(header_seed).hexdigest()
    accumulator_start = hashlib.sha256(commitment_bytes).digest()
    header_merkle_root = hashlib.sha256(accumulator_start).digest().hex()
    proof = {
        "kind": "ots",
        "ops": [["sha256"]],
        "header_merkle_root": header_merkle_root,
        "header_hash": header_hash,
        "header_time": header_time,
    }
    policy = anchor.AnchorPolicy(
        pinned_headers={
            header_hash: anchor.PinnedHeader(
                header_hash=header_hash, merkle_root=header_merkle_root, time=header_time
            )
        },
        crqc_horizon=None,
    )
    return proof, policy


def _trust_material(
    *issuer_manifest_provenance: tuple[str, dict[str, Any], str],
    chains: dict[str, list[dict[str, Any]]] | None = None,
    artifact_manifests: dict[str, dict[str, dict[str, Any]]] | None = None,
    artifact_manifest_chains: dict[str, dict[str, list[dict[str, Any]]]] | None = None,
) -> dict[str, Any]:
    """Assemble a `manifests.json` payload from `(issuer_id, manifest, provenance)` triples.

    `chains`, when supplied, is embedded verbatim under `"chains"` — the same
    shape `verify.TrustStore.chains` and the replay test's `_trust_store()`
    already expect (design §5/§7.3): `{issuer_id: [manifest_v1, manifest_v2,
    ...]}`, oldest first, ending with the same manifest passed under
    `manifests` for that issuer. Only vectors 14/14b populate it; every other
    vector keeps the Task-10 default of an empty `chains` object.

    `artifact_manifests`/`artifact_manifest_chains` (G2/G3, attest-versioning.md
    rev 4) are the artifact-manifest analog, keyed by issuer and then
    `work.artifact_series` — the same shape
    `verify.TrustStore.artifact_manifests`/`.artifact_manifest_chains` expect.
    Only vector group 31 populates them;
    every other vector keeps the empty-object default.
    """
    return {
        "manifests": {issuer: manifest for issuer, manifest, _ in issuer_manifest_provenance},
        "provenance": {issuer: prov for issuer, _, prov in issuer_manifest_provenance},
        "chains": chains if chains is not None else {},
        "artifact_manifests": artifact_manifests if artifact_manifests is not None else {},
        "artifact_manifest_chains": (
            artifact_manifest_chains if artifact_manifest_chains is not None else {}
        ),
    }


def _issuer_only_trust() -> dict[str, Any]:
    """The common case: a single trusted issuer manifest, TLS provenance."""
    return _trust_material((ISSUER_ID, _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP), "tls"))


def _base_payload_kwargs(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "issuer_id": ISSUER_ID,
        "display_name": "Example Games Store",
        "buyer_identifier": "buyer-001",
        "buyer_identifier_type": "issuer-account",
        "buyer_salt": SALT,
        "title": "Example Game",
        "publisher": "Example Publisher srl",
        "identifiers": {"issuer_sku": "EXG-001"},
        "artifact_series": f"{ISSUER_ID}/works/EXG-001",
        "terms_uri": f"https://{ISSUER_ID}/attest/license-templates/standard-v1",
        "legal_text_sha256": LEGAL_TEXT_SHA256,
        "receipt_id": RECEIPT_ID,
        "issued_at": ISSUED_AT,
    }
    kwargs.update(overrides)
    return kwargs


def _assert_schema_valid(payload: dict[str, Any]) -> None:
    violations = validate.validate_payload(payload)
    if violations:
        raise AssertionError(f"generator built a schema-invalid payload: {violations}")


def write_vector(
    name: str,
    *,
    payload: dict[str, Any] | None,
    envelope: dict[str, Any] | None,
    envelope_raw: bytes | None,
    trust: dict[str, Any],
    expected: dict[str, Any],
    disclosure: dict[str, Any] | None = None,
    manifest_pristine: dict[str, Any] | None = None,
    revocation_record: dict[str, Any] | None = None,
    canonical: bytes | None = None,
    transparency: dict[str, Any] | None = None,
    log_keys: list[tlog.LogKey] | None = None,
    anchor_policy: anchor.AnchorPolicy | None = None,
    revocation_evidence: dict[str, Any] | None = None,
    transfer_view: list[dict[str, Any]] | None = None,
    witness_policy: dict[str, Any] | None = None,
) -> None:
    """`transparency`/`log_keys`/`anchor_policy` (group 28 only, design doc
    "transparency/corroboration layer") are the untrusted evidence bundle and
    the verifier's trusted, pinned configuration for evaluating it — see
    `verify.verify()`'s keyword-only arguments of the same names. Every
    existing leaf (groups 01-27) omits all three, so `expected.json` gains no
    new members there; only group 28 leaves carry `transparency`/
    `corroboration`/`manifest_freshness` in `expected.json`, fed by the new
    `transparency.json`/`log-keys.json`/`anchor-policy.json` files below.

    `revocation_evidence` (group 33 only, v0.2 §8/§15 amendment, G5/TM-47) is
    the untrusted transparency evidence bundle for a SPECIFIC `refund_window`
    revocation record's `revocation-record` log entry, fed to `verify()` as
    `revocation_evidence=` and reusing the SAME `log_keys`/`anchor_policy`
    written above — see `verify.verify()`'s keyword-only argument of the
    same name.

    `transfer_view` (group 35 only, v0.2 §17 Stage 3) is a list of untrusted
    claims `{"record": <a transfer.py record>, "evidence": <§10.2 evidence
    bundle>}`, fed to `verify()` as `transfer_view=` and reusing the SAME
    `log_keys`/`anchor_policy` written above — a DIFFERENT evidence channel
    from `transparency.json`/`revocation_evidence.json`: group 35's
    `expected.json` carries none of `transparency`/`corroboration`/
    `manifest_freshness` either, same discipline as group 33.

    `witness_policy` (group 39 only, v0.2 §11.4, P1.1b) is a TRUSTED
    `attest-witness-policy-v1` DOCUMENT, written to `witness-policy.json` and
    fed to `verify()` as `witness_policy=`. It rides the same rail as
    `log-keys.json`/`anchor-policy.json` — verifier configuration, never
    evidence — which is why it is its own file and is never nested inside
    `transparency.json`. The untrusted evidence names the epoch it claims
    (`witness_policy_epoch`); the trusted policy is what says who that epoch
    pins. Absent for every leaf outside group 39, so `verify()` sees `None`
    there and `corroboration: "witnessed"` stays unreachable."""
    vector_dir = VECTORS_DIR / name
    if payload is not None:
        _write_json(vector_dir / "payload.json", payload)
    if envelope is not None:
        _write_json(vector_dir / "envelope.json", envelope)
    if envelope_raw is not None:
        _write_bytes(vector_dir / "envelope.raw.json", envelope_raw)
    _write_json(vector_dir / "manifests.json", trust)
    _write_json(vector_dir / "expected.json", expected)
    if disclosure is not None:
        _write_json(vector_dir / "disclosure.json", disclosure)
    if manifest_pristine is not None:
        _write_json(vector_dir / "manifest_pristine.json", manifest_pristine)
    if revocation_record is not None:
        _write_json(vector_dir / "revocation.json", revocation_record)
    if canonical is not None:
        _write_bytes(vector_dir / "canonical.json", canonical)
    if transparency is not None:
        _write_json(vector_dir / "transparency.json", transparency)
    if log_keys is not None:
        _write_json(vector_dir / "log-keys.json", [_log_key_json(k) for k in log_keys])
    if anchor_policy is not None:
        _write_json(vector_dir / "anchor-policy.json", _anchor_policy_json(anchor_policy))
    if revocation_evidence is not None:
        _write_json(vector_dir / "revocation-evidence.json", revocation_evidence)
    if transfer_view is not None:
        _write_json(vector_dir / "transfer-view.json", transfer_view)
    if witness_policy is not None:
        _write_json(vector_dir / "witness-policy.json", witness_policy)


def write_chain_vector(
    name: str,
    *,
    chain: dict[str, Any],
    trust: dict[str, Any],
    expected: dict[str, Any],
    log_keys: list[tlog.LogKey],
    anchor_policy: anchor.AnchorPolicy,
) -> None:
    """Group 36 only (v0.2 §17.5, chain-of-title audit): a `chain.json` leaf
    (`{"payloads", "transfer_view", "revocation_view"}`) is routed to
    `transfer.audit_chain` instead of `verify()` by every harness — see
    `tests/test_vectors.py`'s `test_chain_audit_vectors` and its TS/site
    mirrors. `trust`/`log_keys`/`anchor_policy` are the same
    `manifests.json`/`log-keys.json`/`anchor-policy.json` shapes every other
    group already writes; the harness extracts the single trusted issuer
    manifest `audit_chain` expects as its own `key_manifest` argument from
    `trust["manifests"]`'s sole entry (every group 36 leaf trusts exactly one
    issuer)."""
    vector_dir = VECTORS_DIR / name
    _write_json(vector_dir / "chain.json", chain)
    _write_json(vector_dir / "manifests.json", trust)
    _write_json(vector_dir / "expected.json", expected)
    _write_json(vector_dir / "log-keys.json", [_log_key_json(k) for k in log_keys])
    _write_json(vector_dir / "anchor-policy.json", _anchor_policy_json(anchor_policy))


def write_quorum_vector(
    name: str,
    *,
    quorum: dict[str, Any],
    witness_policy: dict[str, Any],
    anchor_policy: anchor.AnchorPolicy,
    expected: dict[str, Any],
) -> None:
    """Group 40 only (v0.2 §11.4, activation-grade witness quorum): a leaf
    containing `witness-quorum.json` is a THIRD audit surface, routed to
    `evaluate_activation_witness_quorum`/`evaluateActivationWitnessQuorum`/
    `runWitnessQuorum` instead of `verify()` or `audit_chain` — the same
    file-presence routing `chain.json` established for group 36, applied at
    the six independent points that each re-implement the corpus contract.

    There is no receipt here, and deliberately so: §11.4's quorum is a
    STANDALONE primitive that answers one question — did a quorum of pinned
    witnesses observe THIS checkpoint, and by when. It knows nothing about
    receipts, so these leaves ship neither `payload.json`/`envelope.json` nor
    `manifests.json`.

    `witness-quorum.json` carries the call's own inputs. Two of its members
    are TRUSTED call configuration (`expected_origin`, `conflict_domain`, both
    of which RAISE when malformed); the other three are UNTRUSTED and must
    only ever degrade the verdict (`epoch_id`, named by the evidence;
    `checkpoint`, the signed note text; `anchor_evidence`, the anchor bundle —
    named for what it is, an evidence channel, and never nested inside the
    trusted `anchor-policy.json` beside it). The two POLICIES stay in their
    own files, which is where the rail separation actually lives.

    `expected.json` is the result shape, `{"valid", "witness_time",
    "counting_control_groups"}` — no `signature`/`schema`/`trust` members
    exist on this surface at all."""
    vector_dir = VECTORS_DIR / name
    _write_json(vector_dir / "witness-quorum.json", quorum)
    _write_json(vector_dir / "witness-policy.json", witness_policy)
    _write_json(vector_dir / "anchor-policy.json", _anchor_policy_json(anchor_policy))
    _write_json(vector_dir / "expected.json", expected)


# --- vector 01: valid-minimal ------------------------------------------------


def gen_01_valid_minimal() -> None:
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "01-valid-minimal",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 02: valid-full ----------------------------------------------------


def gen_02_valid_full() -> None:
    payload = issue.build_payload(
        **_base_payload_kwargs(
            edition="Deluxe",
            artifacts=[
                {
                    "role": "installer",
                    "platform": "windows-x86_64",
                    "filename": "example-game-1.0-setup.exe",
                    "size_bytes": 734003200,
                    "sha256": ARTIFACT_SHA256,
                }
            ],
            grant="perpetual",
            revocability="refund_window",
            revocation_window_days=14,
            transferable=False,
            drm="drm-bound",
            jurisdiction_flags={"eu_usedsoft_asserted": False},
            redownload_right=True,
            mirror_policy_uri=f"https://{ISSUER_ID}/attest/mirror-policy-v1",
            mirror_policy_sha256=MIRROR_POLICY_SHA256,
            end_of_life="escrow",
            eol_commitment_uri=f"https://{ISSUER_ID}/attest/eol-commitment-v1",
            eol_commitment_sha256=EOL_COMMITMENT_SHA256,
            supersedes=PRIOR_RECEIPT_ID,
            buyer_pubkey=BUYER_KP.pub,
        )
    )
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["drm-bound"],
    }
    write_vector(
        "02-valid-full",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 03: tampered-payload ----------------------------------------------


def gen_03_tampered_payload() -> None:
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    tampered = copy.deepcopy(envelope)
    title = tampered["payload"]["work"]["title"]
    assert title[0] == "E", f"unexpected title, fix the tamper index: {title!r}"
    tampered["payload"]["work"]["title"] = "F" + title[1:]  # flip one byte, post-signing
    trust = _issuer_only_trust()
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["signature verification failed"],
        "warnings": [],
    }
    write_vector(
        "03-tampered-payload",
        payload=payload,
        envelope=tampered,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 04: wrong-key -----------------------------------------------------


def gen_04_wrong_key() -> None:
    """Signed by a key whose kid domain matches the issuer but is absent from
    the trusted manifest (§6 step 3, not step 2 — the domain check passes)."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, WRONG_KP, WRONG_KID)  # kid domain matches issuer.id
    trust = _issuer_only_trust()
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["no key", "in issuer manifest"],
        "warnings": [],
    }
    write_vector(
        "04-wrong-key",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 05: issuer-mismatch -----------------------------------------------


def gen_05_issuer_mismatch() -> None:
    """A valid signature by evil.example.com's key over a payload claiming
    issuer.id store.example.com — must reject at §6 step 2 (issuer_mismatch).
    `issue.issue()` itself refuses to build this (kid-domain/issuer.id check
    at issuance time), so the envelope is hand-signed exactly like the attack
    it models."""
    payload = issue.build_payload(**_base_payload_kwargs())  # issuer.id == store.example.com
    _assert_schema_valid(payload)
    sig = keys.sign(canon.canonical_bytes(payload), EVIL_KP)
    envelope = {
        "payload": payload,
        "signatures": [{"kid": EVIL_KID, "alg": "Ed25519", "sig": keys.b64u(sig)}],
    }
    trust = _trust_material(
        (ISSUER_ID, _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP), "tls"),
        (EVIL_ISSUER_ID, _manifest_material(EVIL_ISSUER_ID, EVIL_KID, EVIL_KP), "tls"),
    )
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["issuer_mismatch"],
        "warnings": [],
    }
    write_vector(
        "05-issuer-mismatch",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 06: duplicate-key-reject ------------------------------------------


def gen_06_duplicate_key_reject() -> None:
    """A genuinely duplicated JSON object member — a Python dict cannot
    represent this, so the envelope is a hand-written raw byte string, not a
    serialized dict. Rejected at §6 step 0 (RFC 8785 forbids duplicate
    members; `canon.loads_strict` raises `DuplicateKeyError`), before any
    issuer/key resolution — trust stays at its unresolved default."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    text = json.dumps(envelope, separators=(",", ":"))
    marker = '"attest_version":"0.1"'
    assert text.count(marker) == 1, "expected exactly one attest_version member to duplicate"
    duplicated = text.replace(marker, marker + "," + marker, 1)
    assert json.loads(duplicated)  # sanity: still syntactically valid generic JSON
    trust = _issuer_only_trust()
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "unauthenticated_tofu",  # step 0 fails before any issuer is even identified
        "ok": False,
        "errors_contains": ["duplicate object key"],
        "warnings": [],
    }
    write_vector(
        "06-duplicate-key-reject",
        payload=payload,
        envelope=None,
        envelope_raw=duplicated.encode("utf-8"),
        trust=trust,
        expected=expected,
    )


# --- vector 07: unicode-canon (two sub-cases) ---------------------------------


def gen_07_unicode_canon() -> None:
    # NFD-decomposed "é" (e + combining acute accent U+0301) — JCS must sign
    # and verify the exact code points given, never silently NFC-normalizing
    # arbitrary payload string content (unlike commitment.normalize(), which
    # is the one place NFC normalization is normative, §3.2).
    nfd_title = "Café"

    assert unicodedata.normalize("NFC", nfd_title) != nfd_title, "title must be genuinely NFD"

    payload = issue.build_payload(
        **_base_payload_kwargs(
            title=nfd_title,
            artifacts=[
                {
                    "role": "installer",
                    "platform": "windows-x86_64",
                    "filename": "example-game-1.0-setup.exe",
                    "size_bytes": INT_MAX_ACCEPTED,
                    "sha256": ARTIFACT_SHA256,
                }
            ],
        )
    )
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()

    expected_a = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "07-unicode-canon/a-nfd-and-int-boundary-accepted",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected_a,
    )

    # Sub-case b: bump the same field one past the I-JSON safe boundary. This
    # payload can never be produced by issue() (canon.canonical_bytes() -
    # required to sign it - raises CanonError on the oversized int), so it is
    # built as a post-signing mutation of sub-case a's envelope, exactly like
    # vector 03's tamper: the (now stale) signature no longer applies to the
    # mutated payload, AND the mutated payload cannot even be canonicalized.
    # Design §11 vector 7 says "rejected by schema" in shorthand; the actual
    # rejection point is earlier and unavoidable — every payload field,
    # including this one, is part of JCS(payload), which `verify()` step 4
    # must canonicalize BEFORE it could ever reach step 5's schema check. See
    # the Task 10 report for the full discrepancy note.
    rejected_envelope = copy.deepcopy(envelope)
    rejected_envelope["payload"]["work"]["artifacts"][0]["size_bytes"] = INT_MAX_REJECTED
    expected_b = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["integer out of I-JSON safe range"],
        "warnings": [],
    }
    write_vector(
        "07-unicode-canon/b-int-boundary-rejected",
        payload=None,
        envelope=rejected_envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected_b,
    )


# --- vector 08: sig-malleability ----------------------------------------------


def _malleate_signature(sig: bytes) -> bytes:
    """S -> S + L (group order): mathematically the same scalar mod L, since
    `B` has order `L`, so `[S+L]B == [S]B` — a non-canonical re-encoding of
    "the same" signature that the attest pinned ruleset (design §4) must reject
    (SUF-CMA: reject S >= L)."""
    r, s = sig[:32], int.from_bytes(sig[32:], "little")
    malleated_s = s + keys.L
    return r + malleated_s.to_bytes(32, "little")


def gen_08_sig_malleability() -> None:
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    original_sig = keys.b64u_decode(envelope["signatures"][0]["sig"])
    malleated = copy.deepcopy(envelope)
    malleated["signatures"][0]["sig"] = keys.b64u(_malleate_signature(original_sig))
    trust = _issuer_only_trust()
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["signature verification failed"],
        "warnings": [],
    }
    write_vector(
        "08-sig-malleability",
        payload=payload,
        envelope=malleated,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 09: commitment (three sub-cases) ----------------------------------


def _commitment_subvector(subname: str, identifier: str, identifier_type: str) -> None:
    payload = issue.build_payload(
        **_base_payload_kwargs(buyer_identifier=identifier, buyer_identifier_type=identifier_type)
    )
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    commitment_b64u = payload["buyer"]["commitment"]
    assert commitment_b64u == keys.b64u(commitment.compute(identifier, identifier_type, SALT))
    trust = _issuer_only_trust()
    disclosure = {
        "identifier": identifier,
        "identifier_type": identifier_type,
        "salt_b64u": keys.b64u(SALT),
    }
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "proven",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
        "commitment_b64u": commitment_b64u,
        "normalized_identifier": commitment.normalize(identifier, identifier_type),
    }
    write_vector(
        f"09-commitment/{subname}",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
        disclosure=disclosure,
    )


def gen_09_commitment() -> None:
    _commitment_subvector("a-ascii-email", "Buyer@Example.com", "email")
    _commitment_subvector("b-unicode-email", "Büyér+Tag@Example.com", "email")
    # NFD input ("Zan" + combining tilde U+0303 + "y_ID-042"): normalize() for
    # issuer-account NFC-composes without case-folding, so the commitment is
    # computed over "Zañy_ID-042" (NFC), not the NFD bytes as typed.
    _commitment_subvector("c-issuer-account", "Zañy_ID-042", "issuer-account")


# --- vector 10: unknown-field -------------------------------------------------


def gen_10_unknown_field() -> None:
    payload = issue.build_payload(**_base_payload_kwargs())
    payload["promo_code"] = "SUMMER2026"  # unknown top-level field, signed and warned about
    _assert_schema_valid(payload)  # additionalProperties: true at the top level
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["unknown payload field", "promo_code"],
    }
    write_vector(
        "10-unknown-field",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 11: manifest-tamper -----------------------------------------------


def gen_11_manifest_tamper() -> None:
    """A key's `status` flipped from `active` to `compromised` after the
    manifest was signed. `verify()` never re-checks a trust-store manifest's
    own self-signature (that is the caller's responsibility before trusting
    a manifest at all — see `manifests.verify_key_manifest`); it reads
    `status` directly off whatever manifest the trust store hands it. So the
    tampered manifest has two independently checkable effects, both asserted
    here: (a) it no longer self-verifies (`manifest_pristine.json` lets the
    replay test check this directly), and (b) any receipt genuinely signed
    while the key WAS active now reports `signature: invalid` via the §6
    step 3 fail-closed compromise check, because the trust store's copy says
    `compromised` regardless of what was true when the manifest was signed."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)  # signed while genuinely active

    pristine_manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP, status="active")
    tampered_manifest = copy.deepcopy(pristine_manifest)
    tampered_manifest["keys"][0]["status"] = "compromised"  # post-signing tamper
    assert manifests.verify_key_manifest(pristine_manifest) is True
    assert manifests.verify_key_manifest(tampered_manifest) is False

    trust = _trust_material((ISSUER_ID, tampered_manifest, "tls"))
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["compromised"],
        "warnings": [],
        "note": (
            "manifests.json carries the TAMPERED manifest (what verify() is fed); "
            "manifest_pristine.json is the untampered, self-consistent original."
        ),
    }
    write_vector(
        "11-manifest-tamper",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
        manifest_pristine=pristine_manifest,
    )


# --- vector 12: retired-key-ok ------------------------------------------------


def gen_12_retired_key_ok() -> None:
    """A receipt genuinely signed while `ISSUER_KID` was `active`, verified
    against a trust-store manifest where that same key is now `retired`
    (design §7.3: "Receipts signed while a key was active remain valid after
    that key is later retired"). `verify()` step 3 only rejects on
    `compromised`; `retired` continues verification but MUST emit a warning
    (§11.2) — this vector is that warning path, distinct from vector 13
    (compromised) which rejects outright."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP, status="retired")
    trust = _trust_material((ISSUER_ID, manifest, "tls"))
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["retired"],
    }
    write_vector(
        "12-retired-key-ok",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 13: compromised-key -------------------------------------------------


def gen_13_compromised_key() -> None:
    """A receipt genuinely signed by `ISSUER_KID`, verified against a
    trust-store manifest where that key is now `compromised`. Unlike vector
    11 (manifest-tamper, where the manifest's OWN signature breaks because a
    field was mutated post-signing), this manifest is fully self-consistent
    — it is the ordinary, honestly-authored lifecycle state an issuer
    publishes after a real compromise. §7.3 / §11 step 3: `compromised`
    fails closed unconditionally, checked BEFORE the `issued_at`-in-window
    test in `verify.py` — so rejection here does not depend on `issued_at`
    at all, which is the concrete evidence for "ALL its signatures invalid
    regardless of issued_at" (design §11 vector 13)."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)  # genuinely signed while active
    manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP, status="compromised")
    assert manifests.verify_key_manifest(manifest) is True  # self-consistent, unlike vector 11
    trust = _trust_material((ISSUER_ID, manifest, "tls"))
    expected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["compromised"],
        "warnings": [],
    }
    write_vector(
        "13-compromised-key",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 14 / 14b: rotation continuity / discontinuity -----------------------


def _genuine_rotation_pair() -> tuple[dict[str, Any], dict[str, Any]]:
    """A legitimate v1 -> v2 rotation: v2 retires the old key, introduces
    ROTATED_KID, and is signed by ISSUER_KID (active in v1) -> continuity holds."""
    v1 = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    v2_entries = [
        manifests.key_entry(
            ISSUER_KID, ISSUER_KP.pub, KEY_VALID_FROM, ROTATION_ISSUED_AT, "retired"
        ),
        manifests.key_entry(ROTATED_KID, ROTATED_KP.pub, ROTATION_ISSUED_AT, None, "active"),
    ]
    v2 = manifests.build_key_manifest(
        ISSUER_ID, 2, ROTATION_ISSUED_AT, v2_entries, ISSUER_KP, ISSUER_KID
    )
    assert manifests.check_continuity(v1, v2) is True
    return v1, v2


def gen_14_rotation_continuity() -> None:
    """A two-manifest chain: v1 (`ISSUER_KID` sole active key) -> v2, where v2
    introduces a genuinely NEW active key (`ROTATED_KID`) and retires the old
    one, but v2 is itself signed by the OLD key — the standard "old key
    signs off on the new one" handoff (design §7.3). `manifests.check_continuity`
    requires the signer to be `active` in the TRUSTED (v1) manifest; it is,
    so the chain is continuous and `trust` stays at its provenance-derived
    value (`verified`, since provenance is `tls`) rather than being forced
    to `unverified_rotation`. The receipt itself is issued by the NEW key,
    proving verification correctly resolves against the CURRENT (v2) manifest."""
    v1, v2 = _genuine_rotation_pair()

    payload = issue.build_payload(**_base_payload_kwargs(issued_at=RECEIPT_ISSUED_AFTER_ROTATION))
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ROTATED_KP, ROTATED_KID)

    trust = _trust_material((ISSUER_ID, v2, "tls"), chains={ISSUER_ID: [v1, v2]})
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "14-rotation-continuity",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


def gen_14b_rotation_discontinuous() -> None:
    """Same v1 root as vector 14, but the candidate v2 is signed by
    `ROGUE_KID` — a key that is never listed, active or otherwise, in v1.
    `manifests.check_continuity` looks up the CANDIDATE's signer inside the
    TRUSTED manifest's own keys; that lookup misses, so the chain is
    discontinuous (design §7.3: "if intermediates are unavailable, the
    manifest MUST be treated as reached via a discontinuous rotation").
    `verify()` forces `trust: "unverified_rotation"`, overriding provenance,
    even though the receipt's own signature (by `ROGUE_KID`, which IS active
    in the CURRENT/v2 manifest actually used to resolve it) verifies cleanly
    — `trust` is not one of the four components `VerificationResult.ok`
    checks (§11.1: signature/schema/revocation/errors only), so `ok` stays
    `True` by explicit spec definition: this is a trust *downgrade* signal
    for the caller to act on, not a rejection. (Mirrors the existing
    `test_rotation_discontinuous_chain_yields_unverified_rotation` unit test
    in `tests/test_verify.py`.)"""
    v1 = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)  # same root as vector 14
    rogue_entries = [
        manifests.key_entry(ROGUE_KID, ROGUE_KP.pub, ROTATION_ISSUED_AT, None, "active")
    ]
    v2_rogue = manifests.build_key_manifest(
        ISSUER_ID, 2, ROTATION_ISSUED_AT, rogue_entries, ROGUE_KP, ROGUE_KID
    )
    assert manifests.check_continuity(v1, v2_rogue) is False  # signer absent from the trusted root

    payload = issue.build_payload(**_base_payload_kwargs(issued_at=RECEIPT_ISSUED_AFTER_ROTATION))
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ROGUE_KP, ROGUE_KID)

    trust = _trust_material((ISSUER_ID, v2_rogue, "tls"), chains={ISSUER_ID: [v1, v2_rogue]})
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "unverified_rotation",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "14b-rotation-discontinuous",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 15: revoked-policy ---------------------------------------------------


def gen_15_revoked_policy() -> None:
    """A `revocability: "policy"` receipt plus an authenticated, matching
    revocation record: per §12.2, `policy` honors an effective record as-is
    -> `revocation: "revoked"`, `ok: False`. The record is signed by
    `ISSUER_KID` while it is `active` with a `[valid_from, valid_to]` window
    covering `REVOKED_AT` — the Task 9 hardening
    (`revocation.verify_record`, mirroring `manifests.verify_artifact_manifest`)
    requires exactly this or the record is silently ignored; the generator
    asserts `verify_record` is True so a future regression here fails loudly
    at generation time, not just at replay time."""
    payload = issue.build_payload(**_base_payload_kwargs(revocability="policy"))
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    issuer_manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    trust = _trust_material((ISSUER_ID, issuer_manifest, "tls"))
    record = revocation.build_record(RECEIPT_ID, "revoked", REVOKED_AT, ISSUER_KP, ISSUER_KID)
    assert revocation.verify_record(record, issuer_manifest) is True
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "revoked",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "15-revoked-policy",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
        revocation_record=record,
    )


# --- vector 16: revocation-against-none-ignored ----------------------------------


def gen_16_revocation_against_none_ignored() -> None:
    """A `revocability: "none"` receipt (the `_base_payload_kwargs()` default)
    plus an authenticated, matching revocation record: §6.2 / §12.2's
    irrevocability guarantee means the record itself is treated as invalid —
    `revocation: "invalid_revocation_ignored"`, a warning is emitted, and the
    receipt's `ok` is UNAFFECTED (`True`). Without this rule the revocation
    mechanism would falsify every `revocability: "none"` receipt's own
    claim (design vector 16 is exactly this regression test)."""
    payload = issue.build_payload(**_base_payload_kwargs())  # revocability defaults to "none"
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    issuer_manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    trust = _trust_material((ISSUER_ID, issuer_manifest, "tls"))
    record = revocation.build_record(RECEIPT_ID, "revoked", REVOKED_AT, ISSUER_KP, ISSUER_KID)
    assert revocation.verify_record(record, issuer_manifest) is True  # authenticated, but ignored
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "invalid_revocation_ignored",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["revocability is 'none'"],
    }
    write_vector(
        "16-revocation-against-none-ignored",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
        revocation_record=record,
    )


# --- vector 17: binding-proven (two sub-cases) -----------------------------------


def gen_17_binding_proven() -> None:
    """§8/§11 step 7 buyer binding, both proof paths (design vector 17):

    (a) salt disclosure — `(identifier, identifier_type, salt)` recomputes
    `buyer.commitment`; a clean minimal-receipt case (the default
    `_base_payload_kwargs()` identity), isolating the binding proof itself
    from the normalization edge cases already covered by vector 09.

    (b) pubkey challenge-response — `buyer.pubkey` is populated at issuance;
    the disclosure carries `(nonce, sig)` where `sig` is the buyer's own
    Ed25519 signature (§8.2) over the fixed challenge transcript, proving
    possession of the private key without ever revealing an identifier.
    Neither vectors 01-16 nor vector 09 exercise this path — vector 09 only
    ever populates the salt path."""
    # (a) salt disclosure
    payload_a = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload_a)
    envelope_a = issue.issue(payload_a, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()
    disclosure_a = {
        "identifier": "buyer-001",  # matches _base_payload_kwargs()'s buyer_identifier default
        "identifier_type": "issuer-account",
        "salt_b64u": keys.b64u(SALT),
    }
    expected_a = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "proven",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "17-binding-proven/a-salt-disclosure",
        payload=payload_a,
        envelope=envelope_a,
        envelope_raw=None,
        trust=trust,
        expected=expected_a,
        disclosure=disclosure_a,
    )

    # (b) pubkey challenge-response transcript
    payload_b = issue.build_payload(**_base_payload_kwargs(buyer_pubkey=BUYER_KP.pub))
    _assert_schema_valid(payload_b)
    envelope_b = issue.issue(payload_b, ISSUER_KP, ISSUER_KID)
    receipt_id_b = payload_b["receipt_id"]
    challenge_sig = commitment.sign_challenge(receipt_id_b, CHALLENGE_NONCE, BUYER_KP)
    assert commitment.verify_challenge(receipt_id_b, CHALLENGE_NONCE, challenge_sig, BUYER_KP.pub)
    disclosure_b = {
        "nonce_b64u": keys.b64u(CHALLENGE_NONCE),
        "sig_b64u": keys.b64u(challenge_sig),
    }
    expected_b = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "proven",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "17-binding-proven/b-pubkey-challenge",
        payload=payload_b,
        envelope=envelope_b,
        envelope_raw=None,
        trust=trust,
        expected=expected_b,
        disclosure=disclosure_b,
    )


# --- vector 18: drm-bound ---------------------------------------------------------


def gen_18_drm_bound() -> None:
    """`license.drm == "drm-bound"` MUST verify green but MUST carry a
    mandatory warning (§5.5, §11.2) — a receipt never removes DRM and this
    specification never claims it does. `revocability` is bumped off the
    schema default `"none"` to `"policy"` purely because §6.1's conditional
    requires `drm == "drm-free"` when `revocability == "none"`; `"policy"`
    carries no such constraint, so this is the minimal change that keeps the
    payload schema-valid while setting `drm: "drm-bound"`."""
    payload = issue.build_payload(**_base_payload_kwargs(revocability="policy", drm="drm-bound"))
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["drm-bound"],
    }
    write_vector(
        "18-drm-bound",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 19: rotation-substituted-key (2 sub-cases) ---------------------------


def gen_19_rotation_substituted_key() -> None:
    """Regression pair for the 2026-07-13 must-fix #1 (key substitution in
    check_continuity) and the PR #4 chain-tail binding fix.

    (a) The candidate v2 re-declares ISSUER_KID but with SUBSTITUTED_KP's
    public key, and is signed by SUBSTITUTED_KP under that kid. The manifest
    is SELF-consistent (its own declared pub verifies its own signature) —
    exactly the attack the pre-fix code fell for by validating the candidate
    signature against the candidate's self-declared pub. The fixed
    check_continuity resolves the signer pub from the TRUSTED manifest, where
    ISSUER_KID maps to the real key -> signature mismatch -> discontinuous ->
    trust: "unverified_rotation" (a trust downgrade, not a rejection: ok stays
    True per §11.1, same reasoning as vector 14b).

    (b) The chain [v1, v2] is genuinely continuous, but the manifest under
    `manifests` (the one used to resolve the receipt's kid) is v1, NOT the
    chain tail v2. Post-PR#4, a chain only vouches for the manifest it ends
    with -> unverified_rotation."""
    # (a) substituted candidate key
    v1 = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    evil_entries = [
        manifests.key_entry(ISSUER_KID, SUBSTITUTED_KP.pub, KEY_VALID_FROM, None, "active"),
        manifests.key_entry(ROTATED_KID, ROTATED_KP.pub, ROTATION_ISSUED_AT, None, "active"),
    ]
    v2_evil = manifests.build_key_manifest(
        ISSUER_ID, 2, ROTATION_ISSUED_AT, evil_entries, SUBSTITUTED_KP, ISSUER_KID
    )
    assert manifests.verify_key_manifest(v2_evil) is True  # self-consistent: that's the point
    assert manifests.check_continuity(v1, v2_evil) is False  # but the trusted root unmasks it

    payload = issue.build_payload(**_base_payload_kwargs(issued_at=RECEIPT_ISSUED_AFTER_ROTATION))
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ROTATED_KP, ROTATED_KID)
    trust_a = _trust_material((ISSUER_ID, v2_evil, "tls"), chains={ISSUER_ID: [v1, v2_evil]})
    expected_downgrade = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "unverified_rotation",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "19-rotation-substituted-key/a-substituted-candidate-key",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust_a,
        expected=expected_downgrade,
    )

    # (b) valid chain whose tail is not the manifest in use
    v1b, v2b = _genuine_rotation_pair()
    payload_b = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload_b)
    envelope_b = issue.issue(
        payload_b, ISSUER_KP, ISSUER_KID
    )  # resolvable in v1 (the manifest used)
    trust_b = _trust_material((ISSUER_ID, v1b, "tls"), chains={ISSUER_ID: [v1b, v2b]})
    write_vector(
        "19-rotation-substituted-key/b-chain-tail-not-manifest-used",
        payload=payload_b,
        envelope=envelope_b,
        envelope_raw=None,
        trust=trust_b,
        expected=expected_downgrade,
    )


# --- vector 20: sig-canonicity (three sub-cases) ------------------------------


def gen_20_sig_canonicity() -> None:
    """Ed25519 pinned-ruleset edges (design §4): S must satisfy S < L
    (vector 08 already pins S+L; sub-case a pins the exact boundary S == L),
    and small-order A (signer pubkey) / small-order R (signature prefix) must
    be rejected — libsodium rejects both natively, @noble does with
    zip215:false (verifiers/ts/src/ed25519.ts). The identity element is used
    as the canonical small-order point."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()
    original_sig = keys.b64u_decode(envelope["signatures"][0]["sig"])
    r_bytes, s_bytes = original_sig[:32], original_sig[32:]

    rejected = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["signature verification failed"],
        "warnings": [],
    }

    # (a) S == L exactly: the smallest non-canonical scalar.
    s_equals_l = copy.deepcopy(envelope)
    s_equals_l["signatures"][0]["sig"] = keys.b64u(r_bytes + keys.L.to_bytes(32, "little"))
    write_vector(
        "20-sig-canonicity/a-s-equals-l",
        payload=payload,
        envelope=s_equals_l,
        envelope_raw=None,
        trust=trust,
        expected=rejected,
    )

    # (b) signer pubkey is small-order: manifest lists SMALL_ORDER_KID with the
    # identity point as pub (manifest itself is signed by ISSUER_KID, so its
    # self-verify holds); the envelope claims SMALL_ORDER_KID.
    so_entries = [
        manifests.key_entry(ISSUER_KID, ISSUER_KP.pub, KEY_VALID_FROM, None, "active"),
        manifests.key_entry(SMALL_ORDER_KID, SMALL_ORDER_POINT, KEY_VALID_FROM, None, "active"),
    ]
    so_manifest = manifests.build_key_manifest(
        ISSUER_ID, 1, MANIFEST_ISSUED_AT, so_entries, ISSUER_KP, ISSUER_KID
    )
    so_envelope = copy.deepcopy(envelope)
    so_envelope["signatures"][0]["kid"] = SMALL_ORDER_KID
    write_vector(
        "20-sig-canonicity/b-small-order-pubkey",
        payload=None,
        envelope=so_envelope,
        envelope_raw=None,
        trust=_trust_material((ISSUER_ID, so_manifest, "tls")),
        expected=rejected,
    )

    # (c) signature R component is small-order, S kept from the real signature.
    so_r = copy.deepcopy(envelope)
    so_r["signatures"][0]["sig"] = keys.b64u(SMALL_ORDER_POINT + s_bytes)
    write_vector(
        "20-sig-canonicity/c-small-order-r",
        payload=None,
        envelope=so_r,
        envelope_raw=None,
        trust=trust,
        expected=rejected,
    )


def _nested_list(levels: int) -> Any:
    value: Any = 1
    for _ in range(levels):
        value = [value]
    return value


def gen_21_canon_strict() -> None:
    """Strict-parser parity set: BOM, depth boundary triple, lone surrogate,
    and supplementary-plane raw-vs-escaped equivalence. Parse-level rejects
    reuse vector 06's expected shape (issuer unextractable -> TOFU trust)."""
    parse_reject_base = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "unauthenticated_tofu",
        "ok": False,
        "warnings": [],
    }
    accepted_with_unknown_field = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["unknown payload field"],
    }
    trust = _issuer_only_trust()

    # (a) BOM: both parsers reject, with language-specific messages -> no errors* field.
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    bom_raw = b"\xef\xbb\xbf" + json.dumps(envelope).encode("utf-8")
    write_vector(
        "21-canon-strict/a-bom",
        payload=None,
        envelope=None,
        envelope_raw=bom_raw,
        trust=trust,
        expected=dict(parse_reject_base),
    )

    # (b)(c)(d) depth boundary triple: whole-text nesting 255 / 256 / 257,
    # against canon.py's own parse-time structural safety cap (256,
    # `canon.MAX_DEPTH` — exists only to keep the parser itself safe from
    # stack exhaustion; also the single normative nesting-depth ceiling,
    # `validate.MAX_JSON_DEPTH` aliases it, 2026-07-22 fix wave — see
    # `validate.py`'s `MAX_JSON_DEPTH` docstring). The deep structure lives
    # in an unknown top-level payload field "x" (vector 10 pins
    # unknown-field tolerance: schema stays valid + warning), so 255/256 are
    # genuinely, cleanly signed and accepted; only 257 trips the cap.
    for depth_target, subname in ((255, "b-depth-255"), (256, "c-depth-256"), (257, "d-depth-257")):
        deep_payload = issue.build_payload(**_base_payload_kwargs())
        # envelope text depth at "x" = {envelope {payload [x nesting...]}} = 2 + levels
        deep_payload["x"] = _nested_list(depth_target - 2)
        deep_envelope = issue.issue(deep_payload, ISSUER_KP, ISSUER_KID)
        deep_raw = json.dumps(deep_envelope).encode("utf-8")
        assert _text_max_depth(deep_raw.decode("utf-8")) == depth_target
        if depth_target <= 256:
            expected: dict[str, Any] = dict(accepted_with_unknown_field)
        else:
            expected = dict(parse_reject_base)
            expected["errors_contains"] = ["maximum nesting depth exceeded"]
        write_vector(
            f"21-canon-strict/{subname}",
            payload=None,
            envelope=None,
            envelope_raw=deep_raw,
            trust=trust,
            expected=expected,
        )

    # (e) lone surrogate via \uXXXX escape, injected textually (a payload
    # carrying it can never be signed: canonical_bytes rejects it).
    surr_payload = issue.build_payload(**_base_payload_kwargs())
    surr_payload["x"] = "PLACEHOLDER_SURR"
    surr_envelope = issue.issue(surr_payload, ISSUER_KP, ISSUER_KID)
    surr_raw_text = json.dumps(surr_envelope).replace('"PLACEHOLDER_SURR"', '"\\ud800"')
    assert "\\ud800" in surr_raw_text
    surr_expected = dict(parse_reject_base)
    surr_expected["errors_contains"] = ["lone surrogate"]
    write_vector(
        "21-canon-strict/e-lone-surrogate",
        payload=None,
        envelope=None,
        envelope_raw=surr_raw_text.encode("utf-8"),
        trust=trust,
        expected=surr_expected,
    )

    # (f)(g) supplementary-plane raw vs escaped: same signed payload, two
    # byte-level encodings of the same envelope -> both must verify (JCS
    # canonical form is what got signed, independent of transport escaping).
    supp_payload = issue.build_payload(**_base_payload_kwargs(title=SUPPLEMENTARY_TITLE))
    _assert_schema_valid(supp_payload)
    supp_envelope = issue.issue(supp_payload, ISSUER_KP, ISSUER_KID)
    raw_text = json.dumps(supp_envelope, ensure_ascii=False)
    escaped_text = json.dumps(supp_envelope, ensure_ascii=True)
    assert "\U0001d11e" in raw_text and "\\ud834\\udd1e" in escaped_text
    accepted_clean = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "21-canon-strict/f-supplementary-raw",
        payload=supp_payload,
        envelope=None,
        envelope_raw=raw_text.encode("utf-8"),
        trust=trust,
        expected=dict(accepted_clean),
        canonical=canon.canonical_bytes(supp_payload),
    )
    write_vector(
        "21-canon-strict/g-supplementary-escaped",
        payload=None,
        envelope=None,
        envelope_raw=escaped_text.encode("utf-8"),
        trust=trust,
        expected=dict(accepted_clean),
        canonical=canon.canonical_bytes(supp_payload),
    )


_B64U_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def gen_22_b64u_decoder_parity() -> None:
    """Both languages deliberately accept non-strict base64url on the sig
    field (padding, standard alphabet, dirty trailing bits) -- triaged
    LOW/by-design-symmetric in the 2026-07-13 review. The parity risk is one
    decoder tightening without the other; pin the shared behavior."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()
    sig_text: str = envelope["signatures"][0]["sig"]
    sig_bytes = keys.b64u_decode(sig_text)
    accepted = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }

    # (a) explicit padding
    padded = copy.deepcopy(envelope)
    padded["signatures"][0]["sig"] = sig_text + "=" * (-len(sig_text) % 4)
    assert padded["signatures"][0]["sig"].endswith("==")  # 86 chars -> two pad chars
    assert keys.b64u_decode(padded["signatures"][0]["sig"]) == sig_bytes
    write_vector(
        "22-b64u-decoder-parity/a-padding-accepted",
        payload=payload,
        envelope=padded,
        envelope_raw=None,
        trust=trust,
        expected=dict(accepted),
    )

    # (b) standard +/ alphabet
    assert "-" in sig_text or "_" in sig_text, "fixed sig must exercise the urlsafe alphabet"
    std = copy.deepcopy(envelope)
    std["signatures"][0]["sig"] = sig_text.replace("-", "+").replace("_", "/")
    assert std["signatures"][0]["sig"] != sig_text
    assert keys.b64u_decode(std["signatures"][0]["sig"]) == sig_bytes
    write_vector(
        "22-b64u-decoder-parity/b-standard-alphabet-accepted",
        payload=None,
        envelope=std,
        envelope_raw=None,
        trust=trust,
        expected=dict(accepted),
    )

    # (c) non-zero discarded trailing bits in the final char (4 bits unused)
    last_idx = _B64U_ALPHABET.index(sig_text[-1])
    dirty_char = _B64U_ALPHABET[last_idx ^ 0x0F]
    dirty = copy.deepcopy(envelope)
    dirty["signatures"][0]["sig"] = sig_text[:-1] + dirty_char
    assert dirty["signatures"][0]["sig"] != sig_text
    assert keys.b64u_decode(dirty["signatures"][0]["sig"]) == sig_bytes
    write_vector(
        "22-b64u-decoder-parity/c-trailing-bits-accepted",
        payload=None,
        envelope=dirty,
        envelope_raw=None,
        trust=trust,
        expected=dict(accepted),
    )


# --- vector 23: revocation-refund-window ------------------------------------


def gen_23_revocation_refund_window() -> None:
    """A `revocability: "refund_window"` receipt with `revocation_window_days
    = REFUND_WINDOW_DAYS` (14): per verify.py:359-367 a revocation record is
    effective iff `revoked_at <= issued_at + revocation_window_days`, i.e.
    ISSUED_AT 2025-07-02 -> window end 2025-07-16. (a) REVOKED_INSIDE_WINDOW_AT
    (2025-07-10) is inside the window -> effective, `revocation: "revoked"`,
    `ok: False`. (b) REVOKED_AT (2025-08-01) is outside -> the record is
    ignored, `revocation: "invalid_revocation_ignored"`, a warning is
    emitted, and `ok` is UNAFFECTED (`True`). Both records are otherwise
    authenticated and well-formed (`verify_record` asserted True at
    generation time) so the boundary is exercised purely on the refund-window
    comparison, mirroring the `revoked_policy` / `revocation_against_none`
    generation-time discipline (vectors 15/16)."""
    payload = issue.build_payload(
        **_base_payload_kwargs(
            revocability="refund_window", revocation_window_days=REFUND_WINDOW_DAYS
        )
    )
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    issuer_manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    trust = _trust_material((ISSUER_ID, issuer_manifest, "tls"))

    record_inside = revocation.build_record(
        RECEIPT_ID, "revoked", REVOKED_INSIDE_WINDOW_AT, ISSUER_KP, ISSUER_KID
    )
    assert revocation.verify_record(record_inside, issuer_manifest) is True
    expected_a = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "revoked",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "23-revocation-refund-window/a-inside-window",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected_a,
        revocation_record=record_inside,
    )

    record_after = revocation.build_record(RECEIPT_ID, "revoked", REVOKED_AT, ISSUER_KP, ISSUER_KID)
    assert (
        revocation.verify_record(record_after, issuer_manifest) is True
    )  # authenticated, but ignored
    expected_b = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "invalid_revocation_ignored",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["outside refund window"],
    }
    write_vector(
        "23-revocation-refund-window/b-after-window",
        payload=None,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected_b,
        revocation_record=record_after,
    )


def gen_24_canonical_roundtrip() -> None:
    """A plain valid receipt that additionally commits its payload's exact
    canonical bytes; both primary runners must reproduce them byte-for-byte
    (see the runner docstrings). ASCII here; vectors 21 f/g carry the same
    file for the supplementary-plane hard case."""
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "24-canonical-roundtrip",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=_issuer_only_trust(),
        expected=expected,
        canonical=canon.canonical_bytes(payload),
    )


def _sign_manually(payload: dict[str, Any]) -> dict[str, Any]:
    """Build a signature envelope the way `issue.issue` does internally,
    bypassing its schema-validity gate. Used only for vector 25, whose
    payloads are deliberately schema-invalid but still JCS-signable (see
    `gen_25_schema_parity`)."""
    payload_bytes = canon.canonical_bytes(payload)
    sig = keys.sign(payload_bytes, ISSUER_KP)
    return {
        "payload": payload,
        "signatures": [{"kid": ISSUER_KID, "alg": "Ed25519", "sig": keys.b64u(sig)}],
    }


def gen_25_schema_parity() -> None:
    """Direct regressions for the two schema drifts the 2026-07-13 review
    caught: work.edition accepting non-strings in schema.ts (must-fix #5)
    and the ULID regex accepting a first char > '7' (must-fix #7, pattern
    ^[0-7][0-9A-HJKMNP-TV-Z]{25}$ in both schema implementations). Both
    payloads are mutated to be schema-invalid AFTER `build_payload` but
    BEFORE signing (JCS accepts ints and any string) -- `issue.issue`
    itself would reject them at its schema gate, so the envelope is built
    manually via `_sign_manually`, isolating the schema check from the
    signature check."""
    trust = _issuer_only_trust()

    # (a) work.edition as an int
    payload_a = issue.build_payload(**_base_payload_kwargs())
    payload_a["work"]["edition"] = 7
    violations_a = validate.validate_payload(payload_a)
    assert any("edition" in v for v in violations_a), violations_a
    envelope_a = _sign_manually(payload_a)
    expected_a = {
        "signature": "valid",
        "schema": "invalid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["edition"],
        "warnings": [],
    }
    write_vector(
        "25-schema-parity/a-edition-nonstring",
        payload=payload_a,
        envelope=envelope_a,
        envelope_raw=None,
        trust=trust,
        expected=expected_a,
    )

    # (b) receipt_id first char '8' (> 128-bit ULID timestamp prefix)
    payload_b = issue.build_payload(**_base_payload_kwargs())
    payload_b["receipt_id"] = "8" + RECEIPT_ID[1:]
    violations_b = validate.validate_payload(payload_b)
    assert any("receipt_id" in v for v in violations_b), violations_b
    envelope_b = _sign_manually(payload_b)
    expected_b = {
        "signature": "valid",
        "schema": "invalid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": ["receipt_id"],
        "warnings": [],
    }
    write_vector(
        "25-schema-parity/b-ulid-first-char",
        payload=payload_b,
        envelope=envelope_b,
        envelope_raw=None,
        trust=trust,
        expected=expected_b,
    )


# --- vector 26: hybrid (v0.2 Ed25519+ML-DSA-65) conformance (8 sub-cases) ----


def gen_26_hybrid() -> None:
    """v0.2 hybrid envelope conformance (design Task 8/9): the receipt carries
    two ordered signatures over the same canonical payload bytes, Ed25519
    then ML-DSA-65, both required (AND semantics, `verify.py` §step-1
    hybrid path). ML-DSA-65 signing here goes through the deterministic
    dev oracle (`dilithium_py`, `_oracle_sign`), never `pq.sign`/pqcrypto
    (verified non-deterministic live 2026-07-17) — `issue.issue()` and
    `manifests.build_key_manifest`'s hybrid path are therefore never used
    to produce vector material; every hybrid envelope/manifest below is
    built by the local `_hybrid_envelope`/`_hybrid_manifest` helpers instead."""
    assert manifests.verify_key_manifest(_hybrid_manifest(ISSUER_ID, ISSUER_KID, ISSUER_KP))

    payload = issue.build_payload(**_base_payload_kwargs(attest_version="0.2"))
    _assert_schema_valid(payload)
    hybrid_manifest = _hybrid_manifest(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    hybrid_trust = _trust_material((ISSUER_ID, hybrid_manifest, "tls"))

    # (a) all-valid baseline.
    envelope_a = _hybrid_envelope(payload, ISSUER_KP, ISSUER_KID)
    expected_a = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "26-hybrid/a-valid-hybrid",
        payload=payload,
        envelope=envelope_a,
        envelope_raw=None,
        trust=hybrid_trust,
        expected=expected_a,
    )

    invalid_hybrid_base = {
        "signature": "invalid",
        "schema": "not_checked",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "warnings": [],
    }

    # (b) Ed25519 leg tampered: the ML-DSA-65 leg alone can't save it.
    envelope_b = copy.deepcopy(envelope_a)
    envelope_b["signatures"][0]["sig"] = _flip_sig_byte(envelope_b["signatures"][0]["sig"])
    expected_b = dict(invalid_hybrid_base)
    expected_b["errors_contains"] = ["signature verification failed"]
    write_vector(
        "26-hybrid/b-ed25519-leg-tampered",
        payload=None,
        envelope=envelope_b,
        envelope_raw=None,
        trust=hybrid_trust,
        expected=expected_b,
    )

    # (c) ML-DSA-65 leg tampered: the Ed25519 leg alone can't save it either.
    envelope_c = copy.deepcopy(envelope_a)
    envelope_c["signatures"][1]["sig"] = _flip_sig_byte(envelope_c["signatures"][1]["sig"])
    expected_c = dict(invalid_hybrid_base)
    expected_c["errors_contains"] = ["ML-DSA-65 signature verification failed"]
    write_vector(
        "26-hybrid/c-mldsa-leg-tampered",
        payload=None,
        envelope=envelope_c,
        envelope_raw=None,
        trust=hybrid_trust,
        expected=expected_c,
    )

    # (d) ML-DSA-65 leg entirely missing: only one signature entry present.
    envelope_d = copy.deepcopy(envelope_a)
    envelope_d["signatures"] = envelope_d["signatures"][:1]
    expected_d = dict(invalid_hybrid_base)
    expected_d["errors_contains"] = ["hybrid envelope requires exactly two signatures"]
    write_vector(
        "26-hybrid/d-mldsa-leg-missing",
        payload=None,
        envelope=envelope_d,
        envelope_raw=None,
        trust=hybrid_trust,
        expected=expected_d,
    )

    # (e) both legs claim alg "Ed25519" — order/identity of algs is pinned,
    # never inferred from the second entry's own claim.
    envelope_e = copy.deepcopy(envelope_a)
    envelope_e["signatures"][1]["alg"] = "Ed25519"
    expected_e = dict(invalid_hybrid_base)
    expected_e["errors_contains"] = ["hybrid envelope requires algs Ed25519 and ML-DSA-65 in order"]
    write_vector(
        "26-hybrid/e-duplicate-ed25519-alg",
        payload=None,
        envelope=envelope_e,
        envelope_raw=None,
        trust=hybrid_trust,
        expected=expected_e,
    )

    # (f) the two legs claim different kids.
    envelope_f = copy.deepcopy(envelope_a)
    envelope_f["signatures"][1]["kid"] = ISSUER_KID + "#ml-dsa"
    expected_f = dict(invalid_hybrid_base)
    expected_f["errors_contains"] = ["hybrid envelope signatures must share a single kid"]
    write_vector(
        "26-hybrid/f-kid-mismatch-between-legs",
        payload=None,
        envelope=envelope_f,
        envelope_raw=None,
        trust=hybrid_trust,
        expected=expected_f,
    )

    # (g) a structurally valid hybrid envelope, but the resolved key entry is
    # Ed25519-only (no `pub_ml_dsa_65`) — the second leg has nothing to verify
    # against. Substring-only errors_contains (no rendered kid): Python's
    # `{kid!r}` repr and the TS verifier's pyRepr-equivalent are a known,
    # deferred cross-language divergence (2026-07-13 review) — asserting the
    # kid-free suffix keeps this leaf parity-safe across both runtimes.
    ed_only_manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    expected_g = dict(invalid_hybrid_base)
    expected_g["errors_contains"] = ["has no ML-DSA-65 public key"]
    write_vector(
        "26-hybrid/g-key-entry-not-hybrid",
        payload=None,
        envelope=envelope_a,
        envelope_raw=None,
        trust=_trust_material((ISSUER_ID, ed_only_manifest, "tls")),
        expected=expected_g,
    )

    # (h) manifest rotation continuity broken by a downgraded (ed-only)
    # `manifest_signature` on the candidate — the single-manifest RECEIPT
    # path never self-verifies the trust manifest (TOFU §5), so this
    # downgrade is only caught via CONTINUITY (`check_continuity` ->
    # `_verify_signature_block`), not by rejecting the receipt itself: the
    # receipt's own hybrid signature (against v2's still-hybrid key entry)
    # verifies cleanly, and `trust` alone is forced down to
    # "unverified_rotation" (mirrors 14b: a downgrade signal, not a
    # rejection — `ok` excludes `trust` by spec).
    v1 = _hybrid_manifest(ISSUER_ID, ISSUER_KID, ISSUER_KP, version=1)
    v2_body: dict[str, Any] = {
        "issuer": ISSUER_ID,
        "manifest_version": 2,
        "issued_at": ROTATION_ISSUED_AT,
        "keys": [_hybrid_key_entry(ISSUER_KID, ISSUER_KP, status="active")],
    }
    v2_signable = manifests._signable(v2_body)
    v2 = dict(v2_body)
    v2["manifest_signature"] = {
        "kid": ISSUER_KID,
        "sig": keys.b64u(keys.sign(v2_signable, ISSUER_KP)),  # ed-only: sig_ml_dsa_65 omitted
    }
    assert manifests.check_continuity(v1, v2) is False  # downgrade breaks continuity

    payload_h = issue.build_payload(
        **_base_payload_kwargs(attest_version="0.2", issued_at=RECEIPT_ISSUED_AFTER_ROTATION)
    )
    _assert_schema_valid(payload_h)
    envelope_h = _hybrid_envelope(payload_h, ISSUER_KP, ISSUER_KID)
    trust_h = _trust_material((ISSUER_ID, v2, "tls"), chains={ISSUER_ID: [v1, v2]})
    expected_h = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "unverified_rotation",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "26-hybrid/h-manifest-downgraded-continuity",
        payload=payload_h,
        envelope=envelope_h,
        envelope_raw=None,
        trust=trust_h,
        expected=expected_h,
    )


def gen_27_valid_to_absent() -> None:
    entry = manifests.key_entry(ISSUER_KID, ISSUER_KP.pub, KEY_VALID_FROM, None)
    del entry["valid_to"]  # omit the field entirely (not null) — the divergence case
    manifest = manifests.build_key_manifest(
        ISSUER_ID, 1, MANIFEST_ISSUED_AT, [entry], ISSUER_KP, ISSUER_KID
    )
    assert manifests.verify_key_manifest(manifest)  # self-consistent without valid_to
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _trust_material((ISSUER_ID, manifest, "tls"))
    expected = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "27-valid-to-absent",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


def gen_28_transparency() -> None:
    """v0.2 transparency/corroboration conformance corpus (Stage 2, design doc
    "transparency/corroboration layer") — the cross-core corpus pinning
    Tasks 1-7's `tlog`/`anchor`/`transparency` layer end to end, replayed by
    all three runners (Python, TS, site).

    `transparency`/`corroboration`/`manifest_freshness` are ALWAYS
    informational (never affect `ok`/`errors`/`trust`/key-status — design
    fix 6): every leaf below demonstrates that independently, most sharply
    in 28i, where a compromised-key rejection stays fully intact regardless
    of what the log says. Leaves a-g/j-l/n share one v0.1 receipt/issuer-
    manifest pair (`payload`/`envelope`/`entry_a`, built once at the top of
    this function) so only the transparency evidence itself varies between
    them, following this file's existing convention of reusing one payload/
    envelope across many otherwise-independent vectors.
    Leaves h/i/m need their own issuer-manifest material (a v2 manifest with
    no rotation chain, a compromised key, and a hybrid key respectively) and
    build it locally.

    Two leaves are deliberate ADAPTATIONS from the original design vector
    list, documented here and in `docs/spec/vectors/README.md` (2026-07-18
    review should treat these as intentional scope decisions, not gaps):

    - 28k ("rfc3161-only anchor"): the original intent ties this to a
      declared `crqc_horizon` showing "no post-horizon standing". No leaf
      here actually needs `policy.crqc_horizon` set — an rfc3161-only proof
      never sets `pq_surviving`, so `transparency` already stays `"logged"`
      (never upgrades to `anchored_before:<T>`) regardless of horizon
      configuration. What IS pinned: the exact warning literal
      (`RFC3161_WARNING`) and the "no PQ standing" property, which is the
      testable substance of "no post-horizon standing" — a horizon value
      would add configuration, not test coverage, since nothing here reaches
      `anchor.passes_horizon`.
    - 28m ("post-horizon ed-only revocation -> ignored, ties Task 6"):
      `verify.py`'s revocation classification (`_classify_revocation`) has NO
      `crqc_horizon`-shaped parameter anywhere — revocation records and the
      transparency/anchor horizon cap are entirely separate subsystems, so a
      literal "post-horizon revocation" cannot be expressed through any
      `verify()` input. Adapted to the mechanism that would have to exist for
      that framing to hold: an Ed25519-only-signed revocation record against
      a HYBRID (`pub_ml_dsa_65`-carrying) issuer key fails the Task 6/8
      AND-rule fail-closed, unconditionally — "ignored" is exactly the
      Task-6 sibling-hybrid property, pinned here at the conformance level
      instead of only in `tests/test_sibling_hybrid_sidedocs.py` /
      `verifiers/ts/test/sibling-hybrid.test.ts`.
    """
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()

    entry_a = {
        "type": "receipt",
        "issuer": ISSUER_ID,
        "core_sha256": tlog.receipt_core_hash(envelope),
    }
    entry_bytes_a = tlog.encode_entry(entry_a)
    root_a = tlog.build_tree([entry_bytes_a])
    checkpoint_a = _sign_checkpoint_oracle(LOG_ORIGIN, 1, root_a)
    inclusion_a = _hex_proof(tlog.inclusion_proof([entry_bytes_a], 0))

    def _evidence_a(**overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "entry": entry_a,
            "leaf_index": 0,
            "tree_size": 1,
            "inclusion_proof": inclusion_a,
            "checkpoint": checkpoint_a,
        }
        base.update(overrides)
        return base

    # Generation-time sanity checks: confirm the hand-built Merkle/checkpoint
    # material actually has the narrow cryptographic property each leaf
    # relies on, BEFORE any of it is asserted (via hand-derived expected.json
    # values, independently reasoned about below) to be committed as a
    # vector. Mirrors this file's existing narrow self-checks (e.g.
    # `assert manifests.check_continuity(v1, v2) is False` in
    # `gen_14_rotation_continuity`) — this checks generator correctness, not
    # `verify()`'s; `expected.json` below is never copied from a live
    # `verify()`/`evaluate_transparency()` call.
    assert tlog.verify_inclusion(tlog.leaf_hash(entry_bytes_a), 0, 1, [], root_a)

    # --- (a) logged, trust-unchanged: the baseline "this receipt is in the
    # log" claim, everything valid. Deliberately use TOFU/bundle provenance:
    # glowing, valid log evidence MUST NOT upgrade trust, so this leaf pins
    # `unauthenticated_tofu` staying TOFU even when the receipt is logged. ---
    trust_a = _trust_material(
        (ISSUER_ID, _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP), "bundle")
    )
    write_vector(
        "28-transparency/a-logged-trust-unchanged",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust_a,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "unauthenticated_tofu",
            "transparency": "logged",
            "corroboration": "logged",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": [],
        },
        transparency=_evidence_a(),
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (b) wrong root: a validly hybrid-signed checkpoint, but for a tree
    # that does not actually contain this entry -> inclusion proof fails. ---
    wrong_root = hashlib.sha256(b"attest-vectors-28b-wrong-root-v1").digest()
    checkpoint_b = _sign_checkpoint_oracle(LOG_ORIGIN, 1, wrong_root)
    assert not tlog.verify_inclusion(tlog.leaf_hash(entry_bytes_a), 0, 1, [], wrong_root)
    write_vector(
        "28-transparency/b-wrong-root",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "not_checked",
            "corroboration": "none",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": ["inclusion_proof_invalid"],
        },
        transparency=_evidence_a(checkpoint=checkpoint_b),
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (c) ed-only checkpoint: a genuine Ed25519 signature line, but no
    # ML-DSA-65 leg at all -> checkpoint auth is hybrid, MANDATORY (design
    # doc), so this grants no standing whatsoever. ---
    checkpoint_c = _sign_checkpoint_ed_only(LOG_ORIGIN, 1, root_a)
    write_vector(
        "28-transparency/c-ed-only-checkpoint",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "not_checked",
            "corroboration": "none",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": ["checkpoint_verification_failed"],
        },
        transparency=_evidence_a(checkpoint=checkpoint_c),
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (d) origin-mismatch log key: a genuinely hybrid-signed checkpoint
    # by the SAME log key material, but claiming a different origin than the
    # one pinned in log_keys -> no pinned candidate verifies. ---
    checkpoint_d = _sign_checkpoint_oracle(WRONG_LOG_ORIGIN, 1, root_a)
    write_vector(
        "28-transparency/d-origin-mismatch-log-key",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "not_checked",
            "corroboration": "none",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": ["checkpoint_verification_failed"],
        },
        transparency=_evidence_a(checkpoint=checkpoint_d),
        log_keys=[_log_key(LOG_ORIGIN)],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (e) valid consistency: a two-leaf tree, entry_a at index 1, plus a
    # verifying prior checkpoint (tree_size 1) and a genuine consistency
    # proof against the current (tree_size 2) checkpoint -> still just
    # "logged" (consistency alone never upgrades standing, it only rules out
    # equivocation). ---
    filler_entry = {
        "type": "receipt",
        "issuer": ISSUER_ID,
        "core_sha256": hashlib.sha256(b"attest-vectors-28e-filler-leaf-v1").hexdigest(),
    }
    leaves_e = [tlog.encode_entry(filler_entry), entry_bytes_a]
    root1_e = tlog.build_tree(leaves_e[:1])
    root2_e = tlog.build_tree(leaves_e)
    inclusion_e = _hex_proof(tlog.inclusion_proof(leaves_e, 1))
    consistency_e = _hex_proof(tlog.consistency_proof(leaves_e, 1))
    prior_checkpoint_e = _sign_checkpoint_oracle(LOG_ORIGIN, 1, root1_e)
    checkpoint_e = _sign_checkpoint_oracle(LOG_ORIGIN, 2, root2_e)
    assert tlog.verify_inclusion(
        tlog.leaf_hash(entry_bytes_a), 1, 2, tlog.inclusion_proof(leaves_e, 1), root2_e
    )
    assert tlog.verify_consistency(1, root1_e, 2, root2_e, tlog.consistency_proof(leaves_e, 1))
    write_vector(
        "28-transparency/e-consistency-ok",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "logged",
            "corroboration": "logged",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": [],
        },
        transparency=_evidence_a(
            leaf_index=1,
            tree_size=2,
            inclusion_proof=inclusion_e,
            checkpoint=checkpoint_e,
            prior_checkpoint=prior_checkpoint_e,
            consistency_proof=consistency_e,
        ),
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (f) equivocation_detected: a validly hybrid-signed prior checkpoint
    # claiming the SAME tree_size (1) as the current checkpoint but a
    # DIFFERENT root -> proof the log signed two incompatible histories for
    # the same size (a hard verdict, not fail-safe degradation). ---
    equivocation_root = hashlib.sha256(b"attest-vectors-28f-equivocation-root-v1").digest()
    prior_checkpoint_f = _sign_checkpoint_oracle(LOG_ORIGIN, 1, equivocation_root)
    assert equivocation_root != root_a
    write_vector(
        "28-transparency/f-equivocation-detected",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "equivocation_detected",
            "corroboration": "none",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": ["log_equivocation_detected"],
        },
        transparency=_evidence_a(prior_checkpoint=prior_checkpoint_f, consistency_proof=[]),
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (g) entry hash mismatch: the evidence's `entry` disagrees with the
    # hash verify() independently computes from the actual receipt ->
    # transparency_entry_mismatch, regardless of an otherwise-valid
    # checkpoint/proof. ---
    wrong_hash_g = hashlib.sha256(b"attest-vectors-28g-unrelated-v1").hexdigest()
    entry_g = dict(entry_a, core_sha256=wrong_hash_g)
    assert wrong_hash_g != tlog.receipt_core_hash(envelope)
    write_vector(
        "28-transparency/g-entry-hash-mismatch",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "not_checked",
            "corroboration": "none",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": ["transparency_entry_mismatch"],
        },
        transparency=_evidence_a(entry=entry_g),
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (h) rotation-chain omitted: a self-consistent manifest_version=2
    # issuer manifest, logged as a key-manifest claim, but the trust store
    # holds NO rotation chain for this issuer at all -> corroboration cannot
    # validate the rotation, downgraded to "none" with a warning, even
    # though the log standing itself ("logged") and manifest_freshness are
    # unaffected. ---
    v2_manifest = manifests.build_key_manifest(
        ISSUER_ID,
        2,
        MANIFEST_ISSUED_AT,
        [manifests.key_entry(ISSUER_KID, ISSUER_KP.pub, KEY_VALID_FROM, None, "active")],
        ISSUER_KP,
        ISSUER_KID,
    )
    assert manifests.verify_key_manifest(v2_manifest)
    manifest_sha256_h = hashlib.sha256(canon.canonical_bytes(v2_manifest)).hexdigest()
    entry_h = {
        "type": "key-manifest",
        "issuer": ISSUER_ID,
        "manifest_version": 2,
        "manifest_sha256": manifest_sha256_h,
    }
    entry_bytes_h = tlog.encode_entry(entry_h)
    root_h = tlog.build_tree([entry_bytes_h])
    checkpoint_h = _sign_checkpoint_oracle(LOG_ORIGIN, 1, root_h)
    trust_h = _trust_material((ISSUER_ID, v2_manifest, "tls"))  # chains omitted (Task-8 default)
    write_vector(
        "28-transparency/h-rotation-chain-omitted",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust_h,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "logged",
            "corroboration": "none",
            "manifest_freshness": "verified_as_of:1",
            "ok": True,
            "errors": [],
            "warnings": ["corroboration_requires_rotation_chain"],
        },
        transparency={
            "entry": entry_h,
            "leaf_index": 0,
            "tree_size": 1,
            "inclusion_proof": _hex_proof(tlog.inclusion_proof([entry_bytes_h], 0)),
            "checkpoint": checkpoint_h,
        },
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (i) old logged manifest vs compromised key: transparency/
    # corroboration are resolved BEFORE the receipt's own pass/fail verdict
    # (design fix 6) — a receipt rejected outright for a compromised
    # signing key must still report whatever standing its OWN evidence
    # earns, proving corroboration can never rescue an otherwise-invalid
    # receipt. Reuses entry_a/checkpoint_a (the SAME envelope as (a)); only
    # the issuer manifest's key status differs. ---
    manifest_compromised = _manifest_material(
        ISSUER_ID, ISSUER_KID, ISSUER_KP, status="compromised"
    )
    assert manifests.verify_key_manifest(manifest_compromised)  # self-consistent, unlike vector 11
    trust_i = _trust_material((ISSUER_ID, manifest_compromised, "tls"))
    write_vector(
        "28-transparency/i-compromised-key-fail-closed",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust_i,
        expected={
            "signature": "invalid",
            "schema": "not_checked",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "logged",
            "corroboration": "logged",
            "manifest_freshness": "not_checked",
            "ok": False,
            "errors_contains": ["compromised"],
            "warnings": [],
        },
        transparency=_evidence_a(),
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (j) receipt core + OTS anchor: a PQ-surviving `ots` proof replaying
    # from SHA-256(checkpoint.note_bytes) to a pinned Bitcoin header ->
    # transparency upgrades to anchored_before:<ISO-8601 UTC>. header_time
    # 1700000000 is transparency.py's own documented KAT
    # (_iso8601: 1700000000 -> "2023-11-14T22:13:20Z"). No `anchor_profile`
    # on the anchors evidence -> legacy note-bytes-only commitment (G4,
    # attest-v0.2.md §11.1), still fully verifiable but classified with
    # warning `anchor_note_only` (32-anchor-v2's `c-v1-note-only-warn`
    # exercises the same classification directly against `verify_anchor`). ---
    header_hash_j = hashlib.sha256(b"attest-vectors-28j-anchor-header-v1").hexdigest()
    accumulator_start_j = hashlib.sha256(tlog.parse_checkpoint(checkpoint_a).note_bytes).digest()
    header_merkle_root_j = hashlib.sha256(accumulator_start_j).digest().hex()
    header_time_j = 1700000000
    ots_proof_j = {
        "kind": "ots",
        "ops": [["sha256"]],
        "header_merkle_root": header_merkle_root_j,
        "header_hash": header_hash_j,
        "header_time": header_time_j,
    }
    policy_j = anchor.AnchorPolicy(
        pinned_headers={
            header_hash_j: anchor.PinnedHeader(
                header_hash=header_hash_j, merkle_root=header_merkle_root_j, time=header_time_j
            )
        },
        crqc_horizon=None,
    )
    write_vector(
        "28-transparency/j-ots-anchor",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "anchored_before:2023-11-14T22:13:20Z",
            "corroboration": "logged",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": ["anchor_note_only"],
        },
        transparency=_evidence_a(anchors={"checkpoint": checkpoint_a, "proofs": [ots_proof_j]}),
        log_keys=[_log_key()],
        anchor_policy=policy_j,
    )

    # --- (k) rfc3161-only anchor: opaque classical corroboration only ->
    # never sets pq_surviving, so transparency stays "logged" (no PQ/
    # post-horizon standing) — see the ADAPTATION note in this function's
    # docstring for why no crqc_horizon is needed to demonstrate that. ---
    rfc3161_proof_k = {
        "kind": "rfc3161",
        "token_b64": base64.b64encode(b"attest-vectors-28k-fake-tsa-token").decode("ascii"),
    }
    write_vector(
        "28-transparency/k-rfc3161-only",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "logged",
            "corroboration": "logged",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": [anchor._RFC3161_WARNING],
        },
        transparency=_evidence_a(anchors={"checkpoint": checkpoint_a, "proofs": [rfc3161_proof_k]}),
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (l) payload-only precommit hash: the entry's core_sha256 is hashed
    # over the PAYLOAD alone (no domain separation, no signature
    # commitment) — exactly the "pre-sign, log now, sign later" attack
    # `tlog.receipt_core_hash`'s domain separation defeats (design vector
    # 28l's property, named in that function's own docstring). Same
    # observable outcome as (g) (transparency_entry_mismatch), different
    # attacker narrative: this is not an arbitrary wrong hash, it is
    # SPECIFICALLY the hash an attacker could have computed before the
    # receipt was ever signed. ---
    payload_only_hash_l = hashlib.sha256(canon.canonical_bytes(payload)).hexdigest()
    entry_l = dict(entry_a, core_sha256=payload_only_hash_l)
    assert payload_only_hash_l != tlog.receipt_core_hash(envelope)
    write_vector(
        "28-transparency/l-payload-only-precommit",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "not_checked",
            "corroboration": "none",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": ["transparency_entry_mismatch"],
        },
        transparency=_evidence_a(entry=entry_l),
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (m) ADAPTED — post-horizon ed-only revocation, expressed as the
    # Task 6/8 sibling-hybrid AND-rule property (see this function's
    # docstring): an Ed25519-only-signed revocation record against a HYBRID
    # issuer key is unconditionally rejected/ignored, no horizon config
    # involved. Uses its own hybrid manifest/envelope (distinct ML-DSA-65
    # key material, seed bytes([30])*32, from the log's own key material). ---
    m_hybrid_entry = manifests.key_entry(
        ISSUER_KID, ISSUER_KP.pub, KEY_VALID_FROM, None, "active", pub_ml_dsa_65=VECTOR_28M_MLDSA_PK
    )
    m_manifest_body: dict[str, Any] = {
        "issuer": ISSUER_ID,
        "manifest_version": 1,
        "issued_at": MANIFEST_ISSUED_AT,
        "keys": [m_hybrid_entry],
    }
    m_signable = manifests._signable(m_manifest_body)
    m_hybrid_manifest = dict(m_manifest_body)
    m_hybrid_manifest["manifest_signature"] = {
        "kid": ISSUER_KID,
        "sig": keys.b64u(keys.sign(m_signable, ISSUER_KP)),
        "sig_ml_dsa_65": keys.b64u(
            ML_DSA_65.sign(VECTOR_28M_MLDSA_SK, m_signable, deterministic=True)
        ),
    }
    assert manifests.verify_key_manifest(m_hybrid_manifest)

    payload_m = issue.build_payload(
        **_base_payload_kwargs(attest_version="0.2", revocability="policy")
    )
    _assert_schema_valid(payload_m)
    # NOT `_hybrid_envelope`: that helper signs the ML-DSA-65 leg with the
    # shared group-26 oracle key (`HYBRID_MLDSA_SK`, seed bytes([26])*32),
    # which does not match this leaf's OWN issuer key material
    # (`VECTOR_28M_MLDSA_SK`, seed bytes([30])*32) — signing with the wrong
    # secret key here would make the receipt's own ML-DSA-65 leg invalid
    # against `m_hybrid_manifest`, unrelated to what this leaf tests.
    canonical_m = canon.canonical_bytes(payload_m)
    envelope_m = {
        "payload": payload_m,
        "signatures": [
            {
                "kid": ISSUER_KID,
                "alg": "Ed25519",
                "sig": keys.b64u(keys.sign(canonical_m, ISSUER_KP)),
            },
            {
                "kid": ISSUER_KID,
                "alg": pq.ML_DSA_65_ALG,
                "sig": keys.b64u(
                    ML_DSA_65.sign(VECTOR_28M_MLDSA_SK, canonical_m, deterministic=True)
                ),
            },
        ],
    }
    trust_m = _trust_material((ISSUER_ID, m_hybrid_manifest, "tls"))

    ed_only_record_m = revocation.build_record(
        RECEIPT_ID, "revoked", REVOKED_AT, ISSUER_KP, ISSUER_KID
    )
    assert "sig_ml_dsa_65" not in ed_only_record_m["signature"]
    assert (
        revocation.verify_record(ed_only_record_m, m_hybrid_manifest) is False
    )  # AND rule, fail-closed

    write_vector(
        "28-transparency/m-hybrid-revocation-and-rule",
        payload=payload_m,
        envelope=envelope_m,
        envelope_raw=None,
        trust=trust_m,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            # No transparency evidence fed for this leaf (it tests the
            # revocation AND rule, not transparency) — these stay at their
            # ZERO-behavior-change defaults, asserted explicitly for
            # consistency with every other group-28 leaf.
            "transparency": "not_checked",
            "corroboration": "none",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": [f"revocation record for {RECEIPT_ID!r} failed verification, ignored"],
        },
        revocation_record=ed_only_record_m,
    )

    # --- (n) unknown entry type: an entry whose `type` the log's closed
    # schema doesn't recognize -> the claim is unresolvable before any
    # checkpoint/proof is even consulted; the receipt itself is untouched
    # ("rest verifies": ok stays True). ---
    write_vector(
        "28-transparency/n-unknown-entry-type",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "not_checked",
            "corroboration": "none",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": ["transparency_claim_unresolvable"],
        },
        transparency={"entry": {"type": "witness-cosignature"}},
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )


# --- vector 29 (G1 normative ceilings, attest-versioning.md §5 amendment) ---
#
# Three leaves, each a genuinely-signed envelope rejected purely because it
# crosses one of the new structural ceilings (validate.py/manifests.py) —
# never because of a schema-shape or signature problem otherwise.

_LIMITS_FILLER_SEED_PREFIX = "attest-vector-29c-filler"


def gen_29_limits() -> None:
    # No _gen_29b_nesting_depth() (2026-07-22 fix wave): the nesting-depth
    # ceiling is not a distinct, newly-introduced conformance-surface bound
    # (it aliases canon.py's own pre-existing 256 parse-time cap, see
    # validate.py's MAX_JSON_DEPTH docstring) — its boundary is already
    # exercised by the 21-canon-strict b/c/d triple, so a dedicated leaf
    # here would be redundant with that group.
    _gen_29a_envelope_oversize()
    _gen_29c_manifest_array_overflow()


def _gen_29a_envelope_oversize() -> None:
    """`validate.MAX_ENVELOPE_BYTES` bounds the raw envelope before any
    parsing work — a genuinely signed receipt whose serialized size exceeds
    it is rejected with `schema: "invalid"` at the parse boundary, never
    reaching signature verification. The overage is comfortably over the
    ceiling (no exact-boundary claim): the two conformance runners
    re-serialize `envelope.json` differently (Python's replay test
    re-dumps with `json.dumps` default separators; the TS replay test reads
    the generator's indented file bytes directly) — always BIGGER than the
    Python form, never smaller, so "over" stays "over" in both runners
    regardless of which serialization is measured.
    """
    padding = validate.MAX_ENVELOPE_BYTES + 4096
    payload = issue.build_payload(**_base_payload_kwargs(title="x" * padding))
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    envelope_len = len(json.dumps(envelope).encode("utf-8"))
    assert envelope_len > validate.MAX_ENVELOPE_BYTES, envelope_len
    trust = _issuer_only_trust()
    expected = {
        "signature": "invalid",
        "schema": "invalid",
        "revocation": "unknown",
        "binding": "not_checked",
        # The byte-ceiling check runs BEFORE any parsing, so trust is never
        # resolved from the (never-read) payload.issuer.id — it stays at its
        # TOFU default, same as every other precondition failure in step 0.
        "trust": "unauthenticated_tofu",
        "ok": False,
        "errors_contains": [f"envelope exceeds {validate.MAX_ENVELOPE_BYTES} bytes"],
        "warnings": [],
    }
    write_vector(
        "29-limits/a-envelope-oversize",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


def _gen_29c_manifest_array_overflow() -> None:
    """`manifests.MAX_MANIFEST_KEYS` bounds the issuer key manifest's
    `keys[]` array — checked in `verify.py` right after the manifest is
    resolved from the trust store, before any specific key is looked up in
    it. The receipt itself is genuinely, cleanly signed by a key that IS
    listed in the oversized manifest; only the manifest's own size trips
    rejection."""
    filler_entries = [
        manifests.key_entry(
            f"{ISSUER_ID}/keys/2025-01#ed25519-filler-{i}",
            keys.from_seed(
                hashlib.sha256(f"{_LIMITS_FILLER_SEED_PREFIX}-{i}".encode()).digest()
            ).pub,
            KEY_VALID_FROM,
            None,
            "active",
        )
        for i in range(manifests.MAX_MANIFEST_KEYS)
    ]
    entries = [
        manifests.key_entry(ISSUER_KID, ISSUER_KP.pub, KEY_VALID_FROM, None, "active"),
        *filler_entries,
    ]
    assert len(entries) == manifests.MAX_MANIFEST_KEYS + 1
    oversized_manifest = manifests.build_key_manifest(
        ISSUER_ID, 1, MANIFEST_ISSUED_AT, entries, ISSUER_KP, ISSUER_KID
    )
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _trust_material((ISSUER_ID, oversized_manifest, "tls"))
    expected = {
        "signature": "invalid",
        "schema": "invalid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": False,
        "errors_contains": [f"issuer manifest exceeds {manifests.MAX_MANIFEST_KEYS} keys"],
        "warnings": [],
    }
    write_vector(
        "29-limits/c-manifest-array-overflow",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected=expected,
    )


# --- vector 30 (G6 mixed-keyset prohibition, v0.2 §2.3/§13 amendment) ------

_LEGACY_ED_SEED = bytes([31]) * 32  # Ed25519-only sibling key, continuing the numbering scheme
_LEGACY_ED_KP = keys.from_seed(_LEGACY_ED_SEED)
_LEGACY_KID = f"{ISSUER_ID}/keys/2025-01#ed25519-legacy-1"


def _mixed_keyset_manifest(legacy_status: str) -> dict[str, Any]:
    """A v0.2 key manifest declaring the hybrid suite (`ISSUER_KID`, hybrid,
    always active) alongside an Ed25519-only sibling key (`_LEGACY_KID`)
    whose status is the caller's choice — `"active"` reproduces the
    mixed-keyset condition v0.2 §2.3/§13 prohibits; `"retired"` is the
    clean, completed migration (§13's ceremony: the same
    `manifest_version` bump that introduces the hybrid key retires every
    Ed25519-only key)."""
    entries = [
        _hybrid_key_entry(ISSUER_KID, ISSUER_KP, status="active"),
        manifests.key_entry(_LEGACY_KID, _LEGACY_ED_KP.pub, KEY_VALID_FROM, None, legacy_status),
    ]
    body: dict[str, Any] = {
        "issuer": ISSUER_ID,
        "manifest_version": 1,
        "issued_at": MANIFEST_ISSUED_AT,
        "keys": entries,
    }
    signable = manifests._signable(body)
    body["manifest_signature"] = {
        "kid": ISSUER_KID,
        "sig": keys.b64u(keys.sign(signable, ISSUER_KP)),
        "sig_ml_dsa_65": keys.b64u(_oracle_sign(signable)),
    }
    return body


def gen_30_mixed_keyset() -> None:
    # (a) sibling still active: the mixed-keyset condition is present ->
    # warning, receipt otherwise verifies clean (the warning is the whole
    # contract, v0.2 §2.3/§13 — no result field caps "hybrid strength").
    manifest_a = _mixed_keyset_manifest("active")
    assert manifests.has_active_ed_only_sibling(manifest_a) is True
    payload_a = issue.build_payload(**_base_payload_kwargs(attest_version="0.2"))
    _assert_schema_valid(payload_a)
    envelope_a = _hybrid_envelope(payload_a, ISSUER_KP, ISSUER_KID)
    trust_a = _trust_material((ISSUER_ID, manifest_a, "tls"))
    expected_a = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings_contains": ["mixed_keyset_active_ed_only_sibling"],
    }
    write_vector(
        "30-mixed-keyset/a-active-ed-sibling-warn",
        payload=payload_a,
        envelope=envelope_a,
        envelope_raw=None,
        trust=trust_a,
        expected=expected_a,
    )

    # (b) sibling retired: the migration ceremony completed correctly -> no
    # mixed-keyset condition, no warning.
    manifest_b = _mixed_keyset_manifest("retired")
    assert manifests.has_active_ed_only_sibling(manifest_b) is False
    payload_b = issue.build_payload(**_base_payload_kwargs(attest_version="0.2"))
    _assert_schema_valid(payload_b)
    envelope_b = _hybrid_envelope(payload_b, ISSUER_KP, ISSUER_KID)
    trust_b = _trust_material((ISSUER_ID, manifest_b, "tls"))
    expected_b = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "30-mixed-keyset/b-migrated-clean",
        payload=payload_b,
        envelope=envelope_b,
        envelope_raw=None,
        trust=trust_b,
        expected=expected_b,
    )


# --- vector 31: manifest currency (G2/G3, attest-versioning.md rev 4) ------

# `_base_payload_kwargs`'s own default `artifact_series` — reused verbatim so
# the receipt's `work.artifact_series` matches the artifact manifests' own
# `series` field below (v0.1 §7.2: "series ... Matches work.artifact_series").
_CURRENCY_SERIES = f"{ISSUER_ID}/works/EXG-001"
_CURRENCY_RELEASED_AT_1 = "2025-02-01T00:00:00Z"
_CURRENCY_RELEASED_AT_2 = "2025-03-01T00:00:00Z"


def _currency_artifact_manifest(
    version: int, manifest_version: int | None, released_at: str
) -> dict[str, Any]:
    artifact_entry = {
        "role": "installer",
        "platform": "windows-x86_64",
        "filename": "example-game-1.0-setup.exe",
        "size_bytes": 734003200,
        "sha256": ARTIFACT_SHA256,
    }
    return manifests.build_artifact_manifest(
        ISSUER_ID,
        _CURRENCY_SERIES,
        version,
        released_at,
        [artifact_entry],
        ISSUER_KP,
        ISSUER_KID,
        manifest_version=manifest_version,
    )


def gen_31_manifest_currency() -> None:
    """G2 (artifact manifest `manifest_version`) + G3 (newest-seen rule),
    attest-versioning.md rev 4 / v0.1 §7.2-§7.3 amendment. All five leaves
    share one receipt (the artifact-manifest currency check is independent
    of the receipt's own signature/schema verdict — only `trust`/`warnings`
    move) and one issuer key manifest; only the artifact-manifest trust
    material under `manifests.json` differs per leaf."""
    key_manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    am1 = _currency_artifact_manifest(1, 1, _CURRENCY_RELEASED_AT_1)
    am2 = _currency_artifact_manifest(2, 2, _CURRENCY_RELEASED_AT_2)
    assert manifests.check_artifact_continuity(am1, am2) is True
    assert manifests.check_artifact_continuity(am2, am1) is False

    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)

    # (a) rollback-rejected: the trust store's own artifact-manifest chain
    # history already holds am2, but the manifest currently PINNED for the
    # series is the OLDER am1 (a rollback attempt, or a stale re-import) —
    # mirrors vector 14b's key-manifest discontinuity shape, applied to
    # artifact manifests.
    trust_a = _trust_material(
        (ISSUER_ID, key_manifest, "tls"),
        artifact_manifests={ISSUER_ID: {_CURRENCY_SERIES: am1}},
        artifact_manifest_chains={ISSUER_ID: {_CURRENCY_SERIES: [am1, am2]}},
    )
    expected_a = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "unverified_rotation",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "31-manifest-currency/a-rollback-rejected",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust_a,
        expected=expected_a,
    )

    # (b) monotone-ok: the pinned manifest IS the chain tail (am2) -> normal,
    # provenance-derived trust; no currency violation.
    trust_b = _trust_material(
        (ISSUER_ID, key_manifest, "tls"),
        artifact_manifests={ISSUER_ID: {_CURRENCY_SERIES: am2}},
        artifact_manifest_chains={ISSUER_ID: {_CURRENCY_SERIES: [am1, am2]}},
    )
    expected_b = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": [],
    }
    write_vector(
        "31-manifest-currency/b-monotone-ok",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust_b,
        expected=expected_b,
    )

    # (c) legacy-unversioned-warn: the pinned manifest predates this
    # amendment (no `manifest_version`) -> warned, never rejected (eternal
    # verifiability, attest-versioning.md §3).
    am_legacy = _currency_artifact_manifest(1, None, _CURRENCY_RELEASED_AT_1)
    assert "manifest_version" not in am_legacy
    trust_c = _trust_material(
        (ISSUER_ID, key_manifest, "tls"),
        artifact_manifests={ISSUER_ID: {_CURRENCY_SERIES: am_legacy}},
    )
    expected_c = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": ["artifact_manifest_unversioned"],
    }
    write_vector(
        "31-manifest-currency/c-legacy-unversioned-warn",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust_c,
        expected=expected_c,
    )

    # (d) unauthenticated-ignored: a previously valid v1 followed by an
    # unsigned v2 must not influence currency or trust at all.
    am2_unsigned = dict(am2)
    del am2_unsigned["manifest_signature"]
    trust_d = _trust_material(
        (ISSUER_ID, key_manifest, "tls"),
        artifact_manifests={ISSUER_ID: {_CURRENCY_SERIES: am2_unsigned}},
        artifact_manifest_chains={ISSUER_ID: {_CURRENCY_SERIES: [am1, am2_unsigned]}},
    )
    expected_d = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": ["artifact_manifest_unauthenticated"],
    }
    write_vector(
        "31-manifest-currency/d-unauthenticated-ignored",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust_d,
        expected=expected_d,
    )

    # (e) legacy-transition-warn-only: the first versioned manifest after a
    # legacy one is accepted; the legacy member's absence is the only signal.
    am_first_versioned = _currency_artifact_manifest(2, 1, _CURRENCY_RELEASED_AT_2)
    trust_e = _trust_material(
        (ISSUER_ID, key_manifest, "tls"),
        artifact_manifests={ISSUER_ID: {_CURRENCY_SERIES: am_first_versioned}},
        artifact_manifest_chains={ISSUER_ID: {_CURRENCY_SERIES: [am_legacy, am_first_versioned]}},
    )
    expected_e = {
        "signature": "valid",
        "schema": "valid",
        "revocation": "unknown",
        "binding": "not_checked",
        "trust": "verified",
        "ok": True,
        "errors": [],
        "warnings": ["artifact_manifest_unversioned"],
    }
    write_vector(
        "31-manifest-currency/e-legacy-transition-warn-only",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust_e,
        expected=expected_e,
    )


def gen_32_anchor_v2() -> None:
    """G4 (anchor profile v2, attest-v0.2.md §11.1): the OTS commitment
    covers the checkpoint's FULL signed note (header AND signature lines,
    `Checkpoint.signed_note_bytes`) instead of just its unsigned header
    (`note_bytes`) — closing TM-33's residual risk that a chosen unsigned
    note can be pre-anchored and signed later. One receipt/checkpoint
    fixture (independent of group 28's own `entry_a`/`checkpoint_a`, built
    fresh here so this group stands alone) with three OTS anchor evidence
    variants, all against the SAME checkpoint:

    - (a) declares `anchor_profile: "signed-note-v2"` and the op-chain
      genuinely commits over `signed_note_bytes` -> verifies cleanly, no
      note-only warning.
    - (b) also declares `"signed-note-v2"`, but the op-chain was built from
      `SHA-256(note_bytes)` alone (the OLD v1 seed) -> the replayed chain
      lands on a different root than pinned, so the anchor FAILS — the
      direct demonstration that a v1-shaped commitment cannot pass as v2
      proof of the signed note's existence (TM-33's mitigation, negative
      case).
    - (c) declares no `anchor_profile` at all (legacy) with a genuinely
      v1-shaped (`note_bytes`-only) op-chain -> verifies and upgrades
      standing exactly like pre-G4 evidence always has (eternal
      verifiability, attest-versioning.md §3), but now carries the
      `anchor_note_only` warning classifying it as the weaker profile.
    """
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()

    entry = {
        "type": "receipt",
        "issuer": ISSUER_ID,
        "core_sha256": tlog.receipt_core_hash(envelope),
    }
    entry_bytes = tlog.encode_entry(entry)
    root = tlog.build_tree([entry_bytes])
    checkpoint_text = _sign_checkpoint_oracle(LOG_ORIGIN, 1, root)
    inclusion = _hex_proof(tlog.inclusion_proof([entry_bytes], 0))
    parsed_checkpoint = tlog.parse_checkpoint(checkpoint_text)
    note_bytes = parsed_checkpoint.note_bytes
    signed_note_bytes = parsed_checkpoint.signed_note_bytes
    assert signed_note_bytes != note_bytes  # sanity: the v2 seed is strictly more bytes

    def _evidence(**overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "entry": entry,
            "leaf_index": 0,
            "tree_size": 1,
            "inclusion_proof": inclusion,
            "checkpoint": checkpoint_text,
        }
        base.update(overrides)
        return base

    header_time = 1700000000  # transparency.py's own documented KAT (-> 2023-11-14T22:13:20Z)

    def _single_hash_ots_proof(
        commitment_bytes: bytes, header_hash_seed: bytes
    ) -> tuple[dict[str, Any], anchor.AnchorPolicy]:
        header_hash = hashlib.sha256(header_hash_seed).hexdigest()
        accumulator_start = hashlib.sha256(commitment_bytes).digest()
        header_merkle_root = hashlib.sha256(accumulator_start).digest().hex()
        proof = {
            "kind": "ots",
            "ops": [["sha256"]],
            "header_merkle_root": header_merkle_root,
            "header_hash": header_hash,
            "header_time": header_time,
        }
        policy = anchor.AnchorPolicy(
            pinned_headers={
                header_hash: anchor.PinnedHeader(
                    header_hash=header_hash, merkle_root=header_merkle_root, time=header_time
                )
            },
            crqc_horizon=None,
        )
        return proof, policy

    # --- (a) v2-valid ---
    ots_proof_a, policy_a = _single_hash_ots_proof(
        signed_note_bytes, b"attest-vectors-32a-v2-header-v1"
    )
    write_vector(
        "32-anchor-v2/a-v2-valid",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "anchored_before:2023-11-14T22:13:20Z",
            "corroboration": "logged",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": [],
        },
        transparency=_evidence(
            anchors={
                "checkpoint": checkpoint_text,
                "proofs": [ots_proof_a],
                "anchor_profile": "signed-note-v2",
            }
        ),
        log_keys=[_log_key()],
        anchor_policy=policy_a,
    )

    # --- (b) v2-commit-mismatch ---
    ots_proof_b, policy_b = _single_hash_ots_proof(
        note_bytes, b"attest-vectors-32b-v1-shaped-header-v1"
    )
    assert ots_proof_b["header_merkle_root"] != ots_proof_a["header_merkle_root"]
    write_vector(
        "32-anchor-v2/b-v2-commit-mismatch",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "logged",
            "corroboration": "logged",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": [
                "proof[0]: ots op-chain result does not match header_merkle_root; anchor_profile "
                "signed-note-v2 requires the accumulator to start from "
                "SHA256(checkpoint.signed_note_bytes) — this evidence looks like a note-v1 "
                "commitment presented as signed-note-v2"
            ],
        },
        transparency=_evidence(
            anchors={
                "checkpoint": checkpoint_text,
                "proofs": [ots_proof_b],
                "anchor_profile": "signed-note-v2",
            }
        ),
        log_keys=[_log_key()],
        anchor_policy=policy_b,
    )

    # --- (c) v1-note-only-warn ---
    ots_proof_c, policy_c = _single_hash_ots_proof(note_bytes, b"attest-vectors-32c-v1-header-v1")
    write_vector(
        "32-anchor-v2/c-v1-note-only-warn",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": "anchored_before:2023-11-14T22:13:20Z",
            "corroboration": "logged",
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": ["anchor_note_only"],
        },
        transparency=_evidence(anchors={"checkpoint": checkpoint_text, "proofs": [ots_proof_c]}),
        log_keys=[_log_key()],
        anchor_policy=policy_c,
    )


def gen_33_logged_revocation() -> None:
    """G5 (v0.2 §8/§15 amendment, TM-47): `revocation-record` becomes the
    THIRD loggable entry type, and a `refund_window` revocation record is
    effective ONLY when the verifier is Stage-2 capable (`log_keys`/
    `anchor_policy` supplied — the same gate `28-transparency` already uses)
    AND `revocation_evidence` proves the record's log entry was anchored no
    later than the receipt's own refund-window deadline (`issued_at +
    revocation_window_days`) — closing the backdating gap where an unlogged
    or late-anchored revocation had no contradicting evidence.
    `policy`/`compromised`/`none` classes are UNAFFECTED: logging remains
    optional corroboration for them, never a gate.

    One `refund_window` receipt (`REFUND_WINDOW_DAYS` = 14, `ISSUED_AT`
    2025-07-02T13:50:00Z -> deadline 2025-07-16T13:50:00Z) with one
    window-effective record (`REVOKED_INSIDE_WINDOW_AT`, 2025-07-10, reused
    from `23-revocation-refund-window`) drives (a)-(c); (d) is an
    independent `policy`-class fixture.

    - (a) `revocation-record` log entry genuinely logged and OTS-anchored
      BEFORE the deadline (header_time = `REVOKED_INSIDE_WINDOW_AT`) ->
      honored, `revocation: "revoked"`.
    - (b) Stage-2-capable verifier (`log_keys`/`anchor_policy` set), but NO
      `revocation_evidence` at all for this record -> never proven logged,
      ignored with `revocation_unlogged_deadline`.
    - (c) `revocation_evidence` present and genuinely verifies, but the OTS
      anchor's pinned header time (`REVOKED_AT`, 2025-08-01) is AFTER the
      deadline -> ignored with the same warning.
    - (d) `policy` class (not `refund_window`): a Stage-2-capable verifier
      with no `revocation_evidence` still honors it — the deadline rule
      never engages for this class.
    """
    payload = issue.build_payload(
        **_base_payload_kwargs(
            revocability="refund_window", revocation_window_days=REFUND_WINDOW_DAYS
        )
    )
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    issuer_manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    trust = _trust_material((ISSUER_ID, issuer_manifest, "tls"))

    record = revocation.build_record(
        RECEIPT_ID, "revoked", REVOKED_INSIDE_WINDOW_AT, ISSUER_KP, ISSUER_KID
    )
    assert revocation.verify_record(record, issuer_manifest) is True

    entry = {
        "type": "revocation-record",
        "issuer": ISSUER_ID,
        "record_sha256": revocation.record_hash(record),
    }
    entry_bytes = tlog.encode_entry(entry)
    root = tlog.build_tree([entry_bytes])
    checkpoint_text = _sign_checkpoint_oracle(LOG_ORIGIN, 1, root)
    inclusion = _hex_proof(tlog.inclusion_proof([entry_bytes], 0))
    signed_note_bytes = tlog.parse_checkpoint(checkpoint_text).signed_note_bytes

    def _revocation_evidence(header_time: int) -> tuple[dict[str, Any], anchor.AnchorPolicy]:
        """A genuine single-`["sha256"]`-op OTS anchor over
        `SHA-256(checkpoint.signed_note_bytes)`, declaring `anchor_profile:
        "signed-note-v2"` (G4, attest-v0.2.md §11.1) — newly produced anchors
        MUST use the v2 commitment, same shape `32-anchor-v2/a-v2-valid`
        uses, just with a caller-chosen (rather than the group-32 KAT) header
        time so it can straddle the refund-window deadline."""
        header_hash = hashlib.sha256(
            f"attest-vectors-33-revocation-header-{header_time}".encode()
        ).hexdigest()
        accumulator_start = hashlib.sha256(signed_note_bytes).digest()
        header_merkle_root = hashlib.sha256(accumulator_start).digest().hex()
        policy = anchor.AnchorPolicy(
            pinned_headers={
                header_hash: anchor.PinnedHeader(
                    header_hash=header_hash, merkle_root=header_merkle_root, time=header_time
                )
            },
            crqc_horizon=None,
        )
        evidence = {
            "entry": entry,
            "leaf_index": 0,
            "tree_size": 1,
            "inclusion_proof": inclusion,
            "checkpoint": checkpoint_text,
            "anchors": {
                "checkpoint": checkpoint_text,
                "proofs": [
                    {
                        "kind": "ots",
                        "ops": [["sha256"]],
                        "header_merkle_root": header_merkle_root,
                        "header_hash": header_hash,
                        "header_time": header_time,
                    }
                ],
                "anchor_profile": "signed-note-v2",
            },
        }
        return evidence, policy

    # --- (a) timely-logged-honored ---
    # REVOKED_INSIDE_WINDOW_AT (2025-07-10T00:00:00Z) as unix seconds — inside
    # the refund-window deadline (2025-07-16T13:50:00Z).
    evidence_a, policy_a = _revocation_evidence(1752105600)
    write_vector(
        "33-logged-revocation/a-timely-logged-honored",
        payload=payload,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "revoked",
            "binding": "not_checked",
            "trust": "verified",
            "ok": False,
            "errors": [],
            "warnings": [],
        },
        revocation_record=record,
        revocation_evidence=evidence_a,
        log_keys=[_log_key()],
        anchor_policy=policy_a,
    )

    # --- (b) unlogged-ignored-warn ---
    write_vector(
        "33-logged-revocation/b-unlogged-ignored-warn",
        payload=None,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "invalid_revocation_ignored",
            "binding": "not_checked",
            "trust": "verified",
            "ok": True,
            "errors": [],
            "warnings": ["revocation_unlogged_deadline"],
        },
        revocation_record=record,
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (c) late-anchor-ignored ---
    # REVOKED_AT (2025-08-01T00:00:00Z) as unix seconds — after the deadline.
    evidence_c, policy_c = _revocation_evidence(1754006400)
    write_vector(
        "33-logged-revocation/c-late-anchor-ignored",
        payload=None,
        envelope=envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "invalid_revocation_ignored",
            "binding": "not_checked",
            "trust": "verified",
            "ok": True,
            "errors": [],
            "warnings": ["revocation_unlogged_deadline"],
        },
        revocation_record=record,
        revocation_evidence=evidence_c,
        log_keys=[_log_key()],
        anchor_policy=policy_c,
    )

    # --- (d) policy-class-unchanged ---
    policy_payload = issue.build_payload(**_base_payload_kwargs(revocability="policy"))
    _assert_schema_valid(policy_payload)
    policy_envelope = issue.issue(policy_payload, ISSUER_KP, ISSUER_KID)
    policy_record = revocation.build_record(
        policy_payload["receipt_id"], "revoked", REVOKED_AT, ISSUER_KP, ISSUER_KID
    )
    assert revocation.verify_record(policy_record, issuer_manifest) is True
    write_vector(
        "33-logged-revocation/d-policy-class-unchanged",
        payload=policy_payload,
        envelope=policy_envelope,
        envelope_raw=None,
        trust=trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "revoked",
            "binding": "not_checked",
            "trust": "verified",
            "ok": False,
            "errors": [],
            "warnings": [],
        },
        revocation_record=policy_record,
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )


# --- vector 35: transfer (v0.2 §17 Stage 3, issuer-mediated transfer) -------


def gen_35_transfer() -> None:
    """v0.2 Stage 3 (§17): issuer-mediated transfer records. Every OLD receipt
    below is `attest_version: "0.2"` with `license.transferable: true` and a
    fixed `buyer.pubkey` (`BUYER_KP`, the OUTGOING holder) — the D1 holder-
    binding precondition (§17.8) transfer backing needs. Since v0.2 always
    requires a hybrid envelope/manifest (verify.py's own step-1 gate), the
    issuer manifest here is `_hybrid_manifest` (26/28's own pattern) and every
    transfer/revocation side-document that must authenticate against it is
    built via `_hybrid_sign_record` (this module's oracle-sign-then-splice
    technique — `manifests.sign_signature_block`'s hybrid path would
    otherwise route the ML-DSA-65 leg through non-deterministic `pq.sign`).

    One shared backing revocation record (`status: "transferred"`, RECEIPT_ID)
    and one shared "fully valid" transfer record/log-evidence pair
    (`record_valid`/`evidence_valid`, genuinely issuer-signed + holder-
    authorized by `BUYER_KP` + logged at a single-entry tree's index 0) drive
    leaves a/b/g; c-h each vary exactly one gate in isolation (see the
    per-leaf comments below). i/j are the D1 (§17.8) schema-conditional
    control pair, independent of everything else in this function.
    """
    hybrid_manifest = _hybrid_manifest(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    assert manifests.verify_key_manifest(hybrid_manifest) is True
    hybrid_trust = _trust_material((ISSUER_ID, hybrid_manifest, "tls"))

    payload_a = issue.build_payload(
        **_base_payload_kwargs(
            attest_version="0.2",
            transferable=True,
            buyer_pubkey=BUYER_KP.pub,
            revocability="policy",
        )
    )
    _assert_schema_valid(payload_a)
    envelope_a = _hybrid_envelope(payload_a, ISSUER_KP, ISSUER_KID)

    payload_b = issue.build_payload(
        **_base_payload_kwargs(
            attest_version="0.2",
            transferable=True,
            buyer_pubkey=BUYER_KP.pub,
            revocability="none",
        )
    )
    _assert_schema_valid(payload_b)
    envelope_b = _hybrid_envelope(payload_b, ISSUER_KP, ISSUER_KID)

    # The old receipt's own backing revocation, `status: "transferred"` —
    # shared across every leaf below (a-h all reuse RECEIPT_ID; each leaf is
    # an independent verify() call in its own vector directory, so reusing
    # the exact same record bytes across several `revocation.json` files is
    # safe, mirroring group 33's own reuse discipline).
    rev_transferred = _hybrid_sign_record(
        {"receipt_id": RECEIPT_ID, "status": "transferred", "revoked_at": TRANSFERRED_AT}
    )
    assert revocation.verify_record(rev_transferred, hybrid_manifest) is True

    new_holder_pub_b64u = keys.b64u(TRANSFER_NEW_HOLDER_KP.pub)
    record_valid = _hybrid_sign_record(
        _transfer_record_body(
            RECEIPT_ID, NEW_RECEIPT_ID, new_holder_pub_b64u, TRANSFERRED_AT, BUYER_KP
        )
    )
    assert transfer.verify_record(record_valid, hybrid_manifest) is True
    assert transfer.verify_authorization(record_valid, keys.b64u(BUYER_KP.pub)) is True

    entry_valid = {
        "type": "transfer-record",
        "issuer": ISSUER_ID,
        "record_sha256": transfer.record_hash(record_valid),
    }
    entry_valid_bytes = tlog.encode_entry(entry_valid)
    root_valid = tlog.build_tree([entry_valid_bytes])
    checkpoint_valid = _sign_checkpoint_oracle(LOG_ORIGIN, 1, root_valid)
    inclusion_valid = _hex_proof(tlog.inclusion_proof([entry_valid_bytes], 0))
    evidence_valid = {
        "entry": entry_valid,
        "leaf_index": 0,
        "tree_size": 1,
        "inclusion_proof": inclusion_valid,
        "checkpoint": checkpoint_valid,
    }

    # --- (a) transferred-with-backing: fully valid claim (issuer sig + holder
    # auth + logged) -> honored, `revocation: "transferred"`, `ok: false`. ---
    write_vector(
        "35-transfer/a-transferred-with-backing",
        payload=payload_a,
        envelope=envelope_a,
        envelope_raw=None,
        trust=hybrid_trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "transferred",
            "binding": "not_checked",
            "trust": "verified",
            "ok": False,
            "errors": [],
            "warnings": [],
        },
        revocation_record=rev_transferred,
        transfer_view=[{"record": record_valid, "evidence": evidence_valid}],
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (b) transferred-on-none-with-backing: same claim, `revocability:
    # "none"` -> STILL honored — the consent gate (§17.3) applies to every
    # revocability class, `none` included. ---
    write_vector(
        "35-transfer/b-transferred-on-none-with-backing",
        payload=payload_b,
        envelope=envelope_b,
        envelope_raw=None,
        trust=hybrid_trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "transferred",
            "binding": "not_checked",
            "trust": "verified",
            "ok": False,
            "errors": [],
            "warnings": [],
        },
        revocation_record=rev_transferred,
        transfer_view=[{"record": record_valid, "evidence": evidence_valid}],
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (c) transferred-on-none-unbacked: the SAME `none`-class receipt/
    # revocation as (b), but NO transfer-view.json at all -> the resolver is
    # never reached, unbacked directly. ---
    write_vector(
        "35-transfer/c-transferred-on-none-unbacked",
        payload=None,
        envelope=envelope_b,
        envelope_raw=None,
        trust=hybrid_trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "invalid_revocation_ignored",
            "binding": "not_checked",
            "trust": "verified",
            "ok": True,
            "errors": [],
            "warnings": ["transferred_revocation_unbacked"],
        },
        revocation_record=rev_transferred,
    )

    # --- (d) forged-holder-auth: issuer signature genuinely verifies, but
    # `holder_authorization.sig` was made by an unrelated key
    # (`TRANSFER_FORGER_KP`), not the old receipt's own `BUYER_KP` -> the
    # consent gate itself fails, unbacked. ---
    record_forged = _hybrid_sign_record(
        _transfer_record_body(
            RECEIPT_ID, NEW_RECEIPT_ID, new_holder_pub_b64u, TRANSFERRED_AT, TRANSFER_FORGER_KP
        )
    )
    assert transfer.verify_record(record_forged, hybrid_manifest) is True  # issuer sig fine
    assert transfer.verify_authorization(record_forged, keys.b64u(BUYER_KP.pub)) is False
    write_vector(
        "35-transfer/d-forged-holder-auth",
        payload=None,
        envelope=envelope_a,
        envelope_raw=None,
        trust=hybrid_trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "invalid_revocation_ignored",
            "binding": "not_checked",
            "trust": "verified",
            "ok": True,
            "errors": [],
            "warnings": ["transferred_revocation_unbacked"],
        },
        revocation_record=rev_transferred,
        transfer_view=[{"record": record_forged}],
    )

    # --- (e) unlogged-transfer: the SAME fully-authenticating record as (a),
    # but its claim carries NO `evidence` at all -> never proven logged. ---
    write_vector(
        "35-transfer/e-unlogged-transfer",
        payload=None,
        envelope=envelope_a,
        envelope_raw=None,
        trust=hybrid_trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "invalid_revocation_ignored",
            "binding": "not_checked",
            "trust": "verified",
            "ok": True,
            "errors": [],
            "warnings": ["transfer_record_unlogged"],
        },
        revocation_record=rev_transferred,
        transfer_view=[{"record": record_valid}],
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (f) double-assignment-earliest-wins: TWO fully valid claims for the
    # SAME RECEIPT_ID, distinct new_receipt_id/new_holder_pubkey, logged at
    # indices 0 (record_valid, earliest) and 1 (record_lose, later) in a
    # SHARED 2-entry tree -> the later-logged one, listed FIRST in the array,
    # must still lose to the earliest-logged one. ---
    new_holder_2_pub_b64u = keys.b64u(TRANSFER_SECOND_HOLDER_KP.pub)
    record_lose = _hybrid_sign_record(
        _transfer_record_body(
            RECEIPT_ID, NEW_RECEIPT_ID_LOSING, new_holder_2_pub_b64u, TRANSFERRED_AT, BUYER_KP
        )
    )
    assert transfer.verify_record(record_lose, hybrid_manifest) is True
    entry_lose = {
        "type": "transfer-record",
        "issuer": ISSUER_ID,
        "record_sha256": transfer.record_hash(record_lose),
    }
    entry_lose_bytes = tlog.encode_entry(entry_lose)
    leaves_f = [entry_valid_bytes, entry_lose_bytes]
    root_f = tlog.build_tree(leaves_f)
    checkpoint_f = _sign_checkpoint_oracle(LOG_ORIGIN, 2, root_f)
    evidence_win_f = {
        "entry": entry_valid,
        "leaf_index": 0,
        "tree_size": 2,
        "inclusion_proof": _hex_proof(tlog.inclusion_proof(leaves_f, 0)),
        "checkpoint": checkpoint_f,
    }
    evidence_lose_f = {
        "entry": entry_lose,
        "leaf_index": 1,
        "tree_size": 2,
        "inclusion_proof": _hex_proof(tlog.inclusion_proof(leaves_f, 1)),
        "checkpoint": checkpoint_f,
    }
    write_vector(
        "35-transfer/f-double-assignment-earliest-wins",
        payload=None,
        envelope=envelope_a,
        envelope_raw=None,
        trust=hybrid_trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "transferred",
            "binding": "not_checked",
            "trust": "verified",
            "ok": False,
            "errors": [],
            "warnings": ["transfer_double_assignment_conflict"],
        },
        revocation_record=rev_transferred,
        # the later-logged claim (index 1) listed FIRST in the array —
        # earliest-wins must not be an artifact of array order.
        transfer_view=[
            {"record": record_lose, "evidence": evidence_lose_f},
            {"record": record_valid, "evidence": evidence_win_f},
        ],
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (g) not-transferable-before-violation: the old receipt's own
    # `license.not_transferable_before` falls AFTER the (otherwise fully
    # valid, reused) claim's `transferred_at` -> not yet transferable. ---
    payload_g = issue.build_payload(
        **_base_payload_kwargs(
            attest_version="0.2",
            transferable=True,
            buyer_pubkey=BUYER_KP.pub,
            revocability="policy",
        )
    )
    payload_g["license"]["not_transferable_before"] = NOT_TRANSFERABLE_BEFORE_AFTER
    _assert_schema_valid(payload_g)
    envelope_g = _hybrid_envelope(payload_g, ISSUER_KP, ISSUER_KID)
    write_vector(
        "35-transfer/g-not-transferable-before-violation",
        payload=payload_g,
        envelope=envelope_g,
        envelope_raw=None,
        trust=hybrid_trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "invalid_revocation_ignored",
            "binding": "not_checked",
            "trust": "verified",
            "ok": True,
            "errors": [],
            "warnings": ["transfer_not_yet_transferable"],
        },
        revocation_record=rev_transferred,
        transfer_view=[{"record": record_valid, "evidence": evidence_valid}],
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (k) not-transferable-before-boundary: equality is honored. The
    # transfer time is EXACTLY the old receipt's floor, so an implementation
    # must reject only strictly-earlier transfers. ---
    payload_k = issue.build_payload(
        **_base_payload_kwargs(
            attest_version="0.2",
            transferable=True,
            buyer_pubkey=BUYER_KP.pub,
            revocability="policy",
        )
    )
    payload_k["license"]["not_transferable_before"] = TRANSFERRED_AT
    _assert_schema_valid(payload_k)
    envelope_k = _hybrid_envelope(payload_k, ISSUER_KP, ISSUER_KID)
    write_vector(
        "35-transfer/k-not-transferable-before-boundary",
        payload=payload_k,
        envelope=envelope_k,
        envelope_raw=None,
        trust=hybrid_trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "transferred",
            "binding": "not_checked",
            "trust": "verified",
            "ok": False,
            "errors": [],
            "warnings": [],
        },
        revocation_record=rev_transferred,
        transfer_view=[{"record": record_valid, "evidence": evidence_valid}],
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (h) classical-only-record-hybrid-key: the transfer record's
    # holder-authorization is genuine (BUYER_KP), but the ISSUER side is
    # signed Ed25519-ONLY (`transfer.build_record` with a plain
    # `keys.SigningKeyPair`, deterministic — no oracle needed) against the
    # HYBRID manifest -> the §13 AND-rule fails closed, same shape as (c). ---
    auth_h = transfer.sign_authorization(RECEIPT_ID, new_holder_pub_b64u, TRANSFERRED_AT, BUYER_KP)
    record_ed_only = transfer.build_record(
        RECEIPT_ID,
        NEW_RECEIPT_ID,
        new_holder_pub_b64u,
        TRANSFERRED_AT,
        auth_h,
        ISSUER_KP,
        ISSUER_KID,
    )
    assert transfer.verify_authorization(record_ed_only, keys.b64u(BUYER_KP.pub)) is True
    assert transfer.verify_record_signature(record_ed_only, hybrid_manifest) is False
    write_vector(
        "35-transfer/h-classical-only-record-hybrid-key",
        payload=None,
        envelope=envelope_a,
        envelope_raw=None,
        trust=hybrid_trust,
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "invalid_revocation_ignored",
            "binding": "not_checked",
            "trust": "verified",
            "ok": True,
            "errors": [],
            "warnings": ["transferred_revocation_unbacked"],
        },
        revocation_record=rev_transferred,
        transfer_view=[{"record": record_ed_only}],
    )

    # --- (i) v01-transferable-null-pubkey-ok: D1's (§17.8) negative control —
    # `attest_version: "0.1"` is untouched by the schema conditional (it only
    # gates v0.2), so `transferable: true` with a null `buyer.pubkey` stays
    # schema-valid, no transfer files involved at all. ---
    payload_i = issue.build_payload(**_base_payload_kwargs(attest_version="0.1", transferable=True))
    _assert_schema_valid(payload_i)
    envelope_i = issue.issue(payload_i, ISSUER_KP, ISSUER_KID)
    write_vector(
        "35-transfer/i-v01-transferable-null-pubkey-ok",
        payload=payload_i,
        envelope=envelope_i,
        envelope_raw=None,
        trust=_issuer_only_trust(),
        expected={
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "ok": True,
            "errors": [],
            "warnings": [],
        },
    )

    # --- (j) v02-transferable-requires-pubkey: D1's positive gate — the SAME
    # shape under `attest_version: "0.2"` IS a schema error (§17.8). Built
    # like 25-schema-parity: mutated to schema-invalid before signing (via
    # `_hybrid_envelope`, which bypasses `issue.issue`'s own schema gate), so
    # the signature genuinely covers the invalid payload. ---
    payload_j = issue.build_payload(**_base_payload_kwargs(attest_version="0.2", transferable=True))
    violations_j = validate.validate_payload(payload_j)
    assert any("pubkey" in v for v in violations_j), violations_j
    envelope_j = _hybrid_envelope(payload_j, ISSUER_KP, ISSUER_KID)
    write_vector(
        "35-transfer/j-v02-transferable-requires-pubkey",
        payload=payload_j,
        envelope=envelope_j,
        envelope_raw=None,
        trust=hybrid_trust,
        expected={
            "signature": "valid",
            "schema": "invalid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "ok": False,
            "errors_contains": ["pubkey"],
            "warnings": [],
        },
    )


# --- vector 36: transfer-chain (v0.2 §17.5, chain-of-title audit) ----------


def gen_36_transfer_chain() -> None:
    """v0.2 §17.5: `transfer.audit_chain` is a SEPARATE audit surface over a
    whole SEQUENCE of receipt PAYLOADS — it never touches an envelope's own
    signature/schema/hybrid-ness (`audit_chain` only reads `receipt_id` and
    `buyer.pubkey` off each payload), so a PLAIN (non-hybrid) issuer manifest
    keeps every transfer/revocation record fully deterministic via
    `transfer.build_record`/`revocation.build_record` directly — no ML-DSA-65
    oracle needed, unlike group 35. The transparency log's OWN checkpoint
    auth is unaffected by this and stays hybrid-mandatory (§9.2), via the
    same `_sign_checkpoint_oracle` every other group uses.

    Three receipts, R0 -> R1 -> R2 (`CHAIN_HOLDER_{0,1,2}_KP` their own
    holder keypairs), drive all three leaves:

    - (a) two fully valid links (issuer sig + holder auth + logged, backed
      by a `transferred`-class revocation on each of R0/R1) -> `chain_valid:
      true`, both links `"valid"`.
    - (b) one link whose NEXT receipt's `buyer.pubkey` does not match the
      transfer record's own `new_holder_pubkey` (loop closure, §17.1) ->
      `chain_valid: false`.
    - (c) R0 has TWO logged, fully-authenticating transfer records (to a
      phantom receipt at log index 0 and to R1, the actual next receipt, at
      log index 1) — the chain presents the LATER-logged (actual) branch,
      which must lose (§17.4).
    """
    plain_manifest = _manifest_material(ISSUER_ID, ISSUER_KID, ISSUER_KP)
    plain_trust = _trust_material((ISSUER_ID, plain_manifest, "tls"))

    def _chain_payload(receipt_id: str, buyer_pub: bytes) -> dict[str, Any]:
        payload = issue.build_payload(
            **_base_payload_kwargs(
                attest_version="0.2",
                transferable=True,
                buyer_pubkey=buyer_pub,
                receipt_id=receipt_id,
            )
        )
        _assert_schema_valid(payload)
        return payload

    r0 = _chain_payload(CHAIN_RECEIPT_0, CHAIN_HOLDER_0_KP.pub)
    r1 = _chain_payload(CHAIN_RECEIPT_1, CHAIN_HOLDER_1_KP.pub)
    r2 = _chain_payload(CHAIN_RECEIPT_2, CHAIN_HOLDER_2_KP.pub)

    tr1_auth = transfer.sign_authorization(
        CHAIN_RECEIPT_0, keys.b64u(CHAIN_HOLDER_1_KP.pub), TRANSFERRED_AT, CHAIN_HOLDER_0_KP
    )
    tr1 = transfer.build_record(
        CHAIN_RECEIPT_0,
        CHAIN_RECEIPT_1,
        keys.b64u(CHAIN_HOLDER_1_KP.pub),
        TRANSFERRED_AT,
        tr1_auth,
        ISSUER_KP,
        ISSUER_KID,
    )
    assert transfer.verify_record(tr1, plain_manifest) is True

    tr2_auth = transfer.sign_authorization(
        CHAIN_RECEIPT_1, keys.b64u(CHAIN_HOLDER_2_KP.pub), TRANSFERRED_AT, CHAIN_HOLDER_1_KP
    )
    tr2 = transfer.build_record(
        CHAIN_RECEIPT_1,
        CHAIN_RECEIPT_2,
        keys.b64u(CHAIN_HOLDER_2_KP.pub),
        TRANSFERRED_AT,
        tr2_auth,
        ISSUER_KP,
        ISSUER_KID,
    )
    assert transfer.verify_record(tr2, plain_manifest) is True

    rev_r0 = revocation.build_record(
        CHAIN_RECEIPT_0, "transferred", TRANSFERRED_AT, ISSUER_KP, ISSUER_KID
    )
    assert revocation.verify_record(rev_r0, plain_manifest) is True
    rev_r1 = revocation.build_record(
        CHAIN_RECEIPT_1, "transferred", TRANSFERRED_AT, ISSUER_KP, ISSUER_KID
    )
    assert revocation.verify_record(rev_r1, plain_manifest) is True

    entry_tr1 = {
        "type": "transfer-record",
        "issuer": ISSUER_ID,
        "record_sha256": transfer.record_hash(tr1),
    }
    entry_tr2 = {
        "type": "transfer-record",
        "issuer": ISSUER_ID,
        "record_sha256": transfer.record_hash(tr2),
    }

    # --- (a) valid-chain: TR1 and TR2 logged together in one 2-entry tree. ---
    leaves_a = [tlog.encode_entry(entry_tr1), tlog.encode_entry(entry_tr2)]
    root_a = tlog.build_tree(leaves_a)
    checkpoint_a = _sign_checkpoint_oracle(LOG_ORIGIN, 2, root_a)
    ev_tr1_a = {
        "entry": entry_tr1,
        "leaf_index": 0,
        "tree_size": 2,
        "inclusion_proof": _hex_proof(tlog.inclusion_proof(leaves_a, 0)),
        "checkpoint": checkpoint_a,
    }
    ev_tr2_a = {
        "entry": entry_tr2,
        "leaf_index": 1,
        "tree_size": 2,
        "inclusion_proof": _hex_proof(tlog.inclusion_proof(leaves_a, 1)),
        "checkpoint": checkpoint_a,
    }
    write_chain_vector(
        "36-transfer-chain/a-valid-chain",
        chain={
            "payloads": [r0, r1, r2],
            "transfer_view": [
                {"record": tr1, "evidence": ev_tr1_a},
                {"record": tr2, "evidence": ev_tr2_a},
            ],
            "revocation_view": [rev_r0, rev_r1],
        },
        trust=plain_trust,
        expected={
            "chain_valid": True,
            "link_status": ["valid", "valid"],
            "errors_contains": [],
            "warnings": [],
        },
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (b) pubkey-mismatch-no-link: R1's OWN buyer.pubkey does not match
    # TR1's new_holder_pubkey — TR1 itself still fully authenticates and logs
    # (its own receipt_id/new_receipt_id still select it), only the loop
    # closure onto R1 fails. ---
    r1_mismatch = _chain_payload(CHAIN_RECEIPT_1, CHAIN_MISMATCH_HOLDER_KP.pub)
    leaves_b = [tlog.encode_entry(entry_tr1)]
    root_b = tlog.build_tree(leaves_b)
    checkpoint_b = _sign_checkpoint_oracle(LOG_ORIGIN, 1, root_b)
    ev_tr1_b = {
        "entry": entry_tr1,
        "leaf_index": 0,
        "tree_size": 1,
        "inclusion_proof": _hex_proof(tlog.inclusion_proof(leaves_b, 0)),
        "checkpoint": checkpoint_b,
    }
    write_chain_vector(
        "36-transfer-chain/b-pubkey-mismatch-no-link",
        chain={
            "payloads": [r0, r1_mismatch],
            "transfer_view": [{"record": tr1, "evidence": ev_tr1_b}],
            "revocation_view": [rev_r0],
        },
        trust=plain_trust,
        expected={
            "chain_valid": False,
            "link_status": ["invalid"],
            "errors_contains": ["chain link 1: new receipt buyer.pubkey != new_holder_pubkey"],
            "warnings": [],
        },
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (c) losing-branch-no-link: R0 double-assigned — a phantom transfer
    # record (never continued by any payload here) logged FIRST (index 0),
    # the actual R0->R1 record (tr1) logged SECOND (index 1) in the SAME
    # tree — the chain presents the later-logged (actual) branch, which must
    # lose even though it is the one continued by `payloads`. ---
    phantom_auth = transfer.sign_authorization(
        CHAIN_RECEIPT_0, keys.b64u(CHAIN_MISMATCH_HOLDER_KP.pub), TRANSFERRED_AT, CHAIN_HOLDER_0_KP
    )
    tr_phantom = transfer.build_record(
        CHAIN_RECEIPT_0,
        CHAIN_PHANTOM_RECEIPT,
        keys.b64u(CHAIN_MISMATCH_HOLDER_KP.pub),
        TRANSFERRED_AT,
        phantom_auth,
        ISSUER_KP,
        ISSUER_KID,
    )
    assert transfer.verify_record(tr_phantom, plain_manifest) is True
    entry_phantom = {
        "type": "transfer-record",
        "issuer": ISSUER_ID,
        "record_sha256": transfer.record_hash(tr_phantom),
    }
    leaves_c = [tlog.encode_entry(entry_phantom), tlog.encode_entry(entry_tr1)]
    root_c = tlog.build_tree(leaves_c)
    checkpoint_c = _sign_checkpoint_oracle(LOG_ORIGIN, 2, root_c)
    ev_phantom_c = {
        "entry": entry_phantom,
        "leaf_index": 0,
        "tree_size": 2,
        "inclusion_proof": _hex_proof(tlog.inclusion_proof(leaves_c, 0)),
        "checkpoint": checkpoint_c,
    }
    ev_tr1_c = {
        "entry": entry_tr1,
        "leaf_index": 1,
        "tree_size": 2,
        "inclusion_proof": _hex_proof(tlog.inclusion_proof(leaves_c, 1)),
        "checkpoint": checkpoint_c,
    }
    write_chain_vector(
        "36-transfer-chain/c-losing-branch-no-link",
        chain={
            "payloads": [r0, r1],
            "transfer_view": [
                {"record": tr_phantom, "evidence": ev_phantom_c},
                {"record": tr1, "evidence": ev_tr1_c},
            ],
            "revocation_view": [rev_r0],
        },
        trust=plain_trust,
        expected={
            "chain_valid": False,
            "link_status": ["invalid"],
            "errors_contains": ["chain link 1: losing branch of a double assignment"],
            "warnings": [],
        },
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )

    # --- (d) floor-violation-no-link: the otherwise valid R0 -> R1 link
    # predates R0's own floor. This is intentionally a two-receipt, one-link
    # chain so the expected status is unambiguous. ---
    r0_floor = copy.deepcopy(r0)
    r0_floor["license"]["not_transferable_before"] = "2025-08-01T00:00:00Z"
    write_chain_vector(
        "36-transfer-chain/d-floor-violation-no-link",
        chain={
            "payloads": [r0_floor, r1],
            "transfer_view": [{"record": tr1, "evidence": ev_tr1_b}],
            "revocation_view": [rev_r0],
        },
        trust=plain_trust,
        expected={
            "chain_valid": False,
            "link_status": ["invalid"],
            "errors_contains": ["chain link 1: transferred before not_transferable_before"],
            "warnings": [],
        },
        log_keys=[_log_key()],
        anchor_policy=_empty_anchor_policy(),
    )


def gen_39_witness_corroboration() -> None:
    """v0.2 §10.1/§11.4 (P1.1b): `corroboration: "witnessed"` — reachable, and
    hard to reach by accident.

    One receipt/checkpoint fixture, thirteen leaves that differ ONLY in the
    cosignature lines appended to the note and in the TRUSTED
    `witness-policy.json` fed alongside `log-keys.json`. That separation is the
    group's subject: the evidence names an epoch (`witness_policy_epoch`), the
    trusted policy says who that epoch pins, and nothing an evidence bundle
    carries can add a witness (leaf l).

    Every failure here is SILENT by §11.4 — the layer's only permitted literal
    is the independence warning that accompanies a successful upgrade — so ten
    of these leaves are distinguished from each other by nothing but
    `corroboration` staying `"logged"`. That is the normative behavior, not an
    under-specified expectation: a verifier that explained WHY a cosignature
    failed would be leaking the policy's shape to whoever supplied the note.

    Two leaves deliberately probe the CHECKPOINT layer from the witness side:
    `e` presents a genuine signature made in the checkpoint domain as a
    cosignature, and `f` presents a genuine witness `0xff` leg where the log's
    own ML-DSA-65 checkpoint signature should be. Both directions of the
    domain separation of §9.2 have to hold, and only `f` degrades the
    transparency claim itself (the checkpoint never authenticated).

    The epochs' `threshold` is `{n: 1, m: 1}` and every corroborating pin also
    carries `sunset-activation`, so the declared committee form matches the
    membership. Group 39 never evaluates a quorum — but shipping a policy whose
    activation form is incoherent would make these fixtures unusable as
    examples of a real deployment's configuration.
    """
    payload = issue.build_payload(**_base_payload_kwargs())
    _assert_schema_valid(payload)
    envelope = issue.issue(payload, ISSUER_KP, ISSUER_KID)
    trust = _issuer_only_trust()

    entry = {
        "type": "receipt",
        "issuer": ISSUER_ID,
        "core_sha256": tlog.receipt_core_hash(envelope),
    }
    entry_bytes = tlog.encode_entry(entry)
    root = tlog.build_tree([entry_bytes])
    inclusion = _hex_proof(tlog.inclusion_proof([entry_bytes], 0))
    base_checkpoint = _sign_checkpoint_oracle(LOG_ORIGIN, 1, root)
    note_bytes = tlog.parse_checkpoint(base_checkpoint).note_bytes
    assert tlog.verify_inclusion(tlog.leaf_hash(entry_bytes), 0, 1, [], root)

    def _evidence(
        checkpoint_text: str, *, epoch_id: str = WITNESS_EPOCH_ID, **overrides: Any
    ) -> dict[str, Any]:
        base: dict[str, Any] = {
            "entry": entry,
            "leaf_index": 0,
            "tree_size": 1,
            "inclusion_proof": inclusion,
            "checkpoint": checkpoint_text,
            "witness_policy_epoch": epoch_id,
        }
        base.update(overrides)
        return base

    def _expected(
        *, corroboration: str, transparency: str = "logged", warnings: list[str] | None = None
    ) -> dict[str, Any]:
        return {
            "signature": "valid",
            "schema": "valid",
            "revocation": "unknown",
            "binding": "not_checked",
            "trust": "verified",
            "transparency": transparency,
            "corroboration": corroboration,
            "manifest_freshness": "not_checked",
            "ok": True,
            "errors": [],
            "warnings": warnings if warnings is not None else [],
        }

    def _witnessed(*, transparency: str = "logged") -> dict[str, Any]:
        """Every witnessed verdict carries the independence warning, always."""
        return _expected(
            corroboration="witnessed",
            transparency=transparency,
            warnings=[witness.WARN_INDEPENDENCE_NOT_ESTABLISHED],
        )

    def _logged() -> dict[str, Any]:
        """A cosignature that did not count leaves NO trace (§11.4's silence)."""
        return _expected(corroboration="logged")

    def _write(
        name: str,
        *,
        evidence: dict[str, Any],
        expected: dict[str, Any],
        policy_document: dict[str, Any],
        anchor_policy: anchor.AnchorPolicy | None = None,
    ) -> None:
        write_vector(
            f"39-witness-corroboration/{name}",
            payload=payload,
            envelope=envelope,
            envelope_raw=None,
            trust=trust,
            expected=expected,
            transparency=evidence,
            log_keys=[_log_key()],
            anchor_policy=anchor_policy if anchor_policy is not None else _empty_anchor_policy(),
            witness_policy=policy_document,
        )

    corroborating_roles = [witness.ROLE_CORROBORATION, witness.ROLE_SUNSET_ACTIVATION]
    policy_current = _witness_policy_document(
        _witness_epoch([_witness_pin(0, roles=corroborating_roles)])
    )

    # --- (a) the bootstrap case: one pinned witness, one valid `0x04`
    # cosignature, `logged` -> `witnessed`. The independence warning is
    # UNCONDITIONAL on every witnessed verdict (§11.4): policy v1 defines no
    # positive independence certificate, so the verifier says so every time
    # rather than letting silence imply a property it cannot check. ---
    checkpoint_a = _cosigned(
        base_checkpoint, *_witness_vote_lines(0, note_bytes, WITNESS_OBSERVED_AT, with_pq=False)
    )
    _write(
        "a-ed25519-witnessed-bootstrap",
        evidence=_evidence(checkpoint_a),
        expected=_witnessed(),
        policy_document=policy_current,
    )

    # --- (b) an UNPINNED witness's genuine cosignature. The signature
    # verifies against its own key; the key is simply in no epoch, so it
    # carries no standing. Trust comes from the policy, never from the note. ---
    checkpoint_b = _cosigned(
        base_checkpoint,
        _note_line(
            UNPINNED_WITNESS_NAME,
            _ed_cosignature_blob(
                UNPINNED_WITNESS_NAME, UNPINNED_WITNESS_ED_KP, note_bytes, WITNESS_OBSERVED_AT
            ),
        ),
    )
    _write(
        "b-unpinned-witness-does-not-count",
        evidence=_evidence(checkpoint_b),
        expected=_logged(),
        policy_document=policy_current,
    )

    # --- (c) right name, right key ID, WRONG signature: the blob is
    # well-formed all the way down to the last 64 bytes. Nothing but the
    # Ed25519 verification separates this leaf from (a). ---
    checkpoint_c = _cosigned(
        base_checkpoint,
        _note_line(
            WITNESS_NAMES[0],
            _ed_cosignature_blob(
                WITNESS_NAMES[0],
                WITNESS_ED_KPS[0],
                note_bytes,
                WITNESS_OBSERVED_AT,
                corrupt=True,
            ),
        ),
    )
    _write(
        "c-invalid-ed25519-does-not-count",
        evidence=_evidence(checkpoint_c),
        expected=_logged(),
        policy_document=policy_current,
    )

    # --- (d) C2SP type `0x06` (ML-DSA-44 over the `subtree/v1` structure)
    # gets ZERO standing (§9.2). Built as the sharpest possible discriminator:
    # same witness, same timestamp, same 76-byte shape, and a genuine Ed25519
    # signature over the correct cosignature message — the ONLY defect is the
    # signature type baked into the key ID. An implementation that computed
    # the key ID without the type, or with the wrong one, would accept it. ---
    type_06_key_id = tlog.key_hash(WITNESS_NAMES[0], b"\x06", WITNESS_ED_KPS[0].pub)
    assert type_06_key_id != witness.cosignature_key_id(WITNESS_NAMES[0], WITNESS_ED_KPS[0].pub)
    blob_d = (
        type_06_key_id
        + WITNESS_OBSERVED_AT.to_bytes(8, "big")
        + keys.sign(witness.cosignature_message(note_bytes, WITNESS_OBSERVED_AT), WITNESS_ED_KPS[0])
    )
    assert len(blob_d) == len(
        _ed_cosignature_blob(WITNESS_NAMES[0], WITNESS_ED_KPS[0], note_bytes, WITNESS_OBSERVED_AT)
    )
    checkpoint_d = _cosigned(base_checkpoint, _note_line(WITNESS_NAMES[0], blob_d))
    _write(
        "d-c2sp-type-06-does-not-count",
        evidence=_evidence(checkpoint_d),
        expected=_logged(),
        policy_document=policy_current,
    )

    # --- (e) domain separation, first direction: a genuine signature made
    # over the checkpoint BODY, transported into a cosignature blob. Without
    # the `cosignature/v1\ntime <t>\n` prefix the message is a different one,
    # so the pinned witness's own valid signature does not corroborate. ---
    checkpoint_e = _cosigned(
        base_checkpoint,
        _note_line(
            WITNESS_NAMES[0],
            _ed_cosignature_blob(
                WITNESS_NAMES[0],
                WITNESS_ED_KPS[0],
                note_bytes,
                WITNESS_OBSERVED_AT,
                signed_message=note_bytes,
            ),
        ),
    )
    _write(
        "e-checkpoint-domain-not-cosignature",
        evidence=_evidence(checkpoint_e),
        expected=_logged(),
        policy_document=policy_current,
    )

    # --- (f) domain separation, other direction: the log's own ML-DSA-65
    # checkpoint line is MISSING and a genuine witness `0xff` activation leg
    # stands in its place. Checkpoint authentication is hybrid and mandatory,
    # so the claim never reaches `logged` at all — this is the one leaf in the
    # group where `transparency` itself degrades. ---
    checkpoint_f = _cosigned(
        _sign_checkpoint_ed_only(LOG_ORIGIN, 1, root),
        _note_line(
            WITNESS_NAMES[0],
            _pq_cosignature_blob(WITNESS_NAMES[0], 0, note_bytes, WITNESS_OBSERVED_AT),
        ),
    )
    _write(
        "f-cosignature-domain-not-checkpoint",
        evidence=_evidence(checkpoint_f),
        expected=_expected(
            corroboration="none",
            transparency="not_checked",
            warnings=["checkpoint_verification_failed"],
        ),
        policy_document=policy_current,
    )

    # --- (g) the evidence names an epoch the policy does not contain. The
    # cosignature itself is leaf (a)'s, valid in every respect: an unresolvable
    # epoch is not a reason to go looking for another one (§10.2). ---
    _write(
        "g-missing-policy-epoch",
        evidence=_evidence(checkpoint_a, epoch_id="bootstrap-1999"),
        expected=_logged(),
        policy_document=policy_current,
    )

    # --- (h) the pin is real, current, and holds `sunset-activation` — but not
    # `corroboration`. Roles are capabilities, not decoration. ---
    _write(
        "h-wrong-role",
        evidence=_evidence(checkpoint_a),
        expected=_logged(),
        policy_document=_witness_policy_document(
            _witness_epoch([_witness_pin(0, roles=[witness.ROLE_SUNSET_ACTIVATION])])
        ),
    )

    # --- (i) a CLOSED epoch still corroborates: the observation falls inside
    # the 2020 window, and a timely `signed-note-v2` anchor over the full note
    # (cosignature line included) ties it to a PQ-surviving time. The two
    # layers compose — `transparency` upgrades to `anchored_before:<T>` while
    # `corroboration` upgrades to `witnessed` — and neither reads a clock. ---
    policy_historical = _witness_policy_document(
        _witness_epoch(
            [
                _witness_pin(
                    0,
                    roles=corroborating_roles,
                    not_before=HISTORICAL_EPOCH_NOT_BEFORE,
                    not_after=HISTORICAL_EPOCH_NOT_AFTER,
                )
            ],
            epoch_id=HISTORICAL_EPOCH_ID,
            not_before=HISTORICAL_EPOCH_NOT_BEFORE,
            not_after=HISTORICAL_EPOCH_NOT_AFTER,
        )
    )
    checkpoint_i = _cosigned(
        base_checkpoint, *_witness_vote_lines(0, note_bytes, HISTORICAL_OBSERVED_AT, with_pq=False)
    )
    signed_note_i = tlog.parse_checkpoint(checkpoint_i).signed_note_bytes
    assert signed_note_i != note_bytes
    anchor_time_i = 1593561600  # 2020-07-01T00:00:00Z, a month after the observation
    proof_i, anchor_policy_i = _single_hash_anchor(
        signed_note_i, b"attest-vectors-39i-header-v1", anchor_time_i
    )
    _write(
        "i-historical-epoch-valid",
        evidence=_evidence(
            checkpoint_i,
            epoch_id=HISTORICAL_EPOCH_ID,
            anchors={
                "checkpoint": checkpoint_i,
                "proofs": [proof_i],
                "anchor_profile": "signed-note-v2",
            },
        ),
        expected=_witnessed(transparency="anchored_before:2020-07-01T00:00:00Z"),
        policy_document=policy_historical,
        anchor_policy=anchor_policy_i,
    )

    # --- (j) the current committee MUST NOT reinterpret old evidence. Same
    # checkpoint and epoch name as (i), but the 2020 epoch pins a DIFFERENT
    # operator; the witness who actually signed is pinned only in the current
    # epoch. A verifier that fell back to the current membership would read
    # this as witnessed. ---
    policy_two_epochs = _witness_policy_document(
        _witness_epoch(
            [
                _witness_pin(
                    1,
                    roles=corroborating_roles,
                    not_before=HISTORICAL_EPOCH_NOT_BEFORE,
                    not_after=HISTORICAL_EPOCH_NOT_AFTER,
                )
            ],
            epoch_id=HISTORICAL_EPOCH_ID,
            not_before=HISTORICAL_EPOCH_NOT_BEFORE,
            not_after=HISTORICAL_EPOCH_NOT_AFTER,
        ),
        _witness_epoch([_witness_pin(0, roles=corroborating_roles)]),
    )
    _write(
        "j-current-epoch-not-substituted",
        evidence=_evidence(checkpoint_i, epoch_id=HISTORICAL_EPOCH_ID),
        expected=_logged(),
        policy_document=policy_two_epochs,
    )

    # --- (k) eternal verifiability: the pin RETIRED on 2026-06-30, the
    # observation was made on 2026-06-01, and standing is judged at the moment
    # claimed — never at the verifier's local clock. This verdict must still
    # read `witnessed` in 2050. ---
    _write(
        "k-old-valid-no-local-clock-cap",
        evidence=_evidence(checkpoint_a),
        expected=_witnessed(),
        policy_document=_witness_policy_document(
            _witness_epoch(
                [_witness_pin(0, roles=corroborating_roles, not_after="2026-06-30T00:00:00Z")]
            )
        ),
    )

    # --- (l) the evidence carries its OWN, perfectly valid policy document
    # pinning the witness who signed. It is ignored in full: a bundle that
    # could nominate its own witnesses would make the trusted rail decorative.
    # The trusted policy pins someone else, so the verdict stays `logged`. ---
    checkpoint_l = _cosigned(
        base_checkpoint, *_witness_vote_lines(1, note_bytes, WITNESS_OBSERVED_AT, with_pq=False)
    )
    _write(
        "l-evidence-policy-substitution-ignored",
        evidence=_evidence(
            checkpoint_l,
            witness_policy=_witness_policy_document(
                _witness_epoch([_witness_pin(1, roles=corroborating_roles)])
            ),
        ),
        expected=_logged(),
        policy_document=policy_current,
    )

    # --- (m) `compromised_after: null` is the tri-state's third value: a
    # compromise IS declared and its onset is unknown, so the pin fails closed
    # at every instant, forever. Distinct from the member being absent, which
    # is what every other leaf in this group ships. ---
    _write(
        "m-compromise-onset-unknown",
        evidence=_evidence(checkpoint_a),
        expected=_logged(),
        policy_document=_witness_policy_document(
            _witness_epoch([_witness_pin(0, roles=corroborating_roles, compromised_after=None)])
        ),
    )


def gen_40_witness_quorum() -> None:
    """v0.2 §11.4 (P1.1b): the activation-grade hybrid witness quorum, as a
    conformance surface of its own.

    Twenty leaves over ONE checkpoint. There is no receipt anywhere in this
    group: §11.4's quorum is a standalone primitive that answers a single
    question — did a quorum of pinned witnesses observe THIS checkpoint, and
    by when — and returns the conservative time at which that became true. Its
    result vocabulary (`valid`, `witness_time`, `counting_control_groups`) has
    no overlap with a `VerificationResult`, which is why these leaves are
    routed by file presence to a third entry point rather than being bent into
    the `verify()` shape.

    The group is built around the boundaries, because that is where a quorum
    rule either holds or silently does not. Every temporal limit ships as a
    PAIR one second apart — skew 600/601 (l/m), anchor delay 86400/86401
    (o/p) — and the compromise cutoff ships as the pair the §11.4 tri-state
    demands: `T` exactly at the declared onset still counts (s), while a
    declared compromise with unknown onset never counts (t).

    Three leaves attack the evaluation ORDER rather than any single rule,
    because §11.4 makes that order normative: the committee ceiling and the
    one-candidate-per-control-group rule bind BEFORE any signature
    verification, so a hostile policy or note cannot turn the primitive into a
    work amplifier. In (j) ten control groups trip the ceiling while carrying
    votes that would otherwise satisfy the threshold; in (g) a rotated key
    inside one control group presents a second valid vote; in (k) the declared
    form contradicts the membership. All three are rejected outright — not
    de-duplicated, not repaired.

    Declared limit, measured rather than assumed (it is also written into
    `witness.py`): the ceiling in (j) is REDUNDANT with the declared-form
    check today, because `threshold.n > 9` is already refused at parse time.
    No leaf can separate the two, so (j) pins their conjunction. It stays
    because §11.4 states the ordering normatively and because a future policy
    revision that relaxes the parser must not silently relax this.

    What the corpus CANNOT pin here is that no cryptographic work happened —
    a vector observes a verdict, not a call count. The spies that prove zero
    signature verifications live in the unit suites of both cores.
    """
    root = hashlib.sha256(b"attest-vectors-40-root-v1").digest()
    base_checkpoint = _sign_checkpoint_oracle(LOG_ORIGIN, 1, root)
    note_bytes = tlog.parse_checkpoint(base_checkpoint).note_bytes
    # A note the witness never observed, for the transplanted-leg leaf (f).
    other_note_bytes = _checkpoint_note_bytes(
        LOG_ORIGIN, 2, hashlib.sha256(b"attest-vectors-40f-other-root-v1").digest()
    )
    assert other_note_bytes != note_bytes

    observed_at = WITNESS_OBSERVED_AT
    # The compromise-cutoff pair (s/t) only means anything if the POSIX second
    # the cosignature blob carries and the §11.4 timestamp the policy declares
    # are the SAME instant. Checked, not commented.
    assert (
        datetime.strptime(WITNESS_OBSERVED_AT_ISO, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=UTC)
        .timestamp()
        == observed_at
    )
    activation_roles = [witness.ROLE_CORROBORATION, witness.ROLE_SUNSET_ACTIVATION]

    def _policy(
        pins: list[dict[str, Any]],
        *,
        threshold: tuple[int, int],
        epoch_id: str = WITNESS_EPOCH_ID,
        not_before: str = WITNESS_EPOCH_NOT_BEFORE,
        not_after: str | None = None,
    ) -> dict[str, Any]:
        return _witness_policy_document(
            _witness_epoch(
                pins,
                epoch_id=epoch_id,
                not_before=not_before,
                not_after=not_after,
                threshold=threshold,
            )
        )

    def _valid(witness_time: int, control_groups: list[str]) -> dict[str, Any]:
        return {
            "valid": True,
            "witness_time": witness_time,
            "counting_control_groups": sorted(control_groups),
        }

    def _invalid() -> dict[str, Any]:
        """An invalid quorum has no time to report and no groups to name."""
        return {"valid": False, "witness_time": None, "counting_control_groups": []}

    def _write(
        name: str,
        *,
        votes: list[str],
        policy: dict[str, Any],
        anchored_at: int,
        expected: dict[str, Any],
        epoch_id: str = WITNESS_EPOCH_ID,
        note_v1: bool = False,
    ) -> None:
        text = _cosigned(base_checkpoint, *votes)
        signed_note_bytes = tlog.parse_checkpoint(text).signed_note_bytes
        # A `signed-note-v2` anchor commits to the note WITH the votes in it;
        # a `note-v1` anchor commits to the unsigned header alone and so says
        # nothing about the votes being counted (leaf q).
        commitment = note_bytes if note_v1 else signed_note_bytes
        proof, anchor_policy = _single_hash_anchor(
            commitment, f"attest-vectors-{name}-header-v1".encode(), anchored_at
        )
        anchor_evidence: dict[str, Any] = {"checkpoint": text, "proofs": [proof]}
        if not note_v1:
            anchor_evidence["anchor_profile"] = "signed-note-v2"
        write_quorum_vector(
            f"40-witness-quorum/{name}",
            quorum={
                "expected_origin": LOG_ORIGIN,
                "conflict_domain": WITNESS_CONFLICT_DOMAIN,
                "epoch_id": epoch_id,
                "checkpoint": text,
                "anchor_evidence": anchor_evidence,
            },
            witness_policy=policy,
            anchor_policy=anchor_policy,
            expected=expected,
        )

    policy_one = _policy([_witness_pin(0, roles=activation_roles)], threshold=(1, 1))
    policy_three = _policy(
        [_witness_pin(index, roles=activation_roles) for index in range(3)], threshold=(3, 2)
    )
    group_a, group_b = WITNESS_CONTROL_GROUPS[0], WITNESS_CONTROL_GROUPS[1]

    def _vote(index: int, at: int, **overrides: Any) -> list[str]:
        return _witness_vote_lines(index, note_bytes, at, **overrides)

    # --- (a) the shape everything else deviates from: one pinned witness, a
    # complete hybrid vote, an anchor comfortably inside the window. ---
    _write(
        "a-one-of-one-valid",
        votes=_vote(0, observed_at),
        policy=policy_one,
        anchored_at=observed_at + 3600,
        expected=_valid(observed_at, [group_a]),
    )

    # --- (b) 2-of-3, and `T` is the MINIMUM over the counting votes. Taking
    # the maximum instead would let the latest signer stretch the anchor
    # window that every earlier observation is judged by; this leaf is what
    # makes that choice observable, since the two votes are 300s apart. ---
    _write(
        "b-two-of-three-conservative-t",
        votes=_vote(0, observed_at) + _vote(1, observed_at + 300),
        policy=policy_three,
        anchored_at=observed_at + 3600,
        expected=_valid(observed_at, [group_a, group_b]),
    )

    # --- (c)/(d) a vote is the AND of both legs. Half a pair is not a
    # weakened vote, it is no vote: neither the classical leg alone nor the
    # post-quantum leg alone produces a candidate at all. ---
    _write(
        "c-ed25519-leg-only-invalid",
        votes=_vote(0, observed_at, with_pq=False),
        policy=policy_one,
        anchored_at=observed_at + 3600,
        expected=_invalid(),
    )
    _write(
        "d-mldsa-leg-only-invalid",
        votes=_vote(0, observed_at, with_ed=False),
        policy=policy_one,
        anchored_at=observed_at + 3600,
        expected=_invalid(),
    )

    # --- (e) both legs sign the byte-identical payload, timestamp included.
    # Legs carrying different times are not a pair — a one-second difference
    # is enough, and no leg is verified. ---
    _write(
        "e-legs-with-divergent-timestamps",
        votes=_vote(0, observed_at, pq_timestamp=observed_at + 1),
        policy=policy_one,
        anchored_at=observed_at + 3600,
        expected=_invalid(),
    )

    # --- (f) a genuine post-quantum leg, correctly typed and correctly timed,
    # signed over a DIFFERENT note. It pairs structurally with the classical
    # leg and then fails the fail-closed AND — the transplant is caught by
    # verification, not by shape. ---
    _write(
        "f-transplanted-leg",
        votes=_vote(
            0,
            observed_at,
            pq_message=witness.cosignature_message(other_note_bytes, observed_at),
        ),
        policy=policy_one,
        anchored_at=observed_at + 3600,
        expected=_invalid(),
    )

    # --- (g) one vote per control group, enforced as a hard failure rather
    # than a de-duplication: an operator who rotated keys has two pinned
    # identities in one control group, and presents a valid vote from each.
    # A verifier that counted them separately would reach the threshold on a
    # single organization's say-so. ---
    rotated_pin = _witness_pin(
        1,
        roles=activation_roles,
        operator_id=WITNESS_OPERATORS[0],
        control_group=group_a,
    )
    _write(
        "g-one-vote-per-control-group",
        votes=_vote(0, observed_at) + _vote(1, observed_at) + _vote(2, observed_at),
        policy=_policy(
            [
                _witness_pin(0, roles=activation_roles),
                rotated_pin,
                _witness_pin(2, roles=activation_roles),
            ],
            threshold=(2, 2),
        ),
        anchored_at=observed_at + 3600,
        expected=_invalid(),
    )

    # --- (h) direct conflict: the pin itself names the domain whose sunset
    # this quorum would activate, so it is excluded before pairing and the
    # remaining single vote cannot reach 2-of-3. ---
    _write(
        "h-direct-domain-conflict",
        votes=_vote(0, observed_at) + _vote(1, observed_at + 300),
        policy=_policy(
            [
                _witness_pin(
                    0, roles=activation_roles, affiliated_domains=[WITNESS_CONFLICT_DOMAIN]
                ),
                _witness_pin(1, roles=activation_roles),
                _witness_pin(2, roles=activation_roles),
            ],
            threshold=(3, 2),
        ),
        anchored_at=observed_at + 3600,
        expected=_invalid(),
    )

    # --- (i) transitive conflict: the voting pin names nothing, but a sibling
    # in its OWN control group names the domain. Shared control is shared
    # conflict — and there is deliberately no inverse of this predicate:
    # domain inequality never establishes independence. ---
    _write(
        "i-transitive-domain-conflict",
        votes=_vote(0, observed_at) + _vote(1, observed_at + 300),
        policy=_policy(
            [
                _witness_pin(0, roles=activation_roles),
                _witness_pin(1, roles=activation_roles),
                _witness_pin(2, roles=activation_roles),
                _witness_pin(
                    3,
                    roles=activation_roles,
                    control_group=group_a,
                    affiliated_domains=[WITNESS_CONFLICT_DOMAIN],
                ),
            ],
            threshold=(3, 2),
        ),
        anchored_at=observed_at + 3600,
        expected=_invalid(),
    )

    # --- (j) ten activation control groups against a ceiling of nine. The two
    # votes present would satisfy the declared threshold, so a verifier that
    # skipped the membership bound would have to verify them to find out. ---
    _write(
        "j-committee-of-ten-invalid",
        votes=_vote(0, observed_at) + _vote(1, observed_at + 300),
        policy=_policy(
            [_witness_pin(index, roles=activation_roles) for index in range(_WITNESS_SLOTS)],
            threshold=(witness.MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE, 2),
        ),
        anchored_at=observed_at + 3600,
        expected=_invalid(),
    )

    # --- (k) the declared form contradicts the membership: `threshold.n`
    # counts distinct activation control groups, and this epoch declares two
    # while pinning three. The two votes present would satisfy 2-of-2 exactly;
    # the policy is refused instead of being reconciled to them. ---
    _write(
        "k-declared-form-incoherent-with-membership",
        votes=_vote(0, observed_at) + _vote(1, observed_at + 300),
        policy=_policy(
            [_witness_pin(index, roles=activation_roles) for index in range(3)],
            threshold=(2, 2),
        ),
        anchored_at=observed_at + 3600,
        expected=_invalid(),
    )

    # --- (l)/(m) the skew boundary, one second apart. Exactly 600s of spread
    # between the counting votes is inside the limit; 601 is not. ---
    _write(
        "l-skew-600-valid",
        votes=_vote(0, observed_at) + _vote(1, observed_at + 600),
        policy=policy_three,
        anchored_at=observed_at + 700,
        expected=_valid(observed_at, [group_a, group_b]),
    )
    _write(
        "m-skew-601-invalid",
        votes=_vote(0, observed_at) + _vote(1, observed_at + 601),
        policy=policy_three,
        anchored_at=observed_at + 700,
        expected=_invalid(),
    )

    # --- (n) the anchor must land at or after the LATEST counting vote: an
    # anchor that predates a vote cannot be evidence that the vote existed. ---
    _write(
        "n-anchor-before-latest-vote",
        votes=_vote(0, observed_at) + _vote(1, observed_at + 300),
        policy=policy_three,
        anchored_at=observed_at + 100,
        expected=_invalid(),
    )

    # --- (o)/(p) the anchor-delay boundary, one second apart, measured from
    # `T` rather than from the latest vote. ---
    _write(
        "o-anchor-delay-86400-valid",
        votes=_vote(0, observed_at),
        policy=policy_one,
        anchored_at=observed_at + 86400,
        expected=_valid(observed_at, [group_a]),
    )
    _write(
        "p-anchor-delay-86401-invalid",
        votes=_vote(0, observed_at),
        policy=policy_one,
        anchored_at=observed_at + 86401,
        expected=_invalid(),
    )

    # --- (q) a `note-v1` anchor commits to the unsigned header only, so it
    # proves nothing about the cosignature lines this quorum counts. Nothing
    # else about the leaf differs from (a). ---
    _write(
        "q-note-v1-anchor-insufficient",
        votes=_vote(0, observed_at),
        policy=policy_one,
        anchored_at=observed_at + 3600,
        expected=_invalid(),
        note_v1=True,
    )

    # --- (r) fresh evidence does not revive an expired epoch. The pins
    # themselves are open-ended and would have standing today; it is the
    # EPOCH's window that closed in 2020, and `T` falls outside it. ---
    _write(
        "r-new-evidence-does-not-revive-expired-epoch",
        votes=_vote(0, observed_at),
        policy=_policy(
            [_witness_pin(0, roles=activation_roles, not_before=HISTORICAL_EPOCH_NOT_BEFORE)],
            threshold=(1, 1),
            epoch_id=HISTORICAL_EPOCH_ID,
            not_before=HISTORICAL_EPOCH_NOT_BEFORE,
            not_after=HISTORICAL_EPOCH_NOT_AFTER,
        ),
        anchored_at=observed_at + 3600,
        expected=_invalid(),
        epoch_id=HISTORICAL_EPOCH_ID,
    )

    # --- (s) `T` exactly at the declared compromise onset still counts: the
    # boundary is inclusive, and standing is judged at the instant claimed.
    # Without this leaf a verifier could make the window exclusive and stay
    # green everywhere else. ---
    _write(
        "s-quorum-time-exactly-at-compromise-cutoff",
        votes=_vote(0, observed_at),
        policy=_policy(
            [_witness_pin(0, roles=activation_roles, compromised_after=WITNESS_OBSERVED_AT_ISO)],
            threshold=(1, 1),
        ),
        anchored_at=observed_at + 3600,
        expected=_valid(observed_at, [group_a]),
    )

    # --- (t) the same member set as (s) with an explicit `null` onset: a
    # compromise IS declared and nobody knows when it began, so the pin fails
    # closed at every instant and the quorum has zero counting votes. ---
    _write(
        "t-compromise-cutoff-null-zero-votes",
        votes=_vote(0, observed_at),
        policy=_policy(
            [_witness_pin(0, roles=activation_roles, compromised_after=None)],
            threshold=(1, 1),
        ),
        anchored_at=observed_at + 3600,
        expected=_invalid(),
    )


def main() -> None:
    _clear_leaf_dirs(VECTORS_DIR)
    VECTORS_DIR.mkdir(parents=True, exist_ok=True)
    gen_01_valid_minimal()
    gen_02_valid_full()
    gen_03_tampered_payload()
    gen_04_wrong_key()
    gen_05_issuer_mismatch()
    gen_06_duplicate_key_reject()
    gen_07_unicode_canon()
    gen_08_sig_malleability()
    gen_09_commitment()
    gen_10_unknown_field()
    gen_11_manifest_tamper()
    gen_12_retired_key_ok()
    gen_13_compromised_key()
    gen_14_rotation_continuity()
    gen_14b_rotation_discontinuous()
    gen_15_revoked_policy()
    gen_16_revocation_against_none_ignored()
    gen_17_binding_proven()
    gen_18_drm_bound()
    gen_19_rotation_substituted_key()
    gen_20_sig_canonicity()
    gen_21_canon_strict()
    gen_22_b64u_decoder_parity()
    gen_23_revocation_refund_window()
    gen_24_canonical_roundtrip()
    gen_25_schema_parity()
    gen_26_hybrid()
    gen_27_valid_to_absent()
    gen_28_transparency()
    gen_29_limits()
    gen_30_mixed_keyset()
    gen_31_manifest_currency()
    gen_32_anchor_v2()
    gen_33_logged_revocation()
    gen_35_transfer()
    gen_36_transfer_chain()
    gen_39_witness_corroboration()
    gen_40_witness_quorum()
    leaf_count = sum(1 for _ in VECTORS_DIR.rglob("expected.json"))
    print(f"generated {leaf_count} vector cases under {VECTORS_DIR}")


if __name__ == "__main__":
    main()
