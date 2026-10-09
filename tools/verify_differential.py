#!/usr/bin/env python3
"""Feed the same receipts to both verifiers and compare their verdicts.

`src/attest/verify.py` and `verifiers/ts/src/verify.ts` must return the same
verdict for every input: a receipt one conforming verifier accepts and the other
refuses is a receipt whose meaning depends on who reads it. The conformance
corpus pins the cases somebody thought of; this runner generates the ones nobody
chose. Four verdict divergences shipped past the corpus (fixed in 0.9.8): a
cofactored Ed25519 equation on one side, two base64url decoders with different
grammars, an Ed25519-only receipt under a hybrid key, and object-typed envelope
fields that made one side throw. Each of those is a structured edit of a valid
receipt, and that is what this runner makes.

HOW A CASE IS MADE. Every case is ONE mutation of a valid receipt, signed with
fixed seeds under a trust store this file builds (v0.1 Ed25519, v0.2 hybrid
Ed25519 + ML-DSA-65, and key entries whose public keys are crafted curve
points). One mutation is the reproducer: a divergence is reported with the
mutation that produced it and the exact bytes, and `--keep` writes each one as
a conformance leaf (`envelope.raw.json` + `manifests.json`) that
`tools/conformance_adapter_py.py` and `tools/conformance_adapter_ts.mjs` replay.

Mutation families: base64url edits of signature and key strings (alphabet,
padding, whitespace, trailing bits, length), Ed25519 encodings (small-order and
mixed-order R and A, non-canonical R, A and S), type confusion of every
envelope and payload member, version/alg swaps, kid swaps between Ed25519-only
and hybrid key entries, JSON text tricks (duplicate keys, escapes, surrogates,
number spellings, depth) and sizes either side of the envelope ceiling.

WHAT IS COMPARED. Python runs in-process; TypeScript runs through
`tools/verify_adapter_ts.mjs`, one node process for the whole batch, reading the
published `verifiers/ts/dist`. Both sides report ok/invalid plus every member
the conformance adapters report, and `comparable()` keeps all of it exact --
the verdict, every enumerated member, `ok`, and the error and warning strings
the two cores keep word for word -- except three things neither core words for
the other: the JSON parser's own diagnostic (compared by class), the schema
validator's violation texts (`schema: "invalid"` is compared), and how a
non-printable character is quoted inside a message. A THROW is its own
verdict, `crash`, never folded into `invalid`, and a crash on either side fails
the run even when the other side crashed too.

A PROPERTY, NOT A DIFFERENCE. A v0.1 receipt signed by the Ed25519 leg of a
hybrid key is a forgery any Ed25519 break mints; both cores once accepted it,
so they agreed and a differential could not see it. That one is checked as a
property on every run: both sides must refuse it.

    python3 tools/verify_differential.py --count 5000 --seed 20261009
    python3 tools/verify_differential.py --count 500 --keep /tmp/divergences

Exit status: 0 no divergence, crash or property failure; 1 at least one; 78 a
prerequisite (node, or the built `verifiers/ts/dist`) is absent and nothing was
measured. Stdlib plus the project's own dependencies (`dilithium-py`, from the
dev extra, signs the ML-DSA-65 legs deterministically).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import shutil
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from dilithium_py.ml_dsa import ML_DSA_65  # type: ignore[import-untyped]  # noqa: E402

from attest import canon, issue, keys, manifests, trust_material  # noqa: E402
from attest import verify as verify_module  # noqa: E402
from attest.validate import MAX_ENVELOPE_BYTES  # noqa: E402

ADAPTER = REPO_ROOT / "tools" / "verify_adapter_ts.mjs"
DIST_INDEX = REPO_ROOT / "verifiers" / "ts" / "dist" / "index.js"
EXIT_PRECONDITION = 78

# --- fixed inputs (never wall-clock, never os.urandom) -----------------------

ISSUER = "store.example.com"
VALID_FROM = "2025-01-01T00:00:00Z"
ISSUED_AT = "2025-07-02T13:50:00Z"
RECEIPT_ID = "01JZ5PDHT0000G40R40M30E209"

ED_KID = f"{ISSUER}/keys/2025-01#ed25519-1"
HYB_KID = f"{ISSUER}/keys/2025-01#hybrid-1"
MIXED_KID = f"{ISSUER}/keys/2025-01#ed25519-mixed-order"
SMALL_KID = f"{ISSUER}/keys/2025-01#ed25519-small-order"
NONCANON_KID = f"{ISSUER}/keys/2025-01#ed25519-noncanonical"

ED_SEED = bytes([1]) * 32
HYB_ED_SEED = bytes([21]) * 32
MIXED_SEED = bytes([7]) * 32
HYB_MLDSA_PK, HYB_MLDSA_SK = ML_DSA_65.key_derive(bytes([26]) * 32)

# --- Ed25519 arithmetic, for crafting encodings the signing library refuses --

_P = 2**255 - 19
_D = (-121665 * pow(121666, -1, _P)) % _P
_L = 2**252 + 27742317777372353535851937790883648493
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
Point = tuple[int, int]
_IDENTITY: Point = (0, 1)


def _add(p1: Point, p2: Point) -> Point:
    x1, y1 = p1
    x2, y2 = p2
    t = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + y1 * x2) * pow(1 + t, -1, _P) % _P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, -1, _P) % _P
    return (x3, y3)


def _mul(k: int, point: Point) -> Point:
    result = _IDENTITY
    while k:
        if k & 1:
            result = _add(result, point)
        point = _add(point, point)
        k >>= 1
    return result


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, -1, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if x & 1 != sign:
        x = _P - x
    return x


def _encode(point: Point) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_BASE: Point = (_recover_x(4 * pow(5, -1, _P) % _P, 0) or 0, 4 * pow(5, -1, _P) % _P)


def _torsion8() -> Point:
    """A point of order exactly 8: the torsion component of some curve point."""
    y = 2
    while True:
        x = _recover_x(y, 0)
        if x is not None:
            t = _mul(_L, (x, y))
            if _mul(4, t) != _IDENTITY:
                return t
        y += 1


_T8 = _torsion8()


def _noncanonical_point_encoding() -> bytes:
    """A curve point spelled with y >= p (only y < 19 has such a spelling)."""
    for y in range(19):
        if _recover_x(y, 0) is not None:
            return (y + _P).to_bytes(32, "little")
    raise AssertionError("no curve point with y < 19")  # pragma: no cover


@dataclass(frozen=True)
class EdKey:
    """An Ed25519 key with its scalar exposed, so signatures can be crafted."""

    seed: bytes
    scalar: int
    prefix: bytes
    pub: bytes  # the key's own public key, aB

    @classmethod
    def from_seed(cls, seed: bytes) -> EdKey:
        h = hashlib.sha512(seed).digest()
        a = int.from_bytes(h[:32], "little")
        a &= (1 << 254) - 8
        a |= 1 << 254
        pub = _encode(_mul(a, _BASE))
        if pub != keys.from_seed(seed).pub:  # the arithmetic above, checked once
            raise AssertionError("Ed25519 arithmetic disagrees with the signing library")
        return cls(seed, a, h[32:], pub)

    def sign(self, msg: bytes) -> bytes:
        return keys.sign(msg, keys.from_seed(self.seed))

    def craft(self, msg: bytes, *, r_extra: Point = _IDENTITY, a_enc: bytes | None = None) -> bytes:
        """sig = (R, S) with R = rB + r_extra, S = r + kA over the encoding `a_enc`.

        With the defaults this is an ordinary RFC 8032 signature. A torsion
        `r_extra` gives a mixed-order R; `a_enc` lets the key be announced as a
        different encoding (a mixed-order A) while the scalar stays this key's.
        """
        a_bytes = self.pub if a_enc is None else a_enc
        r = int.from_bytes(hashlib.sha512(self.prefix + msg).digest(), "little") % _L
        r_enc = _encode(_add(_mul(r, _BASE), r_extra))
        k = int.from_bytes(hashlib.sha512(r_enc + a_bytes + msg).digest(), "little") % _L
        s = (r + k * self.scalar) % _L
        return r_enc + s.to_bytes(32, "little")

    def craft_small_order_r(self, msg: bytes) -> bytes:
        """R = a point of order 8, S = kA: accepted only by a cofactored check."""
        r_enc = _encode(_T8)
        k = int.from_bytes(hashlib.sha512(r_enc + self.pub + msg).digest(), "little") % _L
        return r_enc + (k * self.scalar % _L).to_bytes(32, "little")


ED = EdKey.from_seed(ED_SEED)
HYB_ED = EdKey.from_seed(HYB_ED_SEED)
MIXED = EdKey.from_seed(MIXED_SEED)
MIXED_PUB = _encode(_add(_mul(MIXED.scalar, _BASE), _T8))
SMALL_PUB = _encode(_T8)
NONCANON_PUB = _noncanonical_point_encoding()

_MLDSA_CACHE: dict[bytes, bytes] = {}


def _mldsa_sign(msg: bytes) -> bytes:
    """Deterministic ML-DSA-65 (the dev oracle), cached: it is the slow step."""
    if msg not in _MLDSA_CACHE:
        _MLDSA_CACHE[msg] = ML_DSA_65.sign(HYB_MLDSA_SK, msg, deterministic=True)
    return _MLDSA_CACHE[msg]


b64u = keys.b64u

# --- payloads, envelopes, trust stores ---------------------------------------


def base_payload(version: str) -> dict[str, Any]:
    return issue.build_payload(
        issuer_id=ISSUER,
        display_name="Example Games Store",
        buyer_identifier="buyer-001",
        buyer_identifier_type="issuer-account",
        buyer_salt=bytes(range(16)),
        title="Example Game",
        publisher="Example Publisher srl",
        identifiers={"issuer_sku": "EXG-001"},
        artifact_series=f"{ISSUER}/works/EXG-001",
        terms_uri=f"https://{ISSUER}/attest/license-templates/standard-v1",
        legal_text_sha256=hashlib.sha256(b"attest-differential-legal-text").hexdigest(),
        receipt_id=RECEIPT_ID,
        issued_at=ISSUED_AT,
        attest_version=version,
    )


def ed_block(kid: str, sig: bytes | str, alg: str = "Ed25519") -> dict[str, Any]:
    return {"kid": kid, "alg": alg, "sig": sig if isinstance(sig, str) else b64u(sig)}


def mldsa_block(kid: str, msg: bytes) -> dict[str, Any]:
    return {"kid": kid, "alg": "ML-DSA-65", "sig": b64u(_mldsa_sign(msg))}


def v01_envelope(payload: Any, key: EdKey = ED, kid: str = ED_KID) -> dict[str, Any]:
    return {
        "payload": payload,
        "signatures": [ed_block(kid, key.sign(canon.canonical_bytes(payload)))],
    }


def v02_envelope(payload: Any, key: EdKey = HYB_ED, kid: str = HYB_KID) -> dict[str, Any]:
    msg = canon.canonical_bytes(payload)
    return {"payload": payload, "signatures": [ed_block(kid, key.sign(msg)), mldsa_block(kid, msg)]}


def _entry(kid: str, pub: bytes, mldsa: bytes | None = None) -> dict[str, Any]:
    return manifests.key_entry(kid, pub, VALID_FROM, None, "active", pub_ml_dsa_65=mldsa)


def _sign_manifest(body: dict[str, Any], signer: str) -> dict[str, Any]:
    body = {k: v for k, v in body.items() if k != "manifest_signature"}
    signable = manifests._signable(body)
    if signer == "hybrid":
        body["manifest_signature"] = {
            "kid": HYB_KID,
            "sig": b64u(HYB_ED.sign(signable)),
            "sig_ml_dsa_65": b64u(_mldsa_sign(signable)),
        }
    else:
        body["manifest_signature"] = {"kid": ED_KID, "sig": b64u(ED.sign(signable))}
    return body


def manifest(store_name: str) -> dict[str, Any]:
    """`mixed`: every key kind under one Ed25519-signed manifest. `hybrid`:
    the hybrid key alone, signed with both legs. `ed`: the Ed25519 key alone."""
    if store_name == "hybrid":
        entries = [_entry(HYB_KID, HYB_ED.pub, HYB_MLDSA_PK)]
        signer = "hybrid"
    elif store_name == "ed":
        entries = [_entry(ED_KID, ED.pub)]
        signer = "ed"
    else:
        entries = [
            _entry(ED_KID, ED.pub),
            _entry(HYB_KID, HYB_ED.pub, HYB_MLDSA_PK),
            _entry(MIXED_KID, MIXED_PUB),
            _entry(SMALL_KID, SMALL_PUB),
            _entry(NONCANON_KID, NONCANON_PUB),
        ]
        signer = "ed"
    body = {"issuer": ISSUER, "manifest_version": 1, "issued_at": VALID_FROM, "keys": entries}
    return _sign_manifest(body, signer)


def store_bytes(manifest_doc: dict[str, Any]) -> bytes:
    document = {
        "manifests": {ISSUER: manifest_doc},
        "provenance": {ISSUER: "tls"},
        "chains": {},
        "artifact_manifests": {},
        "artifact_manifest_chains": {},
    }
    return json.dumps(document, ensure_ascii=False).encode("utf-8")


# --- JSON text with control over its spelling --------------------------------


def dumps(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def _escape_all(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" if ord(c) < 0x10000 else json.dumps(c)[1:-1] for c in s)


def emit(value: Any, path: tuple[Any, ...], edit: Callable[[Any], str] | None) -> str:
    """json.dumps, except the node at `path` is spelled by `edit(node)`."""
    if edit is not None and not path:
        return edit(value)
    if isinstance(value, dict):
        members = []
        for key, item in value.items():
            sub = path[1:] if path and path[0] == key else None
            members.append(
                json.dumps(key, ensure_ascii=False)
                + ":"
                + (emit(item, sub, edit) if sub is not None else emit(item, (), None))
            )
        return "{" + ",".join(members) + "}"
    if isinstance(value, list):
        items = []
        for index, item in enumerate(value):
            sub = path[1:] if path and path[0] == index else None
            items.append(emit(item, sub, edit) if sub is not None else emit(item, (), None))
        return "[" + ",".join(items) + "]"
    return json.dumps(value, ensure_ascii=False)


def get_path(root: Any, path: tuple[Any, ...]) -> Any:
    for step in path:
        root = root[step]
    return root


def set_path(root: Any, path: tuple[Any, ...], value: Any) -> None:
    get_path(root, path[:-1])[path[-1]] = value


def all_paths(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    paths = [prefix]
    if isinstance(value, dict):
        for key, item in value.items():
            paths.extend(all_paths(item, (*prefix, key)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            paths.extend(all_paths(item, (*prefix, index)))
    return paths


# --- cases -------------------------------------------------------------------


@dataclass
class Case:
    id: str
    family: str
    label: str
    envelope: bytes
    store: str  # a key of the store table


@dataclass
class Bases:
    v01: dict[str, Any]
    v02: dict[str, Any]
    env01: dict[str, Any]
    env02: dict[str, Any]
    manifests: dict[str, dict[str, Any]]


def build_bases() -> Bases:
    v01 = base_payload("0.1")
    v02 = base_payload("0.2")
    return Bases(
        v01=v01,
        v02=v02,
        env01=v01_envelope(v01),
        env02=v02_envelope(v02),
        manifests={name: manifest(name) for name in ("mixed", "hybrid", "ed")},
    )


B64_INSERTS = (
    " ",
    "\n",
    "\t",
    "\r",
    "!",
    ".",
    "*",
    "~",
    "%",
    "\u00e9",
    "=",
    "\u00a0",
    "\x00",
    "A",
    "+",
    "/",
)
_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def b64_edits(rng: random.Random, s: str) -> tuple[str, str]:
    """One base64url spelling edit of `s`, and its label."""
    choice = rng.randrange(14)
    if choice == 0:
        char = rng.choice(B64_INSERTS)
        pos = rng.randrange(len(s) + 1)
        return s[:pos] + char + s[pos:], f"insert {char!r} at {pos}"
    if choice == 1:
        char = rng.choice(B64_INSERTS)
        count = rng.choice((2, 3, 4, 8))
        pos = rng.randrange(len(s) + 1)
        return s[:pos] + char * count + s[pos:], f"insert {count}x{char!r} at {pos}"
    if choice == 2:
        pad = rng.choice(("=", "==", "===", "===="))
        return s + pad, f"append {pad!r}"
    if choice == 3:
        return "=" + s, "prepend '='"
    if choice == 4:
        return s.replace("-", "+").replace("_", "/"), "standard alphabet"
    if choice == 5:
        last = _B64_ALPHABET.index(s[-1]) if s and s[-1] in _B64_ALPHABET else 0
        flipped = _B64_ALPHABET[last ^ rng.choice((1, 2, 3, 15))]
        return s[:-1] + flipped, f"trailing bits {s[-1:]!r}->{flipped!r}"
    if choice == 6:
        n = rng.choice((1, 2, 3, 4))
        return s[:-n], f"truncate {n}"
    if choice == 7:
        tail = rng.choice(("A", "AA", "AAA", "AAAA"))
        return s + tail, f"append {tail!r}"
    if choice == 8:
        return "", "empty"
    if choice == 9:
        return s.swapcase(), "swapcase"
    if choice == 10:
        pos = rng.randrange(max(1, len(s) - 4))
        return s[:pos] + "    " + s[pos + 4 :], f"blank 4 at {pos}"
    if choice == 11:
        pos = rng.randrange(len(s) + 1)
        return s[:pos] + "\r\n" + s[pos:], f"insert CRLF at {pos}"
    if choice == 12:
        return s + "\n", "trailing newline"
    pos = rng.randrange(len(s)) if s else 0
    return s[:pos] + "=" + s[pos + 1 :], f"'=' at {pos}"


def _envelope_case(
    family: str, label: str, envelope: Any, store: str
) -> tuple[str, str, bytes, str]:
    return (family, label, dumps(envelope), store)


def gen_b64(rng: random.Random, b: Bases) -> list[tuple[str, str, bytes, str]]:
    """Edit an unsigned signature string, or a key string under a re-signed manifest."""
    target = rng.randrange(6)
    if target <= 2:
        env = json.loads(json.dumps(b.env01 if target == 0 else b.env02))
        leg = 0 if target in (0, 1) else 1
        edited, label = b64_edits(rng, env["signatures"][leg]["sig"])
        env["signatures"][leg]["sig"] = edited
        store = "ed" if target == 0 else rng.choice(("hybrid", "mixed"))
        return [
            _envelope_case(
                "b64-sig", f"sig[{leg}] v0.{1 if target == 0 else 2}: {label}", env, store
            )
        ]
    # A key string. The manifest is re-signed after the edit, so the edit is
    # what the verifier meets, not a broken manifest signature.
    name = "ed" if target == 3 else "hybrid"
    doc = json.loads(json.dumps(b.manifests[name]))
    member = "pub" if target != 5 else "pub_ml_dsa_65"
    edited, label = b64_edits(rng, doc["keys"][0][member])
    doc["keys"][0][member] = edited
    doc = _sign_manifest(doc, "ed" if name == "ed" else "hybrid")
    store = f"edited-{len(_DYNAMIC_STORES)}"
    _DYNAMIC_STORES[store] = doc
    env = b.env01 if name == "ed" else b.env02
    return [_envelope_case("b64-key", f"{name} keys[0].{member}: {label}", env, store)]


def gen_b64_manifest_sig(rng: random.Random, b: Bases) -> list[tuple[str, str, bytes, str]]:
    """Edit the manifest's own (unsigned) signature string."""
    name = rng.choice(("ed", "hybrid"))
    doc = json.loads(json.dumps(b.manifests[name]))
    member = "sig" if name == "ed" or rng.random() < 0.5 else "sig_ml_dsa_65"
    edited, label = b64_edits(rng, doc["manifest_signature"][member])
    doc["manifest_signature"][member] = edited
    store = f"edited-{len(_DYNAMIC_STORES)}"
    _DYNAMIC_STORES[store] = doc
    env = b.env01 if name == "ed" else b.env02
    return [
        _envelope_case(
            "b64-manifest-sig", f"{name} manifest_signature.{member}: {label}", env, store
        )
    ]


def gen_ed25519(rng: random.Random, b: Bases) -> list[tuple[str, str, bytes, str]]:
    msg01 = canon.canonical_bytes(b.v01)
    msg02 = canon.canonical_bytes(b.v02)
    honest01 = ED.sign(msg01)
    variants: list[tuple[str, Callable[[], tuple[dict[str, Any], str]]]] = [
        ("mixed-order R", lambda: (_v01_with(b, ED_KID, ED.craft(msg01, r_extra=_T8)), "mixed")),
        ("small-order R", lambda: (_v01_with(b, ED_KID, ED.craft_small_order_r(msg01)), "mixed")),
        (
            "mixed-order R, order-4 torsion",
            lambda: (_v01_with(b, ED_KID, ED.craft(msg01, r_extra=_mul(2, _T8))), "mixed"),
        ),
        (
            "mixed-order A",
            lambda: (_v01_with(b, MIXED_KID, MIXED.craft(msg01, a_enc=MIXED_PUB)), "mixed"),
        ),
        (
            "mixed-order A and R",
            lambda: (
                _v01_with(b, MIXED_KID, MIXED.craft(msg01, r_extra=_T8, a_enc=MIXED_PUB)),
                "mixed",
            ),
        ),
        (
            "small-order A, identity R",
            lambda: (_v01_with(b, SMALL_KID, _encode(_IDENTITY) + bytes(32)), "mixed"),
        ),
        ("small-order A, honest sig", lambda: (_v01_with(b, SMALL_KID, honest01), "mixed")),
        ("non-canonical A", lambda: (_v01_with(b, NONCANON_KID, honest01), "mixed")),
        ("non-canonical S (S+L)", lambda: (_v01_with(b, ED_KID, _s_plus_l(honest01)), "ed")),
        (
            "S top bit set",
            lambda: (_v01_with(b, ED_KID, honest01[:63] + bytes([honest01[63] | 0x80])), "ed"),
        ),
        (
            "R sign bit flipped",
            lambda: (
                _v01_with(b, ED_KID, honest01[:31] + bytes([honest01[31] ^ 0x80]) + honest01[32:]),
                "ed",
            ),
        ),
        (
            "non-canonical R (y >= p)",
            lambda: (_v01_with(b, ED_KID, NONCANON_PUB + honest01[32:]), "ed"),
        ),
        (
            "negative-zero R",
            lambda: (
                _v01_with(b, ED_KID, (1 | 1 << 255).to_bytes(32, "little") + honest01[32:]),
                "ed",
            ),
        ),
        ("all-zero signature", lambda: (_v01_with(b, ED_KID, bytes(64)), "ed")),
        (
            "v0.2 Ed leg mixed-order R",
            lambda: (_v02_with(b, HYB_ED.craft(msg02, r_extra=_T8)), "hybrid"),
        ),
        (
            "v0.2 Ed leg small-order R",
            lambda: (_v02_with(b, HYB_ED.craft_small_order_r(msg02)), "hybrid"),
        ),
        (
            "v0.2 Ed leg mixed-order R, mixed keyset",
            lambda: (_v02_with(b, HYB_ED.craft(msg02, r_extra=_T8)), "mixed"),
        ),
    ]
    label, make = rng.choice(variants)
    env, store = make()
    return [_envelope_case("ed25519", label, env, store)]


def _s_plus_l(sig: bytes) -> bytes:
    s = int.from_bytes(sig[32:], "little") + _L
    return sig[:32] + s.to_bytes(32, "little")


def _v01_with(b: Bases, kid: str, sig: bytes) -> dict[str, Any]:
    return {"payload": b.v01, "signatures": [ed_block(kid, sig)]}


def _v02_with(b: Bases, ed_sig: bytes) -> dict[str, Any]:
    msg = canon.canonical_bytes(b.v02)
    return {"payload": b.v02, "signatures": [ed_block(HYB_KID, ed_sig), mldsa_block(HYB_KID, msg)]}


HUGE = "x" * 100_000
TYPE_VALUES: tuple[tuple[str, Any], ...] = (
    ("object", {}),
    ("object{a:1}", {"a": 1}),
    ("object{alg:Ed25519}", {"alg": "Ed25519"}),
    ("array", []),
    ("array[1]", [1]),
    ("array[str]", ["Ed25519"]),
    ("int 0", 0),
    ("int 1", 1),
    ("int -1", -1),
    ("int 2^53", 2**53),
    ("int 2^53-1", 2**53 - 1),
    ("float", 1.5),
    ("null", None),
    ("true", True),
    ("false", False),
    ("empty string", ""),
    ("huge string", HUGE),
    ("NUL string", "\x00"),
    ("space", " "),
)
#: The TYPE_VALUES the attest-JCS profile admits (no float, no integer past 2^53 - 1).
PROFILE_VALUES = tuple((n, v) for n, v in TYPE_VALUES if n not in ("float", "int 2^53"))


def gen_type(rng: random.Random, b: Bases) -> list[tuple[str, str, bytes, str]]:
    """Replace one member (or container) anywhere in the envelope with another JSON type."""
    v2 = rng.random() < 0.35
    env = json.loads(json.dumps(b.env02 if v2 else b.env01))
    path = rng.choice(all_paths(env))
    name, value = rng.choice(TYPE_VALUES)
    value = json.loads(json.dumps(value))
    if path == ():
        env = value
    else:
        set_path(env, path, value)
    label = f"v0.{2 if v2 else 1} {'/'.join(map(str, path)) or '<root>'} -> {name}"
    # Re-sign half of the payload edits: unsigned, the signature check refuses
    # first; re-signed, the edit reaches the schema and the later steps.
    if path[:1] == ("payload",) and isinstance(env, dict) and rng.random() < (0.15 if v2 else 0.6):
        resigned = _resign(env, v2)
        if resigned is not None:
            env, label = resigned, label + " (re-signed)"
    return [
        _envelope_case(
            "type", label, env, "mixed" if rng.random() < 0.5 else ("hybrid" if v2 else "ed")
        )
    ]


def _resign(env: dict[str, Any], v2: bool) -> dict[str, Any] | None:
    payload = env.get("payload")
    try:
        msg = canon.canonical_bytes(payload)
    except (canon.CanonError, TypeError, ValueError):
        return None
    sigs = env.get("signatures")
    if not isinstance(sigs, list) or not sigs or not all(isinstance(s, dict) for s in sigs):
        return None
    out = dict(env)
    new = [dict(s) for s in sigs]
    if v2:
        if len(new) != 2:
            return None
        new[0]["sig"] = b64u(HYB_ED.sign(msg))
        new[1]["sig"] = b64u(_mldsa_sign(msg))
    else:
        new[0]["sig"] = b64u(ED.sign(msg))
    out["signatures"] = new
    return out


def _v01_alg(payload: dict[str, Any], alg: str) -> dict[str, Any]:
    msg = canon.canonical_bytes(payload)
    return {"payload": payload, "signatures": [ed_block(ED_KID, ED.sign(msg), alg)]}


def _v02_alg(payload: dict[str, Any], alg: str) -> dict[str, Any]:
    msg = canon.canonical_bytes(payload)
    return {
        "payload": payload,
        "signatures": [ed_block(HYB_KID, HYB_ED.sign(msg), alg), mldsa_block(HYB_KID, msg)],
    }


def gen_version(rng: random.Random, b: Bases) -> list[tuple[str, str, bytes, str]]:
    """attest_version / alg / signature-count swaps, signatures kept genuine."""
    msg01 = canon.canonical_bytes(b.v01)
    msg02 = canon.canonical_bytes(b.v02)
    choices: list[tuple[str, Callable[[], Any]]] = [
        (
            "v0.1 payload, hybrid two-leg envelope",
            lambda: {
                "payload": b.v01,
                "signatures": [ed_block(HYB_KID, HYB_ED.sign(msg01)), mldsa_block(HYB_KID, msg01)],
            },
        ),
        (
            "v0.2 payload, single Ed25519 leg under hybrid kid",
            lambda: {"payload": b.v02, "signatures": [ed_block(HYB_KID, HYB_ED.sign(msg02))]},
        ),
        (
            "v0.2 payload, single Ed25519 leg under Ed25519 kid",
            lambda: {"payload": b.v02, "signatures": [ed_block(ED_KID, ED.sign(msg02))]},
        ),
        (
            "v0.2 legs reversed",
            lambda: {"payload": b.v02, "signatures": list(reversed(b.env02["signatures"]))},
        ),
        (
            "v0.2 Ed leg twice",
            lambda: {
                "payload": b.v02,
                "signatures": [b.env02["signatures"][0], b.env02["signatures"][0]],
            },
        ),
        (
            "v0.2 three signatures",
            lambda: {
                "payload": b.v02,
                "signatures": [*b.env02["signatures"], b.env02["signatures"][1]],
            },
        ),
        (
            "v0.1 two Ed signatures",
            lambda: {
                "payload": b.v01,
                "signatures": [b.env01["signatures"][0], b.env01["signatures"][0]],
            },
        ),
        ("no signatures", lambda: {"payload": b.v01, "signatures": []}),
    ]
    for alg in (
        "ed25519",
        "EdDSA",
        "ML-DSA-65",
        "ML-DSA-44",
        "Ed25519 ",
        " Ed25519",
        "Ed448",
        "ED25519",
        "Ed25519\x00",
    ):
        choices.append(
            (
                f"v0.1 alg {alg!r}",
                partial(_v01_alg, b.v01, alg),
            )
        )
        choices.append(
            (
                f"v0.2 Ed leg alg {alg!r}",
                partial(_v02_alg, b.v02, alg),
            )
        )
    for version in ("0.3", "0.10", "0.2 ", "1", "1.0", "0.1.0", "v0.1", "", "\uff10.1"):
        payload = dict(b.v01, attest_version=version)
        choices.append(
            (f"attest_version {version!r} (Ed25519-signed)", partial(v01_envelope, payload))
        )
    label, make = rng.choice(choices)
    return [_envelope_case("version", label, make(), rng.choice(("mixed", "ed", "hybrid")))]


def gen_kid(rng: random.Random, b: Bases) -> list[tuple[str, str, bytes, str]]:
    """Kid swaps between Ed25519-only and hybrid entries, and spellings of kids."""
    msg02 = canon.canonical_bytes(b.v02)
    choices: list[tuple[str, Callable[[], Any]]] = [
        (
            "v0.1 under hybrid kid, signed by hybrid Ed leg",
            lambda: v01_envelope(b.v01, HYB_ED, HYB_KID),
        ),
        ("v0.1 under hybrid kid, signed by Ed25519 key", lambda: v01_envelope(b.v01, ED, HYB_KID)),
        (
            "v0.2 under Ed25519-only kid, both legs genuine",
            lambda: {
                "payload": b.v02,
                "signatures": [ed_block(ED_KID, ED.sign(msg02)), mldsa_block(ED_KID, msg02)],
            },
        ),
        (
            "v0.2 Ed leg Ed25519 kid, ML-DSA leg hybrid kid",
            lambda: {
                "payload": b.v02,
                "signatures": [ed_block(ED_KID, ED.sign(msg02)), mldsa_block(HYB_KID, msg02)],
            },
        ),
        (
            "v0.2 Ed leg hybrid kid, ML-DSA leg Ed25519 kid",
            lambda: {
                "payload": b.v02,
                "signatures": [ed_block(HYB_KID, HYB_ED.sign(msg02)), mldsa_block(ED_KID, msg02)],
            },
        ),
        (
            "v0.2 under mixed-order kid",
            lambda: {
                "payload": b.v02,
                "signatures": [
                    ed_block(MIXED_KID, MIXED.sign(msg02)),
                    mldsa_block(MIXED_KID, msg02),
                ],
            },
        ),
    ]
    for kid in (
        f"{ISSUER}/keys/2025-01#ed25519-9",
        "evil.example.com/keys/2025-01#ed25519-1",
        f"{ISSUER.upper()}/keys/2025-01#ed25519-1",
        f"{ED_KID} ",
        f" {ED_KID}",
        f"{ED_KID}\x00",
        ED_KID.replace("e", "\u0435", 1),  # Cyrillic e
        ISSUER,
        f"{ISSUER}/",
        "",
        f"{ISSUER}//keys/2025-01#ed25519-1",
    ):
        choices.append((f"v0.1 kid {kid!r}", partial(v01_envelope, b.v01, ED, kid)))
    label, make = rng.choice(choices)
    return [_envelope_case("kid", label, make(), rng.choice(("mixed", "ed", "hybrid")))]


def gen_json(rng: random.Random, b: Bases) -> list[tuple[str, str, bytes, str]]:
    """Spellings of the same (or nearly the same) envelope as JSON text."""
    v2 = rng.random() < 0.3
    env = b.env02 if v2 else b.env01
    store = "hybrid" if v2 else "ed"
    tag = f"v0.{2 if v2 else 1}"
    objects = [p for p in all_paths(env) if isinstance(get_path(env, p), dict) and get_path(env, p)]
    strings = [p for p in all_paths(env) if isinstance(get_path(env, p), str)]
    # Weighted: the two size cases (8, 9) cost a megabyte of canonicalization each.
    choice = rng.choices(range(12), weights=(3, 2, 2, 3, 2, 2, 2, 1, 0.4, 0.4, 1, 2))[0]
    if choice == 0:
        path = rng.choice(objects)
        node = get_path(env, path)
        key = rng.choice(list(node))
        # A value the profile admits, so the duplicate is the case's ONE defect:
        # a float or an out-of-range integer would be a second one, and which
        # of two defects a parser names first is its own business.
        alt = rng.choice(PROFILE_VALUES)[1] if rng.random() < 0.5 else node[key]
        first = rng.random() < 0.5

        def dup(o: Any) -> str:
            inner = emit(o, (), None)[1:-1]
            extra = json.dumps(key, ensure_ascii=False) + ":" + json.dumps(alt, ensure_ascii=False)
            return "{" + (extra + "," + inner if first else inner + "," + extra) + "}"

        text = emit(env, path, dup)
        return [
            (
                "json",
                f"{tag} duplicate key {key!r} in /{'/'.join(map(str, path))}",
                text.encode(),
                store,
            )
        ]
    if choice == 1:
        path = rng.choice(objects)
        node = get_path(env, path)
        key = rng.choice(list(node))

        def esc_key(o: Any) -> str:
            members = []
            for k, v in o.items():
                spelled = (
                    '"' + _escape_all(k) + '"' if k == key else json.dumps(k, ensure_ascii=False)
                )
                members.append(spelled + ":" + emit(v, (), None))
            return "{" + ",".join(members) + "}"

        text = emit(env, path, esc_key)
        return [("json", f"{tag} \\u-escaped key {key!r}", text.encode(), store)]
    if choice == 2:
        path = rng.choice(strings)
        text = emit(env, path, lambda s: '"' + _escape_all(s) + '"')
        return [
            (
                "json",
                f"{tag} \\u-escaped string at /{'/'.join(map(str, path))}",
                text.encode(),
                store,
            )
        ]
    if choice == 3:
        path = rng.choice(strings)
        trick = rng.choice(
            (
                "\\ud800",
                "\\udc00",
                "\\ud800\\ud800",
                "\\/",
                "\\u0000",
                "\u2028",
                "\\u2028",
                "\\ufeff",
                "\\uDBFF\\uDFFF",
            )
        )
        pos_end = rng.random() < 0.5
        text = emit(
            env,
            path,
            lambda s: (
                '"'
                + (json.dumps(s)[1:-1] + trick if pos_end else trick + json.dumps(s)[1:-1])
                + '"'
            ),
        )
        return [
            (
                "json",
                f"{tag} {trick!r} in string /{'/'.join(map(str, path))}",
                text.encode("utf-8", "surrogatepass"),
                store,
            )
        ]
    if choice == 4:
        raw = dumps(env)
        prefix, suffix = rng.choice(
            (
                (b"\xef\xbb\xbf", b""),
                (b"", b"\n"),
                (b" \t\r\n", b" \t\r\n"),
                (b"", b" x"),
                (b"", b"{}"),
                (b"", b"\x00"),
                (b"", b","),
                (b"\x00", b""),
                (b"", b"\xff"),
                (b"", b"//"),
            )
        )
        return [
            ("json", f"{tag} prefix {prefix!r} suffix {suffix!r}", prefix + raw + suffix, store)
        ]
    if choice == 5:
        raw = dumps(env)
        pos = rng.randrange(len(raw))
        byte = rng.choice(
            (b"\xff", b"\xc0\xaf", b"\xed\xa0\x80", b"\x80", b"\xf4\x90\x80\x80", b"\x00")
        )
        return [("json", f"{tag} byte {byte!r} at {pos}", raw[:pos] + byte + raw[pos:], store)]
    if choice == 6:
        number = rng.choice(
            (
                "1.0",
                "-0",
                "1e2",
                "1E2",
                "01",
                "NaN",
                "Infinity",
                "-Infinity",
                "1e400",
                "9007199254740993",
                "-9007199254740993",
                "0.1e1",
                "1.",
                ".5",
                "+1",
                "0x10",
            )
        )
        member = rng.choice(("attest_version", "x_extra", "issued_at"))
        if member == "x_extra":
            text = emit(
                env, ("payload",), lambda p: emit(p, (), None)[:-1] + f',"x_extra":{number}}}'
            )
        else:
            text = emit(env, ("payload", member), lambda _: number)
        return [("json", f"{tag} number {number} at payload.{member}", text.encode(), store)]
    if choice == 7:
        depth = rng.choice((200, 254, 255, 256, 257, 300))
        payload = json.loads(json.dumps(env["payload"]))
        nest: Any = 0
        for _ in range(depth):
            nest = [nest]
        payload["work"]["x_nest"] = nest
        label = f"{tag} array nesting {depth} in payload.work"
        if rng.random() < 0.5:
            try:
                resigned = _resign({"payload": payload, "signatures": env["signatures"]}, v2)
            except RecursionError:
                resigned = None
            if resigned is not None:
                return [("json", label + " (re-signed)", dumps(resigned), store)]
        return [
            (
                "json",
                label,
                emit({"payload": payload, "signatures": env["signatures"]}, (), None).encode(),
                store,
            )
        ]
    if choice == 8:
        raw = dumps(env)
        size = MAX_ENVELOPE_BYTES + rng.choice((-1, 0, 1, 2))
        return [
            (
                "json",
                f"{tag} padded with spaces to {size} bytes",
                raw + b" " * (size - len(raw)),
                store,
            )
        ]
    if choice == 9:
        # A signed payload whose own string makes the envelope land on the ceiling.
        size = MAX_ENVELOPE_BYTES + rng.choice((-1, 0, 1))
        sized = _sized_envelope(size)
        return [("json", f"v0.1 title filling the envelope to {size} bytes (signed)", sized, "ed")]
    if choice == 10:
        ws = rng.choice(("\u00a0", "\u2028", "\f", "\v", "\x85"))
        text = dumps(env).decode()
        pos = text.index('"signatures"')
        return [
            (
                "json",
                f"{tag} non-JSON whitespace {ws!r} between members",
                (text[:pos] + ws + text[pos:]).encode(),
                store,
            )
        ]
    # Members the envelope does not define, at the top and in a signature block.
    where = rng.choice(("top", "sig"))
    extra = json.loads(json.dumps(env))
    if where == "top":
        extra[rng.choice(("x", "payload ", "Payload", "signature"))] = rng.choice(TYPE_VALUES)[1]
    else:
        extra["signatures"][0][rng.choice(("x", "crit", "kid ", "sig_ml_dsa_65"))] = "AAAA"
    return [("json", f"{tag} unknown member ({where})", dumps(extra), store)]


_DYNAMIC_STORES: dict[str, dict[str, Any]] = {}
_SIZED: dict[int, bytes] = {}


def _sized_envelope(size: int) -> bytes:
    """A genuinely signed v0.1 envelope of exactly `size` bytes, its title
    filling the difference (cached: the title is a megabyte to canonicalize)."""
    if size not in _SIZED:
        payload = base_payload("0.1")
        payload["work"]["title"] = ""
        empty = len(dumps(v01_envelope(payload)))
        payload["work"]["title"] = "t" * (size - empty)
        _SIZED[size] = dumps(v01_envelope(payload))
        if len(_SIZED[size]) != size:
            raise AssertionError(f"sized envelope is {len(_SIZED[size])} bytes, not {size}")
    return _SIZED[size]


FAMILIES: tuple[
    tuple[str, int, Callable[[random.Random, Bases], list[tuple[str, str, bytes, str]]]], ...
] = (
    ("b64", 4, gen_b64),
    ("b64-manifest-sig", 1, gen_b64_manifest_sig),
    ("ed25519", 3, gen_ed25519),
    ("type", 6, gen_type),
    ("version", 2, gen_version),
    ("kid", 2, gen_kid),
    ("json", 4, gen_json),
)


def generate(count: int, seed: int, bases: Bases) -> list[Case]:
    rng = random.Random(seed)  # noqa: S311 -- reproducible test data, not secrets
    weights = [weight for _, weight, _ in FAMILIES]
    cases = [
        Case("baseline-v01", "baseline", "valid v0.1", dumps(bases.env01), "ed"),
        Case("baseline-v02", "baseline", "valid v0.2", dumps(bases.env02), "hybrid"),
        Case(
            "baseline-v02-mixed",
            "baseline",
            "valid v0.2, mixed keyset",
            dumps(bases.env02),
            "mixed",
        ),
    ]
    while len(cases) < count:
        _, _, make = rng.choices(FAMILIES, weights)[0]
        for family, label, envelope, store in make(rng, bases):
            cases.append(Case(f"{seed}-{len(cases):05d}", family, label, envelope, store))
    return cases[:count]


# --- the two verdicts ----------------------------------------------------------


def _result_to_json(result: verify_module.VerificationResult) -> dict[str, Any]:
    return {
        "signature": result.signature,
        "schema": result.schema,
        "trust": result.trust,
        "revocation": result.revocation,
        "binding": result.binding,
        "transparency": result.transparency,
        "corroboration": result.corroboration,
        "manifest_freshness": result.manifest_freshness,
        "grant": result.grant,
        "grant_trust": result.grant_trust,
        "publisher_authority": result.publisher_authority,
        "publisher_authority_trust": result.publisher_authority_trust,
        "ok": result.ok,
        "errors": list(result.errors),
        "warnings": list(result.warnings),
    }


#: Refusals of the envelope TEXT before anything is read out of it. Both cores
#: refuse the same bytes here, but the wording after the prefix is the JSON
#: parser's own diagnostic, which neither core controls: Python's `json` names
#: line and column, the TypeScript parser an offset, and a NaN or a too-deep
#: nesting is a parse error to one parser and a profile error to the other.
#: Compared by class, as the trust-material differential compares M7/M8.
_PARSE_REFUSAL = "<envelope text refused while parsing>"
_PARSE_REFUSAL_PREFIXES = ("invalid JSON: ",)
_PARSE_REFUSAL_EXACT = frozenset(
    {"maximum nesting depth exceeded", "floats are not allowed in the attest-JCS profile"}
)
_UTF8_PREFIX = "input is not valid UTF-8: "
#: Schema violations are worded by each core's own validator (jsonschema on one
#: side, a hand-written validator on the other), and they do not even agree on
#: how many violations one defect is. The conformance corpus never pins them
#: either; `schema: "invalid"` is what both owe each other, and it is compared.
_SCHEMA_VIOLATIONS = "<schema violations: worded by each core's validator>"


def _message(text: str) -> str:
    """One error or warning, as the two cores owe it to each other.

    Everything is compared word for word except two things. The parser's own
    diagnostic (see `_PARSE_REFUSAL`). And how a hostile value is QUOTED inside
    a message: Python's `repr` escapes characters that are not printable
    (`'\\x00'`, `'\\ufeff'`) and the TypeScript `pyRepr` is documented as a
    deliberately limited renderer that writes them raw. Rendering every
    non-printable character the way `repr` does, on both sides, leaves the
    message text itself compared exactly.
    """
    if text.startswith(_PARSE_REFUSAL_PREFIXES) or text in _PARSE_REFUSAL_EXACT:
        return _PARSE_REFUSAL
    if text.startswith(_UTF8_PREFIX):
        return _UTF8_PREFIX.rstrip()
    return "".join(ch if ch.isprintable() else repr(ch)[1:-1] for ch in text)


def comparable(verdict: dict[str, Any]) -> dict[str, Any]:
    """The verdict reduced to what both cores must report identically.

    The verdict itself, every enumerated member and `ok` are kept as they are.
    A crash keeps its text: it is a finding whatever the other side says.
    """
    if "result" not in verdict:
        return verdict
    result = dict(verdict["result"])
    if result["schema"] == "invalid":
        result["errors"] = _SCHEMA_VIOLATIONS
    else:
        result["errors"] = [_message(e) for e in result["errors"]]
    result["warnings"] = [_message(w) for w in result["warnings"]]
    return {"verdict": verdict["verdict"], "result": result}


def python_verdict(envelope: bytes, store: bytes) -> dict[str, Any]:
    try:
        trust_store = trust_material.TrustStore.from_bytes(store)
    except trust_material.TrustMaterialError:
        return {"verdict": "store_refused"}
    except Exception as error:
        return {"verdict": "crash", "error": f"{type(error).__name__}: {error}"}
    try:
        result = verify_module.verify(envelope, trust_store)
    except Exception as error:
        return {"verdict": "crash", "error": f"{type(error).__name__}: {error}"}
    return {"verdict": "ok" if result.ok else "invalid", "result": _result_to_json(result)}


def ts_verdicts(cases: list[Case], stores: dict[str, bytes]) -> list[dict[str, Any]]:
    lines = [
        json.dumps({"store_id": name, "store": base64.b64encode(data).decode()})
        for name, data in stores.items()
    ]
    lines += [
        json.dumps(
            {"id": c.id, "store_id": c.store, "envelope": base64.b64encode(c.envelope).decode()}
        )
        for c in cases
    ]
    result = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        ["node", str(ADAPTER)],  # noqa: S607 -- node resolved from PATH, as every other node call here
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    if result.returncode != 0:
        raise SystemExit(f"the TypeScript adapter failed:\n{result.stderr}")
    out = [json.loads(line) for line in result.stdout.split("\n") if line.strip()]
    if len(out) != len(cases):
        raise SystemExit(f"expected {len(cases)} verdicts, got {len(out)}")
    return out


def _property_cases(bases: Bases) -> list[Case]:
    """Both sides must REFUSE these, whether or not they agree."""
    env = v01_envelope(bases.v01, HYB_ED, HYB_KID)
    return [
        Case(
            "property-v01-hybrid-kid",
            "property",
            "v0.1 receipt under hybrid kid (hybrid store)",
            dumps(env),
            "hybrid",
        ),
        Case(
            "property-v01-hybrid-kid-mixed",
            "property",
            "v0.1 receipt under hybrid kid (mixed store)",
            dumps(env),
            "mixed",
        ),
    ]


def _short(data: bytes, limit: int = 600) -> str:
    text = data.decode("utf-8", "backslashreplace")
    return text if len(text) <= limit else f"{text[:limit]}... ({len(data)} bytes)"


def _keep(keep: Path, case: Case, store: bytes, py: dict[str, Any], ts: dict[str, Any]) -> Path:
    leaf = keep / case.id
    leaf.mkdir(parents=True, exist_ok=True)
    (leaf / "envelope.raw.json").write_bytes(case.envelope)
    (leaf / "manifests.json").write_bytes(store)
    (leaf / "divergence.json").write_text(
        json.dumps(
            {"family": case.family, "mutation": case.label, "python": py, "typescript": ts},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return leaf


def _prerequisite_missing() -> str | None:
    if shutil.which("node") is None:
        return "node is not on PATH"
    if not DIST_INDEX.exists():
        return (
            f"{DIST_INDEX.relative_to(REPO_ROOT)} is absent: run "
            "`npm ci --prefix verifiers/ts && npm run build --prefix verifiers/ts`"
        )
    return None


def run(count: int, seed: int, keep: Path | None = None, *, quiet: bool = False) -> int:
    started = time.monotonic()
    _DYNAMIC_STORES.clear()
    bases = build_bases()
    cases = generate(count, seed, bases) + _property_cases(bases)
    store_docs = {**bases.manifests, **_DYNAMIC_STORES}
    stores = {name: store_bytes(doc) for name, doc in store_docs.items()}
    ts = ts_verdicts(cases, stores)

    findings = 0
    verdicts: Counter[str] = Counter()
    by_family: Counter[str] = Counter()
    diverged: Counter[str] = Counter()
    for case, ts_v in zip(cases, ts, strict=True):
        py_v = python_verdict(case.envelope, stores[case.store])
        verdicts[py_v["verdict"]] += 1
        by_family[case.family] += 1
        problem = None
        if case.family == "property":
            if py_v["verdict"] != "invalid" or ts_v["verdict"] != "invalid":
                problem = "PROPERTY VIOLATED (both sides must refuse)"
        elif comparable(py_v) != comparable(ts_v):
            problem = "DIVERGENCE"
        elif py_v["verdict"] == "crash":
            problem = "CRASH ON BOTH SIDES"
        if problem is None:
            continue
        findings += 1
        diverged[case.family] += 1
        where = f" (kept in {_keep(keep, case, stores[case.store], py_v, ts_v)})" if keep else ""
        print(
            f"{problem} [{case.family}] {case.id}: {case.label}{where}\n"
            f"  store:      {case.store}\n"
            f"  envelope:   {_short(case.envelope)}\n"
            f"  python:     {json.dumps(_brief(py_v))}\n"
            f"  typescript: {json.dumps(_brief(ts_v))}",
            file=sys.stderr,
        )
    elapsed = time.monotonic() - started
    if not quiet or findings:
        print(
            f"{len(cases)} cases (seed {seed}), {findings} findings, {elapsed:.1f}s; "
            f"python verdicts: {dict(sorted(verdicts.items()))}"
        )
        print("cases by family: " + ", ".join(f"{k}={v}" for k, v in sorted(by_family.items())))
        if diverged:
            print(
                "findings by family: " + ", ".join(f"{k}={v}" for k, v in sorted(diverged.items()))
            )
    return 1 if findings else 0


def _brief(verdict: dict[str, Any]) -> dict[str, Any]:
    """The verdict without the members that are the same constant on every case."""
    if "result" not in verdict:
        return verdict
    r = verdict["result"]
    return {
        "verdict": verdict["verdict"],
        "signature": r["signature"],
        "schema": r["schema"],
        "errors": r["errors"],
        "warnings": r["warnings"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--count", type=int, default=5000, help="generated cases (default 5000)")
    parser.add_argument("--seed", type=int, default=20261009)
    parser.add_argument(
        "--keep", type=Path, default=None, help="write each finding as a conformance leaf here"
    )
    args = parser.parse_args(argv)
    missing = _prerequisite_missing()
    if missing is not None:
        print(f"PRECONDITION ABSENT: {missing}", file=sys.stderr)
        return EXIT_PRECONDITION
    return run(args.count, args.seed, args.keep)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
