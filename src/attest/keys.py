"""Ed25519 signing/verification under the attest pinned ruleset.

Backend: PyNaCl (libsodium), chosen because libsodium natively enforces
the ruleset attest v0.1 pins: rejection of non-canonical S (SUF-CMA) and of
small-order A and R (SBS). The canonical-S check is additionally enforced
here explicitly so the property is locally testable and documented.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

import nacl.exceptions
import nacl.signing

L = 2**252 + 27742317777372353535851937790883648493


@dataclass(frozen=True)
class SigningKeyPair:
    seed: bytes
    pub: bytes


def generate() -> SigningKeyPair:
    sk = nacl.signing.SigningKey.generate()
    return SigningKeyPair(seed=bytes(sk), pub=bytes(sk.verify_key))


def from_seed(seed: bytes) -> SigningKeyPair:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    sk = nacl.signing.SigningKey(seed)
    return SigningKeyPair(seed=seed, pub=bytes(sk.verify_key))


def sign(payload_bytes: bytes, kp: SigningKeyPair) -> bytes:
    return bytes(nacl.signing.SigningKey(kp.seed).sign(payload_bytes).signature)


def verify_strict(payload_bytes: bytes, sig: bytes, pub: bytes) -> bool:
    if len(sig) != 64:
        raise ValueError("Ed25519 signature must be 64 bytes")
    if len(pub) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    if int.from_bytes(sig[32:], "little") >= L:  # non-canonical S
        return False
    try:
        nacl.signing.VerifyKey(pub).verify(payload_bytes, sig)
        return True
    except (nacl.exceptions.BadSignatureError, nacl.exceptions.ValueError, ValueError):
        return False


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


# The ONE decode grammar both reference decoders share (verifiers/ts/src/b64u.ts
# carries the twin). Deliberately permissive in exactly the three ways vector
# group 22 pins -- optional `=` padding, the standard `+/` alphabet, non-zero
# trailing bits -- and in no other: no whitespace, no other characters. Before
# this, `urlsafe_b64decode` silently DROPPED any non-alphabet character while
# `atob` skipped ASCII whitespace and rejected the rest, so a third party could
# edit an envelope's unsigned `sig` string into one only one verifier accepts.
_B64U_RE = re.compile(r"[A-Za-z0-9_+/-]*={0,2}")


def b64u_decode(s: str) -> bytes:
    if not isinstance(s, str):
        raise TypeError("base64url input must be a string")
    if _B64U_RE.fullmatch(s) is None:
        raise ValueError("invalid base64url: unexpected character")
    body = s.rstrip("=")
    if len(body) % 4 == 1:
        raise ValueError("invalid base64url: impossible length")
    std = body.replace("-", "+").replace("_", "/")
    return base64.b64decode(std + "=" * (-len(std) % 4), validate=True)
