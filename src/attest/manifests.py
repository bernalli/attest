"""Issuer key manifests and artifact manifests — key lifecycle and rotation continuity (design §5).

Manifest signing input is defined exactly like receipts: Ed25519 over
`JCS(manifest)` with the `manifest_signature` member removed — every key's
`kid`, `pub`, `valid_from`, `valid_to`, `status` sits inside the signed
object, so nothing about a key's lifecycle is tamperable without breaking
the signature.

Scope: this module verifies *self-consistency* (a manifest's own signature
against its own listed keys) and the *rotation-continuity* predicate between
two already-self-consistent manifests. It does not decide whether a manifest
is itself trusted (TOFU bootstrap, `unverified_rotation` labeling) — that
trust-store logic belongs to `verify.py`. Likewise, fail-closed `compromised`
handling against *receipts* (a compromised key invalidates all its past
signatures regardless of `issued_at`) is `verify.py`'s concern; here a
`compromised`/`retired` key is simply not `active`, which is sufficient to
model key lifecycle honestly at the manifest level.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from attest import canon, keys, pq

_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"
_ACTIVE = "active"
_RETIRED = "retired"
_COMPROMISED = "compromised"

# G1 normative ceilings (attest-versioning.md §5 amendment; v0.1 §11/§15,
# v0.2 §6/§16) — conformance-surface structural bounds a conforming verifier
# MUST enforce on the untrusted `keys[]`/`artifacts[]` arrays before doing
# any signature work over them.
MAX_MANIFEST_KEYS = 256
MAX_ARTIFACT_ENTRIES = 4096


def _parse_date(value: str) -> datetime:
    return datetime.strptime(value, _DATE_FMT)


def _within_window(issued_at: object, entry: dict[str, Any]) -> bool:
    """Fail-closed: `issued_at` (a str) falls within the key entry's
    [valid_from, valid_to] window. Any malformed/missing bound → False."""
    if not isinstance(issued_at, str):
        return False
    try:
        issued = _parse_date(issued_at)
        valid_from = _parse_date(entry["valid_from"])
    except (KeyError, TypeError, ValueError):
        return False
    if issued < valid_from:
        return False
    valid_to = entry.get("valid_to")
    if valid_to is None:
        return True
    try:
        return issued <= _parse_date(valid_to)
    except (TypeError, ValueError):
        return False


def _signable(manifest: dict[str, Any]) -> bytes:
    body = {k: v for k, v in manifest.items() if k != "manifest_signature"}
    return canon.canonical_bytes(body)


def key_entry(
    kid: str,
    pub: bytes,
    valid_from: str,
    valid_to: str | None = None,
    status: str = _ACTIVE,
    pub_ml_dsa_65: bytes | None = None,
) -> dict[str, Any]:
    """Build one `keys[]` entry. `pub` is raw 32-byte Ed25519 public key bytes.

    Passing `pub_ml_dsa_65` (raw ML-DSA-65 public key bytes) marks the entry
    hybrid: a manifest signed by this key must carry both signature legs
    (see `build_key_manifest`/`verify_key_manifest`).
    """
    entry: dict[str, Any] = {
        "kid": kid,
        "pub": keys.b64u(pub),
        "valid_from": valid_from,
        "valid_to": valid_to,
        "status": status,
    }
    if pub_ml_dsa_65 is not None:
        entry["pub_ml_dsa_65"] = keys.b64u(pub_ml_dsa_65)
    return entry


def find_key(manifest: dict[str, Any], kid: str) -> dict[str, Any] | None:
    """Return the `keys[]` entry with the given `kid`, or None if absent."""
    entries = manifest.get("keys", [])
    if not isinstance(entries, list):
        return None
    for entry in entries:
        # Tolerate a malformed keys[] member (e.g. `keys: [null]`) instead of
        # crashing the caller's verification (2026-07-13 review, finding 11).
        if isinstance(entry, dict) and entry.get("kid") == kid:
            return entry
    return None


def _entries_for_kid(manifest: dict[str, Any], kid: str) -> tuple[dict[str, Any], ...]:
    """Every `keys[]` entry carrying `kid` — the repo does not guarantee uniqueness.

    Status decisions MUST read all of them: with duplicate entries of differing
    status, a first-match read lets the array's ORDER decide the verdict.
    """
    entries = manifest.get("keys", [])
    if not isinstance(entries, list):
        return ()
    return tuple(entry for entry in entries if isinstance(entry, dict) and entry.get("kid") == kid)


def _kid_is_active_for_continuity(manifest: dict[str, Any], kid: str) -> bool:
    """True only when EVERY entry for `kid` says `active` (and at least one exists)."""
    matching_entries = _entries_for_kid(manifest, kid)
    return bool(matching_entries) and all(
        entry.get("status") == _ACTIVE for entry in matching_entries
    )


def sign_signature_block(
    payload: bytes,
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    signing_kid: str,
) -> dict[str, Any]:
    """Build a `{kid, sig, sig_ml_dsa_65?}` signature block over `payload`.

    This is the shared hybrid-signing primitive behind every v0.2 signed
    side-document (key manifests, artifact manifests, revocation records):
    hybrid signing keys (`pq.HybridSigningKeys`) add a second `sig_ml_dsa_65`
    leg over the SAME payload bytes as the Ed25519 `sig` leg, so a single
    canonical payload always drives both legs identically.
    """
    if isinstance(signing_kp, pq.HybridSigningKeys):
        ed_sig = keys.sign(payload, signing_kp.ed)
        mldsa_sig = pq.sign(payload, signing_kp.mldsa)
        return {
            "kid": signing_kid,
            "sig": keys.b64u(ed_sig),
            "sig_ml_dsa_65": keys.b64u(mldsa_sig),
        }
    sig = keys.sign(payload, signing_kp)
    return {"kid": signing_kid, "sig": keys.b64u(sig)}


def _sign_manifest(
    manifest: dict[str, Any],
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    signing_kid: str,
) -> dict[str, Any]:
    """Build the `manifest_signature` block for `manifest` (mutates nothing —
    the caller inserts the returned block). See `sign_signature_block`.
    """
    return sign_signature_block(_signable(manifest), signing_kp, signing_kid)


def verify_signature_block(
    payload: bytes, sig_block: dict[str, Any], entry: dict[str, Any]
) -> bool:
    """AND rule: `entry` hybrid (carries `pub_ml_dsa_65`) requires BOTH legs
    present and valid; non-hybrid requires the Ed25519 leg valid and
    `sig_ml_dsa_65` ABSENT. Any other combination fails closed. Never raises —
    decode/type errors on untrusted input are treated as verification failure.

    Shared by every v0.2 signed side-document's verification (key manifests,
    artifact manifests, revocation records) — the single place the AND rule
    is enforced, so it cannot drift between documents.
    """
    is_hybrid_entry = "pub_ml_dsa_65" in entry
    has_mldsa_leg = "sig_ml_dsa_65" in sig_block
    if is_hybrid_entry != has_mldsa_leg:
        return False
    try:
        ed_ok = keys.verify_strict(
            payload, keys.b64u_decode(sig_block["sig"]), keys.b64u_decode(entry["pub"])
        )
        if not is_hybrid_entry:
            return ed_ok
        mldsa_ok = pq.verify_strict(
            payload,
            keys.b64u_decode(sig_block["sig_ml_dsa_65"]),
            keys.b64u_decode(entry["pub_ml_dsa_65"]),
        )
        return ed_ok and mldsa_ok
    except (KeyError, ValueError, TypeError):
        # Manifests arrive from untrusted sources with no schema gate here; fail
        # closed on wrong-typed fields (e.g. non-str sig/pub -> TypeError) too.
        return False


def build_key_manifest(
    issuer: str,
    manifest_version: int,
    issued_at: str,
    key_entries: list[dict[str, Any]],
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    signing_kid: str,
    *,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if previous is not None:
        _check_keyset_preservation(previous, key_entries)
    manifest: dict[str, Any] = {
        "issuer": issuer,
        "manifest_version": manifest_version,
        "issued_at": issued_at,
        "keys": key_entries,
    }
    manifest["manifest_signature"] = _sign_manifest(manifest, signing_kp, signing_kid)
    return manifest


def _check_keyset_preservation(previous: dict[str, Any], key_entries: list[dict[str, Any]]) -> None:
    previous_entries = previous.get("keys")
    if not isinstance(previous_entries, list):
        raise ValueError("previous manifest keys must be a list")
    if not isinstance(key_entries, list):
        raise ValueError("successor manifest keys must be a list")
    current_by_kid: dict[str, list[dict[str, Any]]] = {}
    for entry in key_entries:
        if not isinstance(entry, dict):
            raise ValueError("successor manifest contains a malformed key entry")
        kid = entry.get("kid")
        if isinstance(kid, str):
            current_by_kid.setdefault(kid, []).append(entry)

    for entry in previous_entries:
        if not isinstance(entry, dict):
            raise ValueError("previous manifest contains a malformed key entry")
        kid = entry.get("kid")
        if not isinstance(kid, str):
            raise ValueError("previous manifest contains a key entry without a string kid")
        current_entries = current_by_kid.get(kid)
        if current_entries is None:
            raise ValueError(f"previous kid {kid!r} omitted from successor manifest")
        if entry.get("status") == _COMPROMISED and any(
            current.get("status") != _COMPROMISED for current in current_entries
        ):
            raise ValueError(f"compromised kid {kid!r} cannot change status")


def _preserves_absorbing_compromises(trusted: dict[str, Any], candidate: dict[str, Any]) -> bool:
    trusted_entries = trusted.get("keys")
    candidate_entries = candidate.get("keys")
    if not isinstance(trusted_entries, list) or not isinstance(candidate_entries, list):
        return False
    candidate_by_kid: dict[str, list[dict[str, Any]]] = {}
    for entry in candidate_entries:
        if not isinstance(entry, dict):
            return False
        kid = entry.get("kid")
        if isinstance(kid, str):
            candidate_by_kid.setdefault(kid, []).append(entry)

    for entry in trusted_entries:
        if not isinstance(entry, dict):
            return False
        kid = entry.get("kid")
        if not isinstance(kid, str):
            return False
        candidate_entries_for_kid = candidate_by_kid.get(kid)
        if candidate_entries_for_kid is None:
            return False
        if entry.get("status") == _COMPROMISED and any(
            candidate_entry.get("status") != _COMPROMISED
            for candidate_entry in candidate_entries_for_kid
        ):
            return False
    return True


def verify_key_manifest(manifest: dict[str, Any]) -> bool:
    """Self-consistency: signature verifies with a key listed in the manifest itself.

    Fails closed (never raises) if `keys[]` exceeds `MAX_MANIFEST_KEYS` — the
    G1 ceiling (attest-versioning.md §5 amendment): an oversized array is not
    evaluated at all, the same fail-closed posture the rest of this function
    already takes on malformed input.
    """
    entries_for_ceiling = manifest.get("keys")
    if isinstance(entries_for_ceiling, list) and len(entries_for_ceiling) > MAX_MANIFEST_KEYS:
        return False
    sig_block = manifest.get("manifest_signature")
    if not isinstance(sig_block, dict):
        return False
    entry = find_key(manifest, sig_block.get("kid", ""))
    if entry is None:
        return False
    try:
        signable = _signable(manifest)
    except (TypeError, canon.CanonError):
        return False
    return verify_signature_block(signable, sig_block, entry)


def check_continuity(trusted: dict[str, Any], candidate: dict[str, Any]) -> bool:
    """True iff `candidate` (version `trusted`+1) was signed by a key `active` in `trusted`.

    Both manifests must be self-consistent and share `issuer`. Version gaps
    (N -> N+2 direct) are discontinuous by construction: only a direct
    successor is accepted here, so bridging a gap requires validating every
    intermediate manifest via repeated calls.
    """
    if not verify_key_manifest(trusted) or not verify_key_manifest(candidate):
        return False
    if trusted.get("issuer") != candidate.get("issuer"):
        return False
    try:
        if candidate["manifest_version"] != trusted["manifest_version"] + 1:
            return False
        signer_kid = candidate["manifest_signature"]["kid"]
    except (KeyError, TypeError):
        return False
    signer_entry = find_key(trusted, signer_kid)
    if signer_entry is None or not _kid_is_active_for_continuity(trusted, signer_kid):
        return False
    # The signer key must also cover the candidate's issuance in its validity
    # window (consistency with verify_artifact_manifest) (2026-07-13 review,
    # finding 12).
    if not _within_window(candidate.get("issued_at"), signer_entry):
        return False
    if not _preserves_absorbing_compromises(trusted, candidate):
        return False
    # Bind continuity to the key TRUSTED vouches for: the candidate's signature
    # must verify under the pub `trusted` holds for signer_kid, NOT the pub the
    # candidate lists for it. Otherwise an attacker reuses a trusted kid, swaps in
    # its own pub, self-signs, and passes — continuity becomes cryptographically
    # hollow (2026-07-13 review, finding 1).
    # Defense in depth only: `verify_key_manifest(candidate)` above already
    # canonicalizes the same object behind the same guard, so this branch is
    # unreachable today and carries no coverage. It stays so that reordering
    # the self-consistency check can never reopen the fail-closed hole.
    try:
        signable = _signable(candidate)
    except (TypeError, canon.CanonError):
        return False
    return verify_signature_block(signable, candidate["manifest_signature"], signer_entry)


def rotate_key_manifest(
    existing: dict[str, Any],
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    signing_kid: str,
    issued_at: str,
    new_entry: dict[str, Any] | None = None,
    retire_kids: Iterable[str] = (),
    compromise_kids: Iterable[str] = (),
) -> dict[str, Any]:
    """Build the next key-manifest version: apply status changes to existing
    keys, optionally append `new_entry`, bump `manifest_version`, re-sign with
    `signing_kp`/`signing_kid`.

    `retired` is planned end-of-use (past signatures stay valid, verify.py only
    warns); `compromised` is an incident (fail-closed; since v0.2 §19 a
    Stage-2-capable verifier spares receipts anchored strictly before the
    declaring manifest's own anchored time — log and anchor this manifest
    promptly or the marking cannot bite anchored stock). Callers pick the one
    whose consequence they mean.

    Fail-closed guards (all raise `ValueError`):
    - at least one change must be requested (a new key or a status change);
    - no kid may be both retired and compromised;
    - `signing_kid` may not be compromised — you cannot sign the recovery
      manifest with the very key you are declaring compromised (the attacker
      holds it too); sign with a different, still-active key;
    - every kid to retire/compromise must exist in `existing["keys"]` — a
      typo'd kid is an error, never a silent no-op;
    - a kid already marked `compromised` may not be touched by a status-change
      request — there is no un-compromise ceremony;
    - `new_entry`'s kid must not already exist in `existing["keys"]` — reusing
      a kid would append a second `keys[]` entry sharing it, a silent no-op
      for the operator since `find_key` returns the first (old-status) match.
    - `existing` must itself be well-formed for the fields read here: `keys`
      a list of objects with string `kid`s, `manifest_version` a non-bool
      integer, `issuer` a string — a malformed trusted manifest is a
      `ValueError` like every other refusal here, never an
      `AttributeError`/`KeyError` escaping to the caller.

    The caller's `existing` manifest is never mutated (keys are copied).
    """
    retire = set(retire_kids)
    compromise = set(compromise_kids)

    if new_entry is None and not retire and not compromise:
        raise ValueError("rotation must change something: a new key or a status change")

    overlap = retire & compromise
    if overlap:
        raise ValueError(f"kid(s) marked both retired and compromised: {sorted(overlap)}")

    if signing_kid in compromise:
        raise ValueError(
            f"signing kid {signing_kid!r} cannot be in the compromised set — sign the "
            "recovery manifest with a different, still-active key"
        )

    existing_keys = existing.get("keys")
    if not isinstance(existing_keys, list) or not all(
        isinstance(entry, dict) for entry in existing_keys
    ):
        raise ValueError("existing manifest keys must be a list of objects")
    existing_version = existing.get("manifest_version")
    if not isinstance(existing_version, int) or isinstance(existing_version, bool):
        raise ValueError("existing manifest_version must be an integer")
    existing_issuer = existing.get("issuer")
    if not isinstance(existing_issuer, str):
        raise ValueError("existing manifest issuer must be a string")
    existing_kids: set[str] = set()
    for entry in existing_keys:
        kid = entry.get("kid")
        if not isinstance(kid, str):
            raise ValueError("existing manifest key entries must have string kid")
        existing_kids.add(kid)

    unknown = (retire | compromise) - existing_kids
    if unknown:
        raise ValueError(f"cannot change status of unknown kid(s): {sorted(unknown)}")
    already_compromised: set[str] = set()
    for entry in existing_keys:
        kid = entry.get("kid")
        if (
            isinstance(kid, str)
            and entry.get("status") == _COMPROMISED
            and kid in (retire | compromise)
        ):
            already_compromised.add(kid)
    if already_compromised:
        raise ValueError(f"compromised kid(s) cannot change status: {sorted(already_compromised)}")

    if new_entry is not None:
        try:
            new_kid = new_entry.get("kid")
        except AttributeError as exc:
            raise ValueError("new key entry must be an object") from exc
        if not isinstance(new_kid, str):
            raise ValueError("new key entry must have string kid")
        if new_kid in existing_kids:
            raise ValueError(
                f"new key kid {new_kid!r} already exists in the manifest — use "
                "--retire-kid/--compromise-kid to change an existing key's status, not --new-kid"
            )

    updated: list[dict[str, Any]] = []
    for entry in existing_keys:
        entry = dict(entry)  # copy — never mutate the caller's manifest
        kid = entry.get("kid")
        if kid in compromise:
            entry["status"] = _COMPROMISED
        elif kid in retire:
            entry["status"] = _RETIRED
        updated.append(entry)
    if new_entry is not None:
        updated.append(new_entry)

    new_version = existing_version + 1
    return build_key_manifest(
        existing_issuer,
        new_version,
        issued_at,
        updated,
        signing_kp,
        signing_kid,
        previous=existing,
    )


def build_artifact_manifest(
    issuer: str,
    series: str,
    version: int,
    released_at: str,
    artifacts: list[dict[str, Any]],
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys,
    signing_kid: str,
    *,
    manifest_version: int | None = None,
) -> dict[str, Any]:
    """Build and sign an artifact manifest. `signing_kp` mirrors
    `build_key_manifest`: an `pq.HybridSigningKeys` produces a
    `manifest_signature` with both the Ed25519 `sig` leg and the
    `sig_ml_dsa_65` leg (see `sign_signature_block`); a plain
    `keys.SigningKeyPair` keeps the v0.1 Ed25519-only shape unchanged.

    `manifest_version` (G2/G3, attest-versioning.md rev 4; v0.1 §7.2/§7.3
    amendment) is the newest-seen/rollback-protection counter — distinct
    from `version` (the series' own release number, unrelated to currency).
    It is REQUIRED on every manifest built by a conforming issuer going
    forward (the CLI's `manifest-artifacts` command always supplies it), but
    OPTIONAL here and OMITTED from the signed body when `None` (the
    default): eternal verifiability (attest-versioning.md §3) means every
    caller of this function that predates this amendment keeps producing
    the exact byte-for-byte shape it always did. A manifest with no
    `manifest_version` is a legacy manifest — `check_artifact_continuity`
    fails closed on it (no currency basis to compare), and `verify()` warns
    `artifact_manifest_unversioned` rather than rejecting it."""
    manifest: dict[str, Any] = {
        "issuer": issuer,
        "series": series,
        "version": version,
        "released_at": released_at,
        "artifacts": artifacts,
    }
    if manifest_version is not None:
        if (
            not isinstance(manifest_version, int)
            or isinstance(manifest_version, bool)
            or manifest_version < 1
        ):
            raise ValueError("manifest_version must be an integer >= 1")
        manifest["manifest_version"] = manifest_version
    manifest["manifest_signature"] = sign_signature_block(
        _signable(manifest), signing_kp, signing_kid
    )
    return manifest


def check_artifact_continuity(trusted: dict[str, Any], candidate: dict[str, Any]) -> bool:
    """G3 currency rule (attest-versioning.md rev 4; v0.1 §7.2/§7.3 amendment):
    True iff `candidate` is a currency-conformant successor to `trusted` for
    the same issuer/series. Currency is evaluable only when both manifests
    carry valid (non-bool integer >= 1) `manifest_version` values: a candidate
    regression, or an advancing candidate other than N+1, is discontinuous.
    Legacy manifests are warn-only and return True. Same contract shape as
    `check_continuity` above, but for artifact manifests.

    This function does NOT verify self-consistency or signer-trust of either
    manifest (unlike `check_continuity`, which can call `verify_key_manifest`
    on both sides with no external input) — `verify_artifact_manifest` needs
    a resolving key manifest this function's `(trusted, candidate)` contract
    has no room for, so that remains the caller's job. Callers MUST
    authenticate both sides with `verify_artifact_manifest` before calling
    this metadata-only predicate. This function ONLY answers the
    currency/newest-seen question: would accepting `candidate` silently roll
    back the issuer's artifact state for this series.

    Currency is STRICT N -> N+1 between two distinct versioned manifests. The
    one exception is a same-version RE-DELIVERY of the value-identical
    manifest (Python `==`), which is continuous by construction (no state
    change). Two DIFFERENT manifests at the SAME `manifest_version` is the
    equivocation shape — the issuer (or an attacker) signed two divergent
    manifests under one version number — and MUST NOT be treated as
    continuous; the caller routes that outcome to `unverified_rotation`.

    Fails closed (never raises) on issuer/series mismatch. On a legacy
    manifest (no valid `manifest_version`) on either side, currency is not
    evaluable and the result is True; the caller emits
    `artifact_manifest_unversioned` instead.
    """
    if trusted.get("issuer") != candidate.get("issuer"):
        return False
    if trusted.get("series") != candidate.get("series"):
        return False
    trusted_version = trusted.get("manifest_version")
    candidate_version = candidate.get("manifest_version")
    if (
        not isinstance(trusted_version, int)
        or isinstance(trusted_version, bool)
        or trusted_version < 1
        or not isinstance(candidate_version, int)
        or isinstance(candidate_version, bool)
        or candidate_version < 1
    ):
        return True
    if candidate_version == trusted_version:
        return trusted == candidate
    return candidate_version == trusted_version + 1


def verify_artifact_manifest(manifest: dict[str, Any], key_manifest: dict[str, Any]) -> bool:
    """Verify against `key_manifest`: signer must be `active` there, with `released_at`
    covered by the signer key's `[valid_from, valid_to]` window, and issuers must match.

    AND rule (v0.2, mirrors `verify_key_manifest`): if the signer's `key_manifest`
    entry is hybrid (carries `pub_ml_dsa_65`), `manifest_signature` MUST also
    carry a valid `sig_ml_dsa_65` leg over the same signed bytes, or verification
    fails closed; an Ed25519-only entry with a stray `sig_ml_dsa_65` leg likewise
    fails closed (see `verify_signature_block`). Ed25519-only signers keep v0.1
    behavior byte-for-byte.

    Defense-in-depth: the `key_manifest` must itself be self-consistent
    (`verify_key_manifest`) so an attacker-fabricated key manifest paired with a
    matching attacker-signed artifact manifest cannot verify. This does not
    preempt the trust-store/TOFU/continuity decisions that live in verify.py —
    a genuinely trusted key manifest always self-verifies, so the happy path is
    unaffected.

    Also fails closed (never raises) if `artifacts[]` exceeds
    `MAX_ARTIFACT_ENTRIES` — the G1 ceiling (attest-versioning.md §5
    amendment) on the sibling array this function is the self-consistency
    gate for, mirroring `verify_key_manifest`'s `MAX_MANIFEST_KEYS` check.
    """
    manifest_version = manifest.get("manifest_version")
    if "manifest_version" in manifest and (
        not isinstance(manifest_version, int)
        or isinstance(manifest_version, bool)
        or manifest_version < 1
    ):
        return False
    artifacts_for_ceiling = manifest.get("artifacts")
    if (
        isinstance(artifacts_for_ceiling, list)
        and len(artifacts_for_ceiling) > MAX_ARTIFACT_ENTRIES
    ):
        return False
    if not verify_key_manifest(key_manifest):
        return False
    sig_block = manifest.get("manifest_signature")
    if not isinstance(sig_block, dict):
        return False
    if manifest.get("issuer") != key_manifest.get("issuer"):
        return False
    entry = find_key(key_manifest, sig_block.get("kid", ""))
    if entry is None or entry.get("status") != _ACTIVE:
        return False
    try:
        released_at = _parse_date(manifest["released_at"])
        if released_at < _parse_date(entry["valid_from"]):
            return False
        valid_to = entry.get("valid_to")
        if valid_to is not None and released_at > _parse_date(valid_to):
            return False
        return verify_signature_block(_signable(manifest), sig_block, entry)
    except (KeyError, ValueError, TypeError):
        # Fail closed on wrong-typed fields (e.g. non-str released_at -> TypeError).
        return False


def has_active_ed_only_sibling(manifest: dict[str, Any]) -> bool:
    """G6 mixed-keyset detection (v0.2 §2.3/§13 amendment): True iff `manifest`
    declares the hybrid profile (at least one `keys[]` entry carries
    `pub_ml_dsa_65`) AND ALSO holds at least one Ed25519-only key (no
    `pub_ml_dsa_65`) whose `status` is `"active"`.

    This is the mixed-keyset condition the amendment prohibits
    (`attack_mixed_keyset_hijack`, the formal exhibit motivating it): an
    issuer that has adopted hybrid signing but left an old Ed25519-only key
    `active` still lets an attacker who only breaks the classical leg forge
    under that still-active sibling — silently downgrading the issuer's
    claimed hybrid protection to classical-only, without any visible
    signal. `verify.py` checks this against the resolved issuer manifest of
    every v0.2 receipt it verifies and, when true, emits the
    `mixed_keyset_active_ed_only_sibling` warning (v0.2 §2.3/§13: the
    warning is the entire verifier-side contract — no result field caps a
    "hybrid strength" classification, since none exists).

    A manifest with no hybrid key at all is not in scope (nothing hybrid to
    downgrade); a manifest where every Ed25519-only key has been retired or
    compromised is a cleanly completed migration (v0.2 §13's migration
    ceremony: the same `manifest_version` bump that introduces the hybrid
    key retires every Ed25519-only key). Never raises — malformed `keys[]`
    entries are ignored, fail-closed to False, mirroring the rest of this
    module's untrusted-input posture.
    """
    entries = manifest.get("keys")
    if not isinstance(entries, list):
        return False
    has_hybrid_key = any(isinstance(e, dict) and "pub_ml_dsa_65" in e for e in entries)
    if not has_hybrid_key:
        return False
    return any(
        isinstance(e, dict) and "pub_ml_dsa_65" not in e and e.get("status") == _ACTIVE
        for e in entries
    )
