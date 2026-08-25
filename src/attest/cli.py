"""`attest` command-line interface — the operator surface (design §10).

Every verb wraps a single library call 1:1: no domain logic (schema rules,
crypto, revocation classification, bundle packaging...) lives here, only
argument parsing, file I/O, and JSON in/out. Stdlib only.

Conventions (per Task 14 brief):
  - `--help` text per verb (argparse default).
  - Primary/status output is JSON on stdout; errors go to stderr.
  - Exit codes: 0 = ok, 1 = verification-failed (a `verify`/`check-artifact`
    call that ran successfully but concluded "not ok"/"no match"), 2 =
    usage-or-IO error (bad flags, missing/malformed files, library-raised
    `ValueError`/`BundleError`/schema violations at issuance).
  - Secrets (seeds, buyer-binding salts) are never printed to stdout and are
    written to disk with 0600 permissions.

`--trust-dir` for `verify` (and the `trust/` directory `import` writes) is a
directory of key-manifest JSON files, one issuer per file (or one file per
manifest *version* when multiple versions of the same issuer are present —
grouped by the manifest's own `issuer` field, not by filename). Every
manifest found is trusted with provenance `"bundle"` (design §5:
unauthenticated TOFU) — a local trust directory was not fetched over TLS at
verification time, so `verify()` reports `trust: "unauthenticated_tofu"`
rather than `"verified"` even when the signature checks out.
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from attest import (
    anchor,
    bundle,
    canon,
    issue,
    keys,
    manifests,
    pq,
    revocation,
    tlog,
    transfer,
    verify,
    witness,
)

EXIT_OK = 0
EXIT_VERIFICATION_FAILED = 1
EXIT_USAGE_ERROR = 2

_SECRET_FILE_MODE = 0o600
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_PROVENANCE_BUNDLE = "bundle"  # local trust material is unauthenticated TOFU (design §5)
_REDACTED_SALT = "<redacted: run on the .private material to see it>"

# --- `attest log` on-disk layout (Stage 2, offline-signer split) -------------
#
# LOG/config.json          — {"origin": ...}, written once by `log init`.
# LOG/entries.jsonl        — one JSON entry object per line, append-only; the
#                            SOLE source of truth (tiles/candidate/checkpoint
#                            are all derived from it, never the reverse).
# LOG/checkpoint.candidate — UNSIGNED note body (origin/size/b64 root only,
#                            no signature lines) written by `log append`.
# LOG/checkpoint           — the hybrid-signed C2SP note, written only by
#                            `log sign-checkpoint` (the offline/ceremony step).
# LOG/tile/0/...           — level-0 (leaf-hash) tlog-tiles, rebuilt from
#                            scratch on every `log append`. Simplification
#                            (documented, see `_rebuild_tiles`): only level 0
#                            is materialized — the C2SP interior-level cache
#                            tiles are a pure read-amplification optimization
#                            for very large logs and are not needed here; a
#                            mirror can rebuild the whole tree from level-0
#                            tiles alone by re-running RFC 6962 MTH over them.
_LOG_CONFIG_FILENAME = "config.json"
_LOG_ENTRIES_FILENAME = "entries.jsonl"
_LOG_CANDIDATE_FILENAME = "checkpoint.candidate"
_LOG_CHECKPOINT_FILENAME = "checkpoint"
_LOG_TILE_DIRNAME = "tile"
_TILE_FULL_WIDTH = 256  # C2SP tlog-tiles: leaves per level-0 tile
_ISO8601_UTC_FMT = "%Y-%m-%dT%H:%M:%SZ"
_RECEIPT_ID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")

# Stage-2 inputs are parsed from untrusted files, so cap them before decoding
# or base64 expansion. JSON feeds `verify`'s 10M-character evidence
# materialization ceiling; a checkpoint candidate feeds the signed-note 500K
# text cap. An RFC 3161 token is embedded base64-expanded (4/3) into the same
# evidence object. These are pre-allocation bounds; `_cmd_log_anchor` applies
# the verifier's exact total-evidence bound after composing the output.
_MAX_STAGE2_INPUT_BYTES = {
    "json": verify._MAX_TRANSPARENCY_EVIDENCE_LEN,
    "candidate": tlog._MAX_NOTE_TEXT_LEN,
    "rfc3161": (verify._MAX_TRANSPARENCY_EVIDENCE_LEN - tlog._MAX_NOTE_TEXT_LEN - 500_000) * 3 // 4,
}


class CliUsageError(Exception):
    """A usage/IO problem this CLI can explain better than the raw exception."""


@dataclass(frozen=True)
class _OverwritePlan:
    existed: bool
    stat_result: os.stat_result | None
    require_unchanged: bool


def _manifest_version_arg(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer >= 1") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be an integer >= 1")
    return parsed


# --- small I/O helpers -------------------------------------------------------


def _same_file_target(a: Path, b: Path) -> bool:
    """True if `a` and `b` denote the same file: identical resolved path
    (covers relative paths and symlinks, even for a path that does not exist
    yet) OR the same existing inode (covers hard links, which resolve()
    cannot see). Fail-safe: a stat error means 'not provably the same'."""
    if a.resolve() == b.resolve():
        return True
    try:
        return a.samefile(b)
    except OSError:
        return False


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _stat_write_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    mtime_ns = getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000))
    ctime_ns = getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000))
    return (value.st_dev, value.st_ino, value.st_size, mtime_ns, ctime_ns)


def _raise_symlink_refusal(path: Path, *, label: str, force: bool) -> None:
    if force:
        raise CliUsageError(f"{label} {path} is a symlink; refusing to overwrite it")
    raise CliUsageError(
        f"{label} {path} already exists and cannot be read back for comparison: symlink; "
        "refusing to overwrite it (pass --force to replace it)"
    )


def _reject_unsafe_output_stat(path: Path, output_stat: os.stat_result, *, label: str) -> None:
    if stat.S_ISDIR(output_stat.st_mode):
        raise CliUsageError(f"{label} {path} is a directory; refusing to write over it")
    if stat.S_ISLNK(output_stat.st_mode):
        _raise_symlink_refusal(path, label=label, force=False)
    if not stat.S_ISREG(output_stat.st_mode):
        raise CliUsageError(f"{label} {path} is not a regular file; refusing to overwrite it")
    if output_stat.st_nlink > 1:
        raise CliUsageError(f"{label} {path} has multiple hard links; refusing to overwrite it")


def _raise_output_changed(path: Path, *, label: str) -> None:
    raise CliUsageError(
        f"{label} {path} changed while writing; "
        "refusing to overwrite it (re-run, or pass --force to replace it)"
    )


def _prepare_overwrite(path: Path, new_text: str, *, label: str, force: bool) -> _OverwritePlan:
    """write-if-absent-or-identical: return the authorized overwrite plan.

    Applied to outputs whose loss is irrecoverable (key seeds, issuer
    manifests, issued envelopes and salts, transfer/revocation records,
    imported trust anchors and `salts.json`). Derivable outputs are left
    unguarded on purpose — see the `Overwrite-unguarded by design` comments.

    - absent -> a non-existing plan, the path is clear;
    - a directory -> refused unconditionally, `--force` included;
    - a symlink or hard link -> refused unconditionally, `--force` included;
    - `--force` -> allowed whatever the content is on a single-link regular file;
    - byte-identical to `new_text` (UTF-8) -> allowed, and the caller rewrites
      the same bytes so `_write_secret_text`'s 0600 re-pin still happens;
    - different content, or unreadable -> CliUsageError (exit 2).

    Presence is decided by `os.lstat`, so a dangling symlink counts as present:
    creating through it would put the file somewhere else entirely. The
    comparison is bounded — a size mismatch on a regular file is decided by
    stat alone, and the read that follows asks for at most one byte more than
    the new content, so an oversized file is never slurped.

    The comparison is byte-level on the serialized text, never JSON-semantic
    equivalence: a file that means the same thing but is formatted differently
    is refused, which is the safe direction. Every writer in this repo
    serializes deterministically, so legitimate re-runs still compare equal.
    """
    try:
        existing_stat = os.lstat(path)
    except FileNotFoundError:
        return _OverwritePlan(existed=False, stat_result=None, require_unchanged=False)
    except OSError as exc:
        raise CliUsageError(
            f"{label} {path} already exists and cannot be read back for comparison: {exc}; "
            "refusing to overwrite it (pass --force to replace it)"
        ) from exc
    if stat.S_ISLNK(existing_stat.st_mode):
        _raise_symlink_refusal(path, label=label, force=force)
    _reject_unsafe_output_stat(path, existing_stat, label=label)
    if force:
        return _OverwritePlan(existed=True, stat_result=existing_stat, require_unchanged=False)
    new_bytes = new_text.encode("utf-8")
    different = CliUsageError(
        f"{label} {path} already exists with different content; "
        "refusing to overwrite it (pass --force to replace it)"
    )
    fd: int | None = None
    opened_stat: os.stat_result | None = None
    existing: bytes | None = None
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
        opened_stat = os.fstat(fd)
        _reject_unsafe_output_stat(path, opened_stat, label=label)
        if not _same_inode(existing_stat, opened_stat):
            raise CliUsageError(
                f"{label} {path} changed while checking; "
                "refusing to overwrite it (re-run, or pass --force to replace it)"
            )
        if opened_stat.st_size != len(new_bytes):
            raise different
        existing = os.read(fd, len(new_bytes) + 1)
    except CliUsageError:
        raise
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            _raise_symlink_refusal(path, label=label, force=force)
        if isinstance(exc, FileNotFoundError):
            return _OverwritePlan(existed=False, stat_result=None, require_unchanged=False)
        if isinstance(exc, IsADirectoryError):
            raise CliUsageError(
                f"{label} {path} is a directory; refusing to write over it"
            ) from exc
        raise CliUsageError(
            f"{label} {path} already exists and cannot be read back for comparison: {exc}; "
            "refusing to overwrite it (pass --force to replace it)"
        ) from exc
    finally:
        if fd is not None:
            os.close(fd)
    assert existing is not None
    if existing != new_bytes:
        raise different
    assert opened_stat is not None
    return _OverwritePlan(existed=True, stat_result=opened_stat, require_unchanged=True)


def _ensure_overwrite_allowed(path: Path, new_text: str, *, label: str, force: bool) -> bool:
    return _prepare_overwrite(path, new_text, label=label, force=force).existed


def _path_is_present(path: Path) -> bool:
    """Fail-closed presence check for a path that must not be clobbered.

    `os.lstat`, so a dangling symlink counts as present; anything other than a
    clean "not found" also counts as present, because a path we cannot inspect
    is a path we must not overwrite.
    """
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def _read_bounded_bytes(path: Path, *, max_bytes: int, input_name: str) -> bytes:
    """Read at most `max_bytes` from an untrusted CLI file.

    The size check avoids allocating a known-oversized regular file; bounded
    read still closes the stat/read race before a decoder or base64 can fully
    materialize a replacement file.
    """
    try:
        if path.stat().st_size > max_bytes:
            raise CliUsageError(f"{input_name} input exceeds {max_bytes} bytes: {path}")
        with path.open("rb") as file:
            data = file.read(max_bytes + 1)
    except FileNotFoundError as exc:
        raise CliUsageError(f"file not found: {path}") from exc
    except OSError as exc:
        raise CliUsageError(f"cannot read {path}: {exc}") from exc
    if len(data) > max_bytes:
        raise CliUsageError(f"{input_name} input exceeds {max_bytes} bytes: {path}")
    return data


def _read_bounded_text(path: Path, *, max_bytes: int, input_name: str) -> str:
    try:
        return _read_bounded_bytes(path, max_bytes=max_bytes, input_name=input_name).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CliUsageError(f"cannot decode {path} as UTF-8: {exc}") from exc


def _read_json(path: Path, *, max_bytes: int | None = None, input_name: str = "JSON") -> Any:
    try:
        text = (
            _read_bounded_text(path, max_bytes=max_bytes, input_name=input_name)
            if max_bytes is not None
            else path.read_text(encoding="utf-8")
        )
    except FileNotFoundError as exc:
        raise CliUsageError(f"file not found: {path}") from exc
    except OSError as exc:
        raise CliUsageError(f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise CliUsageError(f"invalid JSON in {path}: {exc}") from exc


def _json_text(obj: Any) -> str:
    """The canonical on-disk serialization for every JSON file this CLI writes.

    Deterministic on purpose: the overwrite guard compares the bytes it would
    write against the bytes already on disk, so a legitimate re-run producing
    the same object must produce the same file.
    """
    return json.dumps(obj, indent=2, sort_keys=True)


def _write_json_text(
    path: Path,
    text: str,
    *,
    secret: bool = False,
    exclusive: bool = False,
    label: str = "output file",
    overwrite_plan: _OverwritePlan | None = None,
) -> None:
    if secret:
        _write_secret_text(
            path, text, exclusive=exclusive, label=label, overwrite_plan=overwrite_plan
        )
        return
    if not exclusive and overwrite_plan is None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return
    fd = _open_text_output(
        path,
        exclusive=exclusive,
        label=label,
        mode=0o666,
        overwrite_plan=overwrite_plan,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        os.ftruncate(fh.fileno(), 0)
        fh.write(text)


def _write_json_file(path: Path, obj: Any, *, secret: bool = False) -> None:
    _write_json_text(path, _json_text(obj), secret=secret)


def _write_guarded_json(
    path: Path, obj: Any, *, label: str, force: bool, secret: bool = False
) -> None:
    """Serialize once, apply the overwrite guard, then write.

    For a command with a single protected output. Commands with several build
    all their contents and run all their guards first (see `_cmd_issue`), so
    that a refusal on the second output cannot leave the first one written.
    """
    text = _json_text(obj)
    overwrite_plan = _prepare_overwrite(path, text, label=label, force=force)
    _write_json_text(
        path,
        text,
        secret=secret,
        exclusive=not overwrite_plan.existed,
        label=label,
        overwrite_plan=overwrite_plan,
    )


def _raise_appeared_while_writing(path: Path, *, label: str, exc: BaseException) -> None:
    raise CliUsageError(
        f"{label} {path} appeared while writing; "
        "refusing to overwrite it (re-run, or pass --force to replace it)"
    ) from exc


def _check_opened_write_target(
    path: Path,
    opened_stat: os.stat_result,
    *,
    label: str,
    overwrite_plan: _OverwritePlan | None,
) -> None:
    _reject_unsafe_output_stat(path, opened_stat, label=label)
    if overwrite_plan is None or overwrite_plan.stat_result is None:
        return
    expected = overwrite_plan.stat_result
    if not _same_inode(opened_stat, expected):
        _raise_output_changed(path, label=label)
    if overwrite_plan.require_unchanged and _stat_write_signature(
        opened_stat
    ) != _stat_write_signature(expected):
        _raise_output_changed(path, label=label)


def _open_text_output(
    path: Path,
    *,
    exclusive: bool,
    label: str,
    mode: int,
    overwrite_plan: _OverwritePlan | None = None,
) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | _O_NOFOLLOW
    if exclusive:
        flags |= os.O_CREAT | os.O_EXCL
    elif overwrite_plan is None or overwrite_plan.stat_result is None:
        flags |= os.O_CREAT
    try:
        fd = os.open(path, flags, mode)
    except FileExistsError as exc:
        _raise_appeared_while_writing(path, label=label, exc=exc)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            if exclusive:
                _raise_appeared_while_writing(path, label=label, exc=exc)
            _raise_symlink_refusal(path, label=label, force=True)
        if isinstance(exc, FileNotFoundError):
            _raise_output_changed(path, label=label)
        if isinstance(exc, IsADirectoryError):
            raise CliUsageError(
                f"{label} {path} is a directory; refusing to write over it"
            ) from exc
        raise
    try:
        _check_opened_write_target(path, os.fstat(fd), label=label, overwrite_plan=overwrite_plan)
    except Exception:
        os.close(fd)
        raise
    return fd


def _write_secret_text(
    path: Path,
    text: str,
    *,
    exclusive: bool = False,
    label: str = "output file",
    overwrite_plan: _OverwritePlan | None = None,
) -> None:
    """Write a secret (seed, salt, salt-bearing envelope, salts.json) to
    `path`, created atomically with owner-only 0600 permissions.

    `os.open(..., O_CREAT, 0600)` sets the mode at creation time, so there is
    never the brief window `write_text(...)` + `chmod(...)` leaves where the
    file exists world-readable at the default umask. The fd is opened without
    `O_TRUNC`, checked with `fstat`, and only then truncated, so a symlink,
    hard-linked alias, or inode swap is refused before bytes are destroyed.

    `exclusive=True` (used when `_prepare_overwrite` found the path clear) adds
    `O_EXCL`, so a file that appeared between the guard and the write is
    reported instead of truncated.
    """
    fd = _open_text_output(
        path,
        exclusive=exclusive,
        label=label,
        mode=_SECRET_FILE_MODE,
        overwrite_plan=overwrite_plan,
    )
    # `os.fdopen` takes ownership of `fd`, so the `with` closes it even if
    # `fchmod`/`write` raise — no manual close, no double-close.
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        os.fchmod(fh.fileno(), _SECRET_FILE_MODE)
        os.ftruncate(fh.fileno(), 0)
        fh.write(text)


def _publishable_mode(base_mode: int) -> int:
    """Mode bits a plain ``open()``/``mkdir()`` would produce under the umask."""
    mask = os.umask(0)
    os.umask(mask)
    return base_mode & ~mask


def _stage_text(path: Path, text: str) -> Path:
    """Write text to a sibling temporary file and return that file.

    Keeping the temporary file beside its destination makes the eventual
    ``os.replace`` an atomic same-filesystem rename.  Callers retain control
    over commit ordering when several state files must change together.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    staged = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        # mkstemp creates the file owner-only, but every _stage_text target is
        # a public log artifact meant for static hosting — os.replace keeps the
        # staged mode, so restore what a plain open() would have produced.
        os.chmod(staged, _publishable_mode(0o666))
    except Exception:
        staged.unlink(missing_ok=True)
        raise
    return staged


def _replace_staged_file(staged: Path, destination: Path) -> None:
    """Atomically install a sibling staged file, removing it on failure."""
    try:
        os.replace(staged, destination)
    finally:
        staged.unlink(missing_ok=True)


def _read_b64u_file(path: Path) -> bytes:
    return keys.b64u_decode(path.read_text(encoding="utf-8").strip())


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _load_seed_kp(path: Path) -> keys.SigningKeyPair:
    return keys.from_seed(_read_b64u_file(path))


def _load_mldsa_kp(path: Path) -> pq.MLDSAKeyPair:
    """Load an ML-DSA-65 key file written by `keygen --hybrid` (0600 JSON:
    `{"alg": "ML-DSA-65", "sk": <b64u>, "pub": <b64u>}`).

    Any deviation (missing file, bad JSON, wrong alg, malformed/wrong-length
    b64u material) is a `CliUsageError` — clean exit-2 message, no traceback.
    """
    obj = _read_json(path)
    if not isinstance(obj, dict) or obj.get("alg") != pq.ML_DSA_65_ALG:
        raise CliUsageError(
            f"{path} is not a valid ML-DSA-65 key file (expected alg={pq.ML_DSA_65_ALG!r})"
        )
    try:
        sk = keys.b64u_decode(obj["sk"])
        pub = keys.b64u_decode(obj["pub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CliUsageError(f"{path} has malformed sk/pub fields: {exc}") from exc
    if len(sk) != pq.ML_DSA_65_SK_LEN or len(pub) != pq.ML_DSA_65_PK_LEN:
        raise CliUsageError(f"{path} has wrong-length ML-DSA-65 key material")
    return pq.MLDSAKeyPair(sk=sk, pub=pub)


# --- trust-dir loading (shared by `verify` and documented for `import`) -----


def _load_trust_dir(trust_dir: Path) -> verify.TrustStore:
    if not trust_dir.is_dir():
        raise CliUsageError(f"--trust-dir {trust_dir} is not a directory")

    by_issuer: dict[str, list[dict[str, Any]]] = {}
    # G2/G3 (attest-versioning.md rev 4): artifact manifests dropped into the
    # same --trust-dir are grouped by their own `(issuer, series)` pair — which the
    # spec requires to equal a receipt's `work.artifact_series` (v0.1 §7.2) —
    # so `TrustStore.artifact_manifests`/`artifact_manifest_chains` end up
    # keyed exactly the way `verify()` looks them up. Distinguished from key
    # manifests by the absence of `keys[]` (a key manifest always carries it;
    # an artifact manifest never does).
    by_issuer_series: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for path in sorted(trust_dir.glob("*.json")):
        manifest = _read_json(path)
        if not isinstance(manifest, dict):
            continue
        issuer = manifest.get("issuer")
        if not isinstance(issuer, str):
            continue
        if "keys" in manifest:
            by_issuer.setdefault(issuer, []).append(manifest)
            continue
        series = manifest.get("series")
        if isinstance(series, str):
            by_issuer_series.setdefault((issuer, series), []).append(manifest)

    manifests_map: dict[str, dict[str, Any]] = {}
    provenance: dict[str, str] = {}
    chains: dict[str, list[dict[str, Any]]] = {}
    for issuer, versions in by_issuer.items():
        ordered = sorted(versions, key=lambda m: m.get("manifest_version", 0))
        manifests_map[issuer] = ordered[-1]
        provenance[issuer] = _PROVENANCE_BUNDLE
        chains[issuer] = ordered

    artifact_manifests_map: dict[str, dict[str, dict[str, Any]]] = {}
    artifact_manifest_chains: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for (issuer, series), am_versions in by_issuer_series.items():
        am_ordered = sorted(am_versions, key=lambda m: m.get("manifest_version", 0))
        artifact_manifests_map.setdefault(issuer, {})[series] = am_ordered[-1]
        artifact_manifest_chains.setdefault(issuer, {})[series] = am_ordered

    return verify.TrustStore(
        manifests=manifests_map,
        provenance=provenance,
        chains=chains,
        artifact_manifests=artifact_manifests_map,
        artifact_manifest_chains=artifact_manifest_chains,
    )


def _safe_name(value: str) -> str:
    """Sanitize a bundle-controlled issuer/series identifier into a single
    filename component: neutralize path separators (both platforms), the
    drive-letter colon, and any parent-directory component, so a hostile name
    can never escape the output directory (2026-07-13 review, finding 14)."""
    safe = value.replace("/", "_").replace("\\", "_").replace(":", "_").replace("..", "_")
    return safe or "_"


def _trust_manifest_version_for_filename(manifest: dict[str, Any], issuer: str) -> int:
    version = manifest.get("manifest_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise CliUsageError(
            f"import: trust-store file for issuer {issuer!r} has invalid "
            f"manifest_version {version!r}; refusing to write it"
        )
    return version


def _proof_path_in_dir(proof_dir: Path, receipt_id: str) -> Path:
    """Return the one proof path allowed for a schema-valid receipt id.

    Receipt ids are ULIDs, not general path components.  Check that contract
    before forming a filename, then resolve the result and keep it below the
    resolved proof directory as a defence in depth against an unexpected
    symlink.  ``attest export`` must never read evidence outside ``--proof-dir``.
    """
    if _RECEIPT_ID_RE.fullmatch(receipt_id) is None:
        raise CliUsageError(
            f"receipt_id {receipt_id!r} is not a valid ULID; refusing to read a proof path"
        )
    try:
        proof_root = proof_dir.resolve()
        candidate = (proof_dir / f"{receipt_id}.json").resolve()
        candidate.relative_to(proof_root)
    except (OSError, ValueError) as exc:
        raise CliUsageError(
            f"proof path for receipt_id {receipt_id!r} escapes --proof-dir; refusing to read it"
        ) from exc
    return candidate


# --- `attest log` on-disk state helpers --------------------------------------


def _log_config_path(log_dir: Path) -> Path:
    return log_dir / _LOG_CONFIG_FILENAME


def _log_entries_path(log_dir: Path) -> Path:
    return log_dir / _LOG_ENTRIES_FILENAME


def _log_candidate_path(log_dir: Path) -> Path:
    return log_dir / _LOG_CANDIDATE_FILENAME


def _log_checkpoint_path(log_dir: Path) -> Path:
    return log_dir / _LOG_CHECKPOINT_FILENAME


def _log_tile_dir(log_dir: Path) -> Path:
    return log_dir / _LOG_TILE_DIRNAME


def _validate_cli_origin(origin: str) -> str:
    """Require a non-empty printable-ASCII origin, mirroring `tlog`'s own
    checkpoint-origin grammar (kept local rather than reaching into `tlog`'s
    private validator, since this only needs to fail fast at `log init` —
    `tlog.sign_checkpoint` enforces the same rule authoritatively later)."""
    if not origin or any(not "\x20" <= ch <= "\x7e" for ch in origin):
        raise CliUsageError("--origin must be a non-empty printable ASCII string")
    return origin


def _read_log_origin(log_dir: Path) -> str:
    """The log's own AUTHORITATIVE origin, from LOG/config.json — never
    accepted from a command-line flag on any verb but `log init`."""
    config_path = _log_config_path(log_dir)
    if not config_path.is_file():
        raise CliUsageError(
            f"{log_dir} is not an attest log (missing {config_path}); run `attest log init` first"
        )
    config = _read_json(config_path)
    origin = config.get("origin") if isinstance(config, dict) else None
    if not isinstance(origin, str) or not origin:
        raise CliUsageError(f"{config_path} is missing a valid 'origin'")
    return origin


def _read_log_entries(log_dir: Path) -> list[dict[str, Any]]:
    """The log's AUTHORITATIVE entry history, read fresh from
    LOG/entries.jsonl every time — never from the (derived, cached)
    tiles or candidate/checkpoint files."""
    entries_path = _log_entries_path(log_dir)
    if not entries_path.is_file():
        return []
    entries: list[dict[str, Any]] = []
    text = entries_path.read_text(encoding="utf-8")
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CliUsageError(f"{entries_path}:{line_no}: invalid JSON: {exc}") from exc
        if not isinstance(entry, dict):
            raise CliUsageError(f"{entries_path}:{line_no}: entry must be a JSON object")
        entries.append(entry)
    return entries


def _encoded_entries(entries: list[dict[str, Any]]) -> list[bytes]:
    """Re-validate and canonically re-encode every entry via `tlog.encode_entry`
    — the exact bytes `tlog.build_tree`/`inclusion_proof`/`consistency_proof`
    hash as leaves. Re-deriving this from the stored entry dicts (rather than
    caching encoded bytes anywhere) is what makes recomputation independent
    of anything the CI-side `append` step may have written."""
    encoded: list[bytes] = []
    for i, entry in enumerate(entries):
        try:
            encoded.append(tlog.encode_entry(entry))
        except tlog.TlogError as exc:
            raise CliUsageError(f"{_LOG_ENTRIES_FILENAME} entry #{i} is invalid: {exc}") from exc
    return encoded


def _stage_tiles(log_dir: Path, leaf_hashes: list[bytes]) -> Path:
    """Stage rebuilt level-0 (leaf-hash) tlog-tiles beside ``LOG/tile/0``.

    Simplification, documented (see the module-level LOG layout comment
    above and the task report): a full tile covers `_TILE_FULL_WIDTH`
    consecutive leaves and is named by its index; a not-yet-full tile at the
    growing right edge is named `<index>.p.<width>` (a flattened stand-in for
    C2SP's `<index>.p/<width>` — the nested form exists purely to keep tile
    URLs short at huge scale, irrelevant for the small logs this CLI targets).
    The complete replacement is written before it is installed, rather than
    patching the live cache incrementally.  That keeps a failed tile write
    from disturbing the existing cache and prevents an installed cache from
    drifting out of sync with `entries.jsonl` after a successful append.
    """
    tile_parent = _log_tile_dir(log_dir)
    tile_parent.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix=".0.", dir=tile_parent))
    try:
        # mkdtemp creates the directory owner-only, but it becomes the public
        # LOG/tile/0 on install — restore what a plain mkdir() would produce.
        os.chmod(staged, _publishable_mode(0o777))
        for start in range(0, len(leaf_hashes), _TILE_FULL_WIDTH):
            chunk = leaf_hashes[start : start + _TILE_FULL_WIDTH]
            index = start // _TILE_FULL_WIDTH
            width = len(chunk)
            name = str(index) if width == _TILE_FULL_WIDTH else f"{index}.p.{width}"
            (staged / name).write_bytes(b"".join(chunk))
    except Exception:
        shutil.rmtree(staged, ignore_errors=True)
        raise
    return staged


def _replace_staged_tiles(log_dir: Path, staged: Path) -> None:
    """Install a staged tile directory without ever modifying it in place."""
    tile_dir = _log_tile_dir(log_dir) / "0"
    tile_parent = tile_dir.parent
    backup = Path(tempfile.mkdtemp(prefix=".0.previous.", dir=tile_parent))
    backup.rmdir()  # reserve a unique, absent same-directory rename target
    moved_existing = False
    try:
        if os.path.lexists(tile_dir):
            os.replace(tile_dir, backup)
            moved_existing = True
        os.replace(staged, tile_dir)
    except Exception:
        # The cache is derived data, but restore it when the second rename
        # fails so an ordinary I/O error does not leave an avoidable gap.
        if moved_existing and not os.path.lexists(tile_dir):
            try:
                os.replace(backup, tile_dir)
            except OSError:
                pass
        raise
    else:
        if moved_existing:
            shutil.rmtree(backup, ignore_errors=True)
    finally:
        shutil.rmtree(staged, ignore_errors=True)


def _candidate_text(origin: str, tree_size: int, root: bytes) -> str:
    """The UNSIGNED checkpoint-candidate note BODY: the same three header
    lines (origin, decimal size, standard-base64 root) `tlog.sign_checkpoint`
    signs over, with no signature lines at all — genuinely unsigned, not a
    checkpoint with an empty signature list (`tlog.parse_checkpoint` requires
    at least one signature line and will reject this text outright)."""
    return "\n".join([origin, str(tree_size), base64.b64encode(root).decode("ascii")]) + "\n"


def _parse_candidate_text(text: str, path: Path) -> tuple[str, int, bytes]:
    lines = text.split("\n")
    if len(lines) != 4 or lines[3] != "":
        raise CliUsageError(f"{path} is not a valid checkpoint candidate (expected 3 lines)")
    origin, size_str, root_b64 = lines[0], lines[1], lines[2]
    try:
        tree_size = int(size_str)
    except ValueError as exc:
        raise CliUsageError(f"{path} has a non-integer tree size: {size_str!r}") from exc
    try:
        root = base64.b64decode(root_b64, validate=True)
    except ValueError as exc:
        raise CliUsageError(f"{path} has a malformed base64 root: {exc}") from exc
    if len(root) != 32:
        raise CliUsageError(f"{path} root does not decode to 32 bytes")
    return origin, tree_size, root


# --- keygen -------------------------------------------------------------------


def _cmd_keygen(args: argparse.Namespace) -> int:
    if _same_file_target(args.seed_out, args.pub_out):
        # Aliased outputs would overwrite the seed with the pubkey (2026-07-13
        # review, finding 18).
        raise CliUsageError("--seed-out and --pub-out must be different paths")
    if args.hybrid and args.mldsa_out is None:
        raise CliUsageError("--hybrid requires --mldsa-out")
    if not args.hybrid and args.mldsa_out is not None:
        raise CliUsageError("--mldsa-out requires --hybrid")
    if args.mldsa_out is not None and (
        _same_file_target(args.mldsa_out, args.seed_out)
        or _same_file_target(args.mldsa_out, args.pub_out)
    ):
        # Same aliasing hazard as --seed-out/--pub-out above (2026-07-13 review,
        # finding 18), extended to the new ML-DSA output (fix wave, Task 8).
        raise CliUsageError("--mldsa-out must differ from --seed-out and --pub-out")

    kp = keys.generate()
    seed_text = keys.b64u(kp.seed)
    mldsa_kp = pq.generate() if args.hybrid else None
    mldsa_text = (
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(mldsa_kp.sk),
                "pub": keys.b64u(mldsa_kp.pub),
            },
            indent=2,
            sort_keys=True,
        )
        if mldsa_kp is not None
        else None
    )

    # Guard every protected output before the first write, so a refusal never
    # leaves half a keypair on disk. A generated seed is always new, so this
    # refuses on any re-run unless --force is passed.
    seed_plan = _prepare_overwrite(args.seed_out, seed_text, label="--seed-out", force=args.force)
    mldsa_plan: _OverwritePlan | None = None
    if mldsa_text is not None:
        mldsa_plan = _prepare_overwrite(
            args.mldsa_out, mldsa_text, label="--mldsa-out", force=args.force
        )

    _write_secret_text(
        args.seed_out,
        seed_text,
        exclusive=not seed_plan.existed,
        label="--seed-out",
        overwrite_plan=seed_plan,
    )
    # Overwrite-unguarded by design: the public key is derivable from the seed
    # at any time (2026-08-24 destructive-output-paths plan).
    args.pub_out.parent.mkdir(parents=True, exist_ok=True)
    args.pub_out.write_text(keys.b64u(kp.pub), encoding="utf-8")

    report = {
        "pub": keys.b64u(kp.pub),
        "seed_out": str(args.seed_out),
        "pub_out": str(args.pub_out),
    }
    if mldsa_kp is not None and mldsa_text is not None:
        assert mldsa_plan is not None
        _write_secret_text(
            args.mldsa_out,
            mldsa_text,
            exclusive=not mldsa_plan.existed,
            label="--mldsa-out",
            overwrite_plan=mldsa_plan,
        )
        report["mldsa_pub"] = keys.b64u(mldsa_kp.pub)
        report["mldsa_out"] = str(args.mldsa_out)
    _print_json(report)
    return EXIT_OK


# --- manifest init / rotate / artifacts ---------------------------------------


def _cmd_manifest_init(args: argparse.Namespace) -> int:
    if _same_file_target(args.seed, args.out):
        raise CliUsageError("--seed and --out must be different paths")
    if args.mldsa_key is not None and _same_file_target(args.mldsa_key, args.out):
        # Reading --mldsa-key then writing --out to the same path would clobber
        # the freshly-read ML-DSA secret file.
        raise CliUsageError("--mldsa-key and --out must be different paths")
    kp = _load_seed_kp(args.seed)
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys = kp
    if args.mldsa_key is not None:
        mldsa_kp = _load_mldsa_kp(args.mldsa_key)
        entry = manifests.key_entry(
            args.kid, kp.pub, args.valid_from, args.valid_to, pub_ml_dsa_65=mldsa_kp.pub
        )
        signing_kp = pq.HybridSigningKeys(ed=kp, mldsa=mldsa_kp)
    else:
        entry = manifests.key_entry(args.kid, kp.pub, args.valid_from, args.valid_to)
    manifest = manifests.build_key_manifest(
        args.issuer, 1, args.issued_at, [entry], signing_kp, args.kid
    )
    if not manifests.verify_key_manifest(manifest):
        raise CliUsageError(
            "built manifest does not self-verify; check that --seed and --mldsa-key are "
            "a valid matching keypair"
        )
    _write_guarded_json(args.out, manifest, label="--out", force=args.force)
    _print_json({"out": str(args.out), "issuer": args.issuer, "manifest_version": 1})
    return EXIT_OK


def _cmd_manifest_rotate(args: argparse.Namespace) -> int:
    if _same_file_target(args.signing_seed, args.out):
        raise CliUsageError("--signing-seed and --out must be different paths")
    if args.mldsa_key is not None and _same_file_target(args.mldsa_key, args.out):
        # Same input-vs-output aliasing hazard as manifest init/issue (finding 18
        # policy, extended to the new hybrid input).
        raise CliUsageError("--mldsa-key and --out must be different paths")
    if args.new_mldsa_pub is not None and _same_file_target(args.new_mldsa_pub, args.out):
        raise CliUsageError("--new-mldsa-pub and --out must be different paths")

    existing = _read_json(args.manifest_in)
    if not isinstance(existing, dict) or "keys" not in existing:
        raise CliUsageError(f"{args.manifest_in} is not a key manifest")

    retire_kids: list[str] = args.retire_kid or []
    compromise_kids: list[str] = args.compromise_kid or []

    new_entry = None
    if args.new_mldsa_pub is not None and (args.new_kid is None or args.new_pub is None):
        raise CliUsageError("--new-mldsa-pub requires --new-kid and --new-pub")
    if args.new_kid is not None or args.new_pub is not None:
        if args.new_kid is None or args.new_pub is None:
            raise CliUsageError("--new-kid and --new-pub must be given together")
        if args.valid_from is None:
            raise CliUsageError("--valid-from is required when adding a new key")
        new_pub = _read_b64u_file(args.new_pub)
        new_mldsa_pub = None
        if args.new_mldsa_pub is not None:
            new_mldsa_pub = _read_b64u_file(args.new_mldsa_pub)
            if len(new_mldsa_pub) != pq.ML_DSA_65_PK_LEN:
                raise CliUsageError("new --mldsa-pub is not a 1952-byte ML-DSA-65 public key")
        new_entry = manifests.key_entry(
            args.new_kid,
            new_pub,
            args.valid_from,
            args.valid_to,
            pub_ml_dsa_65=new_mldsa_pub,
        )

    if new_entry is None and not retire_kids and not compromise_kids:
        raise CliUsageError(
            "nothing to do: supply a new key (--new-kid/--new-pub) and/or "
            "--retire-kid/--compromise-kid"
        )

    # The signature shape MUST follow the signing entry's own hybrid-ness, not
    # whether the operator happened to pass --mldsa-key: `_verify_signature_block`
    # requires the manifest_signature shape to match "pub_ml_dsa_65" in entry and
    # verifies the ML-DSA leg against the ENTRY's bound pub, so a mismatch here
    # produces a manifest that is cryptographically invalid at exit 0 (2026-07-13
    # adversarial review, Task 8 fix wave, finding 1/critical).
    signer_entry = manifests.find_key(existing, args.signing_kid)
    mldsa_kp: pq.MLDSAKeyPair | None = None
    if signer_entry is not None:
        is_hybrid_signer = "pub_ml_dsa_65" in signer_entry
        if is_hybrid_signer and args.mldsa_key is None:
            raise CliUsageError(
                f"signing key {args.signing_kid!r} is hybrid; --mldsa-key is required"
            )
        if not is_hybrid_signer and args.mldsa_key is not None:
            raise CliUsageError(
                f"signing key {args.signing_kid!r} is Ed25519-only; --mldsa-key is not allowed"
            )
        if is_hybrid_signer and args.mldsa_key is not None:
            mldsa_kp = _load_mldsa_kp(args.mldsa_key)
            try:
                entry_mldsa_pub = keys.b64u_decode(signer_entry["pub_ml_dsa_65"])
            except (KeyError, TypeError, ValueError) as exc:
                raise CliUsageError(
                    f"{args.manifest_in} has a malformed pub_ml_dsa_65 for "
                    f"{args.signing_kid!r}: {exc}"
                ) from exc
            if mldsa_kp.pub != entry_mldsa_pub:
                raise CliUsageError(
                    "--mldsa-key does not match the signing key's ML-DSA-65 public "
                    "key in the manifest"
                )

    ed_signing_kp = _load_seed_kp(args.signing_seed)
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys = ed_signing_kp
    if args.mldsa_key is not None:
        if mldsa_kp is None:
            mldsa_kp = _load_mldsa_kp(args.mldsa_key)
        signing_kp = pq.HybridSigningKeys(ed=ed_signing_kp, mldsa=mldsa_kp)

    try:
        manifest = manifests.rotate_key_manifest(
            existing,
            signing_kp,
            args.signing_kid,
            args.issued_at,
            new_entry=new_entry,
            retire_kids=retire_kids,
            compromise_kids=compromise_kids,
        )
    except ValueError as exc:
        raise CliUsageError(str(exc)) from exc

    # A candidate must be self-consistent AND directly continue the input
    # manifest: the signing key must be active in the input, its validity
    # window must cover this issuance, and the version must advance by one.
    if not manifests.check_continuity(existing, manifest):
        raise CliUsageError(
            "rotation does not continue the input manifest: the signing key must be active "
            "in it and the version must increment by one"
        )

    _write_guarded_json(args.out, manifest, label="--out", force=args.force)
    _print_json(
        {
            "out": str(args.out),
            "issuer": existing["issuer"],
            "manifest_version": manifest["manifest_version"],
        }
    )
    return EXIT_OK


def _cmd_manifest_artifacts(args: argparse.Namespace) -> int:
    if _same_file_target(args.signing_seed, args.out):
        raise CliUsageError("--signing-seed and --out must be different paths")
    if _same_file_target(args.manifest_in, args.out):
        raise CliUsageError("--in and --out must be different paths")
    if args.mldsa_key is not None and _same_file_target(args.mldsa_key, args.out):
        raise CliUsageError("--mldsa-key and --out must be different paths")

    key_manifest = _read_json(args.manifest_in)
    if not isinstance(key_manifest, dict) or "keys" not in key_manifest:
        raise CliUsageError(f"{args.manifest_in} is not a key manifest")
    artifacts = _read_json(args.artifacts)
    if not isinstance(artifacts, list):
        raise CliUsageError(f"{args.artifacts} must contain a JSON array of artifact entries")

    # The signature shape MUST follow the signing entry's own hybrid-ness, not
    # whether the operator happened to pass --mldsa-key. The shared verifier
    # requires the manifest_signature shape to match "pub_ml_dsa_65" in the
    # entry, so any mismatch would otherwise create an invalid artifact
    # manifest at exit 0.
    signer_entry = manifests.find_key(key_manifest, args.signing_kid)
    if signer_entry is None:
        raise CliUsageError(f"signing key {args.signing_kid!r} is not in {args.manifest_in}")
    is_hybrid_signer = "pub_ml_dsa_65" in signer_entry
    mldsa_kp: pq.MLDSAKeyPair | None = None
    if is_hybrid_signer and args.mldsa_key is None:
        raise CliUsageError(f"signing key {args.signing_kid!r} is hybrid; --mldsa-key is required")
    if not is_hybrid_signer and args.mldsa_key is not None:
        raise CliUsageError(
            f"signing key {args.signing_kid!r} is Ed25519-only; --mldsa-key is not allowed"
        )
    if is_hybrid_signer and args.mldsa_key is not None:
        mldsa_kp = _load_mldsa_kp(args.mldsa_key)
        try:
            entry_mldsa_pub = keys.b64u_decode(signer_entry["pub_ml_dsa_65"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CliUsageError(
                f"{args.manifest_in} has a malformed pub_ml_dsa_65 for {args.signing_kid!r}: {exc}"
            ) from exc
        if mldsa_kp.pub != entry_mldsa_pub:
            raise CliUsageError(
                "--mldsa-key does not match the signing key's ML-DSA-65 public key in the manifest"
            )

    ed_signing_kp = _load_seed_kp(args.signing_seed)
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys = ed_signing_kp
    if mldsa_kp is not None:
        signing_kp = pq.HybridSigningKeys(ed=ed_signing_kp, mldsa=mldsa_kp)
    manifest = manifests.build_artifact_manifest(
        args.issuer,
        args.series,
        args.version,
        args.released_at,
        artifacts,
        signing_kp,
        args.signing_kid,
        manifest_version=args.manifest_version,
    )
    if not manifests.verify_artifact_manifest(manifest, key_manifest):
        raise CliUsageError(
            "built artifact manifest does not self-verify against --in; check that "
            "--signing-seed, --mldsa-key, issuer, signer status, and released-at match it"
        )
    # Overwrite-unguarded by design: an artifact manifest is recomputable from
    # its inputs and is not loggable (spec v0.2 sections 13 and 15), so an
    # equivalent re-sign is always acceptable (2026-08-24 destructive-output-paths plan).
    _write_json_file(args.out, manifest)
    _print_json(
        {
            "out": str(args.out),
            "issuer": args.issuer,
            "series": args.series,
            "version": args.version,
            "manifest_version": args.manifest_version,
        }
    )
    return EXIT_OK


# --- issue ----------------------------------------------------------------------


def _cmd_issue(args: argparse.Namespace) -> int:
    if _same_file_target(args.seed, args.out):
        raise CliUsageError("--seed and --out must be different paths")
    if args.salt_out is not None and _same_file_target(args.seed, args.salt_out):
        raise CliUsageError("--seed and --salt-out must be different paths")
    if args.salt_out is not None and args.salt is None:
        raise CliUsageError("--salt-out requires --salt (nothing to write out otherwise)")
    if args.salt_out is not None and _same_file_target(args.out, args.salt_out):
        # Aliased outputs would overwrite the receipt with the raw salt (2026-07-13
        # review, finding 18).
        raise CliUsageError("--out and --salt-out must be different paths")
    if args.attest_version == "0.2" and args.mldsa_key is None:
        raise CliUsageError("--attest-version 0.2 requires --mldsa-key")
    if args.attest_version == "0.1" and args.mldsa_key is not None:
        raise CliUsageError("--mldsa-key requires --attest-version 0.2")
    if args.mldsa_key is not None and _same_file_target(args.mldsa_key, args.out):
        # Same input-vs-output aliasing hazard as --salt/--salt-out above.
        raise CliUsageError("--mldsa-key and --out must be different paths")
    if (
        args.mldsa_key is not None
        and args.salt_out is not None
        and _same_file_target(args.mldsa_key, args.salt_out)
    ):
        # Same input-vs-output aliasing hazard, extended to --salt-out: reading
        # --mldsa-key then overwriting it with the raw salt at exit 0 would
        # silently destroy the ML-DSA secret (adversarial re-review, Task 8
        # fix wave 2, important finding).
        raise CliUsageError("--mldsa-key and --salt-out must be different paths")

    payload = _read_json(args.payload)
    ed_signing_kp = _load_seed_kp(args.seed)
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys = ed_signing_kp
    if args.mldsa_key is not None:
        mldsa_kp = _load_mldsa_kp(args.mldsa_key)
        signing_kp = pq.HybridSigningKeys(ed=ed_signing_kp, mldsa=mldsa_kp)
    salt = _read_b64u_file(args.salt) if args.salt is not None else None
    manifest_snapshot = _read_json(args.manifest_snapshot) if args.manifest_snapshot else None

    envelope = issue.issue(
        payload, signing_kp, args.kid, salt=salt, manifest_snapshot=manifest_snapshot
    )
    # An envelope that embeds delivery.salt carries the buyer-binding secret
    # in cleartext, so its --out file must be as locked-down (0600) as the
    # redundant --salt-out copy. A saltless envelope has no secret and keeps
    # default perms.
    delivery = envelope.get("delivery")
    salt_bearing = isinstance(delivery, dict) and "salt" in delivery

    # Two-phase: build both contents, guard both paths, only then write, so a
    # refusal on the second output cannot leave the first one on disk.
    envelope_text = _json_text(envelope)
    salt_out_text = keys.b64u(salt) if args.salt_out is not None and salt is not None else None
    envelope_plan = _prepare_overwrite(args.out, envelope_text, label="--out", force=args.force)
    salt_out_plan: _OverwritePlan | None = None
    if salt_out_text is not None:
        salt_out_plan = _prepare_overwrite(
            args.salt_out, salt_out_text, label="--salt-out", force=args.force
        )

    _write_json_text(
        args.out,
        envelope_text,
        secret=salt_bearing,
        exclusive=not envelope_plan.existed,
        label="--out",
        overwrite_plan=envelope_plan,
    )
    if salt_out_text is not None:
        assert salt_out_plan is not None
        _write_secret_text(
            args.salt_out,
            salt_out_text,
            exclusive=not salt_out_plan.existed,
            label="--salt-out",
            overwrite_plan=salt_out_plan,
        )

    _print_json({"out": str(args.out), "receipt_id": payload.get("receipt_id")})
    return EXIT_OK


# --- transfer: issuer-mediated transfer operations (v0.2 §17) ----------------


def _cmd_transfer_authorize(args: argparse.Namespace) -> int:
    if _same_file_target(args.receipt, args.out):
        # Same input-vs-output aliasing hazard as manifest init/issue (finding 18
        # policy): writing --out would clobber the receipt just read.
        raise CliUsageError("--receipt and --out must be different paths")
    if _same_file_target(args.holder_seed, args.out):
        # Same input-vs-output aliasing hazard as manifest init/issue (finding 18
        # policy): writing --out would clobber the holder signing seed just read.
        raise CliUsageError("--holder-seed and --out must be different paths")
    envelope = _read_json(args.receipt)
    if not isinstance(envelope, dict):
        raise CliUsageError(f"{args.receipt} must contain a JSON object")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise CliUsageError(f"{args.receipt} is missing object member 'payload'")
    receipt_id = payload.get("receipt_id")
    if not isinstance(receipt_id, str):
        raise CliUsageError(f"{args.receipt} payload is missing string 'receipt_id'")

    holder_kp = _load_seed_kp(args.holder_seed)
    sig = transfer.sign_authorization(
        receipt_id, args.new_holder_pubkey, args.transferred_at, holder_kp
    )
    # Not secret: a holder-authorization signature is meant to be handed to
    # the issuer to build the transfer record, exactly like any other
    # signed side-document — unlike a seed or salt, its disclosure is not a
    # security concern.
    _write_json_file(args.out, {"sig": keys.b64u(sig)})
    _print_json({"out": str(args.out), "receipt_id": receipt_id})
    return EXIT_OK


def _cmd_transfer_record(args: argparse.Namespace) -> int:
    if _same_file_target(args.receipt, args.out):
        # The issuer must read the old receipt before it can verify the
        # outgoing holder's authorization; never let --out clobber that input.
        raise CliUsageError("--receipt and --out must be different paths")
    if _same_file_target(args.seed, args.out):
        raise CliUsageError("--seed and --out must be different paths")
    if args.mldsa_seed is not None and _same_file_target(args.mldsa_seed, args.out):
        raise CliUsageError("--mldsa-seed and --out must be different paths")
    if _same_file_target(args.holder_authorization, args.out):
        # Same input-vs-output aliasing hazard as manifest init/issue (finding 18
        # policy): writing --out would clobber the holder authorization just read.
        raise CliUsageError("--holder-authorization and --out must be different paths")
    if args.revocation_out is not None and (
        _same_file_target(args.revocation_out, args.seed)
        or _same_file_target(args.revocation_out, args.receipt)
        or _same_file_target(args.revocation_out, args.holder_authorization)
        or _same_file_target(args.revocation_out, args.out)
        or (args.mldsa_seed is not None and _same_file_target(args.revocation_out, args.mldsa_seed))
    ):
        # Same input-vs-output aliasing hazard as manifest init/issue (finding 18
        # policy), extended to the second transfer output.
        raise CliUsageError(
            "--revocation-out must differ from --receipt, --seed, --mldsa-seed, "
            "--holder-authorization, and --out"
        )

    envelope = _read_json(args.receipt)
    if not isinstance(envelope, dict):
        raise CliUsageError(f"{args.receipt} must contain a JSON object")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise CliUsageError(f"{args.receipt} is missing object member 'payload'")
    receipt_id = payload.get("receipt_id")
    if not isinstance(receipt_id, str):
        raise CliUsageError(f"{args.receipt} payload is missing string 'receipt_id'")
    buyer = payload.get("buyer")
    holder_pubkey = buyer.get("pubkey") if isinstance(buyer, dict) else None
    if not isinstance(holder_pubkey, str):
        raise CliUsageError(
            f"{args.receipt} payload must carry a non-null buyer.pubkey to transfer"
        )

    holder_authorization = _read_json(args.holder_authorization)
    if not isinstance(holder_authorization, dict) or not isinstance(
        holder_authorization.get("sig"), str
    ):
        raise CliUsageError(f"{args.holder_authorization} must be a JSON object {{'sig': <b64u>}}")
    try:
        holder_sig = keys.b64u_decode(holder_authorization["sig"])
    except (TypeError, ValueError) as exc:
        raise CliUsageError(f"{args.holder_authorization} has a malformed 'sig': {exc}") from exc

    authorization_record = {
        "receipt_id": receipt_id,
        "new_holder_pubkey": args.new_holder_pubkey,
        "transferred_at": args.transferred_at,
        "holder_authorization": holder_authorization,
    }
    if not transfer.verify_authorization(authorization_record, holder_pubkey):
        raise CliUsageError(
            "holder authorization does not verify against the old receipt's buyer.pubkey"
        )

    ed_signing_kp = _load_seed_kp(args.seed)
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys = ed_signing_kp
    if args.mldsa_seed is not None:
        mldsa_kp = _load_mldsa_kp(args.mldsa_seed)
        signing_kp = pq.HybridSigningKeys(ed=ed_signing_kp, mldsa=mldsa_kp)

    record = transfer.build_record(
        receipt_id,
        args.new_receipt_id,
        args.new_holder_pubkey,
        args.transferred_at,
        holder_sig,
        signing_kp,
        args.kid,
    )
    # Two-phase, as in `issue`: both records are built and both paths guarded
    # before either is written.
    record_text = _json_text(record)
    revocation_text = (
        _json_text(
            revocation.build_record(
                receipt_id, "transferred", args.transferred_at, signing_kp, args.kid
            )
        )
        if args.revocation_out is not None
        else None
    )
    record_plan = _prepare_overwrite(args.out, record_text, label="--out", force=args.force)
    revocation_plan: _OverwritePlan | None = None
    if revocation_text is not None:
        revocation_plan = _prepare_overwrite(
            args.revocation_out, revocation_text, label="--revocation-out", force=args.force
        )

    _write_json_text(
        args.out,
        record_text,
        exclusive=not record_plan.existed,
        label="--out",
        overwrite_plan=record_plan,
    )
    report = {
        "out": str(args.out),
        "receipt_id": receipt_id,
        "new_receipt_id": args.new_receipt_id,
    }
    if revocation_text is not None:
        assert revocation_plan is not None
        _write_json_text(
            args.revocation_out,
            revocation_text,
            exclusive=not revocation_plan.existed,
            label="--revocation-out",
            overwrite_plan=revocation_plan,
        )
        report["revocation_out"] = str(args.revocation_out)
    _print_json(report)
    return EXIT_OK


# --- log: transparency-log operator/holder commands (Stage 2) ---------------
#
# THE OFFLINE-SIGNER SPLIT (design doc "Log key custody: offline/HSM ceremony,
# never CI"): `log append` is the CI-side step. It holds no signing key and
# only ever produces an UNSIGNED checkpoint.candidate from the entries file.
# `log sign-checkpoint` is the ceremony-side step, run by a separately-
# administered offline signer: it is the ONLY command in this CLI that may be
# given the log's Ed25519/ML-DSA-65 secret keys, and it refuses to sign
# unless its OWN independent recomputation from LOG/entries.jsonl matches the
# candidate exactly, and — once a checkpoint has previously been signed —
# unless the new tree is a verified RFC 6962 consistency-proof extension of
# it. Never derive either check from which flags were passed: both compare
# against the log's own authoritative on-disk state.


def _cmd_log_init(args: argparse.Namespace) -> int:
    log_dir: Path = args.dir
    origin = _validate_cli_origin(args.origin)
    config_path = _log_config_path(log_dir)
    if config_path.exists():
        raise CliUsageError(f"{log_dir} already has a {_LOG_CONFIG_FILENAME}; refusing to re-init")

    _write_json_file(config_path, {"origin": origin})
    entries_path = _log_entries_path(log_dir)
    entries_path.parent.mkdir(parents=True, exist_ok=True)
    entries_path.touch(exist_ok=True)

    _print_json({"dir": str(log_dir), "origin": origin, "size": 0})
    return EXIT_OK


def _cmd_log_append(args: argparse.Namespace) -> int:
    log_dir: Path = args.dir
    entries_path = _log_entries_path(log_dir)
    candidate_path = _log_candidate_path(log_dir)
    if _same_file_target(args.entry_json, entries_path):
        raise CliUsageError("--entry-json must not be the log's own entries file")
    if _same_file_target(args.entry_json, candidate_path):
        raise CliUsageError("--entry-json must not be the log's own checkpoint candidate")

    origin = _read_log_origin(log_dir)
    new_entry = _read_json(
        args.entry_json, max_bytes=_MAX_STAGE2_INPUT_BYTES["json"], input_name="--entry-json"
    )
    if not isinstance(new_entry, dict):
        raise CliUsageError(f"{args.entry_json} must contain a JSON object")
    try:
        new_entry_bytes = tlog.encode_entry(new_entry)
    except tlog.TlogError as exc:
        raise CliUsageError(f"{args.entry_json} is not a valid log entry: {exc}") from exc

    # Compute everything fallible BEFORE writing anything: a rejected append
    # must leave the log's on-disk state byte-identical to before the call.
    existing_entries = _read_log_entries(log_dir)
    existing_encoded = _encoded_entries(existing_entries)
    for leaf_index, existing_entry_bytes in enumerate(existing_encoded):
        if existing_entry_bytes == new_entry_bytes:
            # Canonically identical leaves are an idempotent append: do not
            # touch any state, so a retry after an authoritative commit stays
            # a no-op instead of growing the tree a second time.
            _print_json(
                {
                    "dir": str(log_dir),
                    "size": len(existing_entries),
                    "leaf_index": leaf_index,
                    "candidate": str(candidate_path),
                    "duplicate": True,
                }
            )
            return EXIT_OK

    updated_entries = [*existing_entries, new_entry]
    encoded = [*existing_encoded, new_entry_bytes]
    leaf_hashes = [tlog.leaf_hash(e) for e in encoded]
    root = tlog.build_tree(encoded)
    tree_size = len(updated_entries)
    candidate_text = _candidate_text(origin, tree_size, root)
    entries_text = "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in updated_entries)

    # Stage every output before changing visible state.  The tile cache is
    # committed first because it is derived only; then commit the candidate
    # before entries, leaving entries LAST.  If a crash lands after the new
    # candidate but before entries, sign-checkpoint independently recomputes
    # from entries and fails closed on the mismatch.  A retry after an
    # authoritative entries commit takes the canonical-byte duplicate branch
    # above, so it cleanly no-ops rather than duplicating that leaf.
    staged_candidate: Path | None = None
    staged_entries: Path | None = None
    staged_tiles: Path | None = None
    try:
        staged_candidate = _stage_text(candidate_path, candidate_text)
        staged_entries = _stage_text(entries_path, entries_text)
        staged_tiles = _stage_tiles(log_dir, leaf_hashes)
        _replace_staged_tiles(log_dir, staged_tiles)
        _replace_staged_file(staged_candidate, candidate_path)
        _replace_staged_file(staged_entries, entries_path)
    finally:
        if staged_candidate is not None:
            staged_candidate.unlink(missing_ok=True)
        if staged_entries is not None:
            staged_entries.unlink(missing_ok=True)
        if staged_tiles is not None:
            shutil.rmtree(staged_tiles, ignore_errors=True)

    _print_json(
        {
            "dir": str(log_dir),
            "size": tree_size,
            "leaf_index": tree_size - 1,
            "candidate": str(candidate_path),
        }
    )
    return EXIT_OK


def _cmd_log_sign_checkpoint(args: argparse.Namespace) -> int:
    log_dir: Path = args.dir
    if _same_file_target(args.ed25519_key, args.mldsa_key):
        raise CliUsageError("--ed25519-key and --mldsa-key must be different paths")
    checkpoint_path = _log_checkpoint_path(log_dir)
    if _same_file_target(args.ed25519_key, checkpoint_path) or _same_file_target(
        args.mldsa_key, checkpoint_path
    ):
        # Writing the signed checkpoint must never clobber the secret key
        # files this same command just read (2026-07-13 review discipline,
        # finding-18 pattern, extended to the log signer's own keys).
        raise CliUsageError("--ed25519-key/--mldsa-key must not be the log's own checkpoint file")

    origin = _read_log_origin(log_dir)
    entries = _read_log_entries(log_dir)
    encoded = _encoded_entries(entries)
    recomputed_root = tlog.build_tree(encoded)
    recomputed_size = len(entries)

    candidate_path = _log_candidate_path(log_dir)
    if not candidate_path.is_file():
        raise CliUsageError(
            f"no checkpoint candidate at {candidate_path}; run `attest log append` first"
        )
    candidate_origin, candidate_size, candidate_root = _parse_candidate_text(
        _read_bounded_text(
            candidate_path,
            max_bytes=_MAX_STAGE2_INPUT_BYTES["candidate"],
            input_name="checkpoint candidate",
        ),
        candidate_path,
    )
    if (
        candidate_origin != origin
        or candidate_size != recomputed_size
        or candidate_root != recomputed_root
    ):
        raise CliUsageError(
            f"{candidate_path} does not match an independent recomputation from "
            f"{_LOG_ENTRIES_FILENAME} — refusing to sign (the candidate or the entries "
            "file may have been tampered with)"
        )

    ed_kp = _load_seed_kp(args.ed25519_key)
    mldsa_kp = _load_mldsa_kp(args.mldsa_key)
    log_key = tlog.LogKey(
        origin=origin, name=args.name, ed25519_pub=ed_kp.pub, mldsa_pub=mldsa_kp.pub
    )

    if checkpoint_path.is_file():
        prior_text = checkpoint_path.read_text(encoding="utf-8")
        try:
            prior_checkpoint = tlog.verify_checkpoint(prior_text, log_key, origin)
        except tlog.TlogError as exc:
            raise CliUsageError(
                f"the existing {checkpoint_path} does not verify under this --name/"
                f"--ed25519-key/--mldsa-key; refusing to sign a successor to a checkpoint "
                f"this signer cannot authenticate: {exc}"
            ) from exc
        if prior_checkpoint.tree_size > recomputed_size:
            raise CliUsageError(
                f"the log has shrunk: the prior signed checkpoint covers "
                f"{prior_checkpoint.tree_size} entries but {_LOG_ENTRIES_FILENAME} now has "
                f"only {recomputed_size}"
            )
        proof = tlog.consistency_proof(encoded, prior_checkpoint.tree_size)
        if not tlog.verify_consistency(
            prior_checkpoint.tree_size,
            prior_checkpoint.root,
            recomputed_size,
            recomputed_root,
            proof,
        ):
            raise CliUsageError(
                "the new tree is not a verified append-only extension of the previously "
                "signed checkpoint — refusing to sign (possible equivocation/history rewrite)"
            )

    signing_keys = pq.HybridSigningKeys(ed=ed_kp, mldsa=mldsa_kp)
    signed_text = tlog.sign_checkpoint(
        origin, recomputed_size, recomputed_root, signing_keys, args.name
    )

    # Self-verify before write: never persist a checkpoint this same signer's
    # own public keys cannot themselves later verify.
    tlog.verify_checkpoint(signed_text, log_key, origin)

    # A failed checkpoint write must preserve the previous signed checkpoint:
    # stage beside it and atomically replace only once the full text exists.
    _replace_staged_file(_stage_text(checkpoint_path, signed_text), checkpoint_path)
    _print_json(
        {
            "dir": str(log_dir),
            "checkpoint": str(checkpoint_path),
            "size": recomputed_size,
            "origin": origin,
        }
    )
    return EXIT_OK


def _cmd_log_prove(args: argparse.Namespace) -> int:
    log_dir: Path = args.dir
    checkpoint_path = _log_checkpoint_path(log_dir)
    entries_path = _log_entries_path(log_dir)
    candidate_path = _log_candidate_path(log_dir)
    if any(
        _same_file_target(args.out, target)
        for target in (checkpoint_path, entries_path, candidate_path)
    ):
        raise CliUsageError("--out must not be one of the log's own state files")

    if not checkpoint_path.is_file():
        raise CliUsageError(
            f"{log_dir} has no signed checkpoint yet; run `attest log sign-checkpoint` first"
        )
    checkpoint_text = checkpoint_path.read_text(encoding="utf-8")
    try:
        checkpoint = tlog.parse_checkpoint(checkpoint_text)
    except tlog.TlogError as exc:
        raise CliUsageError(f"{checkpoint_path} is not a well-formed checkpoint: {exc}") from exc

    entries = _read_log_entries(log_dir)
    if checkpoint.tree_size != len(entries):
        raise CliUsageError(
            f"the signed checkpoint covers {checkpoint.tree_size} entries but "
            f"{_LOG_ENTRIES_FILENAME} now has {len(entries)}; run `attest log sign-checkpoint` "
            "again before proving"
        )

    leaf_index = args.leaf_index
    if not 0 <= leaf_index < len(entries):
        raise CliUsageError(f"--leaf-index {leaf_index} is out of range for {len(entries)} entries")

    encoded = _encoded_entries(entries)
    proof = tlog.inclusion_proof(encoded, leaf_index)

    evidence = {
        "entry": entries[leaf_index],
        "leaf_index": leaf_index,
        "tree_size": checkpoint.tree_size,
        "inclusion_proof": [p.hex() for p in proof],
        "checkpoint": checkpoint_text,
    }
    _write_json_file(args.out, evidence)
    _print_json({"out": str(args.out), "leaf_index": leaf_index, "tree_size": checkpoint.tree_size})
    return EXIT_OK


def _cmd_log_anchor(args: argparse.Namespace) -> int:
    log_dir: Path = args.dir
    checkpoint_path = _log_checkpoint_path(log_dir)
    entries_path = _log_entries_path(log_dir)
    read_paths = [("--evidence", args.evidence), ("--ots-proof", args.ots_proof)]
    if args.rfc3161_token is not None:
        read_paths.append(("--rfc3161-token", args.rfc3161_token))
    if _same_file_target(args.out, checkpoint_path) or _same_file_target(args.out, entries_path):
        raise CliUsageError("--out must not be one of the log's own state files")
    for label, path in read_paths:
        if _same_file_target(path, checkpoint_path) or _same_file_target(path, entries_path):
            raise CliUsageError(f"{label} must not be one of the log's own state files")
        if _same_file_target(args.out, path):
            raise CliUsageError(f"--out must not be the same path as {label}")
    for i, (label_a, path_a) in enumerate(read_paths):
        for label_b, path_b in read_paths[i + 1 :]:
            if _same_file_target(path_a, path_b):
                raise CliUsageError(f"{label_a} and {label_b} must be different paths")

    origin = _read_log_origin(log_dir)

    evidence = _read_json(
        args.evidence, max_bytes=_MAX_STAGE2_INPUT_BYTES["json"], input_name="--evidence"
    )
    if not isinstance(evidence, dict):
        raise CliUsageError(f"{args.evidence} must contain a JSON object")
    checkpoint_text = evidence.get("checkpoint")
    if not isinstance(checkpoint_text, str):
        raise CliUsageError(
            f"{args.evidence} is missing its 'checkpoint' field; run `attest log prove` first"
        )
    try:
        evidence_checkpoint = tlog.parse_checkpoint(checkpoint_text)
    except tlog.TlogError as exc:
        raise CliUsageError(f"{args.evidence}'s checkpoint is malformed: {exc}") from exc
    if evidence_checkpoint.origin != origin:
        raise CliUsageError(
            f"{args.evidence}'s checkpoint origin {evidence_checkpoint.origin!r} does not "
            f"match this log's origin {origin!r}"
        )

    # G4/I1 (attest-v0.2.md §11.1.1): an anchors evidence bundle carries
    # exactly one anchor_profile, and every proof in it MUST commit under
    # that profile — this command only ever produces `signed-note-v2`
    # proofs (see below), so appending to a bundle that already carries
    # proofs under a DIFFERENT profile would silently relabel those retained
    # proofs' profile without re-anchoring them. Refuse instead of
    # overwriting; check this BEFORE reading --ots-proof at all, since the
    # append is refused regardless of what it contains.
    existing_anchors = evidence.get("anchors")
    existing_proofs: list[Any] = (
        existing_anchors["proofs"]
        if isinstance(existing_anchors, dict) and isinstance(existing_anchors.get("proofs"), list)
        else []
    )
    if existing_proofs:
        existing_profile = (
            existing_anchors.get("anchor_profile") if isinstance(existing_anchors, dict) else None
        )
        if existing_profile is None:
            existing_profile = "note-v1"
        if existing_profile != "signed-note-v2":
            raise CliUsageError(
                f"{args.evidence} already carries {len(existing_proofs)} proof(s) under "
                f"anchor_profile {existing_profile!r}; an anchors evidence bundle carries "
                "exactly one anchor_profile and every proof MUST commit under it "
                "(attest-v0.2.md §11.1.1) — produce a fresh signed-note-v2 bundle instead, "
                "or re-anchor every proof in this bundle with v2 tooling"
            )

    ots_proof = _read_json(
        args.ots_proof, max_bytes=_MAX_STAGE2_INPUT_BYTES["json"], input_name="--ots-proof"
    )
    if not isinstance(ots_proof, dict):
        raise CliUsageError(f"{args.ots_proof} must contain a JSON object")
    # `kind` is authoritative from which flag supplied the file, not read from
    # its content: this mirrors --attest-version selecting the signing
    # profile elsewhere in this CLI, not the fail-open "trust the artifact's
    # own self-description" antipattern (there is no accept/reject decision
    # here about `kind` — `verify --transparency` is still the one boundary
    # that judges the evidence's cryptographic standing).
    new_proofs: list[dict[str, Any]] = [{**ots_proof, "kind": "ots"}]
    if args.rfc3161_token is not None:
        token_b64 = base64.b64encode(
            _read_bounded_bytes(
                args.rfc3161_token,
                max_bytes=_MAX_STAGE2_INPUT_BYTES["rfc3161"],
                input_name="--rfc3161-token",
            )
        ).decode("ascii")
        new_proofs.append({"kind": "rfc3161", "token_b64": token_b64})

    # G4/I2 (attest-v0.2.md §11.1.1): this command only ever stamps
    # `anchor_profile: "signed-note-v2"` (below), so a --ots-proof whose
    # op-chain does not actually commit over `signed_note_bytes` would
    # produce evidence that mislabels its own commitment — catch that here,
    # at attachment time, instead of only failing later inside
    # `verify --transparency`'s fail-closed op-chain replay.
    v2_seed = hashlib.sha256(evidence_checkpoint.signed_note_bytes).digest()
    v2_accumulator, v2_warning = anchor.replay_ots_op_chain(v2_seed, ots_proof.get("ops"))
    proof_root = ots_proof.get("header_merkle_root")
    v2_matches = (
        v2_warning is None
        and v2_accumulator is not None
        and isinstance(proof_root, str)
        and v2_accumulator.hex() == proof_root
    )
    if not v2_matches:
        legacy_seed = hashlib.sha256(evidence_checkpoint.note_bytes).digest()
        legacy_accumulator, legacy_warning = anchor.replay_ots_op_chain(
            legacy_seed, ots_proof.get("ops")
        )
        legacy_matches = (
            legacy_warning is None
            and legacy_accumulator is not None
            and isinstance(proof_root, str)
            and legacy_accumulator.hex() == proof_root
        )
        if legacy_matches:
            raise CliUsageError(
                f"{args.ots_proof}'s op-chain was produced by pre-G4 tooling committing "
                "note_bytes (the unsigned checkpoint header alone); anchor_profile "
                "signed-note-v2 requires the full signed note (signed_note_bytes) — "
                "re-produce the OTS proof against the signed checkpoint"
            )
        raise CliUsageError(
            f"{args.ots_proof}'s op-chain does not replay to its own header_merkle_root "
            f"from the signed-note-v2 seed SHA256(signed_note_bytes)={v2_seed.hex()} — "
            "re-produce the OTS proof against this evidence's checkpoint"
        )

    updated_evidence = dict(evidence)
    updated_evidence["anchors"] = {
        "checkpoint": checkpoint_text,
        "proofs": [*existing_proofs, *new_proofs],
        # G4 (attest-v0.2.md §11.1.1): newly-produced anchor evidence MUST
        # declare the v2 commitment profile; the seed check above already
        # confirmed --ots-proof's op-chain replays from
        # SHA-256(checkpoint.signed_note_bytes) (header AND signature
        # lines), not the legacy SHA-256(checkpoint.note_bytes)-only seed.
        "anchor_profile": "signed-note-v2",
    }
    serialized = canon.dumps(updated_evidence)
    if len(serialized) > verify._MAX_TRANSPARENCY_EVIDENCE_LEN:
        raise CliUsageError(
            "produced evidence would exceed the verifier's evidence ceiling "
            f"({len(serialized)} > {verify._MAX_TRANSPARENCY_EVIDENCE_LEN})"
        )

    _write_json_file(args.out, updated_evidence)
    _print_json({"out": str(args.out), "proofs": len(updated_evidence["anchors"]["proofs"])})
    return EXIT_OK


# --- verify -----------------------------------------------------------------------


def _result_to_dict(result: verify.VerificationResult) -> dict[str, Any]:
    return {
        "ok": result.ok,
        "signature": result.signature,
        "schema": result.schema,
        "revocation": result.revocation,
        "binding": result.binding,
        "trust": result.trust,
        "transparency": result.transparency,
        "corroboration": result.corroboration,
        "manifest_freshness": result.manifest_freshness,
        "warnings": list(result.warnings),
        "errors": list(result.errors),
    }


def _load_log_keys(path: Path) -> list[tlog.LogKey]:
    """Parse the vector-runners' `log-keys.json` shape: a JSON array of
    `{"origin", "name", "ed25519_pub_b64u", "mldsa_pub_b64u"}` — the
    verifier's OWN pinned trust config, never taken from a bundle."""
    data = _read_json(path, max_bytes=_MAX_STAGE2_INPUT_BYTES["json"], input_name="--log-keys")
    if not isinstance(data, list):
        raise CliUsageError(f"{path} must contain a JSON array of log keys")
    log_keys: list[tlog.LogKey] = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise CliUsageError(f"{path}[{i}] must be a JSON object")
        try:
            log_keys.append(
                tlog.LogKey(
                    origin=entry["origin"],
                    name=entry["name"],
                    ed25519_pub=keys.b64u_decode(entry["ed25519_pub_b64u"]),
                    mldsa_pub=keys.b64u_decode(entry["mldsa_pub_b64u"]),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CliUsageError(f"{path}[{i}] is a malformed log key: {exc}") from exc
    return log_keys


def _parse_crqc_horizon(value: str) -> int:
    """Parse `--crqc-horizon` as an ISO-8601 UTC timestamp (the same
    `%Y-%m-%dT%H:%M:%SZ` shape `transparency.py`'s `_iso8601` renders) into
    unix seconds for `anchor.AnchorPolicy.crqc_horizon`."""
    try:
        parsed = datetime.datetime.strptime(value, _ISO8601_UTC_FMT).replace(tzinfo=datetime.UTC)
    except ValueError as exc:
        raise CliUsageError(
            f"--crqc-horizon must be an ISO-8601 UTC timestamp like 2030-01-01T00:00:00Z: {value!r}"
        ) from exc
    return int(parsed.timestamp())


def _load_witness_policy(path: Path | None) -> witness.WitnessPolicy | None:
    """Parse `--witness-policy`, the TRUSTED `attest-witness-policy-v1` document
    (v0.2 §11.4) that makes `corroboration: "witnessed"` reachable.

    Loaded from BYTES through `witness.load_policy`, not from a parsed object:
    that is what keeps this core and the TypeScript one agreeing on numbers —
    a JSON `1.0` is refused as a non-integer literal on the byte path and is
    indistinguishable from `1` once it is an in-memory value.
    """
    if path is None:
        return None
    raw = _read_bounded_bytes(
        path, max_bytes=_MAX_STAGE2_INPUT_BYTES["json"], input_name="--witness-policy"
    )
    try:
        return witness.load_policy(raw)
    except ValueError as exc:
        raise CliUsageError(f"--witness-policy {path}: {exc}") from exc


def _load_anchor_policy(path: Path | None, crqc_horizon: int | None) -> anchor.AnchorPolicy | None:
    """Build the verifier's `AnchorPolicy` from `--anchor-policy` (the
    vector-runners' `anchor-policy.json` shape: `{"pinned_headers": {<hex>:
    {"header_hash","merkle_root","time"}}, "crqc_horizon"}`) and/or
    `--crqc-horizon`, which overrides/sets the horizon field. `None` only
    when NEITHER flag was given — `verify()` then leaves anchor evaluation
    unconfigured, same as today's zero-behavior-change default."""
    if path is None and crqc_horizon is None:
        return None
    pinned_headers: dict[str, anchor.PinnedHeader] = {}
    horizon = crqc_horizon
    if path is not None:
        data = _read_json(
            path, max_bytes=_MAX_STAGE2_INPUT_BYTES["json"], input_name="--anchor-policy"
        )
        if not isinstance(data, dict):
            raise CliUsageError(f"{path} must contain a JSON object")
        raw_headers = data.get("pinned_headers", {})
        if not isinstance(raw_headers, dict):
            raise CliUsageError(f"{path}.pinned_headers must be an object")
        for header_hash, header in raw_headers.items():
            if not isinstance(header, dict):
                raise CliUsageError(f"{path}.pinned_headers[{header_hash!r}] must be an object")
            try:
                pinned_headers[header_hash] = anchor.PinnedHeader(
                    header_hash=header["header_hash"],
                    merkle_root=header["merkle_root"],
                    time=header["time"],
                )
            except KeyError as exc:
                raise CliUsageError(
                    f"{path}.pinned_headers[{header_hash!r}] is missing field {exc}"
                ) from exc
        if crqc_horizon is None:
            file_horizon = data.get("crqc_horizon")
            if file_horizon is not None and (
                not isinstance(file_horizon, int) or isinstance(file_horizon, bool)
            ):
                raise CliUsageError(f"{path}.crqc_horizon must be an integer or null")
            horizon = file_horizon
    return anchor.AnchorPolicy(pinned_headers=pinned_headers, crqc_horizon=horizon)


def _build_disclosure(args: argparse.Namespace) -> verify.Disclosure | None:
    salt = _read_b64u_file(args.disclose_salt) if args.disclose_salt is not None else None
    # A half-supplied challenge (only nonce, or only sig) must be rejected, not
    # silently dropped (2026-07-13 review, finding 17).
    if (args.disclose_challenge_nonce is None) != (args.disclose_challenge_sig is None):
        raise CliUsageError(
            "--disclose-challenge-nonce and --disclose-challenge-sig must be given together"
        )
    challenge = None
    if args.disclose_challenge_nonce is not None and args.disclose_challenge_sig is not None:
        challenge = (
            _read_b64u_file(args.disclose_challenge_nonce),
            _read_b64u_file(args.disclose_challenge_sig),
        )
    nothing_supplied = (
        args.disclose_identifier is None
        and args.disclose_type is None
        and salt is None
        and challenge is None
    )
    if nothing_supplied:
        return None
    return verify.Disclosure(
        identifier=args.disclose_identifier,
        identifier_type=args.disclose_type,
        salt=salt,
        challenge=challenge,
    )


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        envelope_bytes = args.envelope.read_bytes()
    except FileNotFoundError as exc:
        raise CliUsageError(f"file not found: {args.envelope}") from exc
    except OSError as exc:
        raise CliUsageError(f"cannot read {args.envelope}: {exc}") from exc

    trust_store = _load_trust_dir(args.trust_dir)
    revocation_view = _read_json(args.revocations) if args.revocations is not None else None
    # Security: require an explicit JSON array. A lone record object (exactly
    # what `revocation.build_record` emits) would otherwise be forwarded
    # untyped and silently ignored by the revocation check, passing a revoked
    # receipt as ok. Do not auto-wrap — make the operator supply the array.
    if revocation_view is not None and not isinstance(revocation_view, list):
        raise CliUsageError(
            "--revocations must contain a JSON array of records; wrap a single record in [ ]"
        )
    disclosure = _build_disclosure(args)

    transparency_evidence = (
        _read_json(
            args.transparency,
            max_bytes=_MAX_STAGE2_INPUT_BYTES["json"],
            input_name="--transparency",
        )
        if args.transparency is not None
        else None
    )
    if transparency_evidence is not None and not isinstance(transparency_evidence, dict):
        raise CliUsageError(f"--transparency file {args.transparency} must contain a JSON object")
    log_keys = _load_log_keys(args.log_keys) if args.log_keys is not None else None
    crqc_horizon = _parse_crqc_horizon(args.crqc_horizon) if args.crqc_horizon is not None else None
    anchor_policy = _load_anchor_policy(args.anchor_policy, crqc_horizon)
    witness_policy = _load_witness_policy(args.witness_policy)

    result = verify.verify(
        envelope_bytes,
        trust_store,
        revocation_view,
        disclosure,
        transparency=transparency_evidence,
        log_keys=log_keys,
        anchor_policy=anchor_policy,
        witness_policy=witness_policy,
    )
    _print_json(_result_to_dict(result))
    return EXIT_OK if result.ok else EXIT_VERIFICATION_FAILED


# --- disclose -----------------------------------------------------------------------


def _resolve_disclose_out(raw_out: str) -> Path:
    """Resolve `--out` for `disclose` into the directory-or-file target
    `bundle.disclose()` expects.

    `bundle.disclose()` only recognizes an ALREADY-EXISTING directory
    (`out.is_dir()`) — a not-yet-created target directory (a fresh demo run
    doing `disclose --out ./share/`) would otherwise be treated as a literal
    file path named "share". A trailing path separator is treated as an
    explicit "this is a directory" signal and created if missing; an
    already-existing directory is honored as-is; anything else is an exact
    file path (its parent directories are created by `bundle.disclose()`
    itself). The named `--out` path itself is refused if it is a symlink before
    any directory routing, including dangling symlinks and links to existing
    directories.
    """
    out_path = Path(raw_out)
    if out_path.is_symlink():
        raise CliUsageError(f"disclose output {out_path} is a symlink; refusing to overwrite it")
    looks_like_directory = raw_out.endswith(("/", os.sep)) or out_path.is_dir()
    if looks_like_directory:
        out_path.mkdir(parents=True, exist_ok=True)
    return out_path


def _cmd_disclose(args: argparse.Namespace) -> int:
    receipts = [_read_json(p) for p in args.receipt]
    key_manifests = [_read_json(p) for p in args.key_manifest]
    salts: dict[str, bytes] = {}
    if args.salt is not None:
        salts[args.receipt_id] = _read_b64u_file(args.salt)

    out_target = _resolve_disclose_out(args.out)
    written = bundle.disclose(receipts, key_manifests, salts, args.receipt_id, out_target)
    _print_json({"out": str(written)})
    return EXIT_OK


# --- export / import -----------------------------------------------------------------


def _cmd_export(args: argparse.Namespace) -> int:
    receipts = [_read_json(p) for p in args.receipt]
    key_manifests = [_read_json(p) for p in args.key_manifest]
    artifact_manifests = [_read_json(p) for p in args.artifact_manifest]

    legal_texts: dict[str, bytes] = {}
    for path in args.legal_text:
        content = path.read_bytes()
        legal_texts[hashlib.sha256(content).hexdigest()] = content

    proofs: dict[str, dict[str, Any]] = {}
    if args.proof_dir is not None:
        if not args.proof_dir.is_dir():
            raise CliUsageError(f"--proof-dir {args.proof_dir} is not a directory")
        for envelope in receipts:
            payload = envelope.get("payload") if isinstance(envelope, dict) else None
            receipt_id = payload.get("receipt_id") if isinstance(payload, dict) else None
            if not isinstance(receipt_id, str):
                continue
            candidate = _proof_path_in_dir(args.proof_dir, receipt_id)
            if candidate.is_file():
                evidence = _read_json(candidate)
                if not isinstance(evidence, dict):
                    raise CliUsageError(f"{candidate} must contain a JSON object")
                proofs[receipt_id] = evidence

    # The private bundle carries salts.json — every buyer-binding salt in the
    # bundle — so it is protected. It is excluded from the identity clause on
    # purpose: a zip is not byte-reproducible even at identical logical content
    # (timestamps, member order, deflate levels), and reopening a file of
    # secrets just to authorize a no-op would be surface for no gain. Refusing
    # on mere existence is the fail-closed direction; --force re-exports.
    #
    # The guard is layered, which is why the filename is spelled out here as
    # well as in bundle.export: this pre-check refuses on mere existence and
    # reports it as a CLI usage error naming the option, while bundle.export
    # opens the same path with O_NOFOLLOW (plus O_EXCL unless --force) and an
    # fstat that rejects a hard-linked alias, so a file that appears between
    # the two is reported instead of truncated. The export tests pin that the
    # two spellings agree, so a naming change fails loudly instead of silently
    # unguarding it.
    #
    # Overwrite-unguarded by design: the shareable `<name>.attest` is
    # recomputable from inputs that all remain on local disk (2026-08-24
    # destructive-output-paths plan).
    guarded_private_path = args.out_dir / f"{args.name}.private.attest"
    if not args.force and _path_is_present(guarded_private_path):
        raise CliUsageError(
            f"--out-dir already contains {guarded_private_path}; "
            "refusing to overwrite a .private.attest (pass --force to replace it)"
        )

    attest_path, private_path = bundle.export(
        receipts,
        key_manifests,
        artifact_manifests,
        legal_texts,
        args.out_dir,
        args.name,
        proofs=proofs or None,
        private_exclusive=not args.force,
    )
    _print_json({"attest": str(attest_path), "private": str(private_path)})
    return EXIT_OK


def _cmd_import(args: argparse.Namespace) -> int:
    if args.private is not None:
        # Spec: a conforming CLI MUST warn whenever .private material is accessed
        # (2026-07-13 review, finding 19).
        print(
            "warning: reading .private.attest — it carries buyer-binding secrets; "
            "handle it with care and never share it.",
            file=sys.stderr,
        )
    imported = bundle.import_bundle(args.bundle, args.private)

    receipts_dir = args.out_dir / "receipts"
    trust_dir = args.out_dir / "trust"

    # Two-phase: precompute the protected files and guard every one of them
    # before the first write, so a bundle that conflicts on its trust anchors
    # or its salts cannot leave a half-imported directory behind. The identity
    # clause is what keeps re-importing the same bundle idempotent.
    trust_writes: list[tuple[Path, str, _OverwritePlan]] = []
    planned_trust_paths: set[Path] = set()
    for issuer, chain in imported.trust_store.chains.items():
        for version_manifest in chain:
            version = _trust_manifest_version_for_filename(version_manifest, issuer)
            trust_path = trust_dir / f"{_safe_name(issuer)}.v{version}.json"
            trust_text = _json_text(version_manifest)
            if trust_path in planned_trust_paths:
                raise CliUsageError(
                    f"import: trust-store file {trust_path} would be written more than once; "
                    "refusing to overwrite it"
                )
            planned_trust_paths.add(trust_path)
            trust_plan = _prepare_overwrite(
                trust_path, trust_text, label="import: trust-store file", force=args.force
            )
            trust_writes.append((trust_path, trust_text, trust_plan))

    salts_path = args.out_dir / "salts.json"
    salts_text: str | None = None
    salts_plan: _OverwritePlan | None = None
    if imported.salts:
        salts_payload = {rid: keys.b64u(s) for rid, s in imported.salts.items()}
        # Serialization kept exactly as before (no sort_keys): the guard must
        # compare the bytes this command actually writes.
        salts_text = json.dumps(salts_payload, indent=2)
        salts_plan = _prepare_overwrite(
            salts_path, salts_text, label="import: salts file", force=args.force
        )

    # Overwrite-unguarded by design: an imported receipt is re-extractable from
    # the bundle the holder still holds (2026-08-24 destructive-output-paths plan).
    for envelope in imported.receipts:
        receipt_id = envelope["payload"]["receipt_id"]
        _write_json_file(receipts_dir / f"{receipt_id}.attest.json", envelope)

    for trust_path, trust_text, trust_plan in trust_writes:
        _write_json_text(
            trust_path,
            trust_text,
            exclusive=not trust_plan.existed,
            label="import: trust-store file",
            overwrite_plan=trust_plan,
        )

    if imported.artifact_manifests:
        artifacts_dir = args.out_dir / "artifact-manifests"
        # Overwrite-unguarded by design: re-extractable from the bundle and not
        # loggable, like `manifest artifacts` (2026-08-24 plan).
        for series, versions in imported.artifact_manifests.items():
            for am in versions:
                version = am.get("version", 0)
                _write_json_file(artifacts_dir / f"{_safe_name(series)}.v{version}.json", am)

    if imported.legal_texts:
        legal_dir = args.out_dir / "legal"
        legal_dir.mkdir(parents=True, exist_ok=True)
        # Overwrite-unguarded by design: content-addressed — the filename IS the
        # SHA-256 of the content and import_bundle validates it, so any overwrite
        # here can only be byte-identical (2026-08-24 plan).
        for digest, content in imported.legal_texts.items():
            (legal_dir / f"{digest}.txt").write_bytes(content)

    if salts_text is not None:
        assert salts_plan is not None
        _write_secret_text(
            salts_path,
            salts_text,
            exclusive=not salts_plan.existed,
            label="import: salts file",
            overwrite_plan=salts_plan,
        )

    if imported.proofs:
        proofs_dir = args.out_dir / "proofs"
        # Overwrite-unguarded by design: evidence is rederivable from the log
        # (`log prove`) or re-extractable from the bundle (2026-08-24 plan).
        for receipt_id, evidence in imported.proofs.items():
            _write_json_file(proofs_dir / f"{receipt_id}.json", evidence)

    _print_json(
        {
            "out_dir": str(args.out_dir),
            "receipts": len(imported.receipts),
            "issuers": sorted(imported.trust_store.manifests),
            "proofs": len(imported.proofs),
        }
    )
    return EXIT_OK


# --- inspect ----------------------------------------------------------------------


def _cmd_inspect(args: argparse.Namespace) -> int:
    envelope = _read_json(args.envelope)
    if not isinstance(envelope, dict):
        raise CliUsageError(f"{args.envelope} is not a JSON object")

    warnings: list[str] = []
    delivery = envelope.get("delivery")
    salt_present = isinstance(delivery, dict) and "salt" in delivery
    if salt_present:
        warnings.append(
            "delivery.salt is present — a shareable file should not carry a buyer-binding salt"
        )

    # Never print the raw buyer-binding secret to stdout: an operator pasting
    # inspect output into a ticket/Slack/shell-history would leak the very
    # secret this verb warns about. Redact it on a deep copy so the on-disk
    # file and the parsed object stay untouched.
    printed = copy.deepcopy(envelope)
    if salt_present:
        printed["delivery"]["salt"] = _REDACTED_SALT

    _print_json({"envelope": printed, "warnings": warnings})
    return EXIT_OK


# --- check-artifact -----------------------------------------------------------------


def _cmd_check_artifact(args: argparse.Namespace) -> int:
    envelope = _read_json(args.receipt)
    payload = envelope.get("payload") if isinstance(envelope, dict) else None
    if not isinstance(payload, dict):
        raise CliUsageError(f"{args.receipt} is missing 'payload'")
    work = payload.get("work")
    artifacts = work.get("artifacts") if isinstance(work, dict) else None
    if not artifacts:
        raise CliUsageError(f"{args.receipt} has no work.artifacts to check against")

    try:
        digest = hashlib.sha256(args.file.read_bytes()).hexdigest()
    except FileNotFoundError as exc:
        raise CliUsageError(f"file not found: {args.file}") from exc

    match = next((a for a in artifacts if isinstance(a, dict) and a.get("sha256") == digest), None)
    # This verb compares hashes only; it does NOT authenticate the receipt. Say so
    # loudly and machine-readably so a match is never mistaken for verification
    # (2026-07-13 review, finding 13).
    print(
        "warning: check-artifact compares hashes only and does NOT verify the receipt "
        "signature — use `attest verify` to authenticate the receipt.",
        file=sys.stderr,
    )
    _print_json(
        {
            "file": str(args.file),
            "sha256": digest,
            "match": match is not None,
            "artifact": match,
            "authenticated": False,
        }
    )
    return EXIT_OK if match is not None else EXIT_VERIFICATION_FAILED


# --- argument parser ----------------------------------------------------------------


def _add_force_flag(parser: argparse.ArgumentParser) -> None:
    """Add --force to a command that writes at least one protected output.

    Deliberately not added to commands whose outputs are all derivable: a flag
    there would misrepresent where the risk actually is.
    """
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite protected output files that already exist with different content",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attest", description="attest operator CLI (v0.1 and v0.2)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="Generate an Ed25519 keypair")
    p.add_argument("--seed-out", required=True, type=Path, help="secret seed output path (0600)")
    p.add_argument("--pub-out", required=True, type=Path, help="public key output path")
    _add_force_flag(p)
    p.add_argument(
        "--hybrid",
        action="store_true",
        help="also generate an ML-DSA-65 keypair for the v0.2 hybrid profile "
        "(requires --mldsa-out)",
    )
    p.add_argument(
        "--mldsa-out",
        type=Path,
        default=None,
        help="ML-DSA-65 secret key output path (0600 JSON); required with --hybrid",
    )
    p.set_defaults(func=_cmd_keygen)

    p_manifest = sub.add_parser("manifest", help="Key/artifact manifest operations")
    manifest_sub = p_manifest.add_subparsers(dest="manifest_command", required=True)

    p = manifest_sub.add_parser("init", help="Create the first, self-signed key manifest")
    p.add_argument("--issuer", required=True, help="issuer id, e.g. store.example.com")
    p.add_argument("--kid", required=True, help="key id of the bootstrap signing key")
    p.add_argument("--seed", required=True, type=Path, help="seed file for the bootstrap key")
    p.add_argument("--valid-from", required=True)
    p.add_argument("--valid-to", default=None)
    p.add_argument("--issued-at", required=True, help="manifest issuance timestamp")
    p.add_argument(
        "--mldsa-key",
        type=Path,
        default=None,
        help="ML-DSA-65 key file (from `keygen --hybrid`); makes the bootstrap entry "
        "and manifest signature hybrid",
    )
    p.add_argument("--out", required=True, type=Path)
    _add_force_flag(p)
    p.set_defaults(func=_cmd_manifest_init)

    p = manifest_sub.add_parser(
        "rotate", help="Add a new key and/or retire/compromise existing ones"
    )
    p.add_argument("--in", dest="manifest_in", required=True, type=Path, help="trusted manifest")
    p.add_argument("--signing-kid", required=True, help="active kid from the trusted manifest")
    p.add_argument("--signing-seed", required=True, type=Path)
    p.add_argument("--new-kid", default=None, help="kid of a new key to add (with --new-pub)")
    p.add_argument("--new-pub", type=Path, default=None, help="public key file of the new key")
    p.add_argument(
        "--new-mldsa-pub",
        type=Path,
        default=None,
        help="ML-DSA-65 public key file for the new key; makes the new entry hybrid — "
        "requires --new-pub",
    )
    p.add_argument("--valid-from", default=None, help="required only when adding a new key")
    p.add_argument("--valid-to", default=None)
    p.add_argument(
        "--retire-kid",
        action="append",
        default=[],
        help="repeatable; set an existing key's status to retired (past signatures stay valid)",
    )
    p.add_argument(
        "--compromise-kid",
        action="append",
        default=[],
        help=(
            "repeatable; set an existing key's status to compromised "
            "(invalidates its past signatures)"
        ),
    )
    p.add_argument("--issued-at", required=True)
    p.add_argument(
        "--mldsa-key",
        type=Path,
        default=None,
        help="ML-DSA-65 leg of the signing key; makes the manifest signature hybrid",
    )
    p.add_argument("--out", required=True, type=Path)
    _add_force_flag(p)
    p.set_defaults(func=_cmd_manifest_rotate)

    p = manifest_sub.add_parser("artifacts", help="Build and sign an artifact manifest")
    p.add_argument(
        "--in", dest="manifest_in", required=True, type=Path, help="signer's key manifest"
    )
    p.add_argument("--issuer", required=True)
    p.add_argument("--series", required=True)
    p.add_argument("--version", required=True, type=int)
    p.add_argument(
        "--manifest-version",
        required=True,
        type=_manifest_version_arg,
        help="G2/G3 currency counter (attest-versioning.md rev 4) — distinct from --version "
        "(the series' own release number); REQUIRED on every manifest built going forward",
    )
    p.add_argument("--released-at", required=True)
    p.add_argument("--artifacts", required=True, type=Path, help="JSON file: array of artifacts")
    p.add_argument("--signing-kid", required=True)
    p.add_argument("--signing-seed", required=True, type=Path)
    p.add_argument(
        "--mldsa-key",
        type=Path,
        default=None,
        help="ML-DSA-65 leg of the signing key; required exactly for a hybrid key entry",
    )
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_cmd_manifest_artifacts)

    p = sub.add_parser("issue", help="Sign a payload into a receipt envelope")
    p.add_argument("--payload", required=True, type=Path, help="payload JSON to sign")
    p.add_argument("--seed", required=True, type=Path, help="issuer signing key seed")
    p.add_argument("--kid", required=True)
    p.add_argument("--salt", type=Path, default=None, help="buyer-binding salt to embed")
    p.add_argument("--salt-out", type=Path, default=None, help="also copy --salt to this path")
    p.add_argument("--manifest-snapshot", type=Path, default=None)
    p.add_argument(
        "--attest-version",
        choices=("0.1", "0.2"),
        default="0.1",
        help="signing profile; 0.2 requires --mldsa-key (hybrid Ed25519+ML-DSA-65)",
    )
    p.add_argument(
        "--mldsa-key",
        type=Path,
        default=None,
        help="ML-DSA-65 key file (from `keygen --hybrid`); required with --attest-version 0.2",
    )
    p.add_argument("--out", required=True, type=Path, help="output envelope JSON path")
    _add_force_flag(p)
    p.set_defaults(func=_cmd_issue)

    p_transfer = sub.add_parser("transfer", help="Issuer-mediated transfer operations (v0.2 §17)")
    transfer_sub = p_transfer.add_subparsers(dest="transfer_command", required=True)

    p = transfer_sub.add_parser(
        "authorize", help="Sign the OUTGOING holder's transfer authorization"
    )
    p.add_argument("--receipt", required=True, type=Path, help="OLD receipt envelope JSON")
    p.add_argument(
        "--new-holder-pubkey", required=True, help="incoming holder's Ed25519 pubkey, b64u"
    )
    p.add_argument("--transferred-at", required=True, help="ISO-8601 UTC signed time")
    p.add_argument(
        "--holder-seed", required=True, type=Path, help="OLD receipt's own buyer.pubkey seed"
    )
    p.add_argument("--out", required=True, type=Path, help="output {'sig': <b64u>} JSON path")
    p.set_defaults(func=_cmd_transfer_authorize)

    p = transfer_sub.add_parser(
        "record", help="Verify holder authorization and sign an issuer-mediated transfer record"
    )
    p.add_argument("--receipt", required=True, type=Path, help="OLD receipt envelope JSON")
    p.add_argument("--new-receipt-id", required=True, help="NEW receipt_id (ULID)")
    p.add_argument(
        "--new-holder-pubkey", required=True, help="incoming holder's Ed25519 pubkey, b64u"
    )
    p.add_argument("--transferred-at", required=True, help="ISO-8601 UTC signed time")
    p.add_argument(
        "--holder-authorization",
        required=True,
        type=Path,
        help="JSON file from `transfer authorize`: {'sig': <b64u>}",
    )
    p.add_argument("--seed", required=True, type=Path, help="issuer signing key seed")
    p.add_argument("--kid", required=True)
    p.add_argument(
        "--mldsa-seed",
        type=Path,
        default=None,
        help="ML-DSA-65 key file (from `keygen --hybrid`); makes the record signature hybrid",
    )
    p.add_argument(
        "--revocation-out",
        type=Path,
        default=None,
        help="also write a status:'transferred' revocation record for the old receipt",
    )
    p.add_argument(
        "--out", required=True, type=Path, help="output signed transfer record JSON path"
    )
    _add_force_flag(p)
    p.set_defaults(func=_cmd_transfer_record)

    p_log = sub.add_parser(
        "log", help="Transparency-log operator/holder commands (offline-signer split)"
    )
    log_sub = p_log.add_subparsers(dest="log_command", required=True)

    p = log_sub.add_parser("init", help="Create an empty transparency log directory")
    p.add_argument("--dir", required=True, type=Path)
    p.add_argument("--origin", required=True, help="C2SP checkpoint origin, printable ASCII")
    p.set_defaults(func=_cmd_log_init)

    p = log_sub.add_parser(
        "append",
        help="Validate+append one entry, rebuild tiles, write an UNSIGNED candidate",
        description=(
            "OFFLINE-SIGNER SPLIT (CI side): validates --entry-json against the closed entry "
            "schema, appends it to the log's entries store, rebuilds the level-0 tlog-tiles "
            "under LOG/tile/0/... (a minimal, C2SP-tlog-tiles-inspired leaf-hash layout — see "
            "the source for the documented simplification), and writes an UNSIGNED "
            "LOG/checkpoint.candidate (origin, size, base64 root only, no signature). This step "
            "never signs anything: only `attest log sign-checkpoint`, run by the separately-"
            "administered offline/ceremony signer, may produce LOG/checkpoint."
        ),
    )
    p.add_argument("--dir", required=True, type=Path)
    p.add_argument("--entry-json", required=True, type=Path, help="one JSON entry object")
    p.set_defaults(func=_cmd_log_append)

    p = log_sub.add_parser(
        "sign-checkpoint",
        help="OFFLINE SIGNER: recompute+verify the candidate, then sign LOG/checkpoint",
        description=(
            "OFFLINE-SIGNER SPLIT (ceremony side): recomputes the tree root directly from the "
            "entries store (never trusting the candidate or the cached tiles), and refuses to "
            "sign unless that recomputation EXACTLY matches LOG/checkpoint.candidate. If a "
            "previously signed LOG/checkpoint already exists, ALSO refuses to sign unless the "
            "new tree is a verified RFC 6962 consistency-proof extension of it (catches history "
            "rewrites a self-consistent candidate alone would not). Only once both checks pass "
            "is the checkpoint hybrid-signed (Ed25519 + ML-DSA-65), self-verified, and written "
            "to LOG/checkpoint. This is the only command that may hold the log's signing keys; "
            "CI/the append step never does."
        ),
    )
    p.add_argument("--dir", required=True, type=Path)
    p.add_argument("--ed25519-key", required=True, type=Path, help="log signer's Ed25519 seed file")
    p.add_argument("--mldsa-key", required=True, type=Path, help="log signer's ML-DSA-65 key file")
    p.add_argument("--name", required=True, help="C2SP signed-note key name")
    p.set_defaults(func=_cmd_log_sign_checkpoint)

    p = log_sub.add_parser(
        "prove", help="Emit inclusion evidence (Task 4 schema) for one logged entry, no anchors"
    )
    p.add_argument("--dir", required=True, type=Path)
    p.add_argument("--leaf-index", required=True, type=int)
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_cmd_log_prove)

    p = log_sub.add_parser(
        "anchor",
        help="Attach externally-obtained OTS/RFC3161 anchor material to an evidence file",
        description=(
            "ATTACHES anchor material obtained OUTSIDE this process to a `log prove`-produced "
            "evidence file's `anchors` member (acquiring an OTS/Bitcoin attestation or an "
            "RFC 3161 timestamp is out of this CLI's scope — it never touches the network). "
            "--dir's config.json is read only to confirm the evidence's own checkpoint origin "
            "actually belongs to this log."
        ),
    )
    p.add_argument("--dir", required=True, type=Path)
    p.add_argument("--evidence", required=True, type=Path, help="evidence JSON from `log prove`")
    p.add_argument(
        "--ots-proof",
        required=True,
        type=Path,
        help="JSON object: ops/header_merkle_root/header_hash/header_time",
    )
    p.add_argument(
        "--rfc3161-token",
        type=Path,
        default=None,
        help="raw RFC 3161 TimeStampToken bytes (opaque, never parsed)",
    )
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_cmd_log_anchor)

    p = sub.add_parser("verify", help="Verify a receipt envelope")
    p.add_argument("envelope", type=Path)
    p.add_argument("--trust-dir", required=True, type=Path, help="directory of key manifest files")
    p.add_argument("--revocations", type=Path, default=None, help="JSON file: revocation records")
    p.add_argument("--disclose-identifier", default=None)
    p.add_argument("--disclose-type", default=None)
    p.add_argument("--disclose-salt", type=Path, default=None)
    p.add_argument("--disclose-challenge-nonce", type=Path, default=None)
    p.add_argument("--disclose-challenge-sig", type=Path, default=None)
    p.add_argument(
        "--transparency",
        type=Path,
        default=None,
        help="Task-4 evidence JSON for one claim (entry/leaf_index/tree_size/"
        "inclusion_proof/checkpoint[/anchors])",
    )
    p.add_argument(
        "--log-keys",
        type=Path,
        default=None,
        help="JSON array of pinned {origin,name,ed25519_pub_b64u,mldsa_pub_b64u} log keys",
    )
    p.add_argument(
        "--anchor-policy",
        type=Path,
        default=None,
        help="JSON {pinned_headers,crqc_horizon} anchor trust policy",
    )
    p.add_argument(
        "--crqc-horizon",
        default=None,
        help="ISO-8601 UTC timestamp (e.g. 2030-01-01T00:00:00Z); overrides/sets "
        "--anchor-policy's crqc_horizon",
    )
    p.add_argument(
        "--witness-policy",
        type=Path,
        default=None,
        help="JSON attest-witness-policy-v1 document pinning witness operators",
    )
    p.set_defaults(func=_cmd_verify)

    p = sub.add_parser("disclose", help="Emit one self-contained receipt file")
    p.add_argument("receipt_id")
    p.add_argument("--receipt", required=True, action="append", type=Path, help="repeatable")
    p.add_argument("--key-manifest", required=True, action="append", type=Path, help="repeatable")
    p.add_argument("--salt", type=Path, default=None, help="this receipt's own buyer-binding salt")
    p.add_argument("--out", required=True, help="output file, or directory (created if missing)")
    p.set_defaults(func=_cmd_disclose)

    p = sub.add_parser("export", help="Export a shareable .attest + secrets .private.attest")
    p.add_argument("--receipt", required=True, action="append", type=Path, help="repeatable")
    p.add_argument("--key-manifest", required=True, action="append", type=Path, help="repeatable")
    p.add_argument("--artifact-manifest", action="append", type=Path, default=[], help="repeatable")
    p.add_argument(
        "--legal-text",
        action="append",
        type=Path,
        default=[],
        help="repeatable; hash is computed from file content",
    )
    p.add_argument(
        "--proof-dir",
        type=Path,
        default=None,
        help="directory of <receipt_id>.json transparency evidence files (from `attest log "
        "prove`/`anchor`) to embed under proofs/ — corroboration, not authenticity",
    )
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--name", required=True)
    _add_force_flag(p)
    p.set_defaults(func=_cmd_export)

    p = sub.add_parser("import", help="Reconstruct receipts + a trust store from a .attest bundle")
    p.add_argument("--bundle", required=True, type=Path)
    p.add_argument("--private", type=Path, default=None, help=".private.attest sibling, for salts")
    p.add_argument("--out-dir", required=True, type=Path)
    _add_force_flag(p)
    p.set_defaults(func=_cmd_import)

    p = sub.add_parser("inspect", help="Pretty-print an envelope and warn on shareability issues")
    p.add_argument("envelope", type=Path)
    p.set_defaults(func=_cmd_inspect)

    p = sub.add_parser("check-artifact", help="Hash a local file against a receipt's artifacts")
    p.add_argument("file", type=Path)
    p.add_argument("--receipt", required=True, type=Path)
    p.set_defaults(func=_cmd_check_artifact)

    return parser


# --- entry point ----------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CliUsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,  # e.g. a well-formed-JSON-but-wrong-shape input (list instead of object)
        json.JSONDecodeError,
        canon.CanonError,
        bundle.BundleError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR


if __name__ == "__main__":
    sys.exit(main())
