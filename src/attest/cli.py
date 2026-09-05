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
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from attest import (
    anchor,
    authority,
    bundle,
    canon,
    grant,
    issue,
    keys,
    manifests,
    ots,
    pq,
    revocation,
    tlog,
    transfer,
    validate,
    verify,
    views,
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
    # Detached OTS samples measured for V-H.7 were small; cap before parsing.
    # Same number as the parser's own file ceiling, taken FROM it: two
    # independent literals would drift, and the CLI cap exists to keep the
    # parser from ever seeing more than the parser itself admits.
    "ots": ots._MAX_OTS_FILE_BYTES,
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


def _loads_strict(data: bytes, path: Path, input_name: str) -> Any:
    """Parse CLI input bytes with the canonical strict parser.

    `_read_json` above uses `json.loads`, where a duplicate object member
    collapses onto the last one and a float parses fine — behavior published
    for the flags that already had it, and not changed here. Inputs introduced
    with the revocation rail read through this function instead: a file whose
    meaning depends on which duplicate a parser happens to keep is refused,
    not resolved by position (`canon.loads_strict`, same reader the verifier's
    own admission path uses).
    """
    try:
        return canon.loads_strict(data)
    except canon.CanonError as exc:
        raise CliUsageError(f"cannot read {input_name} {path}: {exc}") from exc


def _read_strict_json(path: Path, *, max_bytes: int, input_name: str) -> Any:
    """`_read_bounded_bytes` followed by `_loads_strict`, for a NEW CLI input."""
    return _loads_strict(
        _read_bounded_bytes(path, max_bytes=max_bytes, input_name=input_name),
        path,
        input_name,
    )


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


# v0.1 §12.2: only these two classes can be revoked at all. A `none` receipt
# is irrevocable by construction, so a record naming one is an artifact every
# conforming verifier ignores — this producer refuses to write one.
_REVOCABLE_CLASSES = ("refund_window", "policy")


def _cmd_revoke(args: argparse.Namespace) -> int:
    for label, path in (
        ("--receipt", args.receipt),
        ("--manifest", args.manifest),
        ("--seed", args.seed),
    ):
        if _same_file_target(path, args.out):
            raise CliUsageError(f"{label} and --out must be different paths")
    if args.mldsa_seed is not None and _same_file_target(args.mldsa_seed, args.out):
        raise CliUsageError("--mldsa-seed and --out must be different paths")

    # Bounded by the ceiling the VERIFIER applies to an envelope, not by the
    # wider Stage-2 input ceiling the other JSON inputs use: the closing
    # predicate below hands these very bytes to `verify.verify`, which refuses
    # anything above `validate.MAX_ENVELOPE_BYTES`. A wider bound here would
    # only buy the same refusal one step later, with a worse message.
    envelope_bytes = _read_bounded_bytes(
        args.receipt, max_bytes=validate.MAX_ENVELOPE_BYTES, input_name="--receipt"
    )
    envelope = _loads_strict(envelope_bytes, args.receipt, "--receipt")
    if not isinstance(envelope, dict):
        raise CliUsageError(f"{args.receipt} must contain a JSON object")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise CliUsageError(f"{args.receipt} is missing object member 'payload'")
    receipt_id = payload.get("receipt_id")
    if not isinstance(receipt_id, str) or revocation.RECEIPT_ID_RE.fullmatch(receipt_id) is None:
        raise CliUsageError(f"{args.receipt} payload member 'receipt_id' must be a ULID")
    issuer_block = payload.get("issuer")
    issuer_id = issuer_block.get("id") if isinstance(issuer_block, dict) else None
    if not isinstance(issuer_id, str):
        raise CliUsageError(f"{args.receipt} payload is missing string 'issuer.id'")

    license_block = payload.get("license")
    revocability = license_block.get("revocability") if isinstance(license_block, dict) else None
    if not isinstance(revocability, str):
        raise CliUsageError(f"{args.receipt} payload is missing string 'license.revocability'")
    if revocability not in _REVOCABLE_CLASSES:
        raise CliUsageError(
            f"license.revocability is {revocability!r}: v0.1 §12.2 makes such a receipt "
            "irrevocable, and a record naming it would be ignored by every verifier "
            f"(revocable classes: {', '.join(_REVOCABLE_CLASSES)})"
        )

    # `strptime` alone accepts unpadded components (`2025-8-1T0:0:0Z`) and would
    # sign a spelling no verifier re-serializes the same way; the round trip is
    # what pins the byte form the signature commits to.
    try:
        revoked_at = datetime.datetime.strptime(args.revoked_at, revocation._DATE_FMT)
    except ValueError as exc:
        raise CliUsageError(
            f"--revoked-at must be an ISO-8601 UTC instant spelled YYYY-MM-DDTHH:MM:SSZ: {exc}"
        ) from exc
    canonical_revoked_at = revoked_at.strftime(revocation._DATE_FMT)
    if canonical_revoked_at != args.revoked_at:
        raise CliUsageError(
            f"--revoked-at {args.revoked_at!r} is not the canonical spelling of that "
            f"instant: write it exactly as {canonical_revoked_at!r}"
        )

    manifest = _read_strict_json(
        args.manifest, max_bytes=_MAX_STAGE2_INPUT_BYTES["json"], input_name="--manifest"
    )
    if not isinstance(manifest, dict) or not isinstance(manifest.get("keys"), list):
        raise CliUsageError(f"{args.manifest} must contain a key manifest with a 'keys' array")
    if manifest.get("issuer") != issuer_id:
        raise CliUsageError(
            f"{args.manifest} is issued by {manifest.get('issuer')!r}, not by the receipt's "
            f"issuer {issuer_id!r}"
        )
    if not manifests.verify_key_manifest(manifest):
        raise CliUsageError(f"{args.manifest} does not verify against its own listed keys")

    # Hybrid detection reads the manifest ENTRY, exactly as `manifest rotate`
    # does: the key material decides which legs a signature owes, never a flag.
    entry = manifests.find_key(manifest, args.kid)
    if entry is None:
        raise CliUsageError(f"--kid {args.kid!r} is not present in {args.manifest}")
    is_hybrid = "pub_ml_dsa_65" in entry
    if is_hybrid and args.mldsa_seed is None:
        raise CliUsageError(f"signing key {args.kid!r} is hybrid; --mldsa-seed is required")
    if not is_hybrid and args.mldsa_seed is not None:
        raise CliUsageError(
            f"signing key {args.kid!r} is Ed25519-only; --mldsa-seed is not allowed"
        )
    mldsa_kp: pq.MLDSAKeyPair | None = None
    if is_hybrid and args.mldsa_seed is not None:
        mldsa_kp = _load_mldsa_kp(args.mldsa_seed)
        try:
            entry_mldsa_pub = keys.b64u_decode(entry["pub_ml_dsa_65"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CliUsageError(
                f"{args.manifest} has a malformed pub_ml_dsa_65 for {args.kid!r}: {exc}"
            ) from exc
        if mldsa_kp.pub != entry_mldsa_pub:
            raise CliUsageError(
                "--mldsa-seed does not match the signing key's ML-DSA-65 public key in the manifest"
            )

    ed_signing_kp = _load_seed_kp(args.seed)
    signing_kp: keys.SigningKeyPair | pq.HybridSigningKeys = ed_signing_kp
    if mldsa_kp is not None:
        signing_kp = pq.HybridSigningKeys(ed=ed_signing_kp, mldsa=mldsa_kp)

    record = revocation.build_record(receipt_id, "revoked", args.revoked_at, signing_kp, args.kid)

    # `revocation.build_record` signs whatever it is handed: the module has no
    # opinion on whether a record is EFFECTIVE against a given receipt, because
    # answering that needs the receipt payload too. So the only honest test of
    # effectiveness is to run the shipped verifier over the receipt with this
    # record in hand, before anything reaches disk. It covers, without a second
    # copy of the rule: a signer that is not `active`, a signer whose validity
    # window does not cover `revoked_at`, a `revoked_at` past the refund window,
    # and a receipt that does not verify against the manifest given.
    result = verify.verify(
        envelope_bytes,
        verify.TrustStore(manifests={issuer_id: manifest}, provenance={issuer_id: "bundle"}),
        [record],
    )
    if result.revocation != "revoked":
        raise CliUsageError(
            "the verifier would not honor this record: "
            f"revocation={result.revocation!r}, warnings={result.warnings!r}, "
            f"errors={result.errors!r}"
        )

    _write_guarded_json(args.out, record, label="--out", force=args.force)
    if revocability == "refund_window":
        print(
            "warning: refund_window records are ignored by Stage-2 verifiers unless logged "
            "and anchored before the deadline (v0.2 §8/§15, G5): run attest log entry "
            "--type revocation-record and log the record",
            file=sys.stderr,
        )
    _print_json(
        {
            "out": str(args.out),
            "receipt_id": receipt_id,
            "revocability": revocability,
            "revoked_at": args.revoked_at,
            "record_sha256": revocation.record_hash(record),
        }
    )
    return EXIT_OK


# --- view producers: revocation, transfer, compromise (v0.2 §8/§17.1/§19.2) --
#
# Three verbs with one shape. Each reads the documents a view is made of, hands
# them to the builder in `views.py` — the single producer of these three wire
# formats — and writes back what the builder returns. No claim is validated
# here: a producer with its own opinion about a claim's shape would be a second
# spelling of a rule that already has one, and the two would drift.
#
# Two properties are shared and load-bearing. Every input is read with
# `canon.loads_strict` (D11), because a view whose meaning depends on which
# duplicate member a parser happened to keep is a view the operator did not
# read. And every file is read, and every claim built, BEFORE the output is
# opened: a refusal on the last pair must not be able to leave a half-built
# view on disk.

# §19.3's classification is relative to the head and chain the CALLER passed.
# Saying so in the warning is not hedging: the same claim can be ignored by one
# verifier and floor-establishing for another, and an operator who reads
# `ineligible` as a property of the declaration itself will draw the wrong
# conclusion about what they just published.
_COMPROMISE_VIEW_CAVEAT = (
    "against the trusted manifest given; a verifier holding a different head or chain "
    "may classify differently"
)


def _reject_output_aliases(out: Path, inputs: list[tuple[str, Path]]) -> None:
    """Refuse an `--out` that names one of the inputs, before any I/O.

    An input clobbered by its own command's output is unrecoverable, and the
    mistake is about the ARGUMENTS, not about the files: it is reported before
    anything is opened, so the operator is not sent to look at a file that is
    perfectly fine (the ordering `--revocation-evidence` already established).
    """
    for label, path in inputs:
        if _same_file_target(path, out):
            raise CliUsageError(f"{label} and --out must be different paths")


def _require_paired(
    first: list[Path], second: list[Path], first_flag: str, second_flag: str
) -> None:
    """`--manifest`/`--evidence` (and `--record`/`--evidence`) pair by POSITION.

    Checked before any I/O: mismatched lengths mean the operator's idea of
    which evidence backs which document is not the one the command would use,
    and silently zipping to the shorter list would build a view that is
    well-formed and wrong.
    """
    if len(first) != len(second):
        raise CliUsageError(
            f"{first_flag} and {second_flag} are paired by position and must be given the same "
            f"number of times: {len(first)} vs {len(second)}"
        )


def _read_view_inputs(paths: list[Path], flag: str) -> list[Any]:
    return [
        _read_strict_json(path, max_bytes=_MAX_STAGE2_INPUT_BYTES["json"], input_name=flag)
        for path in paths
    ]


def _read_appended_view(path: Path | None) -> list[Any]:
    """The existing view `--append` names, or an empty list.

    Its elements are NOT carried over on trust: they are handed to the builder
    beside the new ones and rebuilt claim by claim, so a claim that would not
    be built today cannot survive in a view merely because it was already in
    the file. An existing view is the obvious vector for a poisoned one.
    """
    if path is None:
        return []
    value = _read_strict_json(
        path, max_bytes=_MAX_STAGE2_INPUT_BYTES["json"], input_name="--append"
    )
    if not isinstance(value, list):
        raise CliUsageError(
            f"--append {path} must contain the JSON array of an existing view; a file "
            "containing `null` is not an empty view — omit the flag instead"
        )
    return value


def _built_view(build: Callable[[], list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Run one `views.py` builder, reporting its refusal as a usage error.

    A `ViewError` is always the material this command was given, never a
    verdict about anyone's receipt, so it exits 2 with the builder's own
    message — which already names the claim and the member at fault.
    """
    try:
        return build()
    except views.ViewError as exc:
        raise CliUsageError(str(exc)) from exc


def _cmd_revocation_view(args: argparse.Namespace) -> int:
    """Assemble `revocation-view.json` from signed revocation records (D12).

    Both statuses §12 registers travel this one rail — `revoked` and
    `transferred` — because `attest transfer record` has always emitted the
    second, and a view that dropped it would hide a transfer from the verifier.

    `--manifest` turns on `revocation.verify_record` for every record: signer
    active in a self-consistent manifest, validity window covering the record's
    own signed `revoked_at`. Without it the records are checked for shape only,
    which is the right default for a holder assembling a view out of records
    they were handed and cannot yet authenticate.
    """
    inputs: list[tuple[str, Path]] = [("--record", path) for path in args.record]
    if args.append is not None:
        inputs.append(("--append", args.append))
    if args.manifest is not None:
        inputs.append(("--manifest", args.manifest))
    _reject_output_aliases(args.out, inputs)

    key_manifest = None
    if args.manifest is not None:
        key_manifest = _read_strict_json(
            args.manifest, max_bytes=_MAX_STAGE2_INPUT_BYTES["json"], input_name="--manifest"
        )
        if not isinstance(key_manifest, dict):
            raise CliUsageError(f"--manifest {args.manifest} must contain a JSON object")
    records = [*_read_appended_view(args.append), *_read_view_inputs(args.record, "--record")]

    view = _built_view(lambda: views.build_revocation_view(records, key_manifest))
    _write_guarded_json(args.out, view, label="--out", force=args.force)
    _print_json(
        {
            "out": str(args.out),
            "records": len(view),
            "verified_against_manifest": key_manifest is not None,
        }
    )
    return EXIT_OK


def _cmd_transfer_view(args: argparse.Namespace) -> int:
    """Assemble `transfer-view.json` from `{record, evidence}` pairs (§17.1).

    No anchor is required of a transfer claim: one carries weight at `logged`
    standing (`transfer.record_logged_standing`), so demanding an anchor here
    would refuse claims the verifier accepts.
    """
    _require_paired(args.record, args.evidence, "--record", "--evidence")
    inputs: list[tuple[str, Path]] = [("--record", path) for path in args.record]
    inputs += [("--evidence", path) for path in args.evidence]
    if args.append is not None:
        inputs.append(("--append", args.append))
    _reject_output_aliases(args.out, inputs)

    records = _read_view_inputs(args.record, "--record")
    evidence = _read_view_inputs(args.evidence, "--evidence")
    claims: list[Any] = [
        *_read_appended_view(args.append),
        *(
            {"record": record, "evidence": bundle}
            for record, bundle in zip(records, evidence, strict=True)
        ),
    ]

    view = _built_view(lambda: views.build_transfer_view(claims))
    _write_guarded_json(args.out, view, label="--out", force=args.force)
    _print_json({"out": str(args.out), "claims": len(view)})
    return EXIT_OK


def _cmd_manifest_compromise_view(args: argparse.Namespace) -> int:
    """Assemble `compromise-view.json`, and say what each claim can do (§19.3).

    The FILE is the protocol artifact and its shape never varies. The report is
    a local diagnostic: for every claim, and for every compromised kid the
    trusted manifest lists, the four independent axes of
    `views.claim_capabilities`. They are kept apart on purpose — a claim can
    establish the status floor and still be unable to date a cutoff, and
    collapsing that into one synthetic verdict is what made an earlier design
    unanswerable.

    `--trusted-manifest` is required because there is no classification without
    one: the same declaration is ignored by a verifier that does not vouch for
    its signer and floor-establishing for one that does. `--log-keys` and
    `--anchor-policy` are given together or not at all — a cutoff exists only
    once `evaluate_transparency` reaches `anchored_before` under BOTH pins, and
    without them the honest answer is that the question was not asked.
    """
    _require_paired(args.manifest, args.evidence, "--manifest", "--evidence")
    if (args.log_keys is None) != (args.anchor_policy is None):
        raise CliUsageError(
            "--log-keys and --anchor-policy are given together or not at all: a cutoff is "
            "established only under both pins, and either one alone establishes nothing"
        )
    inputs: list[tuple[str, Path]] = [("--trusted-manifest", args.trusted_manifest)]
    inputs += [("--chain", path) for path in args.chain]
    inputs += [("--manifest", path) for path in args.manifest]
    inputs += [("--evidence", path) for path in args.evidence]
    for label, optional in (
        ("--append", args.append),
        ("--log-keys", args.log_keys),
        ("--anchor-policy", args.anchor_policy),
    ):
        if optional is not None:
            inputs.append((label, optional))
    _reject_output_aliases(args.out, inputs)

    trusted_manifest = _read_strict_json(
        args.trusted_manifest,
        max_bytes=_MAX_STAGE2_INPUT_BYTES["json"],
        input_name="--trusted-manifest",
    )
    if not isinstance(trusted_manifest, dict):
        raise CliUsageError(
            f"--trusted-manifest {args.trusted_manifest} must contain a JSON object"
        )
    chain = _read_view_inputs(args.chain, "--chain") or None
    declarations = _read_view_inputs(args.manifest, "--manifest")
    evidence = _read_view_inputs(args.evidence, "--evidence")
    claims: list[Any] = [
        *_read_appended_view(args.append),
        *(
            {"manifest": declaration, "evidence": bundle}
            for declaration, bundle in zip(declarations, evidence, strict=True)
        ),
    ]
    log_keys = _load_log_keys(args.log_keys) if args.log_keys is not None else None
    anchor_policy = _load_anchor_policy(args.anchor_policy, None)

    view = _built_view(lambda: views.build_compromise_view(claims))
    # Classification runs before the write, not after: ambiguous or inauthentic
    # trust material yields no classification at all, and a view published with
    # an unanswerable report is a view whose operator was told nothing.
    capabilities = [
        _claim_capabilities(claim, trusted_manifest, chain, log_keys, anchor_policy)
        for claim in view
    ]

    _write_guarded_json(args.out, view, label="--out", force=args.force)
    for index, report in enumerate(capabilities):
        if not report:
            # An empty report is not a quiet success: the claim marks no key
            # that the trusted manifest lists, so no verifier holding this head
            # will act on it. Saying nothing here would let an operator publish
            # a view that does nothing and believe they had published a
            # declaration — the same failure the revocation producer refuses
            # outright. This one is a warning rather than a refusal because the
            # claim IS valid, and against a DIFFERENT trusted head it may well
            # bite; what is local is the verdict, not the claim.
            print(
                f"warning: claim {index} marks no key listed in --trusted-manifest, so it "
                f"changes nothing for a verifier holding that head, "
                f"{_COMPROMISE_VIEW_CAVEAT}",
                file=sys.stderr,
            )
        for kid, axes in report.items():
            if axes["floor"] == "ignored":
                # `claim_capabilities` allows `floor: ignored` together with
                # `cutoff_signer: ineligible`, and the message below asserts the
                # floor IS established — so on that combination the warning said
                # the opposite of the report it came from.
                print(
                    f"warning: claim {index} kid {kid!r} is ignored under the trusted manifest "
                    f"and chain supplied, so it establishes neither the status floor nor a "
                    f"cutoff, {_COMPROMISE_VIEW_CAVEAT}",
                    file=sys.stderr,
                )
            elif axes["cutoff_signer"] == "ineligible":
                print(
                    f"warning: claim {index} kid {kid!r} establishes the status floor but its "
                    f"signer cannot date a cutoff (cutoff_signer: ineligible), "
                    f"{_COMPROMISE_VIEW_CAVEAT}",
                    file=sys.stderr,
                )
            if axes["anchor_evidence"] == "absent":
                print(
                    f"warning: claim {index} kid {kid!r} carries no anchor material "
                    f"(anchor_evidence: absent), so it can establish no cutoff for a verifier "
                    f"that checks anchors, {_COMPROMISE_VIEW_CAVEAT}",
                    file=sys.stderr,
                )
    _print_json({"out": str(args.out), "claims": len(view), "capabilities": capabilities})
    return EXIT_OK


def _claim_capabilities(
    claim: dict[str, Any],
    trusted_manifest: dict[str, Any],
    chain: list[Any] | None,
    log_keys: list[tlog.LogKey] | None,
    anchor_policy: anchor.AnchorPolicy | None,
) -> dict[str, dict[str, str]]:
    try:
        return views.claim_capabilities(
            claim, trusted_manifest, chain, log_keys=log_keys, anchor_policy=anchor_policy
        )
    except views.ViewError as exc:
        raise CliUsageError(str(exc)) from exc


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


# --- grant: preservation-pledge operations (Stage 4, v0.2 §18) --------------
#
# Five verbs across three parties, and the split matters: `issue` and `declare`
# are the RIGHTS HOLDER's (they take a signing key), `challenge` and `verify`
# are the CUSTODIAN's, `respond` is the HOLDER's. Nothing here is a custodian:
# attest operates none, indexes none, and publishes no directory of where files
# may be found (Appendix A). These are the primitives a custodian would use,
# exposed so §18's machinery is exercisable end-to-end from a shell — grant
# EVALUATION stays on `verify --grant-view`, where every other verdict lives.


def _grant_scope_from_args(args: argparse.Namespace) -> dict[str, Any]:
    """§18.2's scope object: at least one of the two non-empty, `artifacts` a
    SORTED, duplicate-free array of artifact hashes. Sorting here rather than
    demanding it of the operator is deliberate — the order is normative, and a
    tool that silently signs an unsorted array produces a document a conforming
    verifier rejects for a reason the operator cannot see."""
    artifacts = sorted(set(args.artifact or []))
    for value in artifacts:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise CliUsageError(f"--artifact must be 64 lowercase hex characters: {value!r}")
    if args.artifact_series is None and not artifacts:
        raise CliUsageError("at least one of --artifact-series or --artifact is required")
    return {"artifact_series": args.artifact_series, "artifacts": artifacts}


def _grant_signing_kp(args: argparse.Namespace) -> keys.SigningKeyPair | pq.HybridSigningKeys:
    ed_signing_kp = _load_seed_kp(args.seed)
    if args.mldsa_seed is None:
        return ed_signing_kp
    return pq.HybridSigningKeys(ed=ed_signing_kp, mldsa=_load_mldsa_kp(args.mldsa_seed))


def _authority_scope_from_args(args: argparse.Namespace) -> dict[str, Any] | None:
    artifacts = sorted(set(args.artifact or []))
    for value in artifacts:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise CliUsageError(f"--artifact must be 64 lowercase hex characters: {value!r}")
    if args.series is None and not artifacts:
        return None
    return {"artifact_series": args.series, "artifacts": artifacts}


def _validate_authorized_issuers(entries: list[Any]) -> list[dict[str, Any]]:
    if len(entries) > authority.MAX_AUTHORIZED_ISSUERS:
        raise CliUsageError(
            "authorized_issuers exceeds the publisher authorization entry ceiling "
            f"({len(entries)} > {authority.MAX_AUTHORIZED_ISSUERS})"
        )

    validated: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise CliUsageError(f"authorized_issuers[{index}] must be an object")
        if not authority._valid_entry_shape(entry):
            raise CliUsageError(f"authorized_issuers[{index}] is not a valid authorization entry")
        validated.append(cast(dict[str, Any], entry))

    issuer_ids = [dict.get(entry, "issuer_id") for entry in validated]
    if not grant._sorted_unique(issuer_ids, grant._is_dns_name):
        raise CliUsageError("authorized_issuers must be sorted by issuer_id with no duplicates")
    return validated


def _authority_entries_from_args(args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.issuer is not None and args.issuers_file is not None:
        raise CliUsageError("--issuer and --issuers-file are mutually exclusive")

    if args.issuers_file is not None:
        if (
            args.valid_from is not None
            or args.valid_to is not None
            or args.permission is not None
            or args.series is not None
            or args.artifact is not None
        ):
            raise CliUsageError(
                "--valid-from, --valid-to, --permission, --series, and --artifact "
                "cannot be used with --issuers-file"
            )
        entries = _read_json(
            args.issuers_file,
            max_bytes=_MAX_STAGE2_INPUT_BYTES["json"],
            input_name="--issuers-file",
        )
        if not isinstance(entries, list):
            raise CliUsageError(
                f"--issuers-file {args.issuers_file} must contain a JSON array of "
                "authorized issuer entries"
            )
        return _validate_authorized_issuers(entries)

    if not args.issuer:
        raise CliUsageError("one of --issuer or --issuers-file is required")
    if args.valid_from is None:
        raise CliUsageError("--valid-from is required with --issuer")

    permissions = sorted(set(args.permission or [authority.PERMISSION_ISSUE]))
    entries = [
        {
            "issuer_id": issuer_id,
            "valid_from": args.valid_from,
            "valid_to": args.valid_to,
            "permissions": permissions,
            "scope": _authority_scope_from_args(args),
        }
        for issuer_id in sorted(set(args.issuer))
    ]
    return _validate_authorized_issuers(entries)


def _cmd_authority_issue(args: argparse.Namespace) -> int:
    for flag, path in (("--seed", args.seed), ("--mldsa-seed", args.mldsa_seed)):
        if path is not None and _same_file_target(path, args.out):
            raise CliUsageError(f"{flag} and --out must be different paths")
    if args.previous is not None and _same_file_target(args.previous, args.out):
        raise CliUsageError("--previous and --out must be different paths")

    previous = (
        _read_json(
            args.previous,
            max_bytes=_MAX_STAGE2_INPUT_BYTES["json"],
            input_name="--previous",
        )
        if args.previous is not None
        else None
    )
    # The successor check is driven by the FLAG, never by the parsed value: a
    # `--previous` file whose content is the JSON literal `null` parses to
    # None, and handing that to the builder as `previous=None` would SKIP the
    # check the caller asked for while the declaration below — also keyed to
    # the flag — stays silent. D18 admits three outcomes for `--previous`:
    # checked, refused, or declared undone. Never faked.
    if args.previous is not None and not isinstance(previous, dict):
        raise CliUsageError(
            f"--previous file {args.previous} must contain a JSON object; a predecessor "
            "that cannot be read as a document cannot show this one conforming"
        )
    # The verb that EMITS validates the form before signing, and the
    # entries are not the whole document — `publisher`, `issued_at` and the
    # version bound are typed by §20.2 too, and the builder deliberately does
    # not read them. A signature over a document no verifier could admit is
    # worse than a refusal: it surfaces later, somewhere else, with no way
    # back to the flag that caused it.
    if not authority.is_authorization_version(args.authorization_version):
        raise CliUsageError(
            "--authorization-version must be an integer in "
            f"[1, {grant._MAX_JCS_INTEGER}]: {args.authorization_version}"
        )
    if not grant._is_dns_name(args.publisher):
        raise CliUsageError(f"--publisher must be a lowercase DNS domain: {args.publisher!r}")
    if not transfer._valid_utc_timestamp(args.issued_at):
        raise CliUsageError(
            "--issued-at must be an ISO-8601 UTC timestamp of the form "
            f"YYYY-MM-DDTHH:MM:SSZ: {args.issued_at!r}"
        )
    try:
        document = authority.build_authorization(
            authorization_version=args.authorization_version,
            publisher=args.publisher,
            authorized_issuers=_authority_entries_from_args(args),
            issued_at=args.issued_at,
            signing_kp=_grant_signing_kp(args),
            kid=args.kid,
            previous=previous,
        )
    except ValueError as exc:
        raise CliUsageError(str(exc)) from exc

    if args.previous is None:
        print(
            "warning: --previous not provided; publisher authorization successor "
            "discipline was not checked",
            file=sys.stderr,
        )
    _write_json_file(args.out, document)
    _print_json({"out": str(args.out), "record_sha256": authority.authorization_hash(document)})
    return EXIT_OK


def _cmd_grant_issue(args: argparse.Namespace) -> int:
    for flag, path in (("--seed", args.seed), ("--mldsa-seed", args.mldsa_seed)):
        if path is not None and _same_file_target(path, args.out):
            raise CliUsageError(f"{flag} and --out must be different paths")

    modes = sorted(set(args.mode or [grant.MODE_PUBLISHER_DECLARATION]))
    if args.fixed_date is not None and grant.MODE_FIXED_DATE not in modes:
        # §18.2: a non-null `fixed_date` REQUIRES "fixed-date" in `modes`. Refuse
        # rather than add the mode silently — the operator is signing a trigger,
        # and a tool that widens one on their behalf is signing something else.
        raise CliUsageError(f"--fixed-date requires --mode {grant.MODE_FIXED_DATE}")

    document = grant.build_grant(
        grant_version=args.grant_version,
        publisher=args.publisher,
        scope=_grant_scope_from_args(args),
        permissions=sorted(set(args.permission or [grant.PERMISSION_DELIVER_TO_HOLDER])),
        activation={
            "modes": modes,
            "fixed_date": args.fixed_date,
            "successor_ids": sorted(set(args.successor or [])),
        },
        unprotected_build=not args.no_unprotected_build,
        legal_text_uri=args.legal_text_uri,
        legal_text_sha256=args.legal_text_sha256,
        jurisdiction=args.jurisdiction,
        issued_at=args.issued_at,
        signing_kp=_grant_signing_kp(args),
        kid=args.kid,
    )
    _write_json_file(args.out, document)
    # The hash is the point of the report: it is what goes into the receipt's
    # `license.preservation_pledge.grant_sha256`, and computing it by hand from
    # a canonicalization the operator has to get right is how a grant ends up
    # unbindable to the receipt that was supposed to carry it.
    _print_json({"out": str(args.out), "grant_sha256": grant.grant_hash(document)})
    return EXIT_OK


def _cmd_grant_declare(args: argparse.Namespace) -> int:
    for flag, path in (("--seed", args.seed), ("--mldsa-seed", args.mldsa_seed)):
        if path is not None and _same_file_target(path, args.out):
            raise CliUsageError(f"{flag} and --out must be different paths")

    declaration = grant.build_declaration(
        publisher=args.publisher,
        scope=_grant_scope_from_args(args),
        declared_at=args.declared_at,
        signing_kp=_grant_signing_kp(args),
        kid=args.kid,
    )
    _write_json_file(args.out, declaration)
    _print_json({"out": str(args.out), "declaration_sha256": grant.declaration_hash(declaration)})
    return EXIT_OK


def _receipt_payload(path: Path) -> dict[str, Any]:
    envelope = _read_json(path)
    if not isinstance(envelope, dict):
        raise CliUsageError(f"{path} must contain a JSON object")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise CliUsageError(f"{path} is missing object member 'payload'")
    return payload


def _cmd_grant_challenge(args: argparse.Namespace) -> int:
    """The custodian's step 3 (Appendix A): a FRESH nonce and its own audience.

    The nonce is generated here and never taken from a flag: §18.7 requires it
    be freshly generated by the custodian per challenge, and a nonce a caller
    can choose is a nonce a caller can replay.
    """
    payload = _receipt_payload(args.receipt)
    receipt_id = payload.get("receipt_id")
    if not isinstance(receipt_id, str):
        raise CliUsageError(f"{args.receipt} payload is missing string 'receipt_id'")
    nonce = os.urandom(32)
    challenge = {
        "receipt_id": receipt_id,
        "audience": args.audience,
        "nonce": keys.b64u(nonce),
    }
    _write_json_file(args.out, challenge)
    _print_json({"out": str(args.out), **challenge})
    return EXIT_OK


def _read_challenge(path: Path) -> tuple[str, str, bytes]:
    challenge = _read_json(path)
    if not isinstance(challenge, dict):
        raise CliUsageError(f"{path} must contain a JSON object")
    receipt_id = challenge.get("receipt_id")
    audience = challenge.get("audience")
    nonce_b64u = challenge.get("nonce")
    if not all(isinstance(value, str) for value in (receipt_id, audience, nonce_b64u)):
        raise CliUsageError(
            f"{path} must be {{'receipt_id': <str>, 'audience': <str>, 'nonce': <b64u>}}"
        )
    try:
        nonce = keys.b64u_decode(str(nonce_b64u))
    except (TypeError, ValueError) as exc:
        raise CliUsageError(f"{path} has a malformed 'nonce': {exc}") from exc
    return str(receipt_id), str(audience), nonce


def _cmd_grant_respond(args: argparse.Namespace) -> int:
    """The holder's step 4: sign §18.7's audience-bound preimage with the
    receipt's own `buyer.pubkey` key. Salt disclosure is NOT accepted as a
    redemption proof anywhere — §18.7 prohibits it normatively, so there is no
    flag here that would let an operator reach for one."""
    if _same_file_target(args.holder_seed, args.out):
        raise CliUsageError("--holder-seed and --out must be different paths")
    receipt_id, audience, nonce = _read_challenge(args.challenge)
    try:
        sig = grant.sign_redemption(receipt_id, audience, nonce, _load_seed_kp(args.holder_seed))
    except ValueError as exc:
        raise CliUsageError(f"{args.challenge} is not a usable challenge: {exc}") from exc
    # Not secret: a redemption response is meant to be handed to the custodian,
    # and it is bound to one receipt, one audience and one nonce.
    _write_json_file(args.out, {"sig": keys.b64u(sig)})
    _print_json({"out": str(args.out), "receipt_id": receipt_id, "audience": audience})
    return EXIT_OK


def _holder_supplied_json(path: Path, flag: str) -> Any:
    """Read a document the HOLDER handed over. A path the operator got wrong is
    still a loud usage error; anything wrong with the CONTENT degrades to
    `None`, because §18.7 forbids a gate that fronts the delivery of content
    from having an error path a holder can tell apart from a refusal."""
    if not path.is_file():
        raise CliUsageError(f"{flag} file not found: {path}")
    try:
        return _read_json(path)
    except CliUsageError:
        return None


def _cmd_grant_verify(args: argparse.Namespace) -> int:
    """The custodian's step 5: verify the holder's response before serving
    bytes.

    EVERY way this can fail produces the SAME observable outcome — the JSON
    `{"redemption": "not_verified"}` and exit 1, the same code a failed receipt
    verification uses, because to a gate they mean the one thing that matters:
    do not deliver. A wrong signature, a response that is not an object, a
    receipt the challenge does not name, a receipt with no `buyer.pubkey` at
    all: §18.7 makes them indistinguishable on purpose, so a holder cannot
    probe the gate to learn which check they failed.

    The one input here that is NOT holder-supplied is `--challenge`: the
    custodian wrote it themselves with `grant challenge`. A malformed one is an
    operator mistake and says nothing about the holder, so it stays a loud
    usage error rather than being disguised as a refusal.
    """
    receipt_id, audience, nonce = _read_challenge(args.challenge)

    envelope = _holder_supplied_json(args.receipt, "--receipt")
    payload = envelope.get("payload") if isinstance(envelope, dict) else None
    buyer = payload.get("buyer") if isinstance(payload, dict) else None
    holder_pubkey = buyer.get("pubkey") if isinstance(buyer, dict) else None

    response = _holder_supplied_json(args.response, "--response")
    sig_b64u = response.get("sig") if isinstance(response, dict) else None
    try:
        sig = keys.b64u_decode(sig_b64u) if isinstance(sig_b64u, str) else b""
    except (TypeError, ValueError):
        sig = b""

    verified = (
        isinstance(payload, dict)
        and payload.get("receipt_id") == receipt_id
        and isinstance(holder_pubkey, str)
        and grant.verify_redemption(receipt_id, audience, nonce, sig, holder_pubkey)
    )
    _print_json({"redemption": "verified" if verified else "not_verified"})
    return EXIT_OK if verified else EXIT_VERIFICATION_FAILED


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


# --- log entry: the six §8 entry types, computed from the documents ----------
#
# One rule holds for all six, and it is the reason this verb exists: the hash
# is ALWAYS recomputed from the document, never read from a member the
# document declares. An entry that repeated a number its own subject supplied
# would commit to nothing.
#
# The second rule is that no document shape is described here. Each is checked
# by asking the module that OWNS it — `validate.validate_payload` for an
# envelope, `manifests.verify_key_manifest` for a manifest,
# `views.build_revocation_view` for a revocation record,
# `grant._valid_declaration_shape` for a declaration,
# `authority._valid_authorization_shape` for an authorization. The one
# document with no single owner-side validator is the transfer record: its
# shape rule is spelled once, in the first half of
# `transfer.verify_record_signature` (`transfer.py:250-263`), and that
# function's second half needs a key manifest a producer holding only a record
# does not have. `_transfer_record_entry` therefore composes the same
# predicates in the same order, and
# `test_log_entry_transfer_shape_agrees_with_the_transfer_module` pins the two
# together so they cannot drift apart in silence.
#
# The `--type` names are taken from `tlog`'s own registry rather than spelled a
# second time: the flag and `tlog.encode_entry` must never be able to disagree
# about which six types exist.
_LOG_ENTRY_TYPES: tuple[str, ...] = (
    tlog._TYPE_RECEIPT,
    tlog._TYPE_KEY_MANIFEST,
    tlog._TYPE_REVOCATION_RECORD,
    tlog._TYPE_TRANSFER_RECORD,
    tlog._TYPE_CESSATION_DECLARATION,
    tlog._TYPE_PUBLISHER_AUTHORIZATION,
)

# Same number `transfer.verify_record_signature` passes to its own decoder for
# `new_holder_pubkey`; named here so the check below reads as the rule it is.
_ED25519_PUB_LEN = 32


def _entry_issuer_hint(document: dict[str, Any], what: str) -> str:
    """The issuer a record-shaped document's signing `kid` names (v0.2 §8).

    A browsing convenience and NOT a trust anchor: `tlog.encode_entry` only
    asks that it be a DNS name, and what binds a document to an issuer is the
    document's own signature, which nothing here verifies.

    The block is read the way the CONSUMER reads it, which `views` now states
    once for every producer: an unknown member is tolerated, and `kid`, `sig`
    and any `sig_ml_dsa_65` are validated. Demanding a closed block here would
    refuse to log a declaration every verifier accepts — a valid document made
    permanently untransparent. Skipping the validation of the members that ARE
    known would do the opposite and log a record with no signature at all.
    What keeps the entry unambiguous is not this field but `record_sha256`,
    which commits to the whole document, the unknown member included.
    """
    try:
        return views._issuer_of_kid(views._signature_block_kid(document.get("signature"), what))
    except views.ViewError as exc:
        raise CliUsageError(str(exc)) from exc


def _receipt_log_entry(document: dict[str, Any], path: Path) -> dict[str, Any]:
    """`{"type","issuer","core_sha256"}` for a schema-valid receipt envelope.

    The payload is validated exactly as `attest issue` validates what it is
    about to sign. An entry naming a payload no verifier would admit commits
    to something nobody can check, which is worse than no entry at all.
    """
    payload = document.get("payload")
    if not isinstance(payload, dict):
        raise CliUsageError(f"{path} is not a receipt envelope: no object member 'payload'")
    if not isinstance(document.get("signatures"), list):
        raise CliUsageError(f"{path} is not a receipt envelope: no array member 'signatures'")
    violations = validate.validate_payload(payload)
    if violations:
        raise CliUsageError(f"{path} payload failed schema validation: " + "; ".join(violations))
    issuer_block = payload.get("issuer")
    issuer = issuer_block.get("id") if isinstance(issuer_block, dict) else None
    if not isinstance(issuer, str):
        raise CliUsageError(f"{path} payload is missing string 'issuer.id'")
    return {
        "type": tlog._TYPE_RECEIPT,
        "issuer": issuer,
        "core_sha256": tlog.receipt_core_hash(document),
    }


def _key_manifest_log_entry(document: dict[str, Any], path: Path) -> dict[str, Any]:
    """`views.key_manifest_log_entry`, for a manifest that verifies against a
    key it lists.

    The self-consistency check is not decoration: `views.build_compromise_claim`
    refuses a claim whose manifest does not self-verify, so an entry logged for
    one is an entry no compromise claim could ever be built around.
    """
    if not manifests.verify_key_manifest(document):
        raise CliUsageError(f"{path} does not verify against its own listed keys")
    return views.key_manifest_log_entry(document)


def _revocation_record_log_entry(document: dict[str, Any], path: Path) -> dict[str, Any]:
    """`{"type","issuer","record_sha256"}` for a §8 four-member revocation record.

    Shape-checked by building a one-record revocation view, which is the same
    producer every consumer of that rail reads: a record this entry names is a
    record `attest revocation-view` would also carry. The hash is taken over
    the view's own materialized copy, never over the caller's object.
    """
    try:
        record = views.build_revocation_view([document])[0]
    except views.ViewError as exc:
        raise CliUsageError(f"{path} is not a revocation record: {exc}") from exc
    return {
        "type": tlog._TYPE_REVOCATION_RECORD,
        "issuer": _entry_issuer_hint(record, "revocation record"),
        "record_sha256": revocation.record_hash(record),
    }


def _transfer_record_log_entry(document: dict[str, Any], path: Path) -> dict[str, Any]:
    """`{"type","issuer","record_sha256"}` for a §17.1 six-member transfer record.

    The shape half of `transfer.verify_record_signature`, in that function's
    own order and out of that function's own predicates. Its other half — the
    signer active in a key manifest, the validity window covering
    `transferred_at` — needs a manifest this producer does not hold, and stays
    the verifier's to apply.
    """
    if set(document) != transfer._TRANSFER_RECORD_MEMBERS:
        raise CliUsageError(
            f"{path} is not a transfer record: v0.2 §17.1 closes it at exactly "
            f"{sorted(transfer._TRANSFER_RECORD_MEMBERS)}"
        )
    for member in ("receipt_id", "new_receipt_id"):
        value = document[member]
        if not isinstance(value, str) or transfer._RECEIPT_ID_RE.fullmatch(value) is None:
            raise CliUsageError(f"{path} transfer record {member!r} must be a ULID: {value!r}")
    if transfer._strict_b64u_decode(document["new_holder_pubkey"], _ED25519_PUB_LEN) is None:
        raise CliUsageError(
            f"{path} transfer record 'new_holder_pubkey' must be canonical base64url of a "
            f"{_ED25519_PUB_LEN}-byte Ed25519 public key"
        )
    if not transfer._valid_utc_timestamp(document["transferred_at"]):
        raise CliUsageError(
            f"{path} transfer record 'transferred_at' must be a zero-padded UTC instant "
            f"spelled YYYY-MM-DDTHH:MM:SSZ: {document['transferred_at']!r}"
        )
    if not transfer._valid_holder_authorization_shape(document["holder_authorization"]):
        raise CliUsageError(
            f"{path} transfer record 'holder_authorization' must be exactly "
            "{'sig': <base64url of a 64-byte Ed25519 signature>}"
        )
    return {
        "type": tlog._TYPE_TRANSFER_RECORD,
        "issuer": _entry_issuer_hint(document, "transfer record"),
        "record_sha256": transfer.record_hash(document),
    }


def _cessation_declaration_log_entry(document: dict[str, Any], path: Path) -> dict[str, Any]:
    """`{"type","issuer","record_sha256"}` for a §18.4 cessation declaration.

    Logging one is RECOMMENDED and never load-bearing: an authenticated
    declaration activates a grant whether or not it was ever logged. The entry
    still has to be exact, because what the log gives it is a date opposable
    to third parties.
    """
    if not grant._valid_declaration_shape(document):
        raise CliUsageError(
            f"{path} is not a valid cessation declaration under v0.2 §18.4: a required "
            "member is missing or extra, or one of them has an invalid value"
        )
    return {
        "type": tlog._TYPE_CESSATION_DECLARATION,
        "issuer": _entry_issuer_hint(document, "cessation declaration"),
        "record_sha256": grant.declaration_hash(document),
    }


def _publisher_authorization_log_entry(document: dict[str, Any], path: Path) -> dict[str, Any]:
    """`{"type","issuer","record_sha256"}` for a §20.2 publisher authorization.

    `issuer` here is the PUBLISHER's domain, and remains the same
    non-authenticated hint as every other type's: currency disputes between two
    authorizations are settled by `authorization_version`, never by the log.
    """
    if not authority._valid_authorization_shape(document):
        raise CliUsageError(
            f"{path} is not a valid publisher authorization under v0.2 §20.2: a required "
            "member is missing or extra, or one of them has an invalid value"
        )
    # §8 defines THIS entry's hint as the document's publisher, not the signer's
    # domain, and the two differ whenever a publisher's authorization is signed
    # under another domain — which `authority.verify_authorization` allows,
    # handling the domain question separately. The signature block is still
    # validated, for the same reason as every other type.
    _entry_issuer_hint(document, "publisher authorization")
    return {
        "type": tlog._TYPE_PUBLISHER_AUTHORIZATION,
        "issuer": cast(str, document["publisher"]),
        "record_sha256": authority.authorization_hash(document),
    }


_LOG_ENTRY_BUILDERS: dict[str, Callable[[dict[str, Any], Path], dict[str, Any]]] = {
    tlog._TYPE_RECEIPT: _receipt_log_entry,
    tlog._TYPE_KEY_MANIFEST: _key_manifest_log_entry,
    tlog._TYPE_REVOCATION_RECORD: _revocation_record_log_entry,
    tlog._TYPE_TRANSFER_RECORD: _transfer_record_log_entry,
    tlog._TYPE_CESSATION_DECLARATION: _cessation_declaration_log_entry,
    tlog._TYPE_PUBLISHER_AUTHORIZATION: _publisher_authorization_log_entry,
}


def _cmd_log_entry(args: argparse.Namespace) -> int:
    """Build one document's transparency-log entry (v0.2 §8).

    Alias checks run before any I/O: `--out` pointing at `--in` is a mistake
    about the arguments, not about the file, and reporting it as a read
    failure would send the operator looking in the wrong place.
    """
    if _same_file_target(args.doc_in, args.out):
        raise CliUsageError("--in and --out must be different paths")

    # A `receipt` entry names an envelope, and an envelope over
    # `MAX_ENVELOPE_BYTES` is one no conforming verifier will parse: bound it
    # by the envelope's own ceiling so the refusal names the real problem here
    # instead of arriving from a verifier three steps later. The other five
    # documents are ordinary Stage-2 JSON inputs.
    max_bytes = (
        validate.MAX_ENVELOPE_BYTES
        if args.type == tlog._TYPE_RECEIPT
        else _MAX_STAGE2_INPUT_BYTES["json"]
    )
    document = _read_strict_json(args.doc_in, max_bytes=max_bytes, input_name="--in")
    if not isinstance(document, dict):
        raise CliUsageError(f"--in {args.doc_in} must contain a JSON object")

    try:
        entry = _LOG_ENTRY_BUILDERS[args.type](document, args.doc_in)
        # The log's own closed schema has the last word, and it gets it BEFORE
        # anything reaches disk: an entry `tlog.encode_entry` refuses is an
        # entry `attest log append` would refuse too, and writing it first
        # would hand the operator a file whose only use is to be rejected.
        tlog.encode_entry(entry)
    except (tlog.TlogError, canon.CanonError, views.ViewError) as exc:
        raise CliUsageError(
            f"--in {args.doc_in} cannot be logged as a {args.type} entry: {exc}"
        ) from exc

    _write_guarded_json(args.out, entry, label="--out", force=args.force)
    # The report IS the entry, plus where it went: an operator can diff it
    # against the file without a second description of the same object.
    _print_json({"out": str(args.out), **entry})
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
    existing_proofs: list[Any] = []
    existing_anchors: dict[str, Any] | None = None
    if "anchors" in evidence:
        raw_anchors = evidence["anchors"]
        if not isinstance(raw_anchors, dict):
            raise CliUsageError(f"{args.evidence}'s 'anchors' member must be a JSON object")
        existing_anchors = raw_anchors
        anchors_checkpoint = existing_anchors.get("checkpoint")
        if not isinstance(anchors_checkpoint, str):
            raise CliUsageError(f"{args.evidence}'s anchors.checkpoint must be a string")
        if anchors_checkpoint != checkpoint_text:
            raise CliUsageError(
                f"{args.evidence}'s anchors.checkpoint does not match its top-level checkpoint"
            )
        raw_proofs = existing_anchors.get("proofs")
        if not isinstance(raw_proofs, list):
            raise CliUsageError(f"{args.evidence}'s anchors.proofs must be a JSON array")
        existing_proofs = raw_proofs

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
    # A replay warning is a structural refusal of the op-chain itself (a cap,
    # a malformed op) and says exactly which one — it is not "this chain
    # commits to something else". Surfacing it here keeps `log anchor`'s
    # message as specific as the verifier's, instead of collapsing every
    # structural refusal into the seed-mismatch text below.
    if v2_warning is not None:
        raise CliUsageError(f"{args.ots_proof}: {v2_warning}")
    v2_matches = (
        v2_accumulator is not None
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


# Names this command always writes into --out-dir, whatever the .ots holds.
# The per-path proof names are derived from the conversion result, so they are
# checked separately once that result exists.
_OTS_CONVERT_FIXED_OUTPUTS = ("pinned-headers.json", "conversion-report.json")


def _reject_ots_outputs_over_inputs(args: argparse.Namespace, filenames: tuple[str, ...]) -> None:
    """Refuse before writing when an output would land on an input.

    `--evidence` is not derivable from anything this command produces (it
    comes from `log prove` against a log that has since moved on) and neither
    is the `.ots`, so silently truncating one is unrecoverable loss. Same
    discipline `log anchor` applies to `--out` against everything it reads.
    """
    inputs = (
        ("--ots", args.ots),
        ("--evidence", args.evidence),
        ("--block-headers", args.block_headers),
    )
    for filename in filenames:
        target = args.out_dir / filename
        for label, path in inputs:
            if _same_file_target(target, path):
                raise CliUsageError(
                    f"--out-dir would write {filename} over {label} {path}; "
                    "choose an --out-dir that does not hold this command's inputs"
                )


def _load_operator_headers(path: Path) -> list[ots.OperatorHeader]:
    raw = _read_json(
        path,
        max_bytes=_MAX_STAGE2_INPUT_BYTES["json"],
        input_name="--block-headers",
    )
    if not isinstance(raw, list):
        raise CliUsageError("--block-headers must contain a JSON array")

    headers: list[ots.OperatorHeader] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise CliUsageError(f"--block-headers[{index}] must be a JSON object")
        height = item.get("height")
        header_hash = item.get("header_hash")
        merkle_root = item.get("merkle_root")
        header_time = item.get("time")
        if not isinstance(height, int) or isinstance(height, bool):
            raise CliUsageError(f"--block-headers[{index}].height must be a non-negative int")
        if not isinstance(header_hash, str):
            raise CliUsageError(f"--block-headers[{index}].header_hash must be a string")
        if not isinstance(merkle_root, str):
            raise CliUsageError(f"--block-headers[{index}].merkle_root must be a string")
        if not isinstance(header_time, int) or isinstance(header_time, bool):
            raise CliUsageError(f"--block-headers[{index}].time must be a positive int")
        headers.append(
            ots.OperatorHeader(
                height=height,
                header_hash=header_hash,
                merkle_root=merkle_root,
                time=header_time,
            )
        )
    return headers


def _preexisting_proof_files(out_dir: Path, written: tuple[str, ...]) -> list[str]:
    """`proof-*.json` already in --out-dir that this run does not write.

    The conversion report is the only inventory of a run, so it has to be true
    about the directory it sits in: a proof left by an earlier conversion
    carries exactly this name shape, `log anchor --ots-proof` is the next
    thing an operator points at it, and nothing else in this output would
    ever mention it. An observation, not a refusal -- every output here is
    derivable from the inputs, so the overwrite discipline stays as it is
    (`_add_force_flag`). A file this run overwrites is this run's own output
    and is not listed. Sorted, because `_json_text` promises a deterministic
    file for the same inputs and directory order is not.
    """
    try:
        found = sorted(entry.name for entry in out_dir.glob("proof-*.json"))
    except OSError:
        # A directory that cannot be listed is not evidence of leftovers; the
        # writes below will fail on their own and say so.
        return []
    return [name for name in found if name not in written]


def _conversion_report_json(
    report: tuple[ots.OtsConversionReportEntry, ...],
    proof_filenames: dict[int, str],
    preexisting_proofs: list[str],
) -> dict[str, Any]:
    paths: list[dict[str, Any]] = []
    converted_count = 0
    for entry in report:
        if entry.converted:
            converted_count += 1
        paths.append(
            {
                "path_index": entry.path_index,
                "attestation_kind": entry.attestation_kind,
                "attestation_tag": entry.attestation_tag,
                "height": entry.height,
                "converted": entry.converted,
                "reason": entry.reason,
                "proof_file": proof_filenames.get(entry.path_index),
            }
        )
    return {
        "converted": converted_count,
        "skipped": len(report) - converted_count,
        # Named for what it asserts: these files were NOT produced now. An
        # operator reading the report must not have to guess whether a proof
        # in this directory belongs to the run the report describes.
        "proof_files_not_written_by_this_run": preexisting_proofs,
        "paths": paths,
    }


def _write_ots_conversion_outputs(
    args: argparse.Namespace, result: ots.ConversionResult
) -> tuple[Path, Path, dict[int, str], list[str]]:
    out_dir: Path = args.out_dir
    proof_filenames: dict[int, str] = {}
    for proof in result.proofs:
        # Named by walk position AND height: two paths anchored in the same
        # block are two claims, and naming by height alone would let the
        # second overwrite the first (C-41).
        proof_filenames[proof.path_index] = f"proof-{proof.path_index}-{proof.height}.json"
    _reject_ots_outputs_over_inputs(args, tuple(proof_filenames.values()))
    # Read the directory BEFORE the first write: afterwards this run's own
    # files are indistinguishable from leftovers by name alone.
    preexisting_proofs = _preexisting_proof_files(out_dir, tuple(proof_filenames.values()))
    for proof in result.proofs:
        _write_json_file(out_dir / proof_filenames[proof.path_index], proof.proof)
    pinned_path = out_dir / "pinned-headers.json"
    _write_json_file(pinned_path, {"pinned_headers": result.pinned_headers})
    report_path = out_dir / "conversion-report.json"
    _write_json_file(
        report_path, _conversion_report_json(result.report, proof_filenames, preexisting_proofs)
    )
    return pinned_path, report_path, proof_filenames, preexisting_proofs


def _cmd_log_ots_convert(args: argparse.Namespace) -> int:
    _reject_ots_outputs_over_inputs(args, _OTS_CONVERT_FIXED_OUTPUTS)
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
        checkpoint = tlog.parse_checkpoint(checkpoint_text)
    except tlog.TlogError as exc:
        raise CliUsageError(f"{args.evidence}'s checkpoint is malformed: {exc}") from exc

    ots_bytes = _read_bounded_bytes(
        args.ots,
        max_bytes=_MAX_STAGE2_INPUT_BYTES["ots"],
        input_name="--ots",
    )
    try:
        parsed = ots.parse_ots(ots_bytes)
    except ots.OtsError as exc:
        raise CliUsageError(f"{args.ots}: {exc}") from exc

    headers = _load_operator_headers(args.block_headers)
    expected_seed = hashlib.sha256(checkpoint.signed_note_bytes).digest()
    try:
        result = ots.convert_ots(parsed, expected_seed, headers)
    except ots.OtsConversionError as exc:
        report_path = args.out_dir / "conversion-report.json"
        # This run emitted no proof, so every `proof-*.json` in the directory
        # is someone else's -- the case where mistaking one for this run's
        # output is easiest.
        _write_json_file(
            report_path,
            _conversion_report_json(exc.report, {}, _preexisting_proof_files(args.out_dir, ())),
        )
        raise CliUsageError(str(exc)) from exc
    except ots.OtsError as exc:
        raise CliUsageError(str(exc)) from exc

    pinned_path, report_path, _proof_filenames, preexisting_proofs = _write_ots_conversion_outputs(
        args, result
    )
    skipped = [entry for entry in result.report if not entry.converted]
    _print_json(
        {
            "out_dir": str(args.out_dir),
            "proofs": len(result.proofs),
            # A dropped Bitcoin path is a lost anchoring claim, and
            # `anchored_before` is the MINIMUM over verified proofs: the
            # operator has to see it on their own channel, not only in a file
            # they may never open.
            "skipped": len(skipped),
            "skipped_bitcoin_heights": [
                entry.height
                for entry in skipped
                if entry.attestation_kind == "bitcoin" and entry.height is not None
            ],
            # Count only: the names are in the report, and an --out-dir
            # holding dozens of old proofs must not flood a machine-readable
            # stdout. One integer is enough to send the operator to the report.
            "preexisting_proofs": len(preexisting_proofs),
            "pinned_headers": str(pinned_path),
            "report": str(report_path),
        }
    )
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
        "grant": result.grant,
        "grant_trust": result.grant_trust,
        "publisher_authority": result.publisher_authority,
        "publisher_authority_trust": result.publisher_authority_trust,
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


def _read_rail_array(path: Path | None, flag: str) -> list[Any] | None:
    """Read one of the two array-shaped evidence rails, or nothing.

    No content validation happens here by design: a malformed claim inside a
    well-formed array is the VERIFIER's to refuse, claim by claim, and
    pre-filtering here would hide from the operator the very refusal the
    verifier exists to make. Only the container is this function's business —
    and an oversized array is forwarded whole, so the verifier reports its own
    ceiling instead of being silently trimmed.
    """
    if path is None:
        return None
    value = _read_strict_json(path, max_bytes=_MAX_STAGE2_INPUT_BYTES["json"], input_name=flag)
    if not isinstance(value, list):
        raise CliUsageError(
            f"{flag} file {path} must contain a JSON array of claims; a file containing "
            "`null` is not an opt-out — omit the flag instead"
        )
    return value


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

    grant_view = (
        _read_json(
            args.grant_view,
            max_bytes=_MAX_STAGE2_INPUT_BYTES["json"],
            input_name="--grant-view",
        )
        if args.grant_view is not None
        else None
    )
    # Security, and the same reason `--revocations` refuses a lone record: a
    # bare grant DOCUMENT passed here would be read member by member and
    # resolve to `grant: "not_checked"`, reporting "no grant evidence" to an
    # operator who supplied some. Do not auto-wrap — make them say `{"grant":
    # ...}`, which is also what the file has to look like for the other three
    # members to have anywhere to go.
    if grant_view is not None and not isinstance(grant_view, dict):
        raise CliUsageError(
            f"--grant-view file {args.grant_view} must contain a JSON object; "
            'wrap a lone grant document as {"grant": <document>}'
        )
    authority_view = (
        _read_json(
            args.authority_view,
            max_bytes=_MAX_STAGE2_INPUT_BYTES["json"],
            input_name="--authority-view",
        )
        if args.authority_view is not None
        else None
    )
    # The guard is on the FLAG, not on the parsed value: a file whose content is
    # `null` parses to None, and testing the parsed value would read a channel
    # the caller DID supply as a channel they never supplied — opting them out
    # of section 20.4 in silence. `--revocations`, `--transparency` and
    # `--grant-view` still test the parsed value; their
    # rails are published, so they change with their own round, not this one.
    if args.authority_view is not None and not isinstance(authority_view, dict):
        raise CliUsageError(
            f"--authority-view file {args.authority_view} must contain a JSON object; "
            'wrap a lone publisher authorization document as {"authorizations": [<document>]}'
        )

    # The three caller-side rails of v0.2 §17/§19.2. They are read strictly
    # (`canon.loads_strict`, D11) because they are new surface: a duplicate
    # member in a claim would otherwise collapse onto whichever copy the
    # parser kept, and the claim that authenticates would not be the claim the
    # operator read.
    #
    # The guard is on the FLAG, not on the parsed value — the same rule
    # `--authority-view` above states and for the same reason: a file
    # containing `null` parses to None, and testing the parsed value would
    # read a channel the caller DID supply as one they never supplied,
    # silently opting them out of the check they asked for.
    if args.revocation_evidence is not None and args.revocations is None:
        # Checked before the file is touched: evidence proves that one of the
        # records in --revocations was logged and anchored in time, so with no
        # records supplied there is nothing for it to be evidence OF — whether
        # or not that file happens to exist and parse. Reading first would
        # report "file not found" for a mistake that is not about the file.
        raise CliUsageError(
            "--revocation-evidence needs --revocations: it proves that one of those "
            "records was logged and anchored before the refund-window deadline"
        )

    transfer_view = _read_rail_array(args.transfer_view, "--transfer-view")
    compromise_view = _read_rail_array(args.compromise_view, "--compromise-view")
    revocation_evidence = None
    if args.revocation_evidence is not None:
        revocation_evidence = _read_strict_json(
            args.revocation_evidence,
            max_bytes=_MAX_STAGE2_INPUT_BYTES["json"],
            input_name="--revocation-evidence",
        )
        if not isinstance(revocation_evidence, dict):
            raise CliUsageError(
                f"--revocation-evidence file {args.revocation_evidence} must contain ONE "
                "JSON object: the log evidence bundle for the refund-window record in "
                "--revocations; a file containing `null` is not an opt-out — omit the "
                "flag instead"
            )
        if args.log_keys is None or args.anchor_policy is None:
            print(
                "warning: --revocation-evidence is only evaluated by a Stage-2-capable "
                "verifier; pass --log-keys and --anchor-policy for it to be read",
                file=sys.stderr,
            )

    result = verify.verify(
        envelope_bytes,
        trust_store,
        revocation_view,
        disclosure,
        transparency=transparency_evidence,
        log_keys=log_keys,
        anchor_policy=anchor_policy,
        revocation_evidence=revocation_evidence,
        transfer_view=transfer_view,
        compromise_view=compromise_view,
        witness_policy=witness_policy,
        grant_view=grant_view,
        authority_view=authority_view,
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

    p = manifest_sub.add_parser(
        "compromise-view",
        help="Assemble compromise-view.json and report what each claim can do (v0.2 §19.3)",
        description=(
            "Builds the compromise view a verifier reads out of {--manifest, --evidence} pairs, "
            "each one a key manifest that marks a key compromised plus the log evidence proving "
            "that manifest was logged. Pairs are matched BY POSITION. The output file's shape "
            "never varies; what varies is the report, which says for every claim and every "
            "compromised kid whether the claim establishes the status floor, whether its signer "
            "could date a §19.3 item 3b cutoff, whether it carries anchor material at all, and "
            "— only with both --log-keys and --anchor-policy — whether a cutoff is actually "
            "established. Those four are independent on purpose. All of it is relative to "
            "--trusted-manifest: the same declaration is ignored by a verifier that does not "
            "vouch for its signer and floor-establishing for one that does. No network I/O."
        ),
    )
    p.add_argument(
        "--trusted-manifest",
        required=True,
        type=Path,
        help="the head key manifest the report classifies against",
    )
    p.add_argument(
        "--chain",
        action="append",
        default=[],
        type=Path,
        help="repeatable; an earlier manifest in the issuer's published chain",
    )
    p.add_argument(
        "--manifest",
        required=True,
        action="append",
        default=[],
        type=Path,
        help="repeatable; a key manifest declaring a key compromised",
    )
    p.add_argument(
        "--evidence",
        required=True,
        action="append",
        default=[],
        type=Path,
        help="repeatable; the `log prove`/`log anchor` evidence for the manifest at this position",
    )
    p.add_argument(
        "--append",
        type=Path,
        default=None,
        help="an existing compromise view to extend; its claims are re-validated too",
    )
    p.add_argument(
        "--log-keys",
        type=Path,
        default=None,
        help="pinned log keys; required with --anchor-policy to evaluate a cutoff",
    )
    p.add_argument(
        "--anchor-policy",
        type=Path,
        default=None,
        help="pinned block headers; required with --log-keys to evaluate a cutoff",
    )
    p.add_argument("--out", required=True, type=Path, help="output compromise view JSON path")
    _add_force_flag(p)
    p.set_defaults(func=_cmd_manifest_compromise_view)

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

    p = sub.add_parser(
        "revoke",
        help="Sign a revocation record for a refund_window or policy receipt (v0.1 §12)",
    )
    p.add_argument("--receipt", required=True, type=Path, help="receipt envelope JSON to revoke")
    p.add_argument("--manifest", required=True, type=Path, help="issuer key manifest listing --kid")
    p.add_argument(
        "--revoked-at",
        required=True,
        help="signed UTC instant, spelled exactly YYYY-MM-DDTHH:MM:SSZ",
    )
    p.add_argument("--seed", required=True, type=Path, help="issuer signing key seed")
    p.add_argument("--kid", required=True, help="key id to sign with; must be active in --manifest")
    p.add_argument(
        "--mldsa-seed",
        type=Path,
        default=None,
        help="ML-DSA-65 leg of the signing key; required exactly for a hybrid key entry",
    )
    p.add_argument("--out", required=True, type=Path, help="output revocation record JSON path")
    _add_force_flag(p)
    p.set_defaults(func=_cmd_revoke)

    p = sub.add_parser(
        "revocation-view",
        help="Assemble the revocation-view.json array a verifier reads (v0.2 §8/§12)",
        description=(
            "Wraps signed revocation records into the JSON ARRAY that `attest verify "
            "--revocations` and both shipped verifier cores read. Carries the two statuses "
            "§12 registers, `revoked` and `transferred`: the second is what `attest transfer "
            "record --revocation-out` emits, and a view that dropped it would hide a transfer. "
            "With --manifest, every record must additionally verify against that key manifest "
            "— signer active, validity window covering the record's own signed revoked_at. "
            "Without it the records are shape-checked only, which is the right default for a "
            "holder assembling records they cannot yet authenticate."
        ),
    )
    p.add_argument(
        "--record",
        required=True,
        action="append",
        default=[],
        type=Path,
        help="repeatable; one signed revocation record JSON file",
    )
    p.add_argument(
        "--append",
        type=Path,
        default=None,
        help="an existing revocation view to extend; its records are re-validated too",
    )
    p.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="issuer key manifest every record must verify against",
    )
    p.add_argument("--out", required=True, type=Path, help="output revocation view JSON path")
    _add_force_flag(p)
    p.set_defaults(func=_cmd_revocation_view)

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

    p = transfer_sub.add_parser(
        "view",
        help="Assemble the transfer-view.json array a verifier reads (v0.2 §17.1)",
        description=(
            "Builds the transfer view out of {--record, --evidence} pairs, matched BY POSITION: "
            "each signed transfer record plus the log evidence proving that record was logged. "
            "No anchor is required — a transfer claim carries weight at `logged` standing, so "
            "demanding one here would refuse claims the verifier accepts. No network I/O."
        ),
    )
    p.add_argument(
        "--record",
        required=True,
        action="append",
        default=[],
        type=Path,
        help="repeatable; one signed transfer record JSON file",
    )
    p.add_argument(
        "--evidence",
        required=True,
        action="append",
        default=[],
        type=Path,
        help="repeatable; the `log prove` evidence for the record at this position",
    )
    p.add_argument(
        "--append",
        type=Path,
        default=None,
        help="an existing transfer view to extend; its claims are re-validated too",
    )
    p.add_argument("--out", required=True, type=Path, help="output transfer view JSON path")
    _add_force_flag(p)
    p.set_defaults(func=_cmd_transfer_view)

    p_grant = sub.add_parser("grant", help="Preservation-pledge operations (v0.2 §18)")
    grant_sub = p_grant.add_subparsers(dest="grant_command", required=True)

    p = grant_sub.add_parser("issue", help="Sign a sunset grant document (rights holder)")
    p.add_argument(
        "--grant-version", required=True, type=int, help="monotonic, per (publisher, scope)"
    )
    p.add_argument("--publisher", required=True, help="rights holder's lowercase DNS domain")
    p.add_argument("--artifact-series", default=None, help="series this grant covers, or omit")
    p.add_argument(
        "--artifact", action="append", default=None, help="artifact SHA-256 (repeatable)"
    )
    p.add_argument(
        "--permission",
        action="append",
        default=None,
        help=f"repeatable; defaults to {grant.PERMISSION_DELIVER_TO_HOLDER}",
    )
    p.add_argument(
        "--mode",
        action="append",
        default=None,
        help=f"activation mode (repeatable); defaults to {grant.MODE_PUBLISHER_DECLARATION}",
    )
    p.add_argument("--fixed-date", default=None, help="ISO-8601 UTC backstop date, or omit")
    p.add_argument(
        "--successor", action="append", default=None, help="successor domain (repeatable)"
    )
    p.add_argument(
        "--no-unprotected-build",
        action="store_true",
        help="do NOT commit to releasing a build free of technological protection",
    )
    p.add_argument("--legal-text-uri", required=True, help="the prose grant")
    p.add_argument("--legal-text-sha256", required=True, help="hash of the prose grant")
    p.add_argument("--jurisdiction", required=True)
    p.add_argument("--issued-at", required=True, help="ISO-8601 UTC signed time")
    p.add_argument("--seed", required=True, type=Path, help="publisher signing key seed")
    p.add_argument("--kid", required=True)
    p.add_argument(
        "--mldsa-seed",
        type=Path,
        default=None,
        help="ML-DSA-65 key file (from `keygen --hybrid`); makes the grant signature hybrid",
    )
    p.add_argument("--out", required=True, type=Path, help="output signed grant JSON path")
    p.set_defaults(func=_cmd_grant_issue)

    p = grant_sub.add_parser(
        "declare", help="Sign a cessation declaration (publisher or designated successor)"
    )
    p.add_argument("--publisher", required=True, help="the grant's publisher, not the signer")
    p.add_argument("--artifact-series", default=None)
    p.add_argument("--artifact", action="append", default=None)
    p.add_argument("--declared-at", required=True, help="ISO-8601 UTC signed time")
    p.add_argument("--seed", required=True, type=Path, help="declaring domain's signing key seed")
    p.add_argument("--kid", required=True)
    p.add_argument("--mldsa-seed", type=Path, default=None)
    p.add_argument("--out", required=True, type=Path, help="output signed declaration JSON path")
    p.set_defaults(func=_cmd_grant_declare)

    p = grant_sub.add_parser(
        "challenge", help="Issue a fresh redemption challenge (custodian, §18.7)"
    )
    p.add_argument("--receipt", required=True, type=Path, help="the holder's receipt envelope")
    p.add_argument("--audience", required=True, help="the custodian's own lowercase DNS domain")
    p.add_argument("--out", required=True, type=Path, help="output challenge JSON path")
    p.set_defaults(func=_cmd_grant_challenge)

    p = grant_sub.add_parser("respond", help="Sign a redemption challenge (holder, §18.7)")
    p.add_argument("--challenge", required=True, type=Path, help="JSON from `grant challenge`")
    p.add_argument(
        "--holder-seed", required=True, type=Path, help="the receipt's own buyer.pubkey seed"
    )
    p.add_argument("--out", required=True, type=Path, help="output {'sig': <b64u>} JSON path")
    p.set_defaults(func=_cmd_grant_respond)

    p = grant_sub.add_parser(
        "verify", help="Verify a holder's redemption response (custodian, §18.7)"
    )
    p.add_argument("--receipt", required=True, type=Path)
    p.add_argument("--challenge", required=True, type=Path, help="JSON from `grant challenge`")
    p.add_argument("--response", required=True, type=Path, help="JSON from `grant respond`")
    p.set_defaults(func=_cmd_grant_verify)

    p_authority = sub.add_parser(
        "authority", help="Publisher authorization manifest operations (v0.2 §20)"
    )
    authority_sub = p_authority.add_subparsers(dest="authority_command", required=True)

    p = authority_sub.add_parser("issue", help="Sign a publisher authorization manifest")
    p.add_argument(
        "--authorization-version",
        required=True,
        type=_manifest_version_arg,
        help="monotonic per publisher authorization manifest version",
    )
    p.add_argument("--publisher", required=True, help="publisher's lowercase DNS domain")
    p.add_argument(
        "--issuer",
        action="append",
        default=None,
        help="authorized issuer id (repeatable); uses the shared entry flags below",
    )
    p.add_argument(
        "--issuers-file",
        type=Path,
        default=None,
        help="JSON array already shaped as authorized_issuers",
    )
    p.add_argument("--valid-from", default=None, help="entry valid_from; required with --issuer")
    p.add_argument("--valid-to", default=None, help="entry valid_to, or omit for null")
    p.add_argument(
        "--permission",
        action="append",
        default=None,
        help=f"repeatable; defaults to {authority.PERMISSION_ISSUE}",
    )
    p.add_argument("--series", default=None, help="scope artifact_series, or omit for all series")
    p.add_argument("--artifact", action="append", default=None, help="scope artifact SHA-256")
    p.add_argument("--issued-at", required=True, help="ISO-8601 UTC signed time")
    p.add_argument(
        "--previous",
        type=Path,
        default=None,
        help="predecessor publisher authorization manifest for successor-discipline checking",
    )
    p.add_argument("--seed", required=True, type=Path, help="publisher signing key seed")
    p.add_argument("--kid", required=True)
    p.add_argument(
        "--mldsa-seed",
        type=Path,
        default=None,
        help="ML-DSA-65 key file (from `keygen --hybrid`); makes the signature hybrid",
    )
    p.add_argument("--out", required=True, type=Path, help="output signed authorization JSON path")
    p.set_defaults(func=_cmd_authority_issue)

    p_log = sub.add_parser(
        "log", help="Transparency-log operator/holder commands (offline-signer split)"
    )
    log_sub = p_log.add_subparsers(dest="log_command", required=True)

    p = log_sub.add_parser("init", help="Create an empty transparency log directory")
    p.add_argument("--dir", required=True, type=Path)
    p.add_argument("--origin", required=True, help="C2SP checkpoint origin, printable ASCII")
    p.set_defaults(func=_cmd_log_init)

    p = log_sub.add_parser(
        "entry",
        help="Build the v0.2 §8 transparency-log entry for one signed document",
        description=(
            "Computes the log entry a signed document produces, ALWAYS by rehashing the "
            "document itself — no hash is ever read from a member the document declares. The "
            "document is first validated against the shape its own module owns (schema for an "
            "envelope, self-consistency for a key manifest, the closed member set for the four "
            "record-shaped types), and the resulting entry is validated against the log's own "
            "closed entry schema BEFORE anything is written, so an entry this command emits is "
            "one `attest log append` accepts. `issuer` is a non-authenticated browsing hint: "
            "for a receipt it is the payload's own issuer id, for the other five the domain of "
            "the signing kid. Nothing here verifies a signature, and nothing here touches the "
            "network."
        ),
    )
    p.add_argument(
        "--type",
        required=True,
        choices=list(_LOG_ENTRY_TYPES),
        help="which of the six §8 entry types this document produces",
    )
    p.add_argument(
        "--in", dest="doc_in", required=True, type=Path, help="the signed document to log"
    )
    p.add_argument("--out", required=True, type=Path, help="output entry JSON path")
    _add_force_flag(p)
    p.set_defaults(func=_cmd_log_entry)

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
            "For a detached .ots over this evidence's signed checkpoint that you already hold, "
            "`attest log ots-convert` turns each convertible Bitcoin path for which you supplied "
            "a matching block header into one --ots-proof JSON file. Skipped paths are named in "
            "its conversion report, and it performs no network I/O either. "
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
        help=(
            "JSON object: ops/header_merkle_root/header_hash/header_time "
            "(pass one converted Bitcoin-path file emitted by `attest log ots-convert`)"
        ),
    )
    p.add_argument(
        "--rfc3161-token",
        type=Path,
        default=None,
        help="raw RFC 3161 TimeStampToken bytes (opaque, never parsed)",
    )
    p.add_argument("--out", required=True, type=Path)
    p.set_defaults(func=_cmd_log_anchor)

    p = log_sub.add_parser(
        "ots-convert",
        help="Convert a detached .ots timestamp into log anchor proof files",
        description=(
            "Convert an already-upgraded detached OpenTimestamps proof into the JSON proof "
            "shape accepted by `attest log anchor`, and emit matching pinned header entries. "
            "This command performs no network I/O: obtain block headers from your own node. "
            "Pending timestamps need `ots upgrade` first. A legacy ripemd160 path is not "
            "skipped: it is refused by op name while the file is read, before any path is "
            "examined, so a .ots carrying one converts nothing at all -- including a modern "
            "Bitcoin path sitting beside it."
        ),
    )
    p.add_argument("--ots", required=True, type=Path, help="detached .ots proof file")
    p.add_argument("--evidence", required=True, type=Path, help="evidence JSON from `log prove`")
    p.add_argument(
        "--block-headers",
        required=True,
        type=Path,
        help="JSON array of {height, header_hash, merkle_root, time}",
    )
    p.add_argument("--out-dir", required=True, type=Path)
    p.set_defaults(func=_cmd_log_ots_convert)

    p = sub.add_parser("verify", help="Verify a receipt envelope")
    p.add_argument("envelope", type=Path)
    p.add_argument("--trust-dir", required=True, type=Path, help="directory of key manifest files")
    p.add_argument("--revocations", type=Path, default=None, help="JSON file: revocation records")
    p.add_argument(
        "--transfer-view",
        type=Path,
        default=None,
        help=(
            "JSON file: array of v0.2 §17 transfer claims [{record, evidence}], supplied by "
            "the party running the verifier — never taken from the presenter's bundle"
        ),
    )
    p.add_argument(
        "--compromise-view",
        type=Path,
        default=None,
        help=(
            "JSON file: array of v0.2 §19.2 compromise claims [{manifest, evidence}]. "
            "Without --log-keys and --anchor-policy a compromise view can only RESTRICT "
            "the verdict: no cutoff can be established, so no receipt can be rescued"
        ),
    )
    p.add_argument(
        "--revocation-evidence",
        type=Path,
        default=None,
        help=(
            "JSON file: ONE log evidence bundle {entry, leaf_index, tree_size, "
            "inclusion_proof, checkpoint[, anchors]} for a refund-window record in "
            "--revocations. Without it, a Stage-2-capable verifier ignores such a record"
        ),
    )
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
    p.add_argument(
        "--grant-view",
        type=Path,
        default=None,
        help="JSON Stage 4 evidence object {grant[,later_grants][,declarations][,anchor]}; "
        "supplying it at all opts into §18.4's grant evaluation",
    )
    p.add_argument(
        "--authority-view",
        type=Path,
        default=None,
        help="JSON publisher authority evidence object "
        "{authorizations[,current_authorization_version]}; supplying it opts into §20.4",
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
