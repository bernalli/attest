"""Write-ahead ledger for the ablation bench: hold a tree, mutate it, put it back.

A mutation bench rewrites a production file and then runs a suite against it.
Between the rewrite and the moment the file is put back, three things can go
wrong, and this module is built so that none of them loses the original bytes:

* The process dies to a signal that runs no Python code at all: SIGKILL,
  including the kernel's out-of-memory killer, skips `atexit` and every signal
  handler. So the record of a mutation -- the original bytes and the hashes the
  file has before and after -- is written and flushed to disk BEFORE the target
  is touched, and a killed run leaves a journal that `restore_journal()` replays
  from another process.
* A second process tries to use the same tree. The journal directory is created
  with an exclusive `mkdir`, which is the lock. A process that loses that race
  refuses without registering any exit or signal handler and without touching
  the directory, so it can neither restore nor delete what the holder wrote.
* The file is found in a state that neither side wrote. A record is replayed
  only if the target hashes to exactly its mutated or its original bytes;
  anything else is refused, and the record stays for a person to look at.

The journal lives at `<tree>/.ablation-in-flight/`. It is deliberately not
ignored by git: while it exists, `git status` reports the tree as dirty, which
is the sentinel that stops anything else from measuring a tree that is being
mutated.

Journal directory layout:

* `owner.json`: `{pid, started_utc, tree, head_sha, argv}` of the process that
  created the directory;
* `NN-<slug>.json`: `{rel_path, sha_before, sha_after, size_before, size_after,
  applied_utc}` for one mutation;
* `NN-<slug>.orig`: the original bytes of the same file;
* `NN-<slug>.tmp` and `NN-<slug>.restore.tmp`: staging files. One holds the
  bytes an apply or a restore is about to put in place of the target until it
  is exchanged with the target, and the target's previous bytes from then until
  it is removed right after; it outlives that sequence only when a process died
  or failed inside it.
* `00-exchange-probe-a.tmp` and `00-exchange-probe-b.tmp`: the two files a
  holder exchanges once while it acquires the journal, before any record, and
  removes again.

`NN` is a two-digit counter, progressive within one holder's run and starting
at `01`; `<slug>` is the tree-relative path with `/` replaced by `__`.

Every write to a journal file is followed by `fsync`. A target is never
rewritten where it stands, and never created: its new bytes go to a staging
file in the journal, which is flushed, given the target's permission bits and
exchanged with the target in one `renameat2(RENAME_EXCHANGE)` call; the staging
file, which then holds the previous bytes, is removed, and the directories of
both are flushed. A process killed at any point leaves the target holding its
previous bytes or its new ones, never a mix, and a staging file left behind is
never the only copy of anything, because the record that names the original
bytes is written before it. An exchange puts nothing in place of a target that
is absent, so a target that vanished while it was being replaced is refused by
name instead of being created.

The exchange is atomic, and never a copy, because the journal sits inside the
tree, on the filesystem of the targets it replaces: a target on another
filesystem makes the exchange fail, and a target with more than one hard link
keeps its other links on the previous bytes. Not every filesystem implements
the exchange, so a holder tries it on two files of its own journal while
acquiring, and refuses with `ExchangeUnavailable` before any record is written
or any target is touched when it is not there. That probe sees the filesystem
of the journal, not of every target: when the exchange with a target is refused
all the same (`EINVAL`, `ENOSYS`, or `EXDEV` for a target on another
filesystem), the refusal is `ExchangeUnavailable` naming that target, which is
verified to be as it was. An apply then removes its staging file and its
record, since the target is still original; a restore removes only its staging
file and keeps the record, the only way back to the original bytes.

Bytecode caches under the tree are removed on every apply and on every
restore: a cache that outlives the source it was compiled from would make a
fresh interpreter import bytes that are no longer on disk.
"""

from __future__ import annotations

import atexit
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import FrameType, TracebackType
from typing import Any, Literal

#: Name of the journal directory, created directly under the tree it guards.
JOURNAL_DIRNAME = ".ablation-in-flight"
#: Name of the holder's identity file inside the journal directory.
OWNER_FILENAME = "owner.json"

#: Exit status a command-line caller reports when the journal is held.
EXIT_JOURNAL_BUSY = 8
#: Exit status a command-line caller reports when a record cannot be replayed.
EXIT_UNKNOWN_STATE = 9
#: Exit status a command-line caller reports when a filesystem of the tree cannot exchange files.
EXIT_EXCHANGE_UNAVAILABLE = 12

#: The fields of a record's `.json` file, and no others.
LEDGER_FIELDS = ("rel_path", "sha_before", "sha_after", "size_before", "size_after", "applied_utc")

_RECORD_FILE = re.compile(r"^(?P<nn>[0-9]{2,})-(?P<slug>.+)\.(?P<part>json|orig)$")
#: Suffix of the staging file that holds a mutation until it is exchanged with its target.
_APPLY_STAGING_SUFFIX = ".tmp"
#: Suffix of the staging file that holds the original bytes until they are exchanged back.
_RESTORE_STAGING_SUFFIX = ".restore.tmp"
_STAGING_FILE = re.compile(r"^(?P<nn>[0-9]{2,})-(?P<name>.+)\.tmp$")
#: The two files the acquisition exchanges, named in the staging form so a replay removes them.
_EXCHANGE_PROBE_NAMES = ("00-exchange-probe-a.tmp", "00-exchange-probe-b.tmp")
#: What the two probe files hold before the exchange; each must hold the other's bytes after it.
_EXCHANGE_PROBE_BYTES = (b"exchange probe: first\n", b"exchange probe: second\n")
#: `renameat2` arguments: paths relative to the working directory, and the flag that swaps them.
_AT_FDCWD = -100
_RENAME_EXCHANGE = 2
#: The errors with which the exchange with a target says the filesystem cannot exchange it.
_TARGET_EXCHANGE_UNAVAILABLE = {
    errno.EINVAL: "EINVAL",
    errno.ENOSYS: "ENOSYS",
    errno.EXDEV: "EXDEV",
}
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_CACHE_DIRNAME = "__pycache__"
_CACHE_WALK_EXCLUDED = frozenset({".venv", "node_modules"})
_HANDLED_SIGNALS = (signal.SIGINT, signal.SIGTERM)

#: What a restore found and did: it wrote the original bytes back, found them
#: already there, or was asked again for a record it had already put back.
RestoreOutcome = Literal["restored", "already_original", "already_restored"]


class JournalError(RuntimeError):
    """Base of the refusals raised by this module.

    `exit_code` is the process exit status a command-line caller reports for the
    refusal, or `None` when the refusal is an outcome the caller records rather
    than a reason to stop.
    """

    exit_code: int | None = None


class JournalBusy(JournalError):
    """The journal is held: by a live process, or left behind by one that died."""

    exit_code = EXIT_JOURNAL_BUSY


class UnknownState(JournalError):
    """A record cannot be replayed safely; it is kept and its file is left alone."""

    exit_code = EXIT_UNKNOWN_STATE


class ExchangeUnavailable(JournalError):
    """A filesystem of the tree cannot exchange two files in one step.

    Raised while a holder acquires the journal, after `owner.json` and before any
    record, when exchanging the two probe files finds the C library without
    `renameat2`, gets `ENOSYS` or `EINVAL` from the kernel, or reports success
    without the files holding each other's bytes. Before it is raised the probe's
    files, `owner.json` and the directory are removed, and no handler is left
    installed.

    Raised also by an apply or a restore whose exchange with its target is
    refused with `EINVAL`, `ENOSYS` or `EXDEV`, or finds no `renameat2` (which
    a probe that passed rules out in practice), once the target is verified to
    hold what it held before the exchange: the apply has then removed its staging
    file and its record, the restore only its staging file, keeping the record.

    The message names the filesystem by the device numbers and the path of the
    directory the exchange was tried in, and names the target when there was one.
    """

    exit_code = EXIT_EXCHANGE_UNAVAILABLE


class _TargetAbsent(Exception):
    """A target was absent when its bytes were to be replaced, and nothing was put in its place.

    Never leaves this module: the apply and the restore each turn it into their
    own refusal, which names the target.
    """


class _TargetExchangeRefused(Exception):
    """The exchange with a target was refused because its filesystem cannot exchange it.

    Nothing was moved and the staging file is still in the journal. `reason` says
    what refused. Never leaves this module: the apply and the restore each verify
    the target and turn it into `ExchangeUnavailable`, which names the target.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class JournalNotHeld(JournalError):
    """A mutation was requested from a holder that is not inside its `with` block.

    Nothing is read or written: without the journal there is nowhere to write
    the record, and a mutation without a record is exactly what the journal
    exists to prevent.
    """

    exit_code = None


class MutationDidNotLand(JournalError):
    """A requested mutation was refused, or was written and not found on disk.

    `record` is `None` when the refusal came before anything was written: the
    anchor is empty, absent, repeated or starts mid-line, `old == new`, the
    replacement changes no byte, or the path is not a file inside the tree. It
    is the record when the record was written and then the target was found
    absent while the mutation was being put in place -- it is not created -- or
    was written and re-reading it did not find the mutation. That record is still
    held and must be restored like any other; restoring it refuses with
    `UnknownState` while the target is absent.
    """

    exit_code = None

    def __init__(self, message: str, record: Record | None = None) -> None:
        super().__init__(message)
        self.record = record


@dataclass(frozen=True)
class Record:
    """One mutation, as the journal holds it.

    `name` is `NN-<slug>`, the stem shared by the record's `.json` and `.orig`
    files, and `nn` is its counter. `confirmed_on_disk` is whether re-reading
    the target after the write found exactly the mutated bytes.
    """

    name: str
    nn: int
    rel_path: str
    sha_before: str
    sha_after: str
    size_before: int
    size_after: int
    applied_utc: str
    confirmed_on_disk: bool

    def ledger_entry(self) -> dict[str, Any]:
        """The content of this record's `.json` file."""
        return {
            "rel_path": self.rel_path,
            "sha_before": self.sha_before,
            "sha_after": self.sha_after,
            "size_before": self.size_before,
            "size_after": self.size_after,
            "applied_utc": self.applied_utc,
        }


@dataclass(frozen=True)
class RestoreSummary:
    """Counts of what `restore_journal()` did, one count per outcome.

    `tmp_removed` counts the staging files removed before any record was replayed,
    the exchange probe's two files included. `exchange_unavailable` counts the
    records kept because the filesystem of their target refused the exchange: a
    limit of that filesystem, not a state nobody wrote, so it is not counted in
    `unknown_state`.
    """

    restored: int
    already_original: int
    unknown_state: int
    tmp_removed: int
    exchange_unavailable: int

    def line(self) -> str:
        """The summary line `restore_journal()` prints."""
        return (
            f"restored={self.restored} already_original={self.already_original} "
            f"unknown_state={self.unknown_state} tmp_removed={self.tmp_removed} "
            f"exchange_unavailable={self.exchange_unavailable}"
        )


def _sha256(data: bytes) -> str:
    """Hex SHA-256 of `data`."""
    return hashlib.sha256(data).hexdigest()


def _sha256_of_file(path: Path) -> str:
    """Hex SHA-256 of the bytes of `path`, or `absent` when it does not exist."""
    try:
        return _sha256(path.read_bytes())
    except FileNotFoundError:
        return "absent"


def _utc_now() -> str:
    """The current UTC time, to the second, in ISO 8601 with a `Z` suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _encode_json(value: dict[str, Any]) -> bytes:
    """Stable, newline-terminated JSON bytes for a journal file."""
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _slug(rel_path: str) -> str:
    """The record-name form of a tree-relative path."""
    return rel_path.replace("/", "__")


def _write_all(fd: int, data: bytes) -> None:
    """Write every byte of `data` to `fd`."""
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _fsync_dir(directory: Path) -> None:
    """Flush a directory's entries, so a file just created or removed stays so."""
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _create_synced(path: Path, data: bytes) -> None:
    """Create `path`, which must not exist yet, with `data`, and flush it."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _staging_path(journal_dir: Path, name: str, suffix: str) -> Path:
    """The staging file of the record called `name`, for an apply or for a restore."""
    return journal_dir / f"{name}{suffix}"


def _load_renameat2() -> Callable[..., object] | None:
    """The C library's `renameat2`, set up to keep `errno`; `None` when it is not exported."""
    try:
        function = ctypes.CDLL(None, use_errno=True).renameat2
    except (OSError, AttributeError):
        return None
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    return function


def _unavailable(directory: Path, reason: str) -> ExchangeUnavailable:
    """The refusal for a filesystem that cannot exchange two files, naming it and `reason`.

    The filesystem is named by the device numbers of `directory` -- the ones
    `/proc/self/mountinfo` and `stat` show for its mount -- and by the path of
    `directory` itself.
    """
    try:
        device = os.stat(directory).st_dev
        where = f"device {os.major(device)}:{os.minor(device)}"
    except OSError as exc:
        where = f"a device that cannot be read ({exc})"
    return ExchangeUnavailable(
        f"REFUSING: atomic exchange unavailable on {where} (the filesystem of {directory}): "
        f"{reason}"
    )


def _exchange(first: Path, second: Path) -> None:
    """Swap what `first` and `second` name, in one `renameat2(RENAME_EXCHANGE)` call.

    Both paths must exist, and neither is ever created. Raises
    `ExchangeUnavailable` when the C library does not export `renameat2`, and
    `OSError` carrying the kernel's errno when the call fails:
    `FileNotFoundError` when either path is absent, and then nothing was moved.
    """
    renameat2 = _load_renameat2()
    if renameat2 is None:
        raise _unavailable(second.parent, "the C library does not export renameat2")
    status = renameat2(
        _AT_FDCWD, os.fsencode(first), _AT_FDCWD, os.fsencode(second), _RENAME_EXCHANGE
    )
    if status != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(first), None, str(second))


def _read_if_present(path: Path) -> bytes | None:
    """The bytes of `path`, or `None` when it does not exist."""
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def _probe_exchange(journal_dir: Path) -> None:
    """Exchange two files of the journal once, to learn whether its filesystem can.

    The two files are created with different bytes, exchanged, and read back,
    and they are removed again on every exit. Raises `ExchangeUnavailable` when
    the C library does not export `renameat2`, when the kernel answers `ENOSYS`
    or `EINVAL`, or when the call reports success and the two files do not hold
    each other's bytes. Any other error propagates with its own type.
    """
    first = journal_dir / _EXCHANGE_PROBE_NAMES[0]
    second = journal_dir / _EXCHANGE_PROBE_NAMES[1]
    first_bytes, second_bytes = _EXCHANGE_PROBE_BYTES
    try:
        _create_synced(first, first_bytes)
        _create_synced(second, second_bytes)
        try:
            _exchange(first, second)
        except OSError as exc:
            answer = {errno.ENOSYS: "ENOSYS", errno.EINVAL: "EINVAL"}.get(exc.errno or 0)
            if answer is None:
                raise
            raise _unavailable(
                journal_dir, f"renameat2(RENAME_EXCHANGE) failed with {answer}"
            ) from None
        if (_read_if_present(first), _read_if_present(second)) != (second_bytes, first_bytes):
            raise _unavailable(
                journal_dir,
                "renameat2(RENAME_EXCHANGE) reported success without swapping the two files",
            )
    finally:
        first.unlink(missing_ok=True)
        second.unlink(missing_ok=True)
        _fsync_dir(journal_dir)


def _exchange_with_target(staging: Path, target: Path) -> None:
    """`_exchange` of a staging file with its target, telling a refusing filesystem apart.

    The journal's probe saw the filesystem of the journal, not necessarily the
    target's. Raises `_TargetExchangeRefused` when the exchange with this target
    is refused with `EINVAL`, `ENOSYS` or `EXDEV`, or `renameat2` is not exported;
    nothing was moved then. Every other error propagates with its own type.
    """
    try:
        _exchange(staging, target)
    except ExchangeUnavailable:
        raise _TargetExchangeRefused("the C library does not export renameat2") from None
    except OSError as exc:
        answer = _TARGET_EXCHANGE_UNAVAILABLE.get(exc.errno or 0)
        if answer is None:
            raise
        raise _TargetExchangeRefused(f"renameat2(RENAME_EXCHANGE) failed with {answer}") from None


def _write_target(target: Path, data: bytes, staging: Path) -> None:
    """Put `data` in place of an existing target file in one exchange, through `staging`.

    `staging` is a path in the journal directory that must not exist yet. It is
    created with `data` and flushed, given the target's permission bits, and
    exchanged with the target in one `renameat2(RENAME_EXCHANGE)` call; `staging`
    then holds the target's previous bytes and is removed, and the directories
    of the target and of `staging` are flushed. A process killed at any point
    leaves the target holding either its previous bytes or `data`, and possibly
    `staging` still in the journal, holding the other.

    The target is never created. When it is absent as its permission bits are
    read, or as the exchange is made, nothing takes its place: `staging` is
    removed and `_TargetAbsent` is raised, for the caller to refuse by name. When
    the target's filesystem refuses the exchange, nothing was moved and
    `_TargetExchangeRefused` is raised with `staging` still in place, for the
    caller to verify the target before removing it. Any other exception
    propagates with its own type and leaves `staging` where it is, for the
    holder's restore to remove.

    `SIGINT` and `SIGTERM` are held back from the creation of `staging` until
    the directories are flushed, so a holder's handler never runs inside the
    sequence: it finds the replacement either not started or complete. A
    held-back signal is delivered as soon as the sequence ends, and the
    previous signal mask is put back on every exit, an exception included. This
    protects a single-threaded caller; `SIGKILL` cannot be held back.
    """
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, _HANDLED_SIGNALS)
    try:
        _create_synced(staging, data)
        try:
            os.chmod(staging, stat.S_IMODE(os.stat(target).st_mode))
            _exchange_with_target(staging, target)
        except FileNotFoundError:
            if os.path.lexists(target):
                raise
            staging.unlink(missing_ok=True)
            _fsync_dir(staging.parent)
            raise _TargetAbsent(str(target)) from None
        staging.unlink()
        _fsync_dir(target.parent)
        _fsync_dir(staging.parent)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def _record_paths(journal_dir: Path, name: str) -> tuple[Path, Path]:
    """The `.json` and `.orig` paths of the record called `name`."""
    return journal_dir / f"{name}.json", journal_dir / f"{name}.orig"


def _write_record(journal_dir: Path, record: Record, original: bytes) -> None:
    """Write a record's two files, flushed, before its target is touched.

    The `.json` file is created first. A process killed between the two leaves a
    `.json` without `.orig` next to a target that was never written, and a
    `.json` alone is enough to establish that the target is original.
    """
    json_path, orig_path = _record_paths(journal_dir, record.name)
    _create_synced(json_path, _encode_json(record.ledger_entry()))
    _create_synced(orig_path, original)
    _fsync_dir(journal_dir)


def _delete_record(journal_dir: Path, name: str) -> None:
    """Remove a record's files: `.orig` first, so a partial removal leaves a `.json`."""
    json_path, orig_path = _record_paths(journal_dir, name)
    orig_path.unlink(missing_ok=True)
    json_path.unlink(missing_ok=True)
    _fsync_dir(journal_dir)


def _malformed(name: str, reason: str) -> UnknownState:
    """The refusal for a record whose files cannot be trusted."""
    return UnknownState(f"REFUSING: record {name} is malformed ({reason}) — not touching it")


def _rel_path_problem(tree: Path, rel_path: object) -> str | None:
    """Why `rel_path` is not a normalized path to a location inside `tree`, or `None`."""
    if not isinstance(rel_path, str) or not rel_path:
        return "the path is not a non-empty string"
    pure = PurePosixPath(rel_path)
    if pure.is_absolute() or "\\" in rel_path or ".." in pure.parts or pure.as_posix() != rel_path:
        return f"{rel_path!r} is not a normalized tree-relative path"
    if pure.parts[0] in {JOURNAL_DIRNAME, ".git"}:
        return f"{rel_path!r} names the journal or the git directory"
    if not (tree / rel_path).resolve().is_relative_to(tree):
        return f"{rel_path!r} resolves outside the tree"
    return None


def _ledger_entry_problems(entry: object, name: str) -> list[str]:
    """Each way a parsed `.json` record departs from the ledger format, named."""
    if not isinstance(entry, dict):
        return ["the record is not a JSON object"]
    problems = [f"field {field} is missing" for field in LEDGER_FIELDS if field not in entry]
    problems += [f"field {key} is not a ledger field" for key in entry if key not in LEDGER_FIELDS]
    for field in ("sha_before", "sha_after"):
        value = entry.get(field)
        if field in entry and not (isinstance(value, str) and _SHA256_HEX.match(value)):
            problems.append(f"field {field} is not a hex SHA-256")
    for field in ("size_before", "size_after"):
        value = entry.get(field)
        if field in entry and not (
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
        ):
            problems.append(f"field {field} is not a non-negative integer")
    if "applied_utc" in entry and not isinstance(entry["applied_utc"], str):
        problems.append("field applied_utc is not a string")
    if "sha_before" in entry and entry.get("sha_before") == entry.get("sha_after"):
        problems.append("sha_before equals sha_after")
    match = _RECORD_FILE.match(f"{name}.json")
    rel_path = entry.get("rel_path")
    if "rel_path" in entry and not isinstance(rel_path, str):
        problems.append("field rel_path is not a string")
    elif match is None or (isinstance(rel_path, str) and match["slug"] != _slug(rel_path)):
        problems.append("the record name does not match its rel_path")
    return problems


def _read_ledger_entry(journal_dir: Path, name: str) -> dict[str, Any] | None:
    """The validated `.json` of a record, or `None` if that file does not exist."""
    json_path, _orig_path = _record_paths(journal_dir, name)
    try:
        raw = json_path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _malformed(name, f"{json_path.name} cannot be read: {exc}") from None
    try:
        entry = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _malformed(name, f"{json_path.name} is not valid JSON: {exc}") from None
    problems = _ledger_entry_problems(entry, name)
    if problems:
        raise _malformed(name, "; ".join(problems))
    result: dict[str, Any] = entry
    return result


def _read_original(journal_dir: Path, name: str, sha_before: str) -> bytes:
    """A record's `.orig` bytes, refused unless they hash to `sha_before`."""
    _json_path, orig_path = _record_paths(journal_dir, name)
    try:
        original = orig_path.read_bytes()
    except FileNotFoundError:
        raise _malformed(name, f"{orig_path.name} is missing") from None
    except OSError as exc:
        raise _malformed(name, f"{orig_path.name} cannot be read: {exc}") from None
    if _sha256(original) != sha_before:
        raise _malformed(
            name, f"{orig_path.name} has sha={_sha256(original)}, expected sha_before {sha_before}"
        )
    return original


def _restore_record(
    tree: Path, journal_dir: Path, name: str, held: Record | None
) -> RestoreOutcome:
    """Replay one record, or refuse and leave both the record and its file alone.

    `held` is the record as the holder keeps it in memory, or `None` when the
    caller is a process replaying a journal it did not write. The files on disk
    decide, and the held copy must agree with them. The held copy stands in for
    the `.json` file only when that file is missing; even then the bytes written
    back come from the `.orig` file on disk, and only once they hash to
    `sha_before`.

    When the filesystem of the target refuses the exchange, the target is
    verified to still hold the mutation; then only the staging file is removed,
    the record is kept -- its `.orig` is the only way back -- and
    `ExchangeUnavailable` is raised naming the target. A target that no longer
    holds the mutation is refused with `UnknownState` and nothing is removed.
    """
    entry = _read_ledger_entry(journal_dir, name)
    if entry is None:
        if held is None:
            json_path, _orig_path = _record_paths(journal_dir, name)
            raise _malformed(name, f"{json_path.name} is missing")
        entry = held.ledger_entry()
    elif held is not None and any(entry[key] != getattr(held, key) for key in LEDGER_FIELDS[:3]):
        raise _malformed(name, "the record on disk is not the one this process wrote")

    rel_path: str = entry["rel_path"]
    sha_before: str = entry["sha_before"]
    sha_after: str = entry["sha_after"]
    problem = _rel_path_problem(tree, rel_path)
    if problem is not None:
        raise _malformed(name, problem)
    target = (tree / rel_path).resolve()
    try:
        current_sha = _sha256(target.read_bytes())
    except FileNotFoundError:
        current_sha = "absent"

    if current_sha == sha_after:
        original = _read_original(journal_dir, name, sha_before)
        staging = _staging_path(journal_dir, name, _RESTORE_STAGING_SUFFIX)
        try:
            _write_target(target, original, staging)
        except _TargetAbsent:
            raise UnknownState(
                f"REFUSING: {rel_path} is absent: it vanished before its original bytes were put "
                f"back, and it was not created — keeping record {name}"
            ) from None
        except _TargetExchangeRefused as refused:
            found_sha = _sha256_of_file(target)
            if found_sha != sha_after:
                raise UnknownState(
                    f"REFUSING: {rel_path} is in an unknown state after its exchange was refused "
                    f"({refused.reason}): sha={found_sha}, expected {sha_after} — keeping record "
                    f"{name}"
                ) from None
            staging.unlink(missing_ok=True)
            _fsync_dir(journal_dir)
            raise _unavailable(
                target.parent,
                f"{rel_path}: {refused.reason}; {rel_path} still holds the mutation and record "
                f"{name} is kept",
            ) from None
        os.utime(target, None)
        reread_sha = _sha256(target.read_bytes())
        if reread_sha != sha_before:
            raise UnknownState(
                f"REFUSING: {rel_path} did not read back as its original bytes after the "
                f"restore (sha={reread_sha}, expected {sha_before}) — keeping record {name}"
            )
        clear_bytecode_caches(tree)
        _delete_record(journal_dir, name)
        print(f"[restore] restored: {rel_path}", file=sys.stderr)
        return "restored"

    if current_sha == sha_before:
        _json_path, orig_path = _record_paths(journal_dir, name)
        if orig_path.exists():
            # The `.orig` is the only copy of the original bytes and the witness that
            # `sha_before` is true: it must be the bytes the file now holds, or their
            # start when the record was cut while the `.orig` was being written (the
            # target is written only after it). Anything else -- the mutated bytes
            # included -- is a record that contradicts itself, and deleting it would
            # leave the file as it is and discard that copy.
            try:
                witness = orig_path.read_bytes()
            except OSError as exc:
                raise _malformed(name, f"{orig_path.name} cannot be read: {exc}") from None
            if _sha256(witness) == sha_after or not target.read_bytes().startswith(witness):
                raise _malformed(
                    name,
                    f"{orig_path.name} has sha={_sha256(witness)}, which is not the start of the "
                    f"file that matches sha_before {sha_before}",
                )
        clear_bytecode_caches(tree)
        _delete_record(journal_dir, name)
        print(f"[restore] already original: {rel_path}", file=sys.stderr)
        return "already_original"

    raise UnknownState(
        f"REFUSING: {rel_path} is in an unknown state (sha={current_sha}, expected "
        f"{sha_after} or {sha_before}) — not touching it"
    )


def _ignore_vanished(function: Callable[..., Any], path: str, exc: BaseException) -> None:
    """`shutil.rmtree` error hook: a cache already gone is fine, anything else is raised."""
    if not isinstance(exc, FileNotFoundError):
        raise exc


def clear_bytecode_caches(tree: Path) -> None:
    """Remove every `__pycache__` directory under `tree`, except under `.venv` or `node_modules`.

    A bytecode cache can outlive the source it was compiled from: a hash-based
    cache with source checking off is read without looking at the source, and a
    timestamp-based one still validates when a same-size rewrite lands within
    the same second. Either way a fresh interpreter would import bytes that are
    no longer on disk. Called on every apply and on every restore, so no cache
    written on one side of a mutation is read on the other.

    A cache that cannot be removed is raised, not skipped.
    """
    for dirpath, dirnames, _filenames in os.walk(tree):
        for dirname in list(dirnames):
            if dirname in _CACHE_WALK_EXCLUDED:
                dirnames.remove(dirname)
            elif dirname == _CACHE_DIRNAME:
                dirnames.remove(dirname)
                shutil.rmtree(Path(dirpath) / dirname, onexc=_ignore_vanished)


def _head_sha(tree: Path) -> str | None:
    """`git rev-parse HEAD` in `tree`, or `None` when git cannot answer."""
    result = subprocess.run(  # noqa: S603 -- fixed argv, no shell
        ["git", "-C", str(tree), "rev-parse", "HEAD"],  # noqa: S607 -- git from PATH
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _busy_message(journal_dir: Path) -> str:
    """The refusal a process prints when the journal already exists.

    Reads `owner.json` if it can; never writes.
    """
    pid: object = "unknown"
    started: object = "unknown"
    try:
        owner = json.loads((journal_dir / OWNER_FILENAME).read_bytes())
    except (OSError, ValueError):
        owner = None
    if isinstance(owner, dict):
        pid = owner.get("pid", "unknown")
        started = owner.get("started_utc", "unknown")
    return (
        f"REFUSING: {journal_dir} exists (owner pid={pid} started={started}) — another "
        "ablation is running, or a killed one left a mutation on disk; run --restore"
    )


def _read_owner_pid(journal_dir: Path) -> int:
    """The pid recorded in `owner.json`; refused when it cannot be read as a positive integer."""
    owner_path = journal_dir / OWNER_FILENAME
    try:
        owner = json.loads(owner_path.read_bytes())
    except (OSError, ValueError) as exc:
        hint = ""
        if isinstance(exc, FileNotFoundError) and not any(journal_dir.iterdir()):
            hint = (
                f"; it holds nothing, which is what a process killed between creating it and "
                f"writing {OWNER_FILENAME} leaves: if no ablation is running on this tree, "
                f"remove it with: rmdir {journal_dir} (rmdir refuses a directory that is not "
                "empty)"
            )
        raise JournalBusy(
            f"REFUSING: {owner_path} cannot be read ({exc}) — cannot establish that the owner "
            f"is gone; not touching the journal{hint}"
        ) from None
    pid = owner.get("pid") if isinstance(owner, dict) else None
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise JournalBusy(
            f"REFUSING: {owner_path} does not name a positive pid ({pid!r}) — cannot establish "
            "that the owner is gone; not touching the journal"
        )
    return pid


def _pid_is_alive(pid: int) -> bool:
    """Whether a process with `pid` exists; one this process may not signal counts as alive."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _scan_journal(journal_dir: Path) -> tuple[list[str], list[str], list[str]]:
    """Record names, newest `NN` first; staging files; and every other entry but the owner.

    A staging file is a regular file named `NN-<name>.tmp`: the form of the files
    the journal exchanges with a target, and of the two its exchange probe writes.
    An entry that is none of a record file, a staging file or the owner file is a
    stray.
    """
    stems: dict[str, int] = {}
    staging: list[str] = []
    strays: list[str] = []
    for entry in sorted(journal_dir.iterdir()):
        if entry.name == OWNER_FILENAME:
            continue
        if _STAGING_FILE.match(entry.name) is not None and entry.is_file():
            staging.append(entry.name)
            continue
        match = _RECORD_FILE.match(entry.name)
        if match is None or not entry.is_file():
            strays.append(entry.name)
            continue
        stems[entry.name[: -len(match["part"]) - 1]] = int(match["nn"])
    names = sorted(stems, key=lambda stem: (stems[stem], stem), reverse=True)
    return names, staging, strays


def _remove_emptied_journal(journal_dir: Path) -> bool:
    """Remove `owner.json` and the directory when nothing else is left; report whether it did."""
    try:
        entries = sorted(entry.name for entry in journal_dir.iterdir())
    except FileNotFoundError:
        return True
    if entries not in ([], [OWNER_FILENAME]):
        return False
    (journal_dir / OWNER_FILENAME).unlink(missing_ok=True)
    os.rmdir(journal_dir)
    return True


def restore_journal(tree: Path) -> RestoreSummary:
    """Replay the journal a dead process left under `tree`.

    Refuses with `JournalBusy` when `owner.json` cannot be read or names a
    process that is alive. Otherwise the staging files are removed first,
    counted in `tmp_removed`: a staging file is never the only copy of anything,
    because the record that names the original bytes is written before it, and
    the exchange probe's two files, left by a process killed while acquiring,
    hold nothing but probe bytes. Then
    every record is replayed newest `NN` first, the summary line is printed, and
    `owner.json` and the directory are removed once nothing else is left. A
    record that cannot be replayed is refused and kept, and counts in
    `unknown_state`; so does a staging file that cannot be removed, and any
    entry that is not a record, a staging file or the owner file. A record whose
    target's filesystem refuses the exchange is kept too, with that target
    verified to still hold the mutation and only the restore's staging file
    removed, and counts in `exchange_unavailable`; the other records are still
    replayed. Nothing else in the journal is deleted except a record whose file
    was verified original, and the journal stays while any record does. A caller
    reports exit status `EXIT_UNKNOWN_STATE` when `unknown_state` is not zero,
    and otherwise `EXIT_EXCHANGE_UNAVAILABLE` when `exchange_unavailable` is not
    zero.
    """
    tree = Path(tree).resolve()
    journal_dir = tree / JOURNAL_DIRNAME
    if not journal_dir.exists():
        summary = RestoreSummary(
            restored=0, already_original=0, unknown_state=0, tmp_removed=0, exchange_unavailable=0
        )
        print(summary.line())
        return summary
    if not journal_dir.is_dir():
        raise UnknownState(f"REFUSING: {journal_dir} is not a directory — not touching it")

    owner_pid = _read_owner_pid(journal_dir)
    if _pid_is_alive(owner_pid):
        raise JournalBusy(f"REFUSING: owner pid={owner_pid} is alive")

    names, staging, strays = _scan_journal(journal_dir)
    counts = {
        "restored": 0,
        "already_original": 0,
        "unknown_state": 0,
        "tmp_removed": 0,
        "exchange_unavailable": 0,
    }
    for staged in staging:
        try:
            (journal_dir / staged).unlink()
        except FileNotFoundError:
            continue
        except OSError as exc:
            print(
                f"REFUSING: staging file {journal_dir / staged} cannot be removed ({exc}) — "
                "leaving it",
                file=sys.stderr,
            )
            counts["unknown_state"] += 1
            continue
        print(f"[restore] removed staging file: {staged}", file=sys.stderr)
        counts["tmp_removed"] += 1
    if counts["tmp_removed"]:
        _fsync_dir(journal_dir)
    for name in names:
        try:
            outcome = _restore_record(tree, journal_dir, name, held=None)
        except UnknownState as exc:
            print(exc, file=sys.stderr)
            counts["unknown_state"] += 1
            continue
        except ExchangeUnavailable as exc:
            print(exc, file=sys.stderr)
            counts["exchange_unavailable"] += 1
            continue
        except OSError as exc:
            print(
                f"REFUSING: record {name} could not be replayed ({exc}) -- not touching it further",
                file=sys.stderr,
            )
            counts["unknown_state"] += 1
            continue
        counts[outcome] += 1
    for stray in strays:
        print(
            f"REFUSING: {journal_dir / stray} is not a journal record — not touching it",
            file=sys.stderr,
        )
        counts["unknown_state"] += 1

    summary = RestoreSummary(**counts)
    print(summary.line())
    if summary.unknown_state == 0 and summary.exchange_unavailable == 0:
        _remove_emptied_journal(journal_dir)
    return summary


class JournalOwner:
    """The process holding a tree's journal, for the duration of a `with` block.

    Entering creates the journal directory with an exclusive `mkdir`; if it
    already exists, `JournalBusy` is raised before any handler is registered and
    without touching the directory. Once the directory is held, `owner.json` is
    written, two probe files in the journal are exchanged once, and only then
    are an `atexit` hook and `SIGINT`/`SIGTERM` handlers installed, each of
    which replays this holder's own records. When the journal's filesystem cannot
    exchange them, `ExchangeUnavailable` is raised with the probe's files,
    `owner.json` and the directory removed and no handler installed.

    Leaving the block removes the staging files of the records this holder
    wrote, replays whatever records are still held, newest first, unregisters
    the hook, puts the previous signal handlers back, and removes the directory
    only if nothing else is in it. A record that cannot be replayed is kept, the
    records after it are still replayed, and leaving then raises `UnknownState`,
    or `ExchangeUnavailable` when every refusal was a target whose filesystem
    refuses the exchange; the message joins every refusal, each naming its
    target. A signal handler or the `atexit` hook prints those refusals instead,
    and the journal stays with the kept records.

    The holder only ever acts on records and staging files it wrote, by name;
    nothing here removes journal entries in bulk.
    """

    def __init__(self, tree: Path, argv: list[str]) -> None:
        self.tree = Path(tree).resolve()
        self.journal_dir = self.tree / JOURNAL_DIRNAME
        self._argv = list(argv)
        self._next_nn = 1
        self._issued: dict[str, Record] = {}
        self._held: dict[str, Record] = {}
        self._acquired = False
        self._open = False
        self._handlers_installed = False
        self._previous_handlers: dict[int, Any] = {}

    def __enter__(self) -> JournalOwner:
        head_sha = _head_sha(self.tree)
        try:
            os.mkdir(self.journal_dir)
        except FileExistsError:
            raise JournalBusy(_busy_message(self.journal_dir)) from None
        self._acquired = True
        try:
            owner_entry = {
                "pid": os.getpid(),
                "started_utc": _utc_now(),
                "tree": str(self.tree),
                "head_sha": head_sha,
                "argv": self._argv,
            }
            _create_synced(self.journal_dir / OWNER_FILENAME, _encode_json(owner_entry))
            _fsync_dir(self.journal_dir)
            _probe_exchange(self.journal_dir)
            self._install_handlers()
        except BaseException:
            self._uninstall_handlers()
            self._release()
            raise
        self._open = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._open = False
        try:
            refusals = self._restore_all()
        finally:
            self._uninstall_handlers()
        if refusals:
            message = "; ".join(str(refusal) for refusal in refusals)
            if any(isinstance(refusal, UnknownState) for refusal in refusals):
                raise UnknownState(message)
            raise ExchangeUnavailable(message)

    @property
    def held_records(self) -> tuple[Record, ...]:
        """Records this holder wrote and has not yet restored, in `NN` order."""
        return tuple(sorted(self._held.values(), key=lambda record: record.nn))

    def apply_source(self, rel_path: str, old: str, new: str) -> Record:
        """Replace the single line-start occurrence of `old` with `new` in `rel_path`.

        The order is the substance: the original bytes and both hashes are
        computed, the record is written and flushed, and only then are the
        mutated bytes staged in the journal and exchanged with the target. The
        target is then re-read from disk, and bytecode caches under the tree are
        removed.

        Raises `MutationDidNotLand` without writing anything when `old` is empty,
        absent, repeated or starts mid-line, when `old == new`, or when the path
        is not a file inside the tree; and with the held record attached when the
        target turns out absent while the mutation is put in place (it is not
        created, and restoring that record refuses while it stays absent) or the
        re-read target is not the mutation.

        Raises `ExchangeUnavailable` naming the target when its filesystem refuses
        the exchange (`EINVAL`, `ENOSYS`, `EXDEV`): the target is first verified to
        still hold its original bytes, then the staging file and the record are
        removed, and the caller must stop. A target that no longer holds its
        original bytes is refused with `UnknownState`, and the record stays held.
        """
        if not self._open:
            raise JournalNotHeld(
                f"REFUSING: {self.journal_dir} is not held by this process — apply a "
                "mutation only inside journal_owner()"
            )
        problem = _rel_path_problem(self.tree, rel_path)
        if problem is not None:
            raise MutationDidNotLand(f"{rel_path}: {problem}")
        target = (self.tree / rel_path).resolve()
        if not target.is_file():
            raise MutationDidNotLand(f"{rel_path}: {rel_path!r} is not a regular file")

        original = target.read_bytes()
        try:
            text = original.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MutationDidNotLand(f"{rel_path}: not decodable as UTF-8 ({exc})") from None
        if not old:
            raise MutationDidNotLand(f"{rel_path}: anchor text is empty")
        occurrences = text.count(old)
        if occurrences != 1:
            raise MutationDidNotLand(
                f"{rel_path}: anchor text occurs {occurrences} times, need exactly 1"
            )
        index = text.index(old)
        if index != 0 and text[index - 1] != "\n":
            raise MutationDidNotLand(
                f"{rel_path}: anchor starts mid-line; the replacement would corrupt indentation"
            )
        if old == new:
            raise MutationDidNotLand(f"{rel_path}: old == new, this mutates nothing")
        mutated = text.replace(old, new, 1).encode("utf-8")
        sha_before = _sha256(original)
        sha_after = _sha256(mutated)
        if sha_before == sha_after:
            raise MutationDidNotLand(f"{rel_path}: bytes unchanged after replacement")

        nn = self._next_nn
        self._next_nn += 1
        record = Record(
            name=f"{nn:02d}-{_slug(rel_path)}",
            nn=nn,
            rel_path=rel_path,
            sha_before=sha_before,
            sha_after=sha_after,
            size_before=len(original),
            size_after=len(mutated),
            applied_utc=_utc_now(),
            confirmed_on_disk=False,
        )
        self._issued[record.name] = record
        self._held[record.name] = record

        _write_record(self.journal_dir, record, original)
        staging = _staging_path(self.journal_dir, record.name, _APPLY_STAGING_SUFFIX)
        try:
            _write_target(target, mutated, staging)
        except _TargetAbsent:
            raise MutationDidNotLand(
                f"{rel_path}: the file is absent: it vanished before the mutation was put in "
                f"place, and it was not created; record {record.name} is held",
                record=record,
            ) from None
        except _TargetExchangeRefused as refused:
            found_sha = _sha256_of_file(target)
            if found_sha != sha_before:
                raise UnknownState(
                    f"REFUSING: {rel_path} is in an unknown state after its exchange was refused "
                    f"({refused.reason}): sha={found_sha}, expected {sha_before} — keeping record "
                    f"{record.name}"
                ) from None
            # The target still holds its original bytes, so the record is no longer needed:
            # it goes only after that was verified, and with it the staging file.
            staging.unlink(missing_ok=True)
            _delete_record(self.journal_dir, record.name)
            self._held.pop(record.name, None)
            raise _unavailable(
                target.parent,
                f"{rel_path}: {refused.reason}; {rel_path} is untouched and its record "
                f"{record.name} was removed",
            ) from None

        on_disk = target.read_bytes()
        if _sha256(on_disk) != sha_after or new not in on_disk.decode("utf-8", errors="replace"):
            raise MutationDidNotLand(
                f"{rel_path}: the file on disk does not hold the mutation "
                f"(sha={_sha256(on_disk)}, expected {sha_after}); record {record.name} is held",
                record=record,
            )
        confirmed = replace(record, confirmed_on_disk=True)
        self._issued[record.name] = confirmed
        self._held[record.name] = confirmed
        clear_bytecode_caches(self.tree)
        return confirmed

    def restore(self, record: Record) -> RestoreOutcome:
        """Replay one of this holder's records.

        Raises `UnknownState`, keeping the record and leaving the file alone, when
        the target is neither the mutated nor the original bytes -- an absent
        target included, also one that vanishes while it is put back, which is
        not created -- or the record on disk cannot be trusted. Raises
        `ExchangeUnavailable` naming the target when its filesystem refuses the
        exchange; the target still holds the mutation and the record stays held.
        Raises `ValueError` for a record this holder did not write. A record
        already restored is left alone.
        """
        issued = self._issued.get(record.name)
        if issued is None or any(
            getattr(issued, key) != getattr(record, key) for key in LEDGER_FIELDS
        ):
            raise ValueError(f"{record.name} is not a record written by this journal holder")
        held = self._held.get(record.name)
        if held is None:
            return "already_restored"
        outcome = _restore_record(self.tree, self.journal_dir, record.name, held=held)
        self._held.pop(record.name, None)
        return outcome

    def _restore_all(self) -> list[UnknownState | ExchangeUnavailable]:
        """Remove this holder's staging files, replay what it still holds newest first, release.

        The staging files go first: in this process one is left behind only by a
        replacement that raised, the record it belongs to still names the original
        bytes, and a restore that met it would find its staging name already taken.

        A record refused with `UnknownState`, or with `ExchangeUnavailable` because
        its target's filesystem refuses the exchange, is printed, kept, and
        returned, and the records after it are still replayed: a refusal on one
        target never costs the others their restore. The journal then stays,
        because those records do.
        """
        refusals: list[UnknownState | ExchangeUnavailable] = []
        self._remove_own_staging()
        for record in sorted(self._held.values(), key=lambda held: held.nn, reverse=True):
            try:
                self.restore(record)
            except (UnknownState, ExchangeUnavailable) as exc:
                print(exc, file=sys.stderr)
                refusals.append(exc)
        self._release()
        return refusals

    def _remove_own_staging(self) -> int:
        """Remove the staging files of the records this holder wrote, by name; report the count.

        Nothing is removed once the directory is no longer held by this holder. A
        staging file that cannot be removed is reported and left, and then keeps
        the directory from being removed.
        """
        if not self._acquired:
            return 0
        removed = 0
        for name in self._issued:
            for suffix in (_APPLY_STAGING_SUFFIX, _RESTORE_STAGING_SUFFIX):
                path = _staging_path(self.journal_dir, name, suffix)
                try:
                    path.unlink()
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    print(f"[journal] cannot remove staging file {path}: {exc}", file=sys.stderr)
                    continue
                removed += 1
        if removed:
            _fsync_dir(self.journal_dir)
            print(f"[journal] tmp_removed={removed}", file=sys.stderr)
        return removed

    def _release(self) -> None:
        """Remove `owner.json` and the directory if this holder made it and nothing else is left."""
        if not self._acquired or self._held:
            return
        if _remove_emptied_journal(self.journal_dir):
            self._acquired = False
        else:
            print(
                f"[journal] leaving {self.journal_dir}: it holds entries this process did not "
                "write",
                file=sys.stderr,
            )

    def _install_handlers(self) -> None:
        """Register the `atexit` hook and the `SIGINT`/`SIGTERM` handlers."""
        atexit.register(self._at_exit)
        self._handlers_installed = True
        for signum in _HANDLED_SIGNALS:
            self._previous_handlers[signum] = signal.signal(signum, self._on_signal)

    def _uninstall_handlers(self) -> None:
        """Unregister the `atexit` hook and put the previous signal handlers back."""
        if not self._handlers_installed:
            return
        atexit.unregister(self._at_exit)
        for signum, previous in self._previous_handlers.items():
            signal.signal(signum, signal.SIG_DFL if previous is None else previous)
        self._previous_handlers.clear()
        self._handlers_installed = False

    def _at_exit(self) -> None:
        """`atexit` hook: replay what is still held."""
        self._restore_all()

    def _on_signal(self, signum: int, frame: FrameType | None) -> None:
        """`SIGINT`/`SIGTERM` handler: replay what is still held, then exit `128 + signum`."""
        self._restore_all()
        self._uninstall_handlers()
        raise SystemExit(128 + signum)


def journal_owner(tree: Path, argv: list[str]) -> JournalOwner:
    """The context manager that holds `tree`'s journal; `argv` is recorded in `owner.json`."""
    return JournalOwner(tree, argv)
