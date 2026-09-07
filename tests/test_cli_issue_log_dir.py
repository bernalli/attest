"""`attest issue --log-dir` (D-1/D-2/D-3/D-4) and `attest log prove --receipt`
(D-5) — Task 1 of docs/plans/2026-09-07_a2-anchoring-default-on.md §5.

Reuses the CLI-driven pipeline helpers from `tests/test_cli.py` (§5.2:
"tests/test_cli.py ... oppure un file nuovo tests/test_cli_issue_log_dir.py
che li importa") rather than duplicating them — that file is already large
enough that a second copy of `_keygen`/`_issue`/`_log_init`/etc. would be a
second thing to keep in sync with the first.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from attest import cli, tlog
from tests.test_cli import (
    ISSUER,
    KID,
    LOG_ORIGIN,
    CapSys,
    _anchor_policy_file,
    _issue,
    _keygen,
    _keygen_hybrid,
    _log_append,
    _log_init,
    _log_keys_file,
    _log_sign_checkpoint,
    _manifest_init,
    _minimal_anchor_evidence,
    _receipt_entry,
    _trust_dir,
    _v2_ots_proof,
    _write_payload,
    _write_salt_file,
)


def _issue_argv(
    payload_path: Path,
    seed: Path,
    out: Path,
    *,
    kid: str = KID,
    log_dir: Path | None = None,
    attest_version: str = "0.1",
    mldsa_key: Path | None = None,
    salt: Path | None = None,
    salt_out: Path | None = None,
    force: bool = False,
) -> list[str]:
    argv = [
        "issue",
        "--payload",
        str(payload_path),
        "--seed",
        str(seed),
        "--kid",
        kid,
        "--out",
        str(out),
    ]
    if attest_version != "0.1":
        argv += ["--attest-version", attest_version]
    if mldsa_key is not None:
        argv += ["--mldsa-key", str(mldsa_key)]
    if salt is not None:
        argv += ["--salt", str(salt)]
    if salt_out is not None:
        argv += ["--salt-out", str(salt_out)]
    if log_dir is not None:
        argv += ["--log-dir", str(log_dir)]
    if force:
        argv.append("--force")
    return argv


# --- 5.3.1/5.3.7: the entry, and the `log` report member ---------------------


def test_issue_log_dir_appends_the_receipt_entry_and_reports_it(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    out = tmp_path / "envelope.json"

    capsys.readouterr()
    rc = cli.main(_issue_argv(payload_path, seed, out, log_dir=log_dir))
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert "log" in result
    assert result["log"]["size"] == 1
    assert result["log"]["leaf_index"] == 0
    assert result["log"]["duplicate"] is False
    assert result["log"]["dir"] == str(log_dir)
    assert result["log"]["candidate"] == str(log_dir / "checkpoint.candidate")

    entries_lines = (log_dir / "entries.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(entries_lines) == 1
    assert json.loads(entries_lines[0]) == _receipt_entry(out)
    assert (log_dir / "checkpoint.candidate").exists()


# --- 5.3.1: byte-identical without the flag ----------------------------------


def test_issue_without_log_dir_is_byte_identical(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    out_a = tmp_path / "a.json"
    out_b = tmp_path / "b.json"

    capsys.readouterr()
    rc_a = cli.main(_issue_argv(payload_path, seed, out_a))
    captured_a = capsys.readouterr()
    rc_b = cli.main(_issue_argv(payload_path, seed, out_b))
    captured_b = capsys.readouterr()

    assert rc_a == 0
    assert rc_b == 0
    assert out_a.read_bytes() == out_b.read_bytes()
    result_a = json.loads(captured_a.out)
    result_b = json.loads(captured_b.out)
    assert set(result_a) == {"out", "receipt_id"}
    assert set(result_b) == {"out", "receipt_id"}
    assert captured_a.err == ""
    assert captured_b.err == ""


# --- 5.3.2: fail fast, before any write --------------------------------------


def test_issue_log_dir_refuses_uninitialized_log(tmp_path: Path, capsys: CapSys) -> None:
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    out = tmp_path / "envelope.json"
    missing_log_dir = tmp_path / "no-such-log"

    capsys.readouterr()
    rc = cli.main(_issue_argv(payload_path, seed, out, log_dir=missing_log_dir))
    captured = capsys.readouterr()

    assert rc == 2
    assert "is not an attest log (missing" in captured.err
    assert not out.exists()


def test_issue_log_dir_refuses_out_aliased_with_log_state(tmp_path: Path, capsys: CapSys) -> None:
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)

    for aliased in (log_dir / "entries.jsonl", log_dir / "config.json"):
        entries_before = (log_dir / "entries.jsonl").read_bytes()
        config_before = (log_dir / "config.json").read_bytes()

        capsys.readouterr()
        rc = cli.main(_issue_argv(payload_path, seed, aliased, log_dir=log_dir))
        captured = capsys.readouterr()

        assert rc == 2, captured.err
        assert "must not be, or be inside, the log's own state path" in captured.err
        assert str(aliased) in captured.err
        assert (log_dir / "entries.jsonl").read_bytes() == entries_before
        assert (log_dir / "config.json").read_bytes() == config_before


# --- 5.3.6: idempotence, qualified by profile --------------------------------


def test_issue_log_dir_is_idempotent_for_v01(tmp_path: Path, capsys: CapSys) -> None:
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    out = tmp_path / "envelope.json"

    rc1 = cli.main(_issue_argv(payload_path, seed, out, log_dir=log_dir))
    assert rc1 == 0
    entries_after_first = (log_dir / "entries.jsonl").read_bytes()
    candidate_after_first = (log_dir / "checkpoint.candidate").read_bytes()

    capsys.readouterr()
    rc2 = cli.main(_issue_argv(payload_path, seed, out, log_dir=log_dir))
    result2 = json.loads(capsys.readouterr().out)

    assert rc2 == 0
    assert result2["log"]["duplicate"] is True
    assert result2["log"]["size"] == 1
    assert result2["log"]["leaf_index"] == 0
    assert (log_dir / "entries.jsonl").read_bytes() == entries_after_first
    assert (log_dir / "checkpoint.candidate").read_bytes() == candidate_after_first


def test_issue_log_dir_v02_rerun_refuses_and_force_appends_a_second_entry(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    seed, _pub, mldsa = _keygen_hybrid(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path, attest_version="0.2")
    out = tmp_path / "envelope.json"

    rc1 = cli.main(
        _issue_argv(payload_path, seed, out, log_dir=log_dir, attest_version="0.2", mldsa_key=mldsa)
    )
    assert rc1 == 0
    first_entries = (log_dir / "entries.jsonl").read_text(encoding="utf-8")
    assert len(first_entries.splitlines()) == 1

    # Without --force: the ML-DSA-65 signature is randomized (P23), so the
    # rerun's envelope differs byte-for-byte from what is on disk, and
    # `_prepare_overwrite` refuses BEFORE any append is attempted.
    capsys.readouterr()
    rc2 = cli.main(
        _issue_argv(payload_path, seed, out, log_dir=log_dir, attest_version="0.2", mldsa_key=mldsa)
    )
    captured2 = capsys.readouterr()
    assert rc2 == 2
    assert "already exists with different content" in captured2.err
    assert (log_dir / "entries.jsonl").read_text(encoding="utf-8") == first_entries

    # With --force: a second, distinct envelope is written, and a SECOND
    # entry is appended (this profile is not idempotent — declared, not a
    # regression: §5.3.6).
    capsys.readouterr()
    rc3 = cli.main(
        _issue_argv(
            payload_path,
            seed,
            out,
            log_dir=log_dir,
            attest_version="0.2",
            mldsa_key=mldsa,
            force=True,
        )
    )
    result3 = json.loads(capsys.readouterr().out)
    assert rc3 == 0
    assert result3["log"]["size"] == 2
    assert result3["log"]["duplicate"] is False

    lines = (log_dir / "entries.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    hashes = {json.loads(line)["core_sha256"] for line in lines}
    assert len(hashes) == 2, "the two entries must NOT collapse into one"


# --- 5.3.4/5.3.5: the receipt survives a commit failure ----------------------


def test_issue_log_dir_commit_failure_keeps_receipt_and_log_state(
    tmp_path: Path, capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    out = tmp_path / "envelope.json"

    entries_before = (log_dir / "entries.jsonl").read_bytes()
    candidate_existed_before = (log_dir / "checkpoint.candidate").exists()
    original_replace_staged_file = cli._replace_staged_file

    def fail_replace(staged: Path, destination: Path) -> None:
        raise OSError("simulated commit failure")

    monkeypatch.setattr(cli, "_replace_staged_file", fail_replace)
    capsys.readouterr()
    rc = cli.main(_issue_argv(payload_path, seed, out, log_dir=log_dir))
    captured = capsys.readouterr()

    assert rc == 2
    assert "but NOT appended to" in captured.err
    assert str(out) in captured.err
    assert str(log_dir) in captured.err

    # The envelope is a valid, disclosable receipt despite the log failure.
    assert out.exists()
    manifest_path = _manifest_init(tmp_path, seed)
    trust_dir = _trust_dir(tmp_path, manifest_path)
    assert cli.main(["verify", str(out), "--trust-dir", str(trust_dir)]) == 0

    # entries.jsonl/candidate are untouched...
    assert (log_dir / "entries.jsonl").read_bytes() == entries_before
    assert (log_dir / "checkpoint.candidate").exists() == candidate_existed_before
    # ...but the tile cache may already reflect the attempted append (§5.3.5:
    # it is derived-only, installed before the candidate/entries commit, and
    # `sign-checkpoint` always recomputes from entries.jsonl regardless).
    tile_files = list((log_dir / "tile" / "0").iterdir())
    assert len(tile_files) == 1
    assert tile_files[0].name == "0.p.1"

    # Retrying the exact same command succeeds and does not leave a
    # duplicate: the failed attempt never appended anything.
    monkeypatch.setattr(cli, "_replace_staged_file", original_replace_staged_file)
    capsys.readouterr()
    rc2 = cli.main(_issue_argv(payload_path, seed, out, log_dir=log_dir))
    result2 = json.loads(capsys.readouterr().out)

    assert rc2 == 0
    assert result2["log"]["size"] == 1
    assert result2["log"]["leaf_index"] == 0
    assert result2["log"]["duplicate"] is False


# --- 5.5: the advisory lock ---------------------------------------------------


def test_log_append_refuses_while_another_append_holds_the_lock(
    tmp_path: Path, capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_dir = _log_init(tmp_path)
    entry = {"type": "receipt", "issuer": ISSUER, "core_sha256": "a" * 64}
    entry_path = tmp_path / "entry.json"
    entry_path.write_text(json.dumps(entry), encoding="utf-8")

    config_path = log_dir / "config.json"
    holder_fd = os.open(config_path, os.O_RDONLY)
    fcntl.flock(holder_fd, fcntl.LOCK_EX)
    monkeypatch.setattr(cli, "_LOG_APPEND_LOCK_TIMEOUT_SECONDS", 0.2)
    before_listing = sorted(p.name for p in log_dir.iterdir())

    try:
        capsys.readouterr()
        rc = cli.main(["log", "append", "--dir", str(log_dir), "--entry-json", str(entry_path)])
        captured = capsys.readouterr()

        assert rc == 2
        assert "is busy: another append holds the lock on" in captured.err
        assert (log_dir / "entries.jsonl").read_text(encoding="utf-8") == ""
        # No lock file was created anywhere in the log directory.
        assert sorted(p.name for p in log_dir.iterdir()) == before_listing
    finally:
        os.close(holder_fd)

    # Positive control (C-203): released, the exact same append proceeds.
    capsys.readouterr()
    rc2 = cli.main(["log", "append", "--dir", str(log_dir), "--entry-json", str(entry_path)])
    assert rc2 == 0


def test_log_append_lock_default_timeout_is_five_seconds(tmp_path: Path) -> None:
    log_dir = _log_init(tmp_path)
    entry = {"type": "receipt", "issuer": ISSUER, "core_sha256": "b" * 64}
    entry_path = tmp_path / "entry.json"
    entry_path.write_text(json.dumps(entry), encoding="utf-8")

    config_path = log_dir / "config.json"
    holder_fd = os.open(config_path, os.O_RDONLY)
    fcntl.flock(holder_fd, fcntl.LOCK_EX)
    try:
        start = time.monotonic()
        rc = cli.main(["log", "append", "--dir", str(log_dir), "--entry-json", str(entry_path)])
        elapsed = time.monotonic() - start
    finally:
        os.close(holder_fd)

    assert rc == 2
    assert 4.5 <= elapsed <= 15, elapsed


def test_log_append_refuses_when_flock_is_unsupported(
    tmp_path: Path, capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_dir = _log_init(tmp_path)
    entry = {"type": "receipt", "issuer": ISSUER, "core_sha256": "c" * 64}
    entry_path = tmp_path / "entry.json"
    entry_path.write_text(json.dumps(entry), encoding="utf-8")

    def fail_flock(fd: int, operation: int) -> None:
        raise OSError(errno.ENOTSUP, "Operation not supported")

    monkeypatch.setattr(cli.fcntl, "flock", fail_flock)
    capsys.readouterr()
    rc = cli.main(["log", "append", "--dir", str(log_dir), "--entry-json", str(entry_path)])
    captured = capsys.readouterr()

    assert rc == 2
    assert "Operation not supported" in captured.err
    # Never an append without the lock: entries.jsonl stays empty.
    assert (log_dir / "entries.jsonl").read_text(encoding="utf-8") == ""


# --- 5.6: `attest log prove --receipt` ---------------------------------------


def test_log_prove_receipt_roundtrip_yields_transparency_logged(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    ed_seed, ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
    seed, _pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, seed)
    envelope_path = _issue(tmp_path, seed, _write_payload(tmp_path))
    trust_dir = _trust_dir(tmp_path, manifest_path)

    _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))
    _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)

    evidence_path = tmp_path / "evidence.json"
    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "prove",
            "--dir",
            str(log_dir),
            "--receipt",
            str(envelope_path),
            "--out",
            str(evidence_path),
        ]
    )
    assert rc == 0

    log_keys_path = _log_keys_file(tmp_path, ed_pub, mldsa_out)
    anchor_policy_path = _anchor_policy_file(tmp_path)
    capsys.readouterr()
    rc = cli.main(
        [
            "verify",
            str(envelope_path),
            "--trust-dir",
            str(trust_dir),
            "--transparency",
            str(evidence_path),
            "--log-keys",
            str(log_keys_path),
            "--anchor-policy",
            str(anchor_policy_path),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["ok"] is True
    assert result["transparency"] == "logged"


def test_log_prove_requires_exactly_one_of_leaf_index_or_receipt(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
    seed, _pub = _keygen(tmp_path, "issuer")
    envelope_path = _issue(tmp_path, seed, _write_payload(tmp_path))
    _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))
    _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)
    out = tmp_path / "evidence.json"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "prove",
            "--dir",
            str(log_dir),
            "--leaf-index",
            "0",
            "--receipt",
            str(envelope_path),
            "--out",
            str(out),
        ]
    )
    captured = capsys.readouterr()
    assert rc == 2
    assert "give exactly one of --leaf-index or --receipt" in captured.err
    assert not out.exists()

    capsys.readouterr()
    rc = cli.main(["log", "prove", "--dir", str(log_dir), "--out", str(out)])
    captured = capsys.readouterr()
    assert rc == 2
    assert "give exactly one of --leaf-index or --receipt" in captured.err
    assert not out.exists()


def test_log_prove_receipt_never_logged_refuses(tmp_path: Path, capsys: CapSys) -> None:
    log_dir = _log_init(tmp_path)
    ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
    seed, _pub = _keygen(tmp_path, "issuer")
    logged_envelope = _issue(tmp_path, seed, _write_payload(tmp_path, "payload-a.json"))
    _log_append(tmp_path, log_dir, _receipt_entry(logged_envelope))
    _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)

    unlogged_envelope = _issue(
        tmp_path,
        seed,
        _write_payload(tmp_path, "payload-b.json", receipt_id="01J1V5B4M9Z8QWERTY12345699"),
        out_name="unlogged.json",
    )
    out = tmp_path / "evidence.json"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "prove",
            "--dir",
            str(log_dir),
            "--receipt",
            str(unlogged_envelope),
            "--out",
            str(out),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "is not logged in" in captured.err
    assert not out.exists()


def test_log_prove_receipt_multiple_matches_proves_the_earliest(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
    seed, _pub = _keygen(tmp_path, "issuer")
    envelope_path = _issue(tmp_path, seed, _write_payload(tmp_path))
    entry = _receipt_entry(envelope_path)

    # `entries.jsonl` does not guarantee unique core_sha256 (P13) — but the
    # CLI's OWN append path dedupes canonically-identical entries, so the
    # only way to a get a genuine duplicate row is to write the file by
    # hand, then hand-build a matching candidate for `sign-checkpoint` to
    # accept (it independently recomputes and refuses on any mismatch).
    entries_path = log_dir / "entries.jsonl"
    entry_line = json.dumps(entry, sort_keys=True) + "\n"
    entries_path.write_text(entry_line * 2, encoding="utf-8")
    encoded = [tlog.encode_entry(entry), tlog.encode_entry(entry)]
    root = tlog.build_tree(encoded)
    (log_dir / "checkpoint.candidate").write_text(
        cli._candidate_text(LOG_ORIGIN, 2, root), encoding="utf-8"
    )
    assert _log_sign_checkpoint(log_dir, ed_seed, mldsa_out).exists()

    out = tmp_path / "evidence.json"
    capsys.readouterr()
    rc = cli.main(
        ["log", "prove", "--dir", str(log_dir), "--receipt", str(envelope_path), "--out", str(out)]
    )
    captured = capsys.readouterr()

    assert rc == 0
    assert "2 entries carry core_sha256" in captured.err
    assert "proving the earliest, index 0" in captured.err
    result = json.loads(captured.out)
    assert result["leaf_index"] == 0


def test_log_prove_fails_closed_on_malformed_entries_jsonl_row(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
    seed, _pub = _keygen(tmp_path, "issuer")
    envelope_path = _issue(tmp_path, seed, _write_payload(tmp_path))
    _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))
    _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)
    entries_path = log_dir / "entries.jsonl"
    out = tmp_path / "evidence.json"

    entries_path.write_text("[]\n", encoding="utf-8")
    capsys.readouterr()
    rc = cli.main(["log", "prove", "--dir", str(log_dir), "--leaf-index", "0", "--out", str(out)])
    captured = capsys.readouterr()
    assert rc == 2
    assert "entry must be a JSON object" in captured.err
    assert not out.exists()

    entries_path.write_text(
        json.dumps({"type": "receipt", "issuer": ISSUER, "core_sha256": 123}) + "\n",
        encoding="utf-8",
    )
    capsys.readouterr()
    rc = cli.main(["log", "prove", "--dir", str(log_dir), "--leaf-index", "0", "--out", str(out)])
    captured = capsys.readouterr()
    assert rc == 2
    assert "is invalid" in captured.err
    assert not out.exists()


def test_log_prove_receipt_of_older_entry_requires_resigning_after_newer_append(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
    seed, _pub = _keygen(tmp_path, "issuer")
    old_envelope = _issue(tmp_path, seed, _write_payload(tmp_path, "old.json"))
    _log_append(tmp_path, log_dir, _receipt_entry(old_envelope), name="old-entry.json")
    _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)

    new_envelope = _issue(
        tmp_path,
        seed,
        _write_payload(tmp_path, "new.json", receipt_id="01J1V5B4M9Z8QWERTY12345698"),
        out_name="new-envelope.json",
    )
    _log_append(tmp_path, log_dir, _receipt_entry(new_envelope), name="new-entry.json")

    out = tmp_path / "evidence.json"
    capsys.readouterr()
    rc = cli.main(
        ["log", "prove", "--dir", str(log_dir), "--receipt", str(old_envelope), "--out", str(out)]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "run `attest log sign-checkpoint` again before proving" in captured.err
    assert not out.exists()


# --- regression: `_append_entry` extraction changed nothing observable ------


def test_log_append_and_sign_checkpoint_still_work_after_the_append_extraction(
    tmp_path: Path,
) -> None:
    """D-3's whole premise: `_append_entry` is a byte-identical extraction.
    A single ordinary roundtrip through the un-refactored verbs is the
    cheapest possible canary for that claim; `tests/test_cli.py`'s own
    `log_append`/`sign_checkpoint`/`log_prove`-marked tests are the real
    regression gate (§5.7 step 1.8) and are run separately.
    """
    log_dir = _log_init(tmp_path)
    ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
    seed, _pub = _keygen(tmp_path, "issuer")
    envelope_path = _issue(tmp_path, seed, _write_payload(tmp_path))

    candidate_path = _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))
    assert candidate_path.exists()
    checkpoint_path = _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)
    assert checkpoint_path.exists()


# --- 5.3.2: the log's state is not only the four FILES -----------------------


def test_issue_log_dir_refuses_out_inside_the_log_tile_tree(tmp_path: Path, capsys: CapSys) -> None:
    """The original defect, reproduced literally: `_replace_staged_tiles`
    installs the tile cache by replacing `LOG/tile` WHOLESALE, and it runs
    AFTER the receipt has been written, so an `--out` inside it used to be
    deleted by the very command that reported having written it, at exit
    0. `_reject_if_under_log_owned_path` refuses it up front instead, via
    the same containment check `_log_owned_paths`' other four (file) members
    get — no directory-specific branch."""
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    out = log_dir / "tile" / "0" / "receipt.json"

    capsys.readouterr()
    rc = cli.main(_issue_argv(payload_path, seed, out, log_dir=log_dir))
    captured = capsys.readouterr()

    assert rc == 2, captured.out
    assert "must not be, or be inside, the log's own state path" in captured.err
    assert str(log_dir / "tile") in captured.err
    assert not out.exists()
    assert (log_dir / "entries.jsonl").read_text(encoding="utf-8") == ""


def test_issue_log_dir_refuses_salt_out_inside_the_log_tile_tree(
    tmp_path: Path, capsys: CapSys
) -> None:
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    salt = _write_salt_file(tmp_path, "salt.txt", bytes(range(16)))

    capsys.readouterr()
    rc = cli.main(
        _issue_argv(
            payload_path,
            seed,
            tmp_path / "envelope.json",
            log_dir=log_dir,
            salt=salt,
            salt_out=log_dir / "tile" / "0" / "salt.out",
        )
    )
    captured = capsys.readouterr()

    assert rc == 2, captured.out
    assert "must not be, or be inside, the log's own state path" in captured.err
    assert str(log_dir / "tile") in captured.err
    assert not (log_dir / "tile" / "0" / "salt.out").exists()
    assert (log_dir / "entries.jsonl").read_text(encoding="utf-8") == ""


def test_issue_log_dir_refuses_salt_out_aliased_with_log_state(
    tmp_path: Path, capsys: CapSys
) -> None:
    """The alias guard covers BOTH receipt outputs and all FOUR file-owned
    state paths; the test above it covers only `--out` against the tile
    directory. (The property test below covers all FIVE owned paths, for
    both flags, generically — this one pins the exact four file paths by
    name, which the property test's `owned / "nested" / ...` candidates do
    not exercise for the equality branch alone.)"""
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    salt = _write_salt_file(tmp_path, "salt.txt", bytes(range(16)))

    for aliased in (
        log_dir / "entries.jsonl",
        log_dir / "config.json",
        log_dir / "checkpoint.candidate",
        log_dir / "checkpoint",
    ):
        entries_before = (log_dir / "entries.jsonl").read_bytes()
        capsys.readouterr()
        rc = cli.main(
            _issue_argv(
                payload_path,
                seed,
                tmp_path / "envelope.json",
                log_dir=log_dir,
                salt=salt,
                salt_out=aliased,
            )
        )
        captured = capsys.readouterr()

        assert rc == 2, captured.out
        assert "--salt-out must not be, or be inside, the log's own state path" in captured.err
        assert str(aliased) in captured.err
        assert (log_dir / "entries.jsonl").read_bytes() == entries_before
        assert not (log_dir / "checkpoint.candidate").exists()


# --- the guard is a PROPERTY of `_log_owned_paths`, not an enumeration -------


def test_issue_log_dir_guard_covers_every_owned_path_and_any_depth_beneath_it(
    tmp_path: Path, capsys: CapSys
) -> None:
    """Pin the PROPERTY the guard holds, not today's enumeration of five
    paths: for EVERY path `_log_owned_paths` returns, both `--out` and
    `--salt-out` are refused when the flag equals that path AND when it
    points arbitrarily deep beneath it. Iterating the function's own
    return value -- never a second, hand-written list living beside it --
    is what makes a future sixth owned path fail THIS test the day it is
    added without a guard update, instead of only failing a hand-written
    case someone remembered to add."""
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    salt = _write_salt_file(tmp_path, "salt.txt", bytes(range(16)))

    owned_paths = cli._log_owned_paths(log_dir)
    # Tripwire on the SET, not on its size: a count says "6 != 5" and gets
    # bumped without thought, while a set names the path that appeared and
    # forces whoever added it to say, here, whether the guard below is still
    # the whole story for it (is it replaced wholesale? is it a directory?).
    # The loop below derives from `_log_owned_paths` and would silently keep
    # passing on its own -- pinning the enumeration belongs in the test, and
    # only in the test; the guard itself must never carry a second copy.
    assert {p.name for p in owned_paths} == {
        "config.json",
        "entries.jsonl",
        "checkpoint.candidate",
        "checkpoint",
        "tile",
    }, "the log's owned-path set changed: confirm the guard still covers the new member"

    for owned in owned_paths:
        for candidate in (owned, owned / "nested" / "deep" / "x.json"):
            capsys.readouterr()
            rc_out = cli.main(_issue_argv(payload_path, seed, candidate, log_dir=log_dir))
            captured_out = capsys.readouterr()
            assert rc_out == 2, (str(owned), str(candidate), captured_out.out)
            assert "--out must not be, or be inside, the log's own state path" in captured_out.err
            assert str(owned) in captured_out.err

            capsys.readouterr()
            rc_salt = cli.main(
                _issue_argv(
                    payload_path,
                    seed,
                    tmp_path / "envelope.json",
                    log_dir=log_dir,
                    salt=salt,
                    salt_out=candidate,
                )
            )
            captured_salt = capsys.readouterr()
            assert rc_salt == 2, (str(owned), str(candidate), captured_salt.out)
            assert (
                "--salt-out must not be, or be inside, the log's own state path"
                in captured_salt.err
            )
            assert str(owned) in captured_salt.err

    # None of the sixty (5 owned x 2 depths x 2 flags) refused attempts
    # above ever appended anything.
    assert (log_dir / "entries.jsonl").read_text(encoding="utf-8") == ""


def test_issue_log_dir_allows_outputs_whose_path_string_merely_extends_an_owned_one(
    tmp_path: Path, capsys: CapSys
) -> None:
    """The other direction of the property, and the one a lazy containment
    check gets wrong: `Path.parents` compares path COMPONENTS, never
    STRINGS. Each candidate below has the STRING of an owned path (or of
    `--log-dir` itself) as a prefix while being no descendant of it, so a
    guard written as `str(a).startswith(str(b))` refuses all of them and a
    component-wise one accepts all of them. Measured: with the containment
    test written as a string prefix, `logbackup` alone stays GREEN -- no
    owned path's string is a prefix of it, because every owned path has a
    component after `log` -- which is why the extending siblings below, not
    the sibling directory, are what actually pins this. Both flags, because
    each goes through the guard independently."""
    log_dir = _log_init(tmp_path, name="log")
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    salt = _write_salt_file(tmp_path, "salt.txt", bytes(range(16)))

    candidates = [
        tmp_path / "logbackup" / "receipt.json",  # extends --log-dir's own string
        log_dir / "entries.jsonl.bak",  # extends the entries file's string
        log_dir / "checkpoint.candidate.bak",  # extends the candidate's string
        log_dir / "tile-backup" / "receipt.json",  # extends the tile dir's string
    ]
    for i, out in enumerate(candidates):
        out.parent.mkdir(parents=True, exist_ok=True)

        capsys.readouterr()
        rc = cli.main(_issue_argv(payload_path, seed, out, log_dir=log_dir, force=True))
        captured = capsys.readouterr()
        assert rc == 0, (str(out), captured.err)
        assert out.exists(), str(out)

        salt_out = out.with_name(out.name + f".salt{i}")
        capsys.readouterr()
        rc = cli.main(
            _issue_argv(
                payload_path,
                seed,
                tmp_path / "envelope.json",
                log_dir=log_dir,
                salt=salt,
                salt_out=salt_out,
                force=True,
            )
        )
        captured = capsys.readouterr()
        assert rc == 0, (str(salt_out), captured.err)
        assert salt_out.exists(), str(salt_out)


def test_issue_log_dir_refuses_out_routed_through_a_symlink_inside_the_tile_cache(
    tmp_path: Path, capsys: CapSys
) -> None:
    """An attenuated H-1, measured: a symlink that SITS inside the tile
    cache but POINTS outside every owned path used to be accepted, because
    the guard judged it only by where its bytes land -- and the bytes do
    survive. The ROUTE does not. `_replace_staged_tiles` replaces
    `LOG/tile/0` wholesale AFTER the receipt is written, taking the link
    with it, so the command exited 0 while `Path(report["out"]).exists()`
    was already False: a signing command reporting a receipt at a path that
    no longer resolves. Both views of the path are compared now, so the
    output is refused up front."""
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    first = _write_payload(tmp_path, "first.json")
    # A successful append first, so LOG/tile/0 exists to put the link in.
    assert cli.main(_issue_argv(first, seed, tmp_path / "r1.json", log_dir=log_dir)) == 0
    tile_dir = cli._log_tile_dir(log_dir)
    assert (tile_dir / "0").is_dir()

    external = tmp_path / "external"
    external.mkdir()
    escape_link = tile_dir / "0" / "escape"
    escape_link.symlink_to(external)
    out = escape_link / "receipt.json"
    second = _write_payload(tmp_path, "second.json", receipt_id="01J1V5B4M9Z8QWERTY12345699")
    entries_before = (log_dir / "entries.jsonl").read_bytes()

    capsys.readouterr()
    rc = cli.main(_issue_argv(second, seed, out, log_dir=log_dir))
    captured = capsys.readouterr()

    assert rc == 2, captured.out
    assert "must not be, or be inside, the log's own state path" in captured.err
    assert str(tile_dir) in captured.err
    assert not (external / "receipt.json").exists()
    assert (log_dir / "entries.jsonl").read_bytes() == entries_before


def test_issue_log_dir_refuses_salt_out_routed_through_a_symlink_inside_the_tile_cache(
    tmp_path: Path, capsys: CapSys
) -> None:
    """Same route, the other output. The salt copy would survive as bytes
    inside the envelope, but the operator asked for a separate file and
    would be told, at exit 0, that it is at a path the same command then
    unlinked."""
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    salt = _write_salt_file(tmp_path, "salt.txt", bytes(range(16)))
    first = _write_payload(tmp_path, "first.json")
    assert cli.main(_issue_argv(first, seed, tmp_path / "r1.json", log_dir=log_dir)) == 0

    external = tmp_path / "external"
    external.mkdir()
    escape_link = cli._log_tile_dir(log_dir) / "0" / "escape"
    escape_link.symlink_to(external)

    capsys.readouterr()
    rc = cli.main(
        _issue_argv(
            _write_payload(tmp_path, "second.json", receipt_id="01J1V5B4M9Z8QWERTY12345699"),
            seed,
            tmp_path / "envelope.json",
            log_dir=log_dir,
            salt=salt,
            salt_out=escape_link / "salt.out",
        )
    )
    captured = capsys.readouterr()

    assert rc == 2, captured.out
    assert "--salt-out must not be, or be inside, the log's own state path" in captured.err
    assert not (external / "salt.out").exists()


def test_issue_log_dir_refuses_out_via_symlink_ancestor_resolving_inside_an_owned_path(
    tmp_path: Path, capsys: CapSys
) -> None:
    """The mirror image, and the one that actually matters for safety: a
    symlink whose own location is nowhere near `--log-dir` is still
    refused if it REALLY points inside one of the log's owned paths --
    here, the tile cache. `out` itself is never a symlink (it does not
    exist yet; only its ANCESTOR does), which is what proves this rejection
    comes from `_reject_if_under_log_owned_path` and not from the
    unrelated 'destination is a symlink' refusal `_prepare_overwrite`
    applies to a pre-existing symlink AT the output path itself."""
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)

    tile_dir = cli._log_tile_dir(log_dir)
    tile_dir.mkdir(parents=True, exist_ok=True)
    outside_link = tmp_path / "outside_link"
    outside_link.symlink_to(tile_dir)
    out = outside_link / "receipt.json"
    assert not out.is_symlink()  # only the ANCESTOR is a symlink

    capsys.readouterr()
    rc = cli.main(_issue_argv(payload_path, seed, out, log_dir=log_dir))
    captured = capsys.readouterr()

    assert rc == 2, captured.out
    assert "must not be, or be inside, the log's own state path" in captured.err
    assert str(tile_dir) in captured.err
    assert not out.exists()
    assert (log_dir / "entries.jsonl").read_text(encoding="utf-8") == ""


class _UnresolvablePath:
    """Duck-typed stand-in for `Path`: `_resolve_or_reject` only ever calls
    `.resolve(strict=...)` on its argument before this raises, so nothing
    else needs to look like a real path."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def resolve(self, strict: bool = False) -> Path:
        raise self._exc

    def __fspath__(self) -> str:
        return "/simulated/unresolvable"

    def __str__(self) -> str:
        return "/simulated/unresolvable"


@pytest.mark.parametrize(
    "exc",
    [
        OSError(errno.ELOOP, "simulated: too many levels of symbolic links"),
        OSError(errno.EACCES, "simulated: permission denied"),
        # NOT hypothetical, and the reason `except OSError` alone is not
        # enough: measured on CPython 3.12 (this project's floor),
        # `Path.resolve(strict=False)` signals a symlink cycle with a
        # RuntimeError, not an OSError; a NUL byte gives a ValueError.
        RuntimeError("Symlink loop from '/simulated/unresolvable'"),
        ValueError("embedded null character in path"),
    ],
    ids=["ELOOP", "EACCES", "RuntimeError-symlink-loop", "ValueError-nul"],
)
def test_resolve_or_reject_fails_closed_on_an_unresolvable_path(exc: BaseException) -> None:
    """Direct pin of `_resolve_or_reject`'s fail-closed contract: a path
    `.resolve()` cannot make sense of for a reason OTHER than 'it does not
    exist yet' must come back as a refusal, never as 'not owned, so let it
    through' -- on a command that signs, an unresolved doubt must never
    silently become a yes. The exception TYPE is part of the contract: a
    handler that names only `OSError` lets the two non-OSError signals
    above escape as an uncaught traceback."""
    with pytest.raises(cli.CliUsageError, match="could not resolve"):
        cli._resolve_or_reject(_UnresolvablePath(exc), flag_name="--out")  # type: ignore[arg-type]


def test_issue_log_dir_refuses_out_when_a_state_path_cannot_be_resolved(
    tmp_path: Path, capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end version of the same contract: if resolving one of the
    log's OWN reserved paths fails for a reason other than 'it does not
    exist yet', `attest issue --log-dir` refuses rather than treating that
    path as 'not owned'. The induced failure targets only
    `_log_owned_paths`' checkpoint-candidate entry, so every other
    `.resolve()` this command makes (the pre-log-dir aliasing checks,
    `--out` itself) keeps behaving exactly as before -- this is
    `_reject_if_under_log_owned_path` failing closed, not an unrelated
    crash swallowing the whole command."""
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    out = tmp_path / "envelope.json"
    poisoned = cli._log_candidate_path(log_dir)
    original = cli._resolve_or_reject

    def flaky(path: Path, *, flag_name: str) -> tuple[Path, Path]:
        if path == poisoned:
            raise cli.CliUsageError(
                f"{flag_name}: could not resolve {path} to check it against the "
                "log's own state: simulated permission error"
            )
        return original(path, flag_name=flag_name)

    monkeypatch.setattr(cli, "_resolve_or_reject", flaky)
    capsys.readouterr()
    rc = cli.main(_issue_argv(payload_path, seed, out, log_dir=log_dir))
    captured = capsys.readouterr()

    assert rc == 2, captured.out
    assert "could not resolve" in captured.err
    assert not out.exists()
    assert (log_dir / "entries.jsonl").read_text(encoding="utf-8") == ""


# --- 5.3.4/5.3.5: the `before_commit` deviation, pinned from the other side ---


def test_issue_log_dir_leaves_the_log_untouched_when_the_receipt_write_fails(
    tmp_path: Path, capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_append_entry`'s `before_commit` hook is this task's one deviation from
    the plan's §5.4 signature, and its whole justification is the order of
    §5.3.4/§5.3.5. The half the commit-failure test above does NOT cover: when
    the CALLBACK fails, nothing of the append may be installed — no candidate,
    no tiles, no entry, no held lock. Whoever edits the shared core next has to
    learn that from a red test, not from a log carrying an entry for a receipt
    nobody was ever handed."""
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    out = tmp_path / "envelope.json"
    entries_before = (log_dir / "entries.jsonl").read_bytes()

    def fail_write(*args: object, **kwargs: object) -> None:
        raise OSError("simulated receipt write failure")

    monkeypatch.setattr(cli, "_write_json_text", fail_write)
    capsys.readouterr()
    rc = cli.main(_issue_argv(payload_path, seed, out, log_dir=log_dir))
    captured = capsys.readouterr()

    assert rc == 2
    assert "simulated receipt write failure" in captured.err
    assert not out.exists()
    assert (log_dir / "entries.jsonl").read_bytes() == entries_before
    assert not (log_dir / "checkpoint.candidate").exists()
    assert not (log_dir / "tile" / "0").exists()
    assert sorted(p.name for p in log_dir.iterdir()) == ["config.json", "entries.jsonl", "tile"]

    # And the lock is released, so the next append is not locked out by a
    # failure that installed nothing.
    holder_fd = os.open(str(log_dir / "config.json"), os.O_RDONLY)
    try:
        fcntl.flock(holder_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(holder_fd)


def test_issue_log_dir_entries_commit_failure_leaves_entries_intact(
    tmp_path: Path, capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The OTHER interleaving of §5.3.5, and the one the plan's wording gets
    wrong: the candidate is committed BEFORE entries, so when the SECOND
    replace fails the candidate has already moved. `entries.jsonl` — the
    authoritative file — is what stays byte-identical; the gap is caught by
    `sign-checkpoint`'s independent recomputation, and healed by a retry."""
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    first = _write_payload(tmp_path, "first.json")
    second = _write_payload(tmp_path, "second.json", receipt_id="01J1V5B4M9Z8QWERTY12345699")
    assert cli.main(_issue_argv(first, seed, tmp_path / "r1.json", log_dir=log_dir)) == 0
    entries_before = (log_dir / "entries.jsonl").read_bytes()
    candidate_before = (log_dir / "checkpoint.candidate").read_bytes()

    original_replace = cli._replace_staged_file
    calls = {"n": 0}

    def flaky(staged: Path, destination: Path) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("simulated failure committing entries.jsonl")
        original_replace(staged, destination)

    monkeypatch.setattr(cli, "_replace_staged_file", flaky)
    capsys.readouterr()
    rc = cli.main(_issue_argv(second, seed, tmp_path / "r2.json", log_dir=log_dir))
    captured = capsys.readouterr()
    monkeypatch.undo()

    assert rc == 2
    assert "but NOT appended to" in captured.err
    assert (tmp_path / "r2.json").exists()
    assert (log_dir / "entries.jsonl").read_bytes() == entries_before
    assert (log_dir / "checkpoint.candidate").read_bytes() != candidate_before

    ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "sign-checkpoint",
            "--dir",
            str(log_dir),
            "--name",
            "log",
            "--ed25519-key",
            str(ed_seed),
            "--mldsa-key",
            str(mldsa_out),
        ]
    )
    captured = capsys.readouterr()
    assert rc == 2
    assert "does not match an independent recomputation" in captured.err

    assert cli.main(_issue_argv(second, seed, tmp_path / "r2.json", log_dir=log_dir)) == 0
    assert len((log_dir / "entries.jsonl").read_text(encoding="utf-8").splitlines()) == 2


# --- 5.5: the lock, on the verb it was introduced for ------------------------


def test_issue_log_dir_refuses_while_another_append_holds_the_lock(
    tmp_path: Path, capsys: CapSys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The three lock tests above all drive `log append`. `issue --log-dir` is
    the naturally concurrent verb the lock exists for (§5.5), and it is the one
    that would lose an entry silently: measured, eight parallel issues against
    an unlocked build kept 1 of 8, every process exiting 0."""
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)
    out = tmp_path / "envelope.json"

    holder_fd = os.open(str(log_dir / "config.json"), os.O_RDONLY)
    fcntl.flock(holder_fd, fcntl.LOCK_EX)
    monkeypatch.setattr(cli, "_LOG_APPEND_LOCK_TIMEOUT_SECONDS", 0.2)
    try:
        capsys.readouterr()
        rc = cli.main(_issue_argv(payload_path, seed, out, log_dir=log_dir))
        captured = capsys.readouterr()

        assert rc == 2
        assert "is busy: another append holds the lock on" in captured.err
        # The receipt is written INSIDE the lock, so a refusal to acquire it
        # leaves no receipt behind either.
        assert not out.exists()
        assert (log_dir / "entries.jsonl").read_text(encoding="utf-8") == ""
    finally:
        os.close(holder_fd)

    # Positive control: released, the same command proceeds.
    assert cli.main(_issue_argv(payload_path, seed, out, log_dir=log_dir)) == 0


# --- 5.6: `log prove --receipt` must not destroy the receipt -----------------


def test_log_prove_refuses_receipt_aliased_with_out(tmp_path: Path, capsys: CapSys) -> None:
    """`--out` is written unguarded because inclusion evidence is derivable.
    The receipt is not derivable, so the input-vs-output alias refusal `log
    anchor` already makes for each of its inputs has to cover `--receipt` too."""
    log_dir = _log_init(tmp_path)
    ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
    seed, _pub = _keygen(tmp_path, "issuer")
    envelope_path = _issue(tmp_path, seed, _write_payload(tmp_path))
    _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))
    _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)
    before = envelope_path.read_bytes()

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "prove",
            "--dir",
            str(log_dir),
            "--receipt",
            str(envelope_path),
            "--out",
            str(envelope_path),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2, captured.out
    assert "--out must not be the same path as --receipt" in captured.err
    assert envelope_path.read_bytes() == before


def test_log_prove_refuses_out_on_every_owned_path_not_only_three_of_them(
    tmp_path: Path, capsys: CapSys
) -> None:
    """`log prove` writes `--out` deliberately unguarded, because inclusion
    evidence is derivable -- which makes the set of paths it may NOT land on
    the whole of the protection. That set used to be hand-written beside the
    one `_log_owned_paths` returns, and named three of the five: measured,
    `--out LOG/config.json` exited 0 and overwrote the log's origin, after
    which `log init` refuses to recreate it and `issue --log-dir`,
    `log append` and `sign-checkpoint` all fail. Iterate the function, so a
    sixth reserved path is covered here the day it is added."""
    log_dir = _log_init(tmp_path)
    ed_seed, _ed_pub, mldsa_out = _keygen_hybrid(tmp_path, "log-signer")
    seed, _pub = _keygen(tmp_path, "issuer")
    envelope_path = _issue(tmp_path, seed, _write_payload(tmp_path))
    _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))
    _log_sign_checkpoint(log_dir, ed_seed, mldsa_out)

    for owned in cli._log_owned_paths(log_dir):
        before = owned.read_bytes() if owned.is_file() else None
        capsys.readouterr()
        rc = cli.main(
            [
                "log",
                "prove",
                "--dir",
                str(log_dir),
                "--receipt",
                str(envelope_path),
                "--out",
                str(owned),
            ]
        )
        captured = capsys.readouterr()
        assert rc == 2, (str(owned), captured.out)
        assert "log's own state" in captured.err, str(owned)
        if before is not None:
            assert owned.read_bytes() == before, str(owned)

    # A HARD LINK to one of them is the case a resolved-path comparison
    # cannot see, and this command has no `st_nlink > 1` refusal downstream.
    linked = tmp_path / "hardlink.json"
    os.link(log_dir / "config.json", linked)
    config_before = (log_dir / "config.json").read_bytes()
    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "prove",
            "--dir",
            str(log_dir),
            "--receipt",
            str(envelope_path),
            "--out",
            str(linked),
        ]
    )
    captured = capsys.readouterr()
    assert rc == 2, captured.out
    assert "--out must not be one of the log's own state files" in captured.err
    assert (log_dir / "config.json").read_bytes() == config_before


# --- the guard is a property of VERBS too, not only of paths ----------------
#
# `_log_owned_paths`' tripwire (above) catches a sixth PATH slipping past
# the guard. Nothing caught a whole VERB doing the same: `log anchor` had
# the identical shape as `issue --log-dir` and `log prove` -- a `--dir`
# argument next to an `--out` argument -- and enumerated two of the five
# owned paths by hand instead of ever calling `_reject_if_under_log_owned_path`.
# The tests below add that missing axis.


def test_log_dir_output_commands_is_todays_three_guarded_verbs() -> None:
    """Tripwire on the SET `cli._log_dir_output_commands()` returns, not on
    a hand-written duplicate of it: that function walks the real parser
    `main()` dispatches every invocation through and reports every
    subcommand path combining a `--dir`/`--log-dir` argument with an
    `--out`/`--salt-out` argument. A future command shaped like these three
    appears here whether or not its own body remembers to call the guard --
    which is exactly what forces
    `test_every_log_dir_output_command_refuses_out_on_every_owned_path`
    below to grow a probe for it, or fail loudly because it did not."""
    assert set(cli._log_dir_output_commands()) == {
        ("issue",),
        ("log", "prove"),
        ("log", "anchor"),
    }, "a --dir/--log-dir + --out/--salt-out-shaped command appeared or vanished"


def test_every_log_dir_output_command_refuses_out_on_every_owned_path(
    tmp_path: Path, capsys: CapSys
) -> None:
    """The per-PATH pins for `issue --log-dir`
    (`test_issue_log_dir_guard_covers_every_owned_path_and_any_depth_beneath_it`)
    and `log prove`
    (`test_log_prove_refuses_out_on_every_owned_path_not_only_three_of_them`)
    each iterate `_log_owned_paths` for ONE verb the test author remembered
    to write. `log anchor` had the identical shape -- `--dir` plus `--out`
    -- and no such test caught it going unguarded, because the enumeration
    lived in the PATH axis only. This walks `cli._log_dir_output_commands()`
    -- the VERB axis -- and for each verb it finds, every owned path, so a
    verb that slips past the shared guard fails HERE by name, the day it is
    added, instead of three PRs later when a receipt lands on
    `LOG/config.json`."""
    log_dir = _log_init(tmp_path)
    seed, _pub = _keygen(tmp_path, "issuer")
    payload_path = _write_payload(tmp_path)

    def issue_argv(out: Path) -> list[str]:
        return _issue_argv(payload_path, seed, out, log_dir=log_dir)

    def log_prove_argv(out: Path) -> list[str]:
        return [
            "log",
            "prove",
            "--dir",
            str(log_dir),
            "--leaf-index",
            "0",
            "--out",
            str(out),
        ]

    def log_anchor_argv(out: Path) -> list[str]:
        return [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(tmp_path / "probe-evidence.json"),
            "--ots-proof",
            str(tmp_path / "probe-ots-proof.json"),
            "--out",
            str(out),
        ]

    probes: dict[tuple[str, ...], Callable[[Path], list[str]]] = {
        ("issue",): issue_argv,
        ("log", "prove"): log_prove_argv,
        ("log", "anchor"): log_anchor_argv,
    }

    verbs = cli._log_dir_output_commands()
    assert set(verbs) == set(probes), (
        "a --dir/--log-dir + --out-shaped command appeared without a probe "
        "in this test -- add one before trusting this pin again"
    )

    for verb in verbs:
        build_argv = probes[verb]
        for owned in cli._log_owned_paths(log_dir):
            capsys.readouterr()
            rc = cli.main(build_argv(owned))
            captured = capsys.readouterr()
            assert rc == 2, (verb, str(owned), captured.out)
            assert "log's own state" in captured.err, (verb, str(owned), captured.err)

    # None of the fifteen (3 verbs x 5 owned paths) refused attempts above
    # ever appended anything to, or overwrote, the log's own state.
    assert (log_dir / "entries.jsonl").read_text(encoding="utf-8") == ""
    assert json.loads((log_dir / "config.json").read_text(encoding="utf-8"))["origin"] == (
        LOG_ORIGIN
    )


def test_log_anchor_refuses_out_via_a_hard_link_to_a_state_file(
    tmp_path: Path, capsys: CapSys
) -> None:
    """The one case a resolved-path comparison cannot see, mirroring `log
    prove`'s identical pin: `log anchor` writes `--out` UNGUARDED
    (`_write_json_file`, no `st_nlink > 1` refusal downstream), so a HARD
    LINK to `config.json` is a second name for the exact same inode that
    `_reject_if_under_log_owned_path`'s resolve-based comparison does not
    equate with the original path -- `_same_file_target` over every owned
    path is what still catches it."""
    log_dir = _log_init(tmp_path)
    linked = tmp_path / "hardlink.json"
    os.link(log_dir / "config.json", linked)
    config_before = (log_dir / "config.json").read_bytes()

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(tmp_path / "probe-evidence.json"),
            "--ots-proof",
            str(tmp_path / "probe-ots-proof.json"),
            "--out",
            str(linked),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2, captured.out
    assert "--out must not be one of the log's own state files" in captured.err
    assert (log_dir / "config.json").read_bytes() == config_before


def _anchor_probe_argv(
    log_dir: Path,
    *,
    evidence: Path,
    ots_proof: Path,
    out: Path,
    rfc3161_token: Path,
) -> list[str]:
    return [
        "log",
        "anchor",
        "--dir",
        str(log_dir),
        "--evidence",
        str(evidence),
        "--ots-proof",
        str(ots_proof),
        "--out",
        str(out),
        "--rfc3161-token",
        str(rfc3161_token),
    ]


def test_log_anchor_refuses_every_read_path_on_every_owned_path_and_any_depth_beneath_it(
    tmp_path: Path, capsys: CapSys
) -> None:
    """`--evidence`/`--ots-proof`/`--rfc3161-token` used to be checked
    against only two of the five owned paths, and only by equality --
    `_log_owned_paths`' tile-cache directory member was not in that
    hand-written pair at all, so any of the three landing anywhere under
    `LOG/tile` slipped through entirely. Converting to
    `_reject_if_under_log_owned_path` extends both axes at once: every
    owned path, AND any depth beneath the directory one -- for all three
    read flags, since they go through the identical loop in
    `_cmd_log_anchor`."""
    log_dir = _log_init(tmp_path)
    owned_paths = cli._log_owned_paths(log_dir)

    default_evidence = tmp_path / "default-evidence.json"
    default_ots_proof = tmp_path / "default-ots-proof.json"
    default_token = tmp_path / "default-token.bin"
    default_out = tmp_path / "default-out.json"

    for owned in owned_paths:
        for candidate in (owned, owned / "nested" / "deep" / "x.json"):
            probes: tuple[tuple[str, list[str]], ...] = (
                (
                    "--evidence",
                    _anchor_probe_argv(
                        log_dir,
                        evidence=candidate,
                        ots_proof=default_ots_proof,
                        out=default_out,
                        rfc3161_token=default_token,
                    ),
                ),
                (
                    "--ots-proof",
                    _anchor_probe_argv(
                        log_dir,
                        evidence=default_evidence,
                        ots_proof=candidate,
                        out=default_out,
                        rfc3161_token=default_token,
                    ),
                ),
                (
                    "--rfc3161-token",
                    _anchor_probe_argv(
                        log_dir,
                        evidence=default_evidence,
                        ots_proof=default_ots_proof,
                        out=default_out,
                        rfc3161_token=candidate,
                    ),
                ),
            )
            for label, argv in probes:
                capsys.readouterr()
                rc = cli.main(argv)
                captured = capsys.readouterr()
                assert rc == 2, (label, str(owned), str(candidate), captured.out)
                assert "log's own state" in captured.err, (label, str(owned), str(candidate))


def test_log_anchor_allows_out_outside_the_log_and_strings_that_merely_extend_an_owned_one(
    tmp_path: Path, capsys: CapSys
) -> None:
    """The other direction of the property (mirrors
    `test_issue_log_dir_allows_outputs_whose_path_string_merely_extends_an_owned_one`,
    for the verb this task converts to the shared guard): an `--out` clean
    outside the log directory, and one whose STRING extends an owned path's
    string while being no descendant of it (`Path.parents` compares path
    COMPONENTS, never characters), must both keep working."""
    log_dir = _log_init(tmp_path)
    checkpoint_text = _minimal_anchor_evidence()["checkpoint"]

    def anchor_once(out: Path) -> None:
        evidence = tmp_path / f"evidence-for-{out.name}.json"
        evidence.write_text(json.dumps(_minimal_anchor_evidence()), encoding="utf-8")
        ots_proof = tmp_path / f"ots-proof-for-{out.name}.json"
        ots_proof.write_text(json.dumps(_v2_ots_proof(checkpoint_text)), encoding="utf-8")
        out.parent.mkdir(parents=True, exist_ok=True)

        capsys.readouterr()
        rc = cli.main(
            [
                "log",
                "anchor",
                "--dir",
                str(log_dir),
                "--evidence",
                str(evidence),
                "--ots-proof",
                str(ots_proof),
                "--out",
                str(out),
            ]
        )
        captured = capsys.readouterr()
        assert rc == 0, (str(out), captured.err)
        assert out.exists(), str(out)

    anchor_once(tmp_path / "outside-the-log.json")  # clean outside --dir
    anchor_once(log_dir / "checkpoint.bak")  # extends the checkpoint file's string
    anchor_once(log_dir / "tile-backup" / "out.json")  # extends the tile dir's string
