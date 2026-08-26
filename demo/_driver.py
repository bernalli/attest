"""demo/_driver.py — the shared CLI driver helpers used by the attest demos."""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from pathlib import Path
from typing import Any

from attest import cli


def narrate(message: str) -> None:
    print(f"\n--- {message} ---")


def verb_label(argv: list[str]) -> str:
    """The human-readable verb name for error messages: the leading
    non-flag tokens, e.g. `['manifest', 'init', '--issuer', ...]` ->
    `'manifest init'`, `['issue', '--payload', ...]` -> `'issue'`."""
    parts: list[str] = []
    for token in argv:
        if token.startswith("-"):
            break
        parts.append(token)
    return " ".join(parts) if parts else argv[0]


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Call `attest.cli.main` exactly as a real operator's shell would invoke
    the installed `attest` binary, returning `(exit_code, stdout, stderr)`.

    `cli.main` only returns an exit code — its status result is the JSON it
    prints to stdout, and its errors go to stderr — so both streams are
    captured (to let the demo assert on outcomes and surface failure causes)
    while still being forwarded to the real stdout/stderr, so the printed
    JSON and any error remain part of the narration exactly as they would
    from a real terminal session.
    """
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
        rc = cli.main(argv)
    stdout = out_buf.getvalue()
    stderr = err_buf.getvalue()
    sys.stdout.write(stdout)
    sys.stderr.write(stderr)
    return rc, stdout, stderr


def run_cli_json(argv: list[str]) -> dict[str, Any]:
    """Run a setup verb that MUST succeed and return its stdout JSON object.

    The exit code is checked BEFORE parsing stdout: a failed verb writes its
    cause to stderr and leaves stdout empty, so parsing first would raise a
    bare `json.JSONDecodeError` one line early and lose the real cause. On
    any nonzero exit this raises a `RuntimeError` naming the verb and
    carrying the CLI's own stderr message.
    """
    rc, stdout, stderr = run_cli(argv)
    verb = verb_label(argv)
    if rc != 0:
        raise RuntimeError(f"demo step failed: `attest {verb}` exited {rc}: {stderr.strip()}")
    result = json.loads(stdout)
    if not isinstance(result, dict):
        raise RuntimeError(f"expected a JSON object from `attest {verb}`, got: {stdout!r}")
    return result


def run_cli_capture(argv: list[str]) -> tuple[int, dict[str, Any]]:
    """Run a verb whose nonzero exit is a legitimate, designed outcome
    (`verify` concluding not-ok, `check-artifact` finding no match) rather
    than an error: these print their JSON result to stdout *even on a
    nonzero exit*, so the demo captures both the exit code and the parsed
    result to assert on, instead of raising.
    """
    rc, stdout, _stderr = run_cli(argv)
    result = json.loads(stdout)
    if not isinstance(result, dict):
        verb = verb_label(argv)
        raise RuntimeError(f"expected a JSON object from `attest {verb}`, got: {stdout!r}")
    return rc, result


def write_secret_text(path: Path, text: str) -> None:
    """Write real secret material (Casey's buyer-binding salt) 0600 from
    creation, mirroring `cli._write_secret_text`/`bundle._write_secret_json`
    — this is genuine buyer-binding secret material, not demo scaffolding,
    so it gets the same owner-only treatment the CLI gives its own secrets."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(text)
