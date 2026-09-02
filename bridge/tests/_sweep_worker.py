"""A second PROCESS for the delivery-sweep bench — not a test module.

`test_bridge_concurrency.py` launches this twice to prove that two real
processes sharing one Ledger file cannot deliver the same receipt twice. It
has to be a separate process: the defect it exists to catch is invisible to
any in-process lock, which is exactly how it survived review.

Two modes:

* `sweep <ledger> <tag> <log> <block|run>` — run one delivery sweep with a
  stub mailer. Every attempted send appends one line to the shared log
  (`O_APPEND`, one `write` per line, so the file is a faithful SEQUENCE of
  events and never a set that has already collapsed the duplicates we are
  hunting). In `block` mode the send parks inside the sweep — and therefore
  inside the lock — until the parent writes a line to stdin.
* `hold-lock <path>` — take the sweep lock and hold it until killed, for the
  "a dead process must not leave the lock held" case.

Progress markers go to stdout, one line each, flushed: the parent reads them
to know exactly where this process is, which is what makes the bench free of
synchronisation sleeps.
"""

from __future__ import annotations

import fcntl
import os
import sys
from typing import Any

from attest_bridge.delivery import DeliveryResult, sweep_undelivered
from attest_bridge.ledger import Ledger


def _say(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _append(log_path: str, line: str) -> None:
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (line + "\n").encode())
    finally:
        os.close(fd)


class _StubMailer:
    """Stands in for `Delivery` — the bench is about the sweep, not SMTP."""

    def __init__(self, tag: str, log_path: str, block: bool) -> None:
        self._tag = tag
        self._log_path = log_path
        self._block = block

    def send(self, **kwargs: Any) -> DeliveryResult:
        _append(self._log_path, f"{self._tag}:SEND-START {kwargs['receipt_id']}")
        if self._block:
            _say(f"{self._tag}:IN-SEND")
            sys.stdin.readline()
        _append(self._log_path, f"{self._tag}:SEND-END")
        return DeliveryResult(status="sent", detail=None)


def _sweep(ledger_path: str, tag: str, log_path: str, mode: str) -> None:
    ledger = Ledger(_path(ledger_path))
    _say(f"{tag}:BEFORE-SWEEP")
    delivered, failed = sweep_undelivered(
        ledger=ledger,
        delivery=_StubMailer(tag, log_path, mode == "block"),  # type: ignore[arg-type]
        public_base_url="https://receipts.example.com",
    )
    _say(f"{tag}:AFTER-SWEEP delivered={delivered} failed={failed}")


def _hold_lock(lock_path: str) -> None:
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    _say("HELD")
    while True:  # killed by the parent; the kernel releases the lock with the fd
        sys.stdin.readline()


def _path(value: str) -> Any:
    from pathlib import Path

    return Path(value)


def main(argv: list[str]) -> int:
    if argv[1] == "sweep":
        _sweep(argv[2], argv[3], argv[4], argv[5])
        return 0
    if argv[1] == "hold-lock":
        _hold_lock(argv[2])
        return 0
    raise SystemExit(f"unknown mode {argv[1]!r}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
