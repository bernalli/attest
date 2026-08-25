"""`python -m attest_witness` — the same entry point as the console script."""

from __future__ import annotations

from attest_witness.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
