"""attest reference C2SP tlog-witness (v0.2 §11.4).

A witness cosigns checkpoints it has authenticated and found consistent with
the last checkpoint it cosigned for that log. It is deliberately small: every
Merkle and signature primitive comes from the `attest` core, so this package
holds protocol plumbing, durable state and configuration — and nothing a
verifier would have to trust twice.

Never published. See `witness/README.md` for what this is, and is not.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
