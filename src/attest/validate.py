"""JSON Schema (draft 2020-12) validation of attest payloads."""

from __future__ import annotations

import importlib.resources
import json
from typing import Any

import jsonschema

from attest import canon
from attest.ulid import RECEIPT_ID_RE

with (
    importlib.resources.files("attest.schema")
    .joinpath("attest-receipt.schema.json")
    .open("rb") as f
):
    SCHEMA: dict[str, Any] = json.load(f)

# Keep the standalone schema artifact intact, but bind both runtime rules to
# the Python owner. Preserve JSON Schema's pattern/search semantics and errors.
for _receipt_id_member in ("receipt_id", "supersedes"):
    SCHEMA["properties"][_receipt_id_member]["pattern"] = RECEIPT_ID_RE.pattern

_VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def validate_payload(payload: object) -> list[str]:
    """Validate `payload` against the attest v0.1 receipt schema.

    Returns an empty list when valid; otherwise one human-readable violation
    per schema error, sorted by JSON path for deterministic output.
    """
    return [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in sorted(_VALIDATOR.iter_errors(payload), key=lambda e: list(e.absolute_path))
    ]


# --- G1 normative ceilings (attest-versioning.md §5 amendment; v0.1 §11/§15,
# v0.2 §6/§16) — conformance-surface structural bounds a conforming verifier
# MUST enforce, independent of and in addition to the payload-shape schema
# check above.

MAX_ENVELOPE_BYTES = 1_048_576  # raw, undecoded envelope size ceiling; checked by
# verify.py before any parsing work, on the untrusted bytes it bounds.

# Nesting-depth ceiling (2026-07-22 fix wave): an alias of `canon.MAX_DEPTH`,
# never a second, smaller value. `canon.loads_strict` already rejects any
# input nested deeper than this during parsing (`CanonError`, "maximum
# nesting depth exceeded") — a parsed tree therefore can never exceed it, so
# this module does NOT define its own `validate_json_depth`-style walk of
# the parsed tree: that check was proven byte-for-byte redundant with
# `canon.py`'s own enforcement (it never guards a path canon.py doesn't
# already cover) and was deleted rather than kept as dead code. The name is
# kept as a public alias, at the single source-of-truth value, because the
# spec (v0.1 §11.3) and tests reference `validate.MAX_JSON_DEPTH` as the
# name of the conformance-surface ceiling even though its enforcement lives
# entirely in `canon.py`.
MAX_JSON_DEPTH = canon.MAX_DEPTH


def validate_envelope_size(envelope_bytes: bytes) -> list[str]:
    """The raw envelope MUST NOT exceed `MAX_ENVELOPE_BYTES`. Checked on the
    undecoded bytes, before any parsing work — the cheapest possible check,
    run first, on input a hostile sender fully controls the size of.
    """
    if len(envelope_bytes) > MAX_ENVELOPE_BYTES:
        return [f"envelope exceeds {MAX_ENVELOPE_BYTES} bytes"]
    return []
