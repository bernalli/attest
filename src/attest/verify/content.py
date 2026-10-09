"""Non-fatal payload-content warnings (v0.1 section 11.2), independent of the
crypto pipeline."""

from __future__ import annotations

from typing import Any

from attest import validate
from attest.verify.constants import _KNOWN_EOL_VALUES


def _content_warnings(payload: dict[str, Any]) -> list[str]:
    """Non-fatal, payload-content warnings — independent of the crypto pipeline.

    Unknown top-level fields are compared against the schema's top-level
    `properties` keys only, as specified by v0.1 section 11.2.
    """
    found: list[str] = []

    known_top_level = set(validate.SCHEMA.get("properties", {}))
    for key in payload:
        if key not in known_top_level:
            found.append(f"unknown payload field: {key!r}")

    license_block = payload.get("license")
    if isinstance(license_block, dict) and license_block.get("drm") == "drm-bound":
        found.append("license.drm is drm-bound (design vector 18)")

    survivability = payload.get("survivability")
    if isinstance(survivability, dict):
        eol = survivability.get("end_of_life")
        # `x not in <frozenset>` RAISES on an unhashable x, and the payload is
        # untrusted wire data: a signed receipt carrying
        # `survivability.end_of_life: {}` crashed verify() with a TypeError.
        # Only a string can ever be a registered value, so the type check is
        # also the guard — and it restores parity with verify.ts, which has
        # always written this as `typeof eol !== 'string' || !KNOWN_EOL.has(eol)`.
        if not isinstance(eol, str) or eol not in _KNOWN_EOL_VALUES:
            found.append(f"unknown survivability.end_of_life value: {eol!r}")

    return found
