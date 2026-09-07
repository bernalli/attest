"""Mutant T2(d), run against today's boundary to MEASURE which vectors move.

The plan's mutant rewrites `_store_data` so that every `provenance` entry is
remapped to "tls". `_store_data` does not exist yet, so the mutation is applied
to the function that occupies its place today: `trust_material.trust_store_fields`
is where a store's five fields are handed to the verifier, and `verify.py:336` is
its only caller, reached through the module attribute — so patching the module
reaches the consumer.

The point of running it is that the plan must NAME the vectors the mutant moves,
and the names have to come from an execution. A previous revision asserted
instead that "the vector tests do not read provenance"; they do.

Nothing in the tree is modified: the mutation lives in this plugin.
"""

from __future__ import annotations

from typing import Any

from attest import trust_material

_original = trust_material.trust_store_fields


def _mutated(store: object) -> dict[str, Any]:
    """Remap every provenance entry to "tls", preserving everything else."""
    fields = _original(store)
    provenance = fields.get("provenance")
    if isinstance(provenance, dict):
        fields["provenance"] = {key: "tls" for key in provenance}
    return fields


def pytest_configure(config: object) -> None:
    trust_material.trust_store_fields = _mutated  # type: ignore[assignment]
