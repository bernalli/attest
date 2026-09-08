"""Mutant T2(d): every `provenance` entry remapped to "tls" at the boundary.

WHERE IT IS AIMED, AND WHY THAT MOVED

The mutation belongs on `trust_material._store_data`: that is the function
`verify.py` calls to open a snapshot, so patching the module attribute reaches
the consumer. Before T2 that function did not yet occupy the boundary and this
plugin was aimed at `trust_material.trust_store_fields`, the name that held the
place then. T2 removes that name, and a plugin bound to it AT IMPORT TIME dies
with `AttributeError` before a single test runs.

That is worth naming, because it is a class and not an accident: a measuring
instrument bound at import time to the very symbol the work is scheduled to
remove. The defect is one of ORDER — the instrument was built before the thing
it measures — so the transcript from before the flip (`mutant-t2d.log`) does
NOT certify the system after it. This mutant is re-run after the flip, and its
transcript takes a new tag.

WHAT THE MUTANT PROVES, AND ON WHICH FIXTURE

Remapping to "tls" is a no-op on a fixture whose provenance is already "tls" --
the positive pair of section 3 is exactly that, so a mutant run against it
would survive green while looking killed. The vectors that move are the ones
whose provenance is NOT "tls"; the observable is `trust` going from
`unauthenticated_tofu` to `verified` while `ok` stays put.

Nothing in the tree is modified: the mutation lives in this plugin.
"""

from __future__ import annotations

from attest import trust_material

_original = trust_material._store_data


def _mutated(store: object) -> trust_material._StoreData | None:
    """Remap every provenance entry to "tls", preserving everything else.

    `_replace` builds a new tuple: the snapshot's own dictionaries are left
    alone, so what this mutates is what the verifier READS, not what the store
    exports. A mutant that also moved `to_bytes()` would be caught by
    conservation instead of by the property under test.
    """
    data = _original(store)
    if data is None:
        return None
    return data._replace(provenance={key: "tls" for key in data.provenance})


def pytest_configure(config: object) -> None:
    trust_material._store_data = _mutated
