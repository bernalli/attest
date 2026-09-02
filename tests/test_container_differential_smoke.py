"""The cross-language gate, run under the suite so it is not optional.

The differential runner is what turns "both implementations agree" from a claim
into a measurement, and a gate that only runs when someone remembers to type it
is a gate that runs on the days nothing is wrong. A short run belongs here; the
long ones belong in CI and in the commands of the plan.

Skipped, loudly, on a machine without the site's dependencies installed: the
TypeScript side is bundled with the site's own esbuild.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools import container_differential

REPO_ROOT = Path(__file__).resolve().parents[1]
ESBUILD = REPO_ROOT / "site" / "node_modules" / ".bin" / "esbuild"


@pytest.mark.skipif(
    not ESBUILD.exists(),
    reason="site/node_modules is absent: run `npm ci --prefix site` to measure the two readers "
    "against each other",
)
def test_the_two_readers_agree_on_generated_archives() -> None:
    assert container_differential.run(count=50, seed=20260902, keep=None) == 0
