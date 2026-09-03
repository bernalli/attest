"""The cross-language gate, run under the suite so it is not optional.

The differential runner is what turns "both implementations agree" from a claim
into a measurement, and a gate that only runs when someone remembers to type it
is a gate that runs on the days nothing is wrong. A short run belongs here; the
long ones belong in CI and in the commands of the plan.

Without the site's dependencies the gate cannot run at all, and what that
absence means depends on where it happens. On a developer's machine it is a
courtesy: install them and the measurement comes back. In CI it is a defect,
because nothing there installs anything by accident — an absent dependency
means the job never provided it, and the skip then takes the place of the
measurement in a total where one skip among four thousand passes reads exactly
like a test that ran. So the same missing file is a skip in one place and a
failure in the other.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools import container_differential
from tools.ci_required import ci_prerequisites_required

REPO_ROOT = Path(__file__).resolve().parents[1]
ESBUILD = REPO_ROOT / "site" / "node_modules" / ".bin" / "esbuild"

_ABSENT = (
    "the site's esbuild is absent: install Node.js >=20, then run "
    "`npm ci --prefix site` to measure the two readers against each other"
)


def test_the_two_readers_agree_on_generated_archives() -> None:
    if not ESBUILD.exists():
        # The job that promised the dependency is the one that opts in, by
        # name. A generic `CI` would be the wrong signal in both directions:
        # `CI=false` and `CI=0` are both truthy read this way, and every other
        # runner that exports `CI` would inherit an obligation nobody made it.
        # Any spelling but an explicitly negative one arms the contract:
        # measured, `ATTEST_CI_REQUIRED=true` silently disarmed an `== "1"`
        # test, and a job added later would write exactly that. Failing on a
        # spelling nobody meant as "off" is a loud error; skipping on one
        # meant as "on" is the silence this whole change exists to remove.
        if ci_prerequisites_required():
            pytest.fail(_ABSENT)
        pytest.skip(_ABSENT)
    assert container_differential.run(count=50, seed=20260902, keep=None) == 0
