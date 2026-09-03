"""Shared interpretation of the test suite's fail-closed CI promise."""

from __future__ import annotations

import os

# Values that leave the fail-closed contract disarmed. Everything else arms
# it, including spellings nobody thought to list.
#
# Refusing an unrecognised spelling outright — rather than reading it as
# "armed" — was considered and deliberately not done here, and the reason is
# worth leaving for whoever revisits this. Such a refusal would have to happen
# ONCE, when the pytest session starts. Put inside a branch that runs only when
# a prerequisite is missing, it would never fire on a complete machine: a job
# setting `ATTEST_CI_REQUIRED=trueish` would sail through every green run and
# only reveal the typo on the day something was already broken. That is a check
# which exists only in the degraded case — precisely the defect this contract
# removes, rebuilt one level down. Whoever adds a second writer for this
# variable should add the session-wide refusal at the same time, not a
# branch-local one.
_NOT_REQUIRED = frozenset({"", "0", "false", "no"})


def ci_prerequisites_required() -> bool:
    """Return whether missing CI-installed prerequisites must fail, not skip."""
    return os.environ.get("ATTEST_CI_REQUIRED", "").strip().lower() not in _NOT_REQUIRED
