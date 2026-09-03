"""The fail-closed CI promise has one parser and an executable truth table."""

from __future__ import annotations

import pytest

from tools.ci_required import ci_prerequisites_required


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, False),
        ("", False),
        ("  ", False),
        ("0", False),
        ("false", False),
        (" FALSE ", False),
        ("no", False),
        (" No ", False),
        ("1", True),
        ("true", True),
        (" TRUE ", True),
        ("yes", True),
        ("off", True),
        ("disabled", True),
        ("trueish", True),
    ],
)
def test_ci_prerequisites_required_truth_table(
    monkeypatch: pytest.MonkeyPatch, value: str | None, expected: bool
) -> None:
    if value is None:
        monkeypatch.delenv("ATTEST_CI_REQUIRED", raising=False)
    else:
        monkeypatch.setenv("ATTEST_CI_REQUIRED", value)

    assert ci_prerequisites_required() is expected
