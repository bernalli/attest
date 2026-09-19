"""Tests for how the ablation bench classifies a mutated suite run.

Every expected classification below is written from what the classification
means for the bench, never computed by calling `classify()` and never by
restating its matching code:

* `KILLED`: the suite went red from the assertion of a test the property names
  in `expect_red`;
* `KILLED_ELSEWHERE`: the suite went red, but none of the named tests did;
* `SURVIVED`: the mutation landed and every test stayed green;
* `BROKEN`: the run measured less than it appears to. Every red is a form error
  (a broken name, import or type, which never reaches the invariant), or a test
  that ran at baseline was skipped under the mutation;
* an `expect_red` entry names a pytest test exactly, parameters excluded, and is
  a fragment of the full name for a vitest test.

Where a malformed record has no documented classification, the test pins only
that one of the bench's classifications is produced without an exception.

Property cases come from a fixed seed. Each generator builds its case so that
the expected classification holds by construction, not by inspection.
"""

from __future__ import annotations

import random
from collections.abc import Iterable, Sequence
from typing import Any

import pytest

from tools.gates.ablation.classify import IncoherentOutcomes, classify, validate_outcomes

CLASSIFICATIONS = frozenset(
    {"BASELINE_RED", "NOT_APPLIED", "BROKEN", "KILLED", "KILLED_ELSEWHERE", "SURVIVED"}
)

SEED = 20260917
ITERATIONS = 400

TEST_NAMES = (
    "test_guard",
    "test_refuses",
    "test_admits",
    "test_orders",
    "test_bounds",
    "test_nests",
)
MODULES = ("tests/test_a.py", "tests/sub/test_b.py")
CLASS_PREFIXES = ("", "TestSuite::")
PARAMETERS = ("", "[0]", "[a-b]", "[x[y]]", "[True-revoked]")
NAME_SUFFIXES = ("_bar", "_extra", "2", "_v2")
# The outcomes plugin records the exception class, prefixed by the phase when the
# error happened outside the test call.
FORM_ERRORS = ("NameError", "ImportError", "TypeError", "setup:NameError", "setup:ImportError")
ANY_REASON = ("AssertionError", "Failed", "unknown", *FORM_ERRORS)

TOO_MANY_SKIPS = "n_skipped exceeds collected_and_run"
FAILURES_WITHOUT_RUN = "failures reported with collected_and_run == 0"
COUNT_MISMATCH = "n_failed does not match len(failed)"
DUPLICATE_FAILURES = "duplicate names in failed"
PROPERTY_TOKENS = (TOO_MANY_SKIPS, FAILURES_WITHOUT_RUN, COUNT_MISMATCH, DUPLICATE_FAILURES)
MALFORMED = "malformed"


def _record(
    failed: Iterable[str] = (),
    *,
    why: dict[str, str] | None = None,
    collected: int = 3,
    skipped: int = 0,
    omit: Iterable[str] = (),
) -> dict[str, Any]:
    """Build one synthetic outcome record in the shape the outcomes plugin writes.

    Every failed test is an `AssertionError` unless `why` says otherwise.
    """
    names = list(failed)
    record: dict[str, Any] = {
        "exitstatus": 1 if names else 0,
        "collected_and_run": collected,
        "n_passed": collected - len(names) - skipped,
        "n_skipped": skipped,
        "n_failed": len(names),
        "failed": names,
        "why": {name: "AssertionError" for name in names} if why is None else why,
        "collect_errors": [],
    }
    for key in omit:
        del record[key]
    return record


def _refused_properties(record: dict[str, Any], label: str) -> set[str] | None:
    """Return the properties a refusal names, or None when the record is accepted."""
    try:
        validate_outcomes(record, label=label)
    except IncoherentOutcomes as exc:
        message = str(exc)
        assert message.startswith(f"{label}: "), message
        return {token for token in (*PROPERTY_TOKENS, MALFORMED) if token in message}
    return None


def _node(rng: random.Random, name: str) -> str:
    """A pytest node id for the test `name`, with a random module, class and parameters."""
    return f"{rng.choice(MODULES)}::{rng.choice(CLASS_PREFIXES)}{name}{rng.choice(PARAMETERS)}"


def _distinct_nodes(rng: random.Random, names: Sequence[str], count: int) -> list[str]:
    """Up to `count` distinct node ids, each for a test name drawn from `names`."""
    nodes = [_node(rng, rng.choice(names)) for _ in range(count)]
    return list(dict.fromkeys(nodes))


def _expect(rng: random.Random, *, minimum: int) -> list[str]:
    """An `expect_red` list: bare test names, possibly repeated."""
    return [rng.choice(TEST_NAMES) for _ in range(rng.randint(minimum, 3))]


def _not_named(expect: Sequence[str]) -> list[str]:
    """Test names whose name, parameters excluded, is not in `expect`.

    Includes names that contain a named test as a prefix or as a suffix, which a
    substring or suffix match would wrongly count as the named test.
    """
    unrelated = [name for name in TEST_NAMES if name not in expect]
    lookalikes = [name + suffix for name in expect for suffix in NAME_SUFFIXES]
    lookalikes += ["re" + name for name in expect]
    return unrelated + lookalikes


# Synthetic records for cases a real run has produced or can produce.


def test_expected_green_sibling_red() -> None:
    """A red sibling while the named test stays green is a red elsewhere."""
    result = classify(_record(), _record(["tests/t.py::test_other"]), ["test_guard"])
    assert result["verdict"] == "KILLED_ELSEWHERE"


def test_prefix_collision() -> None:
    """A red test whose name only starts with the named test's name is not that test."""
    result = classify(_record(), _record(["tests/t.py::test_guard_extra"]), ["test_guard"])
    assert result["verdict"] == "KILLED_ELSEWHERE"


def test_parameterized_expected_red() -> None:
    """A parameterized run of the named test going red is a kill."""
    result = classify(_record(), _record(["tests/t.py::test_guard[param]"]), ["test_guard"])
    assert result["verdict"] == "KILLED"


def test_all_skipped() -> None:
    """A suite that skips every test under the mutation measured nothing: not a survivor."""
    result = classify(_record(), _record(skipped=3), [])
    assert result["verdict"] == "BROKEN"


def test_records_of_the_named_cases_are_coherent() -> None:
    """The records above describe runs that can happen, so the validator accepts them."""
    for record in (
        _record(),
        _record(["tests/t.py::test_other"]),
        _record(["tests/t.py::test_guard_extra"]),
        _record(["tests/t.py::test_guard[param]"]),
        _record(skipped=3),
    ):
        assert _refused_properties(record, "named case") is None


# Malformed and edge records.


def test_incoherent_outcomes_is_a_value_error() -> None:
    """Callers that handle ValueError also handle a refused record."""
    assert issubclass(IncoherentOutcomes, ValueError)


def test_validate_refuses_duplicate_failed_names() -> None:
    """A run cannot report the same test red twice."""
    record = _record(["tests/t.py::test_guard", "tests/t.py::test_guard"])
    assert _refused_properties(record, "M1 mutated") == {DUPLICATE_FAILURES}


def test_validate_accepts_distinct_parameter_sets_of_one_test() -> None:
    """Two parameter sets of one test are two tests, not a duplicate."""
    record = _record(["tests/t.py::test_guard[a]", "tests/t.py::test_guard[b]"])
    assert _refused_properties(record, "M1 mutated") is None


def test_classify_on_duplicate_failed_names_does_not_raise() -> None:
    """The documented classifications say nothing about a duplicated red name."""
    record = _record(["tests/t.py::test_guard", "tests/t.py::test_guard"])
    assert classify(_record(), record, ["test_guard"])["verdict"] in CLASSIFICATIONS


@pytest.mark.parametrize(
    ("failed", "expected"),
    [
        pytest.param(
            ["tests/t.py::test_guard[a]", "tests/t.py::test_guard[b]"],
            "KILLED",
            id="several-parameter-sets",
        ),
        pytest.param(["tests/t.py::TestSuite::test_guard[x-1]"], "KILLED", id="method-in-class"),
        pytest.param(["tests/t.py::test_guard[c[d]]"], "KILLED", id="bracket-in-parameters"),
        pytest.param(
            ["tests/t.py::test_guard_extra[a]"],
            "KILLED_ELSEWHERE",
            id="longer-name-with-parameters",
        ),
        pytest.param(
            ["tests/t.py::test_other[test_guard]"],
            "KILLED_ELSEWHERE",
            id="named-test-only-inside-parameters",
        ),
        pytest.param(
            ["tests/t.py::test_guard[a::b]"],
            "KILLED",
            id="double-colon-in-parameters",
            marks=pytest.mark.xfail(
                strict=True,
                raises=AssertionError,
                reason=(
                    "pytest keeps '::' verbatim inside a parameter id; splitting the node id "
                    "on its last '::' drops the test name, so a red of the named test is "
                    "classified as a red elsewhere"
                ),
            ),
        ),
    ],
)
def test_parameterized_names_match_on_the_test_name_alone(failed: list[str], expected: str) -> None:
    """A pytest `expect_red` entry names the test exactly, parameters excluded."""
    assert classify(_record(), _record(failed), ["test_guard"])["verdict"] == expected


@pytest.mark.parametrize(
    ("failed", "expected"),
    [
        pytest.param(["verifier > refuses an oversize member"], "KILLED", id="fragment-present"),
        pytest.param(
            ["verifier > admits a small member"], "KILLED_ELSEWHERE", id="fragment-absent"
        ),
    ],
)
def test_vitest_full_names_match_on_a_fragment(failed: list[str], expected: str) -> None:
    """A vitest `expect_red` entry is a fragment of the test's full name."""
    result = classify(_record(), _record(failed), ["refuses an oversize member"])
    assert result["verdict"] == expected


@pytest.mark.parametrize("missing", ["entry", "whole-map"])
def test_missing_failure_reason_still_classifies(missing: str) -> None:
    """A red whose reason was not recorded has no documented classification.

    Pinned: a classification is produced, and a red that does not include a
    named test is still never a kill.
    """
    omit = ("why",) if missing == "whole-map" else ()
    named = _record(["tests/t.py::test_guard"], why={}, omit=omit)
    assert classify(_record(), named, ["test_guard"])["verdict"] in CLASSIFICATIONS

    sibling = _record(["tests/t.py::test_other"], why={}, omit=omit)
    verdict = classify(_record(), sibling, ["test_guard"])["verdict"]
    assert verdict in CLASSIFICATIONS
    assert verdict != "KILLED"


def test_absent_skip_counts_on_a_green_run_survive() -> None:
    """A runner that does not count skips: a green run under the mutation survived."""
    baseline = _record(omit=("n_skipped",))
    mutated = _record(omit=("n_skipped",))
    assert classify(baseline, mutated, ["test_guard"])["verdict"] == "SURVIVED"


def test_absent_skip_counts_do_not_hide_a_kill() -> None:
    """Without skip counts, the named test red by its assertion is still a kill."""
    baseline = _record(omit=("n_skipped",))
    mutated = _record(["tests/t.py::test_guard"], omit=("n_skipped",))
    assert classify(baseline, mutated, ["test_guard"])["verdict"] == "KILLED"


@pytest.mark.parametrize("side", ["baseline", "mutated"])
def test_skip_count_absent_on_one_side_still_classifies(side: str) -> None:
    """A skip count on one record only has no documented classification."""
    counted = _record(skipped=1)
    uncounted = _record(omit=("n_skipped",))
    baseline, mutated = (uncounted, counted) if side == "baseline" else (counted, uncounted)
    assert classify(baseline, mutated, [])["verdict"] in CLASSIFICATIONS


def test_validate_accepts_a_record_without_skip_count() -> None:
    """A property that compares a missing field is not checked."""
    assert _refused_properties(_record(omit=("n_skipped",)), "vitest mutated") is None


def test_validate_refuses_more_skips_than_collected() -> None:
    """A run cannot skip more tests than it collected."""
    assert _refused_properties(_record(collected=2, skipped=3), "M2 baseline") == {TOO_MANY_SKIPS}


def test_validate_accepts_every_collected_test_skipped() -> None:
    """Skipping exactly what was collected is a possible run."""
    assert _refused_properties(_record(collected=3, skipped=3), "M2 mutated") is None


def test_validate_refuses_failures_when_nothing_ran() -> None:
    """A run that ran nothing cannot fail anything."""
    record = _record(["tests/t.py::test_guard"], collected=0)
    assert _refused_properties(record, "M3 mutated") == {FAILURES_WITHOUT_RUN}


def test_validate_accepts_nothing_run_and_nothing_failed() -> None:
    """An empty run is coherent; whether it measured anything is not this check's question."""
    assert _refused_properties(_record(collected=0), "M3 mutated") is None


def test_validate_refuses_a_failure_count_that_differs_from_the_names() -> None:
    """`n_failed` and the list of failed names describe the same run."""
    record = _record(["tests/t.py::test_guard"])
    record["n_failed"] = 2
    assert _refused_properties(record, "M4 mutated") == {COUNT_MISMATCH}


@pytest.mark.parametrize("omitted", ["collected_and_run", "n_failed", "failed", "collect_errors"])
def test_validate_refuses_a_record_missing_a_field_classify_reads(omitted: str) -> None:
    """Without a field the classification reads, the record describes no run it can classify."""
    record = _record(["tests/t.py::test_guard"], omit=(omitted,))
    assert _refused_properties(record, "M4 mutated") == {MALFORMED}


def test_validate_accepts_a_record_without_failure_reasons() -> None:
    """`why` is optional: a red whose reason was not recorded is still a coherent record."""
    assert _refused_properties(_record(["tests/t.py::test_guard"], omit=("why",)), "M4") is None


def test_validate_refuses_a_record_that_is_not_an_object() -> None:
    """An outcomes file holding a list is not a record of a run."""
    assert _refused_properties([], "M4 mutated") == {MALFORMED}  # type: ignore[arg-type]


def test_validate_names_every_violated_property_in_one_refusal() -> None:
    """All four properties violated at once are all named, after the label."""
    record = _record(["tests/t.py::test_guard", "tests/t.py::test_guard"], collected=0, skipped=1)
    record["n_failed"] = 5
    assert _refused_properties(record, "M5 mutated") == set(PROPERTY_TOKENS)


@pytest.mark.parametrize(
    ("failed", "expected"),
    [
        pytest.param([], "SURVIVED", id="green"),
        pytest.param(["tests/t.py::test_guard"], "KILLED", id="named-test-red"),
        pytest.param(["tests/t.py::test_other"], "KILLED_ELSEWHERE", id="sibling-red"),
    ],
)
def test_duplicate_expect_red_entries(failed: list[str], expected: str) -> None:
    """Naming a test twice names the same test: the classification is the documented one."""
    result = classify(_record(), _record(failed), ["test_guard", "test_guard"])
    assert result["verdict"] == expected


@pytest.mark.xfail(
    strict=True,
    reason=(
        "a kill is a red from the named test's own assertion, and a NameError is not a kill; "
        "here the named test is red only through a NameError and the only assertion red is "
        "an unnamed sibling, yet the red is classified as a kill"
    ),
)
def test_named_test_red_only_through_a_form_error_is_not_a_kill() -> None:
    """The named test crashing on a broken name while a sibling asserts is not a kill."""
    mutated = _record(
        ["tests/t.py::test_guard", "tests/t.py::test_other"],
        why={"tests/t.py::test_guard": "NameError", "tests/t.py::test_other": "AssertionError"},
    )
    assert classify(_record(), mutated, ["test_guard"])["verdict"] != "KILLED"


def test_collection_errors_are_broken_whatever_went_red() -> None:
    """A mutation that breaks collection never reached the property: not a kill, not a survivor."""
    for failed in ([], ["tests/t.py::test_guard"]):
        mutated = _record(failed)
        mutated["collect_errors"] = ["tests/t.py"]
        assert classify(_record(), mutated, ["test_guard"])["verdict"] == "BROKEN", failed


@pytest.mark.parametrize("baseline_collected", [0, 3])
def test_a_run_that_ran_nothing_is_broken(baseline_collected: int) -> None:
    """Zero tests run measures nothing, whatever the baseline ran."""
    baseline = _record(collected=baseline_collected)
    assert classify(baseline, _record(collected=0), ["test_guard"])["verdict"] == "BROKEN"


def test_tests_that_disappeared_under_the_mutation_are_broken() -> None:
    """Fewer tests ran than at baseline: the run measured less, green or red."""
    for failed in ([], ["tests/t.py::test_guard"]):
        mutated = _record(failed, collected=2)
        assert classify(_record(collected=3), mutated, ["test_guard"])["verdict"] == "BROKEN"


@pytest.mark.parametrize("reason", ["TypeError", "AttributeError"])
def test_a_property_declared_as_a_crash_is_killed_by_the_crash(reason: str) -> None:
    """With `property_red_is_crash` the crash is the property's red; without it, a form break."""
    mutated = _record(["tests/t.py::test_guard"], why={"tests/t.py::test_guard": reason})
    assert classify(_record(), mutated, ["test_guard"], red_is_crash=True)["verdict"] == "KILLED"
    assert classify(_record(), mutated, ["test_guard"])["verdict"] == "BROKEN"


def test_a_vitest_red_that_is_only_a_form_error_is_broken() -> None:
    """The vitest runner records a form error as `FormError(<marker>)`: never a kill."""
    name = "verifier > refuses an oversize member"
    mutated = _record([name], why={name: "FormError(is not a function)"})
    assert classify(_record(), mutated, ["refuses an oversize member"])["verdict"] == "BROKEN"


# Properties over generated records.


def test_property_green_run_without_gained_skips_survives() -> None:
    """Nothing red and no test skipped that ran at baseline: always a survivor."""
    rng = random.Random(SEED)  # noqa: S311 -- reproducible case generation, not cryptography
    for case in range(ITERATIONS):
        collected = rng.randint(1, 40)
        baseline_skips = rng.randint(0, collected)
        mutated_skips = rng.randint(0, baseline_skips)
        baseline = _record(collected=collected, skipped=baseline_skips)
        mutated = _record(collected=collected, skipped=mutated_skips)
        expect = _expect(rng, minimum=0)
        assert _refused_properties(baseline, "baseline") is None
        assert _refused_properties(mutated, "mutated") is None
        verdict = classify(baseline, mutated, expect)["verdict"]
        assert verdict == "SURVIVED", (case, baseline, mutated, expect, verdict)


def test_property_green_run_with_gained_skips_is_broken() -> None:
    """Nothing red but a test skipped that ran at baseline: never a survivor."""
    rng = random.Random(SEED + 1)  # noqa: S311 -- reproducible case generation, not cryptography
    for case in range(ITERATIONS):
        collected = rng.randint(1, 40)
        baseline_skips = rng.randint(0, collected - 1)
        mutated_skips = rng.randint(baseline_skips + 1, collected)
        baseline = _record(collected=collected, skipped=baseline_skips)
        mutated = _record(collected=collected, skipped=mutated_skips)
        expect = _expect(rng, minimum=0)
        verdict = classify(baseline, mutated, expect)["verdict"]
        assert verdict == "BROKEN", (case, baseline, mutated, expect, verdict)


def test_property_red_without_a_named_test_is_never_a_kill() -> None:
    """A red that contains none of the named tests is never a kill.

    With every red an assertion it is exactly a red elsewhere; with any mix of
    recorded reasons it is still not a kill.
    """
    rng = random.Random(SEED + 2)  # noqa: S311 -- reproducible case generation, not cryptography
    for case in range(ITERATIONS):
        expect = _expect(rng, minimum=1)
        failed = _distinct_nodes(rng, _not_named(expect), rng.randint(1, 5))
        collected = len(failed) + rng.randint(0, 5)
        baseline = _record(collected=collected)

        asserted = _record(failed, collected=collected)
        verdict = classify(baseline, asserted, expect)["verdict"]
        assert verdict == "KILLED_ELSEWHERE", (case, failed, expect, verdict)

        reasons = {name: rng.choice(ANY_REASON) for name in failed if rng.random() < 0.8}
        mixed = _record(failed, why=reasons, collected=collected)
        verdict = classify(baseline, mixed, expect)["verdict"]
        assert verdict in CLASSIFICATIONS, (case, failed, reasons, expect, verdict)
        assert verdict != "KILLED", (case, failed, reasons, expect, verdict)


def test_property_a_longer_name_does_not_turn_a_red_elsewhere_into_a_kill() -> None:
    """Adding a red named `<named test><suffix>` leaves a red elsewhere a red elsewhere."""
    rng = random.Random(SEED + 3)  # noqa: S311 -- reproducible case generation, not cryptography
    for case in range(ITERATIONS):
        expect = _expect(rng, minimum=1)
        unrelated_only = [name for name in TEST_NAMES if name not in expect]
        failed = _distinct_nodes(rng, unrelated_only, rng.randint(1, 4))
        collected = len(failed) + 1 + rng.randint(0, 5)
        baseline = _record(collected=collected)

        before = classify(baseline, _record(failed, collected=collected), expect)["verdict"]
        assert before == "KILLED_ELSEWHERE", (case, failed, expect, before)

        lookalike = _node(rng, rng.choice(expect) + rng.choice(NAME_SUFFIXES))
        after_failed = [*failed, lookalike]
        after = classify(baseline, _record(after_failed, collected=collected), expect)["verdict"]
        assert after != "KILLED", (case, after_failed, expect, after)
        assert after == "KILLED_ELSEWHERE", (case, after_failed, expect, after)


def test_property_a_named_test_red_by_its_assertion_is_a_kill() -> None:
    """A named test red by its own assertion is a kill, whatever else went red or was skipped."""
    rng = random.Random(SEED + 4)  # noqa: S311 -- reproducible case generation, not cryptography
    for case in range(ITERATIONS):
        expect = _expect(rng, minimum=1)
        hit = _node(rng, rng.choice(expect))
        pool = list(TEST_NAMES) + _not_named(expect)
        siblings = [node for node in _distinct_nodes(rng, pool, rng.randint(0, 4)) if node != hit]
        failed = [hit, *siblings]
        reasons = {hit: "AssertionError"}
        reasons.update({node: rng.choice(ANY_REASON) for node in siblings})
        spare = rng.randint(0, 5)
        collected = len(failed) + spare
        baseline = _record(collected=collected)
        mutated = _record(failed, why=reasons, collected=collected, skipped=rng.randint(0, spare))
        verdict = classify(baseline, mutated, expect)["verdict"]
        assert verdict == "KILLED", (case, failed, reasons, expect, verdict)


def test_property_a_red_made_only_of_form_errors_is_broken() -> None:
    """Every red a form error: broken, even when the red tests are the named ones."""
    rng = random.Random(SEED + 5)  # noqa: S311 -- reproducible case generation, not cryptography
    for case in range(ITERATIONS):
        expect = _expect(rng, minimum=0)
        pool = list(TEST_NAMES) + _not_named(expect)
        failed = _distinct_nodes(rng, pool, rng.randint(1, 5))
        reasons = {node: rng.choice(FORM_ERRORS) for node in failed}
        collected = len(failed) + rng.randint(0, 5)
        baseline = _record(collected=collected)
        mutated = _record(failed, why=reasons, collected=collected)
        verdict = classify(baseline, mutated, expect)["verdict"]
        assert verdict == "BROKEN", (case, failed, reasons, expect, verdict)


def test_property_validate_refuses_exactly_the_violated_properties() -> None:
    """Each generated record violates a chosen subset of the four properties, and only those."""
    rng = random.Random(SEED + 6)  # noqa: S311 -- reproducible case generation, not cryptography
    for case in range(ITERATIONS):
        too_many_skips = rng.random() < 0.5
        failures_without_run = rng.random() < 0.5
        count_mismatch = rng.random() < 0.5
        duplicates = rng.random() < 0.5

        needs_failures = failures_without_run or duplicates
        failed = _distinct_nodes(rng, TEST_NAMES, rng.randint(1 if needs_failures else 0, 4))
        if duplicates:
            failed.append(rng.choice(failed))
        if failures_without_run:
            collected = 0
        else:
            collected = rng.randint(1 if failed else 0, 20)
        if too_many_skips:
            skipped = collected + rng.randint(1, 3)
        else:
            skipped = rng.randint(0, collected)

        record = _record(failed, collected=collected, skipped=skipped)
        if count_mismatch:
            record["n_failed"] = len(failed) + rng.randint(1, 3)

        chosen = {
            token
            for token, flag in (
                (TOO_MANY_SKIPS, too_many_skips),
                (FAILURES_WITHOUT_RUN, failures_without_run),
                (COUNT_MISMATCH, count_mismatch),
                (DUPLICATE_FAILURES, duplicates),
            )
            if flag
        }
        refused = _refused_properties(record, f"case {case}")
        if chosen:
            assert refused == chosen, (case, record, chosen, refused)
        else:
            assert refused is None, (case, record, refused)


def test_property_validate_refuses_a_wrongly_typed_field_by_name() -> None:
    """A field of the wrong type, or a negative count, is refused as malformed and never raises."""
    rng = random.Random(SEED + 8)  # noqa: S311 -- reproducible case generation, not cryptography
    counts = ("collected_and_run", "n_failed", "n_skipped")
    name_lists = ("failed", "collect_errors")
    bad_counts: tuple[Any, ...] = (None, "3", 1.0, -1, True, [], {})
    bad_lists: tuple[Any, ...] = (None, "tests/t.py::test_guard", 3, {"a": "b"}, [None], [["x"]])
    bad_why: tuple[Any, ...] = (None, "AssertionError", [], {"tests/t.py::test_guard": None})
    for case in range(ITERATIONS):
        failed = _distinct_nodes(rng, TEST_NAMES, rng.randint(0, 3))
        record = _record(failed, collected=rng.randint(3, 8))
        field = rng.choice((*counts, *name_lists, "why"))
        if field in counts:
            record[field] = rng.choice(bad_counts)
        elif field in name_lists:
            record[field] = rng.choice(bad_lists)
        else:
            record[field] = rng.choice(bad_why)
        refused = _refused_properties(record, f"case {case}")
        assert refused == {MALFORMED}, (case, field, record[field], refused)


def test_property_classify_never_raises_on_arbitrary_records() -> None:
    """Records with the documented keys, coherent or not, always get a classification."""
    rng = random.Random(SEED + 7)  # noqa: S311 -- reproducible case generation, not cryptography
    for case in range(ITERATIONS):
        records = []
        for _side in ("baseline", "mutated"):
            failed = [_node(rng, rng.choice(TEST_NAMES)) for _ in range(rng.randint(0, 4))]
            reasons = {name: rng.choice(ANY_REASON) for name in failed if rng.random() < 0.7}
            record = _record(
                failed,
                why=reasons,
                collected=rng.randint(0, 8),
                skipped=rng.randint(0, 10),
                omit=("n_skipped",) if rng.random() < 0.3 else (),
            )
            record["n_failed"] = rng.randint(0, 5)
            if rng.random() < 0.2:
                record["collect_errors"] = ["tests/test_a.py"]
            records.append(record)
        expect = _expect(rng, minimum=0)
        result = classify(records[0], records[1], expect, red_is_crash=rng.random() < 0.2)
        assert result["verdict"] in CLASSIFICATIONS, (case, records, expect, result)
