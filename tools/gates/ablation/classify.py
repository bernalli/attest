"""Classification of one ablation run from its baseline and mutated outcome records.

`classify()` turns the outcome record of the unmutated suite and the outcome record
of the same suite under a mutation into one of the bench's classifications. It is kept
separate from the applicator so that it can be tested on synthetic records,
without touching a file or running a suite.

`classify()` reads the records it is given as they are. Records that contradict
themselves are refused BEFORE classification by `validate_outcomes()`, which the
caller runs on the baseline record and on the mutated record; `classify()` does
not call it.

The classifications the bench produces are `BASELINE_RED`, `NOT_APPLIED`, `BROKEN`,
`KILLED`, `KILLED_ELSEWHERE` and `SURVIVED`. The first two are assigned by the
caller before a mutated run exists; `classify()` produces the other four.
"""

from __future__ import annotations

from collections import Counter
from typing import Any


class IncoherentOutcomes(ValueError):
    """An outcome record whose fields contradict each other.

    Such a record describes no run that could have happened, so any classification
    computed from it would be a statement about the record, not about the suite.
    """


#: Fields `classify()` indexes directly: without one of them there is nothing to classify.
_REQUIRED_FIELDS = ("collected_and_run", "n_failed", "failed", "collect_errors")
_COUNT_FIELDS = ("collected_and_run", "n_failed", "n_skipped")
_NAME_LIST_FIELDS = ("failed", "collect_errors")


def _is_count(value: Any) -> bool:
    """A non-negative `int`; `bool` is refused although it subclasses `int`."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_name_list(value: Any) -> bool:
    """A list whose every item is a string."""
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _shape_problems(outcomes: dict[str, Any]) -> list[str]:
    """Each missing or wrongly typed field, named; empty for a well-formed record."""
    problems = [
        f"malformed field {key}: missing, and classify() reads it"
        for key in _REQUIRED_FIELDS
        if key not in outcomes
    ]
    for key in _COUNT_FIELDS:
        if key in outcomes and not _is_count(outcomes[key]):
            problems.append(
                f"malformed field {key}: {outcomes[key]!r} is not a non-negative integer"
            )
    for key in _NAME_LIST_FIELDS:
        if key in outcomes and not _is_name_list(outcomes[key]):
            problems.append(f"malformed field {key}: {outcomes[key]!r} is not a list of names")
    why = outcomes.get("why", {})
    if not (
        isinstance(why, dict)
        and all(isinstance(name, str) and isinstance(reason, str) for name, reason in why.items())
    ):
        problems.append(f"malformed field why: {why!r} is not a map from test names to reasons")
    return problems


def validate_outcomes(outcomes: dict[str, Any], *, label: str) -> None:
    """Refuse an outcome record that is malformed or whose fields contradict each other.

    First the shape. The fields `classify()` reads directly (`collected_and_run`,
    `n_failed`, `failed`, `collect_errors`) must be present; every count present,
    including the optional `n_skipped`, must be a non-negative integer; `failed`
    and `collect_errors` must be lists of names; `why`, when present, must map
    names to reasons. A malformed record is refused, naming each malformed field,
    before any comparison: a wrong type is a refusal, never a `TypeError`.

    Then the contradictions, each checked only when the fields it compares are
    present:

    * `n_skipped` must not exceed `collected_and_run`;
    * `collected_and_run == 0` must not come with a non-empty `failed`;
    * `n_failed` must equal `len(failed)`;
    * `failed` must not name the same test twice.

    Every violated property is named in a single `IncoherentOutcomes`, whose
    message starts with `label` so the caller can tell which record was refused.

    Args:
        outcomes: the record written for one suite run.
        label: which record this is, for example the mutant id plus
            "baseline" or "mutated".

    Raises:
        IncoherentOutcomes: when the record is malformed or at least one property
            is violated.
    """
    if not isinstance(outcomes, dict):
        raise IncoherentOutcomes(
            f"{label}: incoherent outcomes: malformed record: "
            f"{type(outcomes).__name__} is not an object"
        )
    shape = _shape_problems(outcomes)
    if shape:
        # The comparisons below would raise TypeError on these fields instead of
        # refusing the record by name.
        raise IncoherentOutcomes(f"{label}: incoherent outcomes: " + "; ".join(shape))

    problems: list[str] = []

    if "n_skipped" in outcomes and "collected_and_run" in outcomes:
        n_skipped = outcomes["n_skipped"]
        collected = outcomes["collected_and_run"]
        if n_skipped > collected:
            problems.append(
                f"n_skipped exceeds collected_and_run ({n_skipped} > {collected}): "
                f"a run cannot skip more tests than it collected"
            )

    if "collected_and_run" in outcomes and "failed" in outcomes:
        if outcomes["collected_and_run"] == 0 and outcomes["failed"]:
            problems.append(
                f"failures reported with collected_and_run == 0 "
                f"({len(outcomes['failed'])} failed name(s)): a run that ran nothing "
                f"cannot fail anything"
            )

    if "n_failed" in outcomes and "failed" in outcomes:
        n_failed = outcomes["n_failed"]
        listed = len(outcomes["failed"])
        if n_failed != listed:
            problems.append(f"n_failed does not match len(failed) ({n_failed} != {listed})")

    if "failed" in outcomes:
        repeated = sorted(name for name, count in Counter(outcomes["failed"]).items() if count > 1)
        if repeated:
            problems.append(f"duplicate names in failed: {repeated}")

    if problems:
        raise IncoherentOutcomes(f"{label}: incoherent outcomes: " + "; ".join(problems))


def classify(
    baseline: dict[str, Any],
    mutated: dict[str, Any],
    expect_red: list[str],
    *,
    red_is_crash: bool = False,
) -> dict[str, Any]:
    """Turn two runs into a verdict, refusing to read a broken run as a kill."""
    verdict: str
    why: str

    if mutated["collect_errors"]:
        verdict = "BROKEN"
        why = (
            f"collection failed: {mutated['collect_errors'][:3]} -- "
            f"mutation broke the form, not the property"
        )
    elif mutated["collected_and_run"] == 0:
        verdict = "BROKEN"
        why = "zero tests ran -- selector or collection is wrong, this measures nothing"
    elif mutated["collected_and_run"] < baseline["collected_and_run"]:
        missing = baseline["collected_and_run"] - mutated["collected_and_run"]
        verdict = "BROKEN"
        why = f"{missing} test(s) disappeared vs baseline -- mutation broke the form"
    elif mutated["n_failed"] == 0:
        gained_skips = mutated.get("n_skipped", 0) - baseline.get("n_skipped", 0)
        if gained_skips > 0:
            # A skipped test kills nothing. The plugin records n_skipped for
            # exactly this and classify() never read it, so a mutation that makes
            # the suite skip instead of run read SURVIVED -- a phantom in the one
            # number this bench exists to produce.
            verdict = "BROKEN"
            why = (
                f"{gained_skips} test(s) that ran at baseline were SKIPPED under the "
                f"mutation; a green run that measured less than the baseline did is "
                f"not a survivor"
            )
        else:
            verdict = "SURVIVED"
            why = "mutation landed and every test stayed green"
    else:
        verdict = "KILLED"
        why = f"{mutated['n_failed']}/{mutated['collected_and_run']} red"

    failed = set(mutated["failed"])
    why_map = mutated.get("why", {})

    def _fires(expected: str, failed_name: str) -> bool:
        """Did `expected` name the test that actually went red?

        A pytest nodeid is matched on its test NAME, exactly, parameters
        stripped: a substring match reports `test_foo` as fired when only
        `test_foo_bar` went red, and this field now decides the verdict, so a
        false HIT would be a false KILLED. A vitest `fullName` is prose
        ("describe > it") and the specs name fragments of it, so there a
        substring is the only match available.
        """
        if "::" in failed_name:
            tail = failed_name.rsplit("::", 1)[-1]
            return expected == tail or expected == tail.split("[", 1)[0]
        return expected in failed_name

    hit = sorted(t for t in expect_red if any(_fires(t, f) for f in failed))
    missed = sorted(t for t in expect_red if t not in hit)
    # tests that went red but were not the ones this property is supposed to guard
    collateral = sorted(f for f in failed if not any(_fires(t, f) for t in expect_red))

    # A red raised by a broken name/import/type never reached the invariant.
    FORM_ERRORS = {
        "NameError",
        "ImportError",
        "ModuleNotFoundError",
        "AttributeError",
        "SyntaxError",
        "IndentationError",
        "UnboundLocalError",
        "ReferenceError",
        "TypeError",
    }
    kinds = sorted({why_map.get(f, "unknown") for f in failed})
    form_reds = sorted(
        f
        for f in failed
        if why_map.get(f, "").split(":")[-1] in FORM_ERRORS
        or why_map.get(f, "").startswith("FormError(")
    )
    # Some properties ARE "this input must never crash the parser". For those the
    # property red is a TypeError/AttributeError, and reclassifying it as a form
    # break would hide a real kill. The mutant declares which kind it is.
    if red_is_crash:
        form_reds = []
    # Only a red that is ENTIRELY form errors proves nothing. If an expected test
    # went red through its own assertion, the mutation reached the invariant --
    # and a sibling test crashing can itself be the property (an ordering guard
    # exists precisely so that reaching the later code is an error).
    property_reds = sorted(f for f in failed if f not in form_reds)
    if form_reds and verdict == "KILLED" and not property_reds:
        verdict = "BROKEN"
        why = (
            f"every red comes from {sorted({why_map[f] for f in form_reds})} -- "
            f"mutation broke the form, not the property"
        )
    elif form_reds and verdict == "KILLED":
        why += f"; {len(form_reds)} of them crashed rather than asserted (check they are meant to)"

    # A red SOMEWHERE in the suite is not evidence that THIS guard is covered by
    # the tests that claim to cover it. Measured on this repo: once the token
    # fixtures landed, SITE-S2 read KILLED with NONE of its expected tests red --
    # the two new cases fired and `pins the token-shape residual exactly as it
    # was decided`, the test the spec names, stayed green. That test still does
    # not do what its comment says, and a bare KILLED erases the finding at the
    # exact moment the gap closes. The distinction only survives if the verdict
    # carries it: `expected_red_that_stayed_GREEN` was computed, printed and
    # never consulted.
    if verdict == "KILLED" and expect_red and not hit:
        verdict = "KILLED_ELSEWHERE"
        why = (
            f"{mutated['n_failed']}/{mutated['collected_and_run']} red, but none of the "
            f"tests this property names went red: {missed}. The suite noticed the mutation "
            f"somewhere else, which says nothing about whether this guard is covered by "
            f"the tests whose names claim it."
        )

    return {
        "verdict": verdict,
        "why": why,
        "n_collected": mutated["collected_and_run"],
        "n_failed": mutated["n_failed"],
        "baseline_collected": baseline["collected_and_run"],
        "red_kinds": kinds,
        "form_reds": form_reds,
        "expected_red_that_fired": hit,
        "expected_red_that_stayed_GREEN": missed,
        "collateral_red": collateral,
        "failed": sorted(failed),
    }
