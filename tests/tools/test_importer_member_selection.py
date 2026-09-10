"""An outcome oracle must catch agreement on the wrong answer as well as drift."""

from __future__ import annotations

import io
import json
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from tools import importer_differential as d


@pytest.mark.parametrize(
    ("expected", "answers", "status", "mismatches"),
    [
        (d.MALFORMED, (d.ACCEPT, d.ACCEPT, d.ACCEPT), 1, 3),
        (d.ACCEPT, (d.MALFORMED, d.MALFORMED, d.MALFORMED), 1, 3),
        (d.MALFORMED, (d.ACCEPT, d.MALFORMED, d.MALFORMED), 1, 1),
        (d.MALFORMED, (d.MALFORMED, d.ACCEPT, d.MALFORMED), 1, 1),
        (d.MALFORMED, (d.MALFORMED, d.MALFORMED, d.ACCEPT), 1, 1),
        (d.MALFORMED, (d.MALFORMED, d.MALFORMED, d.MALFORMED), 0, 0),
        (d.ACCEPT, (d.ACCEPT, d.ACCEPT, d.ACCEPT), 0, 0),
        (d.ACCEPT, (d.RESOURCE_LIMIT, d.RESOURCE_LIMIT, d.RESOURCE_LIMIT), 1, 3),
        (d.ACCEPT, (d.CRASH, d.CRASH, d.CRASH), 1, 3),
        (None, (d.MALFORMED, d.MALFORMED, d.MALFORMED), 0, 0),
    ],
)
def test_all_roads_answer_to_the_oracle_even_when_they_agree(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    expected: str | None,
    answers: tuple[str, str, str],
    status: int,
    mismatches: int,
) -> None:
    vector = replace(
        d.family_baseline()[0],
        family="member-selection",
        expected_outcome=expected,
        # Neither advisory nor above-floor may excuse a broken explicit oracle.
        advisory=True,
        above_floor=True,
    )
    monkeypatch.setattr(d, "collect", lambda *args: [vector])
    monkeypatch.setattr(d, "build_ts_bundle", lambda work: work / "unused")

    def projection(outcome: str) -> dict[str, Any]:
        return {"outcome": outcome, "receipts": [], "proofs": [], "issuers": [], "legal": []}

    monkeypatch.setattr(d, "python_projection", lambda *args: projection(answers[0]))
    monkeypatch.setattr(d, "ts_projections", lambda *args: [projection(a) for a in answers[1:]])
    census = {vector.family: d.FamilyRun("archives", (vector.name,))}
    path = tmp_path / "census.json"
    d.write_importer_census(path, census, 1, 1)
    before = path.read_bytes()
    assert (
        d.run(
            [vector.family],
            1,
            1,
            tmp_path / "kept",
            expected=census,
            census_path=path,
            updating=True,
        )
        == status
    )
    captured = capsys.readouterr()
    assert f"{mismatches} expected-outcome mismatches" in captured.out
    if len(set(answers)) == 1:
        assert "0 divergences across 0 families" in captured.out
    if mismatches:
        assert f"ORACLE MISMATCH member-selection/{vector.name}" in captured.err
        assert "refusing to update the census: importer measurement failed" in captured.err
        assert path.read_bytes() == before
        kept = tmp_path / "kept" / f"member-selection--{vector.name}--oracle.json"
        assert json.loads(kept.read_text())["expected_outcome"] == expected
    else:
        assert "ORACLE MISMATCH" not in captured.err


def test_matching_outcomes_still_compare_the_imported_material(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vector = replace(d.family_baseline()[0], family="member-selection", expected_outcome=d.ACCEPT)
    monkeypatch.setattr(d, "collect", lambda *args: [vector])
    monkeypatch.setattr(d, "build_ts_bundle", lambda work: work / "unused")
    reference = {"outcome": d.ACCEPT, "receipts": [], "proofs": [], "issuers": [], "legal": []}
    parsed = {**reference, "legal": [{"digest": "lost", "sha256": "material"}]}
    monkeypatch.setattr(d, "python_projection", lambda *args: reference)
    monkeypatch.setattr(d, "ts_projections", lambda *args: [parsed, reference])
    assert (
        d.run(
            [vector.family],
            1,
            1,
            None,
            expected={vector.family: d.FamilyRun("archives", (vector.name,))},
        )
        == 1
    )
    captured = capsys.readouterr()
    assert "0 expected-outcome mismatches" in captured.out
    assert "DIVERGENCE member-selection/sound-bundle on legal" in captured.err


def test_new_family_has_pinned_identities_and_an_oracle_for_every_archive() -> None:
    vectors = d.family_member_selection()
    expected, _, _ = d.load_importer_census(d.DEFAULT_CENSUS)
    observed = d.observed_census([d.ExecutedCase("archives", v.family, v.name) for v in vectors])
    assert not d.compare_census(observed, {"member-selection": expected["member-selection"]})
    assert all(v.expected_outcome in (d.ACCEPT, d.MALFORMED) for v in vectors)
    assert all(not v.above_floor and not v.advisory for v in vectors)
    assert {v.expected_outcome for v in vectors} == {d.ACCEPT, d.MALFORMED}
    assert next(v for v in vectors if v.name == "exact-family-forms").expected_outcome == d.ACCEPT
    assert {v.expected_outcome for v in vectors if v.name.startswith("astral-")} == {
        d.ACCEPT,
        d.MALFORMED,
    }


@pytest.mark.parametrize("mutation", ["empty", "registry"])
def test_family_loss_is_named_even_with_other_archives_still_running(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mutation: str,
) -> None:
    # Exercise the real registry, collect(), main() and census, avoiding only
    # importer work unrelated to the loss. The other pinned families stay put.
    expected, _, _ = d.load_importer_census(d.DEFAULT_CENSUS)
    if mutation == "empty":
        monkeypatch.setitem(d.DETERMINISTIC_FAMILIES, "member-selection", lambda: [])
    else:
        monkeypatch.delitem(d.DETERMINISTIC_FAMILIES, "member-selection")
        monkeypatch.setattr(
            d, "ALL_FAMILIES", (*d.DETERMINISTIC_FAMILIES, d.MUTATION_FAMILY, d.PAIR_FAMILY)
        )
    monkeypatch.setattr(d, "build_ts_bundle", lambda work: work / "unused")
    monkeypatch.setattr(d, "python_projection", lambda *args, **kwargs: {"outcome": d.MALFORMED})
    monkeypatch.setattr(
        d,
        "ts_projections",
        lambda bundle, requests: [{"outcome": d.MALFORMED} for _ in requests],
    )
    assert d.main([]) == 3
    captured = capsys.readouterr()
    n = len(expected["member-selection"].vectors)
    assert f"member-selection: the census expects {n} archives; the run completed 0 archives" in (
        captured.err
    )


def test_existing_vectors_keep_their_agreement_only_contract() -> None:
    families = [name for name in d.ALL_FAMILIES if name != "member-selection"]
    assert all(v.expected_outcome is None for v in d.collect(families, 1, d.DEFAULT_SEED))
    assert all(v.expected_outcome is None for v in d.pair_vectors())


def test_astral_vectors_reach_the_guard_as_the_declared_unicode_names() -> None:
    vectors = {v.name: v for v in d.family_member_selection()}
    for point in (0x1F600, 0x10000, 0x10FFFF):
        for label, member in (
            ("root-before", f"{chr(point)}manifests/x.json"),
            ("backslash", f"manifests\\{chr(point)}.json"),
            ("free-receipt", f"receipts/a\\{chr(point)}/b.attest.json"),
        ):
            vector = vectors[f"astral-{point:06x}-{label}"]
            with zipfile.ZipFile(io.BytesIO(vector.attest)) as archive:
                assert archive.namelist()[-1] == member
                assert archive.getinfo(member).flag_bits & 0x800
                assert archive.testzip() is None


def test_local_gate_requires_the_oracle_report() -> None:
    gate = (d.REPO_ROOT / "tools/gates/g-ci-py.sh").read_text()
    assert "'^0 expected-outcome mismatches$'" in gate
    assert "'^  oracle: member-selection: [1-9][0-9]* archives checked on all three roads '" in gate
