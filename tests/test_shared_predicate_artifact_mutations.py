"""Mutation properties for the on-disk shared-pattern guard."""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests import test_shared_predicate_parity as guard


@pytest.mark.parametrize("directory", ["docs/spec/schema", "src/attest/schema"])
@pytest.mark.parametrize("member", ["receipt_id", "supersedes"])
@pytest.mark.parametrize("level", ["pattern", "member", "properties"])
@settings(max_examples=8, derandomize=True)
@given(bad_first=st.booleans(), escaped_key=st.booleans())
def test_schema_guard_rejects_shadowed_members(
    tmp_path_factory: pytest.TempPathFactory,
    directory: str,
    member: str,
    level: str,
    bad_first: bool,
    escaped_key: bool,
) -> None:
    root = tmp_path_factory.mktemp("schema-artifact")
    owned = "^[0-7][0-9A-HJKMNP-TV-Z]{25}$"
    properties = {name: {"pattern": owned} for name in ("receipt_id", "supersedes")}
    good = json.dumps({"properties": properties})
    for location in ("docs/spec/schema", "src/attest/schema"):
        path = root / location / "attest-receipt.schema.json"
        path.parent.mkdir(parents=True)
        path.write_text(good, encoding="utf-8")

    key = {"pattern": "pattern", "member": member, "properties": "properties"}[level]
    correct: object = owned
    wrong: object = "^[0-8][0-9A-HJKMNP-TV-Z]{25}$"
    if level in ("member", "properties"):
        correct, wrong = {"pattern": correct}, {"pattern": wrong}
    if level == "properties":
        correct = {**properties, member: correct}
        wrong = {**properties, member: wrong}
    first, second = (wrong, correct) if bad_first else (correct, wrong)
    second_key = json.dumps(key)
    if escaped_key:
        second_key = f'"\\u{ord(key[0]):04x}{key[1:]}"'
    duplicate = "{" + json.dumps(key) + ":" + json.dumps(first)
    duplicate += "," + second_key + ":" + json.dumps(second) + "}"
    if level == "pattern":
        duplicate = "{" + json.dumps(member) + ":" + duplicate + "}"
    if level != "properties":
        duplicate = '{"properties":' + duplicate + "}"
    target = root / directory / "attest-receipt.schema.json"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(guard, "REPO_ROOT", root)
        guard.test_the_schema_artifact_on_disk_still_declares_the_owned_pattern(member)
        target.write_text(duplicate, encoding="utf-8")
        with pytest.raises(AssertionError, match="duplicate schema member"):
            guard.test_the_schema_artifact_on_disk_still_declares_the_owned_pattern(member)
        target.write_text(good, encoding="utf-8")
        guard.test_the_schema_artifact_on_disk_still_declares_the_owned_pattern(member)
