"""The corpus harness: every leaf of `tests/container-corpus/`, read by the
canonical container reader, must produce exactly the verdict the leaf declares.

The same leaves are read by `site/test/container-corpus.test.ts` against the
TypeScript reader. One bench, two implementations: a disagreement between them
is a failing test here or there, never a field report about two verifiers that
read the same file differently.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from attest import container

CORPUS = Path(__file__).resolve().parents[1] / "tests" / "container-corpus"
LEAVES = sorted(p.name for p in CORPUS.iterdir() if p.is_dir())


def read_leaf(name: str) -> tuple[bytes, dict[str, Any]]:
    leaf = CORPUS / name
    expected: dict[str, Any] = json.loads((leaf / "expected.json").read_text(encoding="utf-8"))
    return (leaf / "archive.zip").read_bytes(), expected


def verdict(raw: bytes, caps: dict[str, int]) -> dict[str, Any]:
    """What the reader says about `raw`: the member list plus every member's
    bytes, or the first code it refuses on. Members are read in directory order,
    which is the order both implementations use."""
    try:
        members = container.canonical_members(
            raw,
            max_entries=caps["max_entries"],
            max_member_bytes=caps["max_member_bytes"],
            max_total_bytes=caps["max_total_bytes"],
        )
        budget = container.ReadBudget(caps["max_member_bytes"], caps["max_total_bytes"])
        read = [
            {
                "name": member.name,
                "method": member.method,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            for member, data in ((m, container.read_member(raw, m, budget)) for m in members)
        ]
    except container.ContainerError as error:
        return {"verdict": "reject", "code": error.code, "member": error.member}
    return {"verdict": "accept", "members": read}


@pytest.mark.parametrize("name", LEAVES)
def test_leaf_gets_the_verdict_it_declares(name: str) -> None:
    raw, expected = read_leaf(name)
    got = verdict(raw, expected["caps"])
    assert got["verdict"] == expected["verdict"], got
    if expected["verdict"] == "reject":
        assert got["code"] == expected["code"]
        if expected["member"] is not None:
            assert got["member"] == expected["member"]
    else:
        assert got["members"] == expected["members"]


def test_every_code_of_the_taxonomy_is_reached_by_the_corpus() -> None:
    """A code no archive can produce is a check nobody has ever seen fire."""
    reached = set()
    for name in LEAVES:
        raw, expected = read_leaf(name)
        got = verdict(raw, expected["caps"])
        if got["verdict"] == "reject":
            reached.add(got["code"])
    assert set(container.CODES) - reached == set()


def test_codes_and_messages_match_the_corpus_table() -> None:
    table = json.loads((CORPUS / "codes.json").read_text(encoding="utf-8"))
    assert list(container.CODES) == table["codes"]
    assert dict(container.MESSAGES) == table["messages"]
