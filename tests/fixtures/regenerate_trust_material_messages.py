"""Regenerate the cross-language message fixture. Run by hand, never by a test.

    uv run python tests/fixtures/regenerate_trust_material_messages.py

WHY A GENERATED FILE AND NOT TWO LISTS OF LITERALS
--------------------------------------------------
`trust_material.py` and `verifiers/ts/src/messages.ts` must produce
byte-identical refusals for M1-M8 (plan section 5.4). A literal list of
expected strings copied into each suite pins the copy: the two lists agree
until someone edits one of them, and then they disagree in silence, because
neither suite can see the other. So the Python side -- the owner of the
rendering, since `ascii()` is what the messages interpolate -- writes the
answers ONCE into `trust-material-messages.json`, and both suites are measured
against that file.

The file is under version control and regenerated deliberately. Neither suite
has an update flag: a test that can rewrite its own oracle records whatever the
code does on the day it runs.

WHAT IS RENDERED HERE, AND WHAT IS NOT
--------------------------------------
M7 and M8 interpolate the parser's own diagnostic, which the two languages are
NOT required to word alike (section 5.4: "declared tail"). The cases below
therefore supply a fixed `reason` and pin the TEMPLATE around it -- which is
exactly the part that has to match. The one tail the two cores do share, the
out-of-range integer text (P-23), is one of the reasons used.

M9, M10 and M11 have no Python twin (they refuse buffer shapes that do not
exist in Python) and so are not in the fixture; they are pinned in the
TypeScript suite, where they are the only side that has them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attest import trust_material

FIXTURE_PATH = Path(__file__).resolve().parent / "trust-material-messages.json"

# The two subjects the boundary names in its messages (plan section 5.1.2).
WHATS: tuple[str, ...] = ("trust store", "key manifest")

# Names chosen for the RENDERING paths they take, not for plausibility: quote
# selection (Python's `repr` switches to double quotes only when the string has
# a single quote and no double one), the four escape shorthands, the C0 and DEL
# controls, the three width classes of `\x`/`\u`/`\U` escapes, a lone surrogate
# -- which is a legal Python `str` and a legal JSON escape, and is the one input
# where a UTF-8 round trip would lose the value -- and a name long enough that a
# truncating renderer would show.
#
# The first six are also the unknown members section 6.2 actually generates,
# so the corpus is not purely synthetic: `__proto__`, `constructor`, `toString`
# and `hasOwnProperty` are the names a JavaScript object answers for without
# storing, and `Manifests`/`manifests ` are the two near-misses of a real
# member name.
NAMES: tuple[str, ...] = (
    "Manifests",
    "manifests ",
    "__proto__",
    "constructor",
    "toString",
    "hasOwnProperty",
    "",
    "it's",
    'say "hi"',
    "both ' and \"",
    "back\\slash",
    "new\nline",
    "carriage\rreturn",
    "tab\ttab",
    "\x00",
    "\x1b",
    "\x7f",
    "é",
    "日本",
    "😀",
    "\ud800",
    "n" * 300,
)

# Reasons for the two messages whose tail belongs to the parser. The first is
# the shared one (P-23: both cores word the out-of-range integer identically),
# the others are shaped like real diagnostics so the template is pinned around
# text containing quotes and punctuation.
REASONS: tuple[str, ...] = (
    "integer out of I-JSON safe range: 9007199254740992",
    "duplicate object key: 'chains'",
    "invalid JSON: Expecting ',' delimiter: line 1 column 9 (char 8)",
)


# Documents whose refusal names ONE of several unknown members. What is pinned
# here is not the rendering but the CHOICE: section 5.3 names the minimum in
# canonical key order (JCS, RFC 8785 -- UTF-16 code units), which is the order
# the protocol already signs on.
#
# It used to say "the first in document order", and that rule is not
# implementable in JavaScript at all: `JSON.parse` returns an ordinary object
# and integer-like keys are enumerated first whatever the document said.
# Measured 2026-09-08, before the correction: on the first document below
# Python named 'zz' and TypeScript named '0'.
#
# Each document is chosen so that the answer DISCRIMINATES -- the first member
# in document order is never the canonical minimum -- because a document where
# the two rules agree cannot tell them apart.
UNKNOWN_MEMBER_DOCUMENTS: tuple[str, ...] = (
    # An integer-like name: the case where the two cores disagreed by accident
    # of JavaScript's enumeration, and agree now by construction.
    '{"manifests":{},"provenance":{},"zz":{},"0":{}}',
    # No integer-like name anywhere: here the two cores used to AGREE, both on
    # the wrong answer. This is the control that separates the rule from the
    # accident.
    '{"manifests":{},"provenance":{},"zz":{},"aa":{}}',
    # Case matters, and uppercase sorts first.
    '{"manifests":{},"provenance":{},"beta":{},"Alpha":{}}',
    # UTF-16 code units, NOT code points: U+FB00 is below U+1F600 by code
    # point, and ABOVE it by code unit, because an astral character encodes to
    # a surrogate pair beginning at U+D800. A core that sorted by code point
    # would name the other one, and every other case here would stay green.
    '{"manifests":{},"provenance":{},"\\ufb00":{},"\\ud83d\\ude00":{}}',
    # One unknown member only: the rule must not misfire where there is nothing
    # to choose between.
    '{"manifests":{},"provenance":{},"surprise":{}}',
)


def _message(name: str) -> str:
    """A template read from the module, never retyped: the module owns the text."""
    return str(getattr(trust_material, name))


def derive_cases() -> list[dict[str, Any]]:
    """Every pinned case, rendered from `trust_material`'s own templates.

    The list order is the file order: the fixture is diffed by humans when it
    changes, and a stable order keeps a one-message change to a one-line diff.
    """
    cases: list[dict[str, Any]] = []

    for identifier, constant in (
        ("M1", "_MSG_NOT_BYTES"),
        ("M2", "_MSG_TOO_LARGE"),
        ("M3", "_MSG_NOT_PARSED"),
        ("M4", "_MSG_NOT_OBJECT"),
    ):
        template = _message(constant)
        for what in WHATS:
            cases.append({"id": identifier, "what": what, "expected": template.format(what=what)})

    unknown_member = _message("_MSG_UNKNOWN_MEMBER")
    for name in NAMES:
        cases.append(
            {"id": "M5", "name": name, "expected": unknown_member.format(name=ascii(name))}
        )

    member_shape = _message("_MSG_MEMBER_SHAPE")
    # The five real (member, shape) pairs the grammar produces, read from the
    # module so the fixture cannot pin a phrase the grammar stopped using...
    for member, (_path, shape) in trust_material._MEMBER_SHAPES.items():
        cases.append(
            {
                "id": "M6",
                "member": member,
                "shape": shape,
                "expected": member_shape.format(member=ascii(member), expected=shape),
            }
        )
    # ...and the corpus in the member slot, which the grammar never reaches
    # (the five names above are the only members that exist) but which pins the
    # RENDERER on that slot too. Section 5.4 requires `ascii()` on both slots;
    # without these cases the requirement is only asserted, never measured, and
    # a TypeScript twin that rendered this slot differently would stay green.
    shape_for_corpus = trust_material._MEMBER_SHAPES["manifests"][1]
    for name in NAMES:
        cases.append(
            {
                "id": "M6",
                "member": name,
                "shape": shape_for_corpus,
                "expected": member_shape.format(member=ascii(name), expected=shape_for_corpus),
            }
        )

    for identifier, constant in (("M7", "_MSG_UNPARSABLE"), ("M8", "_MSG_NOT_CANONICAL")):
        template = _message(constant)
        for what in WHATS:
            for reason in REASONS:
                cases.append(
                    {
                        "id": identifier,
                        "what": what,
                        "reason": reason,
                        "expected": template.format(what=what, reason=reason),
                    }
                )

    return cases


def derive_unknown_member_choices() -> list[dict[str, Any]]:
    """For each document, the refusal the Python core actually produces.

    EXECUTED, not rendered from a template: the point of these cases is WHICH
    member the boundary picks, and only running it can answer that. The
    TypeScript suite asserts its own boundary produces the same string from the
    same bytes.
    """
    choices: list[dict[str, Any]] = []
    for document in UNKNOWN_MEMBER_DOCUMENTS:
        try:
            trust_material.TrustStore.from_bytes(document.encode())
        except trust_material.TrustMaterialError as exc:
            choices.append({"document": document, "expected": str(exc)})
        else:  # pragma: no cover - a fixture document that stopped being refused
            raise SystemExit(f"document is no longer refused, the fixture would lie: {document}")
    return choices


def main() -> None:
    """Write the fixture. ASCII-only output, so the file is byte-stable everywhere.

    `ensure_ascii=True` is not cosmetic: one of the names is a lone surrogate,
    which has no UTF-8 encoding at all. Escaped, it survives the file, Python's
    `json.loads` and JavaScript's `JSON.parse` alike -- and it is precisely the
    input a renderer written without thinking about it gets wrong.
    """
    payload = {
        "_comment": (
            "Generated by tests/fixtures/regenerate_trust_material_messages.py. "
            "Edited by hand it stops being a pin. Python owns the rendering; "
            "verifiers/ts/test/messages.test.ts is measured against this file."
        ),
        "cases": derive_cases(),
        "unknown_member_choice": derive_unknown_member_choices(),
    }
    text = json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=False) + "\n"
    FIXTURE_PATH.write_text(text, encoding="ascii")
    print(
        f"wrote {FIXTURE_PATH} ({len(payload['cases'])} cases, "
        f"{len(payload['unknown_member_choice'])} unknown-member choices)"
    )


if __name__ == "__main__":
    main()
