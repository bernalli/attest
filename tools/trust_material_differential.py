#!/usr/bin/env python3
"""Feed the same bytes to both trust-material boundaries and compare what a CALLER sees.

WHY THIS EXISTS (F-4, and it is the reason F-1 survived)
--------------------------------------------------------
Until now the only artefact the two cores shared was
`tests/fixtures/trust-material-messages.json`, and it pins 69 MESSAGES — that
the two cores say the same words. Nothing compared their ANSWERS on the same
bytes. So `issuers()` could list the same store in opposite orders in the two
cores, with both suites green, for as long as nobody happened to look: each
suite used its own language's default sort as the oracle and therefore agreed
with itself.

This runner asks the question the fixture cannot: given these bytes, do the two
boundaries ADMIT or REFUSE alike, blame the same member, and hand back the same
issuer list?

WHAT IS COMPARED, AND WHAT DELIBERATELY IS NOT
----------------------------------------------
Compared: admitted/refused, the refusal CLASS (M1-M8), the `member` the refusal
blames, and the order of `issuers()`. Those are the observable surface — what a
consumer of either package can see.

NOT compared: the refusal TEXT in full. Section 5.4 declares that M7 and M8
carry the parser's own diagnostic and that the two cores are not required to
word those alike. Comparing them would produce noise that trains whoever reads
this to ignore it. The class is the part both cores owe each other, and the
class is what is compared.

THE CORPUS IS THE SUITE'S OWN
-----------------------------
Seeded from `tests.test_trust_material_parse.BYTE_MUTANT_CORPUS` — the same
documents the Python suite already drives the boundary with — plus the
ordering fixtures on which the two candidate sort rules disagree. Importing it
rather than restating it is the point: a second corpus written next to the first
is a second corpus that will drift, and the drifted half is always the one that
stops covering.

    python3 tools/trust_material_differential.py
    python3 tools/trust_material_differential.py --keep /tmp/divergences

Build `verifiers/ts/dist` first: this reads what npm publishes, not `src/`.
"""

from __future__ import annotations

import argparse
import base64
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from attest import manifests, trust_material  # noqa: E402
from tests.test_trust_material_parse import BYTE_MUTANT_CORPUS  # noqa: E402

ADAPTER = ROOT / "tools" / "trust_material_adapter_ts.mjs"
DIST = ROOT / "verifiers" / "ts" / "dist" / "trustMaterial.js"

# Issuer ids on which CODE POINT order and UTF-16 CODE UNIT order disagree.
# Without these the differential cannot see F-1's family at all: every other
# issuer fixture in the suite is BMP-only, where the two rules coincide.
ORDERING_IDS: tuple[tuple[str, ...], ...] = (
    ("\U00010000", ""),
    ("\U0001f600", "ﬀ"),
    ("퟿", "\U00010000", ""),
    ("a", "￿", "\U00010000", "", "\U0001f600"),
)


# Key manifests whose DUPLICATE kids separate the two candidate orders. The
# manifest boundary applies no grammar (section 5.3), so what there is to compare
# on this surface is the ordered list `duplicate_kids` derives from the admitted
# document -- and that list only discriminates when it holds at least two kids on
# which code point and UTF-16 code unit disagree.
#
# Measured 2026-09-08 through `verify()` on both cores, from a real conformance
# vector mutated in its kids alone: Python answered
# `['\ue000', '\U00010000']` and TypeScript the reverse, inside the error string a
# caller reads. The conformance vector for that case asserts only the substring
# "duplicate kid", so the corpus could not see it.
MANIFEST_DUPLICATE_KIDS: tuple[tuple[str, ...], ...] = (
    ("\U00010000", "\ue000"),
    ("\U0001f600", "\ufb00"),
    ("a", "\uffff", "\U00010000"),
)


def _manifest_documents() -> list[tuple[str, bytes]]:
    """Key manifests carrying each kid twice, so `duplicate_kids` returns them all.

    IMPLICIT DEPENDENCY, named here rather than left to be rediscovered (D1 of
    the review): this surface reaches `duplicate_kids` through a STANDALONE
    `KeyManifest.from_bytes`, while the defect it exists to catch surfaced on the
    STORE-EMBEDDED path (`verify.py`'s duplicate-kid preflight, which reads
    `store.manifests[issuer]`). The two are equivalent today because
    `duplicate_kids` is a pure function of the entries list and both paths hand
    it the same unvalidated tree -- neither the store grammar nor the manifest
    boundary looks inside `keys[]`.

    They stop being equivalent the moment either path starts transforming the
    manifest before the call. If that happens, this corpus keeps passing while
    the embedded path diverges, and the gate goes green on a surface it is no
    longer measuring.
    """
    out: list[tuple[str, bytes]] = []
    for index, kids in enumerate(MANIFEST_DUPLICATE_KIDS):
        entries = [
            {"kid": kid, "status": status} for kid in kids for status in ("active", "retired")
        ]
        doc = {"issuer": "store.example.com", "manifest_version": 1, "keys": entries}
        payload = json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode()
        out.append((f"duplicate-kids-{index}", payload))
    return out


def _ordering_documents() -> list[tuple[str, bytes]]:
    """Well-formed stores whose issuer ids separate the two candidate orders."""
    out: list[tuple[str, bytes]] = []
    for index, ids in enumerate(ORDERING_IDS):
        doc = {
            "manifests": {issuer: {"issuer": issuer} for issuer in ids},
            "provenance": {issuer: "tls" for issuer in ids},
        }
        payload = json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode()
        out.append((f"ordering-{index}", payload))
    return out


# The subject each surface's messages name. `_message_class` builds its heads
# from it: with the wrong subject NO head matches and every refusal falls to
# UNCLASSIFIED, which the comparator then reports as a divergence -- measured on
# the first run of the manifest surface, 1774 false divergences from a hardcoded
# "trust store". The classifier must be told which surface it is reading.
SUBJECT = {"store": "trust store", "manifest": "key manifest"}


def _message_class(message: str, what: str) -> str:
    """Which of M1-M8 produced `message`, by its constant head.

    Read from `trust_material`'s own templates, and used for BOTH cores: on
    M1/M2/M4/M5/M6 the two are byte-identical by contract, and on M7/M8 only the
    head is, which is exactly what a class comparison needs. The longest head
    wins, because M4's and M5's share an opening.
    """
    heads: list[tuple[str, str]] = []
    for identifier, constant, kwargs in (
        ("M1", "_MSG_NOT_BYTES", {"what": what}),
        ("M2", "_MSG_TOO_LARGE", {"what": what}),
        ("M4", "_MSG_NOT_OBJECT", {"what": what}),
        # M5 and M6 name the trust store in their own text whatever the subject
        # is, and are unreachable from the manifest side: the manifest boundary
        # has no grammar (section 5.3).
        ("M5", "_MSG_UNKNOWN_MEMBER", {"name": "\x00"}),
        ("M6", "_MSG_MEMBER_SHAPE", {"member": "\x00", "expected": "\x00"}),
        ("M7", "_MSG_UNPARSABLE", {"what": what, "reason": "\x00"}),
        ("M8", "_MSG_NOT_CANONICAL", {"what": what, "reason": "\x00"}),
    ):
        rendered = str(getattr(trust_material, constant)).format(**kwargs)
        heads.append((identifier, rendered.split("\x00")[0]))
    matches = [(identifier, head) for identifier, head in heads if message.startswith(head)]
    if not matches:
        return "UNCLASSIFIED"
    return max(matches, key=lambda item: len(item[1]))[0]


def _python_answer(payload: bytes, surface: str) -> dict[str, Any]:
    """What a caller of the Python core sees, on one surface.

    `ordered` is the surface's ordered result: the issuer list for the store,
    the duplicate-kid list for the manifest. One field, because what the two
    cores owe each other is the same on both -- the same sequence, in the same
    order -- and a comparator with one field per surface would grow a branch per
    surface and stop being one engine.
    """
    try:
        if surface == "store":
            store = trust_material.TrustStore.from_bytes(payload)
            return {"admitted": True, "ordered": list(store.issuers())}
        manifest = trust_material.KeyManifest.from_bytes(payload)
        return {"admitted": True, "ordered": manifests.duplicate_kids(manifest.data().get("keys"))}
    except trust_material.TrustMaterialError as exc:
        message = str(exc)
        return {
            "admitted": False,
            "cls": _message_class(message, SUBJECT[surface]),
            "member": exc.member,
            "message": message,
        }


def _ts_answers(corpus: list[tuple[str, bytes]], surface: str) -> dict[str, dict[str, Any]]:
    payload = [{"id": name, "b64": base64.b64encode(data).decode("ascii")} for name, data in corpus]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(payload, handle)
        corpus_path = handle.name
    # Resolved, not spelled: a partial executable path is decided by whatever
    # PATH happens to hold, and a differential that measured a different runtime
    # than the one the gate believes it measured is worse than one that refuses
    # to run.
    node = shutil.which("node")
    if node is None:
        raise SystemExit("node is not on PATH: the TypeScript half cannot be measured")
    try:
        proc = subprocess.run(  # noqa: S603
            [node, str(ADAPTER), corpus_path, surface],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        Path(corpus_path).unlink(missing_ok=True)
    if proc.returncode != 0:
        raise SystemExit(f"the TypeScript adapter failed (rc={proc.returncode}):\n{proc.stderr}")
    answers: dict[str, dict[str, Any]] = {}
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        answers[item["id"]] = item
    return answers


# Divergences the plan DECLARES, with the reason. Each is subtracted from the
# result AND asserted still present: a declared divergence that stops happening
# means either a core changed or the corpus stopped covering it, and both are
# things somebody has to be told about. A bare allow-list would hide the second.
ORDERED_NAME = {"store": "issuers", "manifest": "duplicate kids"}

_D16 = (
    "D16, declared: Python's int-to-str conversion refuses past 4300 digits and "
    "surfaces it as a PARSE failure (M7), where the TypeScript core reaches the "
    "canonicalizer and reports M8. Neither core produces an object, which is the "
    "property that matters; only the class differs. Reachable from BOTH boundaries: "
    "the token is refused before either grammar is consulted."
)

DECLARED_DIVERGENCES: dict[str, dict[str, str]] = {
    "manifest": {"4301 digit integer token": _D16},
    "store": {
        "4301 digit integer token": (
            "D16, declared: Python's int-to-str conversion refuses past 4300 digits and "
            "surfaces it as a PARSE failure (M7), where the TypeScript core reaches the "
            "canonicalizer and reports M8. Neither core produces an object, which is the "
            "property that matters; only the class differs."
        ),
    },
}


def _divergences(corpus: list[tuple[str, bytes]], surface: str) -> list[tuple[str, str]]:
    """`(document name, what differs)` for every disagreement.

    The name travels as a FIELD, never re-extracted from the rendered line. A
    caller that formats `f"{name}: {reason}"` and then recovers the name by
    splitting on the separator has built a parser for its own output, and it is
    wrong on the first name that contains the separator -- measured: with either
    a `startswith(name + ":")` or a `partition(": ")[0]` test, a document called
    `"<declared name>: variant"` is absorbed as if it WERE the declared one.
    """
    ts = _ts_answers(corpus, surface)
    found: list[tuple[str, str]] = []
    for name, data in corpus:
        theirs = ts.get(name)
        if theirs is None:
            found.append((name, "the TypeScript side returned no answer"))
            continue
        if "foreign" in theirs:
            found.append(
                (name, f"TypeScript refused with a non-TrustMaterialError: {theirs['foreign']}")
            )
            continue
        mine = _python_answer(data, surface)
        if mine["admitted"] != theirs["admitted"]:
            found.append(
                (
                    name,
                    f"python {'admitted' if mine['admitted'] else 'refused'}, "
                    f"typescript {'admitted' if theirs['admitted'] else 'refused'}",
                )
            )
            continue
        if mine["admitted"]:
            if mine["ordered"] != theirs["ordered"]:
                found.append(
                    (
                        name,
                        f"{ORDERED_NAME[surface]} differ — python {mine['ordered']!r}, "
                        f"typescript {theirs['ordered']!r}",
                    )
                )
            continue
        theirs_cls = _message_class(theirs["message"], SUBJECT[surface])
        # An unclassifiable message on EITHER side is a divergence in itself,
        # never a class to compare: `UNCLASSIFIED == UNCLASSIFIED` would make two
        # genuinely different FUTURE refusals agree, and `member` is None on both
        # sides for every class that omits it, so nothing downstream catches it.
        # It is F-1's own shape, applied to the instrument that exists to find
        # F-1: two independent implementations "agreeing" because the tool cannot
        # tell them apart.
        if "UNCLASSIFIED" in (mine["cls"], theirs_cls):
            found.append(
                (
                    name,
                    "a refusal this differential cannot classify — "
                    f"python cls={mine['cls']!r} message={mine['message']!r}, "
                    f"typescript cls={theirs_cls!r} message={theirs['message']!r}",
                )
            )
        elif mine["cls"] != theirs_cls:
            found.append((name, f"class differs — python {mine['cls']}, typescript {theirs_cls}"))
        elif mine["member"] != theirs["member"]:
            found.append(
                (
                    name,
                    f"member differs — python {mine['member']!r}, typescript {theirs['member']!r}",
                )
            )
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--surface", choices=("store", "manifest"), default="store")
    parser.add_argument("--keep", type=Path, default=None, help="write divergences to this file")
    args = parser.parse_args(argv)
    surface: str = args.surface
    declared = DECLARED_DIVERGENCES[surface]

    if not DIST.exists():
        raise SystemExit(f"missing {DIST}: build verifiers/ts first (npm run build)")

    # Both surfaces are seeded from the suite's own byte corpus -- that is what
    # exercises the lexical and parse-level parity -- and each adds the documents
    # that discriminate ITS ordered result. Neither surface is compared against
    # the other: the store has a grammar and the manifest deliberately has none,
    # so a cross-surface comparison would report the contract as a divergence.
    corpus = [(name, data) for name, data in BYTE_MUTANT_CORPUS]
    corpus.extend(_ordering_documents() if surface == "store" else _manifest_documents())
    print(f"surface: {surface}")

    # A count printed, not just an exit code: a differential that fed nothing to
    # either core would exit 0 and mean nothing, and this is the line a gate
    # reads to know the measurement happened at all.
    print(f"documents fed to both cores: {len(corpus)}")

    admitted = sum(1 for _, data in corpus if _python_answer(data, surface)["admitted"])
    print(f"of which admitted by the Python core: {admitted}")
    if admitted == 0:
        raise SystemExit("the corpus admits nothing: the comparison would be vacuous")

    found = _divergences(corpus, surface)

    # Split the declared from the rest, and check the declared ones are STILL
    # there. A gate that only subtracts an allow-list goes quiet the day the
    # thing it was excusing stops happening -- which is exactly when somebody
    # wants to know.
    #
    # Matched on the document NAME as a field. Matching on the rendered line --
    # by prefix or by splitting on the separator -- absorbs any future document
    # whose name begins with a declared one, which is an allow-list quietly
    # growing to cover cases nobody declared.
    declared_seen = {name for name, _ in found if name in declared}
    missing = set(declared) - declared_seen
    found = [(name, reason) for name, reason in found if name not in declared]
    for name in sorted(declared_seen):
        print(f"declared divergence, still present: {name}")
    if missing:
        print("DECLARED DIVERGENCES THAT NO LONGER HAPPEN:")
        for name in sorted(missing):
            print(f"  {name} -- {declared[name]}")
        print("  either a core changed, or the corpus stopped reaching this case.")
        return 1

    lines = [f"{name}: {reason}" for name, reason in found]
    if args.keep is not None:
        args.keep.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if found:
        print(f"DIVERGENCES: {len(found)}")
        for line in lines[:40]:
            print(f"  {line}")
        if len(found) > 40:
            print(f"  ... and {len(found) - 40} more")
        return 1
    print("the two cores agree on every document")
    return 0


if __name__ == "__main__":
    sys.exit(main())
