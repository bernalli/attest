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

from attest import trust_material  # noqa: E402
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


def _message_class(message: str) -> str:
    """Which of M1-M8 produced `message`, by its constant head.

    Read from `trust_material`'s own templates, and used for BOTH cores: on
    M1/M2/M4/M5/M6 the two are byte-identical by contract, and on M7/M8 only the
    head is, which is exactly what a class comparison needs. The longest head
    wins, because M4's and M5's share an opening.
    """
    heads: list[tuple[str, str]] = []
    for identifier, constant, kwargs in (
        ("M1", "_MSG_NOT_BYTES", {"what": "trust store"}),
        ("M2", "_MSG_TOO_LARGE", {"what": "trust store"}),
        ("M4", "_MSG_NOT_OBJECT", {"what": "trust store"}),
        ("M5", "_MSG_UNKNOWN_MEMBER", {"name": "\x00"}),
        ("M6", "_MSG_MEMBER_SHAPE", {"member": "\x00", "expected": "\x00"}),
        ("M7", "_MSG_UNPARSABLE", {"what": "trust store", "reason": "\x00"}),
        ("M8", "_MSG_NOT_CANONICAL", {"what": "trust store", "reason": "\x00"}),
    ):
        rendered = str(getattr(trust_material, constant)).format(**kwargs)
        heads.append((identifier, rendered.split("\x00")[0]))
    matches = [(identifier, head) for identifier, head in heads if message.startswith(head)]
    if not matches:
        return "UNCLASSIFIED"
    return max(matches, key=lambda item: len(item[1]))[0]


def _python_answer(payload: bytes) -> dict[str, Any]:
    try:
        store = trust_material.TrustStore.from_bytes(payload)
    except trust_material.TrustMaterialError as exc:
        return {"admitted": False, "cls": _message_class(str(exc)), "member": exc.member}
    return {"admitted": True, "issuers": list(store.issuers())}


def _ts_answers(corpus: list[tuple[str, bytes]]) -> dict[str, dict[str, Any]]:
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
            [node, str(ADAPTER), corpus_path],
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
DECLARED_DIVERGENCES: dict[str, str] = {
    "4301 digit integer token": (
        "D16, declared: Python's int-to-str conversion refuses past 4300 digits and "
        "surfaces it as a PARSE failure (M7), where the TypeScript core reaches the "
        "canonicalizer and reports M8. Neither core produces an object, which is the "
        "property that matters; only the class differs."
    ),
}


def _divergences(corpus: list[tuple[str, bytes]]) -> list[str]:
    ts = _ts_answers(corpus)
    found: list[str] = []
    for name, data in corpus:
        theirs = ts.get(name)
        if theirs is None:
            found.append(f"{name}: the TypeScript side returned no answer")
            continue
        if "foreign" in theirs:
            found.append(
                f"{name}: TypeScript refused with a non-TrustMaterialError: {theirs['foreign']}"
            )
            continue
        mine = _python_answer(data)
        if mine["admitted"] != theirs["admitted"]:
            found.append(
                f"{name}: python {'admitted' if mine['admitted'] else 'refused'}, "
                f"typescript {'admitted' if theirs['admitted'] else 'refused'}"
            )
            continue
        if mine["admitted"]:
            if mine["issuers"] != theirs["issuers"]:
                found.append(
                    f"{name}: issuers differ — python {mine['issuers']!r}, "
                    f"typescript {theirs['issuers']!r}"
                )
            continue
        theirs_cls = _message_class(theirs["message"])
        if mine["cls"] != theirs_cls:
            found.append(f"{name}: class differs — python {mine['cls']}, typescript {theirs_cls}")
        elif mine["member"] != theirs["member"]:
            found.append(
                f"{name}: member differs — python {mine['member']!r}, "
                f"typescript {theirs['member']!r}"
            )
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", type=Path, default=None, help="write divergences to this file")
    args = parser.parse_args(argv)

    if not DIST.exists():
        raise SystemExit(f"missing {DIST}: build verifiers/ts first (npm run build)")

    corpus = [(name, data) for name, data in BYTE_MUTANT_CORPUS]
    corpus.extend(_ordering_documents())

    # A count printed, not just an exit code: a differential that fed nothing to
    # either core would exit 0 and mean nothing, and this is the line a gate
    # reads to know the measurement happened at all.
    print(f"documents fed to both cores: {len(corpus)}")

    admitted = sum(1 for _, data in corpus if _python_answer(data)["admitted"])
    print(f"of which admitted by the Python core: {admitted}")
    if admitted == 0:
        raise SystemExit("the corpus admits nothing: the comparison would be vacuous")

    found = _divergences(corpus)

    # Split the declared from the rest, and check the declared ones are STILL
    # there. A gate that only subtracts an allow-list goes quiet the day the
    # thing it was excusing stops happening -- which is exactly when somebody
    # wants to know.
    def _is_declared(entry: str) -> bool:
        return any(entry.startswith(name + ":") for name in DECLARED_DIVERGENCES)

    declared_seen = {
        name for name in DECLARED_DIVERGENCES if any(f.startswith(name + ":") for f in found)
    }
    missing = set(DECLARED_DIVERGENCES) - declared_seen
    found = [f for f in found if not _is_declared(f)]
    for name in sorted(declared_seen):
        print(f"declared divergence, still present: {name}")
    if missing:
        print("DECLARED DIVERGENCES THAT NO LONGER HAPPEN:")
        for name in sorted(missing):
            print(f"  {name} -- {DECLARED_DIVERGENCES[name]}")
        print("  either a core changed, or the corpus stopped reaching this case.")
        return 1

    if args.keep is not None:
        args.keep.write_text("\n".join(found) + "\n", encoding="utf-8")
    if found:
        print(f"DIVERGENCES: {len(found)}")
        for line in found[:40]:
            print(f"  {line}")
        if len(found) > 40:
            print(f"  ... and {len(found) - 40} more")
        return 1
    print("the two cores agree on every document")
    return 0


if __name__ == "__main__":
    sys.exit(main())
