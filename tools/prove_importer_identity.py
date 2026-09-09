#!/usr/bin/env python3
"""Exercise OL-14 through Python import and the site's parseBundle and intake.

Run after building verifiers/ts: uv run python tools/prove_importer_identity.py.
This supplementary matrix leaves the differential and its census untouched.
Node and esbuild are required; an absent prerequisite is not a passing check.
"""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attest import bundle, cli
from tools import importer_differential as d

ISSUER = "good.example"
MEMBER = f"manifests/{ISSUER}.json"
RECEIPT = "01HZX0000000000000000000AA"


def encoded(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True).encode()


def manifest(issuer: Any = ISSUER) -> dict[str, Any]:
    return {
        "issuer": issuer,
        "key_manifests": [{"issuer": issuer, "manifest_version": 1, "keys": []}],
    }


@dataclass(frozen=True)
class Case:
    label: str
    body: bytes
    issuers: tuple[str, ...] | None = None  # None means refuse the entire import.
    member: str = MEMBER
    reason: str = ""
    duplicate: bool = False


def cases() -> list[Case]:
    result = [
        Case("hostile", encoded(manifest("evil.example")), reason="does not match content issuer"),
        Case("matching", encoded(manifest()), (ISSUER,)),
        Case("case-mismatch", encoded(manifest()), member="manifests/GOOD.example.json"),
        Case(
            "unicode-mismatch",
            encoded(manifest("caf\u00e9.example")),
            member="manifests/cafe\u0301.example.json",
        ),
        Case("missing-wrapper-issuer", b'{"key_manifests":[]}'),
        Case(
            "duplicate-member", encoded(manifest("evil.example")), duplicate=True, reason="duplicat"
        ),
    ]
    for issuer in (
        "GOOD.example",
        "caf\u00e9.example",
        "cafe\u0301.example",
        "\U0001f600.example",
        "__proto__",
        "toString",
        " good.example ",
    ):
        result.append(
            Case(
                f"exact-{issuer}",
                encoded(manifest(issuer)),
                (issuer,),
                member=f"manifests/{issuer}.json",
            )
        )
    for stem in ("", "sub/good.example", "sub\\good.example", "sub\0good.example"):
        # Malformed JSON must not mask the earlier member-name refusal.
        for body in (encoded(manifest(stem)), b"not json", b"null"):
            result.append(
                Case(
                    f"bad-name-{stem!r}-{body!r}",
                    body,
                    member=f"manifests/{stem}.json",
                    reason="expected manifests/",
                )
            )
    for name in (
        "notes/good.example.json",
        "manifests/good.example.JSON",
        "/manifests/good.example.json",
        "manifests/good.example.json/",
        "Manifests/good.example.json",
    ):
        result.append(Case(f"unclaimed-{name}", b"not json", (), member=name))
    for value in (None, False, True, 0, "x", [], [1, {}]):
        result.append(Case(f"non-object-{value!r}", encoded(value), ()))
    invalid_issuers = (None, False, True, 0, 7, "", [], {})
    for value in invalid_issuers:
        result.append(
            Case(
                f"wrapper-issuer-{value!r}",
                encoded(manifest(value)),
                reason="content issuer must be a nonempty string",
            )
        )
    for label, body in (
        ("syntax", b"not json"),
        ("utf8", b"\xff"),
        ("float", b'{"issuer":1.0}'),
        ("duplicate-key", b'{"issuer":"good.example","issuer":"good.example"}'),
        ("surrogate", b'{"issuer":"\\ud800"}'),
    ):
        result.append(Case(f"json-{label}", body, reason="not valid canonical JSON"))
    for collection in ("key_manifests", "artifact_manifests"):
        for position in (0, 1):
            for value in (
                *invalid_issuers,
                "evil.example",
                "GOOD.example",
                "good.exampl\u0065\u0301",
            ):
                blob = manifest()
                blob[collection] = [
                    {
                        "issuer": ISSUER,
                        "manifest_version": version,
                        "keys": [],
                        "version": version,
                        "series": "s",
                        "artifacts": [],
                    }
                    for version in (1, 2)
                ]
                blob[collection][position]["issuer"] = value
                result.append(
                    Case(
                        f"{collection}-{position}-{value!r}",
                        encoded(blob),
                        reason=f"in {collection}[{position}]",
                    )
                )
        for label, value in (
            ("null", None),
            ("object", {"issuer": "evil.example"}),
            ("string", "bad"),
            ("empty", []),
            ("non-object-entries", [None, False, 7, "bad", []]),
        ):
            blob = manifest()
            blob[collection] = value
            issuers = () if collection == "key_manifests" else (ISSUER,)
            result.append(Case(f"{collection}-{label}", encoded(blob), issuers))
        blob = manifest()
        blob[collection] = [{"manifest_version": 1, "keys": [], "series": "s"}]
        # An absent nested issuer declares no conflicting identity. The
        # import boundary is not a complete manifest-schema validator.
        result.append(
            Case(
                f"{collection}-missing-issuer",
                encoded(blob),
                (ISSUER,),
            )
        )
    result.append(Case("missing-key-collection", encoded({"issuer": ISSUER}), ()))
    return result


NODE_PROBE = """
import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
const { parseBundle, intake, BundleError, BundleTooLargeError } =
  await import(pathToFileURL(process.argv[1]).href)
const results = JSON.parse(readFileSync(0, 'utf8')).map((path) => {
  const bytes = new Uint8Array(readFileSync(path))
  let parse
  try {
    const result = parseBundle(bytes)
    parse = { outcome: 'accept', issuers: result.trustStore.issuers(),
              receipts: result.receipts.map((r) => r.receiptId) }
  } catch (e) {
    if (!(e instanceof BundleError) || e instanceof BundleTooLargeError) throw e
    parse = { outcome: 'malformed', message: e.message }
  }
  const result = intake('library.attest', bytes)
  let door
  if (result.kind === 'rejected' && !result.declined)
    door = { outcome: 'malformed', message: result.reason }
  else if (result.kind === 'jobs')
    door = { outcome: 'accept',
             issuers: [...new Set(result.jobs.flatMap((j) => j.trustStore.issuers()))],
             receipts: result.jobs.map((j) => j.label) }
  else throw new Error(`unexpected intake result: ${result.kind}`)
  return { parse, intake: door }
})
process.stdout.write(JSON.stringify(results))
"""


def main() -> int:
    # Every check below is an `assert`, so `-O` would strip the whole
    # measurement and leave the success line untouched. A run that cannot
    # measure is not a passing run.
    if not __debug__:
        raise SystemExit("refusing to measure with assertions disabled (-O)")
    matrix = cases()
    compared = 0
    with tempfile.TemporaryDirectory(prefix="ol14-identity-") as directory:
        work = Path(directory)
        compiled = d.build_ts_bundle(work)
        paths = []
        for index, case in enumerate(matrix):
            entry = d.Entry(name=case.member.encode(), data=case.body, flags=0x0800)
            entries = [
                d.Entry(
                    name=f"receipts/{RECEIPT}.attest.json".encode(),
                    data=encoded({"payload": {"receipt_id": RECEIPT}}),
                ),
                entry,
            ]
            if case.duplicate:
                entries.append(entry)
            path = work / f"{index}.attest"
            path.write_bytes(d.build(d.Archive(entries=entries)))
            paths.append(path)
        node = subprocess.run(  # noqa: S603 -- fixed code and argv, no shell
            ["node", "--input-type=module", "-e", NODE_PROBE, str(compiled)],  # noqa: S607
            input=json.dumps([str(path) for path in paths]),
            text=True,
            capture_output=True,
            check=True,
        )
        browser = json.loads(node.stdout)
        assert len(browser) == len(matrix)
        for case, path, other in zip(matrix, paths, browser, strict=True):
            try:
                imported = bundle.import_bundle(path)
                python = {
                    "outcome": "accept",
                    "issuers": list(imported.trust_store.issuers()),
                    "receipts": [r["payload"]["receipt_id"] for r in imported.receipts],
                }
            except bundle.BundleTooLargeError:
                raise
            except bundle.BundleError as exc:
                python = {"outcome": "malformed", "message": str(exc)}
            for side, observed in (
                ("Python", python),
                ("parseBundle", other["parse"]),
                ("intake", other["intake"]),
            ):
                if case.issuers is None:
                    assert observed["outcome"] == "malformed", (case.label, side, observed)
                    assert case.reason in observed["message"], (case.label, side, observed)
                else:
                    assert observed == {
                        "outcome": "accept",
                        "issuers": list(case.issuers),
                        "receipts": [RECEIPT],
                    }, (case.label, side, observed)
                compared += 1
            if case.label in ("hostile", "matching"):
                out, err = io.StringIO(), io.StringIO()
                destination = work / f"{case.label}-import"
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    rc = cli.main(["import", "--bundle", str(path), "--out-dir", str(destination)])
                assert rc == (2 if case.issuers is None else 0), (rc, err.getvalue())
                if case.issuers is None:
                    assert not destination.exists()
                    for message in (
                        python["message"],
                        other["parse"]["message"],
                        other["intake"]["message"],
                        err.getvalue(),
                    ):
                        assert "good.example" in message and "evil.example" in message
                else:
                    assert json.loads(out.getvalue())["issuers"] == [ISSUER]
                    assert cli._load_trust_dir(destination / "trust").issuers() == (ISSUER,)
                print(
                    json.dumps(
                        {
                            "case": case.label,
                            "Python import_bundle": python,
                            "TypeScript": other,
                            "Python CLI exit": rc,
                            "Python CLI stdout": out.getvalue(),
                            "Python CLI stderr": err.getvalue(),
                        },
                        ensure_ascii=True,
                    )
                )
    refused = sum(case.issuers is None for case in matrix)
    # `compared` counts comparisons that PASSED, one per case per side; the
    # case count alone is what the matrix was built from and would print
    # unchanged had nothing been checked at all.
    expected = len(matrix) * 3
    if compared != expected:
        raise SystemExit(f"measured {compared} comparisons, expected {expected}")
    print(
        f"identity matrix: {len(matrix)} cases, {refused} refused, "
        f"{len(matrix) - refused} accepted; {compared} comparisons executed "
        "across Python/parseBundle/intake; MATCH"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
