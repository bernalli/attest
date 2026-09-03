"""The merchant setup guides, executed instead of read.

Every other test in this directory builds its own synthetic `bridge.toml`.
That is why a real onboarding defect could sit in the guides unnoticed: no
test ever started from `examples/bridge.toml` — the file a merchant actually
copies — and followed a guide's own instructions.

These tests do. Two claims are pinned, both of the same kind ("this prose is
true at the command"):

1. Following a guide's OWN instructions must reach `check-config` rc 0. The
   test removes from the shipped example only what that guide TELLS the
   reader to remove; whatever the guide never mentions stays in the file,
   exactly as it would for a merchant. A platform rail added to the example
   without a matching line in the other guides therefore fails here, at the
   point where the merchant would have hit it.

2. The sample `check-config` output printed in a guide must be the output
   `check-config` actually produces. Not the values — those are the reader's
   own — but the summary lines: a rail added to the CLI and not to the guide
   is drift the reader discovers instead of us.

Both derive the rail set from the example file rather than hardcoding it, so
a fourth platform inherits the coverage on the day it ships.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import tomllib
from pathlib import Path
from typing import Any

import pytest
from attest_bridge import cli
from conftest import ISSUER

from attest import keys, pq

_BRIDGE_ROOT = Path(__file__).resolve().parents[1]
_EXAMPLE_CONFIG = _BRIDGE_ROOT / "examples" / "bridge.toml"
_DOCS = _BRIDGE_ROOT / "docs"

# Top-level tables that are NOT a platform rail. Everything else at top level
# in the example is one — derived, not listed, so a new rail is picked up by
# both tests without an edit here.
_NON_PLATFORM_TABLES = frozenset({"issuer", "delivery", "products"})

# A guide "tells the reader to remove" a table when one line names the table
# and says so. Kept deliberately literal: the point is that a merchant reading
# linearly is told, not that the instruction exists somewhere in the file.
_REMOVAL_VERBS = ("drop", "omit", "remove", "delete")

_GUIDES = {
    "stripe": "setup-stripe.md",
    "shopify": "setup-shopify.md",
    "itch": "setup-itch.md",
}


def _is_table_value(value: Any) -> bool:
    """Whether a top-level TOML value is a table, or an array of them.

    A plain array (`foo = [1, 2, 3]`) and an array-of-tables (`[[foo]]`)
    parse to the same Python type — `list` — so the only way to tell them
    apart after the fact is to look at what is inside: a non-empty array
    whose every element is itself a table.
    """
    if isinstance(value, dict):
        return True
    return isinstance(value, list) and bool(value) and all(isinstance(item, dict) for item in value)


def _top_level_tables(config_text: str) -> list[str]:
    """Top-level table names, in file order, `[a.b]` reported as `a`.

    Reads structure from `tomllib`, the reference parser, instead of
    deducing it from the text: a top-level key IS a top-level table because
    `tomllib` says so, never because a line matched a header-shaped regex —
    a regex cannot tell a real header from `[1]` sitting inside an array
    value, and one that tries is what this file replaced.

    File order survives the round trip through `tomllib.loads` because
    Python dicts preserve insertion order and `tomllib` inserts each
    top-level key the first time it parses that key, reading top to bottom.
    """
    return [name for name, value in tomllib.loads(config_text).items() if _is_table_value(value)]


def _platform_rails(config_text: str) -> list[str]:
    return [name for name in _top_level_tables(config_text) if name not in _NON_PLATFORM_TABLES]


_TABLE_MARKER = re.compile(r"^\s*#\s*@table-(start|end)\s+(\S+)\s*$")


def _table_spans(config_text: str) -> dict[str, tuple[int, int]]:
    """Line-index spans (inclusive) bounded by `@table-start`/`@table-end`.

    Raises on any marker that is not exactly balanced: a start with no
    matching end, an end with no matching start, or a start nested inside
    another still-open span. Nesting is rejected rather than supported
    because nothing in this file needs it, and a marker parser that accepts
    shapes nobody uses is exactly the kind of code this helper replaced.

    Also raises if a marker names something that is not a real top-level
    table of `config_text`, per `tomllib`. This scanner still knows nothing
    about TOML strings — a line inside a `\"\"\"..\"\"\"` value that reads
    exactly `# @table-start ghost` matches `_TABLE_MARKER` exactly as a real
    banner would — but asking whether the NAME it claims exists is a check
    this scanner CAN make without ever parsing quotes, and it catches a
    marker with no real table behind it before any line is cut.

    Also raises if a table name is opened by more than one balanced pair,
    even when the pairs do not nest (the first closes before the second
    opens). Two such pairs are not an error the scanner would otherwise
    notice — each is individually balanced — but the dict this function
    returns can only hold one span per name, so without this check whichever
    pair is scanned LAST silently wins and the other is discarded with no
    error: a decoy pair placed after the real one makes `drop_table` cut the
    decoy's (harmless) span while leaving the real table entirely in place,
    and `drop_table` reports success.
    """
    lines = config_text.splitlines(keepends=True)
    real_tables = set(_top_level_tables(config_text))
    spans: dict[str, tuple[int, int]] = {}
    open_name: str | None = None
    open_index = -1
    for index, line in enumerate(lines):
        match = _TABLE_MARKER.match(line)
        if match is None:
            continue
        kind, name = match.group(1), match.group(2)
        if kind == "start":
            if name not in real_tables:
                raise ValueError(
                    f"@table-start {name!r} does not name a top-level table in this document"
                )
            if open_name is not None:
                raise ValueError(
                    f"unbalanced table markers: @table-start {name!r} opened while "
                    f"@table-start {open_name!r} is still open"
                )
            if name in spans:
                raise ValueError(
                    f"@table-start {name!r} reopens a table that already has a "
                    "balanced @table-start/@table-end pair earlier in this "
                    "document: a table name may be marked at most once"
                )
            open_name, open_index = name, index
        else:
            if open_name is None:
                raise ValueError(
                    f"unbalanced table markers: @table-end {name!r} has no matching @table-start"
                )
            if name != open_name:
                raise ValueError(
                    f"unbalanced table markers: @table-end {name!r} does not close "
                    f"@table-start {open_name!r}"
                )
            spans[open_name] = (open_index, index)
            open_name, open_index = None, -1
    if open_name is not None:
        raise ValueError(
            f"unbalanced table markers: @table-start {open_name!r} has no matching end"
        )
    return spans


def _marked_tables(config_text: str) -> set[str]:
    """Names of every table bounded by a balanced `@table-start`/`@table-end` pair."""
    return set(_table_spans(config_text))


def _drop_table(config_text: str, table: str) -> str:
    """Remove the section between `@table-start table` and `@table-end table`.

    Mirrors what a reader does with "omit this whole table": the commented
    banner above a section goes with it, because the marker is drawn around
    the banner too — this helper never has to guess where a section starts.

    It is deliberately not a general TOML editor: it does not parse table
    headers, does not know what a bracket means, and does not look at
    anything but its own marker comments. A table with no markers around it
    cannot be dropped at all, loudly rather than by silent corruption. Three
    checks lean on `tomllib` as an oracle instead of teaching this scanner
    anything about TOML grammar: `_table_spans` rejects a marker whose name
    is not a real table, and a table name marked by more than one balanced
    pair, before any cut happens; the cut result below is re-parsed before
    it is ever returned, catching a span that, unknown to a scanner blind to
    string literals, ran through the middle of a string; and finally the
    reparsed result is checked to no longer contain `table` at all, because
    a span can point at the WRONG lines — entirely inside a multi-line
    string value, never crossing its quotes — and still produce text that
    parses fine while leaving the requested table completely untouched.
    Removing an entire table's own lines from a document that parsed before
    always leaves a document that parses after and no longer contains that
    table, so none of these three checks can ever reject a legitimate drop.
    """
    lines = config_text.splitlines(keepends=True)
    spans = _table_spans(config_text)
    if table not in spans:
        raise ValueError(f"no @table-start/@table-end markers found for [{table}]: nothing to drop")
    start, end = spans[table]

    before = lines[:start]
    while before and not before[-1].strip():
        before.pop()

    after_index = end + 1
    while after_index < len(lines) and not lines[after_index].strip():
        after_index += 1

    result = "".join(before) + "\n" + "".join(lines[after_index:])

    try:
        parsed_after = tomllib.loads(result)
    except tomllib.TOMLDecodeError as error:
        raise ValueError(
            f"dropping [{table}] produced text tomllib cannot parse: {error}"
        ) from error

    if table in parsed_after:
        raise ValueError(
            f"dropping [{table}] left it present in the reparsed output: the "
            "marker span did not cover that table's own lines"
        )

    return result


def _same_toml_value(left: Any, right: Any) -> bool:
    """Compare parsed TOML values without Python's cross-type equality."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _same_toml_value(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _same_toml_value(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    if isinstance(left, float):
        return struct.pack(">d", left) == struct.pack(">d", right)
    return bool(left == right)


def _assert_dropped_exactly(before: str, after: str, dropped: set[str]) -> None:
    """`_drop_table` removed what was asked and NOTHING else.

    Checking only that the requested tables are gone is half an invariant,
    and the missing half is where the damage is: an unrecognised header line
    makes the removal run past the end of its own section and swallow the
    tables below it. That loss is invisible to a "did it disappear" check —
    the config still parses, and the test still passes, against a file that
    is no longer the one the guide describes.
    """
    parsed_before = tomllib.loads(before)
    parsed_after = tomllib.loads(after)
    still_present = dropped & parsed_after.keys()
    assert not still_present, (
        f"_drop_table was asked to remove {sorted(dropped)} but "
        f"{sorted(still_present)} survived: the hand-rolled TOML editor "
        "failed silently"
    )
    expected_survivors = parsed_before.keys() - dropped
    assert expected_survivors == parsed_after.keys(), (
        "_drop_table removed tables nobody asked it to: missing "
        f"{sorted(expected_survivors - parsed_after.keys())}"
    )
    for table in expected_survivors:
        assert _same_toml_value(parsed_after[table], parsed_before[table]), (
            f"_drop_table left [{table}] behind but changed its contents — "
            "it ran past the end of the section it was removing"
        )


@pytest.mark.parametrize(
    ("before_value", "after_value"),
    [("true", "1"), ("false", "0"), ("1", "1.0")],
)
def test_assert_dropped_exactly_rejects_type_changes(before_value: str, after_value: str) -> None:
    before = f"[survivor]\nvalue = {before_value}\n"
    after = f"[survivor]\nvalue = {after_value}\n"

    with pytest.raises(AssertionError, match="changed its contents"):
        _assert_dropped_exactly(before, after, set())


def _guide_text_including_referrals(guide_name: str) -> str:
    """A guide's text plus that of any sibling guide it sends the reader to.

    Both the shopify and itch guides configure only their own table and say
    "see setup-stripe.md step 3 for the rest of the file". A reader follows
    that link, so an instruction living there counts as given — what must
    never happen is that it lives in NO guide the reader was pointed at.
    """
    text = (_DOCS / guide_name).read_text(encoding="utf-8")
    referenced = {
        name for name in re.findall(r"\]\((setup-[a-z]+\.md)\)", text) if name != guide_name
    }
    for name in sorted(referenced):
        path = _DOCS / name
        if path.exists():
            text += "\n" + path.read_text(encoding="utf-8")
    return text


def _text_read_before_running_check_config(guide_name: str) -> str:
    """What a reader has read by the time they run `check-config`.

    A variable named only in a later step is not an instruction they have
    received yet — and `check-config` is precisely where an unset one stops
    them. Guides that send the reader elsewhere for part of the config
    contribute their own pre-`check-config` half too.
    """

    def prefix(text: str) -> str:
        # The COMMAND, not the word: a guide naturally mentions
        # `check-config` in the prose introducing it, and cutting there
        # would hide the very instructions that prose is introducing.
        marker = text.find("attest-bridge check-config")
        return text if marker == -1 else text[:marker]

    text = (_DOCS / guide_name).read_text(encoding="utf-8")
    parts = [prefix(text)]
    for name in sorted(set(re.findall(r"\]\((setup-[a-z]+\.md)\)", text)) - {guide_name}):
        path = _DOCS / name
        if path.exists():
            parts.append(prefix(path.read_text(encoding="utf-8")))
    return "\n".join(parts)


def _list_items(paragraph: str) -> list[str]:
    """Split a blank-line-delimited block into one unit per list item.

    A markdown bullet list has no blank line between its items, so splitting
    on blank lines alone leaves a whole multi-bullet list as ONE block. That
    is not a formatting detail: it credits a "drop" verb in one bullet to a
    table name mentioned in a different, unrelated bullet several lines away
    — which is exactly how this test came to pass for guides that never told
    the reader to drop that table at all. Continuation lines (indented, no
    leading "- ") stay attached to the item above them.
    """
    if not re.search(r"^- ", paragraph, flags=re.MULTILINE):
        return [paragraph]
    return re.split(r"\n(?=- )", paragraph)


def _tables_the_guide_says_to_remove(guide_text: str, rails: list[str]) -> set[str]:
    """Rails a guide tells the reader to take out of the config.

    The unit is the single instruction — a bullet where the guide uses a
    list, a blank-line-delimited block otherwise — never the whole markdown
    paragraph. Prose still wraps where it wraps, so verb and table name need
    not share a line; they do have to belong to the same instruction.
    """
    told: set[str] = set()
    for paragraph in re.split(r"\n\s*\n", guide_text):
        for item in _list_items(paragraph):
            lowered = item.lower()
            if not any(verb in lowered for verb in _REMOVAL_VERBS):
                continue
            for rail in rails:
                if f"[{rail}]" in item:
                    told.add(rail)
    return told


def _localize(
    config_text: str, tmp_path: Path, hybrid_keys: pq.HybridSigningKeys, manifest: Any
) -> str:
    """Guide step 4: point the deploy paths at files in the current directory."""
    seed_path = tmp_path / "issuer.seed"
    seed_path.write_text(keys.b64u(hybrid_keys.ed.seed) + "\n", encoding="utf-8")
    mldsa_path = tmp_path / "issuer.mldsa.json"
    mldsa_path.write_text(
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(hybrid_keys.mldsa.sk),
                "pub": keys.b64u(hybrid_keys.mldsa.pub),
            }
        ),
        encoding="utf-8",
    )
    manifest_path = tmp_path / "key-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    legal_path = tmp_path / "licence.txt"
    legal_text = b"example licence terms v1\n"
    legal_path.write_bytes(legal_text)

    replacements = {
        # Guide step 1/2: "replace store.example.com with your own domain".
        # Here the reader's own domain is the one the shared fixtures signed
        # the manifest for, so the `kid` follows from the same substitution.
        "store.example.com": ISSUER,
        "/secrets/issuer.seed": str(seed_path),
        "/secrets/issuer.mldsa.json": str(mldsa_path),
        "/etc/attest-bridge/key-manifest.json": str(manifest_path),
        "/var/lib/attest-bridge/ledger.sqlite3": str(tmp_path / "ledger.sqlite3"),
        "/etc/attest-bridge/licences/EXG-001.txt": str(legal_path),
        "0" * 64: hashlib.sha256(legal_text).hexdigest(),
    }
    for old, new in replacements.items():
        config_text = config_text.replace(old, new)
    return config_text


def _env_vars_named_by(config_text: str) -> list[str]:
    return re.findall(r'_env\s*=\s*"([^"]+)"', config_text)


def _export_referenced_env_vars(config_text: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Set every `*_env` the surviving config names.

    Values are throwaway: `check-config` verifies a variable is set, never
    that it holds a real credential.
    """
    for name in _env_vars_named_by(config_text):
        monkeypatch.setenv(name, "throwaway-test-value")


@pytest.mark.parametrize(
    "rail", sorted(_platform_rails(_EXAMPLE_CONFIG.read_text(encoding="utf-8")))
)
def test_guide_instructions_alone_reach_a_clean_check_config(
    rail: str,
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A merchant who does what one guide says must end up with a valid config.

    Only the tables that guide names are removed. A rail it never mentions
    stays — and then `load_config` refuses to start over an environment
    variable the reader was never told to set or to delete.
    """
    guide_path = _DOCS / _GUIDES[rail]
    guide_text = _guide_text_including_referrals(_GUIDES[rail])
    config_text = _EXAMPLE_CONFIG.read_text(encoding="utf-8")
    rails = _platform_rails(config_text)

    others = [name for name in rails if name != rail]
    told_to_remove = _tables_the_guide_says_to_remove(guide_text, others)
    assert told_to_remove == set(others), (
        f"{guide_path.name} never tells the reader what to do with "
        f"{sorted(set(others) - told_to_remove)}: following it leaves that table "
        "in bridge.toml, and the bridge refuses to start over its unset env var"
    )

    for name in told_to_remove:
        config_text = _drop_table(config_text, name)
    _assert_dropped_exactly(
        _EXAMPLE_CONFIG.read_text(encoding="utf-8"), config_text, told_to_remove
    )
    config_text = _localize(config_text, tmp_path, hybrid_keys, key_manifest)

    # Every `*_env` still named by the config has to be named by the guide
    # too. `load_config` resolves them ALL before validating anything else,
    # so one the reader was never told about stops `check-config` cold —
    # whatever it guards, and however optional that feature is.
    read_so_far = _text_read_before_running_check_config(_GUIDES[rail])
    unmentioned = [name for name in _env_vars_named_by(config_text) if name not in read_so_far]
    assert not unmentioned, (
        f"{guide_path.name} never names {unmentioned}, but the config it leaves "
        "the reader with does: the bridge refuses to start until they are set"
    )
    _export_referenced_env_vars(config_text, monkeypatch)

    config_path = tmp_path / "bridge.local.toml"
    config_path.write_text(config_text, encoding="utf-8")

    rc = cli.main(["check-config", "--config", str(config_path)])

    assert rc == 0, (
        f"check-config rejected the config {guide_path.name} produces: {capsys.readouterr().err}"
    )
    assert f"{rail}: configured" in capsys.readouterr().out


_SUMMARY_START = "<!-- @check-config-summary-start -->"
_SUMMARY_END = "<!-- @check-config-summary-end -->"

# A line that is nothing but a code fence, optionally with an info string.
# Matched only at the two positions where this format allows one — the first
# and last line inside the markers — never searched for across the document:
# finding fences is what the designs this one replaces did.
_CODE_FENCE = re.compile(r"^\s*(?:`{3,}|~{3,})[^`~]*$")


def _sample_summary_lines(guide_text: str) -> list[str] | None:
    """The `check-config` summary a guide shows, if it shows one.

    The block is delimited by markers the document carries, not inferred from
    the document's shape. Three earlier designs read the boundary out of
    something this repository does not own — first CommonMark's fence grammar,
    then the shape of an English sentence — and each failed the same way: a
    sentence that looks like a field was read as one, a fence that looked
    closed was treated as closed. Every fix widened a rule, which is the
    signal that the boundary was still being guessed: the set of cases to
    cover belonged to CommonMark, or to English, and neither is ours.

    Markers move that set back to us. Whatever sits outside them is prose and
    is never examined; whatever sits inside is the claim the guide makes about
    the tool. A sentence opening with a field name is prose unless it is
    marked, and no rule about its shape is needed to say so.

    EOF closes the block, so a guide truncated mid-summary reports the fields
    it still shows instead of reporting none: a truncation must be able to
    fail the comparison, never to skip it.

    Three refusals are properties of the summary rather than of the reader,
    and survive from the designs this replaces: a guide holding two candidate
    summaries contradicts itself and must not be read by taking the first in
    silence; a summary repeating a field is not a summary of anything the tool
    prints; and a fence opened at the block's first line must be closed at its
    last (EOF excepted), because an unclosed fence makes the reader see a
    different block from the one compared. Nothing else about fences is
    checked anywhere in this repository for these guides.
    """
    lines = guide_text.splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == _SUMMARY_START]
    ends = [i for i, line in enumerate(lines) if line.strip() == _SUMMARY_END]

    if not starts:
        if ends:
            raise ValueError(
                f"{_SUMMARY_END} with no {_SUMMARY_START}: the summary block has no "
                "beginning, and reading from the top of the document would invent one"
            )
        return None
    if len(starts) > 1:
        raise ValueError(
            f"{len(starts)} {_SUMMARY_START} markers in one guide: the document shows "
            "two candidate summaries and contradicts itself; reading the first would "
            "hide the second"
        )
    if len(ends) > 1:
        raise ValueError(
            f"{len(ends)} {_SUMMARY_END} markers in one guide: only one block is "
            "delimited, so every end but the first closes nothing"
        )

    start = starts[0]
    if ends and ends[0] < start:
        raise ValueError(
            f"{_SUMMARY_END} precedes {_SUMMARY_START}: the markers do not delimit a block"
        )
    # No end marker is a truncated document, not a malformed one: EOF closes.
    stop = ends[0] if ends else len(lines)

    body = lines[start + 1 : stop]
    # Blank lines hugging the markers are spacing, not the block's edges: the
    # field lines below ignore blank lines, and the two edge positions must
    # see the same document those lines see.
    while body and not body[0].strip():
        body = body[1:]
    while body and not body[-1].strip():
        body = body[:-1]
    # The markers sit outside the code fence, because a comment inside a fenced
    # block would render as text and this must stay invisible to the reader.
    # Dropping the fence is therefore part of reading this format, not an
    # attempt to parse the document: only these two positions are considered.
    opened = bool(body) and _CODE_FENCE.match(body[0]) is not None
    if opened:
        body = body[1:]
    closed = bool(body) and _CODE_FENCE.match(body[-1]) is not None
    if closed:
        body = body[:-1]
    # A fence at one edge and not the other is not this format: either the
    # fence never closes — and the reader sees the end marker and the prose
    # after it as code — or a marker does not hug the block. EOF is exempt: a
    # truncated document closes its fence the way it closes its block, by
    # ending.
    if ends and opened and not closed:
        raise ValueError(
            "check-config summary opens a code fence on its first line and closes none on "
            "its last: the fence is unclosed, or the end marker does not sit directly after "
            "the block"
        )
    if ends and closed and not opened:
        raise ValueError(
            "check-config summary closes a code fence on its last line and opened none on "
            "its first: the start marker does not sit directly before the block"
        )

    fields = [line for line in body if line.strip()]
    if not fields:
        raise ValueError(
            "check-config summary markers delimit no lines: the guide declares a "
            "summary and shows none"
        )

    names = [line.split(":")[0].strip() for line in fields]
    repeated = sorted({name for name in names if names.count(name) > 1})
    if repeated:
        raise ValueError(
            f"check-config summary repeats {', '.join(repr(n) for n in repeated)}: "
            "the tool prints each field once, so a repeated field is a claim about "
            "an output that does not exist"
        )
    return fields


def _field_names(lines: list[str]) -> list[str]:
    return [line.split(":")[0] for line in lines]


def _assert_summary_matches_printed(guide_name: str, sample: list[str], printed: list[str]) -> None:
    """The guide's field list IS the CLI's: same names, same order, same count.

    The single place the comparison is written, so that a test can hold it to
    being an equality. Loosening it here — to a containment, to a set — is what
    `test_a_guide_showing_only_some_printed_fields_cannot_match` fails on.
    """
    assert _field_names(sample) == _field_names(printed), (
        f"{guide_name} shows a check-config summary that the CLI does not print"
    )


@pytest.mark.parametrize("guide_name", sorted(path.name for path in _DOCS.glob("*.md")))
def test_sample_check_config_output_matches_what_the_cli_prints(
    guide_name: str,
    tmp_path: Path,
    hybrid_keys: pq.HybridSigningKeys,
    key_manifest: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A guide that shows the summary must show all of it.

    Compares field names only — the values in a guide are illustrative, the
    set of lines is a claim about the tool.
    """
    guide_text = (_DOCS / guide_name).read_text(encoding="utf-8")
    sample = _sample_summary_lines(guide_text)
    if sample is None:
        pytest.skip(f"{guide_name} shows no check-config summary block")

    config_text = _EXAMPLE_CONFIG.read_text(encoding="utf-8")
    config_text = _localize(config_text, tmp_path, hybrid_keys, key_manifest)
    _export_referenced_env_vars(config_text, monkeypatch)
    config_path = tmp_path / "bridge.toml"
    config_path.write_text(config_text, encoding="utf-8")

    assert cli.main(["check-config", "--config", str(config_path)]) == 0
    printed = [line for line in capsys.readouterr().out.splitlines() if line.strip()]

    _assert_summary_matches_printed(guide_name, sample, printed)


_GUIDES_THAT_MUST_SHOW_THE_SUMMARY = frozenset({"setup-stripe.md"})


def test_the_guides_that_show_the_summary_are_exactly_the_declared_ones() -> None:
    """Losing the markers must be red, not quiet — for every document, not one.

    The comparison above skips a document that shows no summary, which is right
    for one that never showed a summary and wrong for one that stops: removing
    the markers — or mistyping one — turns the check off and leaves the suite
    green, and the skip line reads the same either way. A one-way list ("stripe
    must show it") covers only the guides someone remembered to list: a guide
    that gains a summary later and then loses it is never noticed. So the set
    is held in both directions, over every markdown file in the docs directory
    rather than over the guides the other tests know about: a document that
    starts carrying a marked summary must be declared here, and from then on
    cannot lose it in silence.
    """
    carrying = {
        path.name
        for path in sorted(_DOCS.glob("*.md"))
        if _sample_summary_lines(path.read_text(encoding="utf-8")) is not None
    }
    declared = set(_GUIDES_THAT_MUST_SHOW_THE_SUMMARY)
    assert carrying >= declared, (
        f"{sorted(declared - carrying)} no longer carry a marked check-config summary. If "
        "the block was removed on purpose, drop the name from "
        "_GUIDES_THAT_MUST_SHOW_THE_SUMMARY in the same change; leaving it there is what "
        "keeps the comparison from being skipped into silence."
    )
    assert carrying <= declared, (
        f"{sorted(carrying - declared)} carry a marked check-config summary but are not "
        "declared in _GUIDES_THAT_MUST_SHOW_THE_SUMMARY: declare them, so that losing the "
        "block later is red rather than a skip."
    )


def _marked(body: str) -> str:
    """A guide fragment whose summary carries the markers."""
    return f"prose before\n\n{_SUMMARY_START}\n{body}\n{_SUMMARY_END}\n\nprose after\n"


_SEVEN_FIELDS = (
    "issuer: store.example.com\n"
    "public_base_url: https://receipts.example.com\n"
    "products: price_1PxYzEXAMPLE\n"
    "stripe: configured\n"
    "shopify: not configured\n"
    "itch: not configured\n"
    "delivery: download-link-only"
)


class TestSummaryMarkers:
    """The boundary of the summary block is declared, not inferred.

    Three earlier designs inferred it — from CommonMark's fence grammar, then
    from the shape of an English sentence — and each needed a new rule for
    each hostile case found. Needing a rule per case is the signal that the
    boundary is still a guess: the set of cases belonged to a grammar this
    repository does not define. These tests pin the opposite property, which
    is why the hostile cases below are grouped by WHY they fail rather than
    by what they look like.
    """

    @pytest.mark.parametrize(
        ("label", "fence_open", "fence_close"),
        [
            ("plain fence", "```", "```"),
            ("longer fence with info string", "````text", "````"),
            ("tilde fence", "~~~", "~~~"),
            ("no fence at all", "", ""),
        ],
    )
    def test_the_summary_is_found_whatever_encloses_it(
        self, label: str, fence_open: str, fence_close: str
    ) -> None:
        """The enclosing syntax is not consulted, so it cannot mislead.

        Under the fence-splitting design each of these was a separate case to
        get right, and the tilde form was simply not recognised. Here they are
        one case: the markers say where the block is, and what sits between
        them is read.
        """
        body = "\n".join(part for part in (fence_open, _SEVEN_FIELDS, fence_close) if part)
        found = _sample_summary_lines(_marked(body))
        assert found is not None, f"{label}: the marked summary was not found"
        assert [line.split(":")[0] for line in found] == [
            "issuer",
            "public_base_url",
            "products",
            "stripe",
            "shopify",
            "itch",
            "delivery",
        ], label

    def test_prose_that_opens_with_a_field_name_is_not_a_summary(self) -> None:
        """Outside the markers nothing is examined, so nothing can imitate.

        `issuer: choose the merchant domain shown above.` is a sentence, and
        under the design that recognised the block by the shape of its first
        line it was read as data. No rule about sentences is needed to reject
        it: it is not marked.
        """
        guide = "issuer: choose the merchant domain shown above.\n\nmore prose\n"
        assert _sample_summary_lines(guide) is None

    def test_a_second_marked_summary_is_refused(self) -> None:
        """A guide that shows two summaries contradicts itself.

        Reading the first in silence is the failure mode of a duplicated key:
        the document says two things and the reader picks one.
        """
        guide = _marked(f"```\n{_SEVEN_FIELDS}\n```") + _marked("```\nissuer: other.example\n```")
        with pytest.raises(ValueError, match="two candidate summaries"):
            _sample_summary_lines(guide)

    @pytest.mark.parametrize(
        ("label", "guide", "cause"),
        [
            ("end with no start", f"prose\n{_SUMMARY_END}\nprose\n", "has no beginning"),
            ("end before start", f"{_SUMMARY_END}\nissuer: a\n{_SUMMARY_START}\n", "precedes"),
            (
                "two ends",
                f"{_SUMMARY_START}\nissuer: a\n{_SUMMARY_END}\n{_SUMMARY_END}\n",
                "every end but the first closes nothing",
            ),
            ("markers around nothing", f"{_SUMMARY_START}\n{_SUMMARY_END}\n", "delimit no lines"),
        ],
    )
    def test_markers_that_do_not_delimit_a_block_are_refused(
        self, label: str, guide: str, cause: str
    ) -> None:
        """A declared boundary that is not a boundary fails loudly, naming why.

        The alternative is reading from the top of the document, or to its
        end, and calling the result a summary — inventing the block the
        markers failed to delimit. Each case pins its own cause: a refusal
        that fires for the wrong reason is a refusal that will stop firing
        when that reason is fixed.
        """
        with pytest.raises(ValueError, match=cause):
            _sample_summary_lines(guide)

    def test_blank_lines_hugging_the_markers_are_spacing(self) -> None:
        """A blank line between a marker and the fence is not part of the block."""
        guide = f"{_SUMMARY_START}\n\n```\nissuer: a\n```\n\n{_SUMMARY_END}\n"
        assert _sample_summary_lines(guide) == ["issuer: a"]

    def test_a_fence_opened_and_not_closed_before_the_end_marker_is_refused(self) -> None:
        """The one refusal about the enclosure: a fence that opens must close.

        Rendered, an unclosed fence swallows the end marker and the prose after
        it as code, so the block the reader sees is not the block compared here.
        Nothing is searched for: the same two edge positions are read, and EOF
        stays exempt (see the truncation test).
        """
        guide = f"{_SUMMARY_START}\n```\nissuer: a\n{_SUMMARY_END}\n"
        with pytest.raises(ValueError, match="closes none on its last"):
            _sample_summary_lines(guide)

    def test_a_fence_closed_and_never_opened_is_refused(self) -> None:
        guide = f"{_SUMMARY_START}\nissuer: a\n```\n{_SUMMARY_END}\n"
        with pytest.raises(ValueError, match="opened none on its first"):
            _sample_summary_lines(guide)

    def test_a_repeated_field_is_refused_even_across_a_blank_line(self) -> None:
        """The refusal is over the block, not over adjacent lines.

        This is the case that passed green under the previous design: its
        duplicate check compared each line with the one before it, so a blank
        line between the two occurrences hid the repeat. Reading the whole
        marked block leaves nowhere for the second occurrence to hide.
        """
        body = "```\nissuer: a\npublic_base_url: b\nproducts: c\n\nproducts: duplicated\n```"
        with pytest.raises(ValueError, match="repeats 'products'"):
            _sample_summary_lines(_marked(body))

    def test_a_line_that_is_not_a_field_stays_in_the_block(self) -> None:
        """A malformed trailing line is reported, not silently dropped.

        Nothing here judges whether a line looks like a field: the line is
        inside the markers, so it is part of what the guide claims the tool
        prints, and the comparison against the CLI is what fails. Dropping it
        for not matching a shape is how the previous design let a guide show
        a line the tool never prints and stay green.
        """
        body = "```\nissuer: a\ndelivery: on\nthis line is not a field\n```"
        found = _sample_summary_lines(_marked(body))
        assert found == ["issuer: a", "delivery: on", "this line is not a field"]

    @pytest.mark.parametrize("kept", range(1, 8))
    def test_a_truncated_document_reports_the_fields_it_still_shows(self, kept: int) -> None:
        """EOF closes the block, at every truncation point.

        Truncation must be able to FAIL the comparison, never to skip it: a
        helper returning None here would make a guide that stops mid-summary
        indistinguishable from one that shows no summary, and the test would
        pass by not running. Parametrised over every prefix because a single
        truncation point pins one arithmetic, not the behaviour — the earlier
        test kept every field and dropped only the closing fence, so it never
        exercised a document that ends mid-block at all.
        """
        fields = _SEVEN_FIELDS.split("\n")[:kept]
        guide = f"prose\n\n{_SUMMARY_START}\n```\n" + "\n".join(fields)
        found = _sample_summary_lines(guide)
        assert found == fields, f"truncated after {kept} field(s)"

    def test_a_guide_showing_only_some_printed_fields_cannot_match(
        self,
        tmp_path: Path,
        hybrid_keys: pq.HybridSigningKeys,
        key_manifest: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The comparison is an EQUALITY, and this is where that is written.

        Today a guide showing a subset fails only as a side effect of `==`
        between lists counting elements as well as naming them. Someone
        loosening the comparison to tolerate a field the CLI newly prints
        would turn it into a containment and reopen the case with nothing in
        the file to say what was given up — a guide could then drop half its
        summary and stay green.
        """
        full = _sample_summary_lines((_DOCS / _GUIDES["stripe"]).read_text(encoding="utf-8"))
        assert full is not None and len(full) > 2

        config_text = _localize(
            _EXAMPLE_CONFIG.read_text(encoding="utf-8"), tmp_path, hybrid_keys, key_manifest
        )
        _export_referenced_env_vars(config_text, monkeypatch)
        config_path = tmp_path / "bridge.toml"
        config_path.write_text(config_text, encoding="utf-8")
        assert cli.main(["check-config", "--config", str(config_path)]) == 0
        printed = [line for line in capsys.readouterr().out.splitlines() if line.strip()]

        subset = full[:-2]
        with pytest.raises(AssertionError, match="the CLI does not print"):
            _assert_summary_matches_printed(_GUIDES["stripe"], subset, printed)


def test_every_endpoint_the_docs_name_is_routed_by_the_app() -> None:
    """A path a merchant is told to configure has to exist.

    `deploy.md` tells the reader which endpoint to point a platform health
    check and their monitoring at; `fly.toml` and `render.yaml` put one in a
    config file that only fails at deploy time, on their infrastructure. A
    renamed or dropped route would be discovered there instead of here.
    """
    app_source = (_BRIDGE_ROOT / "src" / "attest_bridge" / "http.py").read_text(encoding="utf-8")
    routed = set(re.findall(r'path == "(/[a-z/]+)"', app_source))
    assert routed, "no routes found: the routing shape this test reads has changed"

    documented: set[str] = set()
    for path in list(_DOCS.glob("*.md")) + list((_BRIDGE_ROOT / "deploy").glob("*")):
        if path.is_dir():
            continue
        text = path.read_text(encoding="utf-8")
        documented |= {name for name in routed | {"/healthz", "/readyz"} if name in text}

    missing = sorted(name for name in documented if name not in routed)
    assert not missing, f"documented endpoints that the app does not route: {missing}"


def _mutate_by_dropping_first_line(text: str, marker: str) -> str:
    """The real example with the first line containing `marker` removed.

    Used to build hostile marker layouts BY MUTATION of the shipped file
    instead of writing broken TOML by hand: a hand-written list of "bad
    shapes" shares the blind spots of whoever wrote it.
    """
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if marker in line:
            return "".join(lines[:index] + lines[index + 1 :])
    raise AssertionError(f"no line contains {marker!r} in the example file")


def _mutate_by_duplicating_first_line(text: str, marker: str) -> str:
    """The real example with the first line containing `marker` repeated.

    Produces two `@table-start` in a row with no `@table-end` between them —
    the nested-marker shape.
    """
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if marker in line:
            return "".join([*lines[: index + 1], line, *lines[index + 1 :]])
    raise AssertionError(f"no line contains {marker!r} in the example file")


def _mutate_by_embedding_a_marker_pair_inside_a_multiline_string(text: str, table_name: str) -> str:
    """Splice a `\"\"\"`-string in front of `[issuer]` whose START marker sits
    INSIDE the string and whose END marker sits AFTER the string closes.

    `_TABLE_MARKER` matches a line by its own shape, never by asking what
    surrounds it: a line that reads exactly `# @table-start <table_name>`
    trips it whether that line is a real section banner or the first line
    of a TOML string value. Putting the two markers on either side of the
    string's closing `\"\"\"` produces the shape a marker scanner cannot see
    coming — the span it records covers the close, so cutting it removes
    the close along with whatever the markers claim to bound.
    """
    lines = text.splitlines(keepends=True)
    anchor = next(index for index, line in enumerate(lines) if line.startswith("[issuer]"))
    decoy = [
        'decoy = """\n',
        f"# @table-start {table_name}\n",
        "irrelevant string content\n",
        '"""\n',
        f"# @table-end {table_name}\n",
    ]
    return "".join([*lines[:anchor], *decoy, *lines[anchor:]])


def _mutate_by_embedding_a_marker_pair_fully_inside_a_multiline_string(
    text: str, table_name: str
) -> str:
    """Splice a `\"\"\"`-string in front of `[issuer]` whose START and END
    markers BOTH sit inside the string, never touching its opening or
    closing quote line.

    Unlike `_mutate_by_embedding_a_marker_pair_inside_a_multiline_string`,
    cutting this span leaves the string's own delimiters intact, so the
    result is still syntactically valid TOML. Re-parsing alone cannot tell
    that the cut lines were the wrong ones — only checking that the
    requested table actually disappeared can.
    """
    lines = text.splitlines(keepends=True)
    anchor = next(index for index, line in enumerate(lines) if line.startswith("[issuer]"))
    decoy = [
        'decoy = """\n',
        f"# @table-start {table_name}\n",
        "irrelevant string content\n",
        f"# @table-end {table_name}\n",
        '"""\n',
    ]
    return "".join([*lines[:anchor], *decoy, *lines[anchor:]])


def _mutate_by_duplicating_a_marker_pair_with_a_decoy_elsewhere(text: str, table_name: str) -> str:
    """The real example with a second, decoy `@table-start`/`@table-end`
    pair for `table_name` spliced in right after the real one closes.

    The decoy is fully outside any string and outside any other span, and
    it closes before anything else opens, so nothing about it is "nested" —
    it is simply a second balanced pair sharing a name with the first.
    """
    lines = text.splitlines(keepends=True)
    end_marker = f"# @table-end {table_name}"
    anchor = next(index for index, line in enumerate(lines) if line.strip() == end_marker) + 1
    decoy = [
        "\n",
        f"# @table-start {table_name}\n",
        "# decoy: not a real section, just a same-named marker pair\n",
        f"# @table-end {table_name}\n",
    ]
    return "".join([*lines[:anchor], *decoy, *lines[anchor:]])


def _mutate_by_renaming_a_marker_pair(text: str, table_name: str, new_name: str) -> str:
    """The real example with one marker pair's name swapped for a fake one.

    The actual `[<table_name>]` section and its markers' positions are
    untouched — only the name inside the two marker comments changes, so
    the document still balances and the only thing wrong with it is that
    `new_name` names no top-level table `tomllib` can find.
    """
    return text.replace(f"@table-start {table_name}", f"@table-start {new_name}").replace(
        f"@table-end {table_name}", f"@table-end {new_name}"
    )


class TestTableSpansAndDropTable:
    """`_drop_table` no longer deduces TOML structure from the text: it cuts
    between `@table-start <name>` / `@table-end <name>` marker comments, and
    those markers are the ONLY thing it looks at. A line that merely looks
    like a table header — `[1]` inside an array value, for instance — is
    just text to it, because it never asks whether a line is a header at
    all.
    """

    _COUNTEREXAMPLE = "[a]\nx = [\n  [1]\n]\n\n[b]\ny = 1\n"

    def test_marker_absent_for_the_requested_table_raises(self) -> None:
        # Valid TOML, valid markers for "a" — none for "b".
        toml_text = "# @table-start a\n[a]\nx = 1\n# @table-end a\n\n[b]\ny = 1\n"

        with pytest.raises(ValueError, match="no @table-start/@table-end markers"):
            _drop_table(toml_text, "b")

    def test_start_marker_without_matching_end_raises(self) -> None:
        mutated = _mutate_by_dropping_first_line(
            _EXAMPLE_CONFIG.read_text(encoding="utf-8"), "@table-end shopify"
        )

        with pytest.raises(ValueError, match="unbalanced table markers"):
            _drop_table(mutated, "itch")

    def test_end_marker_without_matching_start_raises(self) -> None:
        mutated = _mutate_by_dropping_first_line(
            _EXAMPLE_CONFIG.read_text(encoding="utf-8"), "@table-start shopify"
        )

        with pytest.raises(ValueError, match="unbalanced table markers"):
            _drop_table(mutated, "itch")

    def test_nested_start_markers_raise(self) -> None:
        mutated = _mutate_by_duplicating_first_line(
            _EXAMPLE_CONFIG.read_text(encoding="utf-8"), "@table-start shopify"
        )

        with pytest.raises(ValueError, match="unbalanced table markers"):
            _drop_table(mutated, "itch")

    def test_hostile_lookalike_without_markers_is_rejected_not_corrupted(self) -> None:
        """The controexample that defeated the old line-scanning precondition.

        `  [1]` inside the array value for `x` reads, to any line scanner,
        exactly like a table header. Without markers there is nothing this
        helper can do but refuse — which is safe, unlike the old behaviour
        of accepting the document and corrupting it.
        """
        with pytest.raises(ValueError, match="no @table-start/@table-end markers"):
            _drop_table(self._COUNTEREXAMPLE, "a")

    def test_hostile_lookalike_with_markers_is_handled_correctly(self) -> None:
        """The same document, marked up, is dropped correctly and stays valid TOML."""
        marked = "# @table-start a\n[a]\nx = [\n  [1]\n]\n# @table-end a\n\n[b]\ny = 1\n"

        result = _drop_table(marked, "a")

        parsed = tomllib.loads(result)
        assert "a" not in parsed
        assert parsed["b"] == {"y": 1}

    def test_removable_table_removed_from_the_real_example_leaves_others_intact(
        self,
    ) -> None:
        before = _EXAMPLE_CONFIG.read_text(encoding="utf-8")
        removable = _marked_tables(before)
        assert removable, "the example carries no @table-start/@table-end markers at all"

        for table in sorted(removable):
            after = _drop_table(before, table)
            _assert_dropped_exactly(before, after, {table})

    def test_marker_naming_an_unknown_table_outside_any_string_raises(self) -> None:
        """A marker whose name is not a real top-level table is rejected on
        sight, with no bearing on strings at all: the plainest shape of the
        name check the redesign adds.
        """
        mutated = _mutate_by_renaming_a_marker_pair(
            _EXAMPLE_CONFIG.read_text(encoding="utf-8"), "shopify", "ghost"
        )

        with pytest.raises(ValueError, match="does not name a top-level table"):
            _drop_table(mutated, "ghost")

    def test_marker_pair_inside_a_multiline_string_naming_an_unknown_table_raises(
        self,
    ) -> None:
        """The shape that defeated the redesign before this fix: a marker
        comment sitting inside a `\"\"\"`-string, with its partner after the
        string closes, so the span the scanner records covers the close.
        `ghost` names no real table, so the name check catches it before any
        line is ever cut — the corrupt span is never even reached.
        """
        mutated = _mutate_by_embedding_a_marker_pair_inside_a_multiline_string(
            _EXAMPLE_CONFIG.read_text(encoding="utf-8"), "ghost"
        )

        with pytest.raises(ValueError, match="does not name a top-level table"):
            _drop_table(mutated, "ghost")

    def test_marker_pair_inside_a_multiline_string_naming_a_real_table_raises(
        self,
    ) -> None:
        """Same shape, but naming `issuer` — a table that genuinely exists
        and carries no markers of its own. The name check alone would let
        this through, since `issuer` is a real top-level table; only
        re-parsing `_drop_table`'s own output catches the string it would
        otherwise silently leave unterminated.
        """
        mutated = _mutate_by_embedding_a_marker_pair_inside_a_multiline_string(
            _EXAMPLE_CONFIG.read_text(encoding="utf-8"), "issuer"
        )

        with pytest.raises(ValueError, match="tomllib cannot parse"):
            _drop_table(mutated, "issuer")

    def test_marker_pair_fully_inside_a_multiline_string_naming_a_real_table_is_caught(
        self,
    ) -> None:
        """The shape that slips past BOTH earlier defences at once: a marker
        pair that sits entirely inside a multi-line string and never crosses
        its closing quotes cuts only interior string content, so the result
        is still syntactically valid — the name check passed before the cut
        (`issuer` is real) and the re-parse passes after it (the string is
        still properly closed). Only checking that `issuer` itself is gone
        from the reparsed document catches that the span pointed at the
        wrong lines the whole time.
        """
        mutated = _mutate_by_embedding_a_marker_pair_fully_inside_a_multiline_string(
            _EXAMPLE_CONFIG.read_text(encoding="utf-8"), "issuer"
        )

        with pytest.raises(ValueError, match="left it present in the reparsed output"):
            _drop_table(mutated, "issuer")

    def test_duplicate_marker_pair_for_the_same_table_is_rejected(self) -> None:
        """Two balanced `@table-start`/`@table-end shopify` pairs in the same
        document — a decoy spliced in well after the real `[shopify]`
        section closes, so neither pair nests inside the other. `_table_spans`
        keys its result by name, so without this check whichever pair the
        single-pass scan sees LAST silently overwrites the other with no
        error: here that is the decoy, so `drop_table` would cut the decoy's
        harmless span, report success, and leave the real `[shopify]` table
        completely untouched.
        """
        mutated = _mutate_by_duplicating_a_marker_pair_with_a_decoy_elsewhere(
            _EXAMPLE_CONFIG.read_text(encoding="utf-8"), "shopify"
        )

        with pytest.raises(ValueError, match="marked at most once"):
            _drop_table(mutated, "shopify")


class TestTopLevelTables:
    """`_top_level_tables` reads structure from `tomllib.loads`, never from text."""

    def test_preserves_file_order_not_alphabetical_order(self) -> None:
        toml_text = "[zeta]\nx = 1\n\n[alpha]\ny = 1\n"

        assert _top_level_tables(toml_text) == ["zeta", "alpha"]

    def test_excludes_non_table_top_level_keys(self) -> None:
        toml_text = "top_level_scalar = 1\ntop_level_array = [1, 2]\n\n[a]\nx = 1\n"

        assert _top_level_tables(toml_text) == ["a"]

    def test_array_of_tables_counts_as_a_table(self) -> None:
        toml_text = "[[a]]\nx = 1\n\n[b]\ny = 1\n"

        assert _top_level_tables(toml_text) == ["a", "b"]

    def test_dotted_child_header_is_reported_under_its_parent(self) -> None:
        toml_text = "[a.child]\nx = 1\n"

        assert _top_level_tables(toml_text) == ["a"]

    def test_real_example_tables_are_enumerated_in_appearance_order(self) -> None:
        config_text = _EXAMPLE_CONFIG.read_text(encoding="utf-8")

        assert _top_level_tables(config_text) == [
            "issuer",
            "stripe",
            "shopify",
            "itch",
            "delivery",
            "products",
        ]
