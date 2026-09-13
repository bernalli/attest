"""The shipped anchoring policy has to agree with the raw headers, the anchors, and the prose.

Three guards live here, and each one watches a different way the anchoring material can go wrong
once it stops being empty.

The first is arithmetic. A pinned block header states three fields — the block hash, the merkle
root and the time — and all three are derivable from the 80 raw bytes of the header itself. Two of
them have a byte order that is easy to get backwards, and the merkle root is the dangerous one:
the value a block explorer prints is the value the header carries read in the opposite direction,
so a root copied from an explorer looks exactly as plausible as the right one and matches nothing
at all. Recomputing the three fields from the raw header is what tells the two apart, and it is
the only thing that does.

The second is about evidence. Pinning a block header is a claim that some published anchor lands
on that block; a header pinned with nothing behind it asks a reader to take the claim on faith. So
every pinned entry names a converted proof under the published anchors directory, that file has to
exist, and it has to name the same block.

The third is about prose, and it is the one that is easy to underestimate. Sentences across the
repository, the site and the desktop build tell readers that nothing is pinned yet. Every one of
them becomes false the day a header is pinned, and a false sentence in a security document is
worse than a missing one, because someone acts on it. The table below binds each sentence to the
policy: while the policy is empty the sentence has to be present and unchanged, and the moment the
policy pins anything the sentence has to be gone. The table is deliberately narrow — only
sentences that a pinned header actually falsifies, and only the half of a sentence that falls when
it carries more than one fact. That narrowness is a security property rather than a matter of
taste: a guard that fires on sentences which are still true teaches people that the normal way
past it is to switch it off, and from then on it protects nothing.

All three run today against an empty policy, which is the weakest moment for a guard: empty input
passes almost any check, including a broken one. Each guard therefore carries its own bench below,
driving the same logic with synthetic material so that the failing direction is measured now
instead of assumed. The bench for the published-anchor guard starts with a case that has to stay
*silent*, because the published anchors directory does not exist yet — "file not found" is the
default outcome there, and without a positive case a guard that resolves no path at all would look
identical to one that works.

The expected values the benches compare against are the transcribed genesis-block constants in
`tests/helpers_bitcoin.py`, written from the published description of that block and from the
header format. They are not computed by the code under test, which is what lets the comparison
mean something.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

import pytest

from attest import canon
from tests.helpers_bitcoin import (
    GENESIS_HEADER_HASH_DISPLAY,
    GENESIS_HEADER_HEX,
    GENESIS_MERKLE_ROOT_DISPLAY,
    GENESIS_MERKLE_ROOT_INTERNAL,
    GENESIS_TIME,
)
from tools import bitcoin_header

REPO_ROOT = Path(__file__).resolve().parent.parent
TRUST_DIR = REPO_ROOT / "docs" / "trust" / "attest-receipts.org-log"
ANCHOR_POLICY_PATH = TRUST_DIR / "anchor-policy.json"
PINNED_HEADERS_SOURCE_PATH = TRUST_DIR / "pinned-headers.source.json"
PUBLISHED_ANCHORS_ROOT = REPO_ROOT / "site" / "public" / "log" / "anchors"
TRUSTED_LOG_TS = REPO_ROOT / "site" / "src" / "trusted-log.ts"

# The three fields a pinned entry states, in the order a reader of the policy meets them.
PINNED_FIELDS = ("header_hash", "merkle_root", "time")

# `ots_proof` is documented as a path *under* the published anchors directory. Both spellings are
# accepted — the bare tail, and the fully written repository path — because both read as correct
# to someone filling the file in by hand, and refusing one of them would be a rule nobody can see.
_ANCHORS_PREFIX = PurePosixPath("site/public/log/anchors").parts

# The generated TypeScript renders an empty policy as an empty object literal. Matching on the
# literal rather than parsing the file keeps this check independent of the generator, and allowing
# whitespace inside the braces keeps it from turning into a formatting assertion.
_EMPTY_PINNED_HEADERS_TS = re.compile(r"pinnedHeaders:\s*\{\s*\}")

# Every row is a sentence that a pinned Bitcoin header makes false, together with how many times
# it occurs in that file today. A sentence carrying more than one fact is bound only by the half
# that falls: "It ships no pinned Bitcoin block headers and supplies no witness policy" is bound
# up to "headers", because the witness policy is a different object and stays true.
#
# Deliberately absent: `site/index.html` and the generated copies of these files. Each of those
# already has a test that owns it, and two owners for one file means neither can be changed
# without fighting the other.
#
# Also deliberately absent, and for the narrowness rule rather than for ownership — a pinned
# Bitcoin block header does not make any of these false, so binding them would forbid the
# correct text on the one day this guard speaks:
#   - "Both libraries default to no anchoring policy at all" (docs/faq.md). `trusted-log.ts` is
#     imported by `site/src/main.ts` and `desktop/src/app.ts` and by nothing under
#     `verifiers/ts/src/`: pinning a header hands the two APPS a policy, and leaves both library
#     defaults exactly where they are. On pinning day this sentence becomes the most important
#     one on the page, because readers will assume the opposite.
#   - "With those default inputs, there is no dated evidence to rescue a receipt from the
#     declaration" (docs/faq.md). The missing thing is the EVIDENCE, which the bridge still does
#     not produce; an anchor policy is the other half of the pair. Pinning a header leaves this
#     true, and pointedly so.
#   - "the rail cannot be reached with the material this deployment holds" (site/src/exhibits.ts).
#     The half of that sentence which falls is bound above. This half is its CONCLUSION, and §19
#     also needs an anchored compromise cutoff, which pinning a block header does not create:
#     the likeliest correct rewrite keeps this clause, and the guard would refuse it.
# Prefer short phrases for anything inside a comment block, too: `_normalized` does not strip
# `//` or `#`, so a phrase long enough to be rewrapped stops matching when a line re-wraps.
_PROSE_TABLE: tuple[tuple[str, str, int], ...] = (
    ("SECURITY.md", "nothing pins an anchor by default", 1),
    ("README.md", "the browser and desktop currently pin no block headers", 1),
    ("docs/faq.md", "The list of block summaries in the browser verifier is empty", 1),
    ("docs/faq.md", "advice almost nobody can currently follow", 1),
    ("docs/faq.md", "Nothing pins an anchor by default", 1),
    ("docs/faq.md", "It ships no pinned Bitcoin block headers", 1),
    (
        "docs/faq.md",
        "What is missing by default is the evidence itself and an anchor to check it against",
        1,
    ),
    ("verifiers/ts/README.md", "Those apps currently pin no block headers", 1),
    ("tools/gen_buyer_pages.py", "the verifier on this site currently pins no anchors", 2),
    ("tools/gen_buyer_pages.py", "the browser and desktop currently pin no block headers", 1),
    ("site/src/explain.ts", "This page pins no block headers", 1),
    ("site/src/exhibits.ts", "has no anchor attached to any checkpoint yet", 1),
    ("desktop/test/inherited-copy-audit.ts", "nothing pinned", 1),
    ("tools/gen_site_sample.py", "this log has no anchors yet", 1),
    ("site/src/trusted-log.ts", "once anchoring lands", 1),
    ("docs/trust/README.md", "No Bitcoin block header is pinned yet", 1),
)


def _normalized(text: str) -> str:
    """Collapse every run of whitespace to one space.

    The sentences the prose guard looks for are wrapped across lines in the files that carry them,
    so a literal search on the raw text would miss most of them for reasons that have nothing to
    do with what the sentence says.
    """

    return " ".join(text.split())


def _reversed_hex(value: str) -> str:
    """Return the same bytes read in the opposite direction."""

    return bytes.fromhex(value)[::-1].hex()


def _alter_last_byte(hex_value: str) -> str:
    """Flip one bit of the last byte — the smallest change a derivation has to notice."""

    raw = bytearray(bytes.fromhex(hex_value))
    raw[-1] ^= 0x01
    return bytes(raw).hex()


def _anchors_label(anchors_root: Path) -> str:
    """Name the searched directory the way a reader can act on it.

    Repository-relative when the directory is inside the repository, which is the case that ends
    up in a failure message someone has to fix; absolute otherwise, so a bench running in a
    temporary directory does not claim to have looked somewhere it never looked.
    """

    resolved = anchors_root.resolve()
    try:
        return f"{resolved.relative_to(REPO_ROOT).as_posix()}/"
    except ValueError:
        return f"{resolved.as_posix()}/"


def _resolve_published_anchor(anchors_root: Path, reference: str) -> Path | None:
    """Resolve an `ots_proof` reference against the anchors directory, or refuse it.

    Returns `None` for anything that is not a path *under* that directory: an absolute path, or
    one that climbs out with `..`. A pinned header pointing at a file outside the published
    anchors is not a published anchor, whatever is in the file.
    """

    candidate = PurePosixPath(reference)
    if candidate.is_absolute():
        return None
    parts = candidate.parts
    if parts[: len(_ANCHORS_PREFIX)] == _ANCHORS_PREFIX:
        parts = parts[len(_ANCHORS_PREFIX) :]
    if not parts or any(part == ".." for part in parts):
        return None
    return anchors_root.joinpath(*parts)


def _trusted_log_pins_nothing(text: str) -> bool:
    """True when the generated TypeScript carries an empty pinned-header map."""

    return _EMPTY_PINNED_HEADERS_TS.search(_normalized(text)) is not None


def _load_canonical(path: Path) -> object:
    """Read a canonical JSON file, refusing duplicate keys instead of silently keeping one."""

    return canon.loads_strict(path.read_bytes())


def _shipped_policy_headers() -> Mapping[str, object]:
    policy = _load_canonical(ANCHOR_POLICY_PATH)
    assert isinstance(policy, Mapping), f"{ANCHOR_POLICY_PATH} is not a JSON object"
    pinned = policy.get("pinned_headers")
    assert isinstance(pinned, Mapping), f"{ANCHOR_POLICY_PATH} has no pinned_headers object"
    return pinned


def _shipped_source_entries() -> Sequence[object]:
    entries = _load_canonical(PINNED_HEADERS_SOURCE_PATH)
    assert isinstance(entries, list), f"{PINNED_HEADERS_SOURCE_PATH} is not a JSON array"
    return entries


def _pin_consistency_violations(
    policy_headers: Mapping[str, object],
    source_entries: Sequence[object],
) -> list[str]:
    """Report every pinned entry whose fields do not fall out of its own raw header.

    Both directions are checked. A source entry whose recomputed fields disagree with the policy
    is one half; a policy entry with no source entry behind it is the other, and it is the one
    that matters most, because such an entry cannot be recomputed from anything and is therefore
    trusted purely because somebody typed it.

    Parametrised on the two collections rather than reading the files, so the failing direction
    can be driven with synthetic material without touching the repository.
    """

    violations: list[str] = []
    keys_with_a_source: set[str] = set()

    for index, entry in enumerate(source_entries):
        if not isinstance(entry, Mapping):
            violations.append(f"source entry {index} is not a JSON object")
            continue

        key = entry.get("header_hash")
        if not isinstance(key, str):
            violations.append(f"source entry {index} states no header_hash string")
            continue
        keys_with_a_source.add(key)

        raw_hex = entry.get("raw_header_hex")
        if not isinstance(raw_hex, str):
            violations.append(
                f"source entry {key} states no raw_header_hex, so nothing about it can be "
                "recomputed"
            )
            continue
        try:
            raw = bitcoin_header.require_raw_header(raw_hex)
        except ValueError as exc:
            violations.append(f"source entry {key}: {exc}")
            continue

        derived: dict[str, object] = {
            "header_hash": bitcoin_header.header_hash_display(raw),
            "merkle_root": bitcoin_header.merkle_root_internal(raw),
            "time": bitcoin_header.header_time(raw),
        }

        if key != derived["header_hash"]:
            violations.append(
                f"source entry {key} disagrees with its own raw header: those 80 bytes hash to "
                f"{derived['header_hash']}"
            )

        pinned = policy_headers.get(key)
        if pinned is None:
            violations.append(
                f"pinned header {key} has no policy entry, so the raw header kept for it pins "
                "nothing"
            )
            continue
        if not isinstance(pinned, Mapping):
            violations.append(f"pinned header {key} is not a JSON object in pinned_headers")
            continue

        for field in PINNED_FIELDS:
            supplied = pinned.get(field)
            wanted = derived[field]
            if supplied == wanted:
                continue
            if field == "merkle_root" and supplied == _reversed_hex(str(wanted)):
                violations.append(
                    f"pinned header {key}: merkle_root is the byte reversal of bytes 36-68 of "
                    "the raw header, so it was supplied in display order, the way block "
                    "explorers print it; supply the header's own order instead"
                )
                continue
            violations.append(
                f"pinned header {key}: policy {field} is {supplied!r}, but the raw header gives "
                f"{wanted!r}"
            )

    for key in sorted(policy_headers):
        if key not in keys_with_a_source:
            violations.append(
                f"pinned header {key} has no source entry in pinned-headers.source.json, so its "
                "three fields cannot be recomputed from anything"
            )

    return violations


def _published_anchor_violations(
    source_entries: Sequence[object],
    anchors_root: Path,
) -> list[str]:
    """Report every pinned entry with no published anchor landing on its block.

    Parametrised on the anchors directory so the bench can build a real proof file somewhere
    temporary. That parametrisation is what makes the positive case possible, and the positive
    case is what separates a working guard from one that resolves nothing.
    """

    label = _anchors_label(anchors_root)
    violations: list[str] = []

    for index, entry in enumerate(source_entries):
        if not isinstance(entry, Mapping):
            violations.append(f"source entry {index} is not a JSON object")
            continue

        key = entry.get("header_hash")
        if not isinstance(key, str):
            violations.append(f"source entry {index} states no header_hash string")
            continue

        reference = entry.get("ots_proof")
        if not isinstance(reference, str) or not reference:
            violations.append(f"pinned header {key} has no published anchor under {label}")
            continue

        proof_path = _resolve_published_anchor(anchors_root, reference)
        if proof_path is None:
            violations.append(
                f"pinned header {key}: ots_proof {reference!r} is not a path under {label}"
            )
            continue
        if not proof_path.is_file():
            violations.append(f"pinned header {key} has no published anchor under {label}")
            continue

        try:
            proof = _load_canonical(proof_path)
        except canon.CanonError as exc:
            violations.append(
                f"pinned header {key}: published anchor {reference} cannot be read: {exc}"
            )
            continue
        if not isinstance(proof, Mapping):
            violations.append(
                f"pinned header {key}: published anchor {reference} is not a JSON object"
            )
            continue

        named = proof.get("header_hash")
        if named != key:
            violations.append(
                f"pinned header {key}: published anchor {reference} names header {named!r}, "
                f"not {key}"
            )

    return violations


def _prose_matches(policy_is_empty: bool) -> list[str]:
    """Report every sentence whose presence disagrees with what the shipped policy pins.

    Parametrised on the emptiness of the policy rather than reading it, so the branch that has
    never run in anger — the one that fires once a header is pinned — can be measured today
    instead of being taken on trust until the day it is needed.
    """

    if policy_is_empty:
        reason = (
            "the shipped anchoring policy pins nothing, so this sentence is still true and has to "
            "stay as it is"
        )
    else:
        reason = (
            "the shipped anchoring policy pins a block header, so this sentence is now false and "
            "has to be rewritten"
        )

    violations: list[str] = []
    for relative, sentence, occurrences in _PROSE_TABLE:
        path = REPO_ROOT / relative
        if not path.is_file():
            violations.append(f"{relative}: file is missing, so {sentence!r} cannot be checked")
            continue
        wanted = occurrences if policy_is_empty else 0
        found = _normalized(path.read_text(encoding="utf-8")).count(sentence)
        if found != wanted:
            violations.append(
                f"{relative}: {sentence!r} appears {found} time(s), expected {wanted} — {reason}"
            )
    return violations


def _genesis_source_entry() -> dict[str, object]:
    """A source entry for the genesis block, shaped as `docs/trust/README.md` documents it."""

    return {
        "height": 0,
        "header_hash": GENESIS_HEADER_HASH_DISPLAY,
        "raw_header_hex": GENESIS_HEADER_HEX,
        "source": "the Bitcoin genesis block, transcribed in tests/helpers_bitcoin.py",
        "anchored_checkpoint_tree_size": 1,
        "ots_proof": "1/genesis.proof.json",
    }


def _genesis_policy_entry() -> dict[str, object]:
    """The policy entry the genesis header derives to, written from the published block."""

    return {
        "header_hash": GENESIS_HEADER_HASH_DISPLAY,
        "merkle_root": GENESIS_MERKLE_ROOT_INTERNAL,
        "time": GENESIS_TIME,
    }


def _write_published_anchor(anchors_root: Path, reference: str, header_hash: str) -> None:
    """Put a converted proof where a source entry says one is, naming the given block."""

    path = anchors_root / reference
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        canon.canonical_bytes(
            {
                "header_hash": header_hash,
                "header_merkle_root": GENESIS_MERKLE_ROOT_INTERNAL,
                "header_time": GENESIS_TIME,
                "ops": [],
            }
        )
    )


# --- the three guards, against what the repository actually ships ----------------------------


def test_every_pinned_header_derives_from_its_raw_header() -> None:
    """Every pinned field is recomputed from the 80 raw bytes kept beside it.

    A pinned entry that cannot be recomputed is trusted because somebody typed it, and the merkle
    root in particular is wrong exactly half the time when it is typed rather than derived.

    The second half of this test is the browser's copy: the generated TypeScript and the canonical
    JSON have to agree about whether anything is pinned at all. Two copies of trust material that
    disagree mean the page trusts a block header that nothing else in the repository trusts.
    """

    policy_headers = _shipped_policy_headers()

    assert _pin_consistency_violations(policy_headers, _shipped_source_entries()) == []

    ts_pins_nothing = _trusted_log_pins_nothing(TRUSTED_LOG_TS.read_text(encoding="utf-8"))
    assert ts_pins_nothing == (dict(policy_headers) == {}), (
        "site/src/trusted-log.ts and docs/trust/attest-receipts.org-log/anchor-policy.json "
        "disagree about whether any block header is pinned. Regenerate the TypeScript from the "
        "canonical JSON rather than editing the generated file."
    )


def test_the_pin_readme_states_the_genesis_fields_the_derivations_produce() -> None:
    """The worked example is the operator's only check on byte order, so it is derived here.

    `docs/trust/README.md` prints three values for the genesis block and a fourth — the merkle
    root as explorers show it — to name the mistake. They are correct today and nothing measured
    them: a changed nibble in any of the four would ship, and the operator who used the README to
    confirm their byte order would confirm it against a typo. The two merkle spellings are also
    asserted to differ, because a README in which they had become the same value would read as
    perfectly sensible while removing the whole distinction it exists to teach.
    """

    raw = bitcoin_header.require_raw_header(GENESIS_HEADER_HEX)
    readme = _normalized((REPO_ROOT / "docs" / "trust" / "README.md").read_text(encoding="utf-8"))

    assert bitcoin_header.header_hash_display(raw) == GENESIS_HEADER_HASH_DISPLAY
    assert bitcoin_header.merkle_root_internal(raw) == GENESIS_MERKLE_ROOT_INTERNAL
    assert bitcoin_header.header_time(raw) == GENESIS_TIME
    assert raw[36:68][::-1].hex() == GENESIS_MERKLE_ROOT_DISPLAY
    assert GENESIS_MERKLE_ROOT_DISPLAY != GENESIS_MERKLE_ROOT_INTERNAL

    for field, value in (
        ("header_hash", GENESIS_HEADER_HASH_DISPLAY),
        ("merkle_root", GENESIS_MERKLE_ROOT_INTERNAL),
        ("the printed merkle root", GENESIS_MERKLE_ROOT_DISPLAY),
        ("time", str(GENESIS_TIME)),
    ):
        assert value in readme, (
            f"docs/trust/README.md no longer states the genesis {field} that "
            f"tools/bitcoin_header.py derives: {value}"
        )


def test_every_pinned_header_has_a_published_anchor_that_lands_on_it() -> None:
    """No header is pinned ahead of the evidence that would justify pinning it.

    Pinning a block header says that some published anchor lands on that block. Without the proof
    beside it the statement cannot be replayed by anyone, which is the whole point of publishing
    the anchors next to the log.
    """

    assert _published_anchor_violations(_shipped_source_entries(), PUBLISHED_ANCHORS_ROOT) == []


def test_public_prose_says_nothing_is_pinned_iff_the_shipped_policy_is_empty() -> None:
    """What the documents tell readers matches what the policy ships.

    These sentences are the reason someone decides not to look for an anchor. On the day a header
    is pinned they become false, and this test goes red on each one that has not been rewritten,
    naming the file and the sentence.
    """

    assert _prose_matches(policy_is_empty=(dict(_shipped_policy_headers()) == {})) == []


# --- benches: the guards driven with material the repository does not ship yet ------------------


def test_the_pin_consistency_check_is_silent_when_nothing_is_pinned() -> None:
    """The state the repository ships today, stated on its own rather than only via the files."""

    assert _pin_consistency_violations({}, []) == []


def test_the_pin_consistency_check_is_silent_on_an_entry_that_derives() -> None:
    """A coherent entry passes — and the values it is compared against are transcribed, not derived.

    The expected hash, root and time come from the published description of the genesis block, so
    this case measures agreement between the derivation code and something outside it instead of
    the derivation agreeing with itself.
    """

    assert (
        _pin_consistency_violations(
            {GENESIS_HEADER_HASH_DISPLAY: _genesis_policy_entry()},
            [_genesis_source_entry()],
        )
        == []
    )


@pytest.mark.parametrize(
    ("field", "corrupted"),
    [
        ("header_hash", _alter_last_byte(GENESIS_HEADER_HASH_DISPLAY)),
        ("merkle_root", _alter_last_byte(GENESIS_MERKLE_ROOT_INTERNAL)),
        ("time", GENESIS_TIME + 1),
    ],
)
def test_the_pin_consistency_check_names_the_field_that_stopped_deriving(
    field: str, corrupted: object
) -> None:
    """One byte off in any of the three fields is caught, and the message says which field."""

    policy_entry = _genesis_policy_entry()
    policy_entry[field] = corrupted

    violations = _pin_consistency_violations(
        {GENESIS_HEADER_HASH_DISPLAY: policy_entry},
        [_genesis_source_entry()],
    )

    assert len(violations) == 1, violations
    assert field in violations[0]
    assert GENESIS_HEADER_HASH_DISPLAY in violations[0]


def test_the_pin_consistency_check_names_display_order_for_a_reversed_merkle_root() -> None:
    """The mistake this guard exists for is named, not reported as an ordinary mismatch.

    A merkle root copied from a block explorer is the right 32 bytes in the wrong direction. Told
    only that the value does not match, an operator checks the value against the explorer again
    and finds it correct; told that it is the byte reversal, they know what to do.
    """

    policy_entry = _genesis_policy_entry()
    policy_entry["merkle_root"] = GENESIS_MERKLE_ROOT_DISPLAY

    violations = _pin_consistency_violations(
        {GENESIS_HEADER_HASH_DISPLAY: policy_entry},
        [_genesis_source_entry()],
    )

    assert len(violations) == 1, violations
    assert "display order" in violations[0]
    assert GENESIS_HEADER_HASH_DISPLAY in violations[0]


def test_the_pin_consistency_check_names_a_policy_entry_with_no_raw_header_behind_it() -> None:
    """A pinned header nobody kept the bytes for cannot be recomputed by anyone, ever."""

    violations = _pin_consistency_violations(
        {GENESIS_HEADER_HASH_DISPLAY: _genesis_policy_entry()},
        [],
    )

    assert len(violations) == 1, violations
    assert "has no source entry" in violations[0]
    assert GENESIS_HEADER_HASH_DISPLAY in violations[0]


def test_the_trusted_log_reading_tells_an_empty_policy_from_a_populated_one() -> None:
    """The literal the browser copy is read with distinguishes the two states it can be in.

    Both sides of the equivalence in the guard above are true today, so on its own that assertion
    would also hold for a reading that always answered the same way.
    """

    assert _trusted_log_pins_nothing("const P: AnchorPolicy = { pinnedHeaders: {}, x: null }")
    assert _trusted_log_pins_nothing("const P = {\n  pinnedHeaders: {\n  },\n}")
    assert not _trusted_log_pins_nothing(
        f'const P = {{ pinnedHeaders: {{ "{GENESIS_HEADER_HASH_DISPLAY}": {{ time: 1 }} }} }}'
    )


def test_the_published_anchor_check_is_silent_when_the_proof_is_there(tmp_path: Path) -> None:
    """The positive case, and it comes first for a reason.

    `site/public/log/anchors/` does not exist in the repository yet, so "no such file" is what
    this guard returns for every input it is given today. Both negative cases below would
    therefore pass just as well against a guard that resolves no path at all. This case is the
    one that separates the two, because only a guard that really finds and reads the file can
    stay silent here.
    """

    entry = _genesis_source_entry()
    _write_published_anchor(tmp_path, str(entry["ots_proof"]), GENESIS_HEADER_HASH_DISPLAY)

    assert _published_anchor_violations([entry], tmp_path) == []


def test_the_published_anchor_check_reports_a_pin_with_nothing_behind_it(tmp_path: Path) -> None:
    """A pinned header whose proof was never published is a claim with no way to replay it."""

    violations = _published_anchor_violations([_genesis_source_entry()], tmp_path)

    assert len(violations) == 1, violations
    assert "has no published anchor under" in violations[0]
    assert GENESIS_HEADER_HASH_DISPLAY in violations[0]


def test_the_published_anchor_check_reports_a_proof_that_names_another_block(
    tmp_path: Path,
) -> None:
    """A proof file that exists but lands on a different block is the harder half of the check.

    Existence alone would be satisfied by pointing every pinned header at the same file.
    """

    entry = _genesis_source_entry()
    other_block = _alter_last_byte(GENESIS_HEADER_HASH_DISPLAY)
    _write_published_anchor(tmp_path, str(entry["ots_proof"]), other_block)

    violations = _published_anchor_violations([entry], tmp_path)

    assert len(violations) == 1, violations
    assert GENESIS_HEADER_HASH_DISPLAY in violations[0]
    assert other_block in violations[0]


def test_the_published_anchor_check_refuses_a_proof_outside_the_published_anchors(
    tmp_path: Path,
) -> None:
    """A path climbing out of the anchors directory is not a published anchor, whatever it holds."""

    entry = _genesis_source_entry()
    entry["ots_proof"] = "../elsewhere/genesis.proof.json"

    violations = _published_anchor_violations([entry], tmp_path)

    assert len(violations) == 1, violations
    assert "is not a path under" in violations[0]


def test_the_prose_guard_fires_when_a_header_is_pinned() -> None:
    """The branch that has never run in anger, measured today on every row of the table.

    Every sentence in the table is present in the repository right now, so the populated branch
    has to report exactly one violation for each row. That is what proves the table is not vacuous
    in either direction: the empty branch is green because the sentences are all there, and this
    one is red on all of them for the same reason.
    """

    assert _PROSE_TABLE, "an empty table would make the prose guard green for no reason at all"

    violations = _prose_matches(policy_is_empty=False)

    assert violations != []
    assert len(violations) == len(_PROSE_TABLE), violations
    for relative, sentence, _occurrences in _PROSE_TABLE:
        matching = [
            violation
            for violation in violations
            if violation.startswith(f"{relative}:") and repr(sentence) in violation
        ]
        assert len(matching) == 1, f"{relative}: {sentence!r} produced {len(matching)} violations"
