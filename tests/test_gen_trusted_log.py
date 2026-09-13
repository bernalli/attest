"""The browser's trust material is generated from the canonical JSON, and refuses bad input.

`site/src/trusted-log.ts` is a second copy of what
`docs/trust/attest-receipts.org-log/` already states: the same log keys, the same
anchoring policy, spelled for TypeScript instead of for the command line. Two
hand-maintained copies of one fact drift apart, and a drifted copy here is not a cosmetic
problem — it is the page trusting a signing key, or a Bitcoin block header, that nothing
else in the repository trusts.

So the TypeScript is generated, and this file holds the two halves that make a generator
worth having. First, that the committed file is exactly what the generator produces.
Second, and the larger half, that material which does not survive validation produces no
file at all: every hostile case below asserts both that the refusal names the field that
is wrong and that `site/src/trusted-log.ts` was not touched — bytes and modification time
alike. A generator that refused loudly after writing would be no safer than one that
never refused.

Every hostile case is one field of an otherwise valid copy. That only means something
while the copy itself renders, so `test_a_copy_of_the_canonical_material_renders_the_same
_file` runs alongside them: without it, a broken copy helper would make every refusal
below fire for its own reason and the suite would stay green while checking nothing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from attest import keys, pq
from tests.helpers_bitcoin import (
    GENESIS_HEADER_HASH_DISPLAY,
    GENESIS_HEADER_HEX,
    GENESIS_MERKLE_ROOT_DISPLAY,
    GENESIS_MERKLE_ROOT_INTERNAL,
    GENESIS_TIME,
)
from tools import gen_trusted_log
from tools.ci_required import ci_prerequisites_required

REPO_ROOT = Path(__file__).resolve().parent.parent
TRUSTED_LOG = REPO_ROOT / "site" / "src" / "trusted-log.ts"
CANONICAL_TRUST_DIR = REPO_ROOT / "docs" / "trust" / "attest-receipts.org-log"

#: The typechecker the site itself runs, and the declaration file it resolves
#: `attest-verifier` to. Both are build artefacts: present after `npm install` in `site/`
#: and a build of the verifier package, absent in a checkout that has done neither.
SITE_TSC = REPO_ROOT / "site" / "node_modules" / ".bin" / "tsc"
VERIFIER_TYPES = REPO_ROOT / "verifiers" / "ts" / "dist" / "index.d.ts"


# --- Fixtures: the canonical material, and one synthetic pinned header ------


def _canonical_copy(tmp_path: Path) -> Path:
    """A writable copy of the canonical trust material, for a test to break one field of."""
    target = tmp_path / "attest-receipts.org-log"
    shutil.copytree(CANONICAL_TRUST_DIR, target)
    return target


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _genesis_pin() -> dict[str, object]:
    """The pinned-policy entry for the Bitcoin genesis block, in the correct byte order."""
    return {
        "header_hash": GENESIS_HEADER_HASH_DISPLAY,
        "merkle_root": GENESIS_MERKLE_ROOT_INTERNAL,
        "time": GENESIS_TIME,
    }


def _genesis_source() -> dict[str, object]:
    """The source entry the pin above is recomputed from."""
    return {
        "height": 0,
        "header_hash": GENESIS_HEADER_HASH_DISPLAY,
        "raw_header_hex": GENESIS_HEADER_HEX,
        "source": "tests/helpers_bitcoin.py, transcribed from the published genesis block",
        "anchored_checkpoint_tree_size": 1,
        "ots_proof": "site/public/log/anchors/1/genesis.json",
    }


def _pin_genesis(
    material: Path,
    *,
    pin: dict[str, object] | None = None,
    source: dict[str, object] | None = None,
) -> None:
    """Give the copied material one pinned header, so the populated branch is exercised."""
    _write_json(
        material / gen_trusted_log.ANCHOR_POLICY_NAME,
        {
            "crqc_horizon": None,
            "pinned_headers": {GENESIS_HEADER_HASH_DISPLAY: pin or _genesis_pin()},
        },
    )
    _write_json(material / gen_trusted_log.PINNED_SOURCE_NAME, [source or _genesis_source()])


def _refusal(material: Path) -> str:
    """Render `material`, require a refusal, and require the output file to be untouched.

    The second half is the point. `render` returns text and never opens the output for
    writing, which is exactly the kind of property that survives until someone makes the
    generator write as it goes; pinning bytes and modification time here means that change
    cannot pass unnoticed.
    """
    before_bytes = TRUSTED_LOG.read_bytes()
    before_mtime = TRUSTED_LOG.stat().st_mtime_ns

    with pytest.raises(gen_trusted_log.TrustMaterialError) as refused:
        gen_trusted_log.render(material)

    assert TRUSTED_LOG.read_bytes() == before_bytes, (
        "the generator refused the material but site/src/trusted-log.ts changed anyway"
    )
    assert TRUSTED_LOG.stat().st_mtime_ns == before_mtime, (
        "the generator refused the material but rewrote site/src/trusted-log.ts with "
        "identical bytes"
    )
    return str(refused.value)


# --- The committed file is the generated file ------------------------------


def test_committed_trusted_log_is_what_the_generator_produces() -> None:
    """A hand-edited `trusted-log.ts` is a copy that has started to drift.

    Regenerating is the fix, not editing the output: `uv run --frozen python
    tools/gen_trusted_log.py`.
    """
    expected = gen_trusted_log.render()

    assert TRUSTED_LOG.read_text(encoding="utf-8") == expected, (
        "site/src/trusted-log.ts does not match what tools/gen_trusted_log.py produces "
        "from docs/trust/attest-receipts.org-log/. Re-run the generator instead of "
        "editing the generated file."
    )


def test_a_copy_of_the_canonical_material_renders_the_same_file(tmp_path: Path) -> None:
    """The copy the hostile cases mutate must itself render, or they prove nothing.

    Every case below breaks one field of `_canonical_copy` and asserts a refusal. If the
    copy were broken — a missing file, a directory laid out differently — each of those
    refusals would fire for that reason instead, and the whole set would pass while
    testing nothing.
    """
    assert gen_trusted_log.render(_canonical_copy(tmp_path)) == gen_trusted_log.render()


def test_check_reports_no_drift_on_the_committed_tree() -> None:
    assert gen_trusted_log.main(["--check"]) == 0


def test_refused_material_exits_two_and_leaves_the_file_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit 2 is refusal and exit 1 is drift, and neither writes.

    This drives `main` rather than `render`, because the write lives in `main`: a refusal
    that returned the right code after writing the file would satisfy a test of `render`
    alone.
    """
    material = _canonical_copy(tmp_path)
    _write_json(material / gen_trusted_log.ANCHOR_POLICY_NAME, {"crqc_horizon": None})
    monkeypatch.setattr(gen_trusted_log, "TRUST_DIR", material)
    before_bytes = TRUSTED_LOG.read_bytes()
    before_mtime = TRUSTED_LOG.stat().st_mtime_ns

    assert gen_trusted_log.main([]) == 2
    assert gen_trusted_log.main(["--check"]) == 2

    assert TRUSTED_LOG.read_bytes() == before_bytes
    assert TRUSTED_LOG.stat().st_mtime_ns == before_mtime


def test_check_reports_drift_as_exit_one_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drift is exit 1, and exit 1 is not exit 2.

    `test_check_reports_no_drift_on_the_committed_tree` only ever sees the agreeing
    state, so on its own it is satisfied by a `--check` that can no longer disagree.
    Measured: with `if committed != rendered` replaced by `if False`, and again with its
    `return 1` changed to `return 2`, this whole file stayed green.

    Drift is driven the way it really arrives — canonical material edited and the
    TypeScript not regenerated — rather than from a hand-written output file, and the
    committed file is pinned by bytes and modification time, because a `--check` that
    returned the right number after writing would be no safer than not checking.
    """
    material = _canonical_copy(tmp_path)
    _write_json(
        material / gen_trusted_log.ANCHOR_POLICY_NAME,
        {"crqc_horizon": 1893456000, "pinned_headers": {}},
    )
    monkeypatch.setattr(gen_trusted_log, "TRUST_DIR", material)
    before_bytes = TRUSTED_LOG.read_bytes()
    before_mtime = TRUSTED_LOG.stat().st_mtime_ns

    assert gen_trusted_log.main(["--check"]) == 1

    assert TRUSTED_LOG.read_bytes() == before_bytes
    assert TRUSTED_LOG.stat().st_mtime_ns == before_mtime


def test_the_generator_writes_the_file_it_renders(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one thing the tool is for, and nothing reached it.

    Every other case here either refuses before the write or compares text that `render`
    returned. Measured: deleting `OUTPUT_PATH.write_text` left this whole file green, so
    a generator that printed `written:` and wrote nothing would have shipped.

    `REPO_ROOT` moves with `OUTPUT_PATH` because `main` names the output relative to it;
    redirecting both is what keeps a test from writing into the real tree.
    """
    output = tmp_path / "trusted-log.ts"
    monkeypatch.setattr(gen_trusted_log, "OUTPUT_PATH", output)
    monkeypatch.setattr(gen_trusted_log, "REPO_ROOT", tmp_path)

    assert gen_trusted_log.main([]) == 0

    assert output.read_text(encoding="utf-8") == gen_trusted_log.render()
    assert gen_trusted_log.main(["--check"]) == 0


# --- The anchoring policy: the rules belong to anchor.validate_policy -------


def test_a_pinned_headers_key_that_is_not_lowercase_hex_is_refused(tmp_path: Path) -> None:
    material = _canonical_copy(tmp_path)
    _pin_genesis(material)
    policy = _read_json(material / gen_trusted_log.ANCHOR_POLICY_NAME)
    assert isinstance(policy, dict)
    policy["pinned_headers"] = {GENESIS_HEADER_HASH_DISPLAY.upper(): _genesis_pin()}
    _write_json(material / gen_trusted_log.ANCHOR_POLICY_NAME, policy)

    assert "pinned_headers key must be 64 lowercase hex chars" in _refusal(material)


def test_a_pinned_header_whose_inner_hash_differs_from_its_key_is_refused(tmp_path: Path) -> None:
    """The key and the field are the same value written twice, so they can disagree."""
    other = "11" * 32
    _pin_genesis(
        material := _canonical_copy(tmp_path), pin={**_genesis_pin(), "header_hash": other}
    )

    message = _refusal(material)

    assert "!= PinnedHeader.header_hash" in message
    assert other in message


def test_a_merkle_root_of_the_wrong_length_is_refused(tmp_path: Path) -> None:
    _pin_genesis(
        material := _canonical_copy(tmp_path),
        pin={**_genesis_pin(), "merkle_root": GENESIS_MERKLE_ROOT_INTERNAL[:-1]},
    )

    assert "PinnedHeader.merkle_root must be 64 lowercase hex chars" in _refusal(material)


@pytest.mark.parametrize(
    "bad_time",
    [
        pytest.param(0, id="zero"),
        pytest.param(True, id="true"),
        pytest.param(253402300800, id="one-past-the-last-representable-second"),
    ],
)
def test_a_pinned_time_outside_the_representable_range_is_refused(
    tmp_path: Path, bad_time: object
) -> None:
    """`True` belongs here and not in a separate case: `isinstance(True, int)` is true.

    A shape check written here would let it through to be rendered as `time: true`; the
    validator that owns the rule is the one that knows a bool is not a timestamp.
    """
    _pin_genesis(material := _canonical_copy(tmp_path), pin={**_genesis_pin(), "time": bad_time})

    assert "PinnedHeader.time must be a positive int no later than 253402300799" in _refusal(
        material
    )


def test_a_crqc_horizon_that_is_a_string_is_refused(tmp_path: Path) -> None:
    material = _canonical_copy(tmp_path)
    _write_json(
        material / gen_trusted_log.ANCHOR_POLICY_NAME,
        {"crqc_horizon": "1", "pinned_headers": {}},
    )

    assert "policy.crqc_horizon must be an int or None: '1'" in _refusal(material)


def test_an_unknown_field_inside_a_pinned_header_is_refused(tmp_path: Path) -> None:
    """The CLI's own loader ignores what it does not recognise; the canonical source must not.

    A field the generator does not know is nearly always a misspelling of one it does, and
    ignoring it ships a pin missing the value its author believed they had written.
    """
    _pin_genesis(
        material := _canonical_copy(tmp_path),
        pin={**_genesis_pin(), "note": "second source: two explorers"},
    )

    assert "unknown field 'note' in pinned header" in _refusal(material)


def test_a_pinned_header_missing_a_field_is_refused(tmp_path: Path) -> None:
    pin = _genesis_pin()
    del pin["time"]
    _pin_genesis(material := _canonical_copy(tmp_path), pin=pin)

    assert "missing field 'time' in pinned header" in _refusal(material)


def test_a_pinned_headers_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    """The branch `load_anchor_policy` hands through untouched, so the validator owns it.

    That passthrough is written and commented but nothing drove it: replacing it with an
    empty dict left this file green, which would have turned a malformed policy into a
    silently empty one — the shape that pins nothing and reports success for it.
    """
    material = _canonical_copy(tmp_path)
    _write_json(
        material / gen_trusted_log.ANCHOR_POLICY_NAME,
        {"crqc_horizon": None, "pinned_headers": []},
    )

    assert "policy.pinned_headers must be a dict" in _refusal(material)


def test_a_canonical_file_of_the_wrong_json_shape_is_refused(tmp_path: Path) -> None:
    """An object where an array belongs: the shape check nothing exercised."""
    material = _canonical_copy(tmp_path)
    _write_json(material / gen_trusted_log.LOG_KEYS_NAME, {"origin": "attest-receipts.org/log"})

    assert "log-keys.json must be a JSON array" in _refusal(material)


def test_a_non_string_field_is_refused_by_its_type(tmp_path: Path) -> None:
    """`_require_str` refused nothing in this file; measured by disabling its check."""
    material = _canonical_copy(tmp_path)
    entries = _read_json(material / gen_trusted_log.LOG_KEYS_NAME)
    assert isinstance(entries, list)
    entries[0]["origin"] = 7
    _write_json(material / gen_trusted_log.LOG_KEYS_NAME, entries)

    assert "origin in log-keys.json[0] must be a string, got int" in _refusal(material)


def test_a_repeated_key_in_the_canonical_json_is_refused(tmp_path: Path) -> None:
    """Written as text, because no JSON encoder will emit a duplicate key.

    It matters because the two parsers disagree: the CLI reads these files with one that
    keeps the last of a repeated key, so a file like this would mean one thing to a
    verifier and another to whatever read it strictly. `canon.loads_strict` refuses it
    instead of silently picking a winner.
    """
    material = _canonical_copy(tmp_path)
    pin = json.dumps(_genesis_pin(), sort_keys=True)
    (material / gen_trusted_log.ANCHOR_POLICY_NAME).write_text(
        "{\n"
        '  "crqc_horizon": null,\n'
        '  "pinned_headers": {\n'
        f'    "{GENESIS_HEADER_HASH_DISPLAY}": {pin},\n'
        f'    "{GENESIS_HEADER_HASH_DISPLAY}": {pin}\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    message = _refusal(material)

    assert "duplicate object key" in message
    assert GENESIS_HEADER_HASH_DISPLAY in message


# --- The log keys: a key that signs nothing is not a key -------------------


def test_a_log_key_of_the_wrong_length_is_refused(tmp_path: Path) -> None:
    material = _canonical_copy(tmp_path)
    entries = _read_json(material / gen_trusted_log.LOG_KEYS_NAME)
    assert isinstance(entries, list)
    entries[0]["mldsa_pub_b64u"] = keys.b64u(b"\x00" * (pq.ML_DSA_65_PK_LEN - 1))
    _write_json(material / gen_trusted_log.LOG_KEYS_NAME, entries)

    assert f"log_key.mldsa_pub must be {pq.ML_DSA_65_PK_LEN} bytes" in _refusal(material)


def test_a_well_formed_key_that_did_not_sign_the_checkpoint_is_refused(tmp_path: Path) -> None:
    """The check that shape cannot make: does this key verify what the log serves?

    A mistyped or stale public key has the right length and the right alphabet. Only
    running it against a real signature separates a key from a string, which is why the
    generator verifies the published checkpoint before it will write anything.
    """
    material = _canonical_copy(tmp_path)
    entries = _read_json(material / gen_trusted_log.LOG_KEYS_NAME)
    assert isinstance(entries, list)
    entries[0]["ed25519_pub_b64u"] = keys.b64u(bytes(range(32)))
    _write_json(material / gen_trusted_log.LOG_KEYS_NAME, entries)

    message = _refusal(material)

    assert "does not verify the checkpoint the site serves" in message
    assert "checkpoint has no valid Ed25519+ML-DSA-65 signature pair" in message


def test_pinning_no_log_key_at_all_is_refused(tmp_path: Path) -> None:
    """An empty array would render an empty `LOG_KEYS` and verify nothing, successfully."""
    material = _canonical_copy(tmp_path)
    _write_json(material / gen_trusted_log.LOG_KEYS_NAME, [])

    assert "pins no log key" in _refusal(material)


# --- The raw headers: every pinned field is recomputed from the 80 bytes ----


def test_a_truncated_raw_header_is_refused(tmp_path: Path) -> None:
    _pin_genesis(
        material := _canonical_copy(tmp_path),
        source={**_genesis_source(), "raw_header_hex": GENESIS_HEADER_HEX[:-2]},
    )

    assert "raw header must be 160 lowercase hex chars (80 bytes), got 158" in _refusal(material)


def test_a_merkle_root_in_display_order_is_refused_and_named_as_such(tmp_path: Path) -> None:
    """The mistake this whole chain of checks exists for.

    `bitcoin-cli getblockheader` and every block explorer print `merkleroot` byte-reversed
    from the order the header carries and an OpenTimestamps replay lands on. The two are
    the same 32 bytes read in opposite directions, so the wrong one is exactly as
    plausible as the right one to anyone reading the file — and it would pin a header no
    proof can ever match. Saying "display order" in the refusal is what turns a puzzling
    mismatch into an instruction.
    """
    _pin_genesis(
        material := _canonical_copy(tmp_path),
        pin={**_genesis_pin(), "merkle_root": GENESIS_MERKLE_ROOT_DISPLAY},
    )

    message = _refusal(material)

    assert "merkle_root" in message
    assert "it equals the byte reversal of bytes 36-68: supplied in display order" in message


def test_a_pinned_time_that_is_not_the_headers_own_is_refused(tmp_path: Path) -> None:
    _pin_genesis(
        material := _canonical_copy(tmp_path), pin={**_genesis_pin(), "time": GENESIS_TIME + 1}
    )

    message = _refusal(material)

    assert "time" in message
    assert str(GENESIS_TIME) in message


def test_a_source_entry_whose_hash_is_not_its_own_headers_is_refused(tmp_path: Path) -> None:
    material = _canonical_copy(tmp_path)
    _pin_genesis(material)
    _write_json(
        material / gen_trusted_log.PINNED_SOURCE_NAME,
        [{**_genesis_source(), "raw_header_hex": "00" * 80}],
    )

    assert "is not the hash of its own raw header" in _refusal(material)


def test_a_raw_header_the_policy_does_not_pin_is_refused(tmp_path: Path) -> None:
    """Half of a set comparison is not a check: this is the direction the policy is empty."""
    material = _canonical_copy(tmp_path)
    _write_json(material / gen_trusted_log.PINNED_SOURCE_NAME, [_genesis_source()])

    message = _refusal(material)

    assert "does not pin" in message
    assert GENESIS_HEADER_HASH_DISPLAY in message


def test_a_pinned_header_with_no_raw_header_is_refused(tmp_path: Path) -> None:
    """The other direction: a pin nobody can recompute is a value taken on faith."""
    material = _canonical_copy(tmp_path)
    _pin_genesis(material)
    _write_json(material / gen_trusted_log.PINNED_SOURCE_NAME, [])

    message = _refusal(material)

    assert "has no source entry" in message
    assert GENESIS_HEADER_HASH_DISPLAY in message


def test_the_same_header_recorded_twice_in_the_source_is_refused(tmp_path: Path) -> None:
    """The duplicate `canon.loads_strict` cannot see: a repeated ARRAY entry, not a key.

    Two entries for one block cannot disagree about the three derived fields — each is
    recomputed from its own raw header — but they can disagree about everything that is
    not derived: the height, where the header came from, which checkpoint it anchors and
    which proof stands behind it. Whichever a reader believes, the other one is wrong.
    """
    material = _canonical_copy(tmp_path)
    _pin_genesis(material)
    _write_json(
        material / gen_trusted_log.PINNED_SOURCE_NAME,
        [
            _genesis_source(),
            {**_genesis_source(), "source": "a second node", "ots_proof": "9/other.json"},
        ],
    )

    message = _refusal(material)

    assert "is already recorded by" in message
    assert GENESIS_HEADER_HASH_DISPLAY in message


def test_an_unknown_field_in_a_source_entry_is_refused(tmp_path: Path) -> None:
    _pin_genesis(
        material := _canonical_copy(tmp_path), source={**_genesis_source(), "note": "from a node"}
    )

    assert "unknown field 'note' in pinned-headers.source.json[0]" in _refusal(material)


# --- The populated branch of the template ----------------------------------


def test_a_consistent_pinned_header_renders_the_populated_branch(tmp_path: Path) -> None:
    """The positive control for every refusal above, and the only test of that branch.

    The empty policy the repository ships today never reaches this half of the template,
    so without a synthetic pin the populated branch would be written, committed and never
    executed until the day a real header is pinned.
    """
    _pin_genesis(material := _canonical_copy(tmp_path))

    rendered = gen_trusted_log.render(material)

    assert "// Pinned headers: one per anchored checkpoint" in rendered
    assert "// No anchor has been attached to a checkpoint yet" not in rendered
    assert (
        "export const ANCHOR_POLICY: AnchorPolicy = { pinnedHeaders: { "
        f'"{GENESIS_HEADER_HASH_DISPLAY}": '
        f'{{ headerHash: "{GENESIS_HEADER_HASH_DISPLAY}", '
        f'merkleRoot: "{GENESIS_MERKLE_ROOT_INTERNAL}", '
        f"time: {GENESIS_TIME} }} }}, crqcHorizon: null }}"
    ) in rendered


def test_a_non_null_crqc_horizon_reaches_the_rendered_file(tmp_path: Path) -> None:
    """The template's other future branch, and the one with no positive control.

    The populated `pinnedHeaders` branch is driven above precisely because the shipped
    policy never reaches it. `crqcHorizon` is in the same position and was not: every
    fixture leaves it `None`, so replacing `str(policy.crqc_horizon)` with a constant
    left this file green. A horizon is a compromise cutoff — rendering it wrongly on the
    day one is set changes which receipts survive a declaration, silently.
    """
    material = _canonical_copy(tmp_path)
    _write_json(
        material / gen_trusted_log.ANCHOR_POLICY_NAME,
        {"crqc_horizon": 1893456000, "pinned_headers": {}},
    )

    rendered = gen_trusted_log.render(material)

    assert "crqcHorizon: 1893456000 }" in rendered
    assert "crqcHorizon: null" not in rendered


def test_the_rendered_policy_does_not_depend_on_the_order_of_its_input(tmp_path: Path) -> None:
    """Two headers, written in both orders, must produce the same bytes.

    Otherwise the drift check becomes a test of how an editor left the file, and a real
    regeneration would show a diff that changes nothing.
    """
    second_source = {
        **_genesis_source(),
        "height": 1,
        "header_hash": "00" * 32,
        "raw_header_hex": "ff" * 80,
    }
    second_raw = bytes.fromhex(second_source["raw_header_hex"])
    from tools import bitcoin_header

    second_pin = {
        "header_hash": bitcoin_header.header_hash_display(second_raw),
        "merkle_root": bitcoin_header.merkle_root_internal(second_raw),
        "time": bitcoin_header.header_time(second_raw),
    }
    second_source["header_hash"] = second_pin["header_hash"]
    pins = {GENESIS_HEADER_HASH_DISPLAY: _genesis_pin(), second_pin["header_hash"]: second_pin}
    sources = [_genesis_source(), second_source]

    forward = _canonical_copy(tmp_path / "forward")
    _write_json(
        forward / gen_trusted_log.ANCHOR_POLICY_NAME,
        {"crqc_horizon": None, "pinned_headers": pins},
    )
    _write_json(forward / gen_trusted_log.PINNED_SOURCE_NAME, sources)

    reversed_dir = _canonical_copy(tmp_path / "reversed")
    (reversed_dir / gen_trusted_log.ANCHOR_POLICY_NAME).write_text(
        json.dumps({"crqc_horizon": None, "pinned_headers": dict(reversed(list(pins.items())))})
        + "\n",
        encoding="utf-8",
    )
    _write_json(reversed_dir / gen_trusted_log.PINNED_SOURCE_NAME, list(reversed(sources)))

    assert gen_trusted_log.render(forward) == gen_trusted_log.render(reversed_dir)


_TYPECHECK_ABSENT = (
    "needs the site's own typechecker and the built verifier declarations: run "
    "`npm ci --prefix site` and `npm run build --prefix verifiers/ts`"
)


def test_a_populated_policy_typechecks_against_the_shipped_types(tmp_path: Path) -> None:
    """Compile the populated branch with the site's own `tsc`, against the real types.

    The empty branch is typechecked on every `npm run build`, because it is the file that
    ships. The populated one is not compiled by anything until a header is pinned, which
    is the worst possible moment to discover that `headerHash` was spelled `header_hash`.

    This is the real typechecker (`site/node_modules/.bin/tsc`) resolving
    `attest-verifier` to the declarations the site resolves it to — not a reconstruction
    of `AnchorPolicy` written here, which would only ever agree with itself. Measured by
    ablation: renaming `merkleRoot` to `merkle_root` in the rendered file fails with
    TS2561 naming `PinnedHeader`, and typing `time` as a string fails with TS2322.

    The prerequisites are installed by the job that runs this suite, so that job is the
    one entitled to demand them. A bare `skipif` would have skipped the ONLY compilation
    of the populated branch exactly where the workflow promises that a missing
    prerequisite fails instead — a silence in the place built to remove it.
    """
    if not SITE_TSC.exists() or not VERIFIER_TYPES.exists():
        if ci_prerequisites_required():
            pytest.fail(_TYPECHECK_ABSENT)
        pytest.skip(_TYPECHECK_ABSENT)
    _pin_genesis(material := _canonical_copy(tmp_path))
    project = tmp_path / "typecheck"
    project.mkdir()
    (project / "trusted-log.ts").write_text(gen_trusted_log.render(material), encoding="utf-8")
    shutil.copy(REPO_ROOT / "site" / "src" / "b64u.ts", project / "b64u.ts")
    site_options = json.loads((REPO_ROOT / "site" / "tsconfig.json").read_text(encoding="utf-8"))[
        "compilerOptions"
    ]
    _write_json(
        project / "tsconfig.json",
        {
            # The site's own options, minus the ambient type packages this one file does
            # not use and could not resolve from outside the site tree.
            "compilerOptions": {
                **{key: value for key, value in site_options.items() if key != "types"},
                "baseUrl": ".",
                "paths": {"attest-verifier": [str(VERIFIER_TYPES)]},
            },
            "include": ["."],
        },
    )

    completed = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        [str(SITE_TSC), "--noEmit", "-p", str(project / "tsconfig.json")],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        cwd=project,
        env={**os.environ, "NO_COLOR": "1"},
    )

    assert completed.returncode == 0, (
        f"the populated ANCHOR_POLICY branch does not typecheck:\n{completed.stdout}"
        f"{completed.stderr}"
    )
