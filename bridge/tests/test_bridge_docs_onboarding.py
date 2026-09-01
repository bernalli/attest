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


def _top_level_tables(config_text: str) -> list[str]:
    """Top-level table names, in file order, `[a.b]` reported as `a`."""
    seen: list[str] = []
    for match in re.finditer(r"^\[([^\]]+)\]", config_text, flags=re.MULTILINE):
        name = match.group(1).split(".")[0].strip()
        if name not in seen:
            seen.append(name)
    return seen


def _platform_rails(config_text: str) -> list[str]:
    return [name for name in _top_level_tables(config_text) if name not in _NON_PLATFORM_TABLES]


def _drop_table(config_text: str, table: str) -> str:
    """Remove `[table]` and its sub-tables, up to the next unrelated table.

    Mirrors what a reader does with "omit this whole table": the commented
    banner above the table goes with it, since it is that table's own
    explanation.
    """
    lines = config_text.splitlines(keepends=True)
    out: list[str] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].lstrip()
        header = re.match(r"^\[([^\]]+)\]", stripped)
        if header is not None and header.group(1).split(".")[0].strip() == table:
            # Walk back over the comment banner that introduces this table.
            while out and out[-1].lstrip().startswith("#"):
                out.pop()
            index += 1
            while index < len(lines):
                nxt = re.match(r"^\[([^\]]+)\]", lines[index].lstrip())
                if nxt is not None and nxt.group(1).split(".")[0].strip() != table:
                    break
                index += 1
            # Leave at most one blank separator behind.
            while out and not out[-1].strip():
                out.pop()
            out.append("\n")
            continue
        out.append(lines[index])
        index += 1
    return "".join(out)


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


def _tables_the_guide_says_to_remove(guide_text: str, rails: list[str]) -> set[str]:
    """Rails a guide tells the reader to take out of the config.

    The unit is the paragraph, not the line: prose wraps where it wraps, and
    a test that demanded the verb and the table name land on the same line
    would be dictating line breaks instead of checking that the reader was
    told.
    """
    told: set[str] = set()
    for paragraph in re.split(r"\n\s*\n", guide_text):
        lowered = paragraph.lower()
        if not any(verb in lowered for verb in _REMOVAL_VERBS):
            continue
        for rail in rails:
            if f"[{rail}]" in paragraph:
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


def _sample_summary_lines(guide_text: str) -> list[str] | None:
    """The fenced `check-config` summary a guide shows, if it shows one.

    Splits on the fence marker rather than matching a fenced block with a
    regex: an alternating split cannot mistake a closing fence for an opening
    one, which is exactly the confusion that would make this helper report
    "no sample here" for a guide that has one.
    """
    for block in guide_text.split("```")[1::2]:
        lines = [line for line in block.splitlines() if line.strip()]
        if lines and lines[0].startswith("issuer: "):
            return lines
    return None


@pytest.mark.parametrize("guide_name", sorted(_GUIDES.values()))
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

    assert [line.split(":")[0] for line in sample] == [line.split(":")[0] for line in printed], (
        f"{guide_name} shows a check-config summary that the CLI does not print"
    )
