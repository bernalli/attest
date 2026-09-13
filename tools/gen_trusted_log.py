"""Generate `site/src/trusted-log.ts` from the canonical trust material, refusing bad input.

The browser and the desktop app carry their own copy of what
`docs/trust/attest-receipts.org-log/` already states: the same log keys, the same
anchoring policy, spelled for TypeScript instead of for the command line. Two
hand-maintained copies of one fact drift apart, and a drifted copy here is not cosmetic —
it is the page trusting a signing key, or a Bitcoin block header, that nothing else in
the repository trusts. So one of the two is generated, and this is the generator.

What it will not do is copy. Every value it emits has been through the code that owns the
rule for it, and a value that does not survive that code produces no file at all:

- the JSON is read with `canon.loads_strict`, which refuses duplicate object keys. The
  CLI's own loaders use a parser that keeps the last of a repeated key instead, so a file
  that names `pinned_headers` twice would mean one thing to a verifier and another here;
- unknown and missing fields are refused. The CLI's loaders ignore what they do not
  recognise, which is the right call for a flag a user points at an arbitrary file and the
  wrong one for the canonical source that this repository maintains: a misspelt field name
  should be a refusal, not a silently dropped pin;
- the policy is handed to `anchor.validate_policy`, the same function a verifier runs over
  it, rather than to a second spelling of those rules here;
- every pinned log key must actually verify the checkpoint the site serves under
  `site/public/log/`. A key of the right shape that signs nothing is exactly what a
  trust-store typo produces, and shape alone cannot tell the two apart;
- every pinned header must be recomputable from the raw 80-byte header recorded beside it
  in `pinned-headers.source.json`, using `tools/bitcoin_header.py` — including the byte
  order of `merkle_root`, where the plausible-looking mistake is to copy the value a block
  explorer prints, which is the same 32 bytes reversed.

Usage: `uv run --frozen python tools/gen_trusted_log.py` writes the file;
`--check` rewrites nothing and exits non-zero if the committed file has drifted.
Exit 1 means drift, exit 2 means the trust material was refused.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import cast

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attest import anchor, canon, keys, tlog
from tools import bitcoin_header

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The canonical trust material for `attest-receipts.org/log`, in the shape the CLI's
#: `--log-keys` and `--anchor-policy` read.
TRUST_DIR = REPO_ROOT / "docs" / "trust" / "attest-receipts.org-log"

#: The checkpoint the site publishes, and the origin it is published under. The pinned
#: keys are checked against these: this is what turns "the key has the right shape" into
#: "the key signs what this log serves".
CHECKPOINT_PATH = REPO_ROOT / "site" / "public" / "log" / "checkpoint"
LOG_CONFIG_PATH = REPO_ROOT / "site" / "public" / "log" / "config.json"

#: The file this generator owns. Editing it by hand is what the generator exists to stop.
OUTPUT_PATH = REPO_ROOT / "site" / "src" / "trusted-log.ts"

LOG_KEYS_NAME = "log-keys.json"
ANCHOR_POLICY_NAME = "anchor-policy.json"
PINNED_SOURCE_NAME = "pinned-headers.source.json"

#: The fields each canonical record carries, exactly. Anything else is a refusal rather
#: than something quietly ignored.
_LOG_KEY_FIELDS = ("origin", "name", "ed25519_pub_b64u", "mldsa_pub_b64u")
_ANCHOR_POLICY_FIELDS = ("pinned_headers", "crqc_horizon")
_PINNED_HEADER_FIELDS = ("header_hash", "merkle_root", "time")
_SOURCE_ENTRY_FIELDS = (
    "height",
    "header_hash",
    "raw_header_hex",
    "source",
    "anchored_checkpoint_tree_size",
    "ots_proof",
)

_FILE_HEADER = """\
import { b64uDecode } from './b64u.js'
import type { LogKey, AnchorPolicy } from 'attest-verifier'

// The verifier's own TRUSTED configuration — not evidence. Everything here is
// pinned out of band and shipped inside the page: v0.2 §7.3 forbids a verifier
// from taking log keys from the material it is checking, which is why these
// bytes are compiled in rather than fetched, and why the log does not serve a
// copy of them next to itself.
//
// Compiled in, also, so the page keeps the promise it makes to the reader: cut
// the network after it loads and verification still works. A JSON asset would
// have made this one more request.
//
// These are PUBLIC keys. The private halves that sign the checkpoints live
// outside this repository and are seen only by the signing ceremony.
"""

_EMPTY_POLICY_COMMENT = """\
// No anchor has been attached to a checkpoint yet, so nothing is pinned. This
// is NOT a placeholder that weakens anything: an empty policy simply pins no
// Bitcoin header, and a proof pointing at an unpinned header degrades to a
// warning while the receipt keeps its `logged` standing. Supplying the policy
// at all is half of the capability gate — without it, evidence is not even
// looked at. Entries appear here, one per block, once anchoring lands.
"""

_PINNED_POLICY_COMMENT = """\
// Pinned headers: one per anchored checkpoint, each added by the process in
// docs/trust/README.md; the raw header each derives from is in pinned-headers.source.json.
"""


class TrustMaterialError(ValueError):
    """The canonical trust material was refused, so no file is written.

    Carries the message of whichever owner did the refusing — `anchor.validate_policy`,
    `tlog.verify_checkpoint`, `canon.loads_strict`, `bitcoin_header` — prefixed with the
    file and the record it came from, so the reader learns both what is wrong and where.
    """


def _repo_relative(path: Path) -> str:
    """Name `path` the way a reader can act on it: repository-relative, or absolute.

    Every path this module names in a message is overridable — `render` takes the
    material, the checkpoint and the log config as arguments, and says so — so a bare
    `relative_to(REPO_ROOT)` raises `ValueError` on exactly the call it was written to
    serve. Two of the three sites sit inside a refusal, where that crash REPLACES the
    refusal: `main` catches `TrustMaterialError`, not `ValueError`, so the process dies
    on a traceback instead of exiting 2. `_anchors_label` in
    `tests/test_shipped_anchor_policy.py` already answers this for the sibling guard;
    this is the same answer on the generator's side.
    """
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _quoted(value: str) -> str:
    """Render a TypeScript double-quoted string literal.

    JSON's string escapes are a subset of TypeScript's, so the JSON encoder produces a
    literal TypeScript reads identically, with anything non-ASCII escaped to `\\uXXXX`
    rather than emitted raw.
    """
    return json.dumps(value)


def _read_json(path: Path) -> object:
    """Read one canonical JSON file with the strict parser."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TrustMaterialError(f"{path.name}: {exc}") from exc
    try:
        return canon.loads_strict(raw)
    except canon.CanonError as exc:
        raise TrustMaterialError(f"{path.name}: {exc}") from exc


def _require_object(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TrustMaterialError(f"{where} must be a JSON object")
    return value


def _require_array(value: object, where: str) -> list[object]:
    if not isinstance(value, list):
        raise TrustMaterialError(f"{where} must be a JSON array")
    return value


def _require_exact_fields(record: dict[str, object], fields: Sequence[str], where: str) -> None:
    """Refuse a record that names a field we do not know, or omits one we need.

    Both directions matter and for different reasons: an unknown field is usually a
    misspelling of a real one, which would otherwise ship a record missing the value the
    author believed they had written; a missing one would otherwise reach a constructor as
    a default nobody chose.
    """
    unknown = sorted(set(record) - set(fields))
    if unknown:
        raise TrustMaterialError(f"unknown field {unknown[0]!r} in {where}")
    missing = [field for field in fields if field not in record]
    if missing:
        raise TrustMaterialError(f"missing field {missing[0]!r} in {where}")


def _require_str(value: object, field: str, where: str) -> str:
    if not isinstance(value, str):
        raise TrustMaterialError(f"{field} in {where} must be a string, got {type(value).__name__}")
    return value


def load_log_keys(path: Path) -> list[tlog.LogKey]:
    """Build the pinned log keys, refusing anything the shape rules do not admit.

    The cryptographic half of the check is not here: see `_verify_against_checkpoint`.
    """
    entries = _require_array(_read_json(path), path.name)
    if not entries:
        raise TrustMaterialError(
            f"{path.name} pins no log key; a page that pins none accepts no checkpoint, "
            "and generating one would report success for having checked nothing"
        )
    log_keys: list[tlog.LogKey] = []
    for index, entry in enumerate(entries):
        where = f"{path.name}[{index}]"
        record = _require_object(entry, where)
        _require_exact_fields(record, _LOG_KEY_FIELDS, where)
        try:
            ed25519_pub = keys.b64u_decode(
                _require_str(record["ed25519_pub_b64u"], "ed25519_pub_b64u", where)
            )
            mldsa_pub = keys.b64u_decode(
                _require_str(record["mldsa_pub_b64u"], "mldsa_pub_b64u", where)
            )
        except ValueError as exc:
            raise TrustMaterialError(f"{where}: {exc}") from exc
        log_keys.append(
            tlog.LogKey(
                origin=_require_str(record["origin"], "origin", where),
                name=_require_str(record["name"], "name", where),
                ed25519_pub=ed25519_pub,
                mldsa_pub=mldsa_pub,
            )
        )
    return log_keys


def _verify_against_checkpoint(
    log_keys: Sequence[tlog.LogKey], checkpoint_path: Path, log_config_path: Path
) -> str:
    """Require every pinned key to verify the checkpoint the site actually serves.

    This is the step that distinguishes a key from a well-formed string. A mistyped or
    stale public key has the right length and the right alphabet; only running it against
    a real signature says whether the page would accept anything signed by the log.

    Returns the log origin, which the generated file also exports.
    """
    config = _require_object(_read_json(log_config_path), log_config_path.name)
    origin = _require_str(config.get("origin"), "origin", log_config_path.name)
    try:
        text = checkpoint_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TrustMaterialError(f"{checkpoint_path.name}: {exc}") from exc
    for index, log_key in enumerate(log_keys):
        try:
            tlog.verify_checkpoint(text, log_key, origin)
        except ValueError as exc:
            raise TrustMaterialError(
                f"{LOG_KEYS_NAME}[{index}] does not verify the checkpoint the site serves "
                f"at {_repo_relative(checkpoint_path)}: {exc}"
            ) from exc
    return origin


def load_anchor_policy(path: Path) -> anchor.AnchorPolicy:
    """Build the anchoring policy and hand it to the code that owns its rules.

    The fields go to `anchor.PinnedHeader` and `anchor.AnchorPolicy` exactly as the JSON
    gave them, wrong types included: `anchor.validate_policy` is the one place that decides
    what a pinned header may say, and a type check here would answer the same question in
    different words and eventually a different way.
    """
    document = _require_object(_read_json(path), path.name)
    _require_exact_fields(document, _ANCHOR_POLICY_FIELDS, path.name)
    raw_headers = document["pinned_headers"]
    pinned_headers: dict[str, anchor.PinnedHeader] = {}
    if isinstance(raw_headers, dict):
        for header_hash, raw_header in raw_headers.items():
            where = f"pinned header {header_hash}"
            record = _require_object(raw_header, where)
            _require_exact_fields(record, _PINNED_HEADER_FIELDS, where)
            pinned_headers[header_hash] = anchor.PinnedHeader(
                header_hash=cast(str, record["header_hash"]),
                merkle_root=cast(str, record["merkle_root"]),
                time=cast(int, record["time"]),
            )
    policy = anchor.AnchorPolicy(
        # A `pinned_headers` that is not an object at all goes through untouched too, so the
        # refusal is still the validator's own "policy.pinned_headers must be a dict".
        pinned_headers=(
            pinned_headers
            if isinstance(raw_headers, dict)
            else cast("dict[str, anchor.PinnedHeader]", raw_headers)
        ),
        crqc_horizon=cast("int | None", document["crqc_horizon"]),
    )
    try:
        return anchor.validate_policy(policy)
    except ValueError as exc:
        raise TrustMaterialError(f"{path.name}: {exc}") from exc


def check_headers_derive_from_source(policy: anchor.AnchorPolicy, path: Path) -> None:
    """Recompute every pinned field from the raw header recorded beside it.

    A pinned entry is three numbers copied out of a block, and two of them have a byte
    order that is easy to get backwards. Recomputing them from the raw 80 bytes is the only
    check that tells a right entry from a plausible one, so the raw header travels with the
    pin and this runs before anything is written.
    """
    entries = _require_array(_read_json(path), path.name)
    seen: dict[str, str] = {}
    for index, entry in enumerate(entries):
        where = f"{path.name}[{index}]"
        record = _require_object(entry, where)
        _require_exact_fields(record, _SOURCE_ENTRY_FIELDS, where)
        raw_hex = _require_str(record["raw_header_hex"], "raw_header_hex", where)
        try:
            raw = bitcoin_header.require_raw_header(raw_hex)
        except ValueError as exc:
            raise TrustMaterialError(f"{where}: {exc}") from exc
        derived_hash = bitcoin_header.header_hash_display(raw)
        declared_hash = _require_str(record["header_hash"], "header_hash", where)
        if declared_hash != derived_hash:
            raise TrustMaterialError(
                f"{where}: header_hash {declared_hash!r} is not the hash of its own raw "
                f"header, which is {derived_hash!r}"
            )
        if derived_hash in seen:
            raise TrustMaterialError(
                f"{where}: header_hash {derived_hash!r} is already recorded by {seen[derived_hash]}"
            )
        seen[derived_hash] = where

    _require_same_headers(policy, set(seen), path)

    for index, entry in enumerate(entries):
        record = cast(dict[str, object], entry)
        raw = bitcoin_header.require_raw_header(cast(str, record["raw_header_hex"]))
        header_hash = cast(str, record["header_hash"])
        pinned = policy.pinned_headers[header_hash]
        where = f"pinned header {header_hash}"
        source_where = f"{path.name}[{index}]"
        derived_root = bitcoin_header.merkle_root_internal(raw)
        if pinned.merkle_root != derived_root:
            message = (
                f"{where}: merkle_root {pinned.merkle_root!r} is not bytes 36-68 of the raw "
                f"header in {source_where}, which are {derived_root!r}"
            )
            if pinned.merkle_root == raw[36:68][::-1].hex():
                message += "; it equals the byte reversal of bytes 36-68: supplied in display order"
            raise TrustMaterialError(message)
        derived_time = bitcoin_header.header_time(raw)
        if pinned.time != derived_time:
            raise TrustMaterialError(
                f"{where}: time {pinned.time!r} is not the timestamp of the raw header in "
                f"{source_where}, which is {derived_time!r}"
            )


def _require_same_headers(policy: anchor.AnchorPolicy, source_hashes: set[str], path: Path) -> None:
    """Require the two files to name the same set of blocks, in both directions.

    One direction alone is half a check: a pin with no raw header is a value nobody can
    recompute, and a raw header with no pin is a block the page does not actually trust,
    usually because the pin was dropped in an edit.
    """
    pinned_hashes = set(policy.pinned_headers)
    unpinned = sorted(source_hashes - pinned_hashes)
    if unpinned:
        raise TrustMaterialError(
            f"{path.name} records raw header {unpinned[0]!r}, which {ANCHOR_POLICY_NAME} "
            "does not pin"
        )
    unsourced = sorted(pinned_hashes - source_hashes)
    if unsourced:
        raise TrustMaterialError(
            f"pinned header {unsourced[0]}: has no source entry in {path.name}, so none of "
            "its fields can be recomputed"
        )


def _render_log_keys(log_keys: Sequence[tlog.LogKey]) -> str:
    """Render the `LOG_KEYS` array.

    The base64url is re-encoded from the bytes that just verified the checkpoint, not
    copied from the JSON: what ships is then provably the key that was tested, in the
    unpadded spelling the page's own `b64uDecode` accepts — it rejects padding.
    """
    lines = ["export const LOG_KEYS: LogKey[] = ["]
    for log_key in log_keys:
        lines.append("  {")
        lines.append(f"    origin: {_quoted(log_key.origin)},")
        lines.append(f"    name: {_quoted(log_key.name)},")
        lines.append("    ed25519Pub: b64uDecode(")
        lines.append(f"      {_quoted(keys.b64u(log_key.ed25519_pub))},")
        lines.append("    ),")
        lines.append("    mldsaPub: b64uDecode(")
        lines.append(f"      {_quoted(keys.b64u(log_key.mldsa_pub))},")
        lines.append("    ),")
        lines.append("  },")
    lines.append("]")
    return "\n".join(lines) + "\n"


def _render_anchor_policy(policy: anchor.AnchorPolicy) -> str:
    """Render the `ANCHOR_POLICY` constant, with the comment its state deserves.

    Pinned headers are emitted in sorted order, so the file depends on what the policy
    says and not on the order an editor happened to leave it in.
    """
    horizon = "null" if policy.crqc_horizon is None else str(policy.crqc_horizon)
    if not policy.pinned_headers:
        comment = _EMPTY_POLICY_COMMENT
        pinned = "{}"
    else:
        comment = _PINNED_POLICY_COMMENT
        rendered = ", ".join(
            f"{_quoted(header_hash)}: {{ headerHash: "
            f"{_quoted(policy.pinned_headers[header_hash].header_hash)}, merkleRoot: "
            f"{_quoted(policy.pinned_headers[header_hash].merkle_root)}, time: "
            f"{policy.pinned_headers[header_hash].time} }}"
            for header_hash in sorted(policy.pinned_headers)
        )
        pinned = f"{{ {rendered} }}"
    return (
        f"{comment}export const ANCHOR_POLICY: AnchorPolicy = "
        f"{{ pinnedHeaders: {pinned}, crqcHorizon: {horizon} }}\n"
    )


def render(
    source_dir: Path | None = None,
    *,
    checkpoint_path: Path | None = None,
    log_config_path: Path | None = None,
) -> str:
    """Return the TypeScript for `source_dir`, or raise `TrustMaterialError`.

    Returning text rather than writing is what lets `--check` and the test suite ask what
    the material produces without touching the tree, and what makes a refusal produce no
    file: there is nothing to undo, because nothing was opened for writing.

    The paths default to the canonical ones at call time rather than at import time, so the
    module constants stay the single place they are named — and a test can point the whole
    generator at a copy without reaching inside it.
    """
    source_dir = TRUST_DIR if source_dir is None else source_dir
    checkpoint_path = CHECKPOINT_PATH if checkpoint_path is None else checkpoint_path
    log_config_path = LOG_CONFIG_PATH if log_config_path is None else log_config_path
    log_keys = load_log_keys(source_dir / LOG_KEYS_NAME)
    origin = _verify_against_checkpoint(log_keys, checkpoint_path, log_config_path)
    policy = load_anchor_policy(source_dir / ANCHOR_POLICY_NAME)
    check_headers_derive_from_source(policy, source_dir / PINNED_SOURCE_NAME)
    return (
        f"{_FILE_HEADER}\n"
        f"export const LOG_ORIGIN = {_quoted(origin)}\n"
        f"\n"
        f"{_render_log_keys(log_keys)}"
        f"\n"
        f"{_render_anchor_policy(policy)}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate site/src/trusted-log.ts from docs/trust/attest-receipts.org-log/."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="write nothing; exit 1 if the committed file differs from what this produces",
    )
    args = parser.parse_args(argv)

    try:
        rendered = render()
    except TrustMaterialError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    relative = _repo_relative(OUTPUT_PATH)
    committed = OUTPUT_PATH.read_text(encoding="utf-8") if OUTPUT_PATH.exists() else None
    if args.check:
        if committed != rendered:
            print(
                f"{relative} drifts from {_repo_relative(TRUST_DIR)}/: "
                "run tools/gen_trusted_log.py",
                file=sys.stderr,
            )
            return 1
        print(f"unchanged: {relative}")
        return 0

    if committed == rendered:
        print(f"unchanged: {relative}")
        return 0
    OUTPUT_PATH.write_text(rendered, encoding="utf-8")
    print(f"written:   {relative} ({len(rendered.encode('utf-8'))} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
