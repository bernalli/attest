"""Drift guard for the threat-model and privacy companion documents.

Cross-checks `docs/spec/attest-threat-model.md` and `docs/spec/attest-privacy.md`
against each other, against `docs/spec/attest-v0.1.md` / `attest-v0.2.md`, and
against the receipt schema: TM-id sequence and uniqueness, the verdict-line
grammar, spec-reference resolution inside verdict lines, traceability-matrix
coverage and TM citations, the PC testable-claims check-type vocabulary, and
the PC-01 buyer-field pin against the schema. Stdlib only; run standalone via
`uv run python tools/check_spec_docs.py` (also wired into CI).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import NamedTuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
_THREAT_MODEL_PATH = _REPO_ROOT / "docs/spec/attest-threat-model.md"
_PRIVACY_PATH = _REPO_ROOT / "docs/spec/attest-privacy.md"
_SPEC_V01_PATH = _REPO_ROOT / "docs/spec/attest-v0.1.md"
_SPEC_V02_PATH = _REPO_ROOT / "docs/spec/attest-v0.2.md"
_SCHEMA_PATH = _REPO_ROOT / "docs/spec/schema/attest-receipt.schema.json"
_VERSIONING_PATH = _REPO_ROOT / "docs/spec/attest-versioning.md"
_VECTORS_PATH = _REPO_ROOT / "docs/spec/vectors"
_STANDARDS_RELATIONSHIP_PATH = _REPO_ROOT / "docs/spec/attest-standards-relationship.md"
_INTERNET_DRAFT_DIR = _REPO_ROOT / "ietf"
_INTERNET_DRAFT_BASENAME = "draft-bernalli-open-purchase-receipts"
_CONFORMANCE_DOC_PATH = _REPO_ROOT / "docs/conformance.md"

# The six normative sections attest-versioning.md's amendment procedure
# requires (§5) every reader be able to find by exact heading.
_VERSIONING_REQUIRED_HEADINGS: tuple[str, ...] = (
    "## 1. Scope and authority",
    "## 2. The additive pattern",
    "## 3. Eternal verifiability",
    "## 4. Algorithm lifecycle",
    "## 5. Amendment procedure",
    "## 6. Registries",
)

# The two signature suites the two normative specs actually define (v0.1 §10,
# v0.2 §2). A registry entry for a suite neither spec defines would register
# nothing real; naming both here keeps that in sync by construction.
_VERSIONING_REQUIRED_SUITES: tuple[str, ...] = ("`ed25519`", "`ed25519+ml-dsa-65`")

# §4's algorithm lifecycle defines exactly these three states.
_VERSIONING_LIFECYCLE_STATES: tuple[str, ...] = ("`active`", "`deprecated`", "`unsafe`")

# §6.3 lists the existing `license.revocability` classes (v0.1 §5.5).
# `compromised` is NOT one of these: it is a key lifecycle STATUS (v0.1 §7.3),
# not a revocation class, and does not belong in this registry (2026-07-23 fix).
_VERSIONING_REQUIRED_REVOCATION_CLASSES: tuple[str, ...] = (
    "`none`",
    "`refund_window`",
    "`policy`",
)

# `transferred` (v0.2 §17, rev 6) just moved from `reserved` to `active` --
# checked separately from the tuple above, and for its exact state, not just
# its presence: a regression back to `reserved` in this table would silently
# undo the transfer profile's own registry activation, and mere row presence
# (the check every other class above gets) would not catch that regression.
_VERSIONING_ACTIVE_REVOCATION_CLASS = "`transferred`"

# Required traceability-matrix coverage: every numbered section of the two
# normative specs except each document's own §1 (conformance language) and
# v0.2 §5 (a worked example carrying no mechanism of its own).
REQUIRED_SECTIONS: tuple[str, ...] = tuple(f"v0.1 §{n}" for n in range(2, 16)) + tuple(
    f"v0.2 §{n}" for n in range(2, 18) if n != 5
)

_VALID_CHECK_TYPES = frozenset({"schema", "corpus", "spec-text", "manual"})

_TOP_HEADING_RE = re.compile(r"^## (\d+)\.\s")
_SUB_HEADING_RE = re.compile(r"^### (\d+\.\d+)\s")
_TM_HEADING_RE = re.compile(r"^#### TM-(\d+)\b.*$", re.MULTILINE)
_VERDICT_LINE_RE = re.compile(r"^- \*\*Verdict:\*\*.*$", re.MULTILINE)
_VERDICT_GRAMMAR_RE = re.compile(r"^- \*\*Verdict:\*\* (Mitigated|Out of scope) — .+$")
_REF_GROUP_RE = re.compile(
    r"(v0\.[12]) (§\d+(?:\.\d+)?(?:(?:[,;]\s*(?:and\s+)?|\s+and\s+)§\d+(?:\.\d+)?)*)"
)
_REF_SECTION_RE = re.compile(r"§\d+(?:\.\d+)?")
_MATRIX_ROW_RE = re.compile(r"^\| (v0\.[12]) §(\d+) — [^|]*\|([^|]*)\|\s*$", re.MULTILINE)
_MATRIX_TM_REF_RE = re.compile(r"TM-(\d+)")
# A cell may name a TM entry only in the canonical form. Anything else that reads
# as a citation — an en dash, an underscore, a missing number — must be reported
# rather than skipped, or a malformed citation silently covers nothing.
_MATRIX_TM_TOKEN_RE = re.compile(r"TM\S*")
_CANONICAL_TM_REF_RE = re.compile(r"TM-\d+")
# Only v0.1 and v0.2 exist, so any other version cited AS A SPEC is drift. The
# lookahead keeps ordinary prose ("TLS v1.3") out of it: without a section sign
# following, a version token is not a citation and flagging it would fail a
# legitimate edit.
_ANY_SPEC_VERSION_RE = re.compile(r"\bv\d+\.\d+(?=\s*§)")
# CommonMark opens a fence with ``` or ~~~, indented up to three spaces.
_FENCED_BLOCK_RE = re.compile(r"^ {0,3}(```|~~~).*?^ {0,3}\1", re.MULTILINE | re.DOTALL)
# XML comments (used only by check_internet_draft_snapshot(), which scans
# the .xml source rather than Markdown).
_XML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_PC_ROW_RE = re.compile(r"^\| PC-(\d+) \| ([^|]*) \| ([^|]*) \| ([^|]*) \|\s*$", re.MULTILINE)
_PC01_PIN_RE = re.compile(r"key set exactly `?\{([^}]*)\}")
_PC01_REQUIRED_PIN_RE = re.compile(r"`properties\.buyer\.required` equals `?(\[[^`]*\])`?")
_PC01_PATTERN_PIN_RE = re.compile(
    r"`([^`]+)` and `([^`]+)` are pattern-constrained to (\d+) base64url characters"
)
_PC01_PATTERN_FIELDS = {"commitment", "pubkey"}
_PC01_ENUM_PIN_RE = re.compile(r"`identifier_type` to the\s+enum `?(\[[^`]*\])`?")
_REVISION_LOG_HEADING_RE = re.compile(r"^## Revision log$", re.MULTILINE)
_REVISION_LOG_ENTRY_RE = re.compile(
    r"^- \*\*\d{4}-\d{2}-\d{2} \(rev \d+\)\*\*: .+ — vectors: \S.*$"
)

# §5.1's `receipt_id` row inlines the ULID regex in backticks, e.g.:
# `| \`receipt_id\` | string, ULID (\`^[0-7][0-9A-HJKMNP-TV-Z]{25}$\`) | REQUIRED | ... |`
_RECEIPT_ID_PROSE_ROW_RE = re.compile(r"\| `receipt_id` \| string, ULID \(`([^`]+)`\) \|")


class TmEntry(NamedTuple):
    """One `#### TM-nn` attack-catalog entry and its raw block text."""

    tm_id: int
    block: str


class PcRow(NamedTuple):
    """One row of the privacy doc's `## 7. Testable claims` table."""

    pc_id: int
    claim: str
    check_type: str
    detail: str


def parse_headings(spec_text: str) -> set[str]:
    """Map `## N.` and `### N.M` headings to `§N` / `§N.M`."""
    headings: set[str] = set()
    for line in spec_text.splitlines():
        top = _TOP_HEADING_RE.match(line)
        if top is not None:
            headings.add(f"§{top.group(1)}")
            continue
        sub = _SUB_HEADING_RE.match(line)
        if sub is not None:
            headings.add(f"§{sub.group(1)}")
    return headings


def _parse_tm_entries(threat_model: str) -> list[TmEntry]:
    matches = list(_TM_HEADING_RE.finditer(threat_model))
    entries: list[TmEntry] = []
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(threat_model)
        entries.append(TmEntry(tm_id=int(match.group(1)), block=threat_model[start:end]))
    return entries


def parse_tm_ids(threat_model: str) -> list[int]:
    """Every `#### TM-nn` id, in document order (duplicates preserved)."""
    return [entry.tm_id for entry in _parse_tm_entries(threat_model)]


def parse_pc_rows(privacy: str) -> list[PcRow]:
    """Every row of the `## 7. Testable claims` table, in document order."""
    rows: list[PcRow] = []
    for match in _PC_ROW_RE.finditer(privacy):
        rows.append(
            PcRow(
                pc_id=int(match.group(1)),
                claim=match.group(2).strip(),
                check_type=match.group(3).strip(),
                detail=match.group(4).strip(),
            )
        )
    return rows


def _strip_fenced_blocks(text: str) -> str:
    """Blank out fenced code blocks, preserving line count so nothing shifts."""
    return _FENCED_BLOCK_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)


def _strip_xml_comments(text: str) -> str:
    """Blank out XML comments, preserving line count so nothing shifts.

    An XML comment is never rendered, operative content; a snapshot-revision
    declaration or required literal appearing only inside one must not
    satisfy the Internet-Draft checker (2026-07-23 fix, finding 5b) -- the
    same non-operative-content rationale `_strip_fenced_blocks` already
    applies to fenced Markdown blocks.
    """
    return _XML_COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)


def check_ids(tm_ids: list[int]) -> list[str]:
    """Duplicate ids, and gaps in the contiguous-ascending-from-01 sequence."""
    errors: list[str] = []
    seen: set[int] = set()
    duplicates: set[int] = set()
    for tm_id in tm_ids:
        if tm_id in seen:
            duplicates.add(tm_id)
        seen.add(tm_id)
    for tm_id in sorted(duplicates):
        errors.append(f"duplicate TM id TM-{tm_id:02d}")

    if seen:
        missing = sorted(set(range(1, max(seen) + 1)) - seen)
        for tm_id in missing:
            errors.append(f"gap in TM sequence: TM-{tm_id:02d} is missing")

    for index, current in enumerate(tm_ids[1:], start=1):
        previous = tm_ids[index - 1]
        if current < previous:
            errors.append(
                f"TM id sequence is not ascending: TM-{current:02d} appears after TM-{previous:02d}"
            )

    return errors


def check_verdicts(tm_entries: list[TmEntry]) -> list[str]:
    """Exactly one Verdict line per entry, matching the grammar."""
    errors: list[str] = []
    for entry in tm_entries:
        label = f"TM-{entry.tm_id:02d}"
        lines = _VERDICT_LINE_RE.findall(entry.block)
        if len(lines) != 1:
            errors.append(f"{label}: expected exactly one Verdict line, found {len(lines)}")
            continue
        if not _VERDICT_GRAMMAR_RE.match(lines[0]):
            errors.append(
                f"{label}: Verdict line does not match 'Mitigated — …' or 'Out of scope — …'"
            )
    return errors


def check_spec_refs(
    tm_entries: list[TmEntry], headings_v01: set[str], headings_v02: set[str]
) -> list[str]:
    """Every spec ref in a well-formed Verdict line resolves to a real heading."""
    errors: list[str] = []
    for entry in tm_entries:
        label = f"TM-{entry.tm_id:02d}"
        lines = _VERDICT_LINE_RE.findall(entry.block)
        if len(lines) != 1 or not _VERDICT_GRAMMAR_RE.match(lines[0]):
            continue  # already reported by check_verdicts
        verdict_line = lines[0]
        for version_match in _ANY_SPEC_VERSION_RE.finditer(verdict_line):
            version = version_match.group(0)
            if version not in ("v0.1", "v0.2"):
                errors.append(f"{label}: unsupported spec version {version} in Verdict line")
        for group_match in _REF_GROUP_RE.finditer(verdict_line):
            version, group_text = group_match.group(1), group_match.group(2)
            headings = headings_v01 if version == "v0.1" else headings_v02
            for section in _REF_SECTION_RE.findall(group_text):
                if section not in headings:
                    errors.append(f"{label}: dangling spec ref {version} {section}")
    return errors


def check_matrix(threat_model: str, tm_ids: set[int]) -> list[str]:
    """Every required section is covered, and every cited TM id is real."""
    errors: list[str] = []
    covered_sections: set[str] = set()
    for match in _MATRIX_ROW_RE.finditer(threat_model):
        version, number, row_rest = match.group(1), match.group(2), match.group(3)
        has_known_tm = False
        for token_match in _MATRIX_TM_TOKEN_RE.finditer(row_rest):
            token = token_match.group(0).rstrip(",;.")
            if not _CANONICAL_TM_REF_RE.fullmatch(token):
                errors.append(f"malformed TM citation {token!r} (row {version} §{number})")
        for tm_ref in _MATRIX_TM_REF_RE.finditer(row_rest):
            cited = int(tm_ref.group(1))
            if cited not in tm_ids:
                errors.append(
                    f"traceability matrix cites unknown TM-{cited:02d} (row {version} §{number})"
                )
            else:
                has_known_tm = True
        if has_known_tm:
            covered_sections.add(f"{version} §{number}")

    for section in REQUIRED_SECTIONS:
        if section not in covered_sections:
            errors.append(f"required section {section} missing from traceability matrix")

    return errors


def check_claims(pc_rows: list[PcRow]) -> list[str]:
    """Every PC row's check type is one of schema|corpus|spec-text|manual."""
    errors: list[str] = []
    for row in pc_rows:
        if row.check_type not in _VALID_CHECK_TYPES:
            errors.append(
                f"PC-{row.pc_id:02d}: check type {row.check_type!r} is not one of "
                f"{sorted(_VALID_CHECK_TYPES)}"
            )
    return errors


def check_schema_pins(pc_rows: list[PcRow], schema: dict[str, object]) -> list[str]:
    """PC-01's pinned buyer schema constraints match the actual schema."""
    errors: list[str] = []
    pc01_rows = [row for row in pc_rows if row.pc_id == 1]
    if not pc01_rows:
        errors.append("PC-01: required testable-claim row is missing")
        return errors

    properties = schema.get("properties")
    buyer = properties.get("buyer") if isinstance(properties, dict) else None
    buyer_properties = buyer.get("properties") if isinstance(buyer, dict) else None
    actual = sorted(buyer_properties) if isinstance(buyer_properties, dict) else []
    buyer_required = buyer.get("required") if isinstance(buyer, dict) else None
    actual_required = (
        sorted(item for item in buyer_required if isinstance(item, str))
        if isinstance(buyer_required, list)
        else []
    )

    for row in pc01_rows:
        pin_match = _PC01_PIN_RE.search(row.detail)
        if pin_match is None:
            errors.append("PC-01: no 'key set exactly {...}' pin found in check detail")
            continue
        pinned = sorted(name.strip() for name in pin_match.group(1).split(","))
        if pinned != actual:
            errors.append(
                f"PC-01: pinned buyer-property set {pinned} diverges from "
                f"schema's actual set {actual}"
            )

        required_match = _PC01_REQUIRED_PIN_RE.search(row.detail)
        if required_match is None:
            errors.append("PC-01: no 'properties.buyer.required' pin found in check detail")
        else:
            pinned_required = json.loads(required_match.group(1))
            if not isinstance(pinned_required, list) or not all(
                isinstance(item, str) for item in pinned_required
            ):
                errors.append("PC-01: invalid 'properties.buyer.required' pin in check detail")
            elif sorted(pinned_required) != actual_required:
                errors.append(
                    f"PC-01: pinned buyer required list {sorted(pinned_required)} diverges from "
                    f"schema's actual list {actual_required}"
                )

        pattern_match = _PC01_PATTERN_PIN_RE.search(row.detail)
        if pattern_match is None:
            errors.append("PC-01: no base64url pattern-constraint pin found in check detail")
            continue
        first_name, second_name, length_text = pattern_match.groups()
        # The names come from prose, so a drifted document could name the same
        # field twice and leave the other unchecked. Require both by name.
        if {first_name, second_name} != _PC01_PATTERN_FIELDS:
            errors.append(
                f"PC-01: pattern pin names {sorted({first_name, second_name})}, "
                f"expected {sorted(_PC01_PATTERN_FIELDS)}"
            )
        expected_pattern = rf"^[A-Za-z0-9_-]{{{length_text}}}$"
        for name in (first_name, second_name):
            field = buyer_properties.get(name) if isinstance(buyer_properties, dict) else None
            actual_pattern = field.get("pattern") if isinstance(field, dict) else None
            if actual_pattern != expected_pattern:
                errors.append(
                    f"PC-01: pinned buyer pattern constraint for {name!r} "
                    f"diverges from schema's actual pattern {actual_pattern!r}"
                )

        enum_match = _PC01_ENUM_PIN_RE.search(row.detail)
        if enum_match is None:
            errors.append("PC-01: no 'identifier_type' enum pin found in check detail")
            continue
        pinned_enum = json.loads(enum_match.group(1))
        identifier_type = (
            buyer_properties.get("identifier_type") if isinstance(buyer_properties, dict) else None
        )
        actual_enum = identifier_type.get("enum") if isinstance(identifier_type, dict) else None
        if actual_enum != pinned_enum:
            errors.append(
                f"PC-01: pinned 'identifier_type' enum {pinned_enum} diverges from "
                f"schema's actual enum {actual_enum!r}"
            )

    return errors


def check_pc08_corpus_claim(pc_rows: list[PcRow], vectors_path: Path) -> list[str]:
    """PC-08's buyer-field claim covers filename-addressable payloads and
    transfer-chain payloads embedded in ``chain.json``.

    The former are found mechanically by filename; the latter deliberately are
    not, so parse the three chain fixtures' ``payloads`` arrays as JSON.  Keep
    the prose pin explicit about both the count and that distinction.
    """
    pc08_rows = [row for row in pc_rows if row.pc_id == 8]
    if not pc08_rows:
        return []

    errors: list[str] = []
    filename_payloads: list[dict[str, object]] = []
    filename_counts: list[int] = []
    for filename in ("payload.json", "envelope.json", "envelope.raw.json"):
        files = sorted(vectors_path.rglob(filename))
        filename_counts.append(len(files))
        for path in files:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            payload = data if filename == "payload.json" else data.get("payload")
            if not isinstance(payload, dict):
                errors.append(f"PC-08: {path.relative_to(_REPO_ROOT)} has no object payload")
            else:
                filename_payloads.append(payload)

    chain_payloads: list[dict[str, object]] = []
    chain_counts: list[int] = []
    for path in sorted(vectors_path.rglob("chain.json")):
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        payloads = data.get("payloads") if isinstance(data, dict) else None
        if not isinstance(payloads, list) or not all(isinstance(item, dict) for item in payloads):
            errors.append(f"PC-08: {path.relative_to(_REPO_ROOT)} has no object payloads array")
            continue
        chain_counts.append(len(payloads))
        chain_payloads.extend(payloads)

    payloads = filename_payloads + chain_payloads
    expected_buyer_keys = {"commitment", "identifier_type", "pubkey"}
    for index, payload in enumerate(payloads, start=1):
        buyer = payload.get("buyer")
        if not isinstance(buyer, dict) or set(buyer) != expected_buyer_keys:
            errors.append(f"PC-08: payload object {index} has unexpected buyer member set")

    counts = filename_counts + chain_counts
    expected_detail = (
        f"{len(payloads)} payload objects ({' + '.join(str(count) for count in counts)})"
    )
    required_note = "`chain.json` payloads are counted via JSON parse, not filename scan"
    for row in pc08_rows:
        if expected_detail not in row.detail:
            errors.append(
                f"PC-08: pinned corpus count must state {expected_detail}, found {row.detail!r}"
            )
        if required_note not in row.detail:
            errors.append(f"PC-08: check detail must state that {required_note}")
    return errors


def check_versioning_sections(versioning: str) -> list[str]:
    """Every §1-§6 heading the amendment procedure (§5) requires is present."""
    errors: list[str] = []
    for heading in _VERSIONING_REQUIRED_HEADINGS:
        if re.search(rf"^{re.escape(heading)}$", versioning, re.MULTILINE) is None:
            errors.append(f"missing required heading {heading!r}")
    return errors


def check_versioning_suite_names(versioning: str) -> list[str]:
    """The §6.1 registry names every signature suite the specs actually define."""
    errors: list[str] = []
    for suite in _VERSIONING_REQUIRED_SUITES:
        if re.search(rf"^\| {re.escape(suite)} \|", versioning, re.MULTILINE) is None:
            errors.append(f"§6.1 registry missing suite row {suite}")
    return errors


def check_versioning_lifecycle_states(versioning: str) -> list[str]:
    """§4's algorithm lifecycle names exactly the three defined states."""
    section_match = re.search(
        r"^## 4\. Algorithm lifecycle$([\s\S]*?)(?=^## |\Z)", versioning, re.MULTILINE
    )
    if section_match is None:
        return ["missing required heading '## 4. Algorithm lifecycle'"]

    actual = set(re.findall(r"^\| (`[^`]+`) \|", section_match.group(1), re.MULTILINE))
    expected = set(_VERSIONING_LIFECYCLE_STATES)
    if actual != expected:
        return [
            "§4 algorithm lifecycle states must be exactly "
            f"{sorted(expected)}, found {sorted(actual)}"
        ]
    return []


def check_versioning_revocation_classes(versioning: str) -> list[str]:
    """The §6.3 registry has a table row for every existing class, and
    `transferred` (v0.2 §17, rev 6) specifically carries state `active`.

    Matching is scoped to the §6.3 section slice so a row that migrates into a
    DIFFERENT registry's table cannot satisfy these checks (same discipline as
    check_versioning_transfer_registries)."""
    errors: list[str] = []
    revocation_classes_match = re.search(
        r"^### 6\.3 Revocation classes$([\s\S]*?)(?=^### |^## |\Z)", versioning, re.MULTILINE
    )
    if revocation_classes_match is None:
        errors.append("missing required heading '### 6.3 Revocation classes'")
        revocation_classes = ""
    else:
        revocation_classes = revocation_classes_match.group(1)
    for revocation_class in _VERSIONING_REQUIRED_REVOCATION_CLASSES:
        if (
            re.search(rf"^\| {re.escape(revocation_class)} \|", revocation_classes, re.MULTILINE)
            is None
        ):
            errors.append(f"§6.3 registry missing revocation-class row {revocation_class}")
    active_pattern = rf"^\| {re.escape(_VERSIONING_ACTIVE_REVOCATION_CLASS)} \| active \|"
    if re.search(active_pattern, revocation_classes, re.MULTILINE) is None:
        errors.append(
            "§6.3 registry missing active-state row for revocation class "
            f"{_VERSIONING_ACTIVE_REVOCATION_CLASS}"
        )
    return errors


# Stage 3 (v0.2 §17, rev 6) registers two more active rows this document's
# amendment procedure (§5) requires: the §6.4 log entry type `transfer-record`
# and the §6.5 transfer type `issuer-mediated-v1` -- the latter registry was
# empty before this revision, so getting a row there at all (not just the
# right state) is exactly the fact worth guarding against regression.
_VERSIONING_REQUIRED_ACTIVE_LOG_ENTRY_TYPES: tuple[str, ...] = ("`transfer-record`",)
_VERSIONING_REQUIRED_ACTIVE_TRANSFER_TYPES: tuple[str, ...] = ("`issuer-mediated-v1`",)


def check_versioning_transfer_registries(versioning: str) -> list[str]:
    """§6.4 and §6.5 each carry their Stage 3 (v0.2 §17, rev 6) active row."""
    errors: list[str] = []
    log_entry_types_match = re.search(
        r"^### 6\.4 Log entry types$([\s\S]*?)(?=^### |^## |\Z)", versioning, re.MULTILINE
    )
    if log_entry_types_match is None:
        errors.append("missing required heading '### 6.4 Log entry types'")
        log_entry_types = ""
    else:
        log_entry_types = log_entry_types_match.group(1)
    for entry_type in _VERSIONING_REQUIRED_ACTIVE_LOG_ENTRY_TYPES:
        pattern = rf"^\| {re.escape(entry_type)} \| active \|"
        if re.search(pattern, log_entry_types, re.MULTILINE) is None:
            errors.append(f"§6.4 registry missing active-state row for log entry type {entry_type}")
    transfer_types_match = re.search(
        r"^### 6\.5 Transfer types$([\s\S]*?)(?=^### |^## |\Z)", versioning, re.MULTILINE
    )
    if transfer_types_match is None:
        errors.append("missing required heading '### 6.5 Transfer types'")
        transfer_types = ""
    else:
        transfer_types = transfer_types_match.group(1)
    for transfer_type in _VERSIONING_REQUIRED_ACTIVE_TRANSFER_TYPES:
        pattern = rf"^\| {re.escape(transfer_type)} \| active \|"
        if re.search(pattern, transfer_types, re.MULTILINE) is None:
            errors.append(
                f"§6.5 registry missing active-state row for transfer type {transfer_type}"
            )
    return errors


def check_versioning_lifecycle_exception(versioning: str) -> list[str]:
    """§2 explicitly exempts lifecycle-driven classification downgrades."""
    if re.search(r"^One exception exists:.*$", versioning, re.MULTILINE) is None:
        return ["§2 missing required lifecycle exception paragraph 'One exception exists:'"]
    return []


_STAGE3_HEADING = "## 17. Stage 3: issuer-mediated transfer"
_STAGE3_REQUIRED_LITERALS: tuple[str, ...] = (
    "Attest-transfer-authorization-v1",
    "transfer-record",
    "transferred_revocation_unbacked",
    "transfer_record_unlogged",
    "transfer_not_yet_transferable",
    "transfer_double_assignment_conflict",
    'revocation: "transferred"',
)

_CHAIN_AUDIT_HEADING = "### 17.5 Chain of title (separate audit surface)"
_CHAIN_AUDIT_REQUIRED_LITERALS: tuple[str, ...] = (
    "chain link {i}: no transfer record",
    "chain link {i}: issuer signature invalid",
    "chain link {i}: holder authorization invalid",
    "chain link {i}: transfer record not logged",
    "chain link {i}: transferred before not_transferable_before",
    "chain link {i}: losing branch of a double assignment",
    "chain link {i}: new receipt buyer.pubkey != new_holder_pubkey",
    "chain link {i}: previous receipt lacks a backed transferred-class revocation",
)


def check_v02_stage3_transfer_profile(spec_v02: str) -> list[str]:
    """v0.2 §17 retains its heading and Stage 3 fixed vocabulary."""
    errors: list[str] = []
    stage3_match = re.search(
        rf"^{re.escape(_STAGE3_HEADING)}$([\s\S]*?)(?=^## |\Z)", spec_v02, re.MULTILINE
    )
    if stage3_match is None:
        errors.append(f"attest-v0.2.md: missing required heading {_STAGE3_HEADING!r}")
        stage3_text = ""
    else:
        stage3_text = stage3_match.group(1)
    for literal in _STAGE3_REQUIRED_LITERALS:
        if literal not in stage3_text:
            errors.append(f"attest-v0.2.md: §17 missing required literal {literal!r}")
    return errors


def check_v02_chain_audit_literals(spec_v02: str) -> list[str]:
    """v0.2 §17.5 pins the cross-language chain-audit diagnostic contract."""
    section_match = re.search(
        rf"^{re.escape(_CHAIN_AUDIT_HEADING)}$([\s\S]*?)(?=^### |^## |\Z)",
        spec_v02,
        re.MULTILINE,
    )
    if section_match is None:
        return [f"attest-v0.2.md: missing required heading {_CHAIN_AUDIT_HEADING!r}"]
    section_text = section_match.group(1)
    return [
        f"attest-v0.2.md: §17.5 missing required chain-audit literal {literal!r}"
        for literal in _CHAIN_AUDIT_REQUIRED_LITERALS
        if literal not in section_text
    ]


def check_v01_not_transferable_before_row(spec_v01: str) -> list[str]:
    """v0.1 §5.5 retains Stage 3's not_transferable_before field row."""
    license_match = re.search(
        r"^### 5\.5 `license`$([\s\S]*?)(?=^### |^## |\Z)", spec_v01, re.MULTILINE
    )
    if license_match is None:
        return ["attest-v0.1.md: missing required heading '### 5.5 `license`'"]
    if re.search(r"^\| `not_transferable_before` \|", license_match.group(1), re.MULTILINE) is None:
        return ["attest-v0.1.md: §5.5 missing required not_transferable_before row"]
    return []


def check_v01_publisher_id_row(spec_v01: str) -> list[str]:
    """v0.1 §5.4 retains Stage 4's publisher_id field row."""
    work_match = re.search(r"^### 5\.4 `work`$([\s\S]*?)(?=^### |^## |\Z)", spec_v01, re.MULTILINE)
    if work_match is None:
        return ["attest-v0.1.md: missing required heading '### 5.4 `work`'"]
    if re.search(r"^\| `work\.publisher_id` \|", work_match.group(1), re.MULTILINE) is None:
        return ["attest-v0.1.md: §5.4 missing required work.publisher_id row"]
    return []


def check_v01_preservation_pledge_row(spec_v01: str) -> list[str]:
    """v0.1 §5.5 retains Stage 4's preservation_pledge license-term row."""
    license_match = re.search(
        r"^### 5\.5 `license`$([\s\S]*?)(?=^### |^## |\Z)", spec_v01, re.MULTILINE
    )
    if license_match is None:
        return ["attest-v0.1.md: missing required heading '### 5.5 `license`'"]
    if re.search(r"^\| `preservation_pledge` \|", license_match.group(1), re.MULTILINE) is None:
        return ["attest-v0.1.md: §5.5 missing required preservation_pledge row"]
    return []


_STAGE4_HEADING = "## 18. Stage 4: the preservation pledge"
_STAGE4_REQUIRED_LITERALS: tuple[str, ...] = (
    # The license term and the document it hash-binds.
    "license.preservation_pledge",
    "sunset-grant-v1",
    "sunset-grant",
    "deliver-to-holder",
    "redistribute-among-holders",
    # The activation vocabulary. `heartbeat-absence` is pinned deliberately:
    # it is the mode this revision declines to make reachable, and the prose
    # that says so is what keeps a later reader from assuming otherwise.
    "publisher-declaration",
    "fixed-date",
    "heartbeat-absence",
    "cessation-declaration",
    "Attest-redemption-challenge-v1",
    # Warning literals, byte-identical across both cores.
    "grant_narrowing_ignored",
    "grant_unanchored",
    "grant_signer_not_publisher",
    "grant_scope_uncovered",
    "grant_commitment_mismatch",
    "grant_commitment_divergence",
    "grant_declaration_ignored",
    "grant_activated_by_successor",
    "grant_pledge_type_unknown",
    "grant_legal_text_changed",
    'grant: "activated"',
    'grant_trust: "signer_mismatch"',
    # Ceilings, both counted before any signature is verified.
    "_MAX_GRANT_LATER_VERSIONS",
    "_MAX_GRANT_DECLARATIONS",
    # The load-bearing normative claims. Each is a sentence a regression could
    # quietly invert while leaving prose that still reads fluently, and each
    # inversion would ship something we know to be false:
    #   - activation never follows from an absence,
    #   - logging a declaration is recommended but never load-bearing,
    #   - the fixed-date proof runs in the direction OTS can actually prove,
    #   - and it aggregates several proofs the way that question needs, which
    #     is the opposite reduction from the one §11 applies,
    #   - the prose a buyer is bound by stays the one their receipt signed,
    #   - an uncovered receipt cannot reach "activated".
    "never from the absence of evidence",
    "never required for validity",
    "T >= fixed_date",
    "MAXIMUM over the verified proofs",
    "The legal text that binds a buyer is always the FLOOR's",
    "Scope coverage, and it is a gate",
    # Three determinism claims. Coverage is TWO predicates, not one reused
    # twice; the declaration step scans everything so the warning set does
    # not depend on the order evidence arrived in; and all three
    # prose-bearing members count, the URI included.
    "Grant coverage of a receipt is a DIFFERENT predicate",
    "never stops at the first one that succeeds",
    "ANY of the three prose-bearing members",
    # A universal quantifier over an absent artifact list is vacuously true,
    # which would make every grant cover every series-only receipt. The
    # non-empty requirement is what stops a false activation from falling out
    # of a quantifier, so it is pinned as a claim, not left in a table cell.
    "present and non-empty",
    # Seven places where the first implementation had to CHOOSE and §18 did
    # not say. None of the choices is safety-critical on its own; every one of
    # them lets two conforming verifiers reach different verdicts on identical
    # bytes, which is the failure this whole section is written to prevent. A
    # regression that dropped any of these sentences would leave prose reading
    # perfectly while reopening the divergence:
    #   - which document seeds the fixed-date accumulator,
    #   - that its evidence is one bundle rather than a fourth hostile array,
    #   - that an inadmissible or unauthenticated later version moves nothing
    #     (otherwise a trust downgrade costs an attacker one array append),
    #   - and that only publisher-signed documents can signal a rollback,
    #   - that signer_mismatch needs a document that already authenticated,
    #   - that the evidence channel is the opt-in, without which step 1 alone
    #     would contradict §18.5's unchanged-result promise,
    #   - and that "sorted" is code-point order, which UTF-16 code-unit order
    #     contradicts on input `permissions`/`modes` actually accept.
    "it is the effective grant, not the floor",
    "ONE §11 evidence bundle",
    "ignored WITHOUT effect on `grant_trust`",
    "Only an AUTHENTICATED, same-publisher document may move `grant_trust`",
    "reachable only for a document that has already authenticated",
    "The evidence channel is also the capability gate",
    '"Sorted" means by Unicode CODE POINT',
)

_APPENDIX_A_HEADING = "## Appendix A — The custodian interface (non-normative)"


def check_v02_stage4_preservation_pledge(spec_v02: str) -> list[str]:
    """v0.2 §18 retains its heading, Stage 4 fixed vocabulary, and Appendix A."""
    errors: list[str] = []
    stage4_match = re.search(
        rf"^{re.escape(_STAGE4_HEADING)}$([\s\S]*?)(?=^## |\Z)", spec_v02, re.MULTILINE
    )
    if stage4_match is None:
        errors.append(f"attest-v0.2.md: missing required heading {_STAGE4_HEADING!r}")
        stage4_text = ""
    else:
        stage4_text = stage4_match.group(1)
    for literal in _STAGE4_REQUIRED_LITERALS:
        if literal not in stage4_text:
            errors.append(f"attest-v0.2.md: §18 missing required literal {literal!r}")
    if re.search(rf"^{re.escape(_APPENDIX_A_HEADING)}$", spec_v02, re.MULTILINE) is None:
        errors.append(f"attest-v0.2.md: missing required heading {_APPENDIX_A_HEADING!r}")
    return errors


# Stage 4 (v0.2 §18, rev 8) registers one more active row in the existing §6.4
# log-entry-types registry, plus four new registries of its own: §6.7
# (end-of-life commitment values), §6.8 (grant permissions), §6.9 (activation
# modes) and §6.10 (preservation pledge types). §6.6 is already taken by the
# warning-literals registry, so these numbers are not the ones the plan quotes.
_VERSIONING_REQUIRED_ACTIVE_LOG_ENTRY_TYPES_STAGE4: tuple[str, ...] = ("`cessation-declaration`",)
_VERSIONING_REQUIRED_ACTIVE_EOL_VALUES: tuple[str, ...] = ("`sunset-grant`",)
_VERSIONING_REQUIRED_ACTIVE_GRANT_PERMISSIONS: tuple[str, ...] = (
    "`deliver-to-holder`",
    "`redistribute-among-holders`",
)
_VERSIONING_REQUIRED_ACTIVE_ACTIVATION_MODES: tuple[str, ...] = (
    "`publisher-declaration`",
    "`fixed-date`",
)
# The one mode this revision registers WITHOUT making it reachable. Pinned in
# its reserved state so that promoting it stays a deliberate amendment rather
# than a silent edit: absence-based activation is unsound until witness
# freshness exists.
_VERSIONING_REQUIRED_RESERVED_ACTIVATION_MODES: tuple[str, ...] = ("`heartbeat-absence`",)
_VERSIONING_REQUIRED_ACTIVE_PLEDGE_TYPES: tuple[str, ...] = ("`sunset-grant-v1`",)


def _registry_rows(versioning: str, heading: str) -> tuple[str, list[str]]:
    """Return a registry subsection's body, or an error naming the missing heading."""
    match = re.search(
        rf"^### {re.escape(heading)}$([\s\S]*?)(?=^### |^## |\Z)", versioning, re.MULTILINE
    )
    if match is None:
        return "", [f"missing required heading '### {heading}'"]
    return match.group(1), []


def check_versioning_stage4_registries(versioning: str) -> list[str]:
    """§6.4 gains `cessation-declaration`; §6.7-§6.10 carry Stage 4's own rows."""
    errors: list[str] = []
    checks: tuple[tuple[str, str, tuple[str, ...], str, str], ...] = (
        (
            "6.4 Log entry types",
            "§6.4",
            _VERSIONING_REQUIRED_ACTIVE_LOG_ENTRY_TYPES_STAGE4,
            "active",
            "log entry type",
        ),
        (
            "6.7 End-of-life commitment values",
            "§6.7",
            _VERSIONING_REQUIRED_ACTIVE_EOL_VALUES,
            "active",
            "end-of-life value",
        ),
        (
            "6.8 Grant permissions",
            "§6.8",
            _VERSIONING_REQUIRED_ACTIVE_GRANT_PERMISSIONS,
            "active",
            "grant permission",
        ),
        (
            "6.9 Activation modes",
            "§6.9",
            _VERSIONING_REQUIRED_ACTIVE_ACTIVATION_MODES,
            "active",
            "activation mode",
        ),
        (
            "6.9 Activation modes",
            "§6.9",
            _VERSIONING_REQUIRED_RESERVED_ACTIVATION_MODES,
            "reserved",
            "activation mode",
        ),
        (
            "6.10 Preservation pledge types",
            "§6.10",
            _VERSIONING_REQUIRED_ACTIVE_PLEDGE_TYPES,
            "active",
            "preservation pledge type",
        ),
    )
    reported_headings: set[str] = set()
    for heading, section, entries, state, noun in checks:
        rows, heading_errors = _registry_rows(versioning, heading)
        # §6.9 is checked twice — once for its active rows, once for the
        # reserved one — so a missing heading would otherwise be reported twice.
        if heading not in reported_headings:
            errors.extend(heading_errors)
            reported_headings.add(heading)
        for entry in entries:
            pattern = rf"^\| {re.escape(entry)} \| {state} \|"
            if re.search(pattern, rows, re.MULTILINE) is None:
                errors.append(f"{section} registry missing {state}-state row for {noun} {entry}")
    return errors


def _check_revision_log(spec_text: str, filename: str) -> list[str]:
    """Validate the required revision-log heading, entries, and entry grammar."""
    errors: list[str] = []
    heading_match = _REVISION_LOG_HEADING_RE.search(spec_text)
    if heading_match is None:
        return [f"{filename}: missing '## Revision log' section"]

    lines = spec_text.splitlines()
    heading_line = spec_text[: heading_match.start()].count("\n")
    entry_count = 0
    for index in range(heading_line + 1, len(lines)):
        line = lines[index]
        if line.startswith("## "):
            break
        if line.startswith("- "):
            entry_count += 1
            if _REVISION_LOG_ENTRY_RE.fullmatch(line) is None:
                errors.append(
                    f"{filename}: revision-log entry on line {index + 1} does not match "
                    "required grammar"
                )
    if entry_count == 0:
        errors.append(f"{filename}: revision log requires at least one revision-log entry")
    return errors


# P1.1b is deliberately a specification-only trust-surface amendment.  These
# literals are exact conformance text, rather than aspirational documentation:
# each prevents a later edit from silently reopening one of D7--D11 or moving
# Stage 4 material onto the P1.1b branch.
_P11B_V02_REQUIRED_LITERALS: tuple[str, ...] = (
    "attest-cosignature-ml-dsa-65-v1",
    '`0xff || UTF8("attest-cosignature-ml-dsa-65-v1")`',
    "C2SP type `0x06` MUST NOT count",
    'UTF8("cosignature/v1\\n")',
    '`corroboration: "witnessed"` asserts timestamped witness observation only',
    "MUST NOT be described as proof of organizational independence or split-view prevention",
    "One valid Ed25519 C2SP type-`0x04` cosignature",
    "witness_independence_not_established",
    "`WitnessPolicy` is a closed JSON object",
    '"schema": "attest-witness-policy-v1"',
    '"epochs": []',
    "`^[a-z0-9][a-z0-9._-]{0,127}$`",
    "exact UTC ISO-8601 second timestamps",
    "inclusive at both declared boundaries",
    "Evidence MUST identify `witness_policy_epoch` explicitly; "
    "the current epoch is never substituted",
    "sorted and duplicate-free",
    "distinct activation-role `control_group` values, not keys",
    "same verifier-owned configuration rail as existing pinned log keys",
    "Python core keyword `witness_policy=`",
    "Python CLI file `--witness-policy`",
    "TypeScript verifier option `witnessPolicy`",
    "Installing a release authorizes that packaged policy revision",
    "Evidence MUST NOT carry epoch contents",
    "one canonical JCS document and MUST be byte-identical",
    "Direct conflict: `X` appears in the pin's `affiliated_domains`.",
    "Transitive conflict: the pin's `control_group` equals the `control_group`",
    "parameterized as `conflict_domain`",
    "Domain inequality MUST NOT establish independence",
    "no positive independence certificate or inference rule",
    "Absent `compromised_after` means no compromise is declared",
    "`T <= compromised_after` retains its standing",
    "`T > compromised_after` excludes it",
    'explicit `"compromised_after": null` means compromise onset is unknown',
    "release publisher that ships the policy",
    "cannot rewrite or delete prior epoch contents",
    "reference witness receives a configured allowlist of log origins "
    "and their pinned hybrid log keys",
    "No origin or log key is hardcoded in source",
    "any configured allowlist size, including a single origin",
    "Unknown origins are rejected before checkpoint or consistency work can advance state",
    "spec, policy, both-core verification, vectors, reference witness, ceremony, review/PR/tag",
    "top-level `witness/`",
    "unpublished, receives no independent tag, and is excluded from both public package artifacts",
    "one vote per `control_group`",
    "MAX_WITNESS_SKEW_SECONDS = 600",
    "MAX_WITNESS_ANCHOR_DELAY_SECONDS = 86400",
    "MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE = 9",
    "before any Ed25519 or ML-DSA-65 signature verification",
    "full `signed-note-v2` anchor over the complete signed note",
    "`max(t_i) <= A <= T + MAX_WITNESS_ANCHOR_DELAY_SECONDS`",
    "No warning literal is introduced by this section other than "
    "`witness_independence_not_established`",
)

_P11B_VERSIONING_REQUIRED_LITERALS: tuple[str, ...] = (
    "`attest-cosignature-ml-dsa-65-v1`",
    "`witness_independence_not_established`",
    "WitnessPolicy epochs are immutable",
    "groups 39 and 40",
)


def check_p11b_witness_contract(spec_v02: str, versioning: str) -> list[str]:
    """Fail closed on drift in P1.1b's witness-policy amendment."""
    errors = [
        f"attest-v0.2.md: P1.1b witness contract missing required literal {literal!r}"
        for literal in _P11B_V02_REQUIRED_LITERALS
        if literal not in spec_v02
    ]
    errors.extend(
        f"attest-versioning.md: P1.1b registry/lifecycle missing required literal {literal!r}"
        for literal in _P11B_VERSIONING_REQUIRED_LITERALS
        if literal not in versioning
    )
    return errors


def check_receipt_id_pattern(spec_v01: str, schema: dict[str, object]) -> list[str]:
    """§5.1's inline `receipt_id` ULID regex MUST equal the schema's own
    `properties.receipt_id.pattern` — the two describe the same wire
    constraint (a Crockford base32 ULID whose leading character is bounded
    to `[0-7]`, since a 26-char ULID otherwise overflows 128 bits) and must
    never drift (2026-07-22 fix: the prose lacked that high-bit guard while
    the schema already had it).

    Skips ONLY when NEITHER side models `receipt_id` at all — most fixture
    docs in this test module carry no full §5.1 table and no `receipt_id`
    schema property, and are not meant to exercise this check; that is not a
    drift signal. A ONE-SIDED absence, though, IS a drift signal (a prose row
    added/removed without touching the schema, or vice versa) and is now an
    explicit, fail-closed error (M2, 2026-07-22 fix wave 2 — this function
    used to `return []` on either side's absence alone, silently blessing
    exactly that drift). The real spec and schema always carry both.
    """
    match = _RECEIPT_ID_PROSE_ROW_RE.search(spec_v01)

    properties = schema.get("properties")
    receipt_id_schema = properties.get("receipt_id") if isinstance(properties, dict) else None
    schema_pattern = (
        receipt_id_schema.get("pattern") if isinstance(receipt_id_schema, dict) else None
    )

    if match is None and schema_pattern is None:
        return []

    if match is None:
        return [
            f"attest-v0.1.md: schema defines receipt_id.pattern {schema_pattern!r} but "
            "§5.1 has no receipt_id prose row (fail-closed: one-sided absence is drift)"
        ]

    prose_pattern = match.group(1)

    if schema_pattern is None:
        return [
            f"attest-v0.1.md: §5.1 receipt_id prose pattern {prose_pattern!r} but schema "
            "defines no receipt_id.pattern (fail-closed: one-sided absence is drift)"
        ]

    if prose_pattern != schema_pattern:
        return [
            f"attest-v0.1.md: §5.1 receipt_id prose pattern {prose_pattern!r} diverges from "
            f"schema pattern {schema_pattern!r}"
        ]
    return []


def check_revision_logs(spec_v01: str, spec_v02: str) -> list[str]:
    """Both normative specs have non-empty revision logs with valid entries."""
    return _check_revision_log(spec_v01, "attest-v0.1.md") + _check_revision_log(
        spec_v02, "attest-v0.2.md"
    )


# The seven H2 headings docs/spec/attest-standards-relationship.md pins verbatim.
# The Internet-Draft appendix (a later phase task) distills this same list, so a
# heading rename here would silently orphan that appendix's pointer.
_STANDARDS_RELATIONSHIP_REQUIRED_HEADINGS: tuple[str, ...] = (
    "## 1. W3C Verifiable Credentials",
    "## 2. eIDAS 2.0 and the EUDI Wallet",
    "## 3. JOSE/JWS and COSE",
    "## 4. RFC 8785 (JCS)",
    "## 5. C2PA",
    "## 6. SCITT and RFC 9943",
    "## 7. RATS (RFC 9334): a terminology note",
)

# RFC 9943 (SCITT) and RFC 9334 (RATS) are the two vocabulary-collision entries
# the annex exists to defuse; RFC 8785 is the JCS base entry 4 builds on. All
# three must be citable by number, not just implied in prose.
_STANDARDS_RELATIONSHIP_REQUIRED_LITERALS: tuple[str, ...] = ("RFC 9943", "RFC 9334", "RFC 8785")


def check_standards_relationship() -> list[str]:
    """Fail-closed existence/shape guard for the standards-relationship annex.

    Checks the file exists, carries its seven pinned H2 headings verbatim (the
    Internet-Draft appendix and this checker both depend on them), and cites
    the three RFCs the SCITT/RATS defusal and the JCS entry require by number.
    Fenced code blocks are stripped before either scan (a heading or literal
    appearing only inside an illustrative fence is never operative content
    and must not satisfy this guard, 2026-07-23 fix, finding 5a). Not wired
    into `collect_errors()`: unlike the threat-model/privacy/spec quintet it
    does not cross-reference another document's parsed structure, so it is
    called directly from `main()`.
    """
    if not _STANDARDS_RELATIONSHIP_PATH.exists():
        return ["attest-standards-relationship.md: file is missing"]
    # Illustrative fenced examples read exactly like the real thing (see
    # collect_errors()'s identical rationale for the threat-model/privacy
    # docs); a required heading or literal appearing only inside one must
    # not satisfy this fail-closed guard (2026-07-23 fix, finding 5a).
    text = _strip_fenced_blocks(_STANDARDS_RELATIONSHIP_PATH.read_text(encoding="utf-8"))
    errors: list[str] = []
    for heading in _STANDARDS_RELATIONSHIP_REQUIRED_HEADINGS:
        if re.search(rf"^{re.escape(heading)}$", text, re.MULTILINE) is None:
            errors.append(f"attest-standards-relationship.md: missing required heading {heading!r}")
    for literal in _STANDARDS_RELATIONSHIP_REQUIRED_LITERALS:
        if literal not in text:
            errors.append(f"attest-standards-relationship.md: missing required literal {literal!r}")
    return errors


# The Internet-Draft (P1.6 T2) is a snapshot-profile mirror of the living
# specs, never their replacement: its Introduction MUST declare, in one
# physical line per spec, which attest-v0.1.md/attest-v0.2.md revision it
# mirrors. Each regex is deliberately anchored to a single line (`[^\n]*`,
# no DOTALL) so the two declarations can never bleed into each other when
# both appear in the same paragraph -- a greedy `.*` spanning newlines could
# otherwise let the v0.1 regex capture the v0.2 sentence's revision number.
# Each is matched with `findall`, not `search`, and the checker requires
# EXACTLY ONE match in the whole source: a source carrying a valid
# declaration AND a second, conflicting one used to pass silently, because
# `search` only ever validated the first match (2026-07-23 fix, finding 8).
_DRAFT_V01_SNAPSHOT_RE = re.compile(r"attest-v0\.1\.md[^\n]*revision (\d+)")
_DRAFT_V02_SNAPSHOT_RE = re.compile(r"attest-v0\.2\.md[^\n]*revision (\d+)")

# RFC 9943 (SCITT) and RFC 9334 (RATS) are the terminology-defusal citations
# (v0.1 §2/§3-equivalent Conventions and Terminology section); RFC 8785 is
# the JCS base the Canonicalization section cites. Mirrors the annex's own
# _STANDARDS_RELATIONSHIP_REQUIRED_LITERALS choice of exactly these three.
_DRAFT_REQUIRED_LITERALS: tuple[str, ...] = ("9943", "9334", "8785")

# Any `(rev N)` token, used to scan a spec's own "## Revision log" section
# for declared-revision EXISTENCE (never latest-equality -- a later spec
# bump must never redden this check, only make drift detectable to a reader
# who compares the draft's declared revision against the living log).
_REV_LOG_ENTRY_REV_RE = re.compile(r"\(rev (\d+)\)")


def _internet_draft_source_path() -> Path | None:
    """The single `ietf/draft-bernalli-open-purchase-receipts.{md,xml}`
    source, or None if zero or more than one candidate exists."""
    candidates = [
        path
        for path in (
            _INTERNET_DRAFT_DIR / f"{_INTERNET_DRAFT_BASENAME}.md",
            _INTERNET_DRAFT_DIR / f"{_INTERNET_DRAFT_BASENAME}.xml",
        )
        if path.exists()
    ]
    return candidates[0] if len(candidates) == 1 else None


def _revisions_in_log(spec_text: str) -> set[int]:
    """Every `(rev N)` integer inside a spec's own `## Revision log` section
    (never body prose elsewhere, which may mention a revision in passing)."""
    heading_match = _REVISION_LOG_HEADING_RE.search(spec_text)
    if heading_match is None:
        return set()
    rest = spec_text[heading_match.end() :]
    next_heading = re.search(r"^## ", rest, re.MULTILINE)
    section = rest[: next_heading.start()] if next_heading is not None else rest
    return {int(match.group(1)) for match in _REV_LOG_ENTRY_REV_RE.finditer(section)}


def check_internet_draft_snapshot() -> list[str]:
    """Fail-closed existence/shape guard for the Internet-Draft source.

    Checks that exactly one of `ietf/draft-bernalli-open-purchase-receipts.md`
    /`.xml` exists, that its text (XML comments stripped first -- a
    declaration or required literal inside a `<!-- ... -->` comment is
    never operative content and must not satisfy this guard, 2026-07-23
    fix, finding 5b) declares (via two pinned per-line regexes) which
    attest-v0.1.md/attest-v0.2.md revision it mirrors -- EXACTLY ONCE
    each: a second, conflicting declaration for the same spec is ambiguous
    and is reported as an error rather than silently validated against
    whichever match happens to come first (2026-07-23 fix, finding 8) --
    that each declared revision integer EXISTS in the corresponding spec's
    own revision log (existence, not latest-equality -- a later spec
    revision bump alone must never turn this red; drift is instead
    detectable by a reader comparing the declared revision against the
    living log), and that the source cites the three RFCs the terminology
    defusals (RFC 9943, RFC 9334) and the canonicalization section
    (RFC 8785) require by number. Not wired into `collect_errors()`, same
    reasoning as check_standards_relationship(): it does not
    cross-reference another document's parsed structure, so it is called
    directly from `main()`.
    """
    source_path = _internet_draft_source_path()
    if source_path is None:
        candidate_count = sum(
            1
            for path in (
                _INTERNET_DRAFT_DIR / f"{_INTERNET_DRAFT_BASENAME}.md",
                _INTERNET_DRAFT_DIR / f"{_INTERNET_DRAFT_BASENAME}.xml",
            )
            if path.exists()
        )
        return [
            "internet-draft: expected exactly one of "
            f"{_INTERNET_DRAFT_BASENAME}.md/.xml under {_INTERNET_DRAFT_DIR}, "
            f"found {candidate_count}"
        ]

    # Strip XML comments before any scan: a snapshot declaration or required
    # literal inside a `<!-- ... -->` comment is never operative content and
    # must not satisfy this fail-closed guard (2026-07-23 fix, finding 5b).
    text = _strip_xml_comments(source_path.read_text(encoding="utf-8"))
    errors: list[str] = []

    for spec_label, snapshot_re, spec_path in (
        ("attest-v0.1.md", _DRAFT_V01_SNAPSHOT_RE, _SPEC_V01_PATH),
        ("attest-v0.2.md", _DRAFT_V02_SNAPSHOT_RE, _SPEC_V02_PATH),
    ):
        matches = snapshot_re.findall(text)
        if len(matches) != 1:
            errors.append(
                f"internet-draft: expected exactly one {spec_label} snapshot-revision "
                f"declaration (expected to match {snapshot_re.pattern!r}), found "
                f"{len(matches)}"
            )
            continue
        declared = int(matches[0])
        spec_text = spec_path.read_text(encoding="utf-8")
        if declared not in _revisions_in_log(spec_text):
            errors.append(
                f"internet-draft: declared {spec_label} revision {declared} does not exist "
                f"as '(rev {declared})' in {spec_label}'s revision log"
            )

    for literal in _DRAFT_REQUIRED_LITERALS:
        if literal not in text:
            errors.append(f"internet-draft: missing required literal {literal!r}")

    return errors


# The four anchors the public conformance-program doc must carry: the
# runner's own path (so a reader can find and run it), the adapter
# template's placeholder literal, the fixed phrase the claim-sentence
# template (docs/conformance.md §5) uses, and the self-certification
# process by name (P1.6 plan Task 4).
_CONFORMANCE_DOC_REQUIRED_LITERALS: tuple[str, ...] = (
    "tools/conformance_runner.py",
    "{leaf}",
    "attest conformant",
    "self-certification",
)


def check_conformance_doc() -> list[str]:
    """Fail-closed existence/content guard for `docs/conformance.md`.

    Checks the file exists and mentions the runner's path, the adapter
    template placeholder, the claim-sentence's fixed phrase, and the
    self-certification process by name. Not wired into `collect_errors()`,
    same reasoning as `check_standards_relationship()`/
    `check_internet_draft_snapshot()`: it does not cross-reference another
    document's parsed structure, so it is called directly from `main()`.
    """
    if not _CONFORMANCE_DOC_PATH.exists():
        return ["conformance.md: file is missing"]
    text = _CONFORMANCE_DOC_PATH.read_text(encoding="utf-8")
    return [
        f"conformance.md: missing required literal {literal!r}"
        for literal in _CONFORMANCE_DOC_REQUIRED_LITERALS
        if literal not in text
    ]


# Every place a document states the size of the conformance corpus, in any of
# the shapes prose actually uses. The corpus grows whenever a stage ships, and
# each growth has left at least one of these numbers behind: the 0.8.1 release
# corrected two of them and still shipped six more, in five files, because the
# search that followed looked for the exact strings just seen rather than for
# the class of claim. This guard looks for the class.
_CORPUS_CLAIM_PATTERNS = (
    re.compile(r"\b(\d+)[- ]leaf conformance corpus\b"),
    re.compile(r"\b(\d+)[- ]leaf corpus\b"),
    re.compile(r"\b(\d+) leaf vectors\b"),
    re.compile(r"\ball (\d+) conformance vector leaves\b"),
    re.compile(r"\bnot all (\d+)\b"),
    re.compile(r"\bnot against all (\d+)\b"),
    re.compile(r"\b(\d+)/\1 leaves pass\b"),
    re.compile(r"\bat least (\d+) leaves\b"),
    # Shapes the first version of this guard missed, each found by a review
    # reading the same documents by hand: a normative sentence telling a v0.2
    # implementation to "reproduce all 130", and a parenthetical giving the
    # subset size as "(all leaves, currently 156)". Both are corpus claims in
    # every sense that matters, and neither looked like one to a pattern list
    # written from the examples already in front of it.
    re.compile(r"\breproduce all (\d+)\b"),
    re.compile(r"\ball leaves, currently (\d+)\b"),
    re.compile(r"\bevery leaf in the corpus \(currently (\d+)\)"),
)

# Claims about the v0.1 subset, which is a different number from the total.
_SUBSET_CLAIM_PATTERNS = (
    re.compile(r"\bthe (\d+)[- ]leaf subset\b"),
    re.compile(r"\bv0\.1 subset \((\d+) leaves\b"),
    re.compile(r"\b(\d+)[- ]leaf v0\.1 subset\b"),
    re.compile(r"\bv0\.1.{0,3}\((\d+) leaves\)"),
)

_GROUP_CLAIM_PATTERN = re.compile(r"\b(\d+) leaf vectors across (\d+) groups\b")

# Numbers that look like corpus claims but are not, each deliberate and each
# checked by something else. Keyed by path so that editing one of these lines
# fails this guard and forces a fresh look, which is the point.
_CORPUS_CLAIM_EXEMPTIONS = {
    # The share of leaves routed to the `verify()` surface, not the corpus
    # size: `130 + 4 + 20 + 4 = 158` is the partition a TypeScript guard test
    # pins, and rewriting the 130 to match the total would break it.
    "verifiers/ts/README.md": ("**`verify()`** (130 leaves)",),
}


def _measured_corpus() -> tuple[int, int, int]:
    """Count the corpus on disk: (leaves, groups, v0.1 subset size).

    Reuses `conformance_runner`'s own discovery and subset rule rather than
    restating them, so this guard cannot drift from the runner that produces
    the numbers the documents quote.
    """
    sys.path.insert(0, str(_REPO_ROOT / "tools"))
    from conformance_runner import find_leaf_dirs, select_subset

    vectors_root = _REPO_ROOT / "docs/spec/vectors"
    leaves = find_leaf_dirs(vectors_root)
    groups = sorted({leaf.relative_to(vectors_root).parts[0] for leaf in leaves})
    subset = select_subset(leaves, vectors_root, "v0.1")
    return len(leaves), len(groups), len(subset)


def check_corpus_counts() -> list[str]:
    """Every stated corpus size must match the corpus on disk.

    Scans every Markdown file in the repository — not a fixed list, because the
    numbers that went stale were in files nobody thought to list. Matching runs
    against the text with newlines folded to spaces: prose wraps, and the first
    version of this guard was blind to `the 52-leaf\nsubset` for exactly that
    reason, which its own red bench caught. Line numbers are recovered from the
    match offset so a report still points at the right line.

    Called directly from `main()`, like the other single-document guards.
    """
    total, groups, subset_size = _measured_corpus()
    errors: list[str] = []
    for path in sorted(_REPO_ROOT.rglob("*.md")):
        rel = path.relative_to(_REPO_ROOT).as_posix()
        if "node_modules" in rel or rel.startswith(".git/"):
            continue
        # The changelog records what the numbers WERE; that is its job.
        if rel.endswith("CHANGELOG.md"):
            continue
        text = path.read_text(encoding="utf-8")
        for phrase in _CORPUS_CLAIM_EXEMPTIONS.get(rel, ()):
            text = text.replace(phrase, "")
        # Fold newlines to spaces, preserving length so offsets stay valid.
        folded = text.replace("\n", " ")

        def line_of(offset: int, _text: str = text) -> int:
            return _text.count("\n", 0, offset) + 1

        for pattern in _CORPUS_CLAIM_PATTERNS:
            for match in pattern.finditer(folded):
                claimed = int(match.group(1))
                if claimed != total:
                    errors.append(
                        f"{rel}:{line_of(match.start())}: claims {claimed} corpus "
                        f"leaves, but the corpus holds {total}"
                    )
        for pattern in _SUBSET_CLAIM_PATTERNS:
            for match in pattern.finditer(folded):
                claimed = int(match.group(1))
                if claimed != subset_size:
                    errors.append(
                        f"{rel}:{line_of(match.start())}: claims a {claimed}-leaf "
                        f"v0.1 subset, but the subset holds {subset_size}"
                    )
        for match in _GROUP_CLAIM_PATTERN.finditer(folded):
            if int(match.group(2)) != groups:
                errors.append(
                    f"{rel}:{line_of(match.start())}: claims {match.group(2)} "
                    f"vector groups, but there are {groups}"
                )
    return errors


def collect_errors(
    threat_model: str,
    privacy: str,
    spec_v01: str,
    spec_v02: str,
    schema: dict[str, object],
    versioning: str,
) -> list[str]:
    """Cross-check the two companion docs against each other and the specs.

    Also checks attest-versioning.md's required sections and registries, and
    that both normative specs carry the `## Revision log` section its
    amendment procedure (§5) requires.

    Returns one human-readable string per problem found; an empty list means
    the documents are internally consistent and in sync with the specs and
    schema they cite.
    """
    # Illustrative tables and sample entries live in code fences throughout both
    # documents. They read exactly like the real thing, so scanning them would let
    # a fenced example stand in for a real matrix row or catalog entry.
    threat_model = _strip_fenced_blocks(threat_model)
    privacy = _strip_fenced_blocks(privacy)

    headings_v01 = parse_headings(spec_v01)
    headings_v02 = parse_headings(spec_v02)
    tm_entries = _parse_tm_entries(threat_model)
    tm_ids = [entry.tm_id for entry in tm_entries]
    pc_rows = parse_pc_rows(privacy)

    errors: list[str] = []
    errors += [f"attest-threat-model.md: {e}" for e in check_ids(tm_ids)]
    errors += [f"attest-threat-model.md: {e}" for e in check_verdicts(tm_entries)]
    errors += [
        f"attest-threat-model.md: {e}"
        for e in check_spec_refs(tm_entries, headings_v01, headings_v02)
    ]
    errors += [f"attest-threat-model.md: {e}" for e in check_matrix(threat_model, set(tm_ids))]
    errors += [f"attest-privacy.md: {e}" for e in check_claims(pc_rows)]
    errors += [f"attest-privacy.md: {e}" for e in check_schema_pins(pc_rows, schema)]
    errors += [f"attest-privacy.md: {e}" for e in check_pc08_corpus_claim(pc_rows, _VECTORS_PATH)]
    errors += [f"attest-versioning.md: {e}" for e in check_versioning_sections(versioning)]
    errors += [f"attest-versioning.md: {e}" for e in check_versioning_suite_names(versioning)]
    errors += [f"attest-versioning.md: {e}" for e in check_versioning_lifecycle_states(versioning)]
    errors += [
        f"attest-versioning.md: {e}" for e in check_versioning_revocation_classes(versioning)
    ]
    errors += [
        f"attest-versioning.md: {e}" for e in check_versioning_lifecycle_exception(versioning)
    ]
    errors += [
        f"attest-versioning.md: {e}" for e in check_versioning_transfer_registries(versioning)
    ]
    errors += check_v02_stage3_transfer_profile(spec_v02)
    errors += check_v02_chain_audit_literals(spec_v02)
    errors += check_v01_not_transferable_before_row(spec_v01)
    errors += [f"attest-versioning.md: {e}" for e in check_versioning_stage4_registries(versioning)]
    errors += check_v02_stage4_preservation_pledge(spec_v02)
    errors += check_v01_publisher_id_row(spec_v01)
    errors += check_v01_preservation_pledge_row(spec_v01)
    errors += check_revision_logs(spec_v01, spec_v02)
    errors += _check_revision_log(versioning, "attest-versioning.md")
    errors += check_receipt_id_pattern(spec_v01, schema)
    return errors


def main() -> int:
    threat_model = _THREAT_MODEL_PATH.read_text(encoding="utf-8")
    privacy = _PRIVACY_PATH.read_text(encoding="utf-8")
    spec_v01 = _SPEC_V01_PATH.read_text(encoding="utf-8")
    spec_v02 = _SPEC_V02_PATH.read_text(encoding="utf-8")
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    versioning = _VERSIONING_PATH.read_text(encoding="utf-8")

    errors = collect_errors(threat_model, privacy, spec_v01, spec_v02, schema, versioning)
    errors += check_p11b_witness_contract(spec_v02, versioning)
    errors += check_standards_relationship()
    errors += check_internet_draft_snapshot()
    errors += check_conformance_doc()
    errors += check_corpus_counts()
    for error in errors:
        print(f"ERROR {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
