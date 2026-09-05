"""Tests for the spec-docs drift-guard checker (tools/check_spec_docs.py).

Fixture-driven: each case builds minimal doc strings and asserts on
`collect_errors(...)`. Case 11 is the drift-guard proper: it reads the real
`docs/spec/*.md` files and the real schema and asserts a clean run.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tools import check_spec_docs
from tools.check_spec_docs import REQUIRED_SECTIONS, collect_errors, main

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "docs/spec"

# Buyer property set used by the minimal schema fixture and pinned by the
# minimal PC-01 row below -- kept in sync deliberately, the way the real
# schema and privacy doc are meant to stay in sync.
_BUYER_KEYS = ["commitment", "identifier_type", "pubkey"]
_BUYER_REQUIRED = ["commitment", "identifier_type"]
_BUYER_PATTERN = "^[A-Za-z0-9_-]{43}$"


def _minimal_schema(
    buyer_required: list[str] | None = None,
    commitment_pattern: str = _BUYER_PATTERN,
) -> dict[str, object]:
    if buyer_required is None:
        buyer_required = _BUYER_REQUIRED
    return {
        "properties": {
            "buyer": {
                "required": buyer_required,
                "properties": {
                    "commitment": {"type": "string", "pattern": commitment_pattern},
                    "identifier_type": {"enum": ["issuer-account", "email"]},
                    "pubkey": {"type": ["string", "null"], "pattern": _BUYER_PATTERN},
                },
            },
        },
    }


def _spec_text(version: str, sections: list[int]) -> str:
    """Build a minimal spec doc with one `## N. Title` heading per section."""
    lines = [f"# attest — v{version}", ""]
    for n in sections:
        lines.append(f"## {n}. Section {n}")
        lines.append("")
        lines.append(f"Body text for section {n}.")
        lines.append("")
    return "\n".join(lines)


def _minimal_spec_v01() -> str:
    return (
        _spec_text("0.1", list(range(1, 16)))  # §1..§15
        + "### 5.4 `work`\n\n"
        + "| `work.publisher_id` | string, lowercase DNS domain | OPTIONAL | Reserved. |\n"
        + "\n### 5.5 `license`\n\n"
        + "| `not_transferable_before` | string, ISO-8601 UTC | OPTIONAL | Reserved. |\n"
        + "| `preservation_pledge` | object | OPTIONAL | Reserved. |\n"
    )


def _minimal_spec_v02() -> str:
    return (
        _spec_text("0.2", list(range(1, 17)))  # §1..§16
        + "## 17. Stage 3: issuer-mediated transfer\n\n"
        + "`Attest-transfer-authorization-v1` `transfer-record` "
        + "`transferred_revocation_unbacked` `transfer_record_unlogged` "
        + "`transfer_not_yet_transferable` `transfer_double_assignment_conflict` "
        + '`revocation: "transferred"`\n'
        + "\n### 17.5 Chain of title (separate audit surface)\n\n"
        + "\n".join(
            (
                "chain link {i}: no transfer record",
                "chain link {i}: issuer signature invalid",
                "chain link {i}: holder authorization invalid",
                "chain link {i}: transfer record not logged",
                "chain link {i}: transferred before not_transferable_before",
                "chain link {i}: losing branch of a double assignment",
                "chain link {i}: new receipt buyer.pubkey != new_holder_pubkey",
                "chain link {i}: previous receipt lacks a backed transferred-class revocation",
            )
        )
        + "\n"
        + "\n## 18. Stage 4: the preservation pledge\n\n"
        + "`license.preservation_pledge` `sunset-grant-v1` `sunset-grant` "
        + "`deliver-to-holder` `redistribute-among-holders` `publisher-declaration` "
        + "`fixed-date` `heartbeat-absence` `cessation-declaration` "
        + "`Attest-redemption-challenge-v1` `grant_narrowing_ignored` `grant_unanchored` "
        + "`grant_signer_not_publisher` `grant_scope_uncovered` `grant_commitment_mismatch` "
        + "`grant_commitment_divergence` `grant_declaration_ignored` "
        + "`grant_activated_by_successor` `grant_pledge_type_unknown` "
        + "`grant_legal_text_changed` `_MAX_GRANT_LATER_VERSIONS` "
        + '`_MAX_GRANT_DECLARATIONS` `grant: "activated"` `grant_trust: "signer_mismatch"`\n\n'
        + "Activation follows from positive evidence, never from the absence of evidence; "
        + "logging a declaration is RECOMMENDED and never required for validity; the "
        + "fixed-date proof runs in the direction anchoring can give, `T >= fixed_date`, "
        + "taking the MAXIMUM over the verified proofs. The legal text that binds a buyer "
        + "is always the FLOOR's, and a later version differing in ANY of the three "
        + "prose-bearing members is reported. Scope coverage, and it is a gate: Grant "
        + "coverage of a receipt is a DIFFERENT predicate from declaration coverage, and "
        + "the artifact list must be present and non-empty. The declaration step never "
        + "stops at the first one that succeeds.\n\n"
        + "The evidence channel is also the capability gate. Which document seeds the "
        + "accumulator is normative, and it is the effective grant, not the floor; the "
        + "attestation is ONE §11 evidence bundle. A later version naming another "
        + "publisher is inadmissible and ignored WITHOUT effect on `grant_trust`. Only "
        + "an AUTHENTICATED, same-publisher document may move `grant_trust`, and "
        + "`signer_mismatch` is reachable only for a document that has already "
        + 'authenticated. "Sorted" means by Unicode CODE POINT.\n'
        + "\n## Appendix A — The custodian interface (non-normative)\n\nSketch.\n"
    )


def _tm_entry(tm_id: int, verdict_line: str) -> str:
    return (
        f"#### TM-{tm_id:02d} — Example attack\n\n"
        "- **Actor / precondition:** `network attacker` does something.\n"
        "- **Impact:** Something bad would happen.\n"
        f"{verdict_line}\n"
        "- **Residual risk:** None identified.\n\n"
    )


def _minimal_matrix_rows() -> str:
    rows = []
    for section in REQUIRED_SECTIONS:
        rows.append(f"| {section} — Example section | TM-01 |")
    return "\n".join(rows) + "\n"


def _minimal_threat_model(entries: str | None = None, matrix: str | None = None) -> str:
    if entries is None:
        entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.1 §2.  Example mechanism.")
    if matrix is None:
        matrix = _minimal_matrix_rows()
    return (
        "# attest — Threat Model\n\n"
        "## 1. Status and scope\n\nIntro.\n\n"
        "## 2. System model\n\nIntro.\n\n"
        "## 3. Attacker model\n\nIntro.\n\n"
        "## 4. Attack catalog\n\n"
        f"{entries}"
        "## 5. Traceability\n\n"
        "| Spec feature | TM entries |\n"
        "| --- | --- |\n"
        f"{matrix}"
    )


def _minimal_pc_row() -> str:
    keys = ", ".join(_BUYER_KEYS)
    return (
        "| PC-01 | The signed payload schema defines no plaintext "
        "buyer-identity member. | schema | `properties.buyer.properties` "
        f"has key set exactly `{{{keys}}}` and `properties.buyer.required` equals "
        '`["commitment", "identifier_type"]`; `commitment` and `pubkey` are '
        "pattern-constrained to 43 base64url characters and `identifier_type` to the "
        'enum `["issuer-account", "email"]`. |'
    )


def _minimal_privacy(pc_rows: str | None = None) -> str:
    if pc_rows is None:
        pc_rows = _minimal_pc_row()
    return (
        "# attest — Privacy Considerations\n\n"
        "## 1. Status and scope\n\nIntro.\n\n"
        "## 7. Testable claims\n\n"
        "| ID | Claim | Check type | Check detail |\n"
        "| --- | --- | --- | --- |\n"
        f"{pc_rows}\n"
    )


def _minimal_versioning() -> str:
    """A minimal attest-versioning.md fixture carrying every checked property."""
    return (
        "# attest-versioning — Normative Upgrade Policy\n\n"
        "## 1. Scope and authority\n\nIntro.\n\n"
        "## 2. The additive pattern\n\n"
        "One exception exists: a result-classification downgrade mandated by an algorithm "
        "lifecycle transition (§4) is NOT a breaking change and does not require a new "
        "`attest_version`. A lifecycle transition records newly established cryptanalytic "
        "reality about an algorithm; the protocol semantics are unchanged, and eternal "
        "verifiability (§3) is preserved because the artifact remains verifiable — the result "
        "simply reports what its signature is worth today.\n\n"
        "## 3. Eternal verifiability\n\nIntro.\n\n"
        "## 4. Algorithm lifecycle\n\n"
        "| State | Issue | Verify | Verifier obligation |\n"
        "| --- | --- | --- | --- |\n"
        "| `active` | MAY issue | MUST verify | No downgrade. |\n"
        "| `deprecated` | MUST NOT issue | MUST verify | SHOULD warn. |\n"
        "| `unsafe` | MUST NOT issue | MUST verify with mandatory downgraded classification | "
        "MUST cap the result classification. |\n\n"
        "## 5. Amendment procedure\n\nIntro.\n\n"
        "## 6. Registries\n\n"
        "| Name | State | Introduced | Reference |\n"
        "| --- | --- | --- | --- |\n"
        "| `ed25519` | active | v0.1 | v0.1 §10 |\n"
        "| `ed25519+ml-dsa-65` | active | v0.2 | v0.2 §2 |\n"
        "\n"
        "### 6.3 Revocation classes\n\n"
        "| Name | State | Introduced | Reference |\n"
        "| --- | --- | --- | --- |\n"
        "| `none` | active | v0.1 | v0.1 §5.5 |\n"
        "| `refund_window` | active | v0.1 | v0.1 §5.5 |\n"
        "| `policy` | active | v0.1 | v0.1 §5.5 |\n"
        "| `transferred` | active | v0.2 §17 | v0.2 §17.3 |\n"
        "\n"
        "### 6.4 Log entry types\n\n"
        "| Name | State | Introduced | Reference |\n"
        "| --- | --- | --- | --- |\n"
        "| `transfer-record` | active | v0.2 §17 | v0.2 §8, §17.2 |\n"
        "| `cessation-declaration` | active | v0.2 §18 | v0.2 §8, §18.4 |\n"
        "\n"
        "### 6.5 Transfer types\n\n"
        "| Name | State | Introduced | Reference |\n"
        "| --- | --- | --- | --- |\n"
        "| `issuer-mediated-v1` | active | v0.2 §17 | v0.2 §17 |\n"
        "\n"
        "### 6.7 End-of-life commitment values\n\n"
        "| Name | State | Introduced | Reference |\n"
        "| --- | --- | --- | --- |\n"
        "| `sunset-grant` | active | v0.2 §18 | v0.2 §18 |\n"
        "\n"
        "### 6.8 Grant permissions\n\n"
        "| Name | State | Introduced | Reference |\n"
        "| --- | --- | --- | --- |\n"
        "| `deliver-to-holder` | active | v0.2 §18 | v0.2 §18.2 |\n"
        "| `redistribute-among-holders` | active | v0.2 §18 | v0.2 §18.2 |\n"
        "\n"
        "### 6.9 Activation modes\n\n"
        "| Name | State | Introduced | Reference |\n"
        "| --- | --- | --- | --- |\n"
        "| `publisher-declaration` | active | v0.2 §18 | v0.2 §18.4 |\n"
        "| `fixed-date` | active | v0.2 §18 | v0.2 §18.4 |\n"
        "| `heartbeat-absence` | reserved | v0.2 §18 | v0.2 §18.4 |\n"
        "\n"
        "### 6.10 Preservation pledge types\n\n"
        "| Name | State | Introduced | Reference |\n"
        "| --- | --- | --- | --- |\n"
        "| `sunset-grant-v1` | active | v0.2 §18 | v0.2 §18.2 |\n"
        "\n"
        "## Revision log\n\n"
        "- **2026-07-22 (rev 1)**: document introduced — vectors: none\n"
    )


def _base_docs() -> dict[str, object]:
    return {
        "threat_model": _minimal_threat_model(),
        "privacy": _minimal_privacy(),
        "spec_v01": _minimal_spec_v01()
        + "\n## Revision log\n\n- **2026-07-22 (rev 1)**: initial revision — vectors: none\n",
        "spec_v02": _minimal_spec_v02()
        + "\n## Revision log\n\n- **2026-07-22 (rev 1)**: initial revision — vectors: none\n",
        "schema": _minimal_schema(),
        "versioning": _minimal_versioning(),
    }


def test_duplicate_tm_id_is_an_error() -> None:
    entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.1 §2.  Example.") + _tm_entry(
        1, "- **Verdict:** Mitigated — v0.1 §2.  Example."
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("duplicate" in e.lower() and "TM-01" in e for e in errors)


def test_gap_in_tm_sequence_is_an_error() -> None:
    entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.1 §2.  Example.") + _tm_entry(
        3, "- **Verdict:** Mitigated — v0.1 §2.  Example."
    )
    matrix = "\n".join(
        f"| {section} — Example section | TM-01, TM-03 |" for section in REQUIRED_SECTIONS
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries, matrix=matrix + "\n")

    errors = collect_errors(**docs)

    assert any("gap" in e.lower() or "missing" in e.lower() for e in errors)


def test_tm_ids_out_of_ascending_order_are_an_error() -> None:
    entries = (
        _tm_entry(1, "- **Verdict:** Mitigated — v0.1 §2.  Example.")
        + _tm_entry(3, "- **Verdict:** Mitigated — v0.1 §2.  Example.")
        + _tm_entry(2, "- **Verdict:** Mitigated — v0.1 §2.  Example.")
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("ascending" in e.lower() and "TM-02" in e for e in errors)


def test_entry_missing_verdict_line_is_an_error() -> None:
    entry = (
        "#### TM-01 — Example attack\n\n"
        "- **Actor / precondition:** `network attacker` does something.\n"
        "- **Impact:** Something bad would happen.\n"
        "- **Residual risk:** None identified.\n\n"
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entry)

    errors = collect_errors(**docs)

    assert any("verdict" in e.lower() and "TM-01" in e for e in errors)


def test_verdict_line_not_matching_grammar_is_an_error() -> None:
    entries = _tm_entry(1, "- **Verdict:** Sort of mitigated, maybe.")
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("verdict" in e.lower() and "TM-01" in e for e in errors)


def test_dangling_spec_ref_is_an_error() -> None:
    entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.2 §99.  Nonexistent section.")
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("§99" in e for e in errors)


def test_dangling_spec_ref_after_and_is_an_error() -> None:
    entries = _tm_entry(
        1,
        "- **Verdict:** Mitigated — v0.2 §2 and §99.  Nonexistent section.",
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("§99" in e for e in errors)


def test_matrix_row_citing_nonexistent_tm_is_an_error() -> None:
    matrix = "\n".join(
        f"| {section} — Example section | TM-01, TM-99 |" for section in REQUIRED_SECTIONS
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=matrix + "\n")

    errors = collect_errors(**docs)

    assert any("TM-99" in e for e in errors)


def test_required_spec_section_absent_from_matrix_is_an_error() -> None:
    sections = [s for s in REQUIRED_SECTIONS if s != "v0.1 §2"]
    matrix = "\n".join(f"| {section} — Example section | TM-01 |" for section in sections)
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=matrix + "\n")

    errors = collect_errors(**docs)

    assert any("v0.1 §2" in e for e in errors)


def test_matrix_row_without_tm_citation_does_not_cover_section() -> None:
    matrix = _minimal_matrix_rows().replace(
        "| v0.1 §2 — Example section | TM-01 |",
        "| v0.1 §2 — Example section | |",
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=matrix)

    errors = collect_errors(**docs)

    assert any("required section v0.1 §2" in e for e in errors)


def test_matrix_rows_inside_a_fenced_block_do_not_cover_sections() -> None:
    # An illustrative table in a code fence is not the traceability matrix. If it
    # counted, the real matrix could be emptied without the guard noticing.
    fenced = "```text\n" + _minimal_matrix_rows() + "```\n"
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=fenced)

    errors = collect_errors(**docs)

    assert any("required section v0.1 §2" in e for e in errors)


def test_malformed_tm_citation_in_matrix_is_an_error() -> None:
    # An en dash instead of a hyphen: reads as a citation, matches nothing.
    matrix = _minimal_matrix_rows().replace(
        "| v0.1 §2 — Example section | TM-01 |",
        "| v0.1 §2 — Example section | TM–999 |",  # noqa: RUF001 - the en dash IS the defect
    )
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=matrix)

    errors = collect_errors(**docs)

    assert any("malformed TM citation" in e for e in errors)


def test_unsupported_spec_version_in_verdict_is_an_error() -> None:
    entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.3 §999.  Nonexistent version.")
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("unsupported spec version v0.3" in e for e in errors)


def test_tilde_fenced_matrix_rows_do_not_cover_sections() -> None:
    fenced = "~~~text\n" + _minimal_matrix_rows() + "~~~\n"
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=fenced)

    errors = collect_errors(**docs)

    assert any("required section v0.1 §2" in e for e in errors)


def test_indented_fenced_matrix_rows_do_not_cover_sections() -> None:
    # Up to three leading spaces still opens a fence in CommonMark.
    fenced = "   ```text\n" + _minimal_matrix_rows() + "   ```\n"
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(matrix=fenced)

    errors = collect_errors(**docs)

    assert any("required section v0.1 §2" in e for e in errors)


def test_dangling_spec_ref_after_oxford_comma_is_an_error() -> None:
    entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.2 §2, §3, and §99.  Nonexistent.")
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert any("§99" in e for e in errors)


def test_non_spec_version_token_is_not_flagged() -> None:
    # A version that is not a spec citation is ordinary prose. Flagging it would
    # fail a legitimate edit, which is worse than the gap it would close.
    entries = _tm_entry(1, "- **Verdict:** Mitigated — v0.1 §2.  Delivery over TLS v1.3.")
    docs = _base_docs()
    docs["threat_model"] = _minimal_threat_model(entries=entries)

    errors = collect_errors(**docs)

    assert not any("unsupported spec version" in e for e in errors)


def test_pc_01_pattern_pin_naming_the_wrong_fields_is_an_error() -> None:
    pc_row = _minimal_pc_row().replace(
        "`commitment` and `pubkey` are", "`commitment` and `commitment` are"
    )
    docs = _base_docs()
    docs["privacy"] = _minimal_privacy(pc_rows=pc_row)

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "pubkey" in e for e in errors)


def test_pc_01_identifier_type_enum_drift_is_an_error() -> None:
    schema = _minimal_schema()
    buyer = schema["properties"]["buyer"]  # type: ignore[index]
    buyer["properties"]["identifier_type"] = {"type": "string"}  # type: ignore[index]
    docs = _base_docs()
    docs["schema"] = schema

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "identifier_type" in e for e in errors)


def test_pc_row_with_invalid_check_type_is_an_error() -> None:
    pc_row = (
        "| PC-01 | The signed payload schema defines no plaintext "
        "buyer-identity member. | not-a-real-check-type | some detail. |"
    )
    docs = _base_docs()
    docs["privacy"] = _minimal_privacy(pc_rows=pc_row)

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "check type" in e.lower() for e in errors)


def test_pc_01_pinned_buyer_set_diverging_from_schema_is_an_error() -> None:
    pc_row = (
        "| PC-01 | The signed payload schema defines no plaintext "
        "buyer-identity member. | schema | `properties.buyer.properties` "
        "has key set exactly `{commitment, pubkey}`. |"
    )
    docs = _base_docs()
    docs["privacy"] = _minimal_privacy(pc_rows=pc_row)

    errors = collect_errors(**docs)

    assert any("PC-01" in e for e in errors)


def test_pc_01_absent_from_privacy_doc_is_an_error() -> None:
    docs = _base_docs()
    docs["privacy"] = _minimal_privacy(pc_rows="")

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "missing" in e.lower() for e in errors)


def test_pc_08_corpus_pin_includes_json_parsed_chain_payloads() -> None:
    privacy = (SPEC_DIR / "attest-privacy.md").read_text(encoding="utf-8")
    rows = check_spec_docs.parse_pc_rows(privacy)

    assert check_spec_docs.check_pc08_corpus_claim(rows, SPEC_DIR / "vectors") == []

    # Derived, never hardcoded: the pinned count changes every time the corpus
    # grows, and a stale literal here turns the mutation into a no-op — the
    # test then passes while proving nothing about drift detection.
    pinned = re.search(r"(\d+) payload objects", privacy)
    assert pinned is not None
    current = int(pinned.group(1))
    drifted_privacy = privacy.replace(
        f"{current} payload objects", f"{current - 1} payload objects"
    )
    drifted_rows = check_spec_docs.parse_pc_rows(drifted_privacy)
    errors = check_spec_docs.check_pc08_corpus_claim(drifted_rows, SPEC_DIR / "vectors")

    assert any("PC-08" in error and "count" in error for error in errors)


def test_pc_01_required_pin_diverging_from_schema_is_an_error() -> None:
    docs = _base_docs()
    docs["schema"] = _minimal_schema(buyer_required=["commitment"])

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "required" in e.lower() for e in errors)


def test_pc_01_pattern_pin_diverging_from_schema_is_an_error() -> None:
    docs = _base_docs()
    docs["schema"] = _minimal_schema(commitment_pattern="^[A-Za-z0-9_-]{42}$")

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "commitment" in e for e in errors)


def test_pc_01_pattern_pin_diverging_on_the_pubkey_leg_is_an_error() -> None:
    # Drifting only the second field: a checker that validated the first name it
    # captured and stopped would pass this.
    schema = _minimal_schema()
    buyer = schema["properties"]["buyer"]  # type: ignore[index]
    buyer["properties"]["pubkey"]["pattern"] = "^[A-Za-z0-9_-]{42}$"  # type: ignore[index]
    docs = _base_docs()
    docs["schema"] = schema

    errors = collect_errors(**docs)

    assert any("PC-01" in e and "pubkey" in e for e in errors)


def test_well_formed_fixtures_are_clean() -> None:
    docs = _base_docs()

    errors = collect_errors(**docs)

    assert errors == []


def test_real_repo_docs_are_clean() -> None:
    threat_model = (REPO_ROOT / "docs/spec/attest-threat-model.md").read_text(encoding="utf-8")
    privacy = (REPO_ROOT / "docs/spec/attest-privacy.md").read_text(encoding="utf-8")
    spec_v01 = (REPO_ROOT / "docs/spec/attest-v0.1.md").read_text(encoding="utf-8")
    spec_v02 = (REPO_ROOT / "docs/spec/attest-v0.2.md").read_text(encoding="utf-8")
    schema = json.loads(
        (REPO_ROOT / "docs/spec/schema/attest-receipt.schema.json").read_text(encoding="utf-8")
    )
    versioning = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")

    errors = collect_errors(threat_model, privacy, spec_v01, spec_v02, schema, versioning)

    assert errors == []


def test_v02_stage3_section_removal_is_flagged_by_collect_errors() -> None:
    threat_model = (SPEC_DIR / "attest-threat-model.md").read_text(encoding="utf-8")
    privacy = (SPEC_DIR / "attest-privacy.md").read_text(encoding="utf-8")
    spec_v01 = (SPEC_DIR / "attest-v0.1.md").read_text(encoding="utf-8")
    spec_v02 = (SPEC_DIR / "attest-v0.2.md").read_text(encoding="utf-8")
    schema = json.loads(
        (SPEC_DIR / "schema/attest-receipt.schema.json").read_text(encoding="utf-8")
    )
    versioning = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
    spec_v02_without_stage3 = re.sub(
        r"^## 17\. Stage 3: issuer-mediated transfer.*?(?=^## Revision log$)",
        "",
        spec_v02,
        flags=re.MULTILINE | re.DOTALL,
    )

    errors = collect_errors(
        threat_model, privacy, spec_v01, spec_v02_without_stage3, schema, versioning
    )

    assert errors


def test_v02_chain_audit_literal_table_mutation_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["spec_v02"] = docs["spec_v02"].replace(
        "chain link {i}: losing branch of a double assignment",
        "chain link {i}: losing branch removed",
        1,
    )

    errors = collect_errors(**docs)

    assert any("chain link {i}: losing branch of a double assignment" in error for error in errors)


def test_v01_not_transferable_before_row_removal_is_flagged_by_collect_errors() -> None:
    threat_model = (SPEC_DIR / "attest-threat-model.md").read_text(encoding="utf-8")
    privacy = (SPEC_DIR / "attest-privacy.md").read_text(encoding="utf-8")
    spec_v01 = (SPEC_DIR / "attest-v0.1.md").read_text(encoding="utf-8")
    spec_v02 = (SPEC_DIR / "attest-v0.2.md").read_text(encoding="utf-8")
    schema = json.loads(
        (SPEC_DIR / "schema/attest-receipt.schema.json").read_text(encoding="utf-8")
    )
    versioning = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
    spec_v01_without_transfer_floor = re.sub(
        r"^\| `not_transferable_before` \|.*\n",
        "",
        spec_v01,
        flags=re.MULTILINE,
    )

    errors = collect_errors(
        threat_model, privacy, spec_v01_without_transfer_floor, spec_v02, schema, versioning
    )

    assert errors


def test_versioning_transfer_rows_swapped_between_registries_are_flagged() -> None:
    threat_model = (SPEC_DIR / "attest-threat-model.md").read_text(encoding="utf-8")
    privacy = (SPEC_DIR / "attest-privacy.md").read_text(encoding="utf-8")
    spec_v01 = (SPEC_DIR / "attest-v0.1.md").read_text(encoding="utf-8")
    spec_v02 = (SPEC_DIR / "attest-v0.2.md").read_text(encoding="utf-8")
    schema = json.loads(
        (SPEC_DIR / "schema/attest-receipt.schema.json").read_text(encoding="utf-8")
    )
    versioning = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
    swapped_versioning = (
        versioning.replace("`transfer-record`", "`temporary-transfer-row`")
        .replace("`issuer-mediated-v1`", "`transfer-record`")
        .replace("`temporary-transfer-row`", "`issuer-mediated-v1`")
    )

    errors = collect_errors(threat_model, privacy, spec_v01, spec_v02, schema, swapped_versioning)

    assert errors


def test_versioning_transferred_row_moved_out_of_section_6_3_is_flagged() -> None:
    threat_model = (SPEC_DIR / "attest-threat-model.md").read_text(encoding="utf-8")
    privacy = (SPEC_DIR / "attest-privacy.md").read_text(encoding="utf-8")
    spec_v01 = (SPEC_DIR / "attest-v0.1.md").read_text(encoding="utf-8")
    spec_v02 = (SPEC_DIR / "attest-v0.2.md").read_text(encoding="utf-8")
    schema = json.loads(
        (SPEC_DIR / "schema/attest-receipt.schema.json").read_text(encoding="utf-8")
    )
    versioning = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
    lines = versioning.splitlines(keepends=True)
    row_idx = next(
        i for i, line in enumerate(lines) if line.startswith("| `transferred` | active |")
    )
    row = lines.pop(row_idx)
    anchor_idx = next(
        i for i, line in enumerate(lines) if line.startswith("| `issuer-mediated-v1` | active |")
    )
    lines.insert(anchor_idx + 1, row)
    moved_versioning = "".join(lines)

    errors = collect_errors(threat_model, privacy, spec_v01, spec_v02, schema, moved_versioning)

    assert errors


def test_main_exits_zero_on_the_real_docs() -> None:
    # The CI gate is the process exit code, not the error list. Every other test
    # calls collect_errors directly, so main() could return 0 unconditionally and
    # they would all still pass.
    assert main() == 0


def test_main_exits_nonzero_when_a_document_drifts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    drifted = tmp_path / "attest-threat-model.md"
    drifted.write_text(_minimal_threat_model(matrix="| v0.1 §2 — Example | TM-99 |\n"), "utf-8")
    monkeypatch.setattr(check_spec_docs, "_THREAT_MODEL_PATH", drifted)
    monkeypatch.setattr(
        check_spec_docs, "_PRIVACY_PATH", _write(tmp_path, "p.md", _minimal_privacy())
    )
    monkeypatch.setattr(
        check_spec_docs, "_SPEC_V01_PATH", _write(tmp_path, "v1.md", _minimal_spec_v01())
    )
    monkeypatch.setattr(
        check_spec_docs, "_SPEC_V02_PATH", _write(tmp_path, "v2.md", _minimal_spec_v02())
    )
    monkeypatch.setattr(
        check_spec_docs, "_SCHEMA_PATH", _write(tmp_path, "s.json", json.dumps(_minimal_schema()))
    )
    monkeypatch.setattr(
        check_spec_docs,
        "_VERSIONING_PATH",
        _write(tmp_path, "versioning.md", _minimal_versioning()),
    )

    assert main() == 1


class TestStage3Transfer:
    def test_v02_has_stage3_sections(self) -> None:
        text = (SPEC_DIR / "attest-v0.2.md").read_text(encoding="utf-8")
        for needle in (
            "## 17. Stage 3: issuer-mediated transfer",
            "`Attest-transfer-authorization-v1`",
            "`transfer-record`",
            "`transferred_revocation_unbacked`",
            "`transfer_record_unlogged`",
            "`transfer_not_yet_transferable`",
            "`transfer_double_assignment_conflict`",
            '`revocation: "transferred"`',
        ):
            assert needle in text

    def test_registry_transferred_is_active(self) -> None:
        text = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
        assert "| `transferred` | active" in text
        assert "| `transfer-record` | active" in text
        assert "`issuer-mediated-v1`" in text

    def test_v01_registers_not_transferable_before(self) -> None:
        text = (SPEC_DIR / "attest-v0.1.md").read_text(encoding="utf-8")
        assert "`not_transferable_before`" in text


class TestVersioningDoc:
    def test_versioning_doc_exists_and_has_required_sections(self) -> None:
        text = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
        assert check_spec_docs.check_versioning_sections(text) == []

    def test_both_specs_have_revision_log(self) -> None:
        for name in ("attest-v0.1.md", "attest-v0.2.md"):
            text = (SPEC_DIR / name).read_text(encoding="utf-8")
            assert not check_spec_docs.check_revision_logs(text, text)

    def test_registry_suite_names_match_specs(self) -> None:
        text = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
        assert check_spec_docs.check_versioning_suite_names(text) == []

    def test_lifecycle_states_are_exactly_three(self) -> None:
        text = (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8")
        assert check_spec_docs.check_versioning_lifecycle_states(text) == []


class TestStandardsRelationship:
    def test_annex_has_all_seven_entries(self) -> None:
        text = (SPEC_DIR / "attest-standards-relationship.md").read_text(encoding="utf-8")
        for needle in (
            "## 1. W3C Verifiable Credentials",
            "## 2. eIDAS 2.0 and the EUDI Wallet",
            "## 3. JOSE/JWS and COSE",
            "## 4. RFC 8785 (JCS)",
            "## 5. C2PA",
            "## 6. SCITT and RFC 9943",
            "## 7. RATS (RFC 9334): a terminology note",
        ):
            assert needle in text

    def test_scitt_entry_defuses_the_receipt_collision(self) -> None:
        text = (SPEC_DIR / "attest-standards-relationship.md").read_text(encoding="utf-8")
        assert "RFC 9943" in text
        assert "inclusion" in text  # their receipt = proof of inclusion
        assert "RFC 9334" in text  # RATS note present

    def test_checker_reports_missing_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            check_spec_docs, "_STANDARDS_RELATIONSHIP_PATH", SPEC_DIR / "does-not-exist.md"
        )
        errors = check_spec_docs.check_standards_relationship()
        assert any("missing" in e.lower() for e in errors)

    def test_checker_is_clean_on_the_real_annex(self) -> None:
        assert check_spec_docs.check_standards_relationship() == []

    def test_checker_flags_a_renamed_heading(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        text = (SPEC_DIR / "attest-standards-relationship.md").read_text(encoding="utf-8")
        drifted = text.replace("## 6. SCITT and RFC 9943", "## 6. SCITT")
        monkeypatch.setattr(
            check_spec_docs, "_STANDARDS_RELATIONSHIP_PATH", _write(tmp_path, "d.md", drifted)
        )
        errors = check_spec_docs.check_standards_relationship()
        assert any("SCITT and RFC 9943" in e for e in errors)

    def test_main_exits_nonzero_when_annex_file_is_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Pins the main() wiring: check_standards_relationship() is called
        # directly from main() (not through collect_errors()), so a test that
        # only calls the checker function directly would stay green even if
        # main() stopped calling it.
        monkeypatch.setattr(
            check_spec_docs, "_STANDARDS_RELATIONSHIP_PATH", SPEC_DIR / "does-not-exist.md"
        )
        assert main() == 1

    def test_main_exits_nonzero_when_annex_heading_is_renamed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        text = (SPEC_DIR / "attest-standards-relationship.md").read_text(encoding="utf-8")
        drifted = text.replace("## 6. SCITT and RFC 9943", "## 6. SCITT")
        monkeypatch.setattr(
            check_spec_docs, "_STANDARDS_RELATIONSHIP_PATH", _write(tmp_path, "d.md", drifted)
        )
        assert main() == 1

    def test_checker_heading_inside_fenced_block_does_not_satisfy(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """RED for finding 5(a): a required heading present only inside a
        fenced code block (illustrative content) must not satisfy the
        checker -- fenced blocks must be stripped first, the same way
        collect_errors() already does for the threat-model/privacy docs via
        _strip_fenced_blocks()."""
        text = (SPEC_DIR / "attest-standards-relationship.md").read_text(encoding="utf-8")
        fenced = text.replace(
            "## 6. SCITT and RFC 9943",
            "```text\n## 6. SCITT and RFC 9943\n```",
        )
        monkeypatch.setattr(
            check_spec_docs, "_STANDARDS_RELATIONSHIP_PATH", _write(tmp_path, "d.md", fenced)
        )
        errors = check_spec_docs.check_standards_relationship()
        assert any("SCITT and RFC 9943" in e for e in errors)

    def test_main_exits_nonzero_when_annex_literal_is_removed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        text = (SPEC_DIR / "attest-standards-relationship.md").read_text(encoding="utf-8")
        # RFC 9943 is a required literal (and also part of a required heading,
        # so this mutation removes both at once -- either alone is sufficient
        # to make main() non-zero, which is all this test needs to pin).
        drifted = text.replace("RFC 9943", "the SCITT architecture document")
        assert "RFC 9943" not in drifted
        monkeypatch.setattr(
            check_spec_docs, "_STANDARDS_RELATIONSHIP_PATH", _write(tmp_path, "d.md", drifted)
        )
        assert main() == 1


# Minimal well-formed draft-source fixture text: carries both snapshot-
# declaration lines (one revision integer per physical line, each existing in
# the REAL attest-v0.1.md/attest-v0.2.md revision logs) and the three
# required RFC-number literals the terminology defusals and JCS entry cite.
_MINIMAL_DRAFT_TEXT = (
    "<rfc><middle><section><name>Introduction</name>\n"
    "<t>Relationship to the living specification: this document mirrors "
    "attest-v0.1.md at revision 5.</t>\n"
    "<t>It also mirrors attest-v0.2.md at revision 6 as the source of its "
    "Extensions pointers.</t>\n"
    "<t>See RFC 9943, RFC 9334, and RFC 8785.</t>\n"
    "</section></middle></rfc>\n"
)


class TestInternetDraftSnapshot:
    def test_draft_source_exists_and_declares_snapshot(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(check_spec_docs, "_INTERNET_DRAFT_DIR", tmp_path)
        _write(tmp_path, f"{check_spec_docs._INTERNET_DRAFT_BASENAME}.xml", _MINIMAL_DRAFT_TEXT)
        assert check_spec_docs.check_internet_draft_snapshot() == []

    def test_draft_carries_the_terminology_defusals(self) -> None:
        # Exercises the REAL committed draft source under ietf/, read the
        # same way check_internet_draft_snapshot() itself reads it (the
        # standalone _internet_draft_source_text() helper this test used to
        # call was dead production code -- unused by the checker, which
        # reads source_path directly -- so it was removed, 2026-07-23 fix,
        # finding 10).
        path = check_spec_docs._internet_draft_source_path()
        assert path is not None
        text = path.read_text(encoding="utf-8")
        for needle in ("9943", "9334", "8785"):
            assert needle in text

    def test_checker_reports_missing_source(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(check_spec_docs, "_INTERNET_DRAFT_DIR", tmp_path)
        errors = check_spec_docs.check_internet_draft_snapshot()
        assert any("exactly one" in e.lower() for e in errors)

    def test_checker_reports_more_than_one_source(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(check_spec_docs, "_INTERNET_DRAFT_DIR", tmp_path)
        _write(tmp_path, f"{check_spec_docs._INTERNET_DRAFT_BASENAME}.md", _MINIMAL_DRAFT_TEXT)
        _write(tmp_path, f"{check_spec_docs._INTERNET_DRAFT_BASENAME}.xml", _MINIMAL_DRAFT_TEXT)
        errors = check_spec_docs.check_internet_draft_snapshot()
        assert any("exactly one" in e.lower() for e in errors)

    def test_checker_is_clean_on_the_real_draft(self) -> None:
        assert check_spec_docs.check_internet_draft_snapshot() == []

    def test_checker_flags_a_v01_revision_absent_from_the_log(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(check_spec_docs, "_INTERNET_DRAFT_DIR", tmp_path)
        drifted = _MINIMAL_DRAFT_TEXT.replace("revision 5", "revision 999")
        _write(tmp_path, f"{check_spec_docs._INTERNET_DRAFT_BASENAME}.xml", drifted)
        errors = check_spec_docs.check_internet_draft_snapshot()
        assert any("999" in e and "attest-v0.1.md" in e for e in errors)

    def test_checker_flags_a_v02_revision_absent_from_the_log(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(check_spec_docs, "_INTERNET_DRAFT_DIR", tmp_path)
        drifted = _MINIMAL_DRAFT_TEXT.replace("revision 6", "revision 999")
        _write(tmp_path, f"{check_spec_docs._INTERNET_DRAFT_BASENAME}.xml", drifted)
        errors = check_spec_docs.check_internet_draft_snapshot()
        assert any("999" in e and "attest-v0.2.md" in e for e in errors)

    def test_checker_flags_a_removed_required_literal(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(check_spec_docs, "_INTERNET_DRAFT_DIR", tmp_path)
        drifted = _MINIMAL_DRAFT_TEXT.replace("RFC 9943", "the SCITT architecture document")
        assert "9943" not in drifted
        _write(tmp_path, f"{check_spec_docs._INTERNET_DRAFT_BASENAME}.xml", drifted)
        errors = check_spec_docs.check_internet_draft_snapshot()
        assert any("9943" in e for e in errors)

    def test_main_exits_nonzero_when_draft_source_is_missing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Pins the main() wiring: check_internet_draft_snapshot() is called
        # directly from main() (not through collect_errors()), so a test that
        # only calls the checker function directly would stay green even if
        # main() stopped calling it.
        monkeypatch.setattr(check_spec_docs, "_INTERNET_DRAFT_DIR", tmp_path)
        assert main() == 1

    def test_main_exits_nonzero_when_snapshot_revision_is_absent_from_the_log(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(check_spec_docs, "_INTERNET_DRAFT_DIR", tmp_path)
        drifted = _MINIMAL_DRAFT_TEXT.replace("revision 5", "revision 999")
        _write(tmp_path, f"{check_spec_docs._INTERNET_DRAFT_BASENAME}.xml", drifted)
        assert main() == 1

    def test_main_exits_nonzero_when_required_literal_is_removed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(check_spec_docs, "_INTERNET_DRAFT_DIR", tmp_path)
        drifted = _MINIMAL_DRAFT_TEXT.replace("RFC 9334", "the RATS architecture document")
        assert "9334" not in drifted
        _write(tmp_path, f"{check_spec_docs._INTERNET_DRAFT_BASENAME}.xml", drifted)
        assert main() == 1

    def test_checker_declaration_inside_xml_comment_does_not_satisfy(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """RED for finding 5(b): a snapshot-revision declaration present only
        inside an XML comment must not satisfy the checker -- comments are
        never rendered, operative content and must be stripped before the
        findall, the same way fenced Markdown blocks are stripped for the
        standards-relationship annex."""
        commented = _MINIMAL_DRAFT_TEXT.replace(
            "<t>Relationship to the living specification: this document "
            "mirrors attest-v0.1.md at revision 5.</t>\n",
            "<!-- <t>Relationship to the living specification: this "
            "document mirrors attest-v0.1.md at revision 5.</t> -->\n",
        )
        monkeypatch.setattr(check_spec_docs, "_INTERNET_DRAFT_DIR", tmp_path)
        _write(tmp_path, f"{check_spec_docs._INTERNET_DRAFT_BASENAME}.xml", commented)
        errors = check_spec_docs.check_internet_draft_snapshot()
        assert any("attest-v0.1.md" in e and "found 0" in e for e in errors)

    def test_checker_flags_two_v01_declarations_as_ambiguous(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # A source carrying a valid v0.1 declaration AND a second,
        # conflicting one used to pass silently: the old `re.search` call
        # only ever validated the FIRST match (2026-07-23 fix wave, finding
        # 8 -- `findall` now requires exactly one).
        duplicated = _MINIMAL_DRAFT_TEXT.replace(
            "attest-v0.1.md at revision 5.</t>\n",
            "attest-v0.1.md at revision 5.</t>\n"
            "<t>A second, conflicting declaration also mirrors "
            "attest-v0.1.md at revision 12.</t>\n",
        )
        assert duplicated.count("attest-v0.1.md") == 2
        monkeypatch.setattr(check_spec_docs, "_INTERNET_DRAFT_DIR", tmp_path)
        _write(tmp_path, f"{check_spec_docs._INTERNET_DRAFT_BASENAME}.xml", duplicated)
        errors = check_spec_docs.check_internet_draft_snapshot()
        assert any("exactly one" in e.lower() and "attest-v0.1.md" in e for e in errors)

    def test_checker_flags_a_second_conflicting_v02_declaration_as_ambiguous(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        duplicated = _MINIMAL_DRAFT_TEXT.replace(
            "attest-v0.2.md at revision 6 as the source of its Extensions pointers.</t>\n",
            "attest-v0.2.md at revision 6 as the source of its "
            "Extensions pointers.</t>\n"
            "<t>A second, conflicting declaration also mirrors "
            "attest-v0.2.md at revision 2.</t>\n",
        )
        assert duplicated.count("attest-v0.2.md") == 2
        monkeypatch.setattr(check_spec_docs, "_INTERNET_DRAFT_DIR", tmp_path)
        _write(tmp_path, f"{check_spec_docs._INTERNET_DRAFT_BASENAME}.xml", duplicated)
        errors = check_spec_docs.check_internet_draft_snapshot()
        assert any("exactly one" in e.lower() and "attest-v0.2.md" in e for e in errors)


class TestConformanceDoc:
    def test_doc_exists_and_covers_the_required_topics(self) -> None:
        text = (REPO_ROOT / "docs" / "conformance.md").read_text(encoding="utf-8")
        for needle in (
            "tools/conformance_runner.py",
            "{leaf}",
            "attest conformant",
            "self-certification",
        ):
            assert needle in text

    def test_checker_reports_missing_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            check_spec_docs, "_CONFORMANCE_DOC_PATH", REPO_ROOT / "does-not-exist.md"
        )
        errors = check_spec_docs.check_conformance_doc()
        assert any("missing" in e.lower() for e in errors)

    def test_checker_is_clean_on_the_real_doc(self) -> None:
        assert check_spec_docs.check_conformance_doc() == []

    def test_checker_flags_a_removed_required_literal(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        text = (REPO_ROOT / "docs" / "conformance.md").read_text(encoding="utf-8")
        drifted = text.replace("{leaf}", "LEAF_PLACEHOLDER")
        assert "{leaf}" not in drifted
        monkeypatch.setattr(
            check_spec_docs, "_CONFORMANCE_DOC_PATH", _write(tmp_path, "c.md", drifted)
        )
        errors = check_spec_docs.check_conformance_doc()
        assert any("{leaf}" in e for e in errors)

    def test_main_exits_nonzero_when_doc_is_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Pins the main() wiring: check_conformance_doc() is called directly
        # from main() (not through collect_errors()), so a test that only
        # calls the checker function directly would stay green even if
        # main() stopped calling it.
        monkeypatch.setattr(
            check_spec_docs, "_CONFORMANCE_DOC_PATH", REPO_ROOT / "does-not-exist.md"
        )
        assert main() == 1


# --- check_conformance_self_certification -------------------------------------
#
# The table these tests guard shipped three stages stale -- `213/213` and
# `61/61` against a corpus of 221 and 63 -- while the prose two paragraphs
# above it was right and the gate was green. Every case below is written as a
# cell shape, not as a sentence: the reason the drift was invisible is that a
# table cell has no sentence in it, so a guard that goes back to matching prose
# here would pass all of these and still miss the next one.
#
# The second half of the class exists because the first version of this guard
# was rejected in review with ten reproduced false greens, all of them SHAPE
# rather than content: one row instead of four, a duplicated row, a truncated
# one, a row without its leading pipe, a decoy section in a code fence, the
# real one inside an HTML comment, the header's columns swapped. A stale-claim
# guard that can be silenced by deleting a row is not a guard, so each of those
# is pinned here by the shape that silenced it.

_SELF_CERT_DOC = """# fixture

## 6. Before

Prose that must stay outside the section.
{decoy}
## 7. Self-certification table

Rows are a CURRENT claim, not a changelog.

| Implementation | Subset | Leaves passed | Corpus revision | Date | Command |
| --- | --- | --- | --- | --- | --- |
{rows}

## 8. After

| impl | v0.2 | 999/999 | `{zeros}` | 2026-01-01 | cmd |
"""

_SELF_CERT_ZEROS = "0" * 64


def _self_cert_document(rows: str, *, decoy: str = "") -> str:
    return _SELF_CERT_DOC.format(rows=rows, zeros=_SELF_CERT_ZEROS, decoy=decoy)


def _self_cert_corpus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[check_spec_docs._CorpusMeasurement, str]:
    """Point the guard at a three-leaf corpus and hand back what it measures.

    Nothing like the real numbers, so a check that hardcoded 221 or 63 could
    not pass by accident; and the two figures differ, so a check that conflated
    the corpus with its v0.1 subset could not either.
    """
    vectors = tmp_path / "docs" / "spec" / "vectors"
    for group, leaf in (("01-a", "a"), ("01-a", "b"), ("26-b", "a")):
        (vectors / group / leaf).mkdir(parents=True, exist_ok=True)
        (vectors / group / leaf / "expected.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(check_spec_docs, "_REPO_ROOT", tmp_path)
    return check_spec_docs._measured_corpus(), check_spec_docs._measured_corpus_revision()


def _self_cert_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, document: str) -> list[str]:
    monkeypatch.setattr(
        check_spec_docs, "_CONFORMANCE_DOC_PATH", _write(tmp_path, "c.md", document)
    )
    return check_spec_docs.check_conformance_self_certification()


def _self_cert_row(
    implementation: str, subset: str, passed: int, of_total: int, revision: str
) -> str:
    return (
        f"| {implementation} | {subset} | {passed}/{of_total} | `{revision}` | 2026-01-01 | cmd |"
    )


def _reference_rows(measured: check_spec_docs._CorpusMeasurement, revision: str) -> list[str]:
    """The four rows a correct §7 table carries, built from the live manifests."""
    labels, errors = check_spec_docs._reference_implementation_labels()
    assert errors == [], errors
    counts = {"v0.2": measured.total, "v0.1": measured.subset}
    return [
        _self_cert_row(label, subset, counts[subset], counts[subset], revision)
        for label, _name, _manifest in labels
        for subset in ("v0.2", "v0.1")
    ]


class TestConformanceSelfCertification:
    def test_checker_is_clean_on_the_real_doc(self) -> None:
        assert check_spec_docs.check_conformance_self_certification() == []

    def test_the_four_correct_rows_are_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Without this the drift cases below would all pass on a guard that
        # simply rejects every row it is shown.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        errors = _self_cert_errors(
            tmp_path,
            monkeypatch,
            _self_cert_document("\n".join(_reference_rows(measured, revision))),
        )
        assert errors == []

    def test_a_stale_leaf_count_is_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The exact shape that shipped: a whole-corpus row three stages behind.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        rows = _reference_rows(measured, revision)
        rows[0] = rows[0].replace(f"| {measured.total}/{measured.total} |", "| 213/213 |")
        errors = _self_cert_errors(tmp_path, monkeypatch, _self_cert_document("\n".join(rows)))
        assert any("213" in e and str(measured.total) in e for e in errors)

    def test_a_v01_row_is_measured_against_the_subset_not_the_whole_corpus(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A guard that checked both columns against one number would call this
        # clean, and the v0.1 row is where the stale 61 lived.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        assert measured.subset != measured.total, "fixture must keep the two figures apart"
        rows = _reference_rows(measured, revision)
        rows[1] = rows[1].replace(
            f"| {measured.subset}/{measured.subset} |", f"| {measured.total}/{measured.total} |"
        )
        errors = _self_cert_errors(tmp_path, monkeypatch, _self_cert_document("\n".join(rows)))
        assert any("v0.1" in e and str(measured.subset) in e for e in errors)

    def test_a_row_that_did_not_fully_pass_is_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # §1: no partial credit. A row saying otherwise is not a claim.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        rows = _reference_rows(measured, revision)
        rows[0] = rows[0].replace(
            f"| {measured.total}/{measured.total} |", f"| {measured.total - 1}/{measured.total} |"
        )
        errors = _self_cert_errors(tmp_path, monkeypatch, _self_cert_document("\n".join(rows)))
        assert any("partial credit" in e for e in errors)

    def test_a_stale_corpus_revision_is_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A row can name the right count and still be unrunnable: the digest is
        # what makes the claim falsifiable, so it goes stale on its own.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        rows = _reference_rows(measured, revision)
        rows[0] = rows[0].replace(revision, _SELF_CERT_ZEROS)
        errors = _self_cert_errors(tmp_path, monkeypatch, _self_cert_document("\n".join(rows)))
        assert any("revision" in e for e in errors)

    def test_a_corpus_revision_is_compared_whole_not_by_its_prefix(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The runner prints the digest abbreviated and so does this guard's own
        # error text, which makes comparing the abbreviation the natural
        # shortcut. A digest is a claim about every leaf file, so it is either
        # compared whole or it is not compared.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        near_miss = revision[:12] + ("f" * 52 if revision[12:] != "f" * 52 else "0" * 52)
        assert near_miss != revision and near_miss[:12] == revision[:12]
        rows = _reference_rows(measured, revision)
        rows[0] = rows[0].replace(revision, near_miss)
        errors = _self_cert_errors(tmp_path, monkeypatch, _self_cert_document("\n".join(rows)))
        assert any("revision" in e for e in errors)

    def test_a_stale_implementation_version_is_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The drift that shipped WITH the stale counts: the rows named 0.9.0
        # while both package manifests said 0.9.1. A claim about a version this
        # tree no longer builds is a claim nobody can reproduce.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        labels, _ = check_spec_docs._reference_implementation_labels()
        rows = [
            row.replace(labels[0][0], f"{labels[0][1]} 0.0.1")
            for row in _reference_rows(measured, revision)
        ]
        errors = _self_cert_errors(tmp_path, monkeypatch, _self_cert_document("\n".join(rows)))
        assert any("0.0.1" in e and "no longer" in e for e in errors)

    def test_a_deleted_reference_row_is_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Deleting a row is the cheapest way to silence a guard that only
        # judges the rows it is shown.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        rows = _reference_rows(measured, revision)[:-1]
        errors = _self_cert_errors(tmp_path, monkeypatch, _self_cert_document("\n".join(rows)))
        assert any("has no v0.1 row" in e for e in errors)

    def test_a_duplicated_row_is_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Two rows for one implementation and subset cannot both be current,
        # and a stale duplicate beside a fresh row reads as certification.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        rows = _reference_rows(measured, revision)
        errors = _self_cert_errors(
            tmp_path, monkeypatch, _self_cert_document("\n".join([*rows, rows[0]]))
        )
        assert any("repeats a claim" in e for e in errors)

    @pytest.mark.parametrize(
        ("row", "needle"),
        [
            (f"| impl | v0.3 | 3/3 | `{_SELF_CERT_ZEROS}` | d | cmd |", "subset"),
            (f"| impl | v0.2 | all of them | `{_SELF_CERT_ZEROS}` | d | cmd |", "leaves-passed"),
            ("| impl | v0.2 | 3/3 | `1cdec7b8` | d | cmd |", "corpus-revision"),
            ("| impl | v0.2 | 3/3 | see the report | d | cmd |", "corpus-revision"),
            ("| impl | v0.2 | 3/3 |", "cells"),
            (f"| impl | v0.2 | 3/3 | `{_SELF_CERT_ZEROS}` | d | cmd | extra |", "cells"),
            (f"impl | v0.2 | 213/213 | `{_SELF_CERT_ZEROS}` | d | cmd", "213"),
        ],
    )
    def test_a_row_the_guard_cannot_line_up_is_reported_not_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, row: str, needle: str
    ) -> None:
        # Every one of these was a reproduced false green: a cell that does not
        # parse, a truncated row, an extra column, a GFM row with no leading
        # pipe. Skipping any of them is how a stale claim survives the guard
        # that exists to find it.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        rows = [*_reference_rows(measured, revision), row]
        errors = _self_cert_errors(tmp_path, monkeypatch, _self_cert_document("\n".join(rows)))
        assert any(needle in e for e in errors)

    def test_a_missing_section_is_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        errors = _self_cert_errors(tmp_path, monkeypatch, "# fixture\n\n## 7. Something else\n")
        assert any("Self-certification table" in e for e in errors)

    def test_a_second_section_with_the_same_heading_is_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The guard reads one section. A second one is a table nothing checks,
        # and the stale copy is the one a reader would find first or last.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        document = _self_cert_document("\n".join(_reference_rows(measured, revision)))
        errors = _self_cert_errors(
            tmp_path, monkeypatch, document + "\n## 7. Self-certification table\n\nstale\n"
        )
        assert any("sections are headed" in e for e in errors)

    def test_a_renamed_or_reordered_column_is_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # With Date and Leaves passed swapped in the header, every cell the
        # guard reads means something else; it must refuse rather than compare.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        document = _self_cert_document("\n".join(_reference_rows(measured, revision))).replace(
            "| Implementation | Subset | Leaves passed | Corpus revision | Date | Command |",
            "| Implementation | Subset | Date | Corpus revision | Leaves passed | Command |",
        )
        errors = _self_cert_errors(tmp_path, monkeypatch, document)
        assert any("header row" in e for e in errors)

    def test_a_separator_row_must_be_a_separator_and_not_just_the_right_width(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Checking the separator's width and not its content is the cheap half
        # of the check, and it leaves the guard reading whatever follows a
        # six-celled line as though a table had been declared there.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        document = _self_cert_document("\n".join(_reference_rows(measured, revision))).replace(
            "| --- | --- | --- | --- | --- | --- |",
            "| === | === | === | === | === | === |",
        )
        errors = _self_cert_errors(tmp_path, monkeypatch, document)
        assert any("separator row" in e for e in errors)

    def test_a_table_with_no_claim_row_is_flagged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # An emptied table must fail, not pass vacuously.
        _self_cert_corpus(tmp_path, monkeypatch)
        errors = _self_cert_errors(tmp_path, monkeypatch, _self_cert_document(""))
        assert any("no claim row" in e for e in errors)

    def test_the_real_table_commented_out_is_not_a_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Commenting the table out removes the claims; it must not remove the
        # guard with them.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        document = _self_cert_document("\n".join(_reference_rows(measured, revision)))
        head, table = document.split("Rows are a CURRENT claim, not a changelog.\n", 1)
        errors = _self_cert_errors(tmp_path, monkeypatch, f"{head}<!--\n{table}\n-->\n")
        assert errors != []

    def test_a_decoy_section_in_a_code_fence_is_not_the_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A fenced example of the table is documentation, not a claim: it must
        # neither be read as the section nor make the real one ambiguous.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        decoy = (
            "\n```\n## 7. Self-certification table\n\n"
            "| Implementation | Subset | Leaves passed | Corpus revision | Date | Command |\n"
            "| --- | --- | --- | --- | --- | --- |\n"
            f"| impl | v0.2 | 213/213 | `{_SELF_CERT_ZEROS}` | d | cmd |\n```\n"
        )
        errors = _self_cert_errors(
            tmp_path,
            monkeypatch,
            _self_cert_document("\n".join(_reference_rows(measured, revision)), decoy=decoy),
        )
        assert errors == []

    def test_rows_below_the_next_heading_are_outside_the_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The fixture doc carries a 999/999 row under "## 8. After". The guard
        # reads one section, so that row must never be reported -- otherwise
        # every markdown table in the file becomes a conformance claim.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        errors = _self_cert_errors(
            tmp_path,
            monkeypatch,
            _self_cert_document("\n".join(_reference_rows(measured, revision))),
        )
        assert not any("999" in e for e in errors)

    def test_the_reported_line_counts_every_separator_splitlines_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Counting "\n" and splitting with splitlines() disagree on U+2028 and
        # friends, and the error would then point at the wrong line -- the one
        # thing a drift report has to get right for the reader to act on it.
        measured, revision = _self_cert_corpus(tmp_path, monkeypatch)
        rows = _reference_rows(measured, revision)
        rows[0] = rows[0].replace(f"| {measured.total}/{measured.total} |", "| 213/213 |")
        separator = chr(0x2028)  # a line break splitlines() sees and str.count("\n") does not
        document = _self_cert_document("\n".join(rows)).replace(
            "# fixture", f"# first{separator}second"
        )
        expected_line = next(
            number for number, line in enumerate(document.splitlines(), 1) if "213/213" in line
        )
        errors = _self_cert_errors(tmp_path, monkeypatch, document)
        assert any(f"conformance.md:{expected_line}:" in e for e in errors)

    def test_main_exits_nonzero_when_a_row_is_stale(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Pins the main() wiring, same reasoning as the sibling guard above:
        # a check only exercised directly stays green if main() drops it.
        real_doc = (REPO_ROOT / "docs" / "conformance.md").read_text(encoding="utf-8")
        # Match the row by SHAPE, not by its current figure. The self-cert
        # counts move every time the corpus grows, and naming one here made
        # this guard go red for a reason that has nothing to do with the
        # main() wiring it exists to pin — the sibling guards above already
        # derive theirs from `measured`, which is the same discipline.
        drifted, substitutions = re.subn(r"\| (\d+)/\1 \|", "| 213/213 |", real_doc, count=1)
        assert substitutions == 1, "the real table no longer has a row this test can drift"
        monkeypatch.setattr(
            check_spec_docs, "_CONFORMANCE_DOC_PATH", _write(tmp_path, "c.md", drifted)
        )
        assert main() == 1


def test_versioning_doc_missing_heading_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace("## 4. Algorithm lifecycle\n\n", "")

    errors = collect_errors(**docs)

    assert any("4. Algorithm lifecycle" in e for e in errors)


def test_versioning_doc_demoted_heading_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "## 4. Algorithm lifecycle", "### 4. Algorithm lifecycle"
    )

    errors = collect_errors(**docs)

    assert any("4. Algorithm lifecycle" in e for e in errors)


def test_versioning_doc_missing_lifecycle_state_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `unsafe` | MUST NOT issue | MUST verify with mandatory downgraded classification | "
        "MUST cap the result classification. |\n",
        "",
    )

    errors = collect_errors(**docs)

    assert any("unsafe" in e for e in errors)


def test_versioning_doc_extra_lifecycle_state_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `unsafe` | MUST NOT issue | MUST verify with mandatory downgraded classification | "
        "MUST cap the result classification. |\n",
        "| `unsafe` | MUST NOT issue | MUST verify with mandatory downgraded classification | "
        "MUST cap the result classification. |\n"
        "| `frozen` | MUST NOT issue | MUST NOT verify | Reject. |\n",
    )

    errors = collect_errors(**docs)

    assert any("frozen" in e or "exactly" in e for e in errors)


def test_versioning_doc_missing_suite_name_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `ed25519` | active | v0.1 | v0.1 §10 |\n", ""
    )

    errors = collect_errors(**docs)

    assert any("ed25519" in e for e in errors)


def test_versioning_doc_missing_policy_revocation_row_is_flagged() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `policy` | active | v0.1 | v0.1 §5.5 |\n", ""
    )

    errors = collect_errors(**docs)

    assert any("policy" in e for e in errors)


def test_versioning_doc_transferred_row_not_active_is_flagged() -> None:
    # A regression back to `reserved` (or any state other than `active`) must
    # be caught -- mere row presence is not enough for this specific class,
    # since v0.2 §17 (rev 6) activation is exactly the fact worth guarding.
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `transferred` | active | v0.2 §17 | v0.2 §17.3 |\n",
        "| `transferred` | reserved | — | Future transfer profile |\n",
    )

    errors = collect_errors(**docs)

    assert any("transferred" in e and "active" in e for e in errors)


def test_versioning_doc_transfer_record_row_not_active_is_flagged() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `transfer-record` | active | v0.2 §17 | v0.2 §8, §17.2 |\n", ""
    )

    errors = collect_errors(**docs)

    assert any("transfer-record" in e and "active" in e for e in errors)


def test_versioning_doc_issuer_mediated_v1_row_not_active_is_flagged() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "| `issuer-mediated-v1` | active | v0.2 §17 | v0.2 §17 |\n", ""
    )

    errors = collect_errors(**docs)

    assert any("issuer-mediated-v1" in e and "active" in e for e in errors)


def test_versioning_doc_missing_lifecycle_exception_is_flagged() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "One exception exists:", "The exception exists:"
    )

    errors = collect_errors(**docs)

    assert any("One exception exists:" in e for e in errors)


def test_versioning_doc_missing_revision_log_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["versioning"] = _minimal_versioning().replace(
        "\n## Revision log\n\n- **2026-07-22 (rev 1)**: document introduced — vectors: none\n",
        "",
    )

    errors = collect_errors(**docs)

    assert any("attest-versioning.md" in e and "Revision log" in e for e in errors)


def test_missing_revision_log_is_flagged_by_collect_errors() -> None:
    docs = _base_docs()
    docs["spec_v01"] = _minimal_spec_v01()  # no '## Revision log' section

    errors = collect_errors(**docs)

    assert any("attest-v0.1.md" in e and "Revision log" in e for e in errors)


def test_revision_log_requires_a_grammar_valid_entry() -> None:
    docs = _base_docs()
    docs["spec_v01"] = _minimal_spec_v01() + "\n## Revision log\n\nIntro.\n"

    errors = collect_errors(**docs)

    assert any("attest-v0.1.md" in e and "revision-log entry" in e for e in errors)


def test_revision_log_malformed_entry_is_flagged_with_its_line() -> None:
    docs = _base_docs()
    docs["spec_v01"] = _minimal_spec_v01() + (
        "\n## Revision log\n\n- **2026-07-22 (rev 1)**: initial revision; vectors: none\n"
    )

    errors = collect_errors(**docs)

    assert any("attest-v0.1.md" in e and "line" in e and "revision-log entry" in e for e in errors)


# --- P1.1b witness-policy normative contract --------------------------------


def _p11b_witness_docs() -> tuple[str, str]:
    """The P1.1b contract is checked against its normative documents, not a
    reduced fixture: its purpose is to keep exact authority and phase-boundary
    language from drifting after the amendment lands."""
    return (
        (SPEC_DIR / "attest-v0.2.md").read_text(encoding="utf-8"),
        (SPEC_DIR / "attest-versioning.md").read_text(encoding="utf-8"),
    )


def test_p11b_witness_contract_is_complete() -> None:
    spec_v02, versioning = _p11b_witness_docs()

    assert check_spec_docs.check_p11b_witness_contract(spec_v02, versioning) == []


@pytest.mark.parametrize(
    ("name", "old", "new", "document", "expected"),
    (
        (
            "domain separation",
            '`0xff || UTF8("attest-cosignature-ml-dsa-65-v1")`',
            '`0xff || UTF8("attest-ml-dsa-65-v1")`',
            "spec",
            '0xff || UTF8("attest-cosignature-ml-dsa-65-v1")',
        ),
        (
            "type 0x06 exclusion",
            "C2SP type `0x06` MUST NOT count",
            "C2SP type `0x06` may count",
            "spec",
            "C2SP type `0x06` MUST NOT count",
        ),
        (
            "evidence authority boundary",
            "Evidence MUST NOT carry epoch contents",
            "Evidence carries epoch contents",
            "spec",
            "Evidence MUST NOT carry epoch contents",
        ),
        (
            "direct conflict limb",
            "Direct conflict: `X` appears in the pin's `affiliated_domains`.",
            "Direct conflict: omitted.",
            "spec",
            "Direct conflict",
        ),
        (
            "transitive conflict limb",
            "Transitive conflict: the pin's `control_group` equals the `control_group`",
            "Transitive conflict: omitted.",
            "spec",
            "Transitive conflict",
        ),
        (
            "inclusive compromise cutoff",
            "`T <= compromised_after` retains its standing",
            "`T < compromised_after` retains its standing",
            "spec",
            "T <= compromised_after",
        ),
        (
            "committee ceiling before crypto",
            "before any Ed25519 or ML-DSA-65 signature verification",
            "after signature verification",
            "spec",
            "before any Ed25519 or ML-DSA-65 signature verification",
        ),
    ),
)
def test_p11b_witness_contract_rejects_required_negative_mutations(
    name: str, old: str, new: str, document: str, expected: str
) -> None:
    spec_v02, versioning = _p11b_witness_docs()
    if document == "spec":
        assert old in spec_v02, name
        spec_v02 = spec_v02.replace(old, new, 1)
    else:
        assert old in versioning, name
        versioning = versioning.replace(old, new, 1)

    errors = check_spec_docs.check_p11b_witness_contract(spec_v02, versioning)

    assert any(expected in error for error in errors), (name, errors)


# --- receipt_id §5.1 prose <-> schema.receipt_id.pattern drift guard ---------


def _spec_v01_with_receipt_id_row(prose_pattern: str) -> str:
    """A minimal §5.1 receipt_id table row, injected into a v0.1 fixture doc."""
    base = _minimal_spec_v01()
    row = f"\n\n| `receipt_id` | string, ULID (`{prose_pattern}`) | REQUIRED | ULID. |\n"
    return base + row


def test_receipt_id_prose_pattern_diverging_from_schema_is_an_error() -> None:
    docs = _base_docs()
    docs["spec_v01"] = (
        _spec_v01_with_receipt_id_row("^[0-9A-HJKMNP-TV-Z]{26}$")
        + "\n## Revision log\n\n- **2026-07-22 (rev 1)**: initial revision — vectors: none\n"
    )
    docs["schema"] = _minimal_schema()
    docs["schema"]["properties"]["receipt_id"] = {
        "type": "string",
        "pattern": "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
    }

    errors = collect_errors(**docs)

    assert any("receipt_id" in e and "diverges from" in e and "attest-v0.1.md" in e for e in errors)


def test_receipt_id_prose_pattern_matching_schema_is_clean() -> None:
    docs = _base_docs()
    pattern = "^[0-7][0-9A-HJKMNP-TV-Z]{25}$"
    docs["spec_v01"] = (
        _spec_v01_with_receipt_id_row(pattern)
        + "\n## Revision log\n\n- **2026-07-22 (rev 1)**: initial revision — vectors: none\n"
    )
    docs["schema"] = _minimal_schema()
    docs["schema"]["properties"]["receipt_id"] = {"type": "string", "pattern": pattern}

    errors = collect_errors(**docs)

    assert not any("receipt_id" in e and "diverges from" in e for e in errors)


def test_receipt_id_row_absent_from_fixture_does_not_error() -> None:
    """Fixture docs where NEITHER side models `receipt_id` at all (the
    common case for every other test in this file, via `_base_docs()`/
    `_minimal_schema()`) are not a drift signal and must not be flagged —
    the check only skips when both sides are simultaneously absent; a
    one-sided absence (M2, 2026-07-22 fix wave 2) is fail-closed instead,
    see `test_receipt_id_schema_pattern_absent_while_prose_present_is_an_error`
    and `test_receipt_id_prose_row_absent_while_schema_pattern_present_is_an_error`."""
    docs = _base_docs()

    errors = collect_errors(**docs)

    assert not any("receipt_id" in e for e in errors)


def test_receipt_id_schema_pattern_absent_while_prose_present_is_an_error() -> None:
    """M2 (2026-07-22 fix wave 2): §5.1 carries a receipt_id ULID prose
    pattern, but the schema has no `properties.receipt_id.pattern` at all —
    previously this fell through the old code's early `if schema_pattern is
    None: return []`, fail-open. Must now be an explicit, fail-closed error."""
    docs = _base_docs()
    docs["spec_v01"] = (
        _spec_v01_with_receipt_id_row("^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
        + "\n## Revision log\n\n- **2026-07-22 (rev 1)**: initial revision — vectors: none\n"
    )
    docs["schema"] = _minimal_schema()  # no receipt_id property at all

    errors = collect_errors(**docs)

    assert any(
        "receipt_id" in e and "attest-v0.1.md" in e and "schema" in e.lower() for e in errors
    )


def test_receipt_id_prose_row_absent_while_schema_pattern_present_is_an_error() -> None:
    """M2 companion: the schema defines `receipt_id.pattern`, but §5.1 carries
    no receipt_id prose row at all — previously this fell through the old
    code's early `if match is None: return []`, fail-open. Must now be an
    explicit, fail-closed error."""
    docs = _base_docs()  # spec_v01 has no §5.1 receipt_id row
    docs["schema"] = _minimal_schema()
    docs["schema"]["properties"]["receipt_id"] = {
        "type": "string",
        "pattern": "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
    }

    errors = collect_errors(**docs)

    assert any("receipt_id" in e and "attest-v0.1.md" in e and "prose" in e.lower() for e in errors)


@pytest.mark.parametrize(
    ("name", "old", "new", "document", "expected"),
    (
        (
            "section removed",
            "## 18. Stage 4: the preservation pledge",
            "## 18. Stage 4: something else",
            "spec_v02",
            "missing required heading",
        ),
        (
            "appendix removed",
            "## Appendix A — The custodian interface (non-normative)",
            "## Appendix A — Something else",
            "spec_v02",
            "Appendix A",
        ),
        (
            "warning literal dropped",
            "`grant_declaration_ignored`",
            "`grant_declaration_dropped`",
            "spec_v02",
            "grant_declaration_ignored",
        ),
        (
            "successor warning dropped",
            "`grant_activated_by_successor`",
            "`grant_by_successor`",
            "spec_v02",
            "grant_activated_by_successor",
        ),
        (
            "divergence warning dropped",
            "`grant_commitment_divergence`",
            "`grant_commitment_differs`",
            "spec_v02",
            "grant_commitment_divergence",
        ),
        (
            "declaration ceiling dropped",
            "`_MAX_GRANT_DECLARATIONS`",
            "`_MAX_DECLARATIONS`",
            "spec_v02",
            "_MAX_GRANT_DECLARATIONS",
        ),
        # The three claims a regression could quietly invert. Each mutation
        # below leaves a document that still reads fluently and still says
        # something -- just something we know to be false.
        (
            "activation inferred from absence",
            "never from the absence of evidence",
            "or from the absence of evidence",
            "spec_v02",
            "never from the absence of evidence",
        ),
        (
            "logging made load-bearing",
            "never required for validity",
            "required for validity",
            "spec_v02",
            "never required for validity",
        ),
        (
            "fixed-date inequality reversed",
            "T >= fixed_date",
            "T <= fixed_date",
            "spec_v02",
            "T >= fixed_date",
        ),
        (
            "fixed-date aggregation flipped to the minimum",
            "MAXIMUM over the verified proofs",
            "minimum over the verified proofs",
            "spec_v02",
            "MAXIMUM over the verified proofs",
        ),
        (
            "later prose allowed to displace the floor's",
            "The legal text that binds a buyer is always the FLOOR's",
            "The legal text that binds a buyer is the effective version's",
            "spec_v02",
            "The legal text that binds a buyer is always the FLOOR's",
        ),
        (
            "scope coverage demoted to informational",
            "Scope coverage, and it is a gate",
            "Scope coverage, informational only",
            "spec_v02",
            "Scope coverage, and it is a gate",
        ),
        (
            "grant coverage collapsed back into declaration coverage",
            "Grant coverage of a receipt is a DIFFERENT predicate",
            "Grant coverage of a receipt uses the same predicate",
            "spec_v02",
            "Grant coverage of a receipt is a DIFFERENT predicate",
        ),
        (
            "empty artifact list left to a vacuous quantifier",
            "present and non-empty",
            "present",
            "spec_v02",
            "present and non-empty",
        ),
        (
            "declaration scan turned into a short circuit",
            "never stops at the first one that succeeds",
            "stops at the first one that succeeds",
            "spec_v02",
            "never stops at the first one that succeeds",
        ),
        (
            "prose-bearing members narrowed to two",
            "ANY of the three prose-bearing members",
            "either of the two prose-bearing members",
            "spec_v02",
            "ANY of the three prose-bearing members",
        ),
        (
            "unknown pledge profile warning dropped",
            "`grant_pledge_type_unknown`",
            "`grant_pledge_unknown`",
            "spec_v02",
            "grant_pledge_type_unknown",
        ),
        (
            "legal text change warning dropped",
            "`grant_legal_text_changed`",
            "`grant_text_changed`",
            "spec_v02",
            "grant_legal_text_changed",
        ),
        # The seven divergence claims. Each names a choice §18 originally left
        # to the implementer; dropping any one lets two conforming verifiers
        # disagree on identical bytes while the prose still reads fluently.
        (
            "fixed-date seed left unnamed again",
            "it is the effective grant, not the floor",
            "it is one of the two grants",
            "spec_v02",
            "it is the effective grant, not the floor",
        ),
        (
            "anchor evidence reopened as an array",
            "ONE §11 evidence bundle",
            "a list of §11 evidence bundles",
            "spec_v02",
            "ONE §11 evidence bundle",
        ),
        (
            "inadmissible version allowed to downgrade trust",
            "ignored WITHOUT effect on `grant_trust`",
            "ignored",
            "spec_v02",
            "ignored WITHOUT effect on `grant_trust`",
        ),
        (
            "unauthenticated version allowed to signal rollback",
            "Only an AUTHENTICATED, same-publisher document may move `grant_trust`",
            "Any supplied document may move `grant_trust`",
            "spec_v02",
            "Only an AUTHENTICATED, same-publisher document may move `grant_trust`",
        ),
        (
            "signer_mismatch reachable without authentication",
            "reachable only for a document that has already authenticated",
            "reachable for any document",
            "spec_v02",
            "reachable only for a document that has already authenticated",
        ),
        (
            "capability gate dropped",
            "The evidence channel is also the capability gate",
            "The evidence channel carries evidence",
            "spec_v02",
            "The evidence channel is also the capability gate",
        ),
        (
            "collation left to the runtime",
            '"Sorted" means by Unicode CODE POINT',
            '"Sorted" means whatever the runtime does',
            "spec_v02",
            '"Sorted" means by Unicode CODE POINT',
        ),
        (
            "reserved mode quietly promoted",
            "| `heartbeat-absence` | reserved |",
            "| `heartbeat-absence` | active |",
            "versioning",
            "reserved-state row for activation mode",
        ),
        (
            "pledge type registry emptied",
            "| `sunset-grant-v1` | active |",
            "| `sunset-grant-v2` | active |",
            "versioning",
            "preservation pledge type",
        ),
        (
            "cessation entry type dropped",
            "| `cessation-declaration` | active |",
            "| `cessation-declaration` | reserved |",
            "versioning",
            "log entry type `cessation-declaration`",
        ),
        (
            "publisher_id row removed",
            "| `work.publisher_id` |",
            "| `work.publisher` |",
            "spec_v01",
            "work.publisher_id row",
        ),
        (
            "pledge license row removed",
            "| `preservation_pledge` |",
            "| `preservation_promise` |",
            "spec_v01",
            "preservation_pledge row",
        ),
    ),
)
def test_stage4_required_material_removal_is_flagged(
    name: str, old: str, new: str, document: str, expected: str
) -> None:
    docs = _base_docs()
    text = docs[document]
    assert isinstance(text, str)
    assert old in text, name
    docs[document] = text.replace(old, new, 1)

    errors = collect_errors(**docs)

    assert any(expected in error for error in errors), (name, errors)


def _write(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


# --- check_corpus_counts ------------------------------------------------------
#
# This guard was rejected twice in review for missing claim shapes, and both
# times the fix was protected by nothing but the reviewer's memory of which
# shapes had failed. These pin them. Each case is written as the wrong number,
# in the exact shape a real document used, so a pattern that stops matching
# fails here rather than in the next release.


def _corpus_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: str,
    *,
    links: list[tuple[str, Path]] | None = None,
    raw: list[tuple[str, bytes]] | None = None,
) -> list[str]:
    """Run check_corpus_counts over a repository holding one document.

    `links` places symlinks (name -> target) and `raw` places byte-exact
    files: the two shapes a text-scanning gate must refuse to follow and
    refuse to skip silently.
    """
    vectors = tmp_path / "docs" / "spec" / "vectors"
    # Three leaves in two groups, and a v0.1 subset of one: small, and nothing
    # like the real numbers, so a pattern that happens to hardcode 158 or 52
    # cannot pass by accident.
    for group, leaf in (("01-a", "a"), ("01-a", "b"), ("26-b", "a")):
        (vectors / group / leaf).mkdir(parents=True, exist_ok=True)
        (vectors / group / leaf / "expected.json").write_text("{}", encoding="utf-8")
    (tmp_path / "doc.md").write_text(body, encoding="utf-8")
    for name, target in links or []:
        (tmp_path / name).symlink_to(target)
    for name, blob in raw or []:
        (tmp_path / name).write_bytes(blob)
    monkeypatch.setattr(check_spec_docs, "_REPO_ROOT", tmp_path)
    return check_spec_docs.check_corpus_counts()


def _git(repo: Path, *args: str) -> None:
    git = shutil.which("git")
    assert git is not None, "git is required to build the tracked-perimeter fixtures"
    subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        [git, "-C", str(repo), *args], check=True, capture_output=True
    )


def _tracked_corpus_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracked: dict[str, str],
    untracked: dict[str, str],
) -> list[str]:
    """Like _corpus_case, but inside a real git repository: `tracked`
    files are added to the index, `untracked` ones only sit on disk."""
    vectors = tmp_path / "docs" / "spec" / "vectors"
    for group, leaf in (("01-a", "a"), ("01-a", "b"), ("26-b", "a")):
        (vectors / group / leaf).mkdir(parents=True, exist_ok=True)
        (vectors / group / leaf / "expected.json").write_text("{}", encoding="utf-8")
    _git(tmp_path, "init", "--quiet")
    for name, content in {**tracked, **untracked}.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    for name in tracked:
        _git(tmp_path, "add", name)
    monkeypatch.setattr(check_spec_docs, "_REPO_ROOT", tmp_path)
    return check_spec_docs.check_corpus_counts()


def test_untracked_files_are_outside_the_perimeter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A draft that will never ship must not be able to redden the gate:
    # that asymmetry (red at home, green in CI) is how a gate gets ignored.
    errors = _tracked_corpus_case(
        tmp_path,
        monkeypatch,
        tracked={"doc.md": "nothing numeric here"},
        untracked={"draft.md": "The 130-leaf conformance corpus is the gate."},
    )
    assert errors == []


def test_tracked_files_are_scanned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    errors = _tracked_corpus_case(
        tmp_path,
        monkeypatch,
        tracked={"doc.md": "The 130-leaf conformance corpus is the gate."},
        untracked={},
    )
    assert errors != []


def test_a_tracked_file_missing_from_disk_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `git ls-files` lists the index, not the disk: a locally deleted file
    # must be skipped, never crash the gate. The first call only builds the
    # repository fixture; the assertion runs after the deletion.
    _tracked_corpus_case(
        tmp_path,
        monkeypatch,
        tracked={"doc.md": "nothing numeric here", "gone.md": "The 130-leaf corpus."},
        untracked={},
    )
    (tmp_path / "gone.md").unlink()
    errors = check_spec_docs.check_corpus_counts()
    assert errors == []


def test_perimeter_falls_back_outside_a_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No .git anywhere above tmp_path: the scan must degrade to the rglob
    # walk (this is also what keeps every _corpus_case fixture working).
    errors = _corpus_case(tmp_path, monkeypatch, "The 130-leaf conformance corpus is the gate.")
    assert errors != []


def test_a_symlink_in_the_perimeter_is_refused_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # is_file() resolves the target, so following a link would let text
    # from outside the repository pose as a project surface -- and a
    # dangling one would disappear without a word.
    outside = tmp_path.parent / "outside.md"
    outside.write_text("The 130-leaf conformance corpus is elsewhere.", encoding="utf-8")
    errors = _corpus_case(tmp_path, monkeypatch, "clean body.", links=[("link.md", outside)])
    assert any("symlink" in e for e in errors)


def test_a_file_that_is_not_utf8_is_reported_not_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Silently skipping an unreadable file leaves a surface the gate
    # believes it is defending and is not.
    errors = _corpus_case(
        tmp_path, monkeypatch, "clean body.", raw=[("odd.md", b"\xff\xfe not utf-8")]
    )
    assert any("UTF-8" in e for e in errors)


def test_perimeter_falls_back_when_root_is_inside_an_unrelated_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `git -C X ls-files` succeeds from anywhere inside a checkout and lists
    # only what is under X. A tree nested in a foreign repository would get an
    # empty perimeter and the gate would exit clean having scanned nothing --
    # the silent failure this whole task exists to prevent.
    outer = tmp_path / "outer"
    fixture = outer / "fixture"
    fixture.mkdir(parents=True)
    _git(outer, "init", "--quiet")

    errors = _corpus_case(fixture, monkeypatch, "The 130-leaf conformance corpus is the gate.")
    assert errors != []


def test_a_dangling_symlink_in_the_perimeter_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    errors = _corpus_case(
        tmp_path,
        monkeypatch,
        "clean body.",
        links=[("dangling.md", tmp_path / "missing.md")],
    )
    assert any("dangling.md: symlink" in e for e in errors)


def test_a_directory_symlink_in_the_perimeter_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path.parent / "outside-dir"
    target.mkdir(exist_ok=True)
    errors = _corpus_case(tmp_path, monkeypatch, "clean body.", links=[("linked.md", target)])
    assert any("linked.md: symlink" in e for e in errors)


def test_a_symlink_outside_the_scan_suffixes_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Suffix filtering runs before the symlink refusal, so a link the gate
    # would never read must not add noise to the report.
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("The 130-leaf conformance corpus is elsewhere.", encoding="utf-8")
    errors = _corpus_case(tmp_path, monkeypatch, "clean body.", links=[("link.txt", outside)])
    assert errors == []


def test_a_claim_wrapped_with_indentation_is_still_seen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Markdown wraps with a hanging indent: newline plus four spaces. The
    # length-preserving fold turned this into "51-leaf    subset", which no
    # pattern matches; whitespace runs must collapse to one space.
    body = "measured against the 51-leaf\n    subset of the corpus"
    assert _corpus_case(tmp_path, monkeypatch, body) != []


def test_line_numbers_survive_normalization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = "intro\n\nmore prose\n\nmeasured against the 51-leaf\n    subset of it\n"
    errors = _corpus_case(tmp_path, monkeypatch, body)
    assert any("doc.md:5:" in error for error in errors), errors


def test_normalization_strips_line_comment_markers_and_maps_offsets() -> None:
    text = "// gate (45 vector groups /\n//    212 leaves) discovers\n"
    norm, offsets = check_spec_docs._normalized_with_offsets(text, "//")
    assert "gate (45 vector groups / 212 leaves) discovers" in norm
    idx = norm.index("212")
    assert text[offsets[idx]] == "2"
    assert text.count("\n", 0, offsets[idx]) + 1 == 2  # "212" sits on line 2


def test_normalization_without_a_prefix_keeps_comment_markers() -> None:
    norm, _offsets = check_spec_docs._normalized_with_offsets("a\n// b\n", None)
    assert norm == "a // b"


def test_normalization_offset_map_invariants_for_degenerate_sequences() -> None:
    # Properties, not examples: the offset map is the part that can go wrong
    # in silence, and a collapsed space pointing at the character AFTER the
    # whitespace it came from reports the wrong line without failing anything.
    whitespace_runs = (" ", "\t", "\n", "\r\n", "\u00a0", "\u2028", "\u2029", " \n\t\u00a0")
    fragments = ("", "a", "//", " //", "tail")
    cases: list[tuple[str, str | None]] = [
        ("", None),
        ("   \t\n  ", None),
        ("//\nnext", "//"),
        ("//", "//"),
        ("a //\nb", "//"),
        ("a\n  b", None),
        ("\n\n  a", None),
    ]
    cases.extend(
        (f"{left}{whitespace}{right}", None)
        for left in fragments
        for whitespace in whitespace_runs
        for right in fragments
    )

    for text, prefix in cases:
        norm, offsets = check_spec_docs._normalized_with_offsets(text, prefix)
        assert len(norm) == len(offsets)
        assert all(0 <= offset < len(text) for offset in offsets)
        assert not norm.startswith(" ")
        assert not norm.endswith(" ")
        assert "  " not in norm
        for char, offset in zip(norm, offsets, strict=True):
            if char == " ":
                assert text[offset].isspace()
            else:
                assert text[offset] == char


def test_line_numbers_use_unicode_line_boundaries_seen_by_normalization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = "intro\u2028measured against the 51-leaf subset of it"
    errors = _corpus_case(tmp_path, monkeypatch, body)
    assert any("doc.md:2:" in error for error in errors), errors


def test_every_claim_shape_is_case_insensitive_by_construction() -> None:
    # The defect class this kills: 16 patterns compiled one by one, zero
    # with IGNORECASE. One compile point, flag applied there, no entry can
    # forget it.
    assert check_spec_docs._COMPILED_SHAPES
    for shape, regex in check_spec_docs._COMPILED_SHAPES:
        assert regex.flags & re.IGNORECASE, shape.name


@pytest.mark.parametrize(
    ("shapes", "expected"),
    [
        (
            (
                check_spec_docs._ClaimShape(
                    "dup", r"\b(\d+) leaf vectors\b", ((1, "corpus_total"),)
                ),
                check_spec_docs._ClaimShape("dup", r"\b(\d+) leaves\b", ((1, "corpus_total"),)),
            ),
            "duplicate claim-shape name",
        ),
        (
            (
                check_spec_docs._ClaimShape(
                    "bad-group", r"\b(\d+) leaf vectors\b", ((2, "corpus_total"),)
                ),
            ),
            "capture group 2 is outside 1..1",
        ),
        (
            (check_spec_docs._ClaimShape("bad-key", r"\b(\d+) leaf vectors\b", ((1, "missing"),)),),
            "unknown measured quantity 'missing'",
        ),
        (
            (check_spec_docs._ClaimShape("bad-regex", r"(", ((1, "corpus_total"),)),),
            "regex does not compile",
        ),
        (
            (
                check_spec_docs._ClaimShape(
                    "two-checks-ambiguous",
                    r"\b(\d+) of (\d+)\b",
                    ((1, "corpus_total"), (2, "group_count")),
                    when_unmarked="ambiguous",
                ),
            ),
            "ambiguous when_unmarked requires exactly one checked capture",
        ),
    ],
)
def test_claim_shape_registry_rejects_not_well_formed_entries(
    shapes: tuple[check_spec_docs._ClaimShape, ...], expected: str
) -> None:
    # Making the vocabulary data makes a malformed entry possible. The registry
    # names the bad entry at import instead of surfacing as an IndexError or a
    # KeyError halfway through scanning some unrelated file.
    with pytest.raises(ValueError, match=re.escape(expected)):
        check_spec_docs._compile_claim_shapes(shapes)


def test_overlapping_claim_shapes_do_not_duplicate_the_same_captured_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    errors = _corpus_case(tmp_path, monkeypatch, "130 leaf vectors across 2 groups")
    assert errors == ["doc.md:1: claims 130 corpus leaves, but the corpus holds 3"]


def test_a_bare_total_with_a_current_marker_is_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = "the corpus every implementation MUST meet comes to 9 total."
    errors = _corpus_case(tmp_path, monkeypatch, body)
    assert errors and "9" in errors[0]


def test_a_bare_total_with_a_historical_marker_is_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An explicitly dated figure is somebody's true history. Flagging it
    # would force rewriting the record at every corpus growth, and a gate
    # that does that gets switched off.
    assert _corpus_case(tmp_path, monkeypatch, "group 33 brought it to 9 total.") == []


def test_a_bare_total_with_no_marker_at_all_is_an_ambiguity_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The failure this gate exists to prevent is the SILENT one. Defaulting
    # an unmarked total to history would let "The corpus is 9 total." go
    # unchecked forever; the reader of the error only has to say which
    # tense they meant.
    errors = _corpus_case(tmp_path, monkeypatch, "The corpus is 9 total.")
    assert errors and "ambiguous" in errors[0].lower()


def test_the_verb_bring_alone_does_not_make_a_total_historical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # "bring" is a historical marker only in the shape "bring ... TO N total",
    # which is how the spec's own chain reads. Matching the bare verb would
    # let an ordinary sentence that happens to contain it slip back into the
    # silent-history bucket -- the very hole the tri-state closes.
    errors = _corpus_case(tmp_path, monkeypatch, "To bring clarity, the corpus is 9 total.")
    assert errors and "ambiguous" in errors[0].lower()


def test_an_ambiguous_shape_classifies_from_the_capture_it_declares(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The ambiguous branch used to read group 1 whatever the shape declared, so
    # a shape whose single check reads a later capture would have been
    # classified -- and reported -- from the wrong number.
    shape = check_spec_docs._ClaimShape(
        "second-capture",
        r"\bgroup (\d+) holds (\d+) total\b",
        ((2, "corpus_total"),),
        when_unmarked="ambiguous",
    )
    monkeypatch.setattr(
        check_spec_docs, "_COMPILED_SHAPES", check_spec_docs._compile_claim_shapes((shape,))
    )
    errors = _corpus_case(tmp_path, monkeypatch, "group 7 holds 9 total")
    assert errors and "ambiguous bare total '9'" in errors[0], errors


def test_bare_total_markers_do_not_cross_sentence_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A fixed character window does not know where a sentence ends, so a marker
    # in the neighbouring sentence classified the total next to it.
    errors = _corpus_case(
        tmp_path,
        monkeypatch,
        "Every implementation MUST meet the corpus. The corpus is 9 total.",
    )
    assert errors and "ambiguous bare total '9'" in errors[0]

    errors = _corpus_case(
        tmp_path, monkeypatch, "Group 33 brought it to 3 total. The corpus is 9 total."
    )
    assert errors == [
        "doc.md:1: ambiguous bare total '9' -- mark the sentence present-tense "
        "(it is then checked against the live count) or dated (it is then left alone)"
    ]


@pytest.mark.parametrize("separator", [":", ";", "?", "!"])
def test_bring_to_history_marker_must_bind_the_total(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, separator: str
) -> None:
    # "bring ... to" reaching any word at all was enough to date a present
    # claim: the marker has to reach the number it qualifies.
    errors = _corpus_case(
        tmp_path, monkeypatch, f"Bring clarity to reviewers{separator} the corpus is 9 total."
    )
    assert errors and "ambiguous bare total '9'" in errors[0]


def test_bare_total_marker_context_handles_document_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _corpus_case(tmp_path, monkeypatch, "Now 9 total.") != []
    errors = _corpus_case(tmp_path, monkeypatch, "The corpus is 9 total")
    assert errors and "ambiguous bare total '9'" in errors[0]


def test_a_current_marker_beats_a_historical_verb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The one current claim in the spec's own chain READS historical too
    # ("bring the full corpus ... MUST meet to N total"): history-marker
    # classification would silently drop the only number worth defending.
    body = "later groups bring the full corpus implementations MUST meet to 9 total."
    errors = _corpus_case(tmp_path, monkeypatch, body)
    assert errors and "9" in errors[0]


def test_the_spec_chain_shape_classifies_as_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A faithful miniature of docs/spec/attest-v0.2.md §16's chain: every
    # dated figure stays silent, the MUST-meet figure is compared (and
    # matches the fixture's live total of 3).
    body = (
        "the corpus stood at 78 total before this document's rev 5. "
        "Group 33's leaves brought the full corpus to 82 total. "
        "Groups 35 and 36 bring the corpus to 97 total. "
        "The last group brings the full corpus this document and its "
        "implementations MUST meet to 3 total."
    )
    assert _corpus_case(tmp_path, monkeypatch, body) == []


def test_the_spec_chain_current_figure_is_defended(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = (
        "The last group brings the full corpus this document and its "
        "implementations MUST meet to 130 total."
    )
    errors = _corpus_case(tmp_path, monkeypatch, body)
    assert errors and "130" in errors[0]


def test_case_variant_claims_are_caught(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = "All 130 Conformance Vector Leaves pass on every runner."
    assert _corpus_case(tmp_path, monkeypatch, body) != []


def test_leaves_across_groups_variant_is_defended(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # README.md's live shape ("now 212 leaves across 45 groups") matched
    # nothing: the registered form demanded "leaf vectors across".
    assert _corpus_case(tmp_path, monkeypatch, "now 130 leaves across 2 groups") != []
    assert _corpus_case(tmp_path, monkeypatch, "now 3 leaves across 9 groups") != []


def test_subset_of_them_variant_is_defended(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = "3 leaves across 2 groups: 9 of them the v0.1 corpus"
    assert _corpus_case(tmp_path, monkeypatch, body) != []
    good = "3 leaves across 2 groups: 2 of them the v0.1 corpus"
    assert _corpus_case(tmp_path, monkeypatch, good) == []


def test_the_dead_ts_readme_exemption_is_gone() -> None:
    # The exempt phrase left the file it excused (grep finds zero
    # occurrences), and no pattern ever matched it anyway. The mechanism
    # stays (path- and phrase-exact); the registry is empty.
    assert check_spec_docs._CORPUS_CLAIM_EXEMPTIONS == {}


def test_an_oversized_numeric_claim_is_reported_not_allowed_to_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    huge = "9" * 5000
    errors = _corpus_case(tmp_path, monkeypatch, f"The {huge}-leaf conformance corpus is the gate.")
    assert any("too many digits" in e for e in errors)


@pytest.mark.parametrize(
    "body",
    [
        # The shapes that shipped stale, verbatim in form.
        "The 130-leaf conformance corpus is the gate.",
        "reproduce all 130 of them",
        "`v0.2` (all leaves, currently 156)",
        # README.md's own sentence, which shipped stale while the sentence one
        # line below it was defended: both halves of a self-contradiction have
        # to be in the vocabulary, or the guard passes a file arguing with
        # itself.
        "the corpus now contains 130 leaves",
        "the corpus contains 130 leaves",
        "this corpus contains 130 leaves",
        "the corpus currently contains 130 leaves",
        "the corpus now contains all 130 leaves",
        "the full corpus contains 130 leaves",
        "130 leaf vectors across 2 groups",
        "measured against the 51-leaf subset",
        # Wrapped across a line break: the shape one version of the guard was
        # blind to, which is why the match runs on folded text.
        "measured against the 51-leaf\nsubset of the corpus",
    ],
)
def test_corpus_counts_rejects_a_stale_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> None:
    assert _corpus_case(tmp_path, monkeypatch, body) != []


@pytest.mark.parametrize(
    "body",
    [
        # A count scoped to something SMALLER than the corpus is not a claim
        # about the total, and reading it as one would report a true sentence
        # as stale — the failure mode a shape earns by matching on the noun
        # alone instead of on the phrase that owns it.
        "the v0.1 subset corpus contains 130 leaves",
        "group 32 corpus contains 130 leaves",
    ],
)
def test_a_scoped_count_is_not_read_as_the_corpus_total(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> None:
    assert _corpus_case(tmp_path, monkeypatch, body) == []


def test_corpus_counts_accepts_the_true_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Group 01 is below the v0.1 ceiling and holds two leaves; group 26 is not.
    body = "3 leaf vectors across 2 groups; a v0.1-only verifier meets the 2-leaf subset."
    assert _corpus_case(tmp_path, monkeypatch, body) == []


def test_corpus_counts_skips_a_changelog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A changelog records what the counts WERE, so its stale numbers are the
    # point rather than a defect.
    errors = _corpus_case(tmp_path, monkeypatch, "nothing here")
    assert errors == []
    (tmp_path / "CHANGELOG.md").write_text("The 130-leaf corpus grew.", encoding="utf-8")
    assert check_spec_docs.check_corpus_counts() == []


def test_corpus_exemptions_are_path_and_phrase_exact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The exemption excuses one sentence in one file, never a number wherever
    # it appears: the same figure in the same file, in a shape the guard does
    # match, is still reported.
    monkeypatch.setattr(
        check_spec_docs,
        "_CORPUS_CLAIM_EXEMPTIONS",
        {"doc.md": ("(130 leaves), the share routed to verify()",)},
    )
    body = (
        "**verify()** (130 leaves), the share routed to verify(). The 130-leaf corpus is the gate."
    )
    errors = _corpus_case(tmp_path, monkeypatch, body)
    assert len(errors) == 1
    assert "130" in errors[0]


# --- the wider perimeter: code comments, generated files, manifests -----------


def test_a_stale_claim_in_a_python_comment_is_caught(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    errors = _tracked_corpus_case(
        tmp_path,
        monkeypatch,
        tracked={"tests/test_x.py": "# checked over 130 leaves across 2 groups\n"},
        untracked={},
    )
    assert errors and "130" in errors[0]


def test_a_wrapped_quota_in_a_ts_comment_is_caught(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The live shape: the quota wraps onto a continuation comment line, so
    # the marker `//` sits INSIDE the phrase until normalization strips it.
    body = (
        "//  - `witness-quorum.json` (group 40, §11.4): evaluateActivationWitnessQuorum,\n"
        "//    9 leaves.\n"
    )
    errors = _tracked_corpus_case(
        tmp_path, monkeypatch, tracked={"test/conformance.test.ts": body}, untracked={}
    )
    assert errors and "9" in errors[0]


@pytest.mark.parametrize(
    "body",
    [
        "// The conformance merge gate (2 vector groups/9 leaves):\n",
        "//  - the default: verify(), for leaves with no special marker files (9 leaves).\n",
        "//  - `chain.json` (group 36, §17.5): auditChain with 9 leaves.\n",
        "//  - `witness-quorum.json` (group 40, §11.4): "
        "evaluateActivationWitnessQuorum with 9 leaves.\n",
        "//  - `redemption.json` (group 38, §18.7): verifyRedemption with 9 leaves.\n",
    ],
)
def test_surface_quota_claims_survive_reasonable_comment_rewrites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> None:
    # A quota anchored to the punctuation joining its words is a quota that
    # silently leaves the vocabulary the day somebody rephrases the sentence
    # around it. Each of these is the live comment, reworded innocuously.
    errors = _tracked_corpus_case(
        tmp_path,
        monkeypatch,
        tracked={"test/conformance.test.ts": body},
        untracked={},
    )
    assert errors and "9" in errors[0]


def test_the_gate_and_its_bench_do_not_scan_themselves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Both files carry claim-shaped strings ON PURPOSE (pattern docstrings,
    # bench fixtures); scanning them reports the fixtures as drift.
    # The suffix is forced on so the test is red for the RIGHT reason: without
    # it, it would pass before this task merely because .py is not scanned yet.
    monkeypatch.setattr(check_spec_docs, "_SCAN_SUFFIXES", (".md", ".py"))
    stale = "# reproduce all 130 of them\n"
    errors = _tracked_corpus_case(
        tmp_path,
        monkeypatch,
        tracked={
            "tools/check_spec_docs.py": stale,
            "tests/test_check_spec_docs.py": stale,
        },
        untracked={},
    )
    assert errors == []


def test_a_generated_tracked_file_is_excluded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Same reason as above: force the suffix so the exclusion is what is
    # under test, not the absence of .html from the perimeter.
    monkeypatch.setattr(check_spec_docs, "_SCAN_SUFFIXES", (".md", ".html"))
    errors = _tracked_corpus_case(
        tmp_path,
        monkeypatch,
        tracked={"site/public/what-is-this.html": "<p>the 130-leaf corpus</p>"},
        untracked={},
    )
    assert errors == []


def _surface_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    # One leaf per special surface plus two plain ones: chain=1, quorum=1,
    # redemption=1, verify=2, total=5.
    vectors = tmp_path / "docs" / "spec" / "vectors"
    layout = {
        ("36-chain", "a"): "chain.json",
        ("40-quorum", "a"): "witness-quorum.json",
        ("38-redemption", "a"): "redemption.json",
        ("01-plain", "a"): None,
        ("01-plain", "b"): None,
    }
    for (group, leaf), marker in layout.items():
        directory = vectors / group / leaf
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "expected.json").write_text("{}", encoding="utf-8")
        if marker is not None:
            (directory / marker).write_text("{}", encoding="utf-8")
    monkeypatch.setattr(check_spec_docs, "_REPO_ROOT", tmp_path)
    return check_spec_docs._measured_quantities()


def test_surface_quotas_are_measured_from_marker_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    quantities = _surface_case(tmp_path, monkeypatch)
    assert quantities["chain_surface"] == 1
    assert quantities["quorum_surface"] == 1
    assert quantities["redemption_surface"] == 1
    assert quantities["verify_surface"] == 2


def test_the_four_surfaces_partition_the_corpus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The quotas are only meaningful as a partition: every leaf belongs to
    # exactly one surface, so the four must add up to the corpus. A shape
    # that double-counted would still look plausible read one figure at a time.
    quantities = _surface_case(tmp_path, monkeypatch)
    assert (
        quantities["verify_surface"]
        + quantities["chain_surface"]
        + quantities["quorum_surface"]
        + quantities["redemption_surface"]
        == quantities["corpus_total"]
    )


def test_a_leaf_shipping_two_surface_markers_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Nothing in the tree GUARANTEES the partition the comments describe.
    # Assigning such a leaf to the first registered surface keeps the four
    # quotas adding up, so once somebody reconciles the stated quotas with
    # those counts the guard would bless a "partitioned" claim that is false
    # -- permanently, and without a word. It is refused instead.
    vectors = tmp_path / "docs" / "spec" / "vectors"
    both = vectors / "36-chain" / "a"
    both.mkdir(parents=True)
    for name in ("expected.json", "chain.json", "redemption.json"):
        (both / name).write_text("{}", encoding="utf-8")
    monkeypatch.setattr(check_spec_docs, "_REPO_ROOT", tmp_path)
    errors = check_spec_docs.check_corpus_counts()
    assert errors == [
        "36-chain/a: leaf ships multiple surface marker files: chain.json, redemption.json"
    ]


def test_a_quantity_the_registry_names_but_nothing_measures_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The registry validator pins that a shape only checks a quantity the
    # messages know. Nothing pinned the other half: a quantity that stops
    # being MEASURED used to surface as a KeyError partway through a scan.
    monkeypatch.setitem(check_spec_docs._CLAIM_MESSAGES, "phantom", lambda *_: "phantom")
    errors = _tracked_corpus_case(
        tmp_path,
        monkeypatch,
        tracked={"doc.md": "The 130-leaf conformance corpus is the gate."},
        untracked={},
    )
    assert errors == ["claim registry names quantities nothing measures: phantom"]


def _lockstep_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pyproject: str,
    package_json: str,
) -> list[str]:
    py = _write(tmp_path, "pyproject.toml", pyproject)
    ts = _write(tmp_path, "package.json", package_json)
    monkeypatch.setattr(check_spec_docs, "_PYPROJECT_PATH", py)
    monkeypatch.setattr(check_spec_docs, "_TS_PACKAGE_PATH", ts)
    return check_spec_docs.check_package_version_lockstep()


def test_matching_package_versions_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ok = _lockstep_case(
        tmp_path,
        monkeypatch,
        '[project]\nname = "x"\nversion = "1.2.3"\n',
        '{"name": "y", "version": "1.2.3"}',
    )
    assert ok == []


def test_diverging_package_versions_are_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    errors = _lockstep_case(
        tmp_path,
        monkeypatch,
        '[project]\nname = "x"\nversion = "1.2.3"\n',
        '{"name": "y", "version": "1.2.4"}',
    )
    assert errors and "1.2.3" in errors[0] and "1.2.4" in errors[0]


def test_lockstep_fails_closed_on_missing_or_broken_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No version key, and outright unparsable files: errors, never raises.
    assert _lockstep_case(tmp_path, monkeypatch, '[project]\nname = "x"\n', '{"name": "y"}') != []
    assert _lockstep_case(tmp_path, monkeypatch, "not toml ][", "not json {") != []


def test_lockstep_refuses_a_version_that_is_not_a_string(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A JSON number and a TOML array both survive parsing and then compare
    # unequal to anything: without a type check the report would read as a
    # version mismatch and send the reader to bump the wrong file.
    errors = _lockstep_case(
        tmp_path,
        monkeypatch,
        '[project]\nname = "x"\nversion = ["1.2.3"]\n',
        '{"name": "y", "version": 3}',
    )
    assert len(errors) == 2
    assert all("not a string" in error for error in errors)


def test_lockstep_refuses_two_empty_versions_rather_than_calling_them_equal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Blank compares equal to blank, so the one shape of disagreement this
    # check cannot see is two packages that agree on declaring nothing.
    errors = _lockstep_case(
        tmp_path,
        monkeypatch,
        '[project]\nname = "x"\nversion = ""\n',
        '{"name": "y", "version": "   "}',
    )
    assert len(errors) == 2
    assert all("version is empty" in error for error in errors)


def test_lockstep_reports_a_missing_manifest_rather_than_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(check_spec_docs, "_PYPROJECT_PATH", tmp_path / "absent.toml")
    monkeypatch.setattr(check_spec_docs, "_TS_PACKAGE_PATH", tmp_path / "absent.json")
    errors = check_spec_docs.check_package_version_lockstep()
    assert len(errors) == 2


def test_lockstep_refuses_duplicate_json_version_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # json.loads keeps the LAST duplicate, so a manifest naming `version`
    # twice would be read as one of the two and could be called in lockstep
    # while being malformed. (tomllib refuses a duplicate outright, so the
    # TOML side needs nothing.)
    errors = _lockstep_case(
        tmp_path,
        monkeypatch,
        '[project]\nname = "x"\nversion = "1.2.3"\n',
        '{"name": "y", "version": "1.2.3", "version": "1.2.4"}',
    )
    assert errors and "duplicate JSON object member 'version'" in errors[0]


def test_lockstep_refuses_a_duplicate_key_in_the_toml_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The symmetric case, pinned rather than assumed: it is tomllib doing the
    # refusing, and a parser swap must not quietly take that away.
    errors = _lockstep_case(
        tmp_path,
        monkeypatch,
        '[project]\nname = "x"\nversion = "1.2.3"\nversion = "1.2.4"\n',
        '{"name": "y", "version": "1.2.3"}',
    )
    assert errors and "cannot read a version to compare" in errors[0]


# --- coined terms on positioning surfaces -------------------------------------


def _coined_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, files: dict[str, str]
) -> list[str]:
    defining = (
        "## 3. Eternal verifiability\n\nNo amendment may render unverifiable an "
        "artifact that was conforming when issued. Deprecation degrades the "
        "result classification, never the ability to verify the bytes.\n"
    )
    contents = {"docs/spec/attest-versioning.md": defining, **files}
    for name, content in contents.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(check_spec_docs, "_REPO_ROOT", tmp_path)
    return check_spec_docs.check_coined_terms()


def test_a_bare_coined_term_on_a_positioning_surface_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    errors = _coined_case(
        tmp_path, monkeypatch, {"README.md": "We offer the eternal-verifiability guarantee.\n"}
    )
    assert errors and "README.md:1" in errors[0]


def test_a_glossed_coined_term_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = (
        "We offer the eternal-verifiability guarantee (deprecation degrades the "
        "result classification, never the ability to verify the bytes).\n"
    )
    assert _coined_case(tmp_path, monkeypatch, {"README.md": body}) == []


def test_the_gloss_must_share_the_paragraph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A gloss two paragraphs away does not disambiguate the sentence a
    # reader actually lands on.
    body = (
        "We offer the eternal-verifiability guarantee.\n\n"
        "Elsewhere: never the ability to verify the bytes.\n"
    )
    assert _coined_case(tmp_path, monkeypatch, {"README.md": body}) != []


@pytest.mark.parametrize("separator", ["\r\n\r\n", "\n   \n", "\n\n\n", "\n\t\n"])
def test_paragraph_break_variants_keep_the_gloss_scoped_to_its_own_paragraph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, separator: str
) -> None:
    # A blank line written with CRLF, or carrying spaces, is still a blank
    # line to every reader and every renderer. Splitting on the literal
    # "\n\n" alone merges the two blocks, and the gloss below then answers
    # for the term above -- silently, which is the direction that matters.
    body = (
        "We offer the eternal-verifiability guarantee."
        f"{separator}"
        "Elsewhere: never the ability to verify the bytes.\n"
    )
    assert _coined_case(tmp_path, monkeypatch, {"README.md": body}) != []


def test_coined_term_line_numbers_use_unicode_line_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Normalization already treats U+2028 as a line end, so a report that
    # counted only "\n" would name a line the reader cannot find.
    errors = _coined_case(
        tmp_path, monkeypatch, {"README.md": "intro\u2028the eternal-verifiability guarantee\n"}
    )
    assert errors and "README.md:2" in errors[0]


def test_a_coined_term_on_a_structured_surface_is_refused_outright(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A package manifest has no paragraph to gloss in: the whole file is one
    # block, so "the gloss must share the paragraph" degrades to "somewhere
    # in this file", which is exactly the silent pass this guard exists to
    # refuse. Where no unit of reading is defined, the term is not allowed.
    errors = _coined_case(
        tmp_path,
        monkeypatch,
        {"verifiers/ts/package.json": '{"description": "eternal verifiability, guaranteed"}\n'},
    )
    assert errors and "verifiers/ts/package.json" in errors[0]
    assert "cannot be glossed" in errors[0]


def test_a_structured_surface_that_does_not_name_the_term_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = {"verifiers/ts/package.json": '{"description": "an offline receipt verifier"}\n'}
    assert _coined_case(tmp_path, monkeypatch, files) == []


def test_a_gloss_does_not_rescue_a_structured_surface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The point of the term-free rule: writing the gloss elsewhere in the
    # file must NOT buy the term its way in, or the rule is the file-wide
    # one it replaced.
    body = (
        '{"description": "eternal verifiability, guaranteed",\n'
        ' "longDescription": "never the ability to verify the bytes"}\n'
    )
    errors = _coined_case(tmp_path, monkeypatch, {"verifiers/ts/package.json": body})
    assert errors != []


def test_case_variants_of_the_term_are_caught(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    errors = _coined_case(
        tmp_path, monkeypatch, {"README.md": "Eternal Verifiability, guaranteed.\n"}
    )
    assert errors != []


def test_the_term_outside_positioning_surfaces_is_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = {
        "CONTRIBUTING.md": "eternal verifiability is discussed in the spec.\n",
        "README.md": "no coined terms here.\n",
    }
    assert _coined_case(tmp_path, monkeypatch, files) == []


def test_a_missing_positioning_surface_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Surfaces may legitimately disappear (a renamed FAQ); the defining
    # document may not — without it the registry is stale.
    assert _coined_case(tmp_path, monkeypatch, {}) == []


def test_a_defining_document_that_lost_the_term_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = {"docs/spec/attest-versioning.md": "## 3. Something else entirely\n"}
    errors = _coined_case(tmp_path, monkeypatch, files)
    assert errors and "attest-versioning" in errors[0]


def test_a_missing_defining_document_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Distinct from the case above and just as fail-closed: a registry that
    # points at a document nobody ships defends nothing, and a check that
    # skipped it would go green having verified no definition exists.
    monkeypatch.setattr(check_spec_docs, "_REPO_ROOT", tmp_path)
    errors = check_spec_docs.check_coined_terms()
    assert errors and "attest-versioning" in errors[0]


def test_the_line_reported_is_the_paragraph_that_names_the_term(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A report pointing at the top of the file sends the reader hunting; the
    # offset has to survive the paragraph split and the normalization.
    body = "filler\n\nmore filler\n\nthe eternal-verifiability guarantee, unglossed.\n"
    errors = _coined_case(tmp_path, monkeypatch, {"README.md": body})
    assert errors and "README.md:5" in errors[0]


def test_a_positioning_surface_that_is_not_utf8_is_reported_not_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Same reflex as the drift scan: a surface the check cannot read is a
    # surface it is not defending, and silence would look identical to clean.
    _coined_case(tmp_path, monkeypatch, {"README.md": "clean\n"})
    (tmp_path / "README.md").write_bytes(b"\xff\xfe eternal verifiability")
    errors = check_spec_docs.check_coined_terms()
    assert errors and "UTF-8" in errors[0]


def test_every_coined_term_is_case_insensitive_by_construction() -> None:
    # The sixteen claim shapes lost a year of coverage to a missing flag
    # applied entry by entry; the coined-term registry compiles in one place
    # so the same defect cannot come back through a new door.
    for pattern in check_spec_docs._COMPILED_COINED_TERMS.values():
        assert pattern.term.flags & re.IGNORECASE
        assert pattern.gloss.flags & re.IGNORECASE


def _term(
    name: str,
    pattern: object = r"x",
    *,
    glossable: object = ("README.md",),
    term_free: object = (),
    defined_in: object = "d.md",
) -> check_spec_docs._CoinedTerm:
    return check_spec_docs._CoinedTerm(
        name,
        pattern,  # type: ignore[arg-type]
        defined_in,  # type: ignore[arg-type]
        r"g",
        glossable,  # type: ignore[arg-type]
        term_free,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    ("terms", "expected"),
    [
        ((_term("dup"), _term("dup")), "duplicate coined-term name"),
        ((_term("bad-regex", "("),), "regex"),
        ((_term("no-surfaces", glossable=()),), "no surfaces"),
        # A bytes pattern COMPILES, and only fails later against str: the
        # registry validator exists to make that failure happen at import.
        ((_term("bad-type", b"x"),), "pattern must be a string"),
        ((_term("bad-surface", glossable=("README.md", "")),), "must be non-empty strings"),
        ((_term("bad-defined-in", defined_in=""),), "defined_in"),
        ((_term(""),), "name must be a non-empty string"),
    ],
)
def test_coined_term_registry_rejects_not_well_formed_entries(
    terms: tuple[check_spec_docs._CoinedTerm, ...], expected: str
) -> None:
    with pytest.raises(ValueError, match=re.escape(expected)):
        check_spec_docs._compile_coined_terms(terms)


def test_a_bytes_gloss_pattern_is_refused_at_import_too() -> None:
    # The term pattern had its check; the gloss pattern is the same hazard by
    # the same route, and a registry that closed one door is not closed.
    term = check_spec_docs._CoinedTerm("g", r"x", "d.md", b"g", ("README.md",), ())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="gloss pattern must be a string"):
        check_spec_docs._compile_coined_terms((term,))


def test_line_number_for_an_offset_past_the_end_names_the_last_line() -> None:
    # Unreachable from today's callers, and pinned anyway: the fallback used
    # to be line 1, which sends a reader to the top of a file to look for
    # something at its bottom.
    assert check_spec_docs._line_number_for_offset("a\nb\nc", 5) == 3
    assert check_spec_docs._line_number_for_offset("", 0) == 1


def test_a_surface_may_not_be_listed_as_both_glossable_and_term_free() -> None:
    # The two rules contradict each other on the same file, and a registry
    # that let both stand would apply whichever the loop reached first.
    with pytest.raises(ValueError, match="both glossable and term-free"):
        check_spec_docs._compile_coined_terms(
            (_term("both", glossable=("README.md",), term_free=("README.md",)),)
        )
