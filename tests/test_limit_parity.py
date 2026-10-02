"""Every hostile-input ceiling both cores enforce must have the same value in both.

The two verifiers ship separately, so each states its own copy of every limit
(envelope bytes, manifest keys, proof lengths, claim counts, note sizes...). A
copy that drifts makes one core accept what the other refuses, and nothing
fails: each core's own tests pin the value it believes. This test reads the
TypeScript sources as data -- no build, no node -- resolves each `const` to an
integer, and compares it with the Python attribute that is its twin.

Adding a ceiling to one core without adding it to `PAIRS` is not caught here;
`test_every_exported_ts_ceiling_is_paired` closes that for the exported ones.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

TS_SRC = Path(__file__).resolve().parents[1] / "verifiers" / "ts" / "src"

_CONST_RE = re.compile(
    r"^(?P<export>export )?const (?P<name>[A-Z][A-Z0-9_]*)\s*(?::[^=\n]+)?=\s*(?P<expr>[^\n]+)$",
    re.MULTILINE,
)
_IDENT_RE = re.compile(r"\b[A-Z][A-Z0-9_]*\b")
_SAFE_EXPR_RE = re.compile(r"^[0-9n_\s()+\-*]+$")


def _ts_consts() -> tuple[dict[tuple[str, str], str], dict[str, str]]:
    local: dict[tuple[str, str], str] = {}
    exported: dict[str, str] = {}
    for path in sorted(TS_SRC.glob("*.ts")):
        for m in _CONST_RE.finditer(path.read_text(encoding="utf-8")):
            expr = m.group("expr").split("//", 1)[0].strip().rstrip(";")
            local[(path.stem, m.group("name"))] = expr
            if m.group("export"):
                exported[m.group("name")] = path.stem
    return local, exported


_LOCAL, _EXPORTED = _ts_consts()


def ts_value(module: str, name: str, _depth: int = 0) -> int:
    """Resolve TS `module.name` to an int, following same-file then exported names."""
    assert _depth < 16, f"cycle resolving {module}.{name}"
    key = (module, name)
    if key not in _LOCAL:
        assert name in _EXPORTED, f"{name} is not a top-level const in {module}.ts"
        key = (_EXPORTED[name], name)
    expr = _LOCAL[key]

    def sub(m: re.Match[str]) -> str:
        return str(ts_value(key[0], m.group(0), _depth + 1))

    resolved = _IDENT_RE.sub(sub, expr)
    resolved = re.sub(r"(?<=\d)n\b", "", resolved).replace("_", "")
    assert _SAFE_EXPR_RE.match(resolved), f"{key}: not an integer expression: {expr!r}"
    value = eval(resolved, {"__builtins__": {}}, {})  # noqa: S307 -- digits/operators only
    assert isinstance(value, int)
    return value


# (ts module, ts const) -> (python module, python attribute)
PAIRS: list[tuple[str, str, str, str]] = [
    ("canon", "MAX_DEPTH", "canon", "MAX_DEPTH"),
    ("canon", "MAX_ADMISSION_BYTES", "canon", "MAX_ADMISSION_BYTES"),
    ("canon", "MAX_ADMISSION_NODES", "canon", "MAX_ADMISSION_NODES"),
    ("schema", "MAX_ENVELOPE_BYTES", "validate", "MAX_ENVELOPE_BYTES"),
    ("schema", "MAX_JSON_DEPTH", "validate", "MAX_JSON_DEPTH"),
    ("manifests", "MAX_MANIFEST_KEYS", "manifests", "MAX_MANIFEST_KEYS"),
    ("manifests", "MAX_ARTIFACT_ENTRIES", "manifests", "MAX_ARTIFACT_ENTRIES"),
    ("revocation", "MAX_REVOCATION_RECORDS", "revocation", "MAX_REVOCATION_RECORDS"),
    ("revocation", "MAX_REVOCATION_EVIDENCE_LEN", "verify", "_MAX_TRANSPARENCY_EVIDENCE_LEN"),
    ("verify", "MAX_TRANSPARENCY_EVIDENCE_LEN", "verify", "_MAX_TRANSPARENCY_EVIDENCE_LEN"),
    ("verify", "MAX_COMPROMISE_CLAIMS", "verify", "_MAX_COMPROMISE_CLAIMS"),
    ("transfer", "MAX_TRANSFER_CLAIMS", "transfer", "MAX_TRANSFER_CLAIMS"),
    ("transfer", "MAX_TRANSFER_EVIDENCE_LEN", "transfer", "_MAX_TRANSFER_EVIDENCE_LEN"),
    ("transparency", "MAX_PROOF_LEN", "transparency", "_MAX_PROOF_LEN"),
    ("anchor", "MAX_PROOFS_PER_EVIDENCE", "anchor", "_MAX_PROOFS_PER_EVIDENCE"),
    ("anchor", "MAX_OPS_PER_PROOF", "anchor", "_MAX_OPS_PER_PROOF"),
    ("anchor", "MAX_OP_HEX_LEN", "anchor", "_MAX_OP_HEX_LEN"),
    ("anchor", "MAX_TOTAL_OP_HEX_LEN", "anchor", "_MAX_TOTAL_OP_HEX_LEN"),
    ("anchor", "MAX_CHECKPOINT_TEXT_LEN", "anchor", "_MAX_CHECKPOINT_TEXT_LEN"),
    ("tlog", "MAX_NOTE_SIGNATURES", "tlog", "_MAX_NOTE_SIGNATURES"),
    ("tlog", "MAX_NOTE_LINES", "tlog", "_MAX_NOTE_LINES"),
    ("tlog", "MAX_NOTE_TEXT_LEN", "tlog", "_MAX_NOTE_TEXT_LEN"),
    ("tlog", "MAX_SIG_B64_LEN", "tlog", "_MAX_SIG_B64_LEN"),
    ("tlog", "MAX_ROOT_B64_LEN", "tlog", "_MAX_ROOT_B64_LEN"),
    ("tlog", "MAX_ENTRY_SCALAR_LEN", "tlog", "_MAX_ENTRY_SCALAR_LEN"),
    ("tlog", "MAX_TREE_SIZE", "tlog", "_MAX_TREE_SIZE"),
    ("tlog", "MAX_TREE_SIZE_DIGITS", "tlog", "_MAX_TREE_SIZE_DIGITS"),
    ("tlog", "MAX_JCS_INTEGER", "tlog", "_MAX_JCS_INTEGER"),
    ("grant", "MAX_JCS_INTEGER", "grant", "_MAX_JCS_INTEGER"),
    ("grant", "MAX_GRANT_DECLARATIONS", "grant", "_MAX_GRANT_DECLARATIONS"),
    ("grant", "MAX_GRANT_LATER_VERSIONS", "grant", "_MAX_GRANT_LATER_VERSIONS"),
    ("authority", "MAX_AUTHORITY_DOCUMENTS", "authority", "MAX_AUTHORITY_DOCUMENTS"),
    ("authority", "MAX_AUTHORIZED_ISSUERS", "authority", "MAX_AUTHORIZED_ISSUERS"),
    ("witness", "MAX_WITNESS_SKEW_SECONDS", "witness", "MAX_WITNESS_SKEW_SECONDS"),
    ("witness", "MAX_WITNESS_ANCHOR_DELAY_SECONDS", "witness", "MAX_WITNESS_ANCHOR_DELAY_SECONDS"),
    (
        "witness",
        "MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE",
        "witness",
        "MAX_ACTIVATION_WITNESS_COMMITTEE_SIZE",
    ),
    ("witness", "MAX_COSIGNATURE_TIMESTAMP", "witness", "MAX_COSIGNATURE_TIMESTAMP"),
    ("dates", "MAX_REPRESENTABLE_UNIX_SECONDS", "dates", "MAX_REPRESENTABLE_UNIX_SECONDS"),
]


@pytest.mark.parametrize(
    ("ts_mod", "ts_name", "py_mod", "py_name"),
    PAIRS,
    ids=[f"{t}.{n}" for t, n, _, _ in PAIRS],
)
def test_ceiling_matches_across_cores(ts_mod: str, ts_name: str, py_mod: str, py_name: str) -> None:
    py_value = getattr(importlib.import_module(f"attest.{py_mod}"), py_name)
    assert ts_value(ts_mod, ts_name) == py_value, (
        f"verifiers/ts/src/{ts_mod}.ts {ts_name} != attest.{py_mod}.{py_name}"
    )


def test_every_exported_ts_ceiling_is_paired() -> None:
    paired = {name for _, name, _, _ in PAIRS}
    # A trailing underscore marks a test-only alias of a module-local ceiling
    # (e.g. tlog.ts `MAX_NOTE_TEXT_LEN_`); the module-local original is what is paired.
    unpaired = sorted(
        n for n in _EXPORTED if n.startswith("MAX_") and not n.endswith("_") and n not in paired
    )
    assert unpaired == [], f"exported TS ceilings with no Python twin in PAIRS: {unpaired}"


# --- Fixed message vocabularies -------------------------------------------------

_MESSAGE_OBJECT_RE = re.compile(r"^export const ([A-Z_]+) = \{(.*?)^\}", re.MULTILINE | re.DOTALL)
_MESSAGE_VALUE_RE = re.compile(r":\s*'((?:[^'\\]|\\.)*)'")

# TS value -> why it is allowed to differ from every Python literal.
KNOWN_MESSAGE_DIVERGENCES: dict[str, str] = {
    # canon.py appends the offending Python type name (f"...: {type(obj).__name__}");
    # the TS serializer has no equivalent type name to report. Serializer-side only.
    "type not representable in JSON": "canon.py appends ': <type>'",
}


def _python_string_literals() -> set[str]:
    import ast

    out: set[str] = set()
    for path in (TS_SRC.parents[2] / "src" / "attest").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                out.add(node.value)
    return out


def _ts_fixed_messages() -> list[tuple[str, str]]:
    text = (TS_SRC / "messages.ts").read_text(encoding="utf-8")
    found: list[tuple[str, str]] = []
    for obj in _MESSAGE_OBJECT_RE.finditer(text):
        for value in _MESSAGE_VALUE_RE.findall(obj.group(2)):
            found.append((obj.group(1), value.replace("\\'", "'").replace("\\\\", "\\")))
    return found


def test_fixed_ts_messages_exist_verbatim_in_python() -> None:
    """Every value of messages.ts's ERR / *WARN objects is a Python literal too.

    Implicit concatenation is joined by the parser, so a Python message split
    over several source lines still compares as one string.
    """
    messages = _ts_fixed_messages()
    assert len(messages) > 50, "messages.ts parse found too few values"
    literals = _python_string_literals()

    def composed(value: str) -> bool:
        # anchor.py builds one warning as `message += " — ..."`: two literals.
        return any(value.startswith(head) and value[len(head) :] in literals for head in literals)

    missing = [
        (group, value)
        for group, value in messages
        if value not in literals and value not in KNOWN_MESSAGE_DIVERGENCES and not composed(value)
    ]
    assert missing == [], f"messages.ts values with no byte-identical Python literal: {missing}"
