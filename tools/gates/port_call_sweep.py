"""Every call to a trust-material port under `tools/` hands over a SNAPSHOT.

WHY THIS EXISTS, AND WHY A GREP WOULD NOT DO

The ports take parsed trust material. A caller that hands one a plain tree is
told `False` — a genuine manifest declared inauthentic, in silence. Inside the
library the type checker catches it; in `tools/` it does not, because these are
generators and adapters that build documents and pass them straight in.

Measured, and it is why this is a gate: rebasing onto a commit that added a
conformance leaf brought six such calls into `gen_vectors.py`, written against
the pre-flip API. No test executes that file, so the suite was green. The defect
would have surfaced at the next corpus regeneration, as an assertion failure
nobody was expecting, in a file nobody had touched.

Three properties a line-based search cannot have, all three measured on this
tree rather than imagined:

  1. A call the formatter WRAPPED spans lines, so `[^)]*` never reaches its
     arguments. Two such calls in `gen_vectors.py` were reported as suspicious
     by the line-based form while being perfectly migrated.
  2. Prose in docstrings and comments matches a search for `port(`. Two more.
  3. The trust material is NOT always the first argument — `verify_record(record,
     manifest)` carries it second. A probe that looked at the first argument
     reported 33 false positives, which is the probe measuring itself.

So the sweep reads the syntax tree and asks one question per call: does ANY
argument arrive through an ADMISSION -- a name that, in that same file, is
annotated as returning a parsed handle, or the library constructor called
inline? The admissions are derived per file, because the tools do not share one.

THE DECLARED EXCEPTION, AND WHY IT IS BY NAME

`transfer.verify_authorization(record, "<b64u pubkey>")` shares its name with
`authority.verify_authorization(document, key_manifest)`, and only the latter
takes trust material. The name is the trap, so the exception is pinned by owner
AND name, with its reason, and the gate FAILS if it stops matching anything:
an exemption that outlives its cause is how an exception list becomes a
blindfold.

OWNER RESOLUTION, AND WHY IT IS NOT JUST A NAME

A call is only recognised if it has the shape `<owner-name>.<port-name>(...)`,
which two review probes broke without touching a single port call: importing
an owner under an alias (`from attest import manifests as manifests_mod`,
the exact pattern `src/attest/verify.py` already uses for `grant`/`authority`
to dodge a local-name collision), and importing a port function directly
(`from attest.manifests import verify_key_manifest`). Both make the call a
different AST shape -- an Attribute whose value is not a bare OWNERS name, or
a bare Name call -- and both were, before this fix, not merely misjudged: the
call was never counted, so the total did not move and nothing said a call had
gone unseen. `_owner_aliases` and `_direct_port_imports` resolve both back to
`(owner, port)` before the shape check runs.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

TREE = Path(__file__).resolve().parents[2]

#: The two handle types. An admission is anything that produces one of these.
HANDLES = ("KeyManifest", "TrustStore")

#: (owner, name) -> why this call does not take trust material at all.
DECLARED_EXCEPTIONS: dict[tuple[str, str], str] = {
    ("transfer", "verify_authorization"): (
        "second argument is a b64u PUBLIC KEY string, not trust material; shares its "
        "name with authority.verify_authorization, which does take a manifest"
    ),
}


def port_names() -> set[str]:
    """The ports, from the plugin that already owns that list.

    One source, not two: `substituted_ports_plugin.PORT_NAMES` is what G-SUBST
    derives its own population from, and a second copy here would drift the
    first time a port is added.
    """
    sys.path.insert(0, str(TREE / "tools" / "gates"))
    from substituted_ports_plugin import PORT_NAMES

    return {name.lstrip("_") for name in PORT_NAMES}


OWNERS = ("manifests", "revocation", "transfer", "grant", "authority", "views")


def _owner_aliases(tree: ast.Module) -> dict[str, str]:
    """Local names, in THIS file, that stand in for one of OWNERS.

    See the module docstring: this is not a hypothetical shape, it is the one
    `src/attest/verify.py` already uses for `grant`/`authority`/`transparency`.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "attest":
            for alias in node.names:
                if alias.name in OWNERS and alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.Import):
            for alias in node.names:
                owner = alias.name.rsplit(".", 1)[-1]
                if owner in OWNERS and alias.asname:
                    aliases[alias.asname] = owner
    return aliases


def _direct_port_imports(tree: ast.Module, ports: set[str]) -> dict[str, tuple[str, str]]:
    """Local names, in THIS file, bound directly to a port function.

    `from attest.manifests import verify_key_manifest` makes the call a bare
    Name, never an Attribute access -- invisible to the owner-based shape
    check unless resolved back to (owner, port) here.
    """
    mapping: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.module is None:
            continue
        parts = node.module.split(".")
        if parts[0] != "attest" or len(parts) < 2:
            continue
        owner = parts[-1]
        if owner not in OWNERS:
            continue
        for alias in node.names:
            if alias.name in ports:
                mapping[alias.asname or alias.name] = (owner, alias.name)
    return mapping


def _is_handle_annotation(node: ast.expr) -> bool:
    """True iff this annotation names EXACTLY one handle type -- not a
    container, not a union, not a tuple that merely mentions one.
    `KeyManifest` and `trust_material.KeyManifest` both count;
    `tuple[KeyManifest, bytes]`, `KeyManifest | None` and
    `Optional[KeyManifest]` do not, because a caller receiving any of those
    does not receive a handle by construction. Replaces a substring match
    against the unparsed annotation text, which admitted the tuple case:
    measured, a helper annotated `-> tuple[KeyManifest, bytes]` let a call
    that handed a port the two-tuple itself pass as if it had handed over the
    manifest.
    """
    if isinstance(node, ast.Name):
        return node.id in HANDLES
    if isinstance(node, ast.Attribute):
        return node.attr in HANDLES
    return False


def _admissions(tree: ast.Module) -> set[str]:
    """The names, in THIS file, that produce a parsed handle.

    Derived from the return annotations rather than named: measured, the tools
    do not share one admission helper. `gen_vectors.py` canonicalizes a dict it
    just built (`_snapshot`); `conformance_adapter_py.py` reads bytes off disk
    (`_sole_key_manifest`, `_trust_store`). A sweep that knew only the first
    reported the second as a defect on its first run — the probe answering
    about its own shape instead of about the file, which is the very family this
    gate exists to catch.
    """
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.returns is None:
            continue
        if _is_handle_annotation(node.returns):
            found.add(node.name)
    return found


def _reaches_admission(node: ast.AST, admissions: set[str]) -> bool:
    for inner in ast.walk(node):
        if not isinstance(inner, ast.Call):
            continue
        func = inner.func
        # a local helper that returns a handle ...
        if isinstance(func, ast.Name) and func.id in admissions:
            return True
        # ... or the library constructor itself, called inline.
        if isinstance(func, ast.Attribute) and func.attr == "from_bytes":
            return True
    return False


def sweep(path: Path, ports: set[str]) -> tuple[int, list[str], set[tuple[str, str]]]:
    """Returns (call sites seen, offending descriptions, exceptions exercised)."""
    tree = ast.parse(path.read_text(), filename=str(path))
    admissions = _admissions(tree)
    owner_aliases = _owner_aliases(tree)
    direct_ports = _direct_port_imports(tree, ports)
    seen = 0
    offending: list[str] = []
    exercised: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        key: tuple[str, str] | None = None
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.attr in ports
        ):
            owner = owner_aliases.get(func.value.id, func.value.id)
            if owner in OWNERS:
                key = (owner, func.attr)
        elif isinstance(func, ast.Name) and func.id in direct_ports:
            key = direct_ports[func.id]
        if key is None:
            continue
        seen += 1
        if key in DECLARED_EXCEPTIONS:
            exercised.add(key)
            continue
        if not any(_reaches_admission(arg, admissions) for arg in node.args):
            rel = path.relative_to(TREE)
            offending.append(
                f"{rel}:{node.lineno}: {key[0]}.{key[1]}(...) — no argument arrives "
                f"through an admission (this file has: {sorted(admissions) or None})"
            )
    return seen, offending, exercised


def targets() -> list[Path]:
    """Derived from the filesystem, never listed: a tool added tomorrow is in
    scope the day it lands, which a written list cannot promise."""
    return sorted(p for p in (TREE / "tools").glob("*.py") if p.is_file())


def main() -> int:
    ports = port_names()
    total = 0
    offending: list[str] = []
    exercised: set[tuple[str, str]] = set()
    files_with_calls = 0
    for path in targets():
        seen, bad, used = sweep(path, ports)
        if seen:
            files_with_calls += 1
            print(f"  {path.relative_to(TREE)}: {seen} port call site(s)")
        total += seen
        offending += bad
        exercised |= used

    print(f"ports watched: {len(ports)} (derived from substituted_ports_plugin.PORT_NAMES)")
    print(f"port call sites under tools/: {total} across {files_with_calls} file(s)")

    if total == 0:
        print("FAIL: no port call site found at all — an empty sweep proves nothing")
        return 1

    unused = set(DECLARED_EXCEPTIONS) - exercised
    for owner, name in sorted(unused):
        print(f"FAIL: declared exception {owner}.{name} matched nothing; delete it")
    for line in offending:
        print(f"FAIL: {line}")

    for owner, name in sorted(exercised):
        print(f"  exception exercised: {owner}.{name} — {DECLARED_EXCEPTIONS[owner, name]}")

    if offending or unused:
        return 1
    print("every port call under tools/ admits its trust material through a parsed handle")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
