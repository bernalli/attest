#!/usr/bin/env bash
# predicted-red-set.sh — derives, from the CONTENT of the test files, the set
# of tests that plan T2 ("Flip Python: porte chiuse...", docs/plans/
# 2026-09-08-trust-material-serialized-entry.md) predicts will turn red the
# moment the trust-material doors close — i.e. the moment Python ports stop
# accepting a raw `dict` as a trust store / key manifest and start requiring
# the parsed `TrustStore`/`KeyManifest` handles from `trust_material.py`.
#
# This REPLACES a hand-written list of file names. A list like that ages the
# moment another front merges a new test file, and nobody can check it
# without re-deriving it by hand anyway — so it is derived here, every time,
# from THREE structural properties that are true of a test file TODAY
# (before the T2 flip) if and only if the flip turns it red. Two are direct
# (a file's own text); the third is transitive (a file inherits the breakage
# of a shared fixture it did not write). Investigating this derivation
# against the plan's hand-written 42-file list (docs/plans/2026-09-08-trust-
# material-serialized-entry.md, T2, "Previsione del rosso PRIMA del flip")
# found that the hand list MISSES four files for exactly this transitive
# reason — see Criterion C below and the worktree report for the evidence
# (a plan quote proving the construction raises, plus targeted pytest runs
# proving the four files pass today). This script reports what it derives,
# not what the plan happens to say; a residual either direction is reported
# by this script's own presence in the diff, not silently absorbed.
#
# Scope mirrors the census command T2 itself uses ("Previsione del rosso
# PRIMA del flip"): tests/*.py at the top level only (no subdirectories),
# plus tests/tools, bridge/tests and witness/tests as whole directories.
#
# ---------------------------------------------------------------------------
# CRITERION A — owns trust material built the OLD way
# ---------------------------------------------------------------------------
#   - `TrustStore(`        constructs the pre-T2 dataclass directly (e.g.
#                           `verify_mod.TrustStore(manifests=..., provenance=...)`).
#                           After T2, `verify.TrustStore` is re-aliased to
#                           `trust_material.TrustStore`, whose `__init__`
#                           takes a private admission token positionally
#                           (§5.1.2) — the OLD keyword call fails at argument
#                           BINDING, before the constructor body ever runs
#                           (plan, §5.1.2: "verify.TrustStore(manifests=...)
#                           solleva TypeError" — "TrustStore.__init__() got
#                           an unexpected keyword argument 'manifests'").
#   - `_trust_store(` / `_store(`
#                           calls a LOCAL per-file helper (the plan counts 20
#                           of these) whose own body does the same direct
#                           construction on the caller's behalf. Matched with
#                           a leading underscore specifically so this does
#                           NOT match an unrelated method call (`tx.store(`,
#                           `self._inner.store(`) or a `def store(...)`
#                           definition — both exist in this tree today
#                           (witness/tests) and are unrelated to trust
#                           material; a bare `\bstore\(` pattern (no leading
#                           underscore) catches both and was rejected for
#                           that reason — verified: it is the exact pattern
#                           that first suggested this derivation and it
#                           wrongly pulled in witness/tests/test_witness_service.py
#                           and witness/tests/test_witness_store.py, whose
#                           `store(` calls are a Witness transparency-log
#                           write method with nothing to do with trust
#                           material.
#   - `trust_store=`       passes an already-built store to a door BY
#                           KEYWORD (e.g. `evaluate_grant(..., trust_store=x)`).
#
# Property captured: this file's trust material is built by code that the
# T2 flip invalidates at CONSTRUCTION time, before any door is even reached.
#
# ---------------------------------------------------------------------------
# CRITERION B — calls a T2 door with what is, today, a raw dict
# ---------------------------------------------------------------------------
# A file matches B if it calls one of the Python doors enumerated in the
# plan's §5.5 table ("TUTTE le porte") BY NAME. Every one of these doors
# takes a `key_manifest`/`trust_store` argument that, today, is a plain
# `dict` — the `KeyManifest`/`TrustStore` wrapper types do not exist as
# arguments to these functions until T2 introduces them — so EVERY call site
# in the tree right now passes a dict. After T2 each door's NS ("non-snapshot")
# behaviour from §5.5 fires on that same dict: `False`/`None` for the
# predicate/lookup family, `TypeError` for `evaluate_*`, a `ChainAuditResult`
# with `valid=False` for `audit_chain`. A currently-passing assertion that
# expects success on a well-formed dict flips outcome; a currently-passing
# assertion that already expects rejection does not (same door, same F/TE/CA
# outcome as before) — but grep cannot and does not try to tell those apart
# by call site; it flags the FILE, which is the granularity the plan's own
# elenco uses.
#
# `verify.verify` is deliberately EXCLUDED from this list: it is far too
# generic a name (`something.verify(...)` collides with signature/crypto
# verification elsewhere in the suite) and every file that can call it with a
# REAL trust store already matches Criterion A or C to get that store in the
# first place. `evaluate_grant`/`evaluate_publisher_authority` ARE kept in
# this list (not left to Criterion A's `trust_store=` sub-pattern alone):
# they are specific enough names to carry no collision risk, and relying on
# a keyword-argument spelling convention to catch them would be fragile
# should a caller switch to a positional argument.
PORTS_PY_DOORS='verify_authorization|verify_authorization_signature|verify_grant|verify_grant_signature|verify_declaration|verify_declaration_signature|verify_record|verify_record_signature|audit_chain|find_key|verify_key_manifest|manifest_signature_is_authentic|check_continuity|claim_capabilities|build_revocation_view|verify_artifact_manifest|evaluate_grant|evaluate_publisher_authority'
#   - manifests.{find_key, verify_key_manifest, manifest_signature_is_authentic,
#     check_continuity} — D-A1's four primitives: name and publicity kept,
#     contract changed to require KeyManifest.
#   - {revocation,transfer}.verify_record / verify_record_signature
#   - transfer.audit_chain
#   - grant.verify_grant / verify_grant_signature / verify_declaration /
#     verify_declaration_signature
#   - authority.verify_authorization / verify_authorization_signature
#   - manifests.verify_artifact_manifest
#   - views.claim_capabilities / views.build_revocation_view
#   - verify.evaluate_grant / verify.evaluate_publisher_authority
#
# ---------------------------------------------------------------------------
# CRITERION C — inherits the breakage of a SHARED fixture it did not write
# ---------------------------------------------------------------------------
# A file can go red without containing a single trace of Criterion A or B in
# its own text, if it merely REQUESTS a pytest fixture — defined once in a
# `conftest.py` that scopes over it — whose OWN body matches Criterion A.
# Confirmed case in this tree: `bridge/tests/conftest.py` defines a
# session-scoped fixture `trust_store` that does
# `verify_mod.TrustStore(manifests={ISSUER: key_manifest}, provenance={ISSUER: "tls"})`
# — Criterion A, direct old-style construction. FIVE files under
# `bridge/tests/` request that fixture by parameter name: `test_bridge_cli.py`,
# `test_bridge_http.py`, `test_bridge_core_oracle.py`, `test_bridge_itch.py`,
# `test_bridge_shopify.py`. The plan's hand-written 42-file list names only
# ONE of these five as its own line-item plus the conftest.py that defines
# the fixture (its annotation reads "bridge/tests/conftest.py (-> tutti i
# test di bridge/tests)", i.e. it INTENDED the arrow to reach all of them,
# but the enumerated 42 only followed through on one). Since the fixture is
# `scope="session"`, pytest constructs it exactly once; if that construction
# raises, EVERY test across all five files that requests it errors, not just
# the one the plan named. Verified live in this worktree: all four omitted
# tests currently PASS at baseline
# (test_itch_dry_run_writes_the_pair_and_the_shareable_half_is_salt_free,
# test_e2e_signed_webhook_to_offline_verified_receipt,
# test_e2e_claim_tick_issues_api_confirmed_receipt_that_verifies_offline,
# test_e2e_signed_shopify_webhook_to_offline_verified_receipt), and the plan
# text itself (§5.1.2) states the exact TypeError the old keyword call will
# raise once `verify.TrustStore = trust_material.TrustStore` takes effect —
# so this is not a hypothesis, it follows from the plan's own words.
#
# Implementation: for every `conftest.py` under the scanned directories,
# each top-level `def NAME(...):` block is treated as a candidate fixture
# body and checked against Criterion A. If it matches, NAME is "tainted".
# Every OTHER file under that SAME conftest.py's directory (fixtures do not
# cross into sibling directories) that references NAME as a bare identifier
# — not as `obj.NAME` (attribute access; e.g. `imported.trust_store`, the
# `ImportedBundle.trust_store` attribute from `bundle.import_bundle`, is
# unrelated and must not match) and not because the file defines its own
# same-named override — inherits the taint.
#
# ---------------------------------------------------------------------------
# What this script deliberately does NOT try to derive
# ---------------------------------------------------------------------------
# The plan's T2 bullet also expects red on "tutti i tests/test_cli*.py (9
# file)" IN ADDITION to the structural set below. That block is a different
# claim (D-A3: cli.py itself is not touched in T2, so its tests are expected
# red as a category tied to the CLI surface, not to any per-file property a
# grep can see) and is left to the plan to name directly — this script only
# derives the three structural criteria above. Two of the nine
# (test_cli.py, test_cli_revoke_properties.py) ALSO satisfy Criterion B on
# their own merits and so already appear in this script's output.
#
# This script performs NO test execution (no pytest, no suite) and does not
# require the virtualenv to be built — it is a scan over source text and
# runs in well under a second.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ ! -d "$REPO_ROOT/tests" ]; then
  echo "predicted-red-set.sh: $REPO_ROOT/tests not found — tree looks wrong" >&2
  exit 2
fi

PORTS_PY_DOORS="$PORTS_PY_DOORS" REPO_ROOT="$REPO_ROOT" python3 - <<'PYEOF'
import os
import re
import sys

REPO_ROOT = os.environ["REPO_ROOT"]
DIRS = ["tests", "tests/tools", "bridge/tests", "witness/tests"]


def list_files():
    files = []
    for d in DIRS:
        full = os.path.join(REPO_ROOT, d)
        if not os.path.isdir(full):
            continue
        for name in sorted(os.listdir(full)):
            if name.endswith(".py"):
                files.append(os.path.join(d, name))
    return files


FILES = list_files()
if not FILES:
    print("predicted-red-set.sh: no .py files found under tests/, tests/tools/, "
          "bridge/tests/, witness/tests/ — tree looks wrong", file=sys.stderr)
    sys.exit(2)

TEXT = {rel: open(os.path.join(REPO_ROOT, rel), encoding="utf-8").read() for rel in FILES}

# --- Criterion A ---------------------------------------------------------
CRIT_A = re.compile(r'\bTrustStore\(|\b_trust_store\(|\b_store\(|\btrust_store=')

# --- Criterion B ---------------------------------------------------------
door_names = os.environ["PORTS_PY_DOORS"].split("|")
CRIT_B = re.compile(r'\b(' + '|'.join(re.escape(n) for n in door_names) + r')\(')

# --- Criterion C: taint through a shared conftest.py fixture -------------
def conftest_fixture_bodies(text):
    """Yield (name, body) for each top-level `def NAME(...):` block."""
    starts = [m.start() for m in re.finditer(r'^def (\w+)\(', text, re.M)]
    names = re.findall(r'^def (\w+)\(', text, re.M)
    bounds = starts + [len(text)]
    for i, name in enumerate(names):
        yield name, text[bounds[i]:bounds[i + 1]]


tainted = {}  # fixture name -> (defining conftest.py rel path, its scope dir)
for rel in FILES:
    if os.path.basename(rel) != "conftest.py":
        continue
    scope_dir = os.path.dirname(rel)
    for name, body in conftest_fixture_bodies(TEXT[rel]):
        if CRIT_A.search(body):
            tainted[name] = (rel, scope_dir)

setA, setB, setC = set(), set(), set()
for rel in FILES:
    text = TEXT[rel]
    if CRIT_A.search(text):
        setA.add(rel)
    if CRIT_B.search(text):
        setB.add(rel)

for name, (defining_rel, scope_dir) in tainted.items():
    usage_pat = re.compile(r'(?<![.\w])' + re.escape(name) + r'\b')
    def_pat = re.compile(r'^\s*def\s+' + re.escape(name) + r'\s*\(', re.M)
    for rel in FILES:
        if rel != scope_dir and not rel.startswith(scope_dir + "/"):
            continue  # outside this conftest.py's fixture scope
        if rel == defining_rel:
            continue
        text = TEXT[rel]
        if def_pat.search(text):
            continue  # local override shadows the tainted fixture
        if usage_pat.search(text):
            setC.add(rel)

for rel in sorted(setA | setB | setC):
    print(rel)
PYEOF
