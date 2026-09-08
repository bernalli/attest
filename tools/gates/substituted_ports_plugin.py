"""Neutralize every monkeypatch that SUBSTITUTES a trust-material port.

WHY THIS EXISTS

A test that replaces a port with a stand-in measures the stand-in. That is
often exactly right — it is how you check that a caller reaches a door at all,
or that an exception from it is mapped. But it has a failure mode with no
symptom: when the code under test stops calling the PUBLIC door and starts
calling its private twin, the stand-in is never invoked, the test keeps
passing, and nothing anywhere goes red. The test did not fail — it went
silent, which looks identical to success.

Measured on this tree (2026-09-08): `tests/test_views.py` substituted
`manifests.manifest_signature_is_authentic` to prove the preflight consults it.
After the doors were re-typed, `views.py` reached the private twin instead, so
the stand-in stopped being called. The test still passed.

WHAT THIS PLUGIN DOES

It wraps every watched port in a COUNTING WRAPPER around the real function,
installed for the whole session before any test runs, and tallies every call made
through that name. A test's own substitution is still APPLIED -- the stand-in is
not dropped, it replaces the counter for that test's duration -- so what the count
answers is whether the name is reached by the REST of the file. (An earlier
wording here said the stand-in was dropped. It is not, and the difference matters
to anyone reading a count and deciding what it proves.)

The gate then asks one question of each: **was this name reached at all?** A
count of zero means the test filed its stand-in at an address the code under
test never visits — whatever the stand-in was for, it cannot have measured it.

WHY COUNTING AND NOT NEUTRALIZING

The first version of this plugin made the substitution a no-op and required
the file to go red. That works for a stand-in that REPLACES a behaviour (a
lambda returning False, a spy that counts) — remove it and the outcome moves.
It is wrong for the other half of the family: a sentinel that proves a
NON-event, written as a function that raises if it is ever called. Removing
that one changes nothing by construction, because the whole point is that it
never fires — so the file stays green and the neutralizing gate reports a
defect that is not there. Measured on `tests/test_authority.py`, whose
`fail_if_called` proves a shape guard runs BEFORE any manifest cryptography.

Counting asks the question both halves actually share, and it is the question
that matters: is the name the test chose the name the code calls? A replacing
stand-in and a non-event sentinel are equally useless when the answer is no,
and both are fine when it is yes.
"""

from __future__ import annotations

from typing import Any

import pytest

# The doors of section 5.5, plus their private twins: a stand-in on EITHER is a
# substitution, and the gate wants to know about both. Derived from one place
# so the plugin and the gate script cannot disagree about what a port is.
PORT_NAMES: frozenset[str] = frozenset(
    {
        "find_key",
        "verify_key_manifest",
        "manifest_signature_is_authentic",
        "check_continuity",
        "verify_artifact_manifest",
        "verify_record",
        "verify_record_signature",
        "verify_grant",
        "verify_grant_signature",
        "verify_declaration",
        "verify_declaration_signature",
        "verify_authorization",
        "verify_authorization_signature",
        "audit_chain",
        "claim_capabilities",
        "build_revocation_view",
    }
)
PORT_NAMES = frozenset(PORT_NAMES | {f"_{name}" for name in PORT_NAMES})

_reached: dict[str, int] = {}
_substituted: set[str] = set()
_MISSING = object()

# The modules whose ports are watched. Named here rather than discovered, and
# the gate checks that every one of them imports: a module that silently failed
# to load would contribute zero counts and read as "nothing to see".
# `grant` and `authority` are here because T2's five NEW composite twins live in
# them: a stand-in filed on `attest.grant.verify_grant` produced a label with no
# counter behind it, which the session reported as `UNWATCHED-NAME` and the gate
# did not count as a failure -- silence on exactly the surface the task changed.
_OWNERS = (
    "attest.manifests",
    "attest.revocation",
    "attest.transfer",
    "attest.views",
    "attest.grant",
    "attest.authority",
)


def _install_counters() -> None:
    """Wrap every watched port with a counter that delegates to the real one.

    Installed for the WHOLE session, before any test runs. A test that
    substitutes a port replaces the counter for its own duration — which is
    correct and is the point: what the gate needs to know is whether the name
    is reached by the OTHER tests in the file, i.e. whether the code under test
    calls that name at all.
    """
    import importlib

    for module_path in _OWNERS:
        try:
            module = importlib.import_module(module_path)
        except ImportError:  # pragma: no cover - reported by the gate as a precondition
            continue
        for attribute in sorted(PORT_NAMES):
            real = getattr(module, attribute, None)
            if real is None or not callable(real):
                continue
            label = f"{module_path}.{attribute}"
            _reached.setdefault(label, 0)

            def counting(*args: Any, _real: Any = real, _label: str = label, **kw: Any) -> Any:
                _reached[_label] += 1
                return _real(*args, **kw)

            counting.__name__ = attribute
            setattr(module, attribute, counting)


def _port_label(target: object, name: object) -> str | None:
    """The label of the port this substitution names, or None.

    Two spellings, told apart by the TYPE of `target`, never by counting
    arguments: in the string form the second positional is the replacement
    VALUE, which can legitimately be anything at all.
    """
    if isinstance(target, str):
        module_path, _, attribute = target.rpartition(".")
        if attribute not in PORT_NAMES:
            return None
        # `attest_bridge.signing.manifests.verify_key_manifest` names the port
        # through the module that imported it; the port itself lives in the
        # module whose name is the last component of the path before it.
        owner = module_path.rsplit(".", 1)[-1]
        return f"attest.{owner}.{attribute}" if not module_path.startswith("attest.") else target
    if isinstance(name, str) and name in PORT_NAMES:
        owner = getattr(target, "__name__", str(target))
        return f"{owner}.{name}"
    return None


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: object) -> None:
    _install_counters()
    original_setattr = pytest.MonkeyPatch.setattr

    def patched(
        self: Any, target: Any, name: Any = _MISSING, value: Any = _MISSING, **kwargs: Any
    ) -> None:
        label = _port_label(target, None if name is _MISSING else name)
        if label is not None:
            _substituted.add(label)
        args = [a for a in (name, value) if a is not _MISSING]
        original_setattr(self, target, *args, **kwargs)

    # Both codes, and mypy names the second itself: `MonkeyPatch.setattr` is
    # overloaded, so replacing it is an `assignment` error as well as a
    # `method-assign` one, and a suppression that covers only the first leaves
    # the file red. It went unseen because the check reported for T2 was
    # `mypy --strict src/attest/`, while G-LINT measures MYPY_ROOTS -- which
    # includes this directory. Same criterion, wider population.
    pytest.MonkeyPatch.setattr = patched  # type: ignore[method-assign, assignment]


def pytest_sessionfinish(session: object, exitstatus: int) -> None:
    if not _substituted:
        print("\n[substituted-ports] NO substitution was intercepted")
        return
    print("\n[substituted-ports] each substituted port, and how often the code reached it:")
    for label in sorted(_substituted):
        count = _reached.get(label)
        if count is None:
            print(f"  {label}: UNWATCHED-NAME (not a port of a watched module)")
            continue
        print(f"  {label}: reached {count} time(s)")
        if count == 0:
            print(f"  UNREACHED: {label}")
