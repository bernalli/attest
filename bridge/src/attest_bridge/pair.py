"""The one place the bridge builds the §14.1/§14.2 receipt pair.

Spec §14.1/§14.2 define exactly two files per export: `<name>.attest`, which
carries the receipt with `delivery.salt` STRIPPED plus the issuer's key
manifest and the licence text, and `<name>.private.attest`, which holds the
salt and says so in its name. That naming is the only guard the web verifier
has (it refuses `*.private.attest` by name), so the salt must never leave
this process under any other filename.

This module exists because the mechanism used to live inside `delivery.py`,
reachable only from the email path: every other surface that handed a receipt
to a buyer — the `/r/<token>` download, `/stripe/receipt`, the itch dry-run —
served the bare salt-bearing envelope under the shareable `.attest` name, so a
buyer forwarding "their receipt" forwarded the issuer-recorded binding secret
that answers its binding proof. Extracting `build_pair` here is what lets all
of them build the same two files.

The key manifest is read from the ENVELOPE (`delivery.issuer_manifest`), not
from an issuer identity: `delivery.sweep_undelivered` and the download routes
have none in scope, and the embedded copy is the snapshot taken at issuance —
byte-identical to what signed this receipt, and therefore still correct after
a later key rotation. The bridge holds no artifact manifests, and `export`
accepts the empty list.

Every precondition miss raises `bundle.BundleError` rather than returning
something half-built, so each caller can map it to its own fail-closed
outcome (a failed `DeliveryResult`, a 500, a config-error exit code) — never
to a fallback that serves the salted envelope.
"""

from __future__ import annotations

import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from attest import bundle

# Module seam: `tempfile.TemporaryDirectory` is 0700 by stdlib contract and
# removes itself on EVERY exit path including exceptions. Indirecting it here
# lets a test observe the directory and its removal without patching the stdlib
# module globally.
_TMPDIR_FACTORY: Callable[[], Any] = tempfile.TemporaryDirectory
# Pinned character classes for anything that becomes a filename. Raw
# interpolation of an issuer id or receipt id into a path is the hazard the
# spec already closes for `proofs/<ULID>` bundle members; the bridge closes it
# the same way rather than trusting the payload.
_RECEIPT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_MAX_SLUG_CHARS = 64


@dataclass(frozen=True, slots=True)
class BundlePair:
    """The two halves of one receipt export, in memory.

    `name` is the shared stem: the shareable half is `<name>.attest` and the
    private half is `<name>.private.attest`. Callers must never rename either
    one — the suffix is the guard.
    """

    name: str
    shareable: bytes
    private: bytes


def _issuer_slug(issuer_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", issuer_id.lower()).strip("-")
    if not slug:
        raise bundle.BundleError("issuer id reduces to an empty filename slug")
    return slug[:_MAX_SLUG_CHARS]


def build_pair(
    envelope: dict[str, Any], receipt_id: str, legal_texts: Mapping[str, bytes]
) -> BundlePair:
    """Build the §14.1/§14.2 pair for one receipt and return it in memory.

    The pair exists on disk only inside a 0700 directory that the context
    manager removes on every exit path — the private member is 0600 from its
    first byte inside `export` itself. Nothing is returned unless both halves
    were written and read back.
    """
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise bundle.BundleError("envelope has no payload object")
    if payload.get("receipt_id") != receipt_id:
        raise bundle.BundleError("receipt id does not match the envelope payload")
    if not _RECEIPT_ID_RE.match(receipt_id):
        raise bundle.BundleError("receipt id is not safe to use in a filename")

    issuer = payload.get("issuer")
    issuer_id = issuer.get("id") if isinstance(issuer, dict) else None
    if not isinstance(issuer_id, str) or not issuer_id:
        raise bundle.BundleError("envelope payload has no issuer id")

    delivery_block = envelope.get("delivery")
    manifest = delivery_block.get("issuer_manifest") if isinstance(delivery_block, dict) else None
    if not isinstance(manifest, dict):
        raise bundle.BundleError("envelope carries no embedded issuer manifest")

    name = f"{_issuer_slug(issuer_id)}-{receipt_id}"
    with _TMPDIR_FACTORY() as workdir:
        attest_path, private_path = bundle.export(
            [envelope], [manifest], [], dict(legal_texts), Path(workdir), name
        )
        return BundlePair(
            name=name,
            shareable=attest_path.read_bytes(),
            private=private_path.read_bytes(),
        )
