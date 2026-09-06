"""Export/import bundles and the single-receipt `disclose` unit (design §9).

"A receipt whose terms can no longer be produced is a signature without a
deal — the bundle must preserve the deal." `export()` therefore refuses
(`BundleError`) to produce a bundle unless every hash-bound legal document a
receipt points to (`license.legal_text_sha256`, `survivability.
mirror_policy_sha256`, `survivability.eol_commitment_sha256`) is supplied
with matching bytes — the deal's terms travel with the signature, not just
the signature.

Two files come out of `export()`:

- `<name>.attest` — shareable-safe. Receipts have `delivery.salt` stripped
  (the buyer-binding secret never leaves the buyer's private file), key and
  artifact manifests are grouped per issuer so `import_bundle()` can rebuild
  a working `verify.TrustStore` offline, referenced legal texts travel
  content-addressed by their sha256, and a generated `README.html` explains
  what the bundle is and which sibling file must never be shared.
- `<name>.private.attest` — secrets. `salts.json` maps `receipt_id -> salt`
  (base64url); `keys/` is reserved for per-receipt buyer signing keypairs,
  but `export()`'s signature never receives that private key material (the
  store issuing receipts never holds a buyer's private key), so it stays
  empty in this implementation — buyer clients that generate per-receipt
  keypairs are expected to manage that material outside of `bundle.py` and
  write it into `keys/` themselves before distributing the private file.

`manifests/<issuer>.json` convention (chosen here, documented for
`import_bundle()` to rely on): one JSON object per issuer,
`{"issuer": ..., "key_manifests": [...], "artifact_manifests": [...]}`, each
list sorted ascending by its own version field
(`manifest_version`/`version`). `import_bundle()` treats the
highest-`manifest_version` entry as the issuer's current key manifest
(`TrustStore.manifests`) and the full sorted list as its rotation history
(`TrustStore.chains`) — every issuer found in the bundle is trusted with
provenance `"bundle"` (design §5: unauthenticated TOFU, never silently
treated as `"verified"`).

`disclose()` is the single-receipt sharing unit (design §9): it emits one
`.attest.json` self-contained via `delivery` — that receipt's own salt (never
the whole salts map) plus a key-manifest snapshot that still lists the kid
that signed it, so the file verifies standalone even against a bundle-less
verifier.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import html
import json
import mmap
import os
import re
import stat
import tempfile
import zipfile
from collections.abc import Buffer, Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from attest import buyer_surface, canon, container, keys, manifests, verify
from attest.ulid import RECEIPT_ID_RE

_PROVENANCE_BUNDLE = "bundle"
_SECRET_FILE_MODE = 0o600  # disclose output carries delivery.salt (a bearer secret)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

# Import ceilings adopt the floor in specification section 14.4 as this
# importer's own ceiling. Section 14.4 explicitly permits implementations to
# make that choice, with the resulting difference in accepted containers being
# observable to callers.
_MAX_MEMBER_BYTES = 64 * 1024 * 1024  # 64 MiB per decompressed member
_MAX_TOTAL_BYTES = 256 * 1024 * 1024  # 256 MiB decompressed across one import
_MAX_ENTRIES = 10_000  # central-directory entry count
_MAX_CONTAINER_BYTES = 1024 * 1024 * 1024  # 1 GiB stored per container
_SNAPSHOT_CHUNK = 1024 * 1024  # bytes copied per read while snapshotting a container

#: The placeholders `_render_readme` substitutes, matched in a single pass.
_PLACEHOLDER_RE = re.compile("__BUNDLE_NAME__|__PRIVATE_WARNING__")

#: Body of the bundle README, wrapped by ``buyer_surface.render_page`` at
#: render time. Two placeholders: ``__BUNDLE_NAME__`` for the bundle stem, and
#: ``__PRIVATE_WARNING__`` for the shared warning block, which is written once
#: in ``buyer_surface`` and rendered identically on every buyer-facing surface
#: rather than hand-copied here.
_README_BODY_TEMPLATE = """\
<h1>attest receipt bundle: __BUNDLE_NAME__</h1>

<p>This file is your receipt. It proves what the seller signed about what's
listed inside, and it's yours: it doesn't live in any account, and nobody can take it away with
a click. Keep it with your own files, the way you'd keep an important paper
receipt. If the store closes one day, or you lose access to your account
there, this file still proves exactly what the seller signed. You don't need an internet
connection or anyone's permission to check it: any attest tool can do it,
free, on your own computer.</p>

<h2>What's inside</h2>
<p>This zip holds one or more of your purchase receipts, plus everything
needed to check that they're genuine: the store's own signing key, and the
full text of the license, mirror policy, and end-of-life promise your
receipts refer to. You don't need an internet connection, an account with
the store, or any help from the store to use this file. It's self-contained
on purpose.</p>

<h2>If the store that sold you this is gone</h2>
<p>You can still check exactly what the seller signed. Use any attest-compatible
tool to check this bundle — for example, the reference tool:
<code>attest import __BUNDLE_NAME__.attest</code>, then
<code>attest verify &lt;receipt_id&gt;</code>. That check runs entirely on
your own computer; it never needs to reach the store.</p>

<h2>Two files, and only one is safe to share</h2>
<p><strong>This file, __BUNDLE_NAME__.attest, is safe to share</strong> — it
was built to contain no secrets. It came with a sibling file, and that one is
different.</p>

__PRIVATE_WARNING__

<h2>About the proofs/ folder (if present)</h2>
<p>Some receipts in this bundle may come with a
<code>proofs/&lt;receipt_id&gt;.json</code> file: evidence that the receipt
was independently recorded in a public log at some point in time, sometimes
backed by a Bitcoin block header. Treat this as corroboration, not proof of
purchase by itself — what actually proves the receipt is genuine is its own
signature, described below. A log entry only shows the receipt was visible
publicly at that time; it can't by itself rule out the log's operator
showing different people different versions of history.</p>

<h2>For the technically curious</h2>
<p>Each receipt is signed with the issuer's private key (Ed25519, with an
optional post-quantum ML-DSA-65 signature alongside it), and the matching
public key manifest travels inside this bundle so the signature can be
checked completely offline. Because this bundle was assembled without a
live, at-verification-time TLS connection back to the issuer, a compliant
verifier reports its trust level as <code>unauthenticated_tofu</code>
rather than <code>verified</code>: the cryptographic signature is exactly
as valid either way, it's specifically the freshness of that trust
confirmation over the network that couldn't be re-checked just now.</p>"""


class BundleError(Exception):
    """A bundle cannot be produced without breaking the deal it claims to preserve (§9)."""


class BundleTooLargeError(BundleError):
    """The importer declined to read the container, and found nothing wrong with it.

    v0.1 §14.4 asks for this as an outcome of its own, apart from every refusal
    that says the container is malformed, and the reason is what a caller does
    next: a refusal of this kind may succeed with a larger budget on a machine
    with more room, while a malformed container will never be readable however
    much budget it is given. Reporting an unread container as corrupt states
    something about bytes nobody looked at.

    It is a `BundleError`, so a caller who does not care keeps catching one
    exception; a caller who does can tell the two apart without reading the
    sentence.
    """


def _proof_member_receipt_id(filename: str) -> str:
    """Return the receipt id in a strictly-shaped ``proofs/`` member.

    A bundle is attacker-supplied, and callers later derive an on-disk proof
    filename from this value.  The receipt schema pins ids to ULIDs, so accept
    only the one safe member shape: ``proofs/<ULID>.json``.  In particular,
    never turn an absolute path, traversal component, or nested member into a
    receipt id that an importer could join below its output directory.
    """
    relative = filename.removeprefix("proofs/")
    if not relative.endswith(".json"):
        raise BundleError(f"invalid proof member path {filename!r}; expected proofs/<ULID>.json")
    receipt_id = relative.removesuffix(".json")
    if relative != f"{receipt_id}.json" or RECEIPT_ID_RE.fullmatch(receipt_id) is None:
        raise BundleError(f"invalid proof member path {filename!r}; expected proofs/<ULID>.json")
    return receipt_id


def _receipt_payload_id(envelope: object, filename: str) -> str:
    """Return the receipt id inside an imported envelope, strictly shaped.

    A bundle is attacker-supplied and `cli.py` derives an on-disk filename from
    this value, exactly as it does for `proofs/` members. The receipt schema
    pins ids to ULIDs, so accept only that shape — never an absolute path, a
    traversal component, or a case/normalization variant that would collide
    with a sibling on a case-insensitive or normalizing filesystem.
    """
    payload = envelope.get("payload") if isinstance(envelope, dict) else None
    receipt_id = payload.get("receipt_id") if isinstance(payload, dict) else None
    if not isinstance(receipt_id, str) or RECEIPT_ID_RE.fullmatch(receipt_id) is None:
        raise BundleError(
            f"receipt entry {filename!r} has invalid receipt_id; expected uppercase ULID"
        )
    return receipt_id


@dataclass(frozen=True)
class ImportedBundle:
    """Everything `import_bundle()` reconstructed from a `.attest` (and,
    optionally, its `.private.attest` sibling) — enough to verify every
    receipt offline via `trust_store`."""

    receipts: list[dict[str, Any]]
    trust_store: verify.TrustStore
    artifact_manifests: dict[str, list[dict[str, Any]]]
    legal_texts: dict[str, bytes]
    salts: dict[str, bytes]
    # Stage 2: transparency-log evidence (Task 4 schema, optionally anchored),
    # keyed by receipt_id — corroboration, not authenticity (see the bundle
    # README's own paragraph on this). Empty by default so existing callers
    # that never pass `proofs=` to `export()` see zero behavior change.
    proofs: dict[str, dict[str, Any]] = field(default_factory=dict)


def _referenced_legal_hashes(payload: dict[str, Any]) -> list[str]:
    """Every hash-bound legal document this payload's terms depend on:
    `license.legal_text_sha256` (always present, schema-required) plus
    `survivability.mirror_policy_sha256` and `survivability.
    eol_commitment_sha256` when present and non-null. Malformed/missing
    blocks contribute no hashes rather than raising — schema validation
    upstream is what should catch a malformed payload; this function only
    decides which legal texts a well-formed one requires."""
    hashes: list[str] = []

    license_block = payload.get("license")
    if isinstance(license_block, dict):
        h = license_block.get("legal_text_sha256")
        if isinstance(h, str):
            hashes.append(h)

    survivability = payload.get("survivability")
    if isinstance(survivability, dict):
        for field_name in ("mirror_policy_sha256", "eol_commitment_sha256"):
            h = survivability.get(field_name)
            if isinstance(h, str):
                hashes.append(h)

    return hashes


def _check_legal_text(digest: str, legal_texts: dict[str, bytes]) -> None:
    content = legal_texts.get(digest)
    if content is None:
        raise BundleError(
            f"no legal text supplied for hash {digest!r} — the bundle cannot preserve "
            "the deal this receipt refers to"
        )
    if hashlib.sha256(content).hexdigest() != digest:
        raise BundleError(f"legal text supplied for hash {digest!r} does not hash to that value")


def _strip_salt(envelope: dict[str, Any]) -> dict[str, Any]:
    """Shareable-safe copy: same envelope, `delivery.salt` removed. If
    `delivery` had no other member, it is dropped entirely rather than left
    as an empty object — `{}` and "member absent" are different shapes and a
    simpler consumer should not have to tell them apart."""
    stripped = dict(envelope)
    delivery = stripped.get("delivery")
    if isinstance(delivery, dict) and "salt" in delivery:
        remaining = {k: v for k, v in delivery.items() if k != "salt"}
        if remaining:
            stripped["delivery"] = remaining
        else:
            del stripped["delivery"]
    return stripped


def _group_manifests_by_issuer(
    key_manifests: list[dict[str, Any]], artifact_manifests: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for km in key_manifests:
        issuer = km.get("issuer")
        if not isinstance(issuer, str):
            continue
        grouped.setdefault(issuer, {"key_manifests": [], "artifact_manifests": []})
        grouped[issuer]["key_manifests"].append(km)
    for am in artifact_manifests:
        issuer = am.get("issuer")
        if not isinstance(issuer, str):
            continue
        grouped.setdefault(issuer, {"key_manifests": [], "artifact_manifests": []})
        grouped[issuer]["artifact_manifests"].append(am)

    result: dict[str, dict[str, Any]] = {}
    for issuer, blob in grouped.items():
        blob["key_manifests"].sort(key=lambda m: m.get("manifest_version", 0))
        blob["artifact_manifests"].sort(key=lambda m: m.get("version", 0))
        result[issuer] = {"issuer": issuer, **blob}
    return result


def _render_readme(name: str) -> str:
    """Render the README that travels inside ``<name>.attest``.

    The page is fully self-contained — styling included, nothing fetched — so
    it opens from the zip on a machine with no network, years from now.
    """
    # The name lands in markup a buyer opens in a browser, and export() is
    # library API: the value can be whatever the caller's own caller supplied.
    # Escape once here; the warning block escapes its own copy, and
    # render_page escapes the title.
    #
    # One pass, so nothing already substituted is scanned again: chained
    # .replace() calls let a name containing the literal text of the other
    # placeholder be rewritten a second time inside the block just inserted,
    # and the warning would then name a private file that is not the one
    # beside this bundle.
    substitutions = {
        "__BUNDLE_NAME__": html.escape(name),
        "__PRIVATE_WARNING__": buyer_surface.private_file_warning_html(name),
    }
    body = _PLACEHOLDER_RE.sub(lambda match: substitutions[match.group(0)], _README_BODY_TEMPLATE)
    return buyer_surface.render_page(f"attest receipt bundle: {name}", body)


def _raise_secret_output_appeared(path: Path, *, label: str, exc: BaseException) -> None:
    raise BundleError(
        f"{label} {path} appeared while writing; "
        "refusing to overwrite it (re-run, or pass --force to replace it)"
    ) from exc


def _reject_unsafe_secret_output(
    path: Path, output_stat: os.stat_result, *, label: str, reject_hardlinks: bool = True
) -> None:
    if not stat.S_ISREG(output_stat.st_mode):
        raise BundleError(f"{label} {path} is not a regular file; refusing to overwrite it")
    if reject_hardlinks and output_stat.st_nlink > 1:
        raise BundleError(f"{label} {path} has multiple hard links; refusing to overwrite it")


def _open_secret_output(
    path: Path, *, label: str, exclusive: bool = False, reject_hardlinks: bool = True
) -> int:
    """Open a secret-bearing output owner-only, never through a symlink.

    `reject_hardlinks=False` keeps the symlink refusal — following a link
    someone else planted writes the secret where they can read it — while
    allowing a target that already has aliases, for outputs whose every alias
    necessarily holds the same secret already (see `_write_secret_json`).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | _O_NOFOLLOW
    if exclusive:
        flags |= os.O_EXCL
    try:
        fd = os.open(path, flags, _SECRET_FILE_MODE)
    except FileExistsError as exc:
        _raise_secret_output_appeared(path, label=label, exc=exc)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            if exclusive:
                _raise_secret_output_appeared(path, label=label, exc=exc)
            raise BundleError(f"{label} {path} is a symlink; refusing to overwrite it") from exc
        raise
    try:
        _reject_unsafe_secret_output(
            path, os.fstat(fd), label=label, reject_hardlinks=reject_hardlinks
        )
    except Exception:
        os.close(fd)
        raise
    return fd


def _write_secret_json(path: Path, obj: dict[str, Any]) -> None:
    """Write a secret-bearing JSON file (the disclose output embeds
    `delivery.salt`) created atomically with owner-only 0600 permissions.

    The fd is opened before truncation and checked with `fstat`, so a symlink
    is refused before any bytes are destroyed: the disclosure carries
    `delivery.salt`, and following a link someone else planted would hand that
    salt to them. A hard-linked target is written, unlike every other secret
    output here — the aliases of that inode are earlier disclosures of this
    same receipt, so they already hold this same salt and refusing would cost
    a working call without protecting anything. There is no `--force`: the
    disclosure is recomputable, so a refusal is answered by naming another path.
    """
    fd = _open_secret_output(path, label="disclose output", reject_hardlinks=False)
    with os.fdopen(fd, "w") as fh:  # takes ownership of fd; closes even on raise
        os.fchmod(fh.fileno(), _SECRET_FILE_MODE)
        os.ftruncate(fh.fileno(), 0)
        json.dump(obj, fh)


def export(
    receipts: list[dict[str, Any]],
    key_manifests: list[dict[str, Any]],
    artifact_manifests: list[dict[str, Any]],
    legal_texts: dict[str, bytes],
    out_dir: Path,
    name: str,
    *,
    proofs: dict[str, dict[str, Any]] | None = None,
    private_exclusive: bool = False,
) -> tuple[Path, Path]:
    """Write `<name>.attest` (shareable) and `<name>.private.attest` (secrets).

    Every legal-text hash referenced by any receipt is checked against
    `legal_texts` BEFORE anything is written to disk (§9: preserve the
    deal) — a partially-written bundle is worse than none, so validation
    happens as a whole pass first.

    `proofs` (Stage 2, keyword-only, defaults to `None`) is an optional
    `receipt_id -> evidence dict` map (the `attest.tlog`/`attest.transparency`
    evidence schema, produced by `attest log prove`/`anchor`): each entry
    whose `receipt_id` is actually among `receipts` is written to
    `proofs/<receipt_id>.json`. An entry for a receipt_id NOT in this export
    is silently dropped — it would be orphaned evidence for a receipt the
    recipient never receives. Existing callers that never pass `proofs=` see
    zero behavior change (no `proofs/` member is written at all).
    """
    seen_ids: dict[str, int] = {}
    for envelope in receipts:
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            raise BundleError("receipt envelope missing object member 'payload'")
        receipt_id = payload.get("receipt_id")
        if not isinstance(receipt_id, str) or RECEIPT_ID_RE.fullmatch(receipt_id) is None:
            raise BundleError("receipt payload has invalid receipt_id; expected uppercase ULID")
        seen_ids[receipt_id] = seen_ids.get(receipt_id, 0) + 1
        for digest in _referenced_legal_hashes(payload):
            _check_legal_text(digest, legal_texts)
    duplicate_ids = sorted(rid for rid, n in seen_ids.items() if n > 1)
    if duplicate_ids:
        raise BundleError(
            f"duplicate receipt_id(s) across receipts: {duplicate_ids} — member "
            "names receipts/<receipt_id>.attest.json would collide, and name-based "
            "reads on import silently shadow one of the pair (v0.1 §14.1, "
            "2026-08-26 amendment)"
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    attest_path = out_dir / f"{name}.attest"
    private_path = out_dir / f"{name}.private.attest"

    salts_b64u: dict[str, str] = {}
    referenced_hashes: set[str] = set()
    receipt_ids: set[str] = set()

    with zipfile.ZipFile(attest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for envelope in receipts:
            payload = envelope["payload"]
            receipt_id = payload["receipt_id"]
            receipt_ids.add(receipt_id)
            referenced_hashes.update(_referenced_legal_hashes(payload))

            delivery = envelope.get("delivery")
            if isinstance(delivery, dict) and isinstance(delivery.get("salt"), str):
                salts_b64u[receipt_id] = delivery["salt"]

            zf.writestr(f"receipts/{receipt_id}.attest.json", json.dumps(_strip_salt(envelope)))

        for issuer, blob in _group_manifests_by_issuer(key_manifests, artifact_manifests).items():
            zf.writestr(f"manifests/{issuer}.json", json.dumps(blob))

        for digest in sorted(referenced_hashes):
            zf.writestr(f"legal/{digest}.txt", legal_texts[digest])

        for receipt_id, evidence in sorted((proofs or {}).items()):
            if receipt_id in receipt_ids:
                zf.writestr(f"proofs/{receipt_id}.json", json.dumps(evidence))

        zf.writestr("README.html", _render_readme(name))

    # The private archive carries buyer-binding salts (bearer secrets); create it
    # owner-only (0600) race-free, mirroring _write_secret_json, so it never has a
    # world-readable window under the default umask (2026-07-13 review, finding 2).
    fd = _open_secret_output(private_path, label=".private.attest", exclusive=private_exclusive)
    with os.fdopen(fd, "wb") as fh:
        os.fchmod(fh.fileno(), _SECRET_FILE_MODE)
        os.ftruncate(fh.fileno(), 0)
        with zipfile.ZipFile(fh, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("salts.json", json.dumps(salts_b64u))

    return attest_path, private_path


#: Members a shareable bundle must never carry: they are the buyer's own
#: binding secrets, and a file holding them is a `.private.attest` under the
#: wrong name. The browser verifier has always refused such an archive; this
#: importer refuses it too, so the two agree on what a shareable bundle IS and
#: not only on what it contains (v0.1 §9).
_PRIVATE_MEMBER = "salts.json"
_PRIVATE_PREFIX = "keys/"
_PRIVATE_MSG = (
    "this looks like a .private.attest — it holds buyer-binding salts and keys; "
    "refusing to import it as a shareable bundle"
)


class _SnapshotBudget:
    """Bound one container's stored bytes while taking its stable snapshot."""

    __slots__ = ("max_bytes", "spent")

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self.spent = 0


#: The three moves of taking a snapshot, named so a refusal can say which one
#: failed. They are facts about this machine, never about the archive.
_COPY_READ_FAILED = "could not read the container in order to copy it"
_COPY_WRITE_FAILED = (
    "could not copy the container into the private temporary file this importer reads it from"
)
_COPY_MAP_FAILED = "could not map the copy this importer reads the container from"

#: What was opened, named for a refusal that must describe the path and not the
#: content — nothing has been read at the point this is used. A socket is absent
#: because it never reaches here: opening one fails in the kernel with ENXIO.
_PATH_KINDS: tuple[tuple[Callable[[int], bool], str], ...] = (
    (stat.S_ISDIR, "a directory"),
    (stat.S_ISFIFO, "a named pipe"),
    (stat.S_ISCHR, "a character device"),
    (stat.S_ISBLK, "a block device"),
)


def _path_kind(mode: int) -> str:
    """Name what a mode word describes, in words a bundle's holder can act on."""
    for is_kind, name in _PATH_KINDS:
        if is_kind(mode):
            return name
    return "not a regular file"


def _snapshot_failed(error: OSError, doing: str) -> BundleError:
    """Refuse a container whose snapshot could not be taken, naming the step.

    Taking the copy is three moves — read the source, write the temporary file,
    map it — and each can fail for reasons the archive knows nothing about: a
    source that returns an I/O error, a temporary filesystem that is full or
    quota-limited, a map this host has no room for. None of that is a verdict on
    the bytes, most of which have not been read; but an OSError leaving this
    module is worse than an imprecise verdict, because this module's promise is
    that whatever the input the caller is told in this module's own error type.
    So the refusal is one of ours and says which move failed, so its reader
    looks at their machine and not at their bundle.
    """
    return BundleError(f"{doing}: {error.strerror or error}")


def _new_snapshot() -> IO[bytes]:
    """The private temporary file a container is copied into.

    Creating it is the first move of the copy and the first that can fail: a
    temporary directory that does not exist, is read-only, or is out of inodes
    refuses here, before a byte of the archive is touched. Refusing in this
    module's own error type is the same promise the write below keeps.
    """
    try:
        return tempfile.TemporaryFile()
    except OSError as error:
        raise _snapshot_failed(error, _COPY_WRITE_FAILED) from error


def _over_snapshot_bound(budget: _SnapshotBudget) -> BundleTooLargeError:
    """The refusal for a container over the bytes this importer will copy.

    Says what this bound measures and nothing else: the size of the file, not
    of anything inside it. Borrowing the aggregate cap's sentence here read well
    and was false — an archive is over this bound as soon as its FRAMING is, so
    one whose members inflate to a few hundred bytes can cross it, and telling
    its holder the bundle is over a decompression cap sends them to look at the
    wrong thing entirely. One function, so the two places that raise it cannot
    drift into two sentences.
    """
    return BundleTooLargeError(
        f"container is over the {budget.max_bytes}-byte limit this importer "
        "will copy in order to read it — refusing to snapshot an archive "
        "that large"
    )


@contextlib.contextmanager
def _open_container(path: Path, budget: _SnapshotBudget | None = None) -> Iterator[Buffer]:
    """Map a bounded snapshot of a container, so the whole-buffer model the
    container reader needs costs no copy of a large bundle in memory.

    The snapshot is what makes the map safe. Mapping the caller's own inode
    hands whoever can write that file a way to end this process: shortening it
    while a mapped page is read raises SIGBUS, which arrives outside Python's
    exception boundary, so neither this module nor its caller can turn it back
    into a refusal. Copying the bytes into a private temporary file first gives
    the map an inode nobody else holds; a truncation of the source then lands
    before or during the copy, where it is an ordinary short read and the
    archive earns an ordinary verdict.

    What keeps snapshotting from becoming an allocation of the attacker's
    choosing is the bound, and only the bound. The copy is not bounded away from
    memory: it goes wherever this platform puts temporary files, and where that
    directory is memory-backed — a tmpfs `/tmp`, which is the ordinary
    arrangement on Linux — the file IS memory and the bound is a bound on RAM.
    Whoever sets that bound is therefore choosing, on such a host, how much
    memory one import may occupy, and the lever is the caller's:
    `import_bundle(max_container_bytes=...)` sets it, and a host with less room
    than the default should say so there. Nothing here picks the directory — the
    platform's temporary location does — so no promise is made about what backs
    it, none being keepable everywhere this runs.

    An empty snapshot cannot be mapped, and must still earn a verdict about the
    container rather than an OSError.
    """
    if budget is None:
        budget = _SnapshotBudget(_MAX_CONTAINER_BYTES)
    # What the path names is settled before a byte is read from it, and the
    # handle is taken without blocking so that it can be settled at all: opening
    # a FIFO waits for a writer who may never arrive, so `open(path, "rb")` is
    # itself where a named pipe stops this importer for good. A device would not
    # block; it would feed the copy until the bound. O_NONBLOCK changes nothing
    # for the regular file this expects, and asking the open handle rather than
    # the name leaves no window in which the two could differ.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise BundleError(
                f"container path is {_path_kind(info.st_mode)}, "
                "not a regular file — refusing to read it"
            )
        # The same bound, applied before the spend instead of during it. The
        # size a regular file reports is metadata, not content: asking for it
        # costs nothing, trusts nothing the archive says, and never maps the
        # caller's inode, so it is not the hazard the snapshot exists to remove.
        # The loop below stays the authority — a file that grows after this
        # point is still refused there — and this only spares the copy for one
        # that is already over the bound, which without it costs a full
        # `max_bytes` of temporary storage (memory, where that directory is a
        # tmpfs) to reach a refusal the metadata had already settled.
        if info.st_size > budget.max_bytes:
            raise _over_snapshot_bound(budget)
        source = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with source as fh, _new_snapshot() as snapshot:
        while True:
            remaining = budget.max_bytes - budget.spent
            # One byte past what is left is all it takes to know the source is
            # over the bound; nothing beyond it is ever read.
            try:
                chunk = fh.read(min(_SNAPSHOT_CHUNK, remaining + 1))
            except OSError as error:
                # A regular file can still refuse to be read — a failing disk, a
                # network mount that went away, a kernel file whose bytes are not
                # bytes. That is not a short read and there is no verdict in it.
                raise _snapshot_failed(error, _COPY_READ_FAILED) from error
            if not chunk:
                break
            if len(chunk) > remaining:
                raise _over_snapshot_bound(budget)
            try:
                snapshot.write(chunk)
            except OSError as error:
                raise _snapshot_failed(error, _COPY_WRITE_FAILED) from error
            budget.spent += len(chunk)

        try:
            # A buffered write is not a write until it is flushed: a temporary
            # filesystem that has just filled up refuses the tail of the copy
            # here and nowhere else.
            snapshot.flush()
        except OSError as error:
            raise _snapshot_failed(error, _COPY_WRITE_FAILED) from error
        length = snapshot.tell()
        if length == 0:
            yield b""
            return
        try:
            mapped = mmap.mmap(snapshot.fileno(), length, access=mmap.ACCESS_READ)
        except OSError as error:
            # The copy exists and is within its bound; this host still may not
            # have the address space to map it. That is this machine's answer,
            # not the archive's.
            raise _snapshot_failed(error, _COPY_MAP_FAILED) from error
        try:
            yield mapped
        except BaseException:
            # Unmapping is bookkeeping; the refusal already in flight is the
            # answer the caller asked for. A map cannot be closed while anything
            # still holds a view into it, and a view lives for as long as the
            # traceback that mentions it — so closing here can raise a
            # BufferError about exported pointers, and that complaint would
            # arrive in place of the sentence explaining why the archive was
            # refused. The mapping is released either way when the object goes.
            with contextlib.suppress(BufferError):
                mapped.close()
            raise
        mapped.close()


#: The container codes that say the importer DECLINED TO READ, rather than that
#: it read and found something wrong (v0.1 §14.4). The distinction is the
#: caller's to act on and the two have opposite remedies: a refusal in this set
#: may succeed with a larger budget, and one outside it never will.
_RESOURCE_CODES = frozenset(
    {
        "too-many-entries",
        "declared-member-over-cap",
        "declared-total-over-cap",
        "member-over-cap",
        "total-over-cap",
    }
)


def _as_bundle_error(error: container.ContainerError) -> BundleError:
    """Carry a container refusal across the boundary in this module's own voice.
    The member name is appended here, in this language's idiom, and never
    interpolated by the reader itself."""
    kind = BundleTooLargeError if error.code in _RESOURCE_CODES else BundleError
    if error.member is not None and error.code in {"duplicate-name", "record-stored-size"}:
        return kind(f"{error}: {error.member!r}")
    return kind(str(error))


def _members(
    buf: Buffer, *, max_entries: int, max_member_bytes: int, max_total_bytes: int
) -> dict[str, container.Member]:
    """The member list, keyed by name. The mapping is only safe because the
    reader has already refused a directory that repeats a name: building a
    name-keyed map from attacker-supplied names without that guarantee is how a
    duplicated member silently shadows its sibling."""
    try:
        members = container.canonical_members(
            buf,
            max_entries=max_entries,
            max_member_bytes=max_member_bytes,
            max_total_bytes=max_total_bytes,
        )
    except container.ContainerError as error:
        raise _as_bundle_error(error) from None
    return {member.name: member for member in members}


def _refuse_private_material(members: dict[str, container.Member]) -> None:
    """Decided on the member LIST, before a single member is read."""
    if any(name == _PRIVATE_MEMBER or name.startswith(_PRIVATE_PREFIX) for name in members):
        raise BundleError(_PRIVATE_MSG)


def _read(buf: Buffer, member: container.Member, budget: container.ReadBudget) -> bytes:
    try:
        return container.read_member(buf, member, budget)
    except container.ContainerError as error:
        raise _as_bundle_error(error) from None


def _loads(data: bytes, *, label: str) -> Any:
    """Parse bundle-internal JSON through the strict canonical parser (rejects
    duplicate keys, floats, BOMs) so imported trust material matches what the
    verifier will accept (2026-07-13 review, finding 9).

    Every byte here came out of an attacker-supplied archive, so the parser's
    own error is a verdict about that archive and must reach the caller as one:
    a `CanonError` escaping this module tells whoever reads it to go looking in
    the canonicalizer instead of in the bundle they were handed. `label` names
    the member, in this module's idiom, since the parser has never seen it."""
    try:
        return canon.loads_strict(data)
    except canon.CanonError as error:
        raise BundleError(f"{label} is not valid canonical JSON: {error}") from None


def _version_key(manifest: dict[str, Any], field_name: str) -> int:
    """Order manifests by a version field an archive chose, not by whatever type
    it chose to write it as. Comparing the raw values sorts a list of strings
    lexicographically and refuses to sort a mixed list at all — a `TypeError`
    out of `sorted` instead of a verdict. Anything that is not an integer uses
    zero — it ties a version of zero and orders above a negative one, and the
    sort being stable leaves the archive's own order between ties — which
    matches what the browser verifier does with the same archive."""
    value = manifest.get(field_name, 0)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def import_bundle(
    attest_path: Path,
    private_path: Path | None = None,
    *,
    max_member_bytes: int = _MAX_MEMBER_BYTES,
    max_total_bytes: int = _MAX_TOTAL_BYTES,
    max_entries: int = _MAX_ENTRIES,
    max_container_bytes: int = _MAX_CONTAINER_BYTES,
) -> ImportedBundle:
    """Reconstruct receipts, a working `verify.TrustStore`, artifact
    manifests and legal texts from a `.attest` (and, if given, its
    `.private.attest` sibling for salts). Every issuer found in the bundle is
    trusted with provenance `"bundle"` — offline-imported manifests are
    unauthenticated TOFU by construction (design §5), never silently
    upgraded to `"verified"`.

    `max_member_bytes`, `max_total_bytes` and `max_entries` are keyword-only
    zip-bomb decompression caps (§2.1), each defaulting to its module constant:
    a per-member cap on bytes actually streamed out of one zip entry, an
    aggregate cap on the running total decompressed across every member read
    during this call (`.attest` and, when given, `.private.attest` share one
    budget), and a cap on each central directory's entry count. Exceeding any
    of them raises `BundleError` rather than importing a possible bomb.

    `max_container_bytes` is the separate stored-size ceiling for the stable
    snapshot copied before a container is read (see `_open_container`). It is
    applied independently to the `.attest` and its `.private.attest` sibling,
    so a pair is accepted when each container is within this ceiling.
    """
    receipts: list[dict[str, Any]] = []
    seen_receipt_ids: set[str] = set()
    key_manifests_by_issuer: dict[str, list[dict[str, Any]]] = {}
    artifact_manifests: dict[str, list[dict[str, Any]]] = {}
    legal_texts: dict[str, bytes] = {}
    proofs: dict[str, dict[str, Any]] = {}

    # One shared budget for the whole call (spec §2.1: the aggregate cap is a
    # running total of decompressed bytes across ALL members read during one
    # import_bundle call, not per-zip) — reused below for the .private.attest
    # salts read so a hostile .attest/.private.attest pair cannot each spend up
    # to max_total_bytes and together decompress 2x the aggregate ceiling.
    budget = container.ReadBudget(max_member_bytes, max_total_bytes)
    # Stored size and inflated size are independent quantities. The inflated
    # budget above is shared across both halves of the import, while each
    # container gets the full stored-size ceiling required by section 14.4.
    with _open_container(attest_path, _SnapshotBudget(max_container_bytes)) as buf:
        members = _members(
            buf,
            max_entries=max_entries,
            max_member_bytes=max_member_bytes,
            max_total_bytes=max_total_bytes,
        )
        _refuse_private_material(members)
        for filename in sorted(members):
            if filename.startswith("receipts/") and filename.endswith(".attest.json"):
                envelope = _loads(
                    _read(buf, members[filename], budget),
                    label=f"receipt entry {filename!r}",
                )
                receipt_id = _receipt_payload_id(envelope, filename)
                if receipt_id in seen_receipt_ids:
                    raise BundleError(f"bundle lists receipt_id {receipt_id!r} more than once")
                seen_receipt_ids.add(receipt_id)
                receipts.append(envelope)
            elif filename.startswith("manifests/") and filename.endswith(".json"):
                blob = _loads(
                    _read(buf, members[filename], budget),
                    label=f"manifest entry {filename!r}",
                )
                # Everything below is shaped by the archive, not by this
                # repo's exporter: a member that is not an object, a
                # collection that is not an array, an entry that is not an
                # object. Each is a bundle this importer has nothing to say
                # about, so it is skipped exactly as an unreadable issuer
                # already was — never an AttributeError or a TypeError from
                # the machinery, which names the wrong culprit.
                if not isinstance(blob, dict):
                    continue
                issuer = blob.get("issuer")
                if not isinstance(issuer, str):
                    continue
                if issuer in key_manifests_by_issuer:
                    raise BundleError("bundle lists one issuer in more than one manifest member")
                raw_key_manifests = blob.get("key_manifests")
                key_manifests_by_issuer[issuer] = (
                    [item for item in raw_key_manifests if isinstance(item, dict)]
                    if isinstance(raw_key_manifests, list)
                    else []
                )
                raw_artifact_manifests = blob.get("artifact_manifests")
                if not isinstance(raw_artifact_manifests, list):
                    continue
                for am in raw_artifact_manifests:
                    if not isinstance(am, dict):
                        continue
                    series = am.get("series")
                    if isinstance(series, str):
                        artifact_manifests.setdefault(series, []).append(am)
            elif filename.startswith("legal/") and filename.endswith(".txt"):
                digest = filename[len("legal/") : -len(".txt")]
                content = _read(buf, members[filename], budget)
                if hashlib.sha256(content).hexdigest() != digest:
                    raise BundleError(
                        f"legal text {digest!r} failed its own integrity check on import "
                        "— bundle is corrupt or tampered"
                    )
                legal_texts[digest] = content
            elif filename.startswith("proofs/"):
                receipt_id = _proof_member_receipt_id(filename)
                evidence = _loads(
                    _read(buf, members[filename], budget),
                    label=f"proof entry {filename!r}",
                )
                if isinstance(evidence, dict):
                    proofs[receipt_id] = evidence

    # A bundle IS its receipts (v0.1 §14.1). An archive that carries none is
    # not a stripped bundle to be imported empty — it is a file that was never
    # one, and saying so is the only answer that sends its holder to look at
    # the right thing.
    if not receipts:
        raise BundleError("no receipts found inside this archive — is it really a .attest bundle?")

    # Every legal hash referenced by any imported receipt must be present — mirror
    # export's completeness pass so a stripped bundle can't import as if it still
    # preserved the deal (2026-07-13 review, finding 10).
    for envelope in receipts:
        payload = envelope.get("payload") if isinstance(envelope, dict) else None
        if isinstance(payload, dict):
            for digest in _referenced_legal_hashes(payload):
                if digest not in legal_texts:
                    raise BundleError(
                        f"bundle is missing legal text for referenced hash {digest!r} "
                        "— it cannot preserve the deal this receipt refers to"
                    )

    manifests_map: dict[str, dict[str, Any]] = {}
    provenance: dict[str, str] = {}
    chains: dict[str, list[dict[str, Any]]] = {}
    for issuer, versions in key_manifests_by_issuer.items():
        if not versions:
            continue
        ordered = sorted(versions, key=lambda m: _version_key(m, "manifest_version"))
        manifests_map[issuer] = ordered[-1]
        provenance[issuer] = _PROVENANCE_BUNDLE
        chains[issuer] = ordered

    for series, versions in artifact_manifests.items():
        artifact_manifests[series] = sorted(versions, key=lambda m: _version_key(m, "version"))

    trust_store = verify.TrustStore(manifests=manifests_map, provenance=provenance, chains=chains)

    salts: dict[str, bytes] = {}
    if private_path is not None:
        # The private half legitimately carries the salts the shareable half
        # must never hold: same reader, same decompression budget, no
        # private-material refusal.
        with _open_container(private_path, _SnapshotBudget(max_container_bytes)) as private_buf:
            private_members = _members(
                private_buf,
                max_entries=max_entries,
                max_member_bytes=max_member_bytes,
                max_total_bytes=max_total_bytes,
            )
            # v0.1 §14.2: a `.private.attest` MUST contain `salts.json`. A file
            # given as the private half without it is not a private half, and
            # importing it as one silently loses every buyer-binding secret the
            # caller believed they were handing over.
            if _PRIVATE_MEMBER not in private_members:
                raise BundleError(
                    f"private archive is missing {_PRIVATE_MEMBER} — it is not a .private.attest"
                )
            raw_salts = _loads(
                _read(private_buf, private_members[_PRIVATE_MEMBER], budget),
                label=_PRIVATE_MEMBER,
            )
            if not isinstance(raw_salts, dict):
                raise BundleError(f"{_PRIVATE_MEMBER} must be an object mapping receipt_id to salt")
            for salt_id, encoded in raw_salts.items():
                # v0.1 §14.2 keys this map by `receipt_id`, and §5.1 pins a
                # receipt_id to the ULID shape `RECEIPT_ID_RE` already holds —
                # the same shape an imported receipt must carry, since these
                # two maps are joined on it.
                if RECEIPT_ID_RE.fullmatch(salt_id) is None or not isinstance(encoded, str):
                    raise BundleError(
                        f"{_PRIVATE_MEMBER} must map uppercase ULID receipt ids "
                        "to base64url strings"
                    )
                try:
                    salt = keys.b64u_decode(encoded)
                except ValueError:
                    raise BundleError(
                        f"{_PRIVATE_MEMBER} has invalid base64url for receipt_id {salt_id!r}"
                    ) from None
                # v0.1 §8.1: a salt MUST be exactly 16 raw bytes. v0.1 §9.1:
                # salts MUST be encoded as base64url with the padding stripped,
                # so re-encoding what a conforming producer wrote returns the
                # very text it wrote.
                if len(salt) != 16 or keys.b64u(salt) != encoded:
                    raise BundleError(
                        f"{_PRIVATE_MEMBER} has a non-canonical or non-16-byte salt "
                        f"for receipt_id {salt_id!r}"
                    )
                salts[salt_id] = salt

    return ImportedBundle(
        receipts=receipts,
        trust_store=trust_store,
        artifact_manifests=artifact_manifests,
        legal_texts=legal_texts,
        salts=salts,
        proofs=proofs,
    )


def disclose(
    receipts: list[dict[str, Any]],
    key_manifests: list[dict[str, Any]],
    salts: dict[str, bytes],
    receipt_id: str,
    out: Path,
) -> Path:
    """Emit exactly one self-contained `.attest.json` for `receipt_id` (§9): its
    own salt (never the whole `salts` map) plus a key-manifest snapshot that
    still lists the kid that signed it, embedded in `delivery` so the file
    verifies standalone.

    `out` may be an existing directory (the file is written as
    `<receipt_id>.attest.json` inside it) or an exact destination path. A
    symlink passed as `out` is refused before directory routing.
    """
    envelope = next(
        (e for e in receipts if e.get("payload", {}).get("receipt_id") == receipt_id), None
    )
    if envelope is None:
        raise BundleError(f"no receipt with receipt_id {receipt_id!r} to disclose")

    payload = envelope["payload"]
    issuer_id = payload["issuer"]["id"]
    kid = envelope["signatures"][0]["kid"]

    candidates = [
        m
        for m in key_manifests
        if m.get("issuer") == issuer_id and manifests.find_key(m, kid) is not None
    ]
    if not candidates:
        # Fail closed: a disclosure with no key manifest listing the signing
        # kid could never verify standalone, which defeats disclose's whole
        # purpose (§9: "one receipt + its manifests + its salt"). Every other
        # path in this module raises rather than emit a silently-degraded
        # artifact; this one does too.
        raise BundleError(
            f"no key manifest for signing kid {kid!r}; cannot produce a self-contained disclosure"
        )
    manifest_snapshot = max(candidates, key=lambda m: m.get("manifest_version", 0))

    delivery: dict[str, Any] = {"issuer_manifest": manifest_snapshot}
    if receipt_id in salts:
        delivery["salt"] = keys.b64u(salts[receipt_id])

    disclosed: dict[str, Any] = {"payload": payload, "signatures": envelope["signatures"]}
    if delivery:
        disclosed["delivery"] = delivery

    # Second reference emitter of a receipt envelope: `disclosed` wraps the
    # payload in one more level, and `delivery` can push it over on its own. A
    # conforming issuer MUST NOT write a receipt no conforming verifier can
    # parse (v0.1 §11.3), so the check runs on the ASSEMBLED object, before the
    # file is created.
    canon.check_object_depth(disclosed)

    if out.is_symlink():
        raise BundleError(f"disclose output {out} is a symlink; refusing to overwrite it")
    target = out / f"{receipt_id}.attest.json" if out.is_dir() else out
    _write_secret_json(target, disclosed)
    return target
