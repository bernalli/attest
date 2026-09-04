#!/usr/bin/env python3
"""Feed the same file to both importers, at their own defaults, and compare.

`tools/container_differential.py` compares the two container READERS, with one
set of caps injected into both. That measurement cannot see the defect this one
exists for: the two importers wrap those readers in different budgets, reach
them by different doors, and go on to do different things with what comes back.
An archive can therefore travel through both readers identically and still be
imported by one and refused by the other — which is exactly the proposition the
specification denies (`docs/spec/attest-v0.1.md` §14.4).

So this runner works one layer up. It hands the same bytes to `import_bundle()`
and to the browser importer, invokes each AT ITS OWN DEFAULTS — no caps are
passed, because the defaults are themselves one of the things that can disagree
— and compares the outcome CLASS, the receipts, the trust material and the
evidence each one produced. It asks the browser side twice: once at
`parseBundle`, the parser a caller reaches with bytes in hand, and once at
`intake`, the door a FILE arrives at, where a name decides which road the bytes
take. A container that never reaches the parser is invisible to a differential
that only asks the parser.

Both browser entry points are reached THROUGH the admission boundary the two
shipped surfaces put in front of them: a container is refused on the size it
declares before any copy of it is made. That order is what §14.4 asks for, and
a runner that materialises the bytes and then consults the bound has already
spent what the bound exists to protect — so it cannot tell an importer that
holds the order from one that lost it. The stored-floor family is where the
difference is visible: the file declares a gigabyte and carries a hole.

Every bound, refusal class and member family below is written out from the
specification, never imported from either implementation. A generator that
takes its expectations from the code it is meant to judge cannot find the place
where that code is wrong; it stays green and reports coverage.

    python3 tools/importer_differential.py
    python3 tools/importer_differential.py --count 400 --seed 20260904
    python3 tools/importer_differential.py --families legal-hash,cap-boundary
    python3 tools/importer_differential.py --keep /tmp/importer-divergences

Build the browser package before every measurement — `site/` imports the
COMPILED verifier, so a stale build measures the previous revision's logic:

    npm ci --prefix verifiers/ts && npm run build --prefix verifiers/ts
    npm ci --prefix site

Exit status is non-zero when any divergence is found.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, cast

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from attest import bundle as py_importer  # noqa: E402
from attest import canon  # noqa: E402

# A ZIP encoder with every structural field overridable, shared with the
# container bench. It writes archives; it holds no opinion about which ones are
# readable, so taking the encoder from it borrows no expectation.
from tools.gen_container_corpus import Archive, Entry, build  # noqa: E402

# ---------------------------------------------------------------------------
# What the specification says. Transcribed, not imported.
# ---------------------------------------------------------------------------

#: `docs/spec/attest-v0.1.md` §14.4, table "Container bound / Floor". A
#: conforming importer MUST accept a container in which none of these four
#: quantities exceeds its floor value, measured on the container as stored, on
#: every value it declares, and on every value it produces when read.
FLOOR_STORED_BYTES = 1_073_741_824
FLOOR_MEMBER_COUNT = 10_000
FLOOR_MEMBER_DECOMPRESSED_BYTES = 67_108_864
FLOOR_TOTAL_DECOMPRESSED_BYTES = 268_435_456

#: §14.4, "Above the floor a refusal is `resource-limit`, and `resource-limit`
#: is not invalidity." The three classes an importer may report about a
#: container, plus the two this runner needs to describe answers the reference
#: importer has no way to give.
ACCEPT = "accept"
RESOURCE_LIMIT = "resource-limit"
MALFORMED = "malformed"
#: The bytes were taken for one receipt rather than for a container. Only a
#: file-name door can produce it, and §14.1 says a `.attest` is a container, so
#: reaching it for one is a disagreement about what the file even is.
BARE_ENVELOPE = "bare-envelope"
#: Neither an outcome nor a verdict: the implementation left its own error
#: vocabulary. Always a divergence, never a permitted one.
CRASH = "crash"

#: §5.1: `receipt_id` is a ULID, Crockford base32, 26 characters, leading
#: character bounded to `[0-7]`.
RECEIPT_ID_GRAMMAR = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")


def checked_receipt_id(receipt_id: str) -> str:
    """A vector's own receipt id, refused unless it is the shape §5.1 pins.

    A corpus whose ids are subtly off-grammar is refused by both importers for
    a reason that has nothing to do with what each vector measures, and every
    family below would agree about the wrong thing.
    """
    if RECEIPT_ID_GRAMMAR.fullmatch(receipt_id) is None:
        raise SystemExit(f"vector receipt id {receipt_id!r} is not the shape §5.1 requires")
    return receipt_id


#: §14.1: what a `<name>.attest` contains. Member families are named here so a
#: vector can move a member between them on purpose.
RECEIPTS_PREFIX = "receipts/"
RECEIPTS_SUFFIX = ".attest.json"
MANIFESTS_PREFIX = "manifests/"
MANIFESTS_SUFFIX = ".json"
LEGAL_PREFIX = "legal/"
LEGAL_SUFFIX = ".txt"
PROOFS_PREFIX = "proofs/"
#: §14.2: what a `<name>.private.attest` MUST contain.
PRIVATE_MEMBER = "salts.json"

#: §14.4: the member-count floor is deliberately below 65,534, the widest count
#: an end-of-central-directory record can state without ZIP64. The name-length
#: field beside it is 16 bits and nothing caps it, which is the axis the stored
#: bound was added to cover.
ZIP_UINT16_MAX = 0xFFFF

#: The name a file arrives under at the application door. §14.1 makes a
#: `.attest` a container, so this is the name whose road both sides must agree
#: on. Not `.private.attest`, which §14.2 makes a different question.
INTAKE_FILE_NAME = "library.attest"

# ---------------------------------------------------------------------------
# The browser side, behind esbuild.
# ---------------------------------------------------------------------------

ESBUILD = REPO_ROOT / "site" / "node_modules" / ".bin" / "esbuild"
SITE_SRC = REPO_ROOT / "site" / "src"
ADAPTER = REPO_ROOT / "tools" / "importer_adapter_ts.mjs"

#: The browser importer's two entry points plus the canonicalizer the
#: projection needs, gathered into one module esbuild can bundle. Fed on stdin
#: so nothing is written into `site/`, and resolved from `site/src` so the
#: package import finds the site's own installation.
TS_ENTRY = (
    "export { intake, declinedForSize } from './intake.js'\n"
    "export { parseBundle, BundleError, BundleTooLargeError, PrivateBundleError }"
    " from './bundle.js'\n"
    "export { canonicalBytes, loadsStrict } from 'attest-verifier'\n"
)

# ---------------------------------------------------------------------------
# Vectors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Vector:
    """One file, and what is known about it before either importer sees it."""

    family: str
    name: str
    attest: bytes
    #: A `.private.attest` sibling, for the one property §14.4 states about a
    #: pair rather than about a container.
    private: bytes | None = None
    #: When set, the file on disk is extended to this length with a hole after
    #: `attest` has been written. What it costs is a few kilobytes; what it
    #: DECLARES is this size, which is the quantity §14.4's stored bound is
    #: measured on and the only one a surface may consult before it copies.
    sparse_to: int | None = None
    #: True when the archive exceeds a §14.4 floor on some axis. Above the
    #: floor the specification permits one importer to report `resource-limit`
    #: where another reads on, so a divergence there is recorded and marked
    #: rather than counted as a defect of conformance.
    above_floor: bool = False
    #: True when the file is not a container at all. §14.1 reserves the name
    #: for one, so the two importers meeting it differently is worth reporting;
    #: it is not a conformance failure, because the browser door answers a
    #: wider question than the reference importer is ever asked, and nothing in
    #: the specification says it may not. Reported, never counted.
    advisory: bool = False
    #: The review finding this vector reproduces, when it reproduces one.
    finding: str = ""
    note: str = ""


ISSUER = "h.example"
OTHER_ISSUER = "i.example"
RECEIPT_ID = checked_receipt_id("01JBXYZ0000000000000000000")
SECOND_RECEIPT_ID = checked_receipt_id("01JBXYZ0000000000000000001")
LEGAL_TEXT = b"the terms of the deal this receipt refers to\n"
LEGAL_DIGEST = hashlib.sha256(LEGAL_TEXT).hexdigest()
#: A digest-shaped name that is not this text's digest. §14.1 binds a legal
#: member to its hash; a member whose name lies about its content is the case
#: that tells whether an importer checks the binding or trusts the name.
WRONG_DIGEST = "0" * 64
ABSENT_DIGEST = "1" * 64


def _json_bytes(value: Any) -> bytes:
    """Serialise a vector's JSON with the standard library, never with the
    canonicalizer under test. Both importers strict-parse what arrives, and
    neither requires canonical ordering to do it."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _receipt(receipt_id: str = RECEIPT_ID, *, legal: str | None = LEGAL_DIGEST) -> bytes:
    payload: dict[str, Any] = {"receipt_id": receipt_id}
    if legal is not None:
        payload["license"] = {"legal_text_sha256": legal}
    return _json_bytes({"payload": payload})


def _manifest(issuer: str = ISSUER, *, version: int = 1) -> bytes:
    return _json_bytes(
        {
            "issuer": issuer,
            "key_manifests": [{"issuer": issuer, "keys": [], "manifest_version": version}],
        }
    )


def _proof(receipt_id: str = RECEIPT_ID) -> bytes:
    return _json_bytes({"entry": {"receipt_id": receipt_id}})


def _receipt_name(receipt_id: str = RECEIPT_ID) -> bytes:
    return f"{RECEIPTS_PREFIX}{receipt_id}{RECEIPTS_SUFFIX}".encode()


def _legal_name(digest: str = LEGAL_DIGEST) -> bytes:
    return f"{LEGAL_PREFIX}{digest}{LEGAL_SUFFIX}".encode()


def _proof_name(receipt_id: str = RECEIPT_ID) -> bytes:
    return f"{PROOFS_PREFIX}{receipt_id}{MANIFESTS_SUFFIX}".encode()


def sound_entries() -> list[Entry]:
    """A bundle §14.1 describes: one receipt, its issuer's manifests, the legal
    text its terms are bound to, and one evidence member. Every vector below is
    this archive with one thing done to it, so a refusal is attributable."""
    return [
        Entry(name=f"{MANIFESTS_PREFIX}h{MANIFESTS_SUFFIX}".encode(), data=_manifest()),
        Entry(name=_receipt_name(), data=_receipt()),
        Entry(name=_legal_name(), data=LEGAL_TEXT),
        Entry(name=_proof_name(), data=_proof()),
    ]


def private_entries() -> list[Entry]:
    """§14.2: a private half MUST carry `salts.json`."""
    salt = _json_bytes({RECEIPT_ID: "AAAAAAAAAAAAAAAAAAAAAA"})
    return [Entry(name=PRIVATE_MEMBER.encode(), data=salt)]


_DEFLATED_ZEROS: dict[int, bytes] = {}


def _deflate_zeros(size: int) -> bytes:
    """A genuine DEFLATE stream for `size` zero bytes, so a member declaring a
    large uncompressed size is telling the truth about one. Cached: the cap
    vectors ask for the same few sizes repeatedly."""
    cached = _DEFLATED_ZEROS.get(size)
    if cached is None:
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        cached = compressor.compress(b"\x00" * size) + compressor.flush()
        _DEFLATED_ZEROS[size] = cached
    return cached


def _bulk_member(name: bytes, size: int) -> Entry:
    """A member outside every family §14.1 names, so no importer reads it, that
    honestly declares `size` decompressed bytes. It is how the declared axes of
    the floor are reached without an archive of that size on disk."""
    return Entry(
        name=name,
        method=8,
        raw_compressed=_deflate_zeros(size),
        usize=size,
        crc=zlib.crc32(b"\x00" * size) & 0xFFFFFFFF,
    )


def _permute_directory(raw: bytes, order: Callable[[int], int]) -> bytes:
    """Rewrite the central directory with its records in another order.

    The order of the records is not the order of the members: a reader that
    walks the directory meets them as the directory lists them, and nothing in
    the format requires that to follow the layout. Reordering the records
    leaves every offset, size and payload untouched, so the archive still
    describes exactly the same members — which is what makes a disagreement
    here a disagreement about the reading and not about the content.
    """
    eocd = raw.rfind(struct.pack("<I", 0x06054B50))
    if eocd < 0 or eocd + 22 > len(raw):
        return raw
    size_cd, off_cd = struct.unpack("<II", raw[eocd + 12 : eocd + 20])
    if off_cd + size_cd > len(raw):
        return raw
    directory = raw[off_cd : off_cd + size_cd]
    records: list[bytes] = []
    cursor = 0
    while cursor + 46 <= len(directory):
        name_len, extra_len, comment_len = struct.unpack(
            "<HHH", directory[cursor + 28 : cursor + 34]
        )
        end = cursor + 46 + name_len + extra_len + comment_len
        if end > len(directory):
            return raw
        records.append(directory[cursor:end])
        cursor = end
    if cursor != len(directory) or len(records) < 2:
        return raw
    indices = sorted(range(len(records)), key=order)
    shuffled = b"".join(records[index] for index in indices)
    return raw[:off_cd] + shuffled + raw[off_cd + size_cd :]


# ---------------------------------------------------------------------------
# The property families
# ---------------------------------------------------------------------------


def _directory_permuter(rank: dict[int, int]) -> Callable[[bytes], bytes]:
    """A transform that rewrites the central directory in `rank`'s order.

    A record the order says nothing about keeps its own place. A mutation that
    adds a member after the order was drawn is the ordinary case, and it must
    not turn the archive into an exception instead of a vector.
    """

    def permute(raw: bytes) -> bytes:
        return _permute_directory(raw, lambda index: rank.get(index, index))

    return permute


def _vector(
    family: str,
    name: str,
    entries: list[Entry],
    *,
    above_floor: bool = False,
    advisory: bool = False,
    finding: str = "",
    note: str = "",
    post: Callable[[bytes], bytes] | None = None,
    **archive: Any,
) -> Vector:
    raw = build(Archive(entries=entries, **archive))
    if post is not None:
        raw = post(raw)
    return Vector(
        family=family,
        name=name,
        attest=raw,
        above_floor=above_floor,
        advisory=advisory,
        finding=finding,
        note=note,
    )


def family_baseline() -> list[Vector]:
    """The archive every other vector is a mutation of. If the two importers
    disagree here, nothing below means anything."""
    return [_vector("baseline", "sound-bundle", sound_entries())]


def family_duplicate_names() -> list[Vector]:
    """§14.1: member names within a bundle MUST be unique, and an importer MUST
    reject a directory that repeats one rather than resolve it silently."""
    vectors: list[Vector] = []
    for label, extra in (
        ("receipt", Entry(name=_receipt_name(), data=_receipt())),
        (
            "manifest",
            Entry(name=f"{MANIFESTS_PREFIX}h{MANIFESTS_SUFFIX}".encode(), data=_manifest()),
        ),
        ("legal", Entry(name=_legal_name(), data=LEGAL_TEXT)),
        ("proof", Entry(name=_proof_name(), data=_proof())),
    ):
        vectors.append(_vector("duplicate-names", f"repeat-{label}", [*sound_entries(), extra]))
    # The repeat carrying DIFFERENT content, which is the shape where "resolve
    # to one entry" and "reject" produce visibly different imports.
    vectors.append(
        _vector(
            "duplicate-names",
            "repeat-receipt-other-content",
            [*sound_entries(), Entry(name=_receipt_name(), data=_receipt(SECOND_RECEIPT_ID))],
        )
    )
    return vectors


def family_long_names() -> list[Vector]:
    """Name length is a 16-bit field and §14.4 caps nothing inside the
    container, so the whole range is admissible input. The interesting lengths
    are the ones near the field's own ceiling, which no example list reaches."""
    vectors: list[Vector] = []
    for length in (1, 255, 1_200, 8_192, ZIP_UINT16_MAX - 1, ZIP_UINT16_MAX):
        name = b"x" * length
        vectors.append(
            _vector("long-names", f"filler-name-{length}", [*sound_entries(), Entry(name=name)])
        )
    # The same length carried by a member that IS read, so the name travels
    # through the family match, the JSON parse and the id check as well.
    for length in (1_200, ZIP_UINT16_MAX):
        padding = length - len(_receipt_name())
        if padding <= 0:
            continue
        long_receipt = _receipt_name() + b"x" * padding
        vectors.append(
            _vector(
                "long-names",
                f"unread-receipt-name-{length}",
                [*sound_entries(), Entry(name=long_receipt, data=_receipt(SECOND_RECEIPT_ID))],
            )
        )
    # Many long names at once: the shape §14.4 cites as the reason the stored
    # size became an axis of its own, at a size this runner can afford.
    many = [Entry(name=b"pad/" + bytes([65 + index % 26]) * 4_000) for index in range(64)]
    vectors.append(_vector("long-names", "many-long-names", [*sound_entries(), *many]))
    return vectors


def family_unreferenced_regions() -> list[Vector]:
    """§14.4: the canonical reading requires no contiguity between members, so
    gaps and unreferenced regions are admissible. Both importers must agree on
    exactly which of them stay admissible."""
    vectors: list[Vector] = []
    for gap in (1, 3, 4, 512, 4_096):
        entries = sound_entries()
        entries[2] = replace(entries[2], gap_before=gap)
        vectors.append(_vector("unreferenced-regions", f"gap-{gap}", entries))
    whole_file: list[tuple[str, dict[str, Any]]] = [
        ("prefix-stub", {"prefix": b"MZ\x90\x00 self-extracting stub "}),
        ("prefix-one-byte", {"prefix": b"\x00"}),
        ("prefix-pk-lookalike", {"prefix": b"PK\x00\x00"}),
        ("suffix-bytes", {"suffix": b"\x00" * 32}),
        ("directory-trailing-bytes", {"extra_records": b"\x00\x00\x00\x00"}),
        ("eocd-comment", {"eocd_comment": b"a comment nobody reads"}),
    ]
    for label, extra in whole_file:
        finding = "finding 4" if label.startswith("prefix-") else ""
        vectors.append(
            _vector(
                "unreferenced-regions",
                label,
                sound_entries(),
                finding=finding,
                note="a container the file-name door may not recognise as one" if finding else "",
                **extra,
            )
        )
    return vectors


def family_declared_vs_produced() -> list[Vector]:
    """§14.4: a container that declares one thing and produces another is
    within the floor on neither reading, and is malformed besides."""
    vectors: list[Vector] = []
    for delta in (-1, 1, 64):
        for label in ("usize", "csize"):
            entries = sound_entries()
            base = len(entries[2].data)
            override: dict[str, Any] = {label: max(base + delta, 0)}
            entries[2] = replace(entries[2], **override)
            vectors.append(_vector("declared-vs-produced", f"legal-{label}{delta:+d}", entries))
    entries = sound_entries()
    entries[1] = replace(entries[1], crc=0xDEADBEEF)
    vectors.append(_vector("declared-vs-produced", "receipt-crc-wrong", entries))
    entries = sound_entries()
    entries[0] = replace(entries[0], local_csize=len(entries[0].data) + 1)
    vectors.append(_vector("declared-vs-produced", "manifest-local-csize-off", entries))
    entries = sound_entries()
    entries[3] = replace(entries[3], local_name=b"proofs/other.json")
    vectors.append(_vector("declared-vs-produced", "proof-local-name-differs", entries))
    return vectors


def family_truncation() -> list[Vector]:
    """A file that stops. Where it stops decides which reader notices first."""
    whole = build(Archive(entries=sound_entries()))
    vectors: list[Vector] = []
    for fraction in (1, 8, 16, 32, 50, 75, 90, 99):
        cut = len(whole) * fraction // 100
        vectors.append(
            _vector("truncation", f"cut-at-{fraction}pc", sound_entries(), truncate_at=cut)
        )
    for tail in (1, 2, 21, 22, 46):
        vectors.append(
            _vector(
                "truncation", f"cut-{tail}-from-end", sound_entries(), truncate_at=len(whole) - tail
            )
        )
    return vectors


def family_central_order() -> list[Vector]:
    """The directory need not list members in the order they were laid out.
    One example proves nothing here — a reader can be right about one
    permutation and wrong about the next — so every permutation of the sound
    bundle's records is fed through.

    Enumerated rather than listed: a hand-written table of orderings is a
    sample that calls itself exhaustive, and this one was, covering a quarter
    of the orderings of four records under a docstring claiming all of them.
    `itertools.permutations` cannot drift from the member count, so the claim
    holds as the sound bundle grows.
    """
    vectors: list[Vector] = []
    for order in itertools.permutations(range(len(sound_entries()))):
        rank = {position: place for place, position in enumerate(order)}
        vectors.append(
            _vector(
                "central-order",
                "permutation-" + "".join(str(position) for position in order),
                sound_entries(),
                post=_directory_permuter(rank),
            )
        )
    return vectors


def family_json_shape() -> list[Vector]:
    """Fields absent, fields extra, fields of the wrong type — on every member
    family an importer parses. A table of examples shares the blind spots of
    whoever wrote it, so the table below is crossed with the families rather
    than written per case."""
    vectors: list[Vector] = []
    receipt_shapes: dict[str, bytes] = {
        "no-payload": _json_bytes({"signature": "x"}),
        "payload-not-object": _json_bytes({"payload": []}),
        "payload-array-of-pairs": _json_bytes({"payload": [["receipt_id", RECEIPT_ID]]}),
        "no-receipt-id": _json_bytes({"payload": {"license": {}}}),
        "receipt-id-not-string": _json_bytes({"payload": {"receipt_id": 1}}),
        "receipt-id-lowercase": _json_bytes({"payload": {"receipt_id": RECEIPT_ID.lower()}}),
        "receipt-id-too-short": _json_bytes({"payload": {"receipt_id": RECEIPT_ID[:-1]}}),
        "receipt-id-out-of-alphabet": _json_bytes(
            {"payload": {"receipt_id": "I" + RECEIPT_ID[1:]}}
        ),
        "extra-top-level": _json_bytes(
            {"payload": {"receipt_id": RECEIPT_ID}, "unknown": {"a": 1}}
        ),
        "empty-object": b"{}",
        "top-level-array": b"[]",
        "top-level-string": b'"receipt"',
        "not-json": b"receipt",
        "empty": b"",
    }
    for label, data in receipt_shapes.items():
        entries = sound_entries()
        entries[1] = replace(entries[1], data=data)
        vectors.append(_vector("json-shape", f"receipt-{label}", entries))

    manifest_shapes: dict[str, bytes] = {
        "no-issuer": _json_bytes({"key_manifests": []}),
        "issuer-not-string": _json_bytes({"issuer": 7, "key_manifests": []}),
        "key-manifests-absent": _json_bytes({"issuer": ISSUER}),
        "key-manifests-not-array": _json_bytes({"issuer": ISSUER, "key_manifests": {}}),
        "key-manifest-not-object": _json_bytes({"issuer": ISSUER, "key_manifests": [1, "x", None]}),
        "key-manifests-empty": _json_bytes({"issuer": ISSUER, "key_manifests": []}),
        "version-not-integer": _json_bytes(
            {"issuer": ISSUER, "key_manifests": [{"manifest_version": "2"}]}
        ),
        "version-boolean": _json_bytes(
            {"issuer": ISSUER, "key_manifests": [{"manifest_version": True}]}
        ),
        "version-negative": _json_bytes(
            {"issuer": ISSUER, "key_manifests": [{"manifest_version": -3}]}
        ),
        "top-level-array": b"[]",
        "not-json": b"manifest",
    }
    for label, data in manifest_shapes.items():
        entries = sound_entries()
        entries[0] = replace(entries[0], data=data)
        vectors.append(_vector("json-shape", f"manifest-{label}", entries))

    proof_shapes: dict[str, bytes] = {
        "array": b"[]",
        "string": b'"evidence"',
        "number": b"1",
        "null": b"null",
        "not-json": b"proof",
        "empty-object": b"{}",
    }
    for label, data in proof_shapes.items():
        entries = sound_entries()
        entries[3] = replace(entries[3], data=data)
        vectors.append(_vector("json-shape", f"proof-{label}", entries))
    for label, name in (
        ("bad-grammar", b"proofs/not-a-ulid.json"),
        ("no-suffix", f"{PROOFS_PREFIX}{RECEIPT_ID}".encode()),
        ("nested", f"{PROOFS_PREFIX}a/{RECEIPT_ID}{MANIFESTS_SUFFIX}".encode()),
        ("bare-prefix", PROOFS_PREFIX.encode()),
    ):
        entries = sound_entries()
        entries[3] = replace(entries[3], name=name)
        vectors.append(_vector("json-shape", f"proof-name-{label}", entries))
    return vectors


def family_duplicate_json_keys() -> list[Vector]:
    """A member that names one key twice. Written as raw text, since no
    serializer will produce it."""
    cases: dict[str, tuple[int, bytes]] = {
        "receipt-payload-twice": (
            1,
            b'{"payload":{"receipt_id":"' + RECEIPT_ID.encode() + b'"},"payload":{}}',
        ),
        "receipt-id-twice": (
            1,
            b'{"payload":{"receipt_id":"'
            + RECEIPT_ID.encode()
            + b'","receipt_id":"'
            + SECOND_RECEIPT_ID.encode()
            + b'"}}',
        ),
        "manifest-issuer-twice": (
            0,
            b'{"issuer":"' + ISSUER.encode() + b'","issuer":"' + OTHER_ISSUER.encode() + b'"}',
        ),
        "proof-entry-twice": (3, b'{"entry":1,"entry":2}'),
    }
    vectors: list[Vector] = []
    for label, (index, data) in cases.items():
        entries = sound_entries()
        entries[index] = replace(entries[index], data=data)
        vectors.append(_vector("duplicate-json-keys", label, entries))
    return vectors


def family_out_of_range() -> list[Vector]:
    """Values at and past the edges the format and the profile define: the
    integer boundary §9 draws around canonical JSON, and the 16- and 32-bit
    fields the container's own records are made of."""
    vectors: list[Vector] = []
    boundary = 2**53 - 1
    for label, version in (
        ("version-at-integer-boundary", boundary),
        ("version-past-integer-boundary", boundary + 1),
        ("version-negative-boundary", -boundary),
        ("version-past-negative-boundary", -boundary - 1),
    ):
        entries = sound_entries()
        entries[0] = replace(
            entries[0],
            data=_json_bytes(
                {
                    "issuer": ISSUER,
                    "key_manifests": [
                        {"issuer": ISSUER, "manifest_version": 1},
                        {"issuer": ISSUER, "manifest_version": version},
                    ],
                }
            ),
        )
        vectors.append(_vector("out-of-range", label, entries))

    record_fields: list[tuple[str, dict[str, Any]]] = [
        ("name-len-past-name", {"name_len": ZIP_UINT16_MAX}),
        ("extra-len-past-extra", {"extra_len": ZIP_UINT16_MAX}),
        ("comment-len-past-comment", {"comment_len": ZIP_UINT16_MAX}),
        ("lho-past-file", {"lho": 0xFFFFFFFF}),
        ("disk-start-nonzero", {"disk_start": 1}),
    ]
    for label, override in record_fields:
        entries = sound_entries()
        entries[2] = replace(entries[2], **override)
        vectors.append(_vector("out-of-range", label, entries))

    whole_file: list[tuple[str, dict[str, Any]]] = [
        ("entry-count-sentinel", {"n_total": ZIP_UINT16_MAX, "n_disk": ZIP_UINT16_MAX}),
        ("entry-count-one-short", {"n_total": len(sound_entries()) - 1}),
        ("entry-count-one-long", {"n_total": len(sound_entries()) + 1}),
        ("counts-disagree", {"n_disk": 1}),
        ("zip64-locator", {"zip64_locator": True}),
    ]
    for label, archive in whole_file:
        vectors.append(_vector("out-of-range", label, sound_entries(), **archive))
    return vectors


def family_semantic_duplicates() -> list[Vector]:
    """Two members that name the same thing without repeating a member name.
    §14.1's uniqueness rule does not reach these: the archive is well formed
    and the collision is in what the members SAY."""
    vectors: list[Vector] = []
    for label, first, second in (
        ("same-issuer-same-version", _manifest(version=1), _manifest(version=1)),
        ("same-issuer-rising-version", _manifest(version=1), _manifest(version=2)),
        ("same-issuer-falling-version", _manifest(version=2), _manifest(version=1)),
    ):
        for order in ("a-then-b", "b-then-a"):
            names = (b"manifests/a.json", b"manifests/b.json")
            payloads = (first, second) if order == "a-then-b" else (second, first)
            entries = sound_entries()[1:]
            entries = [
                Entry(name=names[0], data=payloads[0]),
                Entry(name=names[1], data=payloads[1]),
                *entries,
            ]
            vectors.append(_vector("semantic-duplicates", f"{label}-{order}", entries))
    # Two receipts whose members differ but whose signed ids do not. §14.1
    # forbids producing one; an importer still has to answer for one.
    entries = sound_entries()
    entries.append(Entry(name=_receipt_name(SECOND_RECEIPT_ID), data=_receipt(RECEIPT_ID)))
    vectors.append(_vector("semantic-duplicates", "two-members-one-receipt-id", entries))
    # Two proof members keyed to the same receipt, one by its own name.
    entries = sound_entries()
    entries.append(Entry(name=_proof_name(SECOND_RECEIPT_ID), data=_proof(RECEIPT_ID)))
    vectors.append(_vector("semantic-duplicates", "second-proof-other-id", entries))
    return vectors


def family_legal_hash() -> list[Vector]:
    """§14.1 binds each `legal/<sha256>.txt` to its hash, and requires a bundle
    to preserve the deal rather than the signature alone. Three shapes decide
    whether an importer checks the binding: a name that is the content's
    digest, a name that is not, and a digest a receipt depends on that no
    member supplies."""
    vectors: list[Vector] = []

    entries = sound_entries()
    vectors.append(_vector("legal-hash", "digest-matches-content", entries))

    entries = sound_entries()
    entries[1] = replace(entries[1], data=_receipt(legal=WRONG_DIGEST))
    entries[2] = replace(entries[2], name=_legal_name(WRONG_DIGEST))
    vectors.append(
        _vector(
            "legal-hash",
            "digest-lies-about-content",
            entries,
            finding="finding 5",
            note="the member's name is not the digest of the member's bytes",
        )
    )

    entries = sound_entries()
    entries[1] = replace(entries[1], data=_receipt(legal=ABSENT_DIGEST))
    vectors.append(
        _vector(
            "legal-hash",
            "referenced-digest-absent",
            entries,
            note="a receipt whose terms no member supplies",
        )
    )

    entries = sound_entries()
    entries[1] = replace(entries[1], data=_receipt(legal=None))
    vectors.append(_vector("legal-hash", "unreferenced-legal-member", entries))

    entries = sound_entries()
    entries[2] = replace(entries[2], name=_legal_name(LEGAL_DIGEST.upper()))
    vectors.append(_vector("legal-hash", "digest-case-flipped", entries))

    entries = sound_entries()
    entries[2] = replace(entries[2], name=f"{LEGAL_PREFIX}short{LEGAL_SUFFIX}".encode())
    entries[1] = replace(entries[1], data=_receipt(legal=None))
    vectors.append(_vector("legal-hash", "name-not-digest-shaped", entries))

    entries = sound_entries()
    entries[2] = replace(entries[2], data=LEGAL_TEXT + b" ")
    vectors.append(_vector("legal-hash", "content-one-byte-longer", entries))
    return vectors


def family_cap_boundary() -> list[Vector]:
    """§14.4's floors, exactly at the floor and one past it, on each axis this
    runner can reach without a container of that size on disk.

    Exactly at the floor a conforming importer MUST accept; one past it, the
    specification permits one importer to report `resource-limit` where another
    reads on, so those vectors are marked above the floor.
    """
    vectors: list[Vector] = []

    # Member count. The sound bundle's own members count towards it.
    base = sound_entries()
    for label, count, above in (
        ("members-at-floor", FLOOR_MEMBER_COUNT, False),
        ("members-one-past-floor", FLOOR_MEMBER_COUNT + 1, True),
    ):
        padding = [
            Entry(name=f"pad/{index:06d}.bin".encode()) for index in range(count - len(base))
        ]
        vectors.append(
            _vector(
                "cap-boundary",
                label,
                [*base, *padding],
                above_floor=above,
                finding="finding 2" if above else "",
            )
        )

    # Decompressed size of any single member.
    for label, size, above in (
        ("single-member-at-floor", FLOOR_MEMBER_DECOMPRESSED_BYTES, False),
        ("single-member-one-past-floor", FLOOR_MEMBER_DECOMPRESSED_BYTES + 1, True),
    ):
        vectors.append(
            _vector(
                "cap-boundary",
                label,
                [*sound_entries(), _bulk_member(b"pad/bulk.bin", size)],
                above_floor=above,
            )
        )

    # Decompressed size of the whole container, counting the sound bundle's own
    # members so the archive lands on the floor and not near it.
    spent = sum(len(entry.data) for entry in sound_entries())
    for label, target, above in (
        ("container-at-floor", FLOOR_TOTAL_DECOMPRESSED_BYTES, False),
        ("container-one-past-floor", FLOOR_TOTAL_DECOMPRESSED_BYTES + 1, True),
    ):
        remaining = target - spent
        bulk: list[Entry] = []
        index = 0
        while remaining > 0:
            size = min(remaining, FLOOR_MEMBER_DECOMPRESSED_BYTES)
            bulk.append(_bulk_member(f"pad/bulk-{index}.bin".encode(), size))
            remaining -= size
            index += 1
        vectors.append(_vector("cap-boundary", label, [*sound_entries(), *bulk], above_floor=above))
    return vectors


def family_stored_floor() -> list[Vector]:
    """§14.4's stored bound, on a container that DECLARES more than the floor.

    The floor is a gigabyte, and no run can afford a gigabyte of content per
    archive on both sides. It can afford the DECLARATION. A file whose length
    is one byte past the floor and whose tail is a hole costs a few kilobytes
    on disk and still reports the size a surface has to refuse it on, because
    the size of a regular file is metadata and asking for it reads none of it.

    That is what makes this vector a measurement of the order rather than of
    the answer. Both importers refuse it — the reference one from `os.fstat`
    before it takes its snapshot, the browser one from the size the file
    declares before it materialises anything — so the outcome class alone
    cannot tell an importer that consults the size from one that copies a
    gigabyte and then reports a limit. What separates them is the spend, and
    an implementation that spends it is not merely slow here: it has already
    paid exactly what the bound exists to protect.
    """
    return [
        Vector(
            family="stored-floor",
            name="declares-one-past-the-floor",
            attest=build(Archive(entries=sound_entries())),
            sparse_to=FLOOR_STORED_BYTES + 1,
            above_floor=True,
            note="refused on the size it declares, before a byte of it is read",
        )
    ]


def family_intake_route() -> list[Vector]:
    """§14.1 makes a `.attest` a container. Every vector here IS one; what
    varies is whether the leading bytes announce it. An importer that decides
    from the first two bytes takes a different road for the same file."""
    vectors: list[Vector] = []
    for label, prefix in (
        ("clean", b""),
        ("stub-prefix", b"MZ\x90\x00 self-extracting stub "),
        ("single-null", b"\x00"),
        ("newline", b"\n"),
        ("utf8-bom", b"\xef\xbb\xbf"),
    ):
        vectors.append(
            _vector(
                "intake-route",
                label,
                sound_entries(),
                prefix=prefix,
                finding="finding 4" if prefix else "",
            )
        )
    # A container that carries private material. §14.2 keeps those in the other
    # file, and both importers refuse a shareable half that holds them, so the
    # two must refuse the same way.
    vectors.append(_vector("intake-route", "carries-salts", [*sound_entries(), *private_entries()]))
    vectors.append(
        _vector(
            "intake-route",
            "carries-keys",
            [*sound_entries(), Entry(name=b"keys/" + RECEIPT_ID.encode() + b".json", data=b"{}")],
        )
    )
    return vectors


def family_not_a_container() -> list[Vector]:
    """Files that are not containers, under the name §14.1 reserves for one.

    Advisory, and deliberately so. The reference importer is only ever called
    on a bundle and answers `malformed` for anything else; the browser door is
    called on whatever a person drops, and reads a bare receipt whatever it is
    named. Neither is wrong under the specification, so a disagreement here is
    reported and not counted — but it is worth seeing, because it is the same
    road a container with an unrecognised first byte takes.
    """
    vectors: list[Vector] = []
    for label, raw in (
        ("empty-file", b""),
        ("two-bytes", b"PK"),
        ("bare-envelope-bytes", _receipt()),
        (
            "bare-envelope-with-manifest",
            _json_bytes(
                {
                    "delivery": {"issuer_manifest": {"issuer": ISSUER, "keys": []}},
                    "payload": {"receipt_id": RECEIPT_ID},
                }
            ),
        ),
    ):
        vectors.append(Vector(family="not-a-container", name=label, attest=raw, advisory=True))
    return vectors


def family_no_receipts() -> list[Vector]:
    """§14.1: a bundle IS its receipts. An archive that carries none is not a
    stripped bundle, and both importers have to say so the same way."""
    vectors: list[Vector] = []
    entries = [entry for entry in sound_entries() if not entry.name.startswith(b"receipts/")]
    vectors.append(_vector("no-receipts", "manifests-and-legal-only", entries))
    vectors.append(_vector("no-receipts", "empty-directory", []))
    entries = sound_entries()
    entries[1] = replace(entries[1], name=b"receipts/" + RECEIPT_ID.encode() + b".json")
    vectors.append(_vector("no-receipts", "receipt-wrong-suffix", entries))
    entries = sound_entries()
    entries[1] = replace(entries[1], name=b"receipt/" + RECEIPT_ID.encode() + b".attest.json")
    vectors.append(_vector("no-receipts", "receipt-wrong-prefix", entries))
    return vectors


DETERMINISTIC_FAMILIES: dict[str, Callable[[], list[Vector]]] = {
    "baseline": family_baseline,
    "duplicate-names": family_duplicate_names,
    "long-names": family_long_names,
    "unreferenced-regions": family_unreferenced_regions,
    "declared-vs-produced": family_declared_vs_produced,
    "truncation": family_truncation,
    "central-order": family_central_order,
    "json-shape": family_json_shape,
    "duplicate-json-keys": family_duplicate_json_keys,
    "out-of-range": family_out_of_range,
    "semantic-duplicates": family_semantic_duplicates,
    "legal-hash": family_legal_hash,
    "cap-boundary": family_cap_boundary,
    "stored-floor": family_stored_floor,
    "intake-route": family_intake_route,
    "not-a-container": family_not_a_container,
    "no-receipts": family_no_receipts,
}

MUTATION_FAMILY = "mutation"
PAIR_FAMILY = "pair-floor"
ALL_FAMILIES = (*DETERMINISTIC_FAMILIES, MUTATION_FAMILY, PAIR_FAMILY)


# ---------------------------------------------------------------------------
# The randomised stratum
# ---------------------------------------------------------------------------

_MUTATION_NAMES = (
    "receipts/{id}.attest.json",
    "manifests/{index}.json",
    "legal/{digest}.txt",
    "proofs/{id}.json",
    "README.html",
    "salts.json",
    "keys/{id}.json",
    "pad/{index}.bin",
    "legal/﻿{digest}.txt",
    "manifests/café-{index}.json",
    "proofs/\U0001f600{index}.json",
)

_MUTATION_PAYLOADS = (
    b"{}",
    b"[]",
    b"null",
    b"0",
    b'"x"',
    b"",
    b"not json",
    b'{"a":1,"a":2}',
    b'{"issuer":"h.example","key_manifests":[{"manifest_version":9007199254740992}]}',
)


@dataclass
class _Draft:
    """A bundle being mutated: members, whole-file overrides, byte rewrites."""

    entries: list[Entry]
    archive: dict[str, Any] = field(default_factory=dict)
    post: list[Callable[[bytes], bytes]] = field(default_factory=list)


def _mutate_rename(rng: random.Random, draft: _Draft) -> None:
    index = rng.randrange(len(draft.entries))
    shape = rng.choice(_MUTATION_NAMES)
    name = shape.format(
        id=rng.choice((RECEIPT_ID, SECOND_RECEIPT_ID, "not-a-ulid", RECEIPT_ID.lower())),
        index=rng.randrange(4),
        digest=rng.choice((LEGAL_DIGEST, WRONG_DIGEST, "short")),
    )
    draft.entries[index] = replace(draft.entries[index], name=name.encode())


def _mutate_payload(rng: random.Random, draft: _Draft) -> None:
    index = rng.randrange(len(draft.entries))
    draft.entries[index] = replace(draft.entries[index], data=rng.choice(_MUTATION_PAYLOADS))


def _mutate_duplicate(rng: random.Random, draft: _Draft) -> None:
    index = rng.randrange(len(draft.entries))
    draft.entries.append(replace(draft.entries[index], data=b"a different member, same name"))


def _mutate_long_name(rng: random.Random, draft: _Draft) -> None:
    index = rng.randrange(len(draft.entries))
    entry = draft.entries[index]
    # The name-length field is 16 bits wide, so a name past it is not a longer
    # name, it is an archive no encoder can write.
    length = min(
        rng.choice((200, 4_000, 30_000, ZIP_UINT16_MAX - 1, ZIP_UINT16_MAX)),
        ZIP_UINT16_MAX - len(entry.name),
    )
    if length <= 0:
        return
    draft.entries[index] = replace(entry, name=entry.name + b"y" * length)


def _mutate_gap(rng: random.Random, draft: _Draft) -> None:
    index = rng.randrange(len(draft.entries))
    draft.entries[index] = replace(draft.entries[index], gap_before=rng.choice((1, 3, 7, 1_024)))


def _mutate_declared(rng: random.Random, draft: _Draft) -> None:
    index = rng.randrange(len(draft.entries))
    entry = draft.entries[index]
    field_name = rng.choice(("usize", "csize", "crc", "local_usize", "local_csize", "local_crc"))
    delta = rng.choice((-1, 1, 2, 4_096))
    base = len(entry.data) if "crc" not in field_name else zlib.crc32(entry.data)
    override: dict[str, Any] = {field_name: (base + delta) & 0xFFFFFFFF}
    draft.entries[index] = replace(entry, **override)


def _mutate_method(rng: random.Random, draft: _Draft) -> None:
    index = rng.randrange(len(draft.entries))
    draft.entries[index] = replace(draft.entries[index], method=rng.choice((0, 8)))


def _mutate_flags(rng: random.Random, draft: _Draft) -> None:
    index = rng.randrange(len(draft.entries))
    draft.entries[index] = replace(
        draft.entries[index], flags=rng.choice((0, 0x0008, 0x0800, 0x0801))
    )


def _mutate_extra(rng: random.Random, draft: _Draft) -> None:
    index = rng.randrange(len(draft.entries))
    draft.entries[index] = replace(
        draft.entries[index],
        extra=b"\x99\x99" + struct.pack("<H", rng.randrange(4)) + b"zzzz"[: rng.randrange(4)],
    )


def _mutate_archive(rng: random.Random, draft: _Draft) -> None:
    key, value = rng.choice(
        cast(
            "tuple[tuple[str, Any], ...]",
            (
                ("prefix", bytes(rng.getrandbits(8) for _ in range(rng.randrange(1, 8)))),
                ("suffix", bytes(rng.getrandbits(8) for _ in range(rng.randrange(1, 8)))),
                ("extra_records", b"\x00" * rng.randrange(1, 8)),
                ("eocd_comment", b"c" * rng.randrange(1, 8)),
                ("n_total", rng.randrange(0, 8)),
                ("n_disk", rng.randrange(0, 8)),
                ("size_cd", rng.randrange(0, 4_096)),
                ("off_cd", rng.randrange(0, 4_096)),
                ("zip64_locator", True),
            ),
        )
    )
    draft.archive[key] = value


def _mutate_permute(rng: random.Random, draft: _Draft) -> None:
    order = list(range(len(draft.entries)))
    rng.shuffle(order)
    rank = {position: place for place, position in enumerate(order)}
    draft.post.append(_directory_permuter(rank))


def _mutate_truncate(rng: random.Random, draft: _Draft) -> None:
    fraction = rng.randrange(1, 100)

    def truncate(raw: bytes) -> bytes:
        return raw[: len(raw) * fraction // 100]

    draft.post.append(truncate)


def _mutate_patch(rng: random.Random, draft: _Draft) -> None:
    where = rng.random()
    value = rng.getrandbits(8)

    def patch(raw: bytes) -> bytes:
        if not raw:
            return raw
        position = min(int(len(raw) * where), len(raw) - 1)
        return raw[:position] + bytes([value]) + raw[position + 1 :]

    draft.post.append(patch)


_MUTATORS: tuple[Callable[[random.Random, _Draft], None], ...] = (
    _mutate_rename,
    _mutate_payload,
    _mutate_duplicate,
    _mutate_long_name,
    _mutate_gap,
    _mutate_declared,
    _mutate_method,
    _mutate_flags,
    _mutate_extra,
    _mutate_archive,
    _mutate_permute,
    _mutate_truncate,
    _mutate_patch,
)


def family_mutation(count: int, seed: int) -> list[Vector]:
    """The sound bundle with one to three mutations drawn from the families
    above. Deterministic in the seed, so a divergence found here is a divergence
    anyone can reproduce."""
    # Reproducibility, not secrecy: the seed is printed and the corpus is
    # meant to be regenerated byte for byte by anyone rerunning the gate.
    rng = random.Random(seed)  # noqa: S311
    vectors: list[Vector] = []
    for index in range(count):
        draft = _Draft(entries=sound_entries())
        chosen = rng.sample(_MUTATORS, rng.randint(1, 3))
        for mutator in chosen:
            mutator(rng, draft)
        raw = build(Archive(entries=draft.entries, **draft.archive))
        for transform in draft.post:
            raw = transform(raw)
        vectors.append(
            Vector(
                family=MUTATION_FAMILY,
                name=f"seed{seed}-{index:05d}",
                attest=raw,
                note=",".join(mutator.__name__[len("_mutate_") :] for mutator in chosen),
            )
        )
    return vectors


# ---------------------------------------------------------------------------
# Projections
# ---------------------------------------------------------------------------


def _canonical_digest(value: object) -> str:
    """The digest of a value in its canonical form, or a marker naming it as
    one the canonicalizer refuses. The marker is as comparable as the digest:
    both sides run their own canonicalizer over the value they parsed."""
    try:
        return hashlib.sha256(canon.canonical_bytes(value)).hexdigest()
    except canon.CanonError:
        return "uncanonicalizable"
    except RecursionError:
        return "uncanonicalizable"


def _receipt_id_of(envelope: object) -> str:
    if not isinstance(envelope, dict):
        return ""
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return ""
    receipt_id = payload.get("receipt_id")
    return receipt_id if isinstance(receipt_id, str) else ""


def python_projection(attest: Path, private: Path | None = None, **caps: int) -> dict[str, Any]:
    """What the reference importer made of a file, in the shape the browser
    adapter reports the same answer in."""
    try:
        imported = py_importer.import_bundle(attest, private, **caps)
    except py_importer.BundleTooLargeError:
        return {"outcome": RESOURCE_LIMIT}
    except py_importer.BundleError:
        return {"outcome": MALFORMED}
    except Exception as error:  # anything else has left the outcome vocabulary
        return {"outcome": CRASH, "error": f"{type(error).__name__}: {error}"}

    store = imported.trust_store
    issuers: list[dict[str, Any]] = []
    for issuer in sorted(store.manifests):
        chain = store.chains.get(issuer) or [store.manifests[issuer]]
        issuers.append(
            {
                "issuer": issuer,
                "provenance": store.provenance.get(issuer),
                "selected": _canonical_digest(store.manifests[issuer]),
                "chain": [_canonical_digest(manifest) for manifest in chain],
            }
        )
    return {
        "outcome": ACCEPT,
        "receipts": [
            {"id": _receipt_id_of(envelope), "sha256": _canonical_digest(envelope)}
            for envelope in imported.receipts
        ],
        "issuers": issuers,
        "proofs": [
            {"id": receipt_id, "sha256": _canonical_digest(imported.proofs[receipt_id])}
            for receipt_id in sorted(imported.proofs)
        ],
        # The member set AND the binding each member stands on: the digest the
        # member was named by, beside the digest of the bytes kept under that
        # name. §14.1 makes the two the same value; comparing the pair is how
        # an importer that admitted the right name over the wrong bytes shows
        # up as a divergence rather than as an equal-looking list of names.
        "legal": [
            {"digest": digest, "sha256": hashlib.sha256(imported.legal_texts[digest]).hexdigest()}
            for digest in sorted(imported.legal_texts)
        ],
    }


def build_ts_bundle(out_dir: Path) -> Path:
    """Bundle the browser importer's two entry points for the adapter."""
    if not ESBUILD.exists():
        raise SystemExit(
            f"missing {ESBUILD} — run `npm ci --prefix site` before the importer differential"
        )
    bundle = out_dir / "importer.mjs"
    result = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        [
            str(ESBUILD),
            "--bundle",
            "--format=esm",
            "--platform=node",
            "--loader=ts",
            f"--outfile={bundle}",
        ],
        input=TS_ENTRY,
        text=True,
        capture_output=True,
        # Resolved from the site's own sources, so `attest-verifier` is the
        # build `site/` itself imports. A stale one measures the previous
        # revision: rebuild the package before trusting a green run.
        cwd=SITE_SRC,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"could not bundle the browser importer:\n{result.stderr}")
    return bundle


def ts_projections(bundle: Path, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    payload = "".join(json.dumps(request) + "\n" for request in requests)
    result = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        ["node", str(ADAPTER), str(bundle)],  # noqa: S607 -- node from PATH, as elsewhere here
        input=payload,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"the browser adapter failed:\n{result.stderr}")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != len(requests):
        raise SystemExit(f"expected {len(requests)} projections, got {len(lines)}")
    return [json.loads(line) for line in lines]


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

#: Fields narrowed out of BOTH sides on the intake road, with the reason. What
#: that door hands a caller is one verify job per receipt; a job carries an
#: envelope, a trust store and the evidence keyed to that receipt, and nothing
#: else. Comparing a field the door's contract does not carry would report the
#: shape of the interface once per archive rather than a disagreement about the
#: archive — and a standing difference reported every time is how a runner
#: teaches its reader to stop looking. The parser road, where both importers do
#: hold the value, compares it in full.
NARROWED_ON_THE_INTAKE_ROAD: dict[str, str] = {
    "legal": (
        "a verify job carries an envelope, a trust store and its evidence — the bundle's "
        "legal members are not part of what the door hands back, on either side"
    ),
}

COMPARED_FIELDS = ("receipts", "issuers", "proofs", "legal")


def matched_proofs_only(projection: dict[str, Any]) -> dict[str, Any]:
    """The projection with evidence narrowed to the receipts it stands for.

    The application door hands a caller one job per receipt, each carrying the
    evidence keyed to that receipt and nothing else, while an importer's own
    result carries the whole evidence map — including a member keyed to a
    receipt the bundle does not contain. Comparing the two unnarrowed reports a
    disagreement about what each surface is FOR, which is not a disagreement
    about the archive. Applied to both sides, so nothing one of them can see is
    dropped from only one.
    """
    if projection.get("outcome") != ACCEPT:
        return projection
    ids = {entry["id"] for entry in projection.get("receipts", [])}
    narrowed = dict(projection)
    narrowed["proofs"] = [entry for entry in projection.get("proofs", []) if entry["id"] in ids]
    return narrowed


def door_contract_only(projection: dict[str, Any]) -> dict[str, Any]:
    """The projection with the fields the application door does not carry
    removed entirely — not emptied.

    Removed, because an empty list is an answer: it says the importer kept
    nothing. The door kept nothing and said nothing, and a comparison that
    cannot tell those apart would read one side's silence as the other side's
    inventory. Applied to both sides, so nothing either of them can see is
    dropped from only one.
    """
    narrowed = dict(projection)
    for name in NARROWED_ON_THE_INTAKE_ROAD:
        narrowed.pop(name, None)
    return narrowed


@dataclass(frozen=True)
class Divergence:
    family: str
    vector: str
    left_label: str
    right_label: str
    left: dict[str, Any]
    right: dict[str, Any]
    fields: list[str]
    permitted: bool
    #: Reported but not counted: the two sides were asked different questions.
    advisory: bool
    finding: str
    note: str


def compare(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    """The fields on which two projections of the same file disagree."""
    fields: list[str] = []
    if left.get("outcome") != right.get("outcome"):
        fields.append("outcome")
    elif left.get("outcome") == ACCEPT:
        fields.extend(name for name in COMPARED_FIELDS if left.get(name) != right.get(name))
    return fields


def spec_permits(vector: Vector, left: dict[str, Any], right: dict[str, Any]) -> bool:
    """§14.4 permits exactly one kind of divergence, and only above the floor:
    an importer with a lower bound reports `resource-limit` where an importer
    with a higher bound reads on. Below the floor it permits none."""
    if not vector.above_floor:
        return False
    outcomes = {left.get("outcome"), right.get("outcome")}
    return RESOURCE_LIMIT in outcomes and len(outcomes) == 2 and CRASH not in outcomes


# ---------------------------------------------------------------------------
# The pair property
# ---------------------------------------------------------------------------

#: §14.4: "The bounds are stated per container. An importer that reads a
#: `.private.attest` sibling (§14.2) in the same operation MAY budget the pair
#: together, provided a pair whose containers are each within the floor is
#: still accepted."
#:
#: Reaching the stored floor with a real pair costs two containers of half a
#: gigabyte each, which this runner will not spend. The bound is exercised at a
#: declared, scaled value instead: the property under test is whether the two
#: containers share one budget, and that is a fact about the shape of the
#: importer rather than about the number. This is the ONE place the runner
#: passes a cap, and it says so in its output.
SCALED_PAIR_BOUND = 4 * 1024 * 1024


def pair_vectors() -> list[Vector]:
    """A `.attest` and a `.private.attest` whose containers are each well
    inside the scaled bound and whose sizes together exceed it."""
    half = SCALED_PAIR_BOUND // 2 + SCALED_PAIR_BOUND // 8
    shareable = build(
        Archive(entries=[*sound_entries(), Entry(name=b"pad/gap.bin", gap_before=half)])
    )
    private = build(
        Archive(entries=[*private_entries(), Entry(name=b"pad/gap.bin", gap_before=half)])
    )
    return [
        Vector(
            family=PAIR_FAMILY,
            name=f"each-within-{SCALED_PAIR_BOUND}-together-over",
            attest=shareable,
            private=private,
            finding="finding 3",
            note="stored size of each container is within the bound the pair shares",
        )
    ]


def run_pair_family(work: Path, keep: Path | None) -> list[Divergence]:
    """Check the property §14.4 states about a pair, on the reference importer.

    Not a differential: the browser importer is handed one file at a time and
    holds no budget across two, so there is no second answer to compare. The
    property is still the one a fix has to preserve, so it is measured against
    what the specification requires rather than against another implementation.
    """
    divergences: list[Divergence] = []
    for vector in pair_vectors():
        attest = work / f"{vector.name}.attest"
        private = work / f"{vector.name}.private.attest"
        attest.write_bytes(vector.attest)
        assert vector.private is not None
        private.write_bytes(vector.private)
        alone = python_projection(attest, None, max_total_bytes=SCALED_PAIR_BOUND)
        together = python_projection(attest, private, max_total_bytes=SCALED_PAIR_BOUND)
        required = {"outcome": ACCEPT}
        if together.get("outcome") != ACCEPT or alone.get("outcome") != ACCEPT:
            divergences.append(
                Divergence(
                    family=PAIR_FAMILY,
                    vector=vector.name,
                    left_label="reference importer, the pair in one operation",
                    right_label="specification §14.4, the pair rule",
                    left=together if together.get("outcome") != ACCEPT else alone,
                    right=required,
                    fields=["outcome"],
                    permitted=False,
                    advisory=False,
                    finding=vector.finding,
                    note=vector.note,
                )
            )
            if keep is not None:
                keep.mkdir(parents=True, exist_ok=True)
                shutil.copy2(attest, keep / attest.name)
                shutil.copy2(private, keep / private.name)
    return divergences


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

#: Axes of §14.4 this runner does not reach, and why. Printed on every run, so
#: a green result is never read as coverage it does not have.
UNREACHED: dict[str, str] = {
    "stored size of the container, as content": (
        f"the floor is {FLOOR_STORED_BYTES} bytes. The DECLARED reading of that axis is "
        "reached by the stored-floor family, on a container whose length is one byte past "
        "the floor and whose tail is a hole; a container carrying that much CONTENT would "
        "have to be written and handed whole to both sides, which is not affordable here. "
        "The pair family exercises the bound's shape across a pair at a scaled value."
    ),
    "decompressed size produced by the whole container": (
        "the declared reading of that axis is exercised at the floor and one byte past it; "
        "the produced reading would mean inflating more than a quarter of a gigabyte per "
        "archive on both sides, which is not affordable at this vector count."
    ),
}


def _describe(projection: dict[str, Any]) -> str:
    outcome = projection.get("outcome", "?")
    if outcome != ACCEPT:
        error = projection.get("error")
        return f"{outcome}" + (f" ({error})" if error else "")
    receipts = ",".join(entry["id"] for entry in projection.get("receipts", []))
    issuers = ",".join(entry["issuer"] for entry in projection.get("issuers", []))
    proofs = ",".join(entry["id"] for entry in projection.get("proofs", []))
    # `None` and an empty list are different answers here — a side that cannot
    # say, and a side that kept nothing — so they read differently.
    kept = projection.get("legal")
    legal = (
        "(not carried on this road)"
        if kept is None
        else "[" + ",".join(f"{entry['digest']}->{entry['sha256']}" for entry in kept) + "]"
    )
    return f"accept receipts=[{receipts}] issuers=[{issuers}] proofs=[{proofs}] legal={legal}"


def report(
    vectors: list[Vector],
    outcomes: dict[str, dict[str, int]],
    divergences: list[Divergence],
) -> None:
    print(f"{len(vectors)} archives fed to both importers at their own defaults")
    for side in sorted(outcomes):
        counts = outcomes[side]
        line = ", ".join(f"{name}={counts[name]}" for name in sorted(counts))
        print(f"  {side}: {line}")

    counted = [divergence for divergence in divergences if not divergence.advisory]
    advisory = [divergence for divergence in divergences if divergence.advisory]
    by_family: dict[str, list[Divergence]] = {}
    for divergence in counted:
        by_family.setdefault(divergence.family, []).append(divergence)
    print(f"{len(counted)} divergences across {len(by_family)} families")
    for family in sorted(by_family):
        found = by_family[family]
        permitted = sum(1 for divergence in found if divergence.permitted)
        findings = sorted({divergence.finding for divergence in found if divergence.finding})
        suffix = f" [{', '.join(findings)}]" if findings else ""
        print(
            f"  {family}: {len(found)}, of which {permitted} the specification permits "
            f"above the floor{suffix}"
        )
    # Permitted above the floor is still counted, and deliberately: §14.4 lets
    # two importers with different bounds disagree there, and this project
    # wants them not to. A permitted divergence is a decision to make, not a
    # defect — but it is not something to hide behind a green exit code.
    print(f"{len(advisory)} advisory disagreements, reported and not counted")
    for divergence in advisory:
        print(f"  {divergence.family}/{divergence.vector} on {', '.join(divergence.fields)}")

    print("canonical projection — compared: outcome class, then " + ", ".join(COMPARED_FIELDS))
    for name, reason in NARROWED_ON_THE_INTAKE_ROAD.items():
        print(f"  compared on the parser road only: {name} — {reason}")
    print("§14.4 axes this run does not reach:")
    for axis, reason in UNREACHED.items():
        print(f"  {axis} — {reason}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def collect(families: list[str], count: int, seed: int) -> list[Vector]:
    vectors: list[Vector] = []
    for family in families:
        if family in DETERMINISTIC_FAMILIES:
            vectors.extend(DETERMINISTIC_FAMILIES[family]())
        elif family == MUTATION_FAMILY:
            vectors.extend(family_mutation(count, seed))
    return vectors


def _materialise(path: Path, vector: Vector) -> None:
    """Write a vector's file, hole and all.

    A vector that declares more than it carries is written and then extended:
    `truncate` past the end of a file leaves a hole, so what the filesystem
    reports as the length is the declared size while what it spends is the few
    kilobytes actually written. Reproducing the vector this way rather than
    copying it is also why a kept divergence stays small — a copy would read
    the hole back as zeroes and write every one of them out.
    """
    path.write_bytes(vector.attest)
    if vector.sparse_to is not None:
        with path.open("r+b") as handle:
            handle.truncate(vector.sparse_to)


def _tally(outcomes: dict[str, dict[str, int]], side: str, projection: dict[str, Any]) -> None:
    counts = outcomes.setdefault(side, {})
    outcome = str(projection.get("outcome", "?"))
    counts[outcome] = counts.get(outcome, 0) + 1


def run(families: list[str], count: int, seed: int, keep: Path | None) -> int:
    divergences: list[Divergence] = []
    outcomes: dict[str, dict[str, int]] = {}
    vectors = collect(families, count, seed)

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        bundle = build_ts_bundle(work)

        paths: list[Path] = []
        requests: list[dict[str, Any]] = []
        for index, vector in enumerate(vectors):
            path = work / f"{index:06d}.attest"
            _materialise(path, vector)
            paths.append(path)
            requests.append({"path": str(path), "fileName": INTAKE_FILE_NAME, "op": "parse"})
            requests.append({"path": str(path), "fileName": INTAKE_FILE_NAME, "op": "intake"})
        answers = ts_projections(bundle, requests) if requests else []

        for index, vector in enumerate(vectors):
            reference = python_projection(paths[index])
            parsed, intook = answers[2 * index], answers[2 * index + 1]
            _tally(outcomes, "reference importer", reference)
            _tally(outcomes, "browser parseBundle", parsed)
            _tally(outcomes, "browser intake", intook)
            for label, mine, other in (
                ("browser parseBundle", reference, parsed),
                (
                    f"browser intake({INTAKE_FILE_NAME})",
                    door_contract_only(matched_proofs_only(reference)),
                    door_contract_only(matched_proofs_only(intook)),
                ),
            ):
                fields = compare(mine, other)
                if not fields:
                    continue
                divergence = Divergence(
                    family=vector.family,
                    vector=vector.name,
                    left_label="reference importer",
                    right_label=label,
                    left=mine,
                    right=other,
                    fields=fields,
                    permitted=spec_permits(vector, reference, other),
                    advisory=vector.advisory,
                    finding=vector.finding,
                    note=vector.note,
                )
                divergences.append(divergence)
                marker = "DIVERGENCE"
                if divergence.advisory:
                    marker = "ADVISORY"
                elif divergence.permitted:
                    marker = "PERMITTED ABOVE FLOOR"
                print(
                    f"{marker} {vector.family}/{vector.name} on {', '.join(fields)}"
                    + (f" [{vector.finding}]" if vector.finding else "")
                    + (f" — {vector.note}" if vector.note else "")
                    + f"\n  reference importer: {_describe(mine)}"
                    + f"\n  {label}: {_describe(other)}",
                    file=sys.stderr,
                )
                if keep is not None:
                    keep.mkdir(parents=True, exist_ok=True)
                    stem = f"{vector.family}--{vector.name}"
                    _materialise(keep / f"{stem}.attest", vector)
                    (keep / f"{stem}.json").write_text(
                        json.dumps(
                            {
                                "fields": fields,
                                "reference importer": mine,
                                label: other,
                            },
                            indent=2,
                            sort_keys=True,
                        )
                        + "\n",
                        encoding="utf-8",
                    )

        if PAIR_FAMILY in families:
            pair_found = run_pair_family(work, keep)
            divergences.extend(pair_found)
            for divergence in pair_found:
                print(
                    f"DIVERGENCE {divergence.family}/{divergence.vector} on "
                    f"{', '.join(divergence.fields)}"
                    + (f" [{divergence.finding}]" if divergence.finding else "")
                    + f"\n  {divergence.left_label}: {_describe(divergence.left)}"
                    + f"\n  {divergence.right_label}: {_describe(divergence.right)}",
                    file=sys.stderr,
                )

    report(vectors, outcomes, divergences)
    return 1 if any(not divergence.advisory for divergence in divergences) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=300, help="archives in the randomised stratum")
    parser.add_argument("--seed", type=int, default=20260904)
    parser.add_argument(
        "--families",
        default=",".join(ALL_FAMILIES),
        help="comma-separated subset of: " + ", ".join(ALL_FAMILIES),
    )
    parser.add_argument("--keep", type=Path, default=None)
    parser.add_argument("--list-families", action="store_true", help="print the families and exit")
    args = parser.parse_args(argv)
    if args.list_families:
        for family in ALL_FAMILIES:
            print(family)
        return 0
    families = [name.strip() for name in args.families.split(",") if name.strip()]
    unknown = [name for name in families if name not in ALL_FAMILIES]
    if unknown:
        raise SystemExit(f"unknown families: {', '.join(unknown)}")
    return run(families, args.count, args.seed, args.keep)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
