"""The C2SP tlog-witness protocol, minus the HTTP.

Contract: given a raw `add-checkpoint` submission body, either produce this
witness's cosignature lines or raise a typed refusal carrying the status the
protocol assigns it. `http.py` turns those into responses and adds nothing of
its own; keeping the decisions here is what makes them testable without a
socket.

The order of operations is the security property, and it is not the order the
code would fall into naturally:

1. Parse the body under fixed bounds.
2. Read the origin the checkpoint DECLARES — its first line — without parsing
   or validating anything else.
3. Refuse an unknown origin (404) — before the note is parsed, before any key
   is used, and before any state is read or written (v0.2 §11.4: "Unknown
   origins are rejected before checkpoint or consistency work can advance
   state"). Parsing the note first to obtain a validated origin looks
   equivalent and is not: the parser checks the root encoding and every
   signature line before it can say what the origin was, so an unknown log
   with a malformed note would get a 400 describing a note this witness should
   not have looked at.
4. Authenticate the checkpoint against the pinned hybrid log key (403) —
   before the state transaction opens, because an unauthenticated checkpoint
   must not be able to make the witness do work.
5. Inside ONE transaction: compare the claimed old size against stored state,
   verify consistency, sign, and persist. C2SP requires the comparison and the
   persistence to be atomic; signing is inside because what gets persisted IS
   the cosigned text.
6. Return only after the commit. A cosignature released before its state was
   durable would survive a crash the state did not — and the witness would
   wake up willing to cosign a fork of the very checkpoint it had already
   endorsed.

Nothing in an invalid request reaches step 5: every refusal above it happens
before a key is used or a row is touched.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from attest import tlog
from attest_witness.config import WitnessConfig
from attest_witness.cosign import Cosignature, CosignError, cosign
from attest_witness.store import StaleState, WitnessStore

_OLD_PREFIX: Final = "old "
# A base64-encoded SHA-256 hash: 44 characters with padding. Proof lines are
# nothing else, so the bound is exact rather than generous.
_MAX_PROOF_LINE_LEN: Final = 44
# RFC 6962: the Merkle tree hash of an empty tree is SHA-256 of the empty
# string. A tree-size-0 checkpoint claiming any other root is not an empty
# tree, whatever it says.
_EMPTY_TREE_ROOT: Final = hashlib.sha256(b"").digest()


class ProtocolError(Exception):
    """A submission the protocol assigns a specific status to."""

    status: int = 400

    def __init__(self, message: str) -> None:
        super().__init__(message)


class BadRequest(ProtocolError):
    status = 400


class UntrustedCheckpoint(ProtocolError):
    """No signature on the note verifies against the pinned log key."""

    status = 403


class UnknownOrigin(ProtocolError):
    status = 404


class Conflict(ProtocolError):
    """The claimed old size, or the checkpoint at an equal size, disagrees
    with what this witness has already cosigned."""

    status = 409

    def __init__(self, message: str, *, stored_size: int) -> None:
        super().__init__(message)
        self.stored_size = stored_size


class Unprocessable(ProtocolError):
    """Well-formed request, contents C2SP refuses to process (422).

    Three conditions share this status by specification: a size-0 checkpoint
    whose root is not the empty-tree root, a non-empty proof when the old size
    is zero, and a consistency proof — including the degenerate n-to-n one —
    that does not verify.
    """

    status = 422


class CosignFailed(ProtocolError):
    """This witness could not sign, for a reason of its own.

    A 500 rather than a 400 on purpose: the request was fine. Telling a client
    its submission was malformed when the fault is ours means it will not
    retry, and a cosignature is lost to a condition that may already have
    passed — a clock that stepped, for instance.
    """

    status = 500


@dataclass(frozen=True, slots=True)
class Submission:
    old_size: int
    proof: tuple[bytes, ...]
    checkpoint_text: str


def parse_submission(body: bytes, *, max_proof_lines: int) -> Submission:
    """Parse an `add-checkpoint` body: `old <size>`, proof lines, blank, note.

    Every bound is checked before any allocation proportional to the input,
    and no part of the body is echoed back to the client: a diagnostic that
    quoted the request would turn this endpoint into a reflector.
    """
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BadRequest("request body is not valid UTF-8") from exc

    head, separator, checkpoint_text = text.partition("\n\n")
    if not separator:
        raise BadRequest("request body has no blank line separating proof from checkpoint")
    if not checkpoint_text:
        raise BadRequest("request body carries no checkpoint")

    lines = head.split("\n")
    old_line = lines[0]
    if not old_line.startswith(_OLD_PREFIX):
        raise BadRequest("request body does not start with an 'old <size>' line")
    digits = old_line[len(_OLD_PREFIX) :]
    # `int()` accepts "+1", "1_0", surrounding whitespace and unicode digits;
    # the protocol accepts a decimal number and nothing else.
    if not digits.isascii() or not digits.isdigit():
        raise BadRequest("old size is not a decimal number")
    if digits != "0" and digits.startswith("0"):
        # C2SP: "encoded as an ASCII decimal with no leading zeroes (unless the
        # size is zero, in which case the encoding MUST be `0`)". Accepting
        # "007" would make two different request bodies mean the same thing,
        # and a witness compares sizes for a living.
        raise BadRequest("old size has a leading zero")
    old_size = int(digits)

    proof_lines = lines[1:]
    if len(proof_lines) > max_proof_lines:
        raise BadRequest(f"more than {max_proof_lines} consistency proof lines")
    proof: list[bytes] = []
    for line in proof_lines:
        if len(line) > _MAX_PROOF_LINE_LEN:
            raise BadRequest("consistency proof line is too long")
        try:
            node = _b64_hash(line)
        except ValueError as exc:
            raise BadRequest("consistency proof line is not a base64 SHA-256 hash") from exc
        proof.append(node)
    return Submission(old_size=old_size, proof=tuple(proof), checkpoint_text=checkpoint_text)


def _b64_hash(line: str) -> bytes:
    import base64

    raw = base64.b64decode(line, validate=True)
    if len(raw) != 32:
        raise ValueError("not a 32-byte hash")
    return raw


# A checkpoint's first line is its origin (v0.2 §9.1). Bounded before use: the
# body is already size-limited, but a lookup key is not a place to put an
# unbounded slice of somebody's request.
_MAX_ORIGIN_LEN: Final = 512


def _declared_origin(checkpoint_text: str) -> str:
    """The origin a submission CLAIMS, read without parsing anything else.

    Deliberately not `parse_checkpoint(...).origin`: that validates the whole
    note first, so an unknown origin in a malformed note would be answered as
    a malformed note. A claim is all that is needed to decide whether this
    witness has any business with it.
    """
    first_line, _, _ = checkpoint_text.partition("\n")
    if not first_line or len(first_line) > _MAX_ORIGIN_LEN:
        raise BadRequest("checkpoint does not begin with an origin line")
    if not all("\x20" <= character <= "\x7e" for character in first_line):
        # v0.2 §9.2's origin grammar. Refused as a malformed request rather
        # than an unknown origin: this is not a name any log could have.
        raise BadRequest("checkpoint origin is not printable ASCII")
    return first_line


def origin_hash(origin: str) -> str:
    """The monitoring path segment for `origin`: hex SHA-256 of its bytes."""
    return hashlib.sha256(origin.encode("utf-8")).hexdigest()


class WitnessService:
    """One witness: a configuration, its state, and a clock."""

    def __init__(
        self,
        config: WitnessConfig,
        store: WitnessStore,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._config = config
        self._store = store
        self._clock = clock
        # Precomputed once: the monitoring endpoint identifies a log by the
        # hash of its origin, and hashing every configured origin per request
        # would be work an unauthenticated caller could ask for.
        self._by_origin_hash = {origin_hash(origin): origin for origin in config.logs}

    def add_checkpoint(self, body: bytes) -> str:
        """Handle one submission. Returns the cosignature lines to send back."""
        submission = parse_submission(body, max_proof_lines=self._config.server.max_proof_lines)

        # The origin is read from the note's FIRST LINE and matched against the
        # allowlist before the checkpoint is parsed. Parsing first would look
        # equivalent and is not: `parse_checkpoint` validates the root encoding
        # and every signature line before it can tell anyone what the origin
        # was, so a submission for an unknown log with a malformed root would
        # come back 400 — a diagnostic about a log this witness has no business
        # saying anything about, and work it should not have done.
        log_key = self._config.logs.get(_declared_origin(submission.checkpoint_text))
        if log_key is None:
            raise UnknownOrigin("unknown log origin")

        try:
            tlog.parse_checkpoint(submission.checkpoint_text)
        except tlog.TlogError as exc:
            # Parsed separately from authentication so the two failures keep
            # their own statuses: C2SP's 403 is specifically "no signature from
            # a trusted key verifies", which a note that cannot be parsed at
            # all has not reached. Now that the origin is known to be one of
            # ours, saying "malformed" tells its operator something useful.
            raise BadRequest(f"checkpoint is malformed: {exc}") from exc

        try:
            checkpoint = tlog.verify_checkpoint(submission.checkpoint_text, log_key, log_key.origin)
        except tlog.TlogError as exc:
            # C2SP: 403 when no signature from a trusted key for the origin
            # verifies. The core's check is the hybrid AND of v0.2 §9.3 — an
            # Ed25519-only note does not authenticate a checkpoint here.
            raise UntrustedCheckpoint(f"checkpoint is not authentic: {exc}") from exc

        if checkpoint.tree_size < submission.old_size:
            raise BadRequest("old size exceeds the checkpoint's tree size")
        if checkpoint.tree_size == 0 and checkpoint.root != _EMPTY_TREE_ROOT:
            # C2SP assigns 422 here, not 400: the request is well formed, its
            # contents are not processable.
            raise Unprocessable("tree size 0 with a root that is not the empty-tree root")

        return self._advance(checkpoint, submission)

    def _advance(self, checkpoint: tlog.Checkpoint, submission: Submission) -> str:
        origin = checkpoint.origin
        with self._store.transaction() as transaction:
            stored = transaction.latest(origin)
            stored_size = 0 if stored is None else stored.tree_size
            if submission.old_size != stored_size:
                # C2SP: the body of a 409 is the size we actually hold, so a
                # client can resynchronise in one round trip.
                raise Conflict("old size does not match stored state", stored_size=stored_size)

            # ONE consistency check covers all three of C2SP's cases, because
            # RFC 6962 already distinguishes them:
            #
            #   old 0            -> consistency from the empty tree holds for
            #                       any tree with an EMPTY proof, and fails
            #                       with a non-empty one, which is exactly the
            #                       rule "if the proof is not empty when the
            #                       old size is zero ... 422";
            #   old == size      -> consistency from n to n holds only when the
            #                       roots are identical and the proof is empty,
            #                       which is the rule "if the old size matches
            #                       the checkpoint size, the root hashes must
            #                       also be identical ... 422";
            #   old <  size      -> the ordinary proof.
            #
            # Writing the three as separate branches invited each of them to
            # drift from the others: the first version compared note bytes by
            # hand at equal sizes and accepted any proof lines alongside them.
            base_root = _EMPTY_TREE_ROOT if stored is None else stored.root
            if not tlog.verify_consistency(
                submission.old_size,
                base_root,
                checkpoint.tree_size,
                checkpoint.root,
                list(submission.proof),
            ):
                raise Unprocessable("consistency proof does not verify")

            signature = self._cosign(checkpoint)
            cosigned_text = submission.checkpoint_text + signature.lines
            try:
                transaction.store(
                    origin,
                    tree_size=checkpoint.tree_size,
                    root=checkpoint.root,
                    note_bytes=checkpoint.note_bytes,
                    cosigned_text=cosigned_text,
                )
            except StaleState as exc:
                # Unreachable through the checks above; kept because "the
                # caller cannot ask for this" is exactly the assumption that
                # stops being true after a refactor.
                raise Conflict(str(exc), stored_size=stored_size) from exc
        # Outside the transaction: the commit has returned, so the state this
        # cosignature attests to is on disk before anyone can read the lines.
        return signature.lines

    def _cosign(self, checkpoint: tlog.Checkpoint) -> Cosignature:
        try:
            return cosign(
                checkpoint.note_bytes,
                name=self._config.identity.name,
                signing_keys=self._config.identity.signing_keys,
                timestamp=int(self._clock()),
            )
        except CosignError as exc:
            raise CosignFailed(f"cannot cosign this checkpoint: {exc}") from exc

    def monitoring(self, hashed_origin: str) -> str:
        """The latest cosigned checkpoint for the log whose origin hashes to
        `hashed_origin`, as its full note text."""
        origin = self._by_origin_hash.get(hashed_origin)
        if origin is None:
            raise UnknownOrigin("unknown log origin")
        stored = self._store.latest(origin)
        if stored is None:
            raise UnknownOrigin("no checkpoint has been cosigned for this log")
        return stored.cosigned_text
