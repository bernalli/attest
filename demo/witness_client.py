"""demo/witness_client.py — the C2SP `add-checkpoint` client this repository
did not have, and the joins that go with it.

attest can build a transparency log, sign its checkpoint, and prove an entry's
inclusion; `witness/` can cosign a checkpoint somebody submits to it. Nothing
usable in between existed. A submission body is built in three places, all of
them test-local helpers inside `witness/tests/` (`_body` in
`test_witness_service.py` and `test_witness_http.py`, one inline in
`test_witness_cli.py`): not importable from here, unbounded, and each a copy of
the last. And nothing anywhere carried the cosignature the witness returns back
into the inclusion evidence a verifier reads — `attest log prove` copies
`LOG/checkpoint` verbatim, which the witness's lines never reach, and emits no
`witness_policy_epoch`. `demo/witness_cosigns.py` needs both, so both live
here.

Non-normative, exactly like `demo/custodian.py`: there is no `attest log
cosign` command and this is not one. It is the reference for what an operator
has to do between `attest log sign-checkpoint` and `attest verify
--witness-policy`, written once so it can be read and run.

What it does not do, stated because a reference that hides its gaps teaches
the wrong thing. It reads a response whole, with no ceiling: the witness this
demo talks to answers with two signature lines or a short diagnostic, and a
client pointed at something else would want a bound before it allocated. It
speaks cleartext HTTP, because the witness binds loopback and TLS belongs to
whatever is in front of it. And it retries nothing: a 409 carries the size
the witness holds precisely so a caller can resynchronise, and deciding
whether to is the caller's, not this module's.
"""

from __future__ import annotations

import base64
import http.client
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

# C2SP tlog-witness bounds a consistency-proof line at a base64 SHA-256 hash.
_SHA256_LEN = 32


def build_submission(old_size: int, checkpoint_text: str, proof: Sequence[bytes] = ()) -> bytes:
    """The C2SP `add-checkpoint` request body.

    `old <decimal size>`, then one base64 line per consistency-proof node,
    then a blank line, then the checkpoint note verbatim. The note is passed
    through unchanged: it is a signed object, and a client that re-rendered it
    would be submitting something the log did not sign.
    """
    if isinstance(old_size, bool) or not isinstance(old_size, int) or old_size < 0:
        raise ValueError(f"old size must be a non-negative integer, got {old_size!r}")
    lines = [f"old {old_size}"]
    for node in proof:
        if not isinstance(node, bytes) or len(node) != _SHA256_LEN:
            raise ValueError(f"a consistency-proof node must be {_SHA256_LEN} bytes, got {node!r}")
        lines.append(base64.b64encode(node).decode("ascii"))
    head = "\n".join(lines) + "\n\n"
    return head.encode("ascii") + checkpoint_text.encode("utf-8")


@dataclass(frozen=True, slots=True)
class Note:
    """A signed note split the one way this module needs it: the body the
    signatures commit to, and the signature lines that follow it."""

    body: str
    signature_lines: tuple[str, ...]


def split_note(text: str) -> Note:
    """Split a C2SP signed note into its body and its signature lines.

    Structural only — nothing here checks a signature. The body is everything
    up to and including the blank line; C2SP fixes that separator, so this
    needs no knowledge of how many header lines a checkpoint has.
    """
    body, separator, signatures = text.partition("\n\n")
    if not separator:
        raise ValueError("not a signed note: no blank line separates the body from the signatures")
    if not signatures.endswith("\n"):
        raise ValueError("not a signed note: the signature block is not newline-terminated")
    return Note(body=body + separator, signature_lines=tuple(signatures.splitlines(keepends=True)))


def cosigned_note(checkpoint_text: str, cosignature_lines: str) -> str:
    """The note with the witness's lines APPENDED — never substituted.

    A cosignature is one more signature line on the same note, not a new note.
    Both operands are parsed before and after the join, because the cheap way
    to corrupt a note is to append to one whose last line has no newline: the
    witness's first line then continues the log's last one, and the damage
    sits inside a signature nobody re-reads.
    """
    if not cosignature_lines:
        raise ValueError("no cosignature lines to append")
    split_note(checkpoint_text)
    merged = checkpoint_text + cosignature_lines
    split_note(merged)
    return merged


def evidence_with_cosignature(
    evidence: dict[str, Any], cosigned_checkpoint: str, *, witness_policy_epoch: str
) -> dict[str, Any]:
    """`attest log prove` evidence, re-pointed at the COSIGNED note.

    Two things a verifier needs that `log prove` cannot supply. The checkpoint
    it writes is the one in `LOG/checkpoint`, which the witness's lines never
    reach; and v0.2 s10.2 step 8 reads the epoch from the evidence's
    `witness_policy_epoch`, which it does not emit. Without both, a verifier
    holding a witness policy reports `corroboration: "logged"` and names no
    condition — step 8's silence is normative (s11.4), so a missing member is
    indistinguishable from a witness that did not count.

    The substitution is guarded: the cosigned note's BODY must be the body the
    evidence already carried. A note for another tree, or another log, carries
    genuine witness signatures over a head this evidence's inclusion proof
    says nothing about. The input is not mutated — the caller keeps the
    un-witnessed bundle, which is what makes the two verdicts comparable.
    """
    existing = evidence.get("checkpoint")
    if not isinstance(existing, str):
        raise ValueError("evidence carries no `checkpoint` note to add a cosignature to")
    if not isinstance(witness_policy_epoch, str) or not witness_policy_epoch:
        raise ValueError(
            "witness_policy_epoch must be a non-empty string naming the epoch the "
            f"verifier is to resolve, got {witness_policy_epoch!r}"
        )
    if split_note(cosigned_checkpoint).body != split_note(existing).body:
        raise ValueError("the cosigned note is a different checkpoint from the evidence's own")
    updated = dict(evidence)
    updated["checkpoint"] = cosigned_checkpoint
    updated["witness_policy_epoch"] = witness_policy_epoch
    return updated


class WitnessRefused(Exception):
    """The witness answered with something other than 200.

    Carries the status because the status IS the answer: C2SP assigns a
    distinct one to every refusal, and a caller that flattens them all into
    "it failed" throws away the only thing the witness said. The 409 goes
    further and puts the size it holds in the body, so a desynchronised
    client resynchronises in one round trip — which is why `body` is kept
    too, rather than only rendered into the message.
    """

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"the witness answered {status}: {body.strip()}")
        self.status = status
        self.body = body


def _request(
    method: str, host: str, port: int, path: str, body: bytes | None, timeout: float
) -> str:
    """One request, one connection, closed on every path.

    `http.client` rather than `urllib`: urllib honours the proxy environment,
    and a proxied request to a loopback witness goes nowhere and then times
    out — a failure that reads like the witness being down.
    """
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(method, path, body=body)
        response = connection.getresponse()
        payload = response.read().decode("utf-8")
        if response.status != 200:
            raise WitnessRefused(response.status, payload)
        return payload
    finally:
        connection.close()


def submit(host: str, port: int, path: str, body: bytes, *, timeout: float = 10.0) -> str:
    """POST one `add-checkpoint` submission; return the cosignature lines."""
    return _request("POST", host, port, path, body, timeout)


def fetch_monitored(host: str, port: int, path: str, *, timeout: float = 10.0) -> str:
    """GET the cosigned note a witness last stored for one log."""
    return _request("GET", host, port, path, None, timeout)
