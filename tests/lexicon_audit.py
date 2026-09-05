"""The retired normative lexicon, and every surviving occurrence with a verdict.

A term this family has retired does not stop existing when the sentences someone
remembered are rewritten. It survives wherever nobody looked — in a comment two
hundred lines below the corrected one, in an annex no sweep reached, wrapped
across two lines so a line-oriented search cannot see it. Twice in a row the
completeness of one rename was left to the attention of whoever was searching,
and twice it was incomplete in exactly that way.

So the property is owned by a check instead. `tests/test_lexicon_guard.py`
enumerates every occurrence of the patterns below across the tracked tree, on
text with its whitespace collapsed, and requires each one to be either a path
this module allows wholesale or a row registered here with a verdict and a
reason. A new occurrence is unregistered and fails; a reworded one changes its
hash and fails; a row whose text is gone fails as stale. The model is
`desktop/test/inherited-copy-audit.ts`, which does the same for the copy the
desktop artifact freezes.

Adding a term to `RETIRED` is what a future rename costs: the check then names
every place the old term still lives, once, instead of a campaign.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

#: The gate's retired NAME. `v0.2` §17.3 renamed it: a valid
#: `holder_authorization` establishes control of the key the issuer recorded in
#: `buyer.pubkey`, never consent by the buyer or the outgoing holder, and the
#: former name asserted what the mechanism does not establish. Both spellings,
#: because the hyphenated one is how the two verifiers wrote it in comments and
#: is exactly what a search for the spaced form missed.
RETIRED_NAME: Final = re.compile(r"consent[- ]gate", re.I)

#: The claim the rename exists to remove, which outlives any one spelling of the
#: name: `consent` as something a signature, a record or the gate establishes.
#: Legitimate uses remain — a negated one, and the unrelated consent v0.1 §5.1
#: attaches to superseding a receipt — and each is registered below rather than
#: carved out by a pattern nobody can read.
CONSENT_CLAIM: Final = re.compile(r"\bconsent(?:ed|s)?\b", re.I)

PATTERNS: Final = (RETIRED_NAME, CONSENT_CLAIM)

#: File extensions the guard reads. Everything else in the tree is binary,
#: generated, or not prose a reader takes a rule from.
TEXT_SUFFIXES: Final = frozenset(
    {".md", ".py", ".ts", ".mjs", ".html", ".xml", ".json", ".yml", ".yaml", ".txt", ".toml"}
)

#: Release records: a changelog entry is the minute of what was shipped under
#: the name in use at the time. Rewriting one would falsify a record, so these
#: two files carry the retired name by right and are not audited line by line.
#: The audit's own two files join them for a different reason of the same kind:
#: they are the register that DEFINES the retired terms, so they must spell
#: them out — including the retired name planted in the negative self-test —
#: and auditing them would turn this guard red on its own vocabulary the very
#: moment it is committed.
ALLOWED_PATHS: Final = frozenset(
    {
        "CHANGELOG.md",
        "verifiers/ts/CHANGELOG.md",
        "tests/lexicon_audit.py",
        "tests/test_lexicon_guard.py",
    }
)

#: How many characters of context either side of a match the excerpt carries.
#: Wide enough that a verdict can be read off it, narrow enough that an edit
#: elsewhere in the paragraph does not move the hash.
CONTEXT: Final = 70


@dataclass(frozen=True)
class Occurrence:
    """One surviving occurrence, and why it is allowed to survive."""

    path: str
    sha256: str
    excerpt: str
    verdict: str
    reason: str


#: The verdicts a row may carry. A new one means a new kind of exception, which
#: is a decision, not a spelling.
VERDICTS: Final = frozenset({"NEGATED", "OTHER-SUBJECT", "DESCRIBES-THE-RENAME"})

#: Every occurrence outside `ALLOWED_PATHS`, each with the verdict that lets it
#: stay. `NEGATED`: the sentence says the mechanism does NOT establish consent.
#: `OTHER-SUBJECT`: a different consent entirely — superseding a receipt
#: (v0.1 §5.1), or signer intent under coercion. `DESCRIBES-THE-RENAME`: the
#: revision-log entry that records the rename and must name the retired term to
#: record it.
AUDITED: Final[tuple[Occurrence, ...]] = (
    Occurrence(
        path="docs/faq.md",
        sha256="a187a65d2352d60184e413289ccc778a662a58a9119ddce493bd7f2c089e70fd",
        excerpt="r is also logged. This proves control of the issuer-record",
        verdict="NEGATED",
        reason=(
            "Says the authorization proves control of the issuer-recorded key and NOT consent "
            "by the buyer."
        ),
    ),
    Occurrence(
        path="docs/spec/attest-privacy.md",
        sha256="a11d30ae96d39f029d56cf8fc0188a215128e0c58e88ccb3b962235d3826a7a6",
        excerpt="d one — which does not invalidate the superseded receipt a",
        verdict="OTHER-SUBJECT",
        reason=(
            "Consent to supersede a receipt (v0.1 §5.1), a different mechanism from §17.3's gate."
        ),
    ),
    Occurrence(
        path="docs/spec/attest-threat-model.md",
        sha256="0d8424385e39c0f8b23f6a0248d81bb9d5b3a46417b5e2179d3cacb35701834c",
        excerpt="mpact:** An earlier receipt is treated as retired without ",
        verdict="OTHER-SUBJECT",
        reason="Consent to supersede a receipt (v0.1 §5.1), named as what a lineage attack lacks.",
    ),
    Occurrence(
        path="docs/spec/attest-threat-model.md",
        sha256="568c35e1ce5870e12bbd20749848518a6ec46503fc943ebf4bf5dbfd5f336949",
        excerpt="ding re-issue does not invalidate the superseded receipt a",
        verdict="OTHER-SUBJECT",
        reason="Consent to supersede a receipt (v0.1 §5.1).",
    ),
    Occurrence(
        path="docs/spec/attest-threat-model.md",
        sha256="baf855abd053b1f0a22ca461a49e4114d93dbe9fd02009e415aefa2717811c5f",
        excerpt="ding re-issue does not invalidate the superseded receipt a",
        verdict="OTHER-SUBJECT",
        reason="Consent to supersede a receipt (v0.1 §5.1).",
    ),
    Occurrence(
        path="docs/spec/attest-threat-model.md",
        sha256="c542e8283222d328f30e10a27db54371afb838c2acb4a845205044ff0a37f52e",
        excerpt="no signature scheme, and no transparency log, distinguishe",
        verdict="OTHER-SUBJECT",
        reason="Signer intent under coercion (TM-65), which the profile declines to adjudicate.",
    ),
    Occurrence(
        path="docs/spec/attest-threat-model.md",
        sha256="67bad3cbe2b1e8bbfa6e2dc89304705430d2e7615ca95022d012819d930135fb",
        excerpt=" key; neither the genuine nor forged result independently ",
        verdict="NEGATED",
        reason=(
            "Says neither a genuine nor a forged authorization establishes consent by the "
            "outgoing holder."
        ),
    ),
    Occurrence(
        path="docs/spec/attest-v0.1.md",
        sha256="6ac50fbd5ede8916aa50833b38a0101368e11d8583e5ddd1a5e3848831e123ca",
        excerpt=" re-issue does **not** invalidate the superseded receipt a",
        verdict="OTHER-SUBJECT",
        reason="Consent to supersede a receipt (v0.1 §5.1).",
    ),
    Occurrence(
        path="docs/spec/attest-v0.2.md",
        sha256="de5b7d8b707e9372299efa93d5013debb3df319cf8a84cda052447b416855dd1",
        excerpt=" in the old receipt's `buyer.pubkey`; it does not by itsel",
        verdict="NEGATED",
        reason=(
            "The normative sentence: the gate does not by itself establish consent or "
            "participation."
        ),
    ),
    Occurrence(
        path="docs/spec/attest-v0.2.md",
        sha256="dd799d79c862f60aca622412d8c07da56531692c776e411f81f0340258dc17a6",
        excerpt="no signature scheme, and no transparency log, distinguishe",
        verdict="OTHER-SUBJECT",
        reason="Signer intent under coercion (v0.2 §17.9).",
    ),
    Occurrence(
        path="docs/spec/attest-v0.2.md",
        sha256="d6dbd29c86993031e113a65e3d768a57d58585868ffc5db2445ecc01686b7d54",
        excerpt="rohibited. The gate is also renamed: what §16.5 and §17.3 ",
        verdict="DESCRIBES-THE-RENAME",
        reason=(
            "The rev 12 log entry that records the rename; it must name the retired term to "
            "record it."
        ),
    ),
    Occurrence(
        path="docs/spec/attest-v0.2.md",
        sha256="5a4302de9da9e937f279c64f7f196db5e549c7370c3b38b6014d9773aa4a4ab0",
        excerpt="he key the issuer recorded in the old receipt's `buyer.pub",
        verdict="NEGATED",
        reason="Says the authorization establishes control of the recorded key, never consent.",
    ),
    Occurrence(
        path="site/public/faq.html",
        sha256="a187a65d2352d60184e413289ccc778a662a58a9119ddce493bd7f2c089e70fd",
        excerpt="r is also logged. This proves control of the issuer-record",
        verdict="NEGATED",
        reason=(
            "Says the authorization proves control of the issuer-recorded key and NOT consent "
            "by the buyer."
        ),
    ),
    Occurrence(
        path="docs/spec/attest-transfer-economics.md",
        sha256="f7373e81f89db6a80ee4893908e20e756a54aa1e36562437c3e498a64a46f719",
        excerpt="uer's cooperation — a signature by the key the issuer reco",
        verdict="NEGATED",
        reason=(
            "Says the record carries the outgoing holder's key authorization and never consent "
            "by the holder."
        ),
    ),
    Occurrence(
        path="src/attest/verify.py",
        sha256="f3f301fe717a3d5e38ebdda8abadee4eadd2d27d0a513f4af0b74a25314ca868",
        excerpt="controls the key the issuer recorded in the OLD receipt, w",
        verdict="NEGATED",
        reason=(
            "The step list says the signer controls the recorded key, which is not consent by "
            "the buyer or outgoing holder."
        ),
    ),
    Occurrence(
        path="verifiers/ts/src/revocation.ts",
        sha256="4a93aafe81eb431dd218bc5ccd580d5f59372881a6098a1be2af3c1eb5b8f36c",
        excerpt="ntrols the * key the issuer recorded in the OLD receipt, w",
        verdict="NEGATED",
        reason=(
            "The step list says the signer controls the recorded key, which is not consent by "
            "the buyer or outgoing holder."
        ),
    ),
)
