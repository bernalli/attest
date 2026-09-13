"""The committed web-verifier sample bundle must be regenerable and genuine.

Loads tools/gen_site_sample.py by file path (tools/ is not a package) and
checks that a fresh generation produces a bundle that imports, verifies ok
at TOFU trust, proves its binding with the sidecar salt, and never leaks a
.private.attest into the output directory.

The second half of the file asks the same questions of the file actually
published — `site/public/sample/demo.attest`. A fresh generation says nothing
about the committed bytes: the sample is the artifact a first-time visitor
drops into the web verifier, so if it stops verifying, the demo lies. Until
these tests existed, only the TypeScript suite ever opened the committed
bundle, and only for its transparency evidence.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import zipfile
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from attest import bundle, cli, keys, tlog, verify

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DIR = REPO_ROOT / "site" / "public" / "sample"
SAMPLE_BUNDLE = SAMPLE_DIR / "demo.attest"
SAMPLE_BINDING = SAMPLE_DIR / "demo-binding.json"
#: The anchoring policy this repository publishes for the log the sample sits
#: in — the same file the generator's own self-check reads, and for the same
#: reason. A policy restated here would be a second copy that can only ever
#: agree with itself, so the day the published one stops being empty this test
#: would go on evaluating the committed evidence against an empty policy.
SHIPPED_ANCHOR_POLICY = (
    REPO_ROOT / "docs" / "trust" / "attest-receipts.org-log" / "anchor-policy.json"
)
#: The log keys the published page pins are compiled into the site rather than
#: served next to the log, deliberately (v0.2 §7.3: a verifier may not take log
#: keys from the material it is checking). That module is therefore the only
#: place they exist, and reading them is what lets this side evaluate the same
#: evidence the browser evaluates, against the same trusted configuration.
TRUSTED_LOG_SOURCE = SAMPLE_DIR.parent.parent / "src" / "trusted-log.ts"


def _load_generator() -> ModuleType:
    path = Path(__file__).resolve().parent.parent / "tools" / "gen_site_sample.py"
    spec = importlib.util.spec_from_file_location("gen_site_sample", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generator_produces_verifiable_sample(tmp_path: Path) -> None:
    gen = _load_generator()
    report = gen.main(tmp_path)

    attest_path = Path(report["attest"])
    binding_path = Path(report["binding"])
    assert attest_path.name == "demo.attest" and attest_path.is_file()
    assert binding_path.name == "demo-binding.json" and binding_path.is_file()

    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    assert binding["identifier_type"] == "email"
    assert len(binding["salt_b64u"]) == 22  # 16 raw bytes, base64url unpadded

    check = report["self_check"]
    assert check["verify"]["ok"] is True
    assert check["verify"]["trust"] == "unauthenticated_tofu"
    assert check["verify_with_disclosure"]["binding"] == "proven"

    # The secrets file must never land in the published output directory.
    assert not list(tmp_path.glob("*.private.attest"))


def test_refresh_readme_rewrites_only_that_member(tmp_path: Path) -> None:
    """`--refresh-readme` exists so the committed sample can follow a wording
    change without minting a key or growing the public log. That is only safe
    if it touches nothing else: every other member — the signed receipt, the
    manifest, the legal text, any proof — must come out byte-identical, and
    the README must be exactly what a fresh export of the same name renders.
    """
    gen = _load_generator()
    attest_path = Path(gen.main(tmp_path)["attest"])

    # Age the committed README by hand, the way a rewording ages it.
    with zipfile.ZipFile(attest_path) as zf:
        before = {info.filename: zf.read(info) for info in zf.infolist()}
    stale = dict(before)
    stale["README.html"] = b"<!doctype html><p>an older README</p>"
    with zipfile.ZipFile(attest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for member, data in stale.items():
            zf.writestr(member, data)

    assert gen.refresh_readme(attest_path) is True

    with zipfile.ZipFile(attest_path) as zf:
        after = {info.filename: zf.read(info) for info in zf.infolist()}
    assert list(after) == list(before)
    assert after["README.html"].decode("utf-8") == bundle._render_readme("demo")
    for member in before:
        if member != "README.html":
            assert after[member] == before[member], member
    # Already current: a second run is a no-op, and says so.
    assert gen.refresh_readme(attest_path) is False


def test_refresh_readme_refuses_anything_but_a_shareable_bundle(tmp_path: Path) -> None:
    gen = _load_generator()
    for name in ("demo.private.attest", "demo.zip", "demo"):
        path = tmp_path / name
        path.write_bytes(b"")
        with pytest.raises(RuntimeError):
            gen.refresh_readme(path)


def test_refresh_proof_refuses_anything_but_a_shareable_bundle(tmp_path: Path) -> None:
    """Same guard as the README refresh, and it needs its own case: every other
    test reaches `refresh_proof` through a generated `demo.attest`, so this
    branch is never taken with a name it must reject."""
    gen = _load_generator()
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    for name in ("demo.private.attest", "demo.zip", "demo"):
        path = tmp_path / name
        path.write_bytes(b"")
        with pytest.raises(RuntimeError, match="not a shareable bundle"):
            gen.refresh_proof(path, evidence)


def _mint_log_keys(tmp_path: Path) -> tuple[Path, Path]:
    """Mint the hybrid keypair that signs this test's log checkpoints.

    The generator takes the log signer's keys by path and never reads them from
    the tree, so exercising its logging half means supplying a pair here.
    """
    seed = tmp_path / "log.seed"
    mldsa = tmp_path / "log.mldsa"
    rc = cli.main(
        [
            "keygen",
            "--seed-out",
            str(seed),
            "--pub-out",
            str(tmp_path / "log.pub"),
            "--hybrid",
            "--mldsa-out",
            str(mldsa),
        ]
    )
    assert rc == 0
    return seed, mldsa


def _logged_sample(
    gen: ModuleType, out_dir: Path, log_dir: Path, log_keys: tuple[Path, Path]
) -> Path:
    """Generate one sample that carries the inclusion evidence for its receipt.

    `log_dir` is always a temporary one here. The generator's default is the log
    published under site/, and that log is append-only: a test that left the
    default in place would grow the real log by one entry per run.
    """
    seed, mldsa = log_keys
    report = gen.main(out_dir, log_dir=log_dir, log_ed25519_key=seed, log_mldsa_key=mldsa)
    assert report["logged"] is True
    return Path(report["attest"])


def _members(attest_path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(attest_path) as zf:
        return {info.filename: zf.read(info) for info in zf.infolist()}


def _member_metadata(attest_path: Path) -> dict[str, tuple[tuple[int, ...], int, int]]:
    """The archive metadata each member carries beside its payload.

    `_members` compares payloads, and a member's timestamp and mode live in the
    archive rather than in the bytes it hands back — so a refresh that dropped
    each member's `ZipInfo` and re-stamped it with the current time would leave
    every payload equal and still rewrite the published file.
    """
    with zipfile.ZipFile(attest_path) as zf:
        return {
            info.filename: (info.date_time, info.external_attr, info.compress_type)
            for info in zf.infolist()
        }


#: An instant well before any test run. A bundle generated in the same second
#: as the refresh under test cannot distinguish a member left alone from one
#: re-stamped with the time it already had; the committed sample is weeks
#: older than any refresh run against it, and this gives the fixture that gap.
_FIXTURE_MTIME = (2020, 1, 1, 0, 0, 0)


def _age_members(attest_path: Path, date_time: tuple[int, int, int, int, int, int]) -> None:
    """Backdate every member, so the refresh under test is not the only writer
    this fixture has ever had."""
    with zipfile.ZipFile(attest_path) as zf:
        members = [(info, zf.read(info)) for info in zf.infolist()]
    replacement = attest_path.with_name(attest_path.name + ".aged")
    with zipfile.ZipFile(replacement, "w", zipfile.ZIP_DEFLATED) as zf:
        for info, data in members:
            aged = zipfile.ZipInfo(info.filename, date_time=date_time)
            aged.external_attr = info.external_attr
            aged.compress_type = info.compress_type
            zf.writestr(aged, data)
    replacement.replace(attest_path)


def _sole_member_under(members: Mapping[str, bytes], prefix: str) -> str:
    names = [name for name in members if name.startswith(prefix)]
    assert len(names) == 1, f"expected exactly one {prefix}* member, found {names}"
    return names[0]


def _anchored(evidence: dict[str, Any], log_dir: Path, out_path: Path) -> dict[str, Any]:
    """Attach a synthetic Bitcoin-style anchor to this evidence's checkpoint.

    `attest log anchor` only ever attaches material obtained outside the
    process, so the block header here is invented rather than fetched. What
    makes it a usable stand-in is its merkle root: that value is what an OTS
    chain of a single `sha256` really produces from this checkpoint's signed
    note, so the anchor is replayed and accepted rather than waved through.
    """
    signed_note = tlog.parse_checkpoint(evidence["checkpoint"]).signed_note_bytes
    merkle_root = hashlib.sha256(hashlib.sha256(signed_note).digest()).hexdigest()
    header_hash = hashlib.sha256(b"attest-site-sample-test-anchor-header").hexdigest()

    workdir = out_path.parent
    evidence_path = workdir / "evidence.json"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    ots_path = workdir / "ots-proof.json"
    ots_path.write_text(
        json.dumps(
            {
                "ops": [["sha256"]],
                "header_merkle_root": merkle_root,
                "header_hash": header_hash,
                "header_time": 1700000000,
            }
        ),
        encoding="utf-8",
    )
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(ots_path),
            "--out",
            str(out_path),
        ]
    )
    assert rc == 0
    anchored: dict[str, Any] = json.loads(out_path.read_text(encoding="utf-8"))
    return anchored


def test_refresh_proof_rewrites_only_that_member(tmp_path: Path) -> None:
    """`--refresh-proof` is how the committed sample's inclusion evidence is
    replaced by a later version of itself — an anchored one, once an anchor
    exists for the checkpoint the evidence already names. Like the README
    refresh it is only safe if it touches nothing else: the signed receipt, the
    manifest, the legal text and the README must all come out byte-identical,
    and the new member must be spelled the way a fresh export would spell it.

    "Byte-identical" covers each member's archive metadata as well as its
    payload. A member's timestamp is part of the published file, and the
    committed sample's members are weeks older than any refresh run against
    them, so a copy-through that re-stamped them would churn bytes the page
    never asked to change — while every payload stayed equal.
    """
    gen = _load_generator()
    log_dir = tmp_path / "log"
    attest_path = _logged_sample(gen, tmp_path / "sample", log_dir, _mint_log_keys(tmp_path))
    _age_members(attest_path, _FIXTURE_MTIME)

    before = _members(attest_path)
    before_metadata = _member_metadata(attest_path)
    proof_member = _sole_member_under(before, "proofs/")
    evidence = json.loads(before[proof_member])
    anchored_path = tmp_path / "anchored-evidence.json"
    anchored = _anchored(evidence, log_dir, anchored_path)

    # The replacement has to differ from the original in exactly one way, or
    # the assertions below would pass without the code under test having done
    # anything: the same log entry, now carrying an anchor it did not carry.
    assert anchored["entry"] == evidence["entry"]
    assert "anchors" in anchored and "anchors" not in evidence

    assert gen.refresh_proof(attest_path, anchored_path) is True

    after = _members(attest_path)
    after_metadata = _member_metadata(attest_path)
    assert list(after) == list(before)
    assert json.loads(after[proof_member]) == anchored
    # `attest export` packs a proof as `json.dumps(evidence)`. A refresh that
    # spelled the same evidence differently would leave the committed bundle
    # unequal to the one a regeneration produces from that same evidence.
    assert after[proof_member] == json.dumps(anchored).encode("utf-8")
    for member, data in before.items():
        if member != proof_member:
            assert after[member] == data, member
            assert after_metadata[member] == before_metadata[member], member
    # The replaced member is the one member allowed to move, and it does move:
    # it is written the way `export` writes one, stamped at the time of writing.
    assert after_metadata[proof_member][0] != before_metadata[proof_member][0]
    # Already current: a second run is a no-op, and says so.
    assert gen.refresh_proof(attest_path, anchored_path) is False


def test_refresh_proof_refuses_evidence_for_another_receipt(tmp_path: Path) -> None:
    """The log accumulates one entry per published sample, so the file most
    easily picked up by mistake is the *previous* sample's evidence: same log,
    same origin, same shape, a different receipt. Swapped in, it would leave a
    bundle that still opens and whose receipt still verifies, while its proof
    proves something about somebody else's receipt. The refusal names both
    hashes, because that is what tells the operator which file they picked up.
    """
    gen = _load_generator()
    log_dir = tmp_path / "log"
    log_keys = _mint_log_keys(tmp_path)
    first = _logged_sample(gen, tmp_path / "first", log_dir, log_keys)
    second = _logged_sample(gen, tmp_path / "second", log_dir, log_keys)

    first_members, second_members = _members(first), _members(second)
    stray = tmp_path / "previous-sample-evidence.json"
    stray.write_bytes(first_members[_sole_member_under(first_members, "proofs/")])
    own = tmp_path / "own-evidence.json"
    own.write_bytes(second_members[_sole_member_under(second_members, "proofs/")])

    envelope = json.loads(second_members[_sole_member_under(second_members, "receipts/")])
    wanted = tlog.receipt_core_hash(envelope)
    got = json.loads(stray.read_text(encoding="utf-8"))["entry"]["core_sha256"]
    assert wanted != got, "the two samples have to describe different receipts"

    with pytest.raises(RuntimeError) as refusal:
        gen.refresh_proof(second, stray)
    assert wanted in str(refusal.value)
    assert got in str(refusal.value)
    # A refusal leaves the bundle alone: no half-rewritten archive on disk.
    assert _members(second) == second_members

    # Positive control, so the refusal above is known to be about which receipt
    # the file describes rather than about the call itself: the same call with
    # this bundle's own evidence gets past that check and reports no change.
    assert gen.refresh_proof(second, own) is False


def test_refresh_proof_refuses_a_file_that_is_not_evidence(tmp_path: Path) -> None:
    """Naming the right receipt is not the same as proving anything about it.

    A file carrying the right `core_sha256` and nothing else passes the
    wrong-receipt check and would install a proof that proves nothing. The
    result is the same undetectable state that check exists to prevent: the
    bundle opens, the receipt verifies, and `verify` reports `not_checked` for
    a page that claims this receipt is in a public log.
    """
    gen = _load_generator()
    log_dir = tmp_path / "log"
    attest_path = _logged_sample(gen, tmp_path / "sample", log_dir, _mint_log_keys(tmp_path))
    members = _members(attest_path)
    envelope = json.loads(members[_sole_member_under(members, "receipts/")])

    stub = tmp_path / "stub-evidence.json"
    stub.write_text(
        json.dumps({"entry": {"core_sha256": tlog.receipt_core_hash(envelope)}}),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="not inclusion evidence"):
        gen.refresh_proof(attest_path, stub)
    assert _members(attest_path) == members

    # A checkpoint alone is not evidence either: it says the log published a
    # tree, not that this receipt is in it. Measured, the bundle such a file
    # installs verifies to transparency='not_checked' — the same unbacked claim.
    checkpoint_only = tmp_path / "checkpoint-only-evidence.json"
    real = json.loads(members[_sole_member_under(members, "proofs/")])
    checkpoint_only.write_text(
        json.dumps(
            {
                "entry": {"core_sha256": tlog.receipt_core_hash(envelope)},
                "checkpoint": real["checkpoint"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="not inclusion evidence"):
        gen.refresh_proof(attest_path, checkpoint_only)
    assert _members(attest_path) == members


def test_refresh_proof_refuses_evidence_from_another_log(tmp_path: Path) -> None:
    """Evidence for the right receipt, in the right shape, from the wrong log.

    A checkpoint is the only part of an evidence file that names the log it
    came from. A second log that had also logged this receipt would produce a
    file clearing every other check here, and the published sample would then
    send a visitor to a log this project does not publish. The refusal names
    the origin it found, because that is what identifies the file.
    """
    gen = _load_generator()
    log_dir = tmp_path / "log"
    attest_path = _logged_sample(gen, tmp_path / "sample", log_dir, _mint_log_keys(tmp_path))
    members = _members(attest_path)
    evidence = json.loads(members[_sole_member_under(members, "proofs/")])

    foreign = dict(evidence)
    foreign["checkpoint"] = evidence["checkpoint"].replace(gen.LOG_ORIGIN, "other.example/log", 1)
    assert tlog.parse_checkpoint(foreign["checkpoint"]).origin == "other.example/log"
    path = tmp_path / "another-logs-evidence.json"
    path.write_text(json.dumps(foreign), encoding="utf-8")

    with pytest.raises(RuntimeError, match=r"is evidence from log 'other\.example/log'"):
        gen.refresh_proof(attest_path, path)
    assert _members(attest_path) == members


# --- the bundle actually published, not a fresh one --------------------------


def _site_log_keys() -> list[tlog.LogKey]:
    """Every log key the published verifier pins, read from the page's own source.

    A copy written out here would be a second pin that can disagree with the
    one the browser uses, which is the failure this whole file is about. But
    reading has to be exact, and a loose pattern is worse than a copy: a
    non-anchored search over the whole file will happily start at a string that
    merely looks like a pin — a comment, an older value left behind — and run on
    into the fields of the real entry, reconstructing a key that is pinned
    nowhere. Then the browser consumes one key and this test blesses another.

    So: find the `LOG_KEYS` array, take each object inside it whole, and read
    the four fields from within that object only. Every entry is returned,
    because a second pin is a second key the page would accept, not a spare.
    """
    source = TRUSTED_LOG_SOURCE.read_text(encoding="utf-8")
    block = re.search(
        r"^export const LOG_KEYS\b[^=]*=\s*\[(.*?)^\]",
        source,
        re.DOTALL | re.MULTILINE,
    )
    assert block is not None, f"cannot find the LOG_KEYS array in {TRUSTED_LOG_SOURCE.name}"

    pinned: list[tlog.LogKey] = []
    for entry in re.findall(r"\{([^{}]*)\}", block.group(1)):
        fields = dict(re.findall(r'(\w+):\s*(?:b64uDecode\(\s*)?"([^"]+)"', entry))
        missing = {"origin", "name", "ed25519Pub", "mldsaPub"} - set(fields)
        assert not missing, f"a LOG_KEYS entry is missing {sorted(missing)}"
        pinned.append(
            tlog.LogKey(
                origin=fields["origin"],
                name=fields["name"],
                ed25519_pub=keys.b64u_decode(fields["ed25519Pub"]),
                mldsa_pub=keys.b64u_decode(fields["mldsaPub"]),
            )
        )
    assert pinned, f"{TRUSTED_LOG_SOURCE.name} pins no log key at all"
    return pinned


def _committed_receipt() -> tuple[bundle.ImportedBundle, dict[str, object]]:
    imported = bundle.import_bundle(SAMPLE_BUNDLE)
    assert len(imported.receipts) == 1, "the sample is meant to hold one receipt"
    return imported, imported.receipts[0]


def test_committed_sample_bundle_still_verifies() -> None:
    """The signature over the published receipt still checks out against the
    trust material published beside it, and the whole envelope still satisfies
    the schema. A README refresh, a re-zip, a stray editor save: any of those
    can leave a bundle that opens and no longer verifies."""
    imported, receipt = _committed_receipt()
    result = verify.verify(json.dumps(receipt).encode("utf-8"), imported.trust_store)
    assert result.signature == "valid"
    assert result.schema == "valid"
    assert result.ok is True
    # Offline-imported manifests are TOFU by construction (design §5); a sample
    # that ever reported "verified" would be advertising trust it cannot have.
    assert result.trust == "unauthenticated_tofu"


def test_committed_sample_binding_sidecar_proves_the_buyer_commitment() -> None:
    """`demo-binding.json` is published so a visitor can reproduce the buyer
    binding, which is the step that shows the receipt is about a person and not
    just well-formed. Salt and commitment must still agree."""
    imported, receipt = _committed_receipt()
    sidecar = json.loads(SAMPLE_BINDING.read_text(encoding="utf-8"))
    disclosure = verify.Disclosure(
        identifier=sidecar["identifier"],
        identifier_type=sidecar["identifier_type"],
        salt=keys.b64u_decode(sidecar["salt_b64u"]),
    )
    result = verify.verify(
        json.dumps(receipt).encode("utf-8"), imported.trust_store, disclosure=disclosure
    )
    assert result.binding == "proven"
    assert result.ok is True


def test_committed_sample_carries_the_evidence_the_demo_promises() -> None:
    """The published bundle ships the legal text its licence binds, and a
    transparency proof for its receipt that actually proves something. Both are
    members a re-export can drop without the signature noticing — the receipt
    stays valid while the demo quietly stops demonstrating anything.

    The proof is EVALUATED, not counted. Asserting that the member is present
    accepts an empty object: the importer takes any JSON there, so a proof
    emptied to `{}` would leave the receipt verifying, the member in place, and
    the claim the demo makes — that this receipt is in a public log — unbacked.

    It is evaluated under the anchoring policy this repository publishes for
    that log, read from its file rather than restated here, because a policy
    restated here is a copy that can only ever agree with itself. Reading it
    makes this test move with the published configuration, and it moves now,
    not someday: measured, a `crqc_horizon` in that file drops this sample
    from `logged` to `not_checked`, since its evidence carries no anchor to
    survive a horizon. A pinned header on its own changes nothing, for the
    same reason — there is no anchor for it to match. So a red here, the day
    that file stops being empty, is the correct signal rather than a broken
    test: the published sample would have stopped demonstrating what the page
    claims about it, and it needs an anchor before it can be shipped again.
    """
    imported, receipt = _committed_receipt()
    payload = receipt["payload"]
    assert isinstance(payload, dict)
    receipt_id = payload["receipt_id"]
    assert isinstance(receipt_id, str)

    licence = payload["license"]
    assert isinstance(licence, dict)
    assert licence["legal_text_sha256"] in imported.legal_texts

    evidence = imported.proofs.get(receipt_id)
    assert evidence is not None, "the sample must carry the proof for its own receipt"
    result = verify.verify(
        json.dumps(receipt).encode("utf-8"),
        imported.trust_store,
        transparency=evidence,
        log_keys=_site_log_keys(),
        anchor_policy=cli._load_anchor_policy(SHIPPED_ANCHOR_POLICY, None),
    )
    assert result.transparency == "logged"
    assert result.corroboration == "logged"


def test_a_horizon_in_the_shipped_policy_would_unseat_the_sample(tmp_path: Path) -> None:
    """The test above reads the published policy instead of restating one, and
    its docstring says what happens the day that file stops being empty. That
    is a claim about behaviour, so it is measured here rather than left for a
    reader to trust — the more so because today the published file and an empty
    policy are the same object, which means reverting that line to a hardcoded
    policy would change nothing that any assertion can see.

    What is pinned is the mechanism, not the file's current contents: a
    `crqc_horizon` drops this sample out of `logged`, since its evidence
    carries no anchor to survive one, and a pinned header on its own changes
    nothing, for the same reason. So the red that arrives the day the policy is
    populated is the correct signal, and this says why.
    """
    imported, receipt = _committed_receipt()
    payload = receipt["payload"]
    assert isinstance(payload, dict)
    receipt_id = payload["receipt_id"]
    assert isinstance(receipt_id, str)
    evidence = imported.proofs[receipt_id]

    def _transparency_under(body: dict[str, Any]) -> str:
        path = tmp_path / "anchor-policy.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        return verify.verify(
            json.dumps(receipt).encode("utf-8"),
            imported.trust_store,
            transparency=evidence,
            log_keys=_site_log_keys(),
            anchor_policy=cli._load_anchor_policy(path, None),
        ).transparency

    header = "a" * 64
    pinned = {header: {"header_hash": header, "merkle_root": header, "time": 1600000000}}
    assert _transparency_under({"crqc_horizon": None, "pinned_headers": {}}) == "logged"
    assert _transparency_under({"crqc_horizon": None, "pinned_headers": pinned}) == "logged"
    assert _transparency_under({"crqc_horizon": 1600000000, "pinned_headers": {}}) == "not_checked"
    assert (
        _transparency_under({"crqc_horizon": 1600000000, "pinned_headers": pinned}) == "not_checked"
    )
