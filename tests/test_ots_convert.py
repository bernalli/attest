"""OpenTimestamps conversion tests.

The `.ots` inputs below are assembled byte-by-byte inside this file. That keeps
the converter tests from sharing a generator with the parser or the converter.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from attest import anchor, cli, ots, tlog

CapSys = pytest.CaptureFixture[str]

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
TAG_SHA256 = b"\x08"
TAG_APPEND = b"\xf0"
TAG_PREPEND = b"\xf1"
TAG_ATTESTATION = b"\x00"
TAG_FORK = b"\xff"
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_LITECOIN = bytes.fromhex("06869a0d73d71b45")
TAG_ETHEREUM = bytes.fromhex("30fe8087b5c7ead7")
TAG_UNKNOWN_ATTESTATION = bytes.fromhex("1122334455667788")

LOG_ORIGIN = "attest-transparency-log.example/test"


def _varuint(value: int) -> bytes:
    assert value >= 0
    encoded = bytearray()
    remaining = value
    while True:
        byte = remaining & 0x7F
        remaining >>= 7
        if remaining:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def _varbytes(value: bytes) -> bytes:
    return _varuint(len(value)) + value


def _attestation(tag: bytes, payload: bytes) -> bytes:
    return TAG_ATTESTATION + tag + _varbytes(payload)


def _bitcoin_attestation(height: int) -> bytes:
    return _attestation(TAG_BITCOIN, _varuint(height))


def _pending_attestation(payload: bytes = b"https://calendar.example/pending") -> bytes:
    return _attestation(TAG_PENDING, payload)


def _ots_with_tree(tree: bytes, *, digest: bytes) -> bytes:
    return MAGIC + b"\x01" + TAG_SHA256 + digest + tree


def _branch_append(value: bytes, height: int) -> bytes:
    return TAG_APPEND + _varbytes(value) + TAG_SHA256 + _bitcoin_attestation(height)


def _branch_prepend(value: bytes, height: int) -> bytes:
    return TAG_PREPEND + _varbytes(value) + TAG_SHA256 + _bitcoin_attestation(height)


def _parsed_with_two_bitcoin_and_pending(seed: bytes) -> ots.OtsFile:
    return ots.parse_ots(
        _ots_with_tree(
            b"".join(
                [
                    TAG_FORK,
                    _branch_append(b"left", 42),
                    TAG_FORK,
                    _branch_prepend(b"right", 43),
                    TAG_APPEND,
                    _varbytes(b"pending"),
                    TAG_SHA256,
                    _pending_attestation(),
                ]
            ),
            digest=seed,
        )
    )


def _parsed_with_identical_bitcoin_paths(seed: bytes) -> ots.OtsFile:
    branch = _branch_append(b"same", 42)
    return ots.parse_ots(_ots_with_tree(TAG_FORK + branch + branch, digest=seed))


def _single_path_file(
    seed: bytes,
    *,
    ops_: tuple[ots.OtsOp, ...],
    attestation: ots.OtsAttestation,
    file_hash_op: str = "sha256",
) -> ots.OtsFile:
    return ots.OtsFile(
        file_digest=seed, file_hash_op=file_hash_op, paths=(ots.OtsPath(ops_, attestation),)
    )


def _replay(seed: bytes, ops_: tuple[ots.OtsOp, ...]) -> bytes:
    accumulator = seed
    for op in ops_:
        if op.name == "append":
            assert op.operand is not None
            accumulator = accumulator + op.operand
        elif op.name == "prepend":
            assert op.operand is not None
            accumulator = op.operand + accumulator
        elif op.name == "sha256":
            assert op.operand is None
            accumulator = hashlib.sha256(accumulator).digest()
        else:
            raise AssertionError(f"unsupported test op {op.name}")
    return accumulator


def _header(
    height: int,
    merkle_root: str,
    *,
    header_hash: str | None = None,
    time: int = 1_700_000_000,
) -> ots.OperatorHeader:
    if header_hash is None:
        header_hash = hashlib.sha256(f"block-header-{height}".encode("ascii")).hexdigest()
    return ots.OperatorHeader(
        height=height,
        header_hash=header_hash,
        merkle_root=merkle_root,
        time=time,
    )


def _headers_for_parsed(seed: bytes, parsed: ots.OtsFile) -> list[ots.OperatorHeader]:
    headers: list[ots.OperatorHeader] = []
    for path in parsed.paths:
        if path.attestation.kind != "bitcoin":
            continue
        assert path.attestation.height is not None
        root = _replay(seed, path.ops).hex()
        headers.append(
            _header(path.attestation.height, root, time=1_700_000_000 + path.attestation.height)
        )
    return headers


def _minimal_anchor_evidence() -> dict[str, str]:
    checkpoint = "\n".join(
        [
            LOG_ORIGIN,
            "0",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "",
            "\u2014 test-signer AA==",
            "",
        ]
    )
    return {"checkpoint": checkpoint}


def _expected_seed_from_evidence(evidence: dict[str, str]) -> bytes:
    checkpoint = tlog.parse_checkpoint(evidence["checkpoint"])
    return hashlib.sha256(checkpoint.signed_note_bytes).digest()


def _write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_convert_ots_emits_anchor_proofs_and_reports_pending_skip() -> None:
    seed = hashlib.sha256(b"signed-note-seed").digest()
    parsed = _parsed_with_two_bitcoin_and_pending(seed)
    headers = _headers_for_parsed(seed, parsed)

    result = ots.convert_ots(parsed, seed, headers)

    assert [proof.path_index for proof in result.proofs] == [0, 1]
    assert result.proofs[0].proof == {
        "ops": [["append", b"left".hex()], ["sha256"]],
        "header_merkle_root": headers[0].merkle_root,
        "header_hash": headers[0].header_hash,
        "header_time": headers[0].time,
    }
    assert result.proofs[1].proof == {
        "ops": [["prepend", b"right".hex()], ["sha256"]],
        "header_merkle_root": headers[1].merkle_root,
        "header_hash": headers[1].header_hash,
        "header_time": headers[1].time,
    }
    assert [(entry.path_index, entry.converted, entry.reason) for entry in result.report] == [
        (0, True, None),
        (1, True, None),
        (2, False, "pending attestation is not upgraded yet; run `ots upgrade` first"),
    ]


def test_convert_ots_rejects_digest_mismatch_with_both_digests() -> None:
    parsed = _parsed_with_two_bitcoin_and_pending(b"\x11" * 32)
    expected_seed = b"\x22" * 32

    with pytest.raises(ots.OtsError) as excinfo:
        ots.convert_ots(parsed, expected_seed, [])

    message = str(excinfo.value)
    assert parsed.file_digest.hex() in message
    assert expected_seed.hex() in message
    assert "does not match expected SHA256(signed_note_bytes)" in message


def test_convert_ots_rejects_non_sha256_file_hash_op() -> None:
    seed = b"\x11" * 32
    parsed = ots.OtsFile(file_digest=seed, file_hash_op="sha1", paths=())

    with pytest.raises(ots.OtsError, match="ots file hash op sha1 is not sha256"):
        ots.convert_ots(parsed, seed, [])


def test_convert_ots_reports_unconvertible_ripemd160_bitcoin_path() -> None:
    seed = b"\x33" * 32
    parsed = _single_path_file(
        seed,
        ops_=(ots.OtsOp("ripemd160"),),
        attestation=ots.OtsAttestation("bitcoin", TAG_BITCOIN, _varuint(42), 42),
    )

    with pytest.raises(ots.OtsConversionError) as excinfo:
        ots.convert_ots(parsed, seed, [_header(42, seed.hex())])

    assert "ripemd160" in str(excinfo.value)
    assert "Bitcoin height 42" in str(excinfo.value)
    assert excinfo.value.report[0].height == 42


@pytest.mark.parametrize(
    ("kind", "tag"),
    [
        ("litecoin", TAG_LITECOIN),
        ("ethereum", TAG_ETHEREUM),
        ("unknown", TAG_UNKNOWN_ATTESTATION),
    ],
)
def test_convert_ots_skips_non_bitcoin_attestations_by_kind_and_tag(kind: str, tag: bytes) -> None:
    seed = b"\x44" * 32
    parsed = _single_path_file(
        seed,
        ops_=(ots.OtsOp("sha256"),),
        attestation=ots.OtsAttestation(kind, tag, b"payload"),
    )

    with pytest.raises(ots.OtsConversionError) as excinfo:
        ots.convert_ots(parsed, seed, [])

    message = str(excinfo.value)
    assert kind in message
    assert tag.hex() in message


def test_convert_ots_reports_merkle_root_mismatch_with_height() -> None:
    seed = b"\x55" * 32
    parsed = _single_path_file(
        seed,
        ops_=(ots.OtsOp("sha256"),),
        attestation=ots.OtsAttestation("bitcoin", TAG_BITCOIN, _varuint(42), 42),
    )

    with pytest.raises(ots.OtsConversionError) as excinfo:
        ots.convert_ots(parsed, seed, [_header(42, "aa" * 32)])

    assert "Bitcoin height 42" in str(excinfo.value)
    assert "merkle_root does not match" in str(excinfo.value)


def test_convert_ots_reports_missing_operator_header_for_height() -> None:
    seed = b"\x66" * 32
    parsed = _single_path_file(
        seed,
        ops_=(ots.OtsOp("sha256"),),
        attestation=ots.OtsAttestation("bitcoin", TAG_BITCOIN, _varuint(42), 42),
    )

    with pytest.raises(ots.OtsConversionError) as excinfo:
        ots.convert_ots(parsed, seed, [])

    assert "missing operator header for Bitcoin height 42" in str(excinfo.value)


def test_convert_ots_rejects_duplicate_operator_header_heights_before_conversion() -> None:
    seed = b"\x77" * 32
    parsed = _single_path_file(
        seed,
        ops_=(ots.OtsOp("sha256"),),
        attestation=ots.OtsAttestation("bitcoin", TAG_BITCOIN, _varuint(42), 42),
    )
    headers = [_header(42, "11" * 32), _header(42, "22" * 32)]

    with pytest.raises(ots.OtsError, match="duplicate operator header height 42"):
        ots.convert_ots(parsed, seed, headers)


def test_convert_ots_rejects_zero_survivors_with_every_path_reason() -> None:
    seed = b"\x88" * 32
    parsed = ots.OtsFile(
        file_digest=seed,
        file_hash_op="sha256",
        paths=(
            ots.OtsPath(
                (ots.OtsOp("sha256"),),
                ots.OtsAttestation("pending", TAG_PENDING, b"https://calendar.example/pending"),
            ),
            ots.OtsPath(
                (ots.OtsOp("sha256"),),
                ots.OtsAttestation("litecoin", TAG_LITECOIN, b"payload"),
            ),
        ),
    )

    with pytest.raises(ots.OtsConversionError) as excinfo:
        ots.convert_ots(parsed, seed, [])

    message = str(excinfo.value)
    assert "path 0" in message
    assert "ots upgrade" in message
    assert "path 1" in message
    assert TAG_LITECOIN.hex() in message
    assert len(excinfo.value.report) == 2


def test_convert_ots_requires_typed_parser_output() -> None:
    with pytest.raises(ots.OtsError, match="convert_ots requires OtsFile"):
        ots.convert_ots(b"not parsed", b"\x00" * 32, [])


def test_log_ots_convert_writes_proofs_pinned_headers_and_report(
    tmp_path: Path, capsys: CapSys
) -> None:
    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    parsed = _parsed_with_two_bitcoin_and_pending(seed)
    headers = _headers_for_parsed(seed, parsed)
    ots_path = tmp_path / "stamp.ots"
    ots_path.write_bytes(
        _ots_with_tree(
            b"".join(
                [
                    TAG_FORK,
                    _branch_append(b"left", 42),
                    TAG_FORK,
                    _branch_prepend(b"right", 43),
                    TAG_APPEND,
                    _varbytes(b"pending"),
                    TAG_SHA256,
                    _pending_attestation(),
                ]
            ),
            digest=seed,
        )
    )
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    headers_path = _write_json(tmp_path / "headers.json", [header.__dict__ for header in headers])
    out_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    stdout = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert stdout["proofs"] == 2
    assert stdout["report"] == str(out_dir / "conversion-report.json")
    assert json.loads((out_dir / "proof-0-42.json").read_text(encoding="utf-8")) == {
        "ops": [["append", b"left".hex()], ["sha256"]],
        "header_merkle_root": headers[0].merkle_root,
        "header_hash": headers[0].header_hash,
        "header_time": headers[0].time,
    }
    assert json.loads((out_dir / "proof-1-43.json").read_text(encoding="utf-8")) == {
        "ops": [["prepend", b"right".hex()], ["sha256"]],
        "header_merkle_root": headers[1].merkle_root,
        "header_hash": headers[1].header_hash,
        "header_time": headers[1].time,
    }
    assert json.loads((out_dir / "pinned-headers.json").read_text(encoding="utf-8")) == {
        "pinned_headers": {
            headers[0].header_hash: {
                "header_hash": headers[0].header_hash,
                "merkle_root": headers[0].merkle_root,
                "time": headers[0].time,
            },
            headers[1].header_hash: {
                "header_hash": headers[1].header_hash,
                "merkle_root": headers[1].merkle_root,
                "time": headers[1].time,
            },
        }
    }
    report = json.loads((out_dir / "conversion-report.json").read_text(encoding="utf-8"))
    assert [
        (entry["path_index"], entry["converted"], entry["reason"]) for entry in report["paths"]
    ] == [
        (0, True, None),
        (1, True, None),
        (2, False, "pending attestation is not upgraded yet; run `ots upgrade` first"),
    ]


def test_log_ots_convert_report_names_skipped_bitcoin_height_on_partial_success(
    tmp_path: Path, capsys: CapSys
) -> None:
    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    ots_path = tmp_path / "stamp.ots"
    ots_path.write_bytes(
        _ots_with_tree(
            TAG_FORK + _branch_append(b"left", 42) + _branch_prepend(b"right", 43),
            digest=seed,
        )
    )
    parsed = ots.parse_ots(ots_path.read_bytes())
    headers = _headers_for_parsed(seed, parsed)[:1]
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    headers_path = _write_json(tmp_path / "headers.json", [header.__dict__ for header in headers])
    out_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    capsys.readouterr()

    assert rc == 0
    assert (out_dir / "proof-0-42.json").exists()
    assert not (out_dir / "proof-1-43.json").exists()
    report = json.loads((out_dir / "conversion-report.json").read_text(encoding="utf-8"))
    skipped = report["paths"][1]
    assert skipped["attestation_kind"] == "bitcoin"
    assert skipped["height"] == 43
    assert skipped["converted"] is False
    assert skipped["reason"] == "missing operator header for Bitcoin height 43"


def test_log_ots_convert_rejects_malformed_block_headers(tmp_path: Path, capsys: CapSys) -> None:
    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    ots_path = tmp_path / "stamp.ots"
    ots_path.write_bytes(_ots_with_tree(_branch_append(b"left", 42), digest=seed))
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    headers_path = _write_json(tmp_path / "headers.json", {"height": 42})
    out_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "--block-headers must contain a JSON array" in captured.err
    assert not out_dir.exists()


def test_log_ots_convert_rejects_duplicate_header_heights_without_outputs(
    tmp_path: Path, capsys: CapSys
) -> None:
    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    ots_path = tmp_path / "stamp.ots"
    ots_path.write_bytes(_ots_with_tree(_branch_append(b"left", 42), digest=seed))
    parsed = ots.parse_ots(ots_path.read_bytes())
    header = _headers_for_parsed(seed, parsed)[0]
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    headers_path = _write_json(tmp_path / "headers.json", [header.__dict__, header.__dict__])
    out_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "duplicate operator header height 42" in captured.err
    assert not out_dir.exists()


def test_log_ots_convert_keeps_same_height_paths_as_distinct_files(
    tmp_path: Path, capsys: CapSys
) -> None:
    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    branch = _branch_append(b"same", 42)
    ots_path = tmp_path / "stamp.ots"
    ots_path.write_bytes(_ots_with_tree(TAG_FORK + branch + branch, digest=seed))
    parsed = _parsed_with_identical_bitcoin_paths(seed)
    headers = _headers_for_parsed(seed, parsed)[:1]
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    headers_path = _write_json(tmp_path / "headers.json", [headers[0].__dict__])
    out_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    capsys.readouterr()

    assert rc == 0
    proof_0 = out_dir / "proof-0-42.json"
    proof_1 = out_dir / "proof-1-42.json"
    assert proof_0.exists()
    assert proof_1.exists()
    assert json.loads(proof_0.read_text(encoding="utf-8")) == json.loads(
        proof_1.read_text(encoding="utf-8")
    )
    report = json.loads((out_dir / "conversion-report.json").read_text(encoding="utf-8"))
    assert [entry["path_index"] for entry in report["paths"] if entry["converted"]] == [0, 1]


# --- not-well-formed `--block-headers`: converter level -----------------------


def _one_bitcoin_path(seed: bytes, height: int = 42) -> ots.OtsFile:
    return _single_path_file(
        seed,
        ops_=(ots.OtsOp("sha256"),),
        attestation=ots.OtsAttestation("bitcoin", TAG_BITCOIN, _varuint(height), height),
    )


@pytest.mark.parametrize(
    ("header", "fragment"),
    [
        (ots.OperatorHeader(-1, "aa" * 32, "bb" * 32, 1), "height must be a non-negative int"),
        (ots.OperatorHeader(True, "aa" * 32, "bb" * 32, 1), "height must be a non-negative int"),
        (ots.OperatorHeader("42", "aa" * 32, "bb" * 32, 1), "height must be a non-negative int"),
        (ots.OperatorHeader(42.0, "aa" * 32, "bb" * 32, 1), "height must be a non-negative int"),
        (ots.OperatorHeader(42, None, "bb" * 32, 1), "header_hash must be 64 lowercase hex chars"),
        (
            ots.OperatorHeader(42, "AA" * 32, "bb" * 32, 1),
            "header_hash must be 64 lowercase hex chars",
        ),
        (
            ots.OperatorHeader(42, "aa" * 31, "bb" * 32, 1),
            "header_hash must be 64 lowercase hex chars",
        ),
        (
            ots.OperatorHeader(42, "aa" * 33, "bb" * 32, 1),
            "header_hash must be 64 lowercase hex chars",
        ),
        (
            ots.OperatorHeader(42, "zz" * 32, "bb" * 32, 1),
            "header_hash must be 64 lowercase hex chars",
        ),
        (
            ots.OperatorHeader(42, "aa" * 32 + "\n", "bb" * 32, 1),
            "header_hash must be 64 lowercase hex chars",
        ),
        (ots.OperatorHeader(42, "aa" * 32, None, 1), "merkle_root must be 64 lowercase hex chars"),
        (
            ots.OperatorHeader(42, "aa" * 32, "BB" * 32, 1),
            "merkle_root must be 64 lowercase hex chars",
        ),
        (
            ots.OperatorHeader(42, "aa" * 32, "bb" * 31, 1),
            "merkle_root must be 64 lowercase hex chars",
        ),
        (
            ots.OperatorHeader(42, "aa" * 32, "zz" * 32, 1),
            "merkle_root must be 64 lowercase hex chars",
        ),
        (ots.OperatorHeader(42, "aa" * 32, "bb" * 32, 0), "time must be a positive int"),
        (ots.OperatorHeader(42, "aa" * 32, "bb" * 32, -1), "time must be a positive int"),
        (ots.OperatorHeader(42, "aa" * 32, "bb" * 32, True), "time must be a positive int"),
        (ots.OperatorHeader(42, "aa" * 32, "bb" * 32, 1.5), "time must be a positive int"),
        (ots.OperatorHeader(42, "aa" * 32, "bb" * 32, "1"), "time must be a positive int"),
        (
            ots.OperatorHeader(42, "aa" * 32, "bb" * 32, anchor._MAX_RENDERABLE_UNIX_TIME + 1),
            "time must be a positive int",
        ),
    ],
)
def test_convert_ots_rejects_malformed_operator_headers(
    header: ots.OperatorHeader, fragment: str
) -> None:
    seed = b"\xa1" * 32

    with pytest.raises(ots.OtsError) as excinfo:
        ots.convert_ots(_one_bitcoin_path(seed), seed, [header])

    assert fragment in str(excinfo.value)
    assert "operator header 0" in str(excinfo.value)


@pytest.mark.parametrize("headers", [42, "abc", b"\x00", None, {"height": 42}, 1.5])
def test_convert_ots_rejects_headers_that_are_not_a_sequence(headers: object) -> None:
    seed = b"\xa2" * 32

    with pytest.raises(ots.OtsError, match="operator headers must be a sequence"):
        ots.convert_ots(_one_bitcoin_path(seed), seed, headers)


@pytest.mark.parametrize(
    "item",
    [{"height": 42, "header_hash": "aa" * 32, "merkle_root": "bb" * 32, "time": 1}, 42, None],
)
def test_convert_ots_rejects_header_items_that_are_not_operator_headers(item: object) -> None:
    seed = b"\xa3" * 32

    with pytest.raises(ots.OtsError, match="operator header 0 must be an OperatorHeader"):
        ots.convert_ots(_one_bitcoin_path(seed), seed, [item])


def test_convert_ots_rejects_two_heights_sharing_one_header_hash() -> None:
    """`pinned_headers` is a MAP keyed by `header_hash` (C-41): two heights
    claiming one hash would collapse into a single pinned entry, and the
    surviving proof would carry a merkle_root the pinned header contradicts."""

    seed = b"\xa4" * 32
    headers = [
        _header(42, "11" * 32, header_hash="cc" * 32),
        _header(43, "22" * 32, header_hash="cc" * 32),
    ]

    with pytest.raises(ots.OtsError, match="duplicate operator header hash " + "cc" * 32):
        ots.convert_ots(_one_bitcoin_path(seed), seed, headers)


def test_convert_ots_rejects_a_non_digest_expected_seed() -> None:
    seed = b"\xa5" * 32

    with pytest.raises(ots.OtsError, match="expected_seed must be a SHA-256 digest"):
        ots.convert_ots(_one_bitcoin_path(seed), b"\xa5" * 31, [])


# --- paths the parser never produces, and one it does ------------------------


@pytest.mark.parametrize(
    ("op", "fragment"),
    [
        (ots.OtsOp("sha256", b"unexpected"), "sha256 op carries an operand on Bitcoin height 42"),
        (ots.OtsOp("append", None), "append op lacks a bytes operand on Bitcoin height 42"),
        (ots.OtsOp("prepend", None), "prepend op lacks a bytes operand on Bitcoin height 42"),
        (ots.OtsOp("append", "6c656674"), "append op lacks a bytes operand on Bitcoin height 42"),
    ],
)
def test_convert_ots_refuses_ops_that_are_not_wire_shaped(op: ots.OtsOp, fragment: str) -> None:
    seed = b"\xa6" * 32
    parsed = _single_path_file(
        seed,
        ops_=(op,),
        attestation=ots.OtsAttestation("bitcoin", TAG_BITCOIN, _varuint(42), 42),
    )

    with pytest.raises(ots.OtsConversionError) as excinfo:
        ots.convert_ots(parsed, seed, [_header(42, "bb" * 32)])

    assert fragment in str(excinfo.value)


def test_convert_ots_skips_a_bitcoin_attestation_without_a_height() -> None:
    seed = b"\xa7" * 32
    parsed = _single_path_file(
        seed,
        ops_=(ots.OtsOp("sha256"),),
        attestation=ots.OtsAttestation("bitcoin", TAG_BITCOIN, b"", None),
    )

    with pytest.raises(ots.OtsConversionError) as excinfo:
        ots.convert_ots(parsed, seed, [_header(42, "bb" * 32)])

    assert "bitcoin attestation has no usable block height" in str(excinfo.value)


def test_convert_ots_refuses_a_leaf_that_commits_to_nothing() -> None:
    """A real `.ots` may carry an attestation with no ops at all; the empty
    op-chain must be refused with the height, never emitted as a proof."""

    seed = hashlib.sha256(b"empty-chain-seed").digest()
    parsed = ots.parse_ots(_ots_with_tree(_bitcoin_attestation(42), digest=seed))
    assert parsed.paths[0].ops == ()

    with pytest.raises(ots.OtsConversionError) as excinfo:
        ots.convert_ots(parsed, seed, [_header(42, seed.hex())])

    assert "empty op-chain" in str(excinfo.value)
    assert "Bitcoin height 42" in str(excinfo.value)


def test_convert_ots_keeps_byte_identical_paths_as_separate_proofs() -> None:
    """C-41/C-48 at the converter boundary, independent of the CLI: `OtsPath`
    is a frozen dataclass, so `set()`/`dict.fromkeys()` would fuse two
    byte-identical calendar branches into one anchoring claim."""

    seed = b"\xa8" * 32
    parsed = _parsed_with_identical_bitcoin_paths(seed)
    headers = _headers_for_parsed(seed, parsed)[:1]

    result = ots.convert_ots(parsed, seed, headers)

    assert [proof.path_index for proof in result.proofs] == [0, 1]
    assert [entry.path_index for entry in result.report] == [0, 1]


# --- not-well-formed `--block-headers`: CLI level -----------------------------


def _convert_cli(tmp_path: Path, out_dir: Path, headers_path: Path) -> int:
    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    ots_path = tmp_path / "stamp.ots"
    ots_path.write_bytes(_ots_with_tree(_branch_append(b"left", 42), digest=seed))
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    return cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )


_GOOD_HEADER = {"height": 42, "header_hash": "aa" * 32, "merkle_root": "bb" * 32, "time": 1}


@pytest.mark.parametrize(
    ("document", "fragment"),
    [
        # Refused by the CLI's own shape check: the message names the option
        # and the index, so a correct refusal cannot be confused with an
        # unrelated failure (the discipline `test_cli_overwrite.py` states).
        ([42], "--block-headers[0] must be a JSON object"),
        (["header"], "--block-headers[0] must be a JSON object"),
        ([None], "--block-headers[0] must be a JSON object"),
        ([[]], "--block-headers[0] must be a JSON object"),
        (
            [{**_GOOD_HEADER, "height": "42"}],
            "--block-headers[0].height must be a non-negative int",
        ),
        (
            [{**_GOOD_HEADER, "height": True}],
            "--block-headers[0].height must be a non-negative int",
        ),
        (
            [{**_GOOD_HEADER, "height": 42.0}],
            "--block-headers[0].height must be a non-negative int",
        ),
        (
            [{**_GOOD_HEADER, "height": None}],
            "--block-headers[0].height must be a non-negative int",
        ),
        (
            [{k: v for k, v in _GOOD_HEADER.items() if k != "height"}],
            "--block-headers[0].height must be a non-negative int",
        ),
        ([{**_GOOD_HEADER, "header_hash": 42}], "--block-headers[0].header_hash must be a string"),
        (
            [{k: v for k, v in _GOOD_HEADER.items() if k != "header_hash"}],
            "--block-headers[0].header_hash must be a string",
        ),
        (
            [{**_GOOD_HEADER, "merkle_root": None}],
            "--block-headers[0].merkle_root must be a string",
        ),
        (
            [{k: v for k, v in _GOOD_HEADER.items() if k != "merkle_root"}],
            "--block-headers[0].merkle_root must be a string",
        ),
        ([{**_GOOD_HEADER, "time": "1"}], "--block-headers[0].time must be a positive int"),
        ([{**_GOOD_HEADER, "time": True}], "--block-headers[0].time must be a positive int"),
        (
            [{k: v for k, v in _GOOD_HEADER.items() if k != "time"}],
            "--block-headers[0].time must be a positive int",
        ),
        # Well-typed on the wire, refused by the converter's own validator:
        # the message comes from the other layer, and that is the point.
        ([{**_GOOD_HEADER, "height": -1}], "operator header 0 height must be a non-negative int"),
        (
            [{**_GOOD_HEADER, "header_hash": "AA" * 32}],
            "operator header 0 header_hash must be 64 lowercase hex chars",
        ),
        (
            [{**_GOOD_HEADER, "header_hash": "aa" * 31}],
            "operator header 0 header_hash must be 64 lowercase hex chars",
        ),
        (
            [{**_GOOD_HEADER, "merkle_root": "BB" * 32}],
            "operator header 0 merkle_root must be 64 lowercase hex chars",
        ),
        ([{**_GOOD_HEADER, "time": 0}], "operator header 0 time must be a positive int"),
        ([{**_GOOD_HEADER, "time": -1}], "operator header 0 time must be a positive int"),
        ([_GOOD_HEADER, {**_GOOD_HEADER, "height": 43}], "duplicate operator header hash"),
    ],
)
def test_log_ots_convert_rejects_malformed_block_headers_without_outputs(
    tmp_path: Path, capsys: CapSys, document: object, fragment: str
) -> None:
    headers_path = _write_json(tmp_path / "headers.json", document)
    out_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = _convert_cli(tmp_path, out_dir, headers_path)
    captured = capsys.readouterr()

    assert rc == 2
    assert fragment in captured.err
    assert not out_dir.exists()


@pytest.mark.parametrize("raw", ["", "   ", "not json", "[", '{"height": 42'])
def test_log_ots_convert_rejects_block_headers_that_are_not_json(
    tmp_path: Path, capsys: CapSys, raw: str
) -> None:
    headers_path = tmp_path / "headers.json"
    headers_path.write_text(raw, encoding="utf-8")
    out_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = _convert_cli(tmp_path, out_dir, headers_path)
    captured = capsys.readouterr()

    assert rc == 2
    assert "invalid JSON in" in captured.err
    assert not out_dir.exists()


def test_log_ots_convert_rejects_an_oversized_ots_file(tmp_path: Path, capsys: CapSys) -> None:
    """The `.ots` ceiling is enforced before the parser sees a byte."""

    evidence = _minimal_anchor_evidence()
    ots_path = tmp_path / "stamp.ots"
    ots_path.write_bytes(b"\x00" * (cli._MAX_STAGE2_INPUT_BYTES["ots"] + 1))
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    headers_path = _write_json(tmp_path / "headers.json", [_GOOD_HEADER])
    out_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert f"--ots input exceeds {ots._MAX_OTS_FILE_BYTES} bytes" in captured.err
    assert not out_dir.exists()


def test_log_ots_convert_rejects_a_malformed_ots_file(tmp_path: Path, capsys: CapSys) -> None:
    evidence = _minimal_anchor_evidence()
    ots_path = tmp_path / "stamp.ots"
    # Long enough to reach the magic comparison instead of the truncation check.
    ots_path.write_bytes(b"not an OpenTimestamps proof file, not at all")
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    headers_path = _write_json(tmp_path / "headers.json", [_GOOD_HEADER])
    out_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "invalid OpenTimestamps magic" in captured.err
    assert not out_dir.exists()


# --- the failure direction stays loud -----------------------------------------


def test_log_ots_convert_zero_survivors_writes_the_report_and_fails(
    tmp_path: Path, capsys: CapSys
) -> None:
    """Zero survivors is an error that still leaves the operator the reasons,
    with the block height of every skipped Bitcoin path — losing the oldest
    anchor silently is losing the strongest `anchored_before` claim."""

    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    ots_path = tmp_path / "stamp.ots"
    ots_path.write_bytes(_ots_with_tree(_branch_append(b"left", 700_000), digest=seed))
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    headers_path = _write_json(tmp_path / "headers.json", [])
    out_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "no convertible Bitcoin paths found" in captured.err
    assert "missing operator header for Bitcoin height 700000" in captured.err
    report = json.loads((out_dir / "conversion-report.json").read_text(encoding="utf-8"))
    assert report["converted"] == 0
    assert report["skipped"] == 1
    assert report["paths"][0]["height"] == 700000
    assert report["paths"][0]["proof_file"] is None
    assert not (out_dir / "pinned-headers.json").exists()
    assert list(out_dir.glob("proof-*.json")) == []


def test_log_ots_convert_report_counts_and_links_every_row_to_its_file(
    tmp_path: Path, capsys: CapSys
) -> None:
    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    parsed = _parsed_with_two_bitcoin_and_pending(seed)
    headers = _headers_for_parsed(seed, parsed)
    ots_path = tmp_path / "stamp.ots"
    ots_path.write_bytes(
        _ots_with_tree(
            b"".join(
                [
                    TAG_FORK,
                    _branch_append(b"left", 42),
                    TAG_FORK,
                    _branch_prepend(b"right", 43),
                    TAG_APPEND,
                    _varbytes(b"pending"),
                    TAG_SHA256,
                    _pending_attestation(),
                ]
            ),
            digest=seed,
        )
    )
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    headers_path = _write_json(tmp_path / "headers.json", [header.__dict__ for header in headers])
    out_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    stdout = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert stdout["proofs"] == 2
    assert stdout["skipped"] == 1
    assert stdout["skipped_bitcoin_heights"] == []
    report = json.loads((out_dir / "conversion-report.json").read_text(encoding="utf-8"))
    assert report["converted"] == 2
    assert report["skipped"] == 1
    assert [entry["proof_file"] for entry in report["paths"]] == [
        "proof-0-42.json",
        "proof-1-43.json",
        None,
    ]
    for entry in report["paths"]:
        if entry["proof_file"] is not None:
            assert (out_dir / entry["proof_file"]).exists()


def test_log_ots_convert_stdout_names_the_skipped_bitcoin_heights(
    tmp_path: Path, capsys: CapSys
) -> None:
    """A dropped Bitcoin path is a lost `anchored_before` claim: it has to
    reach the operator's own channel, not only a file they may never open."""

    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    ots_path = tmp_path / "stamp.ots"
    ots_path.write_bytes(
        _ots_with_tree(
            TAG_FORK + _branch_append(b"left", 42) + _branch_prepend(b"right", 43),
            digest=seed,
        )
    )
    parsed = ots.parse_ots(ots_path.read_bytes())
    headers = _headers_for_parsed(seed, parsed)[:1]
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    headers_path = _write_json(tmp_path / "headers.json", [header.__dict__ for header in headers])
    out_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    stdout = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert stdout["proofs"] == 1
    assert stdout["skipped"] == 1
    assert stdout["skipped_bitcoin_heights"] == [43]


# --- an output must never land on one of this command's own inputs ------------


@pytest.mark.parametrize("victim", ["conversion-report.json", "pinned-headers.json"])
def test_log_ots_convert_refuses_to_write_over_its_own_evidence(
    tmp_path: Path, capsys: CapSys, victim: str
) -> None:
    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    work = tmp_path / "work"
    work.mkdir()
    ots_path = work / "stamp.ots"
    ots_path.write_bytes(_ots_with_tree(_branch_append(b"left", 42), digest=seed))
    evidence_path = _write_json(work / victim, evidence)
    parsed = ots.parse_ots(ots_path.read_bytes())
    headers = _headers_for_parsed(seed, parsed)
    headers_path = _write_json(work / "headers.json", [header.__dict__ for header in headers])
    before = evidence_path.read_text(encoding="utf-8")

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(work),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert f"--out-dir would write {victim} over --evidence" in captured.err
    assert evidence_path.read_text(encoding="utf-8") == before


def test_log_ots_convert_refuses_to_write_a_proof_over_its_own_ots_input(
    tmp_path: Path, capsys: CapSys
) -> None:
    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    work = tmp_path / "work"
    work.mkdir()
    ots_path = work / "proof-0-42.json"
    ots_path.write_bytes(_ots_with_tree(_branch_append(b"left", 42), digest=seed))
    evidence_path = _write_json(work / "evidence.json", evidence)
    parsed = ots.parse_ots(ots_path.read_bytes())
    headers = _headers_for_parsed(seed, parsed)
    headers_path = _write_json(work / "headers.json", [header.__dict__ for header in headers])
    before = ots_path.read_bytes()

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(work),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "--out-dir would write proof-0-42.json over --ots" in captured.err
    assert ots_path.read_bytes() == before


# --- the report is the inventory of the directory it sits in ------------------


def _stale_proof(out_dir: Path, name: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / name
    path.write_text('{"ops": [["sha256"]], "from": "an earlier run"}', encoding="utf-8")
    return path


def test_log_ots_convert_report_names_proof_files_this_run_did_not_write(
    tmp_path: Path, capsys: CapSys
) -> None:
    """A leftover `proof-*.json` carries the exact name shape an operator
    feeds to `log anchor`, and nothing else in this output would mention it.
    The one this run overwrites is NOT a leftover: it is this run's own file.
    """

    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    parsed = _parsed_with_two_bitcoin_and_pending(seed)
    headers = _headers_for_parsed(seed, parsed)
    ots_path = tmp_path / "stamp.ots"
    ots_path.write_bytes(
        _ots_with_tree(
            b"".join(
                [
                    TAG_FORK,
                    _branch_append(b"left", 42),
                    TAG_FORK,
                    _branch_prepend(b"right", 43),
                    TAG_APPEND,
                    _varbytes(b"pending"),
                    TAG_SHA256,
                    _pending_attestation(),
                ]
            ),
            digest=seed,
        )
    )
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    headers_path = _write_json(tmp_path / "headers.json", [header.__dict__ for header in headers])
    out_dir = tmp_path / "converted"
    replaced = _stale_proof(out_dir, "proof-0-42.json")
    _stale_proof(out_dir, "proof-7-99999.json")
    _stale_proof(out_dir, "proof-2-13.json")
    # Neither of these is a proof file, so neither belongs in the list.
    (out_dir / "notes.txt").write_text("operator scratch", encoding="utf-8")
    (out_dir / "evidence-copy.json").write_text("{}", encoding="utf-8")

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    stdout = json.loads(capsys.readouterr().out)

    assert rc == 0
    report = json.loads((out_dir / "conversion-report.json").read_text(encoding="utf-8"))
    assert report["proof_files_not_written_by_this_run"] == [
        "proof-2-13.json",
        "proof-7-99999.json",
    ]
    assert stdout["preexisting_proofs"] == 2
    assert json.loads(replaced.read_text(encoding="utf-8")) == {
        "ops": [["append", b"left".hex()], ["sha256"]],
        "header_merkle_root": headers[0].merkle_root,
        "header_hash": headers[0].header_hash,
        "header_time": headers[0].time,
    }


def test_log_ots_convert_report_says_so_when_it_wrote_the_whole_directory(
    tmp_path: Path, capsys: CapSys
) -> None:
    """The field is always present: an empty list is the statement that this
    run accounts for every proof file in the directory."""

    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    ots_path = tmp_path / "stamp.ots"
    ots_path.write_bytes(_ots_with_tree(_branch_append(b"left", 42), digest=seed))
    parsed = ots.parse_ots(ots_path.read_bytes())
    headers = _headers_for_parsed(seed, parsed)
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    headers_path = _write_json(tmp_path / "headers.json", [header.__dict__ for header in headers])
    out_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    stdout = json.loads(capsys.readouterr().out)

    assert rc == 0
    report = json.loads((out_dir / "conversion-report.json").read_text(encoding="utf-8"))
    assert report["proof_files_not_written_by_this_run"] == []
    assert stdout["preexisting_proofs"] == 0


def test_log_ots_convert_zero_survivors_report_names_the_proofs_it_left_behind(
    tmp_path: Path, capsys: CapSys
) -> None:
    """Zero survivors is where a leftover proof is most dangerous: the run
    emits nothing, so every `proof-*.json` still there is someone else's."""

    evidence = _minimal_anchor_evidence()
    seed = _expected_seed_from_evidence(evidence)
    ots_path = tmp_path / "stamp.ots"
    ots_path.write_bytes(_ots_with_tree(_branch_append(b"left", 700_000), digest=seed))
    evidence_path = _write_json(tmp_path / "evidence.json", evidence)
    headers_path = _write_json(tmp_path / "headers.json", [])
    out_dir = tmp_path / "converted"
    _stale_proof(out_dir, "proof-0-42.json")

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(out_dir),
        ]
    )
    captured = capsys.readouterr()

    assert rc == 2
    assert "no convertible Bitcoin paths found" in captured.err
    report = json.loads((out_dir / "conversion-report.json").read_text(encoding="utf-8"))
    assert report["converted"] == 0
    assert report["proof_files_not_written_by_this_run"] == ["proof-0-42.json"]


def test_preexisting_proof_files_are_sorted_regardless_of_directory_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`readdir`/`scandir` order is filesystem-defined, not name order --
    measured on tmpfs (this suite's tmp_path) with 20 names, 5/5 trials
    non-lexicographic. The report promises a deterministic list for a
    deterministic input set, so the sort has to be pinned independently
    of what the real filesystem happens to return today."""

    out_dir = tmp_path / "converted"
    out_dir.mkdir()
    unsorted_names = ["proof-19-1.json", "proof-7-99999.json", "proof-2-13.json"]

    class _FakeEntry:
        def __init__(self, name: str) -> None:
            self.name = name

    def _fake_glob(self: Path, pattern: str) -> list[_FakeEntry]:
        assert pattern == "proof-*.json"
        return [_FakeEntry(name) for name in unsorted_names]

    monkeypatch.setattr(Path, "glob", _fake_glob)

    assert cli._preexisting_proof_files(out_dir, ()) == [
        "proof-19-1.json",
        "proof-2-13.json",
        "proof-7-99999.json",
    ]


def test_log_ots_convert_output_feeds_log_anchor_and_verify_end_to_end(
    tmp_path: Path, capsys: CapSys
) -> None:
    from tests.test_cli import (
        _issue,
        _keygen,
        _keygen_hybrid,
        _log_append,
        _log_init,
        _log_keys_file,
        _log_prove,
        _log_sign_checkpoint,
        _manifest_init,
        _receipt_entry,
        _trust_dir,
        _write_payload,
    )

    log_dir = _log_init(tmp_path)
    log_ed_seed, log_ed_pub, log_mldsa = _keygen_hybrid(tmp_path, "log-signer")
    issuer_seed, _issuer_pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, issuer_seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, issuer_seed, payload_path)
    trust_dir = _trust_dir(tmp_path, manifest_path)

    _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))
    _log_sign_checkpoint(log_dir, log_ed_seed, log_mldsa)
    evidence_path = _log_prove(tmp_path, log_dir, 0)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    checkpoint = tlog.parse_checkpoint(evidence["checkpoint"])
    signed_note_seed = hashlib.sha256(checkpoint.signed_note_bytes).digest()

    height = 765_432
    header_time = 1_700_000_000
    append_operand = b"vh7-end-to-end"
    ots_path = tmp_path / "signed-note.ots"
    ots_path.write_bytes(
        _ots_with_tree(_branch_append(append_operand, height), digest=signed_note_seed)
    )
    merkle_root = _replay(
        signed_note_seed, (ots.OtsOp("append", append_operand), ots.OtsOp("sha256"))
    ).hex()
    header = _header(
        height,
        merkle_root,
        header_hash=hashlib.sha256(b"vh7-end-to-end-header").hexdigest(),
        time=header_time,
    )
    headers_path = _write_json(tmp_path / "headers.json", [header.__dict__])
    converted_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(converted_dir),
        ]
    )
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["proofs"] == 1

    log_keys_path = _log_keys_file(tmp_path, log_ed_pub, log_mldsa)
    proof_path = converted_dir / f"proof-0-{height}.json"
    pinned_headers_path = converted_dir / "pinned-headers.json"
    assert json.loads(pinned_headers_path.read_text(encoding="utf-8")) == {
        "pinned_headers": {
            header.header_hash: {
                "header_hash": header.header_hash,
                "merkle_root": merkle_root,
                "time": header_time,
            }
        }
    }

    anchored_path = tmp_path / "anchored-evidence.json"
    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "anchor",
            "--dir",
            str(log_dir),
            "--evidence",
            str(evidence_path),
            "--ots-proof",
            str(proof_path),
            "--out",
            str(anchored_path),
        ]
    )
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["proofs"] == 1

    capsys.readouterr()
    rc = cli.main(
        [
            "verify",
            str(envelope_path),
            "--trust-dir",
            str(trust_dir),
            "--transparency",
            str(anchored_path),
            "--log-keys",
            str(log_keys_path),
            "--anchor-policy",
            str(pinned_headers_path),
        ]
    )
    result = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert result["transparency"] == "anchored_before:2023-11-14T22:13:20Z"


def test_anchored_before_composes_over_two_converted_bitcoin_paths(
    tmp_path: Path, capsys: CapSys
) -> None:
    """Prove end to end the claim that the conversion report makes in prose
    and that `_walk_proofs` implements in code: losing one Bitcoin path can
    cost the operator the OLDEST anchoring claim, because `anchored_before`
    is the MINIMUM pinned header time over every proof that verified
    (anchor.py, `AnchorVerdict`).

    Each half already had coverage on its own -- the converter emitting one
    proof file per convertible Bitcoin path backed by a matching header
    (`test_log_ots_convert_keeps_same_height_paths_as_distinct_files`), and
    `log anchor` appending a second v2 proof onto a v2 bundle
    (`test_log_anchor_permits_appending_a_second_v2_proof_to_a_v2_bundle`)
    -- but nothing joined them: no test converted a genuinely two-path
    `.ots`, attached BOTH proofs through two `log anchor` calls, and
    asserted which of the two times the verifier then reports. That join is
    what the claim rests on, so it is what is asserted here.

    The `.ots` forks into an older Bitcoin path (height 765432) and a newer
    one (765500), whose pinned headers are 68 seconds apart. Four verdicts
    come out of those same two converted proof files:

    * each proof alone. The newer one alone reports the newer, WEAKER time
      -- that is the cost of the lost path, stated as a verifier verdict
      rather than as prose in a report.
    * both proofs, attached older-then-newer AND newer-then-older. Both
      orders must compose to the OLDER time. The pair of results distinguishes
      all four candidate reductions: minimum yields older/older, maximum
      newer/newer, first-wins older/newer, and last-wins newer/older. No
      single-order assertion distinguishes all four.
    """
    from tests.test_cli import (
        _issue,
        _keygen,
        _keygen_hybrid,
        _log_append,
        _log_init,
        _log_keys_file,
        _log_prove,
        _log_sign_checkpoint,
        _manifest_init,
        _receipt_entry,
        _trust_dir,
        _write_payload,
    )

    log_dir = _log_init(tmp_path)
    log_ed_seed, log_ed_pub, log_mldsa = _keygen_hybrid(tmp_path, "log-signer")
    issuer_seed, _issuer_pub = _keygen(tmp_path, "issuer")
    manifest_path = _manifest_init(tmp_path, issuer_seed)
    payload_path = _write_payload(tmp_path)
    envelope_path = _issue(tmp_path, issuer_seed, payload_path)
    trust_dir = _trust_dir(tmp_path, manifest_path)

    _log_append(tmp_path, log_dir, _receipt_entry(envelope_path))
    _log_sign_checkpoint(log_dir, log_ed_seed, log_mldsa)
    evidence_path = _log_prove(tmp_path, log_dir, 0)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    checkpoint = tlog.parse_checkpoint(evidence["checkpoint"])
    signed_note_seed = hashlib.sha256(checkpoint.signed_note_bytes).digest()

    # `_headers_for_parsed` pins each header's time at 1_700_000_000 +
    # height, so the lower block height is also the older wall-clock time:
    # 765432 -> 2023-11-23T18:50:32Z, 765500 -> 2023-11-23T18:51:40Z.
    height_older = 765_432
    height_newer = 765_500
    older_time = "anchored_before:2023-11-23T18:50:32Z"
    newer_time = "anchored_before:2023-11-23T18:51:40Z"

    ots_path = tmp_path / "two-paths.ots"
    ots_path.write_bytes(
        _ots_with_tree(
            TAG_FORK
            + _branch_append(b"vh8-older-path", height_older)
            + _branch_prepend(b"vh8-newer-path", height_newer),
            digest=signed_note_seed,
        )
    )
    parsed = ots.parse_ots(ots_path.read_bytes())
    # Pins the walk order the proof filenames below are derived from.
    assert [path.attestation.height for path in parsed.paths] == [height_older, height_newer]
    headers_path = _write_json(
        tmp_path / "headers.json",
        [header.__dict__ for header in _headers_for_parsed(signed_note_seed, parsed)],
    )
    converted_dir = tmp_path / "converted"

    capsys.readouterr()
    rc = cli.main(
        [
            "log",
            "ots-convert",
            "--ots",
            str(ots_path),
            "--evidence",
            str(evidence_path),
            "--block-headers",
            str(headers_path),
            "--out-dir",
            str(converted_dir),
        ]
    )
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["proofs"] == 2

    proof_older = converted_dir / f"proof-0-{height_older}.json"
    proof_newer = converted_dir / f"proof-1-{height_newer}.json"
    assert proof_older.exists()
    assert proof_newer.exists()
    pinned_headers_path = converted_dir / "pinned-headers.json"
    log_keys_path = _log_keys_file(tmp_path, log_ed_pub, log_mldsa)

    def _anchor(source: Path, proof: Path, out_name: str) -> Path:
        """Attach one converted proof onto `source`, returning the result."""
        out_path = tmp_path / out_name
        capsys.readouterr()
        rc = cli.main(
            [
                "log",
                "anchor",
                "--dir",
                str(log_dir),
                "--evidence",
                str(source),
                "--ots-proof",
                str(proof),
                "--out",
                str(out_path),
            ]
        )
        assert rc == 0
        capsys.readouterr()
        return out_path

    def _transparency(anchored: Path) -> str:
        capsys.readouterr()
        rc = cli.main(
            [
                "verify",
                str(envelope_path),
                "--trust-dir",
                str(trust_dir),
                "--transparency",
                str(anchored),
                "--log-keys",
                str(log_keys_path),
                "--anchor-policy",
                str(pinned_headers_path),
            ]
        )
        result = json.loads(capsys.readouterr().out)
        assert rc == 0
        return str(result["transparency"])

    # Each path alone. The newer path alone is the operator who recovered
    # only one of the two: a real, verified anchor, and a weaker claim.
    older_only = _anchor(evidence_path, proof_older, "anchored-older-only.json")
    newer_only = _anchor(evidence_path, proof_newer, "anchored-newer-only.json")
    assert _transparency(older_only) == older_time
    assert _transparency(newer_only) == newer_time

    # Both paths, attached in either order onto the single-proof bundles
    # above. The composed evidence must report the older claim both times.
    older_then_newer = _anchor(older_only, proof_newer, "anchored-older-then-newer.json")
    newer_then_older = _anchor(newer_only, proof_older, "anchored-newer-then-older.json")
    for composed in (older_then_newer, newer_then_older):
        assert len(json.loads(composed.read_text(encoding="utf-8"))["anchors"]["proofs"]) == 2
    assert _transparency(older_then_newer) == older_time
    assert _transparency(newer_then_older) == older_time
