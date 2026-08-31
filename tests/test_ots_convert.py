"""OpenTimestamps conversion tests.

The `.ots` inputs below are assembled byte-by-byte inside this file. That keeps
the converter tests from sharing a generator with the parser or the converter.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from attest import cli, ots, tlog

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
