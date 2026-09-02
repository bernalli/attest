"""The corpus generator is the bench the container reader is judged by, so it
is judged first: it must lie about any field on demand, stay deterministic, and
never learn what "correct" means from the code it exists to break.

`zipfile` appears here as an INDEPENDENT reader of honest output only. It is
never asked what a hostile archive means — that question is exactly the one the
two importers answer differently, and it is the reader under test that must
answer it, not the bench.
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
import zipfile
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from tools import gen_container_corpus as gen

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "tests" / "container-corpus"

# Geometry of the six exhibits, as measured on the archives this corpus ports
# (file length; EOCD offset; entries-on-this-disk / total; size_cd; off_cd;
# the prefix compensation CPython computes as ECD_LOCATION - size_cd - off_cd).
EXHIBIT_GEOMETRY = {
    "exhibit-A-honest": (641, 619, 3, 3, 248, 371, 0),
    "exhibit-B2-counter": (641, 619, 2, 3, 248, 371, 0),
    "exhibit-C-salts-honest": (390, 368, 2, 2, 149, 219, 0),
    "exhibit-C2-salts": (390, 368, 1, 2, 149, 219, 0),
    "exhibit-D-prefix": (744, 722, 2, 2, 149, 248, 325),
    "exhibit-D-prefix-inverse": (376, 354, 1, 1, 146, 282, -74),
}


@dataclass(frozen=True)
class FirstFailure:
    geometry: tuple[int | None, int | None, int | None, int | None, int | None, int | None]
    step: str
    code: str


# Hand-reviewed from plan section 4, not copied from Case.code. Geometry is
# (actual EOCD offset, n_disk, n_total, size_cd, off_cd, concat). Read-stage
# labels follow the ordered checks in plan section 4.4.
FIRST_FAILURES = {
    "central-extra-len": FirstFailure(
        (236, 1, 1, 94, 142, 0), "S9 walk completion", "directory-trailing-bytes"
    ),
    "counter-disk-high": FirstFailure((384, 3, 2, 155, 229, 0), "S6", "entry-counters-disagree"),
    "counter-disk-low": FirstFailure((384, 1, 2, 155, 229, 0), "S6", "entry-counters-disagree"),
    "counter-total-high": FirstFailure((384, 2, 3, 155, 229, 0), "S6", "entry-counters-disagree"),
    "counter-total-low": FirstFailure((384, 2, 1, 155, 229, 0), "S6", "entry-counters-disagree"),
    "counters-both-high": FirstFailure(
        (384, 3, 3, 155, 229, 0), "S9 record signature", "directory-record-signature"
    ),
    "counters-both-low": FirstFailure(
        (384, 1, 1, 155, 229, 0), "S9 walk completion", "directory-trailing-bytes"
    ),
    "crc-wrong": FirstFailure((235, 1, 1, 93, 142, 0), "read CRC", "member-crc-mismatch"),
    "data-runs-into-directory": FirstFailure(
        (240, 1, 1, 93, 147, 0), "S22", "member-data-out-of-range"
    ),
    "declared-member-over-cap": FirstFailure(
        (240, 1, 1, 93, 147, 0), "S23 member cap", "declared-member-over-cap"
    ),
    "declared-total-over-cap": FirstFailure(
        (1996, 2, 2, 114, 1882, 0), "S23 total cap", "declared-total-over-cap"
    ),
    "deflate-reserved-literal-code": FirstFailure(
        (174, 1, 1, 93, 81, 0), "read deflate structure", "member-inflate-error"
    ),
    "deflate-stored-block-bad-complement": FirstFailure(
        (240, 1, 1, 93, 147, 0), "read deflate structure", "member-inflate-error"
    ),
    "deflate-empty-stream": FirstFailure(
        (104, 1, 1, 60, 44, 0), "read inflate", "member-inflate-error"
    ),
    "deflate-garbage": FirstFailure((108, 1, 1, 60, 48, 0), "read inflate", "member-inflate-error"),
    "deflate-truncated": FirstFailure(
        (346, 1, 1, 60, 286, 0), "read inflate", "member-inflate-error"
    ),
    "directory-trailing-record-bytes": FirstFailure(
        (388, 2, 2, 159, 229, 0), "S9 walk completion", "directory-trailing-bytes"
    ),
    "duplicate-name": FirstFailure((470, 2, 2, 186, 284, 0), "S17", "duplicate-name"),
    "eocd-cd-disk": FirstFailure((384, 2, 2, 155, 229, 0), "S4", "multi-disk"),
    "eocd-comment-length-without-comment": FirstFailure(
        (384, 2, 2, 155, 229, 0), "S3", "eocd-comment-length"
    ),
    "eocd-sig": FirstFailure((384, 2, 2, 155, 229, 0), "S2", "eocd-not-last"),
    "eocd-trailing-byte": FirstFailure((384, 2, 2, 155, 229, 0), "S2", "eocd-not-last"),
    "eocd-with-comment": FirstFailure((384, 2, 2, 155, 229, 0), "S2", "eocd-not-last"),
    "exhibit-A-honest": FirstFailure((619, 3, 3, 248, 371, 0), "S17", "duplicate-name"),
    "exhibit-B2-counter": FirstFailure((619, 2, 3, 248, 371, 0), "S6", "entry-counters-disagree"),
    "exhibit-C2-salts": FirstFailure((368, 1, 2, 149, 219, 0), "S6", "entry-counters-disagree"),
    "exhibit-D-prefix": FirstFailure((722, 2, 2, 149, 248, 325), "S8", "directory-misplaced"),
    "exhibit-D-prefix-inverse": FirstFailure(
        (354, 1, 1, 146, 282, -74), "S8", "directory-misplaced"
    ),
    "inflate-lies-low": FirstFailure((114, 1, 1, 60, 54, 0), "read member cap", "member-over-cap"),
    "local-extra-len": FirstFailure((236, 1, 1, 93, 143, 0), "read CRC", "member-crc-mismatch"),
    "local-header-beyond-directory": FirstFailure(
        (235, 1, 1, 93, 142, 0), "S19", "local-header-out-of-range"
    ),
    "local-header-signature": FirstFailure(
        (235, 1, 1, 93, 142, 0), "S20", "local-header-signature"
    ),
    "local-name-differs": FirstFailure((235, 1, 1, 93, 142, 0), "S21", "local-name-mismatch"),
    "local-name-len": FirstFailure((235, 1, 1, 93, 142, 0), "S21", "local-name-mismatch"),
    "local-name-length-differs": FirstFailure(
        (198, 1, 1, 93, 105, 0), "S21", "local-name-mismatch"
    ),
    "multi-disk": FirstFailure((384, 2, 2, 155, 229, 0), "S4", "multi-disk"),
    "off-cd-shifted": FirstFailure((384, 2, 2, 155, 1, 228), "S8", "directory-misplaced"),
    "prefix-honest": FirstFailure((410, 2, 2, 155, 229, 26), "S8", "directory-misplaced"),
    "record-comment": FirstFailure((385, 2, 2, 156, 229, 0), "S10", "record-comment"),
    "record-disk-start": FirstFailure((384, 2, 2, 155, 229, 0), "S11", "record-multi-disk"),
    "record-encrypted-bit0": FirstFailure((235, 1, 1, 93, 142, 0), "S12", "record-encrypted"),
    "record-encrypted-bit6": FirstFailure((235, 1, 1, 93, 142, 0), "S12", "record-encrypted"),
    "record-method-bzip2": FirstFailure((235, 1, 1, 93, 142, 0), "S13", "record-method"),
    "record-name-empty": FirstFailure((141, 1, 1, 46, 95, 0), "S15", "record-name-empty"),
    "record-name-high-bytes-no-flag": FirstFailure(
        (107, 1, 1, 61, 46, 0), "S16", "record-name-encoding"
    ),
    "record-name-invalid-utf8": FirstFailure((101, 1, 1, 58, 43, 0), "S16", "record-name-encoding"),
    "record-name-len-overrun": FirstFailure(
        (384, 2, 2, 155, 229, 0), "S9 record extent", "directory-record-overrun"
    ),
    "record-signature-altered": FirstFailure(
        (384, 2, 2, 155, 229, 0), "S9 record signature", "directory-record-signature"
    ),
    "record-zip64-csize": FirstFailure((235, 1, 1, 93, 142, 0), "S14", "record-zip64"),
    "record-zip64-lho": FirstFailure((235, 1, 1, 93, 142, 0), "S14", "record-zip64"),
    "size-cd-long": FirstFailure((384, 2, 2, 65536, 229, -65381), "S8", "directory-misplaced"),
    "size-cd-short": FirstFailure((384, 2, 2, 154, 229, 1), "S8", "directory-misplaced"),
    "stored-size-mismatch": FirstFailure((235, 1, 1, 93, 142, 0), "S18", "record-stored-size"),
    "too-many-entries": FirstFailure((384, 2, 2, 155, 229, 0), "S7", "too-many-entries"),
    "too-short": FirstFailure((None, None, None, None, None, None), "S1", "too-short"),
    "total-over-cap-across-members": FirstFailure(
        (209, 2, 2, 114, 95, 0), "read total cap", "total-over-cap"
    ),
    "usize-too-large": FirstFailure((240, 1, 1, 93, 147, 0), "read size", "member-size-mismatch"),
    "zip64-locator-present": FirstFailure((404, 2, 2, 155, 229, 20), "S5", "zip64"),
    "zip64-sentinel-total-count": FirstFailure((384, 2, 65535, 155, 229, 0), "S5", "zip64"),
    "record-zip64-usize": FirstFailure((235, 1, 1, 93, 142, 0), "S14", "record-zip64"),
    "zip64-sentinel-count": FirstFailure((384, 65535, 65535, 155, 229, 0), "S5", "zip64"),
    "zip64-sentinel-offset": FirstFailure((384, 2, 2, 155, 4294967295, -4294967066), "S5", "zip64"),
    "zip64-sentinel-size": FirstFailure((384, 2, 2, 4294967295, 229, -4294967140), "S5", "zip64"),
}


STRUCTURAL_FIELD_OFFSETS = {
    "local.sig": ("local", 0),
    "local.ver_need": ("local", 4),
    "local.flags": ("local", 6),
    "local.method": ("local", 8),
    "local.mtime": ("local", 10),
    "local.mdate": ("local", 12),
    "local.crc": ("local", 14),
    "local.csize": ("local", 18),
    "local.usize": ("local", 22),
    "local.name_len": ("local", 26),
    "local.extra_len": ("local", 28),
    "central.sig": ("central", 0),
    "central.ver_made": ("central", 4),
    "central.ver_need": ("central", 6),
    "central.flags": ("central", 8),
    "central.method": ("central", 10),
    "central.mtime": ("central", 12),
    "central.mdate": ("central", 14),
    "central.crc": ("central", 16),
    "central.csize": ("central", 20),
    "central.usize": ("central", 24),
    "central.name_len": ("central", 28),
    "central.extra_len": ("central", 30),
    "central.comment_len": ("central", 32),
    "central.disk_start": ("central", 34),
    "central.int_attr": ("central", 36),
    "central.ext_attr": ("central", 38),
    "central.lho": ("central", 42),
    "eocd.sig": ("eocd", 0),
    "eocd.disk_no": ("eocd", 4),
    "eocd.cd_disk": ("eocd", 6),
    "eocd.n_disk": ("eocd", 8),
    "eocd.n_total": ("eocd", 10),
    "eocd.size_cd": ("eocd", 12),
    "eocd.off_cd": ("eocd", 16),
    "eocd.comment_len": ("eocd", 20),
}

FUZZ_STEP_CODES = {
    "s01": "too-short",
    "s02": "eocd-not-last",
    "s03": "eocd-comment-length",
    "s04": "multi-disk",
    "s05": "zip64",
    "s06": "entry-counters-disagree",
    "s07": "too-many-entries",
    "s08": "directory-misplaced",
    "s09": "directory-record-signature",
    "s10": "record-comment",
    "s11": "record-multi-disk",
    "s12": "record-encrypted",
    "s13": "record-method",
    "s14": "record-zip64",
    "s15": "record-name-empty",
    "s16": "record-name-encoding",
    "s17": "duplicate-name",
    "s18": "record-stored-size",
    "s19": "local-header-out-of-range",
    "s20": "local-header-signature",
    "s21": "local-name-mismatch",
    "s22": "member-data-out-of-range",
    "s23": "declared-member-over-cap",
}


def _eocd_geometry(raw: bytes) -> tuple[int, int, int, int, int, int, int]:
    eocd = raw.rfind(b"PK\x05\x06")
    sig, disk, cd_disk, n_disk, n_total, size_cd, off_cd, comment_len = struct.unpack(
        "<IHHHHIIH", raw[eocd : eocd + 22]
    )
    assert sig == 0x06054B50 and comment_len == 0 and disk == 0 and cd_disk == 0
    return (len(raw), eocd, n_disk, n_total, size_cd, off_cd, eocd - size_cd - off_cd)


def _first_failure_geometry(
    raw: bytes,
) -> tuple[int | None, int | None, int | None, int | None, int | None, int | None]:
    if len(raw) < 22:
        return (None, None, None, None, None, None)
    eocd = raw.rfind(b"PK\x05\x06")
    if eocd < 0:
        eocd = len(raw) - 22
    _, _, _, n_disk, n_total, size_cd, off_cd, _ = struct.unpack("<IHHHHIIH", raw[eocd : eocd + 22])
    return (eocd, n_disk, n_total, size_cd, off_cd, eocd - size_cd - off_cd)


def _field_variant(field_name: str) -> tuple[bytes, bytes, int]:
    entry = gen.Entry(name=b"a", data=b"x")
    archive = gen.Archive(entries=[entry])
    honest = gen.build(archive)
    central = honest.index(b"PK\x01\x02")
    eocd = len(honest) - 22
    crc = struct.unpack_from("<I", honest, 14)[0]

    entry_changes: dict[str, dict[str, int]] = {
        "local.sig": {"local_sig": gen.LFH_SIG ^ 1},
        "local.ver_need": {"local_ver_need": 20 ^ 1},
        "local.flags": {"local_flags": 1},
        "local.method": {"local_method": 1},
        "local.mtime": {"local_mtime": 1},
        "local.mdate": {"local_mdate": 33 ^ 1},
        "local.crc": {"local_crc": crc ^ 1},
        "local.csize": {"local_csize": 1 ^ 1},
        "local.usize": {"local_usize": 1 ^ 1},
        "local.name_len": {"local_name_len": 1 ^ 1},
        "local.extra_len": {"local_extra_len": 1},
        "central.sig": {"central_sig": gen.CD_SIG ^ 1},
        "central.ver_made": {"ver_made": 20 ^ 1},
        "central.ver_need": {"ver_need": 20 ^ 1, "local_ver_need": 20},
        "central.flags": {"flags": 1, "local_flags": 0},
        "central.method": {"method": 1, "local_method": 0},
        "central.mtime": {"mtime": 1, "local_mtime": 0},
        "central.mdate": {"mdate": 33 ^ 1, "local_mdate": 33},
        "central.crc": {"crc": crc ^ 1, "local_crc": crc},
        "central.csize": {"csize": 1 ^ 1, "local_csize": 1},
        "central.usize": {"usize": 1 ^ 1, "local_usize": 1},
        "central.name_len": {"name_len": 1 ^ 1},
        "central.extra_len": {"extra_len": 1},
        "central.comment_len": {"comment_len": 1},
        "central.disk_start": {"disk_start": 1},
        "central.int_attr": {"int_attr": 1},
        "central.ext_attr": {"ext_attr": 1},
        "central.lho": {"lho": 1},
    }
    archive_changes = {
        "eocd.sig": {"eocd_sig": gen.EOCD_SIG ^ 1},
        "eocd.disk_no": {"disk_no": 1},
        "eocd.cd_disk": {"cd_disk": 1},
        "eocd.n_disk": {"n_disk": 1 ^ 1},
        "eocd.n_total": {"n_total": 1 ^ 1},
        "eocd.size_cd": {"size_cd": (eocd - central) ^ 1},
        "eocd.off_cd": {"off_cd": central ^ 1},
        "eocd.comment_len": {"eocd_comment_len": 1},
    }
    if field_name in entry_changes:
        lied = gen.build(replace(archive, entries=[replace(entry, **entry_changes[field_name])]))
    else:
        lied = gen.build(replace(archive, **archive_changes[field_name]))
    section, relative_offset = STRUCTURAL_FIELD_OFFSETS[field_name]
    section_start = {"local": 0, "central": central, "eocd": eocd}[section]
    return honest, lied, section_start + relative_offset


def test_writer_round_trips_an_honest_model_through_an_independent_reader() -> None:
    archive = gen.Archive(
        entries=[
            gen.Entry(name=b"receipts/one.json", data=b'{"a":1}'),
            gen.Entry(name=b"legal/two.txt", data=b"hello world" * 40, method=8),
        ]
    )
    raw = gen.build(archive)
    with zipfile.ZipFile(__import__("io").BytesIO(raw)) as zf:
        assert zf.namelist() == ["receipts/one.json", "legal/two.txt"]
        assert zf.read("receipts/one.json") == b'{"a":1}'
        assert zf.read("legal/two.txt") == b"hello world" * 40
        assert zf.testzip() is None


@pytest.mark.parametrize("field_name", STRUCTURAL_FIELD_OFFSETS)
def test_writer_lies_about_each_fixed_field_independently(field_name: str) -> None:
    honest, lied, expected_offset = _field_variant(field_name)
    assert len(honest) == len(lied)
    changed_offsets = {
        offset for offset, pair in enumerate(zip(honest, lied, strict=True)) if pair[0] != pair[1]
    }
    assert changed_offsets == {expected_offset}


def test_build_is_deterministic() -> None:
    archive = gen.Archive(entries=[gen.Entry(name=b"a.txt", data=b"x" * 100, method=8)])
    assert gen.build(archive) == gen.build(archive)


def test_deflate_bytes_are_runtime_independent_stored_blocks() -> None:
    assert gen._deflate(b"") == b"\x01\x00\x00\xff\xff"
    assert gen._deflate(b"abc") == b"\x01\x03\x00\xfc\xffabc"
    two_blocks = gen._deflate(b"x" * 0x10000)
    assert two_blocks[0] == 0
    assert two_blocks[0x10004] == 1


def test_generator_never_imports_the_implementation_it_judges() -> None:
    source = (REPO_ROOT / "tools" / "gen_container_corpus.py").read_text(encoding="utf-8")
    offending = [
        line
        for line in source.splitlines()
        if line.strip().startswith(("import ", "from "))
        and ("attest" in line or "container" in line.split("#")[0].replace("gen_container", ""))
    ]
    assert offending == []


def test_every_code_is_exercised_by_at_least_one_case() -> None:
    codes = {
        case.code for case in gen.cases() if case.verdict == "reject" and case.code is not None
    }
    assert set(gen.CODES) - codes == set()


def test_codes_and_messages_agree_with_the_generated_table() -> None:
    table = json.loads((CORPUS / "codes.json").read_text(encoding="utf-8"))
    assert table["codes"] == list(gen.CODES)
    assert table["messages"] == dict(gen.MESSAGES)
    assert set(gen.MESSAGES) == set(gen.CODES)


def test_committed_corpus_is_what_the_generator_produces(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "tools/gen_container_corpus.py", "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_regenerating_into_an_empty_directory_reproduces_the_corpus(tmp_path: Path) -> None:
    out = tmp_path / "corpus"
    assert gen.main(["--out", str(out)]) == 0
    committed = sorted(p.name for p in CORPUS.iterdir())
    produced = sorted(p.name for p in out.iterdir())
    assert produced == committed
    for case in gen.cases():
        assert (out / case.name / "archive.zip").read_bytes() == (
            CORPUS / case.name / "archive.zip"
        ).read_bytes()


@pytest.mark.parametrize("name", sorted(EXHIBIT_GEOMETRY))
def test_exhibits_keep_the_length_and_geometry_they_were_measured_with(name: str) -> None:
    raw = (CORPUS / name / "archive.zip").read_bytes()
    assert _eocd_geometry(raw) == EXHIBIT_GEOMETRY[name]


def test_inverse_d_prefix_is_coherent_under_both_addressing_models() -> None:
    raw = (CORPUS / "exhibit-D-prefix-inverse" / "archive.zip").read_bytes()
    eocd = len(raw) - 22
    _, _, _, n_disk, _, size_cd, off_cd, _ = struct.unpack("<IHHHHIIH", raw[eocd:])
    assert eocd - size_cd < off_cd
    assert size_cd > eocd - off_cd

    with zipfile.ZipFile(__import__("io").BytesIO(raw)) as zf:
        assert zf.namelist() == [
            "receipts/earlier.attest.json",
            "receipts/later.attest.json",
        ]
        assert [zf.read(name) for name in zf.namelist()] == [b"size-sees", b"offset-sees"]

    offset_members: list[tuple[str, bytes]] = []
    position = off_cd
    for _ in range(n_disk):
        assert struct.unpack_from("<I", raw, position)[0] == gen.CD_SIG
        method = struct.unpack_from("<H", raw, position + 10)[0]
        csize = struct.unpack_from("<I", raw, position + 20)[0]
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", raw, position + 28)
        lho = struct.unpack_from("<I", raw, position + 42)[0]
        name = raw[position + 46 : position + 46 + name_len].decode()
        assert method == 0 and struct.unpack_from("<I", raw, lho)[0] == gen.LFH_SIG
        local_name_len, local_extra_len = struct.unpack_from("<HH", raw, lho + 26)
        data_start = lho + 30 + local_name_len + local_extra_len
        offset_members.append((name, raw[data_start : data_start + csize]))
        position += 46 + name_len + extra_len + comment_len
    assert offset_members == [("receipts/later.attest.json", b"offset-sees")]


def test_hand_reviewed_first_failure_oracle_matches_committed_expectations() -> None:
    rejected: dict[str, dict[str, object]] = {}
    for leaf in CORPUS.iterdir():
        expected_path = leaf / "expected.json"
        if not expected_path.exists():
            continue
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
        if expected["verdict"] == "reject":
            rejected[leaf.name] = expected

    assert set(FIRST_FAILURES) == set(rejected)
    for name, oracle in FIRST_FAILURES.items():
        raw = (CORPUS / name / "archive.zip").read_bytes()
        assert _first_failure_geometry(raw) == oracle.geometry, name
        assert rejected[name]["code"] == oracle.code, (name, oracle.step)


def test_every_case_directory_carries_an_archive_and_an_expectation() -> None:
    for case in gen.cases():
        expected = json.loads((CORPUS / case.name / "expected.json").read_text(encoding="utf-8"))
        assert expected["verdict"] in {"accept", "reject"}
        assert set(expected["caps"]) == {"max_entries", "max_member_bytes", "max_total_bytes"}
        if expected["verdict"] == "reject":
            assert expected["code"] in gen.CODES
        else:
            for member in expected["members"]:
                assert set(member) == {"name", "method", "size", "sha256"}


def test_accepted_leaves_read_the_same_way_through_an_independent_reader() -> None:
    """Every leaf the corpus calls acceptable is honest enough that a reader
    written by someone else agrees on its member list and its bytes.

    This is the only place `zipfile` is allowed an opinion, and it is allowed it
    only about archives the corpus already claims are unambiguous: an expectation
    invented by the author of the bench would otherwise be checked by nobody.
    """
    import io

    for case in gen.cases():
        expected = json.loads((CORPUS / case.name / "expected.json").read_text(encoding="utf-8"))
        if expected["verdict"] != "accept":
            continue
        raw = (CORPUS / case.name / "archive.zip").read_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            assert zf.namelist() == [m["name"] for m in expected["members"]], case.name
            for member in expected["members"]:
                data = zf.read(member["name"])
                assert len(data) == member["size"], (case.name, member["name"])
                assert __import__("hashlib").sha256(data).hexdigest() == member["sha256"]


def test_fuzz_is_reproducible_from_its_seed(tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    assert gen.main(["--fuzz", "8", "--seed", "7", "--out", str(first)]) == 0
    assert gen.main(["--fuzz", "8", "--seed", "7", "--out", str(second)]) == 0
    names = sorted(p.name for p in first.iterdir())
    assert names == sorted(p.name for p in second.iterdir())
    assert names
    for name in names:
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_fuzz_reaches_every_stratum_and_single_step_target(tmp_path: Path) -> None:
    from attest.container import ContainerError, canonical_members

    out = tmp_path / "fuzz"
    count = len(gen.FUZZ_STRATA) * len(gen.FUZZ_SINGLE_STEPS)
    gen.write_fuzz(out, count, seed=20260902)
    names = [path.name for path in out.iterdir()]
    single = [name for name in names if name.startswith("single-")]
    precedence = [name for name in names if name.startswith("precedence-")]
    raw = [name for name in names if name.startswith("raw-")]
    minimum = count // len(gen.FUZZ_STRATA)
    assert min(len(single), len(precedence), len(raw)) >= minimum
    assert {name.split("-")[1] for name in single} == set(gen.FUZZ_SINGLE_STEPS)
    assert len({name.split("-")[1] for name in precedence}) >= 4
    assert set(FUZZ_STEP_CODES) == set(gen.FUZZ_SINGLE_STEPS)
    for name in single:
        target = name.split("-")[1]
        with pytest.raises(ContainerError) as caught:
            canonical_members((out / name).read_bytes(), **gen.DEFAULT_CAPS)
        assert caught.value.code == FUZZ_STEP_CODES[target]
