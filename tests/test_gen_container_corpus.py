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
from pathlib import Path

import pytest

from tools import gen_container_corpus as gen

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "tests" / "container-corpus"

# Geometry of the five exhibits, as measured on the archives this corpus ports
# (file length; EOCD offset; entries-on-this-disk / total; size_cd; off_cd;
# the prefix compensation CPython computes as ECD_LOCATION - size_cd - off_cd).
EXHIBIT_GEOMETRY = {
    "exhibit-A-honest": (641, 619, 3, 3, 248, 371, 0),
    "exhibit-B2-counter": (641, 619, 2, 3, 248, 371, 0),
    "exhibit-C-salts-honest": (390, 368, 2, 2, 149, 219, 0),
    "exhibit-C2-salts": (390, 368, 1, 2, 149, 219, 0),
    "exhibit-D-prefix": (744, 722, 2, 2, 149, 248, 325),
}


def _eocd_geometry(raw: bytes) -> tuple[int, int, int, int, int, int, int]:
    eocd = raw.rfind(b"PK\x05\x06")
    sig, disk, cd_disk, n_disk, n_total, size_cd, off_cd, comment_len = struct.unpack(
        "<IHHHHIIH", raw[eocd : eocd + 22]
    )
    assert sig == 0x06054B50 and comment_len == 0 and disk == 0 and cd_disk == 0
    return (len(raw), eocd, n_disk, n_total, size_cd, off_cd, eocd - size_cd - off_cd)


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


def test_writer_lies_about_a_field_without_touching_the_rest() -> None:
    honest = gen.Archive(entries=[gen.Entry(name=b"a.txt", data=b"x")])
    lied = gen.Archive(entries=[gen.Entry(name=b"a.txt", data=b"x")], n_disk=0)
    assert len(gen.build(honest)) == len(gen.build(lied))
    assert gen.build(honest) != gen.build(lied)


def test_build_is_deterministic() -> None:
    archive = gen.Archive(entries=[gen.Entry(name=b"a.txt", data=b"x" * 100, method=8)])
    assert gen.build(archive) == gen.build(archive)


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
