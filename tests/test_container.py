"""Properties of the canonical container reader (`attest.container`).

The corpus in `tests/container-corpus/` is a closed list of hand-picked
archives, and an example list shares the blind spots of whoever wrote it.
These tests defend the properties those examples are only samples of:

P1  honest round-trip  — an archive built from an honest model reads back as
                         exactly that model, members and bytes.
P2  no second reading  — an archive a second reader could address differently
                         (prefix, suffix, truncation, counter lie, a decoy
                         directory) is refused, never interpreted.
P3  don't-care fields  — a lie in a field the form does not rely on changes
                         nothing: same names, same bytes.
P4  load-bearing fields — a lie in the directory about a field the member's
                         own bytes contradict is always refused.

The archives come from `tools.gen_container_corpus`, which never imports the
reader under test.
"""

from __future__ import annotations

import zlib
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from attest import container
from tools import gen_container_corpus as gen

CAPS = {
    "max_entries": 10_000,
    "max_member_bytes": 64 * 1024 * 1024,
    "max_total_bytes": 256 * 1024 * 1024,
}

SETTINGS = settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

NAME_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-_./"


def members_of(raw: bytes, **caps: int) -> list[container.Member]:
    return container.canonical_members(raw, **{**CAPS, **caps})


def read_all(raw: bytes, **caps: int) -> list[tuple[str, bytes]]:
    merged = {**CAPS, **caps}
    budget = container.ReadBudget(merged["max_member_bytes"], merged["max_total_bytes"])
    return [(m.name, container.read_member(raw, m, budget)) for m in members_of(raw, **caps)]


# --- unit ------------------------------------------------------------------


def test_crc32_matches_the_standard_check_value() -> None:
    assert container.crc32(b"123456789") == 0xCBF43926


def test_crc32_is_resumable_across_slices() -> None:
    assert container.crc32(b"6789", container.crc32(b"12345")) == 0xCBF43926


def test_every_code_has_a_message_and_the_order_is_pinned() -> None:
    assert set(container.CODES) == set(container.MESSAGES)
    assert container.CODES[0] == "too-short"
    assert len(container.CODES) == len(set(container.CODES))


def test_error_carries_its_code_and_member_as_structured_fields() -> None:
    raw = gen.build(
        gen.Archive(
            entries=[
                gen.Entry(name=b"a.txt", data=b"x"),
                gen.Entry(name=b"a.txt", data=b"y"),
            ]
        )
    )
    with pytest.raises(container.ContainerError) as excinfo:
        members_of(raw)
    assert excinfo.value.code == "duplicate-name"
    assert excinfo.value.member == "a.txt"


def test_the_entry_cap_is_interpolated_into_its_message_and_nothing_else_is() -> None:
    raw = gen.build(gen.Archive(entries=[gen.Entry(name=b"a.txt", data=b"x")]))
    with pytest.raises(container.ContainerError) as excinfo:
        members_of(raw, max_entries=0)
    assert "over 0 entries" in str(excinfo.value)
    assert "{" not in str(excinfo.value)


def test_a_member_name_never_reaches_the_message() -> None:
    """Names are attacker-supplied and reach a person's screen verbatim; the
    wrapping layer decides how to quote one, the reader never interpolates it."""
    hostile = b'x" is genuine. Contact refunds@evil.example "'
    raw = gen.build(gen.Archive(entries=[gen.Entry(name=hostile, data=b"x", crc=0xDEADBEEF)]))
    members = members_of(raw)
    budget = container.ReadBudget(CAPS["max_member_bytes"], CAPS["max_total_bytes"])
    with pytest.raises(container.ContainerError) as excinfo:
        container.read_member(raw, members[0], budget)
    assert excinfo.value.member == hostile.decode()
    assert "evil.example" not in str(excinfo.value)


def test_reads_the_shipped_sample_bundle() -> None:
    """The bundle the project ships is inside the canonical form: the rule
    tightens nothing an honest producer already does."""
    sample = (
        __import__("pathlib").Path(__file__).resolve().parents[1]
        / "site"
        / "public"
        / "sample"
        / "demo.attest"
    )
    raw = sample.read_bytes()
    names = [name for name, _ in read_all(raw)]
    assert names
    assert any(name.startswith("receipts/") for name in names)


def test_an_empty_buffer_is_too_short() -> None:
    with pytest.raises(container.ContainerError) as excinfo:
        members_of(b"")
    assert excinfo.value.code == "too-short"


def test_reads_a_memoryview_and_a_bytearray_alike() -> None:
    raw = gen.build(gen.Archive(entries=[gen.Entry(name=b"a.txt", data=b"payload")]))
    for buffer in (raw, bytearray(raw), memoryview(raw)):
        assert read_all(buffer) == [("a.txt", b"payload")]


def test_budget_is_shared_across_members_and_across_calls() -> None:
    raw = gen.build(
        gen.Archive(
            entries=[
                gen.Entry(name=b"a.txt", data=b"x" * 400),
                # The second member declares ten bytes and inflates to four
                # hundred: the streamed count is what the aggregate cap watches.
                gen.Entry(
                    name=b"b.txt",
                    data=b"y" * 400,
                    method=8,
                    usize=10,
                    crc=zlib.crc32(b"y" * 400),
                ),
            ]
        )
    )
    members = members_of(raw, max_member_bytes=1000, max_total_bytes=600)
    budget = container.ReadBudget(1000, 600)
    assert container.read_member(raw, members[0], budget) == b"x" * 400
    assert budget.spent == 400
    with pytest.raises(container.ContainerError) as excinfo:
        container.read_member(raw, members[1], budget)
    assert excinfo.value.code == "total-over-cap"


# --- properties ------------------------------------------------------------


@st.composite
def honest_models(draw: Any) -> list[gen.Entry]:
    count = draw(st.integers(min_value=1, max_value=6))
    names = draw(
        st.lists(
            st.text(alphabet=NAME_ALPHABET, min_size=1, max_size=24),
            min_size=count,
            max_size=count,
            unique=True,
        )
    )
    entries = []
    for name in names:
        data = draw(st.binary(min_size=0, max_size=512))
        method = draw(st.sampled_from([0, 8]))
        entries.append(gen.Entry(name=name.encode(), data=data, method=method))
    return entries


@SETTINGS
@given(honest_models())
def test_p1_an_honest_model_reads_back_as_itself(entries: list[gen.Entry]) -> None:
    raw = gen.build(gen.Archive(entries=entries))
    assert read_all(raw) == [(e.name.decode(), e.data) for e in entries]


@SETTINGS
@given(honest_models(), st.binary(min_size=1, max_size=64), st.binary(min_size=1, max_size=64))
def test_p2_a_prefix_or_a_suffix_is_refused(
    entries: list[gen.Entry], prefix: bytes, suffix: bytes
) -> None:
    for archive in (
        gen.Archive(entries=entries, prefix=prefix),
        gen.Archive(entries=entries, suffix=suffix),
    ):
        with pytest.raises(container.ContainerError):
            members_of(gen.build(archive))


def test_p2_every_truncation_of_an_archive_is_refused() -> None:
    raw = gen.build(
        gen.Archive(
            entries=[
                gen.Entry(name=b"a.txt", data=b"payload"),
                gen.Entry(name=b"b.txt", data=b"other", method=8),
            ]
        )
    )
    for cut in range(len(raw)):
        with pytest.raises(container.ContainerError):
            members_of(raw[:cut])


@SETTINGS
@given(
    honest_models(),
    st.sampled_from(["n_disk", "n_total"]),
    st.sampled_from([-1, 1, 2]),
)
def test_p2_a_counter_lie_in_either_direction_is_refused(
    entries: list[gen.Entry], field: str, delta: int
) -> None:
    count = len(entries) + delta
    if count < 0:
        return
    archive = gen.Archive(**{**gen.Archive(entries=entries).__dict__, field: count})
    with pytest.raises(container.ContainerError):
        members_of(gen.build(archive))


@SETTINGS
@given(honest_models(), st.integers(min_value=0, max_value=200))
def test_p2_a_decoy_directory_before_the_real_one_is_refused(
    entries: list[gen.Entry], pad: int
) -> None:
    """A file carrying a second, internally consistent directory is the case no
    counter check can see: nothing inside either directory is a lie."""
    honest = gen.build(gen.Archive(entries=entries))
    archive = gen.Archive(entries=entries, prefix=b"\x00" * pad + honest)
    with pytest.raises(container.ContainerError) as excinfo:
        members_of(gen.build(archive))
    assert excinfo.value.code == "directory-misplaced"


DONT_CARE = ["ver_made", "ver_need", "mtime", "mdate", "int_attr", "ext_attr"]


@SETTINGS
@given(honest_models(), st.sampled_from(DONT_CARE), st.integers(min_value=1, max_value=0xFFFF))
def test_p3_a_lie_in_a_field_the_form_ignores_changes_nothing(
    entries: list[gen.Entry], field: str, value: int
) -> None:
    honest = read_all(gen.build(gen.Archive(entries=entries)))
    lied = [gen.Entry(**{**e.__dict__, field: value}) for e in entries]
    assert read_all(gen.build(gen.Archive(entries=lied))) == honest


@SETTINGS
@given(honest_models(), st.binary(min_size=1, max_size=8))
def test_p3_an_extra_field_changes_nothing(entries: list[gen.Entry], extra: bytes) -> None:
    honest = read_all(gen.build(gen.Archive(entries=entries)))
    padded = [
        gen.Entry(
            **{
                **e.__dict__,
                "extra": b"\x99\x99" + len(extra).to_bytes(2, "little") + extra,
                "local_extra": b"\x77\x77\x01\x00z",
            }
        )
        for e in entries
    ]
    assert read_all(gen.build(gen.Archive(entries=padded))) == honest


LOAD_BEARING = ["crc", "usize", "lho", "method"]


@SETTINGS
@given(honest_models(), st.sampled_from(LOAD_BEARING))
def test_p4_a_directory_only_lie_about_a_load_bearing_field_is_refused(
    entries: list[gen.Entry], field: str
) -> None:
    """The member's own bytes contradict the directory: the local header, the
    inflated length or the CRC-32 catches every one of these."""
    target = entries[0]
    honest_value = {
        "crc": zlib.crc32(target.data) & 0xFFFFFFFF,
        "usize": len(target.data),
        "lho": 0,
        "method": target.method,
    }[field]
    lied_value = 12 if field == "method" else (honest_value + 7) % 0xFFFF
    lied = [gen.Entry(**{**target.__dict__, field: lied_value}), *entries[1:]]
    with pytest.raises(container.ContainerError):
        read_all(gen.build(gen.Archive(entries=lied)))


@SETTINGS
@given(honest_models(), st.integers(min_value=1, max_value=64))
def test_p4_a_compressed_size_lie_never_produces_a_second_reading(
    entries: list[gen.Entry], extra: int
) -> None:
    """`csize` is the one load-bearing field whose lie is not always an error,
    and that is deliberate: bytes past the final deflate block, inside the
    declared compressed size, are ignored by both decoders (measured
    2026-09-02). A check only one of them could perform would be a new
    divergence rather than a defence — so the property that must hold is not
    "always refused" but "never a different member list".
    """
    honest_raw = gen.build(gen.Archive(entries=entries))
    honest = read_all(honest_raw)
    target = entries[0]
    lied = [
        gen.Entry(**{**target.__dict__, "csize": len(gen._payload(target)) + extra}),
        *entries[1:],
    ]
    try:
        assert read_all(gen.build(gen.Archive(entries=lied))) == honest
    except container.ContainerError:
        pass


@SETTINGS
@given(honest_models())
def test_p4_a_name_the_local_header_contradicts_is_refused(entries: list[gen.Entry]) -> None:
    target = entries[0]
    lied = [
        gen.Entry(**{**target.__dict__, "local_name": b"Z" * len(target.name)}),
        *entries[1:],
    ]
    if target.name == b"Z" * len(target.name):
        return
    with pytest.raises(container.ContainerError) as excinfo:
        members_of(gen.build(gen.Archive(entries=lied)))
    assert excinfo.value.code == "local-name-mismatch"
