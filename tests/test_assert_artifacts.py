import io
import json
import re
import tarfile
import zipfile
from pathlib import Path

import pytest

from tools.assert_artifacts import (
    ArtifactError,
    assert_npm_tarball,
    assert_sdist,
    assert_wheel,
    main,
)

# The two source declarations a packaged `witness.py` must carry for the
# default policy to be the canonical EMPTY one (v0.2 §11.4). Kept verbatim
# here rather than imported from the tool, so a silent edit to the tool's
# expectation shows up as a red test instead of a tautology.
WITNESS_SOURCE = (
    b'SCHEMA_ID: Final = "attest-witness-policy-v1"\n'
    b"CANONICAL_EMPTY_POLICY_BYTES: Final = canon.canonical_bytes("
    b'{"schema": SCHEMA_ID, "epochs": []})\n'
)
# The same module with a witness already pinned in the shipped default — the
# packaging regression the assertion exists to catch.
WITNESS_SOURCE_SEEDED = (
    b'SCHEMA_ID: Final = "attest-witness-policy-v1"\n'
    b"CANONICAL_EMPTY_POLICY_BYTES: Final = canon.canonical_bytes("
    b'{"schema": SCHEMA_ID, "epochs": [BOOTSTRAP_EPOCH]})\n'
)


def _member_bytes(name: str, witness_source: bytes = WITNESS_SOURCE) -> bytes:
    return witness_source if name.endswith("attest/witness.py") else b"x"


def _make_wheel(tmp: Path, members: list[str], witness_source: bytes = WITNESS_SOURCE) -> Path:
    p = tmp / "attest_receipts-0.1.2-py3-none-any.whl"
    with zipfile.ZipFile(p, "w") as z:
        for m in members:
            z.writestr(m, _member_bytes(m, witness_source))
    return p


def _make_sdist(tmp: Path, members: list[str], witness_source: bytes = WITNESS_SOURCE) -> Path:
    p = tmp / "attest_receipts-0.1.2.tar.gz"
    with tarfile.open(p, "w:gz") as t:
        for m in members:
            data = _member_bytes(m, witness_source)
            info = tarfile.TarInfo(name=m)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return p


WHEEL_OK = [
    "attest/__init__.py",
    "attest/py.typed",
    "attest/schema/attest-receipt.schema.json",
    "attest/witness.py",
    "attest_receipts-0.1.2.dist-info/METADATA",
    "attest_receipts-0.1.2.dist-info/licenses/LICENSE",
]
SDIST_OK = [
    "attest_receipts-0.1.2/pyproject.toml",
    "attest_receipts-0.1.2/src/attest/__init__.py",
    "attest_receipts-0.1.2/src/attest/py.typed",
    "attest_receipts-0.1.2/src/attest/witness.py",
    "attest_receipts-0.1.2/LICENSE",
]


def test_wheel_ok(tmp_path: Path) -> None:
    assert_wheel(_make_wheel(tmp_path, WHEEL_OK))  # no raise


def test_wheel_missing_py_typed_raises(tmp_path: Path) -> None:
    members = [m for m in WHEEL_OK if m != "attest/py.typed"]
    with pytest.raises(ArtifactError, match=r"py\.typed"):
        assert_wheel(_make_wheel(tmp_path, members))


def test_wheel_missing_schema_raises(tmp_path: Path) -> None:
    members = [m for m in WHEEL_OK if "schema" not in m]
    with pytest.raises(ArtifactError, match="schema"):
        assert_wheel(_make_wheel(tmp_path, members))


def test_wheel_wrong_schema_name_raises(tmp_path: Path) -> None:
    members = [m for m in WHEEL_OK if "schema" not in m] + ["attest/schema/attest-v0.1.schema.json"]
    with pytest.raises(ArtifactError, match="schema"):
        assert_wheel(_make_wheel(tmp_path, members))


def test_sdist_ok(tmp_path: Path) -> None:
    assert_sdist(_make_sdist(tmp_path, SDIST_OK))  # no raise


def test_sdist_missing_license_raises(tmp_path: Path) -> None:
    members = [m for m in SDIST_OK if not m.endswith("LICENSE")]
    with pytest.raises(ArtifactError, match="LICENSE"):
        assert_sdist(_make_sdist(tmp_path, members))


def _pack(files: list[str]) -> list[dict]:
    return [{"files": [{"path": f} for f in files]}]


NPM_OK = [
    "dist/index.js",
    "dist/index.d.ts",
    "dist/witness.js",
    "README.md",
    "CHANGELOG.md",
    "package.json",
]


def test_npm_ok() -> None:
    assert_npm_tarball(_pack(NPM_OK))  # no raise


def test_npm_missing_changelog_raises() -> None:
    with pytest.raises(ArtifactError, match=r"CHANGELOG\.md"):
        assert_npm_tarball(_pack([f for f in NPM_OK if f != "CHANGELOG.md"]))


def test_npm_missing_index_js_raises() -> None:
    members = [f for f in NPM_OK if not f.startswith("dist/")] + ["dist/README"]
    with pytest.raises(ArtifactError, match=r"dist/index\.js"):
        assert_npm_tarball(_pack(members))


def test_npm_missing_index_d_ts_raises() -> None:
    members = [f for f in NPM_OK if f != "dist/index.d.ts"]
    with pytest.raises(ArtifactError, match=r"dist/index\.d\.ts"):
        assert_npm_tarball(_pack(members))


def test_npm_forbidden_private_raises() -> None:
    with pytest.raises(ArtifactError, match="forbidden"):
        assert_npm_tarball(_pack([*NPM_OK, "example.private.attest"]))


def test_npm_forbidden_src_raises() -> None:
    with pytest.raises(ArtifactError, match="forbidden"):
        assert_npm_tarball(_pack([*NPM_OK, "src/verify.ts"]))


def test_npm_forbidden_private_case_insensitive_raises() -> None:
    with pytest.raises(ArtifactError, match="forbidden"):
        assert_npm_tarball(_pack([*NPM_OK, "secret.PRIVATE.attest"]))


def test_npm_forbidden_src_case_insensitive_raises() -> None:
    with pytest.raises(ArtifactError, match="forbidden"):
        assert_npm_tarball(_pack([*NPM_OK, "Src/verify.ts"]))


def test_npm_forbidden_tests_dir_raises() -> None:
    with pytest.raises(ArtifactError, match="forbidden"):
        assert_npm_tarball(_pack([*NPM_OK, "tests/verify.ts"]))


def test_npm_forbidden_tsconfig_raises() -> None:
    with pytest.raises(ArtifactError, match="forbidden"):
        assert_npm_tarball(_pack([*NPM_OK, "tsconfig.json"]))


def test_npm_privateer_is_not_a_false_positive() -> None:
    assert_npm_tarball(_pack([*NPM_OK, "api.privateer.md"]))  # no raise


def test_npm_tsconfig_guide_is_not_a_false_positive() -> None:
    assert_npm_tarball(_pack([*NPM_OK, "docs/tsconfig-guide.md"]))  # no raise


def test_wheel_license_txt_lookalike_does_not_satisfy_license_requirement(
    tmp_path: Path,
) -> None:
    members = [m for m in WHEEL_OK if "LICENSE" not in m] + ["LICENSE.txt"]
    with pytest.raises(ArtifactError, match="LICENSE"):
        assert_wheel(_make_wheel(tmp_path, members))


def test_wheel_py_typed_old_lookalike_does_not_satisfy_requirement(
    tmp_path: Path,
) -> None:
    members = [m for m in WHEEL_OK if m != "attest/py.typed"] + ["attest/py.typed.old"]
    with pytest.raises(ArtifactError, match=r"py\.typed"):
        assert_wheel(_make_wheel(tmp_path, members))


def test_wheel_schema_bak_lookalike_does_not_satisfy_requirement(tmp_path: Path) -> None:
    members = [m for m in WHEEL_OK if "schema" not in m] + ["foo.schema.json.bak"]
    with pytest.raises(ArtifactError, match="schema"):
        assert_wheel(_make_wheel(tmp_path, members))


def test_wheel_nested_schema_lookalike_does_not_satisfy_requirement(tmp_path: Path) -> None:
    members = [m for m in WHEEL_OK if "schema" not in m] + [
        "nested/attest/schema/attest-receipt.schema.json"
    ]
    with pytest.raises(ArtifactError, match="schema"):
        assert_wheel(_make_wheel(tmp_path, members))


def test_npm_nested_index_js_lookalike_does_not_satisfy_requirement() -> None:
    members = [f for f in NPM_OK if f != "dist/index.js"] + ["nested/dist/index.js"]
    with pytest.raises(ArtifactError, match=r"dist/index\.js"):
        assert_npm_tarball(_pack(members))


def test_npm_notdist_lookalike_does_not_satisfy_dist_requirement() -> None:
    members = [f for f in NPM_OK if not f.startswith("dist/")] + ["notdist/index.js"]
    with pytest.raises(ArtifactError, match="dist"):
        assert_npm_tarball(_pack(members))


def test_npm_changelog_lookalike_does_not_satisfy_changelog_requirement() -> None:
    members = [f for f in NPM_OK if f != "CHANGELOG.md"] + ["myCHANGELOG.md"]
    with pytest.raises(ArtifactError, match=r"CHANGELOG\.md"):
        assert_npm_tarball(_pack(members))


def test_sdist_pyproject_lookalike_does_not_satisfy_requirement(tmp_path: Path) -> None:
    members = [m for m in SDIST_OK if not m.endswith("pyproject.toml")] + [
        "attest_receipts-0.1.2/pyproject.toml.bak"
    ]
    with pytest.raises(ArtifactError, match=r"pyproject\.toml"):
        assert_sdist(_make_sdist(tmp_path, members))


def test_sdist_license_txt_lookalike_does_not_satisfy_license_requirement(
    tmp_path: Path,
) -> None:
    members = [m for m in SDIST_OK if not m.endswith("LICENSE")] + [
        "attest_receipts-0.1.2/LICENSE.txt"
    ]
    with pytest.raises(ArtifactError, match="LICENSE"):
        assert_sdist(_make_sdist(tmp_path, members))


def test_main_no_targets_returns_nonzero() -> None:
    assert main([]) != 0


def test_main_all_targets_ok_returns_zero(tmp_path: Path) -> None:
    wheel = _make_wheel(tmp_path, WHEEL_OK)
    sdist = _make_sdist(tmp_path, SDIST_OK)
    npm_pack_json = tmp_path / "npm-pack.json"
    npm_pack_json.write_text(json.dumps(_pack(NPM_OK)))
    assert (
        main(
            [
                "--wheel",
                str(wheel),
                "--sdist",
                str(sdist),
                "--npm-pack-json",
                str(npm_pack_json),
            ]
        )
        == 0
    )


def test_wheel_missing_witness_module_raises(tmp_path: Path) -> None:
    """A wheel without the witness-policy layer is broken on import, not
    merely feature-incomplete: `verify()` imports it unconditionally."""
    members = [m for m in WHEEL_OK if m != "attest/witness.py"]
    with pytest.raises(ArtifactError, match="witness"):
        assert_wheel(_make_wheel(tmp_path, members))


def test_wheel_with_seeded_default_policy_raises(tmp_path: Path) -> None:
    """The published packages must ship the canonical EMPTY policy: with no
    epochs, no witness is pinned and `corroboration: "witnessed"` is
    unreachable for anyone installing them. A build that seeded a witness into
    that default would pass every test in the suite and still hand users a
    different trust root."""
    with pytest.raises(ArtifactError, match="does not declare"):
        assert_wheel(_make_wheel(tmp_path, WHEEL_OK, witness_source=WITNESS_SOURCE_SEEDED))


def test_sdist_with_seeded_default_policy_raises(tmp_path: Path) -> None:
    with pytest.raises(ArtifactError, match="does not declare"):
        assert_sdist(_make_sdist(tmp_path, SDIST_OK, witness_source=WITNESS_SOURCE_SEEDED))


def test_npm_missing_witness_module_raises() -> None:
    """`npm pack --json` reports a file list, not contents, so the JavaScript
    core's own packaged default cannot be read here — presence is what this
    side can honestly assert."""
    with pytest.raises(ArtifactError, match=r"dist/witness\.js"):
        assert_npm_tarball(_pack([f for f in NPM_OK if f != "dist/witness.js"]))


# --- The private reference witness must never ship (v0.2 §11.4) --------------
#
# `witness/` is an operator component: its source describes a deployment and
# its example config names key files. hatchling's sdist default is "everything
# not gitignored", so the exclusion in pyproject.toml is load-bearing and these
# tests are what keep it load-bearing. The paired "not a false positive" tests
# below matter just as much: the OPPOSITE requirement — that the packaged
# module `attest/witness.py` IS present — is asserted a few dozen lines up, and
# a pattern that swallowed it would trade one packaging bug for a worse one.


def test_sdist_forbidden_private_witness_workspace_raises(tmp_path: Path) -> None:
    p = _make_sdist(tmp_path, [*SDIST_OK, "attest_receipts-0.1.2/witness/pyproject.toml"])
    with pytest.raises(ArtifactError, match=re.escape("witness/pyproject.toml")):
        assert_sdist(p)


def test_sdist_forbidden_private_witness_example_config_raises(tmp_path: Path) -> None:
    """The example config is the worst single file to ship: it is the shape of
    an operator's deployment, key-file paths included."""
    p = _make_sdist(tmp_path, [*SDIST_OK, "attest_receipts-0.1.2/witness/examples/witness.toml"])
    with pytest.raises(ArtifactError, match=re.escape("witness.toml")):
        assert_sdist(p)


def test_sdist_forbidden_private_witness_package_raises(tmp_path: Path) -> None:
    p = _make_sdist(
        tmp_path,
        [*SDIST_OK, "attest_receipts-0.1.2/witness/src/attest_witness/service.py"],
    )
    with pytest.raises(ArtifactError, match=re.escape("attest_witness")):
        assert_sdist(p)


def test_wheel_forbidden_private_witness_package_raises(tmp_path: Path) -> None:
    """A wheel cannot pick this up by default, but a `packages = [...]` edit
    could — and a wheel is what `pip install` actually consumes."""
    p = _make_wheel(tmp_path, [*WHEEL_OK, "attest_witness/__init__.py"])
    with pytest.raises(ArtifactError, match=re.escape("attest_witness")):
        assert_wheel(p)


def test_npm_forbidden_private_witness_raises() -> None:
    with pytest.raises(ArtifactError, match=re.escape("attest_witness")):
        assert_npm_tarball(_pack([*NPM_OK, "attest_witness/cli.py"]))


def test_sdist_attest_witness_module_is_not_a_false_positive(tmp_path: Path) -> None:
    """`src/attest/witness.py` is REQUIRED in the sdist. The exclusion pattern
    must not match it: it is a file named witness.py, not a witness/ directory
    and not the attest_witness package."""
    assert_sdist(_make_sdist(tmp_path, SDIST_OK))


def test_wheel_attest_witness_module_is_not_a_false_positive(tmp_path: Path) -> None:
    assert_wheel(_make_wheel(tmp_path, WHEEL_OK))


def test_npm_dist_witness_js_is_not_a_false_positive() -> None:
    """`dist/witness.js` is REQUIRED in the npm tarball, for the same reason."""
    assert_npm_tarball(_pack(NPM_OK))
