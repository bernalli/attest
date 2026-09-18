"""Tests for the ablation bench's command line (`tools/gates/ablation/ablate.py`).

Every test that lets the bench touch a tree points it at a fixture repository built
by the bench's own generator under pytest's temporary directory, never at this
repository.

The bench is run as a child process wherever it runs a suite or holds a journal: a
holder installs exit and signal handlers for as long as it holds, and those belong
in a process of their own. Where a test needs to change how the journal behaves --
an exchange a filesystem refuses, a write that does not land, a target that
vanishes -- the child loads the bench by path, replaces a function of the journal
module the bench itself imported, prints a line each time the replacement acts,
and calls the bench's `main()`; the test then requires those lines, so a
replacement that reached a different copy of the module fails instead of passing
unmeasured. Only the `--restore` exits are measured in this process, on journals
left by a child killed with `SIGKILL`, because a restore holds no journal.

Expected hashes come from `git show HEAD:<path>` and from applying the replacement
to that blob here, never from what the bench reports about itself.
"""

from __future__ import annotations

import copy
import errno
import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any, NamedTuple

import pytest

_ABLATION_DIR = Path(__file__).resolve().parents[1] / "tools" / "gates" / "ablation"
_ABLATE = _ABLATION_DIR / "ablate.py"
_JOURNAL = _ABLATION_DIR / "journal.py"
_GENERATOR = _ABLATION_DIR / "selftest" / "make_fixture_tree.py"
_SPEC_FIXTURE = _ABLATION_DIR / "selftest" / "spec_fixture.json"
_SPEC_ST1 = _ABLATION_DIR / "selftest" / "spec_fixture_st1.json"
_ABLATE_MODULE_NAME = "_ablation_ablate_under_test"

JOURNAL_DIRNAME = ".ablation-in-flight"
FIXTURE_IDS = [
    "ST2-property-red",
    "ST3-form-red",
    "ST4-sibling-only",
    "ST5-skip-under-mutation",
    "ST6-inert",
]
FIXTURE_VERDICTS = {
    "ST2-property-red": "KILLED",
    "ST3-form-red": "BROKEN",
    "ST4-sibling-only": "KILLED_ELSEWHERE",
    "ST5-skip-under-mutation": "BROKEN",
    "ST6-inert": "SURVIVED",
}
_GIT_IDENTITY = ("-c", "user.name=ablation", "-c", "user.email=ablation@localhost")

# A child that holds the journal, applies the mutations given as JSON, and is killed
# with SIGKILL while it still holds them: what a run killed by the kernel leaves.
_KILLED_HOLDER = """
import importlib.util, json, os, signal, sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("ablation_journal_killed_holder", sys.argv[1])
journal = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = journal
spec.loader.exec_module(journal)

with journal.journal_owner(Path(sys.argv[2]), sys.argv) as owner:
    for rel_path, old, new in json.loads(sys.argv[3]):
        owner.apply_source(rel_path, old, new)
    os.kill(os.getpid(), signal.SIGKILL)
"""

# A child that loads the bench by path, replaces one function of the journal module
# the bench imported (argv[2] names which behavior), and exits with the bench's main().
_HARNESS = r"""
import errno, importlib.util, os, sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("ablation_ablate_harness", sys.argv[1])
ablate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ablate
spec.loader.exec_module(ablate)
journal = ablate.journal
seam = sys.argv[2]
tree = Path(sys.argv[3])
calls = {"exchange": 0}
held = {}


def acted(what):
    print(f"[seam] {seam}: {what}", file=sys.stderr, flush=True)


def refuse(first, second):
    raise OSError(errno.EXDEV, os.strerror(errno.EXDEV), str(first), None, str(second))


real_exchange = journal._exchange
real_sha_of_file = journal._sha256_of_file
real_write_target = journal._write_target
real_create_synced = journal._create_synced
real_head_sha = journal._head_sha

if seam == "restore-exchange-refused":
    def exchange(first, second):
        if Path(first).name.endswith(".restore.tmp"):
            acted("EXDEV on " + Path(first).name)
            refuse(first, second)
        real_exchange(first, second)
    journal._exchange = exchange
elif seam == "refused-then-unknown":
    def exchange(first, second):
        if Path(first).name.endswith(".restore.tmp"):
            calls["exchange"] += 1
            if calls["exchange"] == 2:
                Path(second).write_bytes(b"VALUE = 7\n")
                acted("wrote the target, then EXDEV")
            else:
                acted("EXDEV, target untouched")
            refuse(first, second)
        real_exchange(first, second)
    journal._exchange = exchange
elif seam == "unknown-then-refused":
    def exchange(first, second):
        if Path(first).name.endswith(".restore.tmp"):
            calls["exchange"] += 1
            if calls["exchange"] == 1:
                held["bytes"] = Path(second).read_bytes()
                Path(second).write_bytes(b"VALUE = 7\n")
                acted("wrote the target, then EXDEV")
            else:
                acted("EXDEV, target untouched")
            refuse(first, second)
        real_exchange(first, second)

    def sha_of_file(path):
        found = real_sha_of_file(path)
        if "bytes" in held:
            Path(path).write_bytes(held.pop("bytes"))
            acted("put the mutated bytes back once the hash was taken")
        return found
    journal._exchange = exchange
    journal._sha256_of_file = sha_of_file
elif seam == "apply-write-lost":
    def write_target(target, data, staging):
        if Path(staging).name == "01-sample.py.tmp":
            acted("dropped the write of the mutation")
            return
        real_write_target(target, data, staging)
    journal._write_target = write_target
elif seam == "apply-target-vanishes":
    def create_synced(path, data):
        real_create_synced(path, data)
        if Path(path).name == "01-sample.py.tmp":
            (tree / "sample.py").unlink()
            acted("removed sample.py while the mutation was staged")
    journal._create_synced = create_synced
elif seam == "acquire-race":
    def head_sha(where):
        journal_dir = tree / journal.JOURNAL_DIRNAME
        journal_dir.mkdir()
        (journal_dir / journal.OWNER_FILENAME).write_text('{"pid": 1, "started_utc": "x"}\n')
        acted("another holder created the journal")
        return real_head_sha(where)
    journal._head_sha = head_sha
elif seam != "none":
    raise SystemExit("unknown seam " + seam)

sys.exit(ablate.main(sys.argv[4:]))
"""

# A launcher standing in for `python -m pytest`, which misbehaves the way
# ABLATION_TEST_LAUNCHER_MODE says, only while `sample.py` holds `VALUE = 0` -- except the
# modes `tolerated-<verse>-during`, which change `logs/` in the baseline run, before the
# snapshot taken during the mutation, and undo the change in the mutated run, before the
# snapshot taken after the run. The modes `tolerated-<verse>-after` change `logs/` in the
# mutated run, after the snapshot taken during the mutation. The mode `stray-before-snapshot`
# leaves `stray.txt` in the baseline run, before the snapshot taken during the mutation, and
# removes it in the mutated run; `break-index` makes `git status` fail after the mutated run.
_LAUNCHER = """
import json, os, subprocess, sys
from pathlib import Path

mode = os.environ.get("ABLATION_TEST_LAUNCHER_MODE", "")
tree = Path.cwd()
mutated = (tree / "sample.py").read_bytes() == b"VALUE = 0\\n"
env = dict(os.environ)
if mutated and mode == "drop-nonce":
    env.pop("ABLATION_NONCE", None)
if mutated and mode == "concurrent-writer":
    (tree / "sample.py").write_bytes(b"VALUE = 5\\n")
if mutated and mode == "stray-file":
    (tree / "stray.txt").write_text("left by the suite\\n")
if mode == "stray-before-snapshot":
    if mutated:
        (tree / "stray.txt").unlink()
    else:
        (tree / "stray.txt").write_text("left by the baseline run\\n")
if mutated and mode == "break-index":
    (tree / ".git" / "index").write_bytes(b"not an index\\n")
if mode.startswith("tolerated-"):
    verse, when = mode[len("tolerated-"):].split("-")
    logs = tree / "logs"
    if (when == "after" and mutated) or (when == "during" and not mutated):
        if verse == "appears":
            (logs / "new.log").write_text("new\\n")
        elif verse == "disappears":
            (logs / "old.log").unlink()
        else:
            (logs / "kept.log").unlink()
    elif when == "during" and mutated:
        if verse == "appears":
            (logs / "new.log").unlink()
        elif verse == "disappears":
            (logs / "old.log").write_text("old\\n")
        else:
            (logs / "kept.log").write_text("kept, edited\\n")
code = subprocess.run([sys.executable, "-m", "pytest", *sys.argv[1:]], env=env).returncode
if mutated and mode == "incoherent-outcomes":
    path = Path(os.environ["ABLATION_OUTCOMES"])
    record = json.loads(path.read_text())
    record["n_failed"] = record["n_failed"] + 1
    path.write_text(json.dumps(record))
sys.exit(code)
"""


# --- helpers --------------------------------------------------------------------------------------


def _load_by_path(path: Path, name: str, *, register: bool) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    if register:
        sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    return _load_by_path(_GENERATOR, "_ablation_fixture_generator_for_ablate", register=False)


def _make_tree(generator: ModuleType, dest: Path) -> Path:
    result: Path = generator.make_fixture_tree(dest, sys.executable)
    return result.resolve()


@pytest.fixture
def tree(tmp_path: Path, generator: ModuleType) -> Path:
    return _make_tree(generator, tmp_path / "fixture")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(tree: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 -- fixed argv, no shell
        ["git", *_GIT_IDENTITY, "-C", str(tree), *args],  # noqa: S607 -- git from PATH
        check=True,
        capture_output=True,
    )


def _head_blob(tree: Path, rel_path: str) -> bytes:
    return _git(tree, "show", f"HEAD:{rel_path}").stdout


def _porcelain(tree: Path) -> str:
    return _git(tree, "status", "--porcelain", "--untracked-files=normal").stdout.decode()


def _commit(tree: Path, files: dict[str, bytes]) -> None:
    for name, data in files.items():
        (tree / name).write_bytes(data)
    _git(tree, "add", *files)
    _git(tree, "commit", "-m", "Add files a test needs tracked")


def _tree_state(tree: Path) -> dict[str, Any]:
    """The tracked bytes, what git reports, and every entry, recursively, outside `.git`."""
    tracked = _git(tree, "ls-files", "-z").stdout.decode().split("\0")
    entries = sorted(
        str(path.relative_to(tree)) for path in tree.rglob("*") if ".git" not in path.parts
    )
    return {
        "tracked": {name: _sha((tree / name).read_bytes()) for name in tracked if name},
        "porcelain": _porcelain(tree),
        "entries": entries,
    }


def _snapshot(directory: Path) -> dict[str, str]:
    return {
        entry.name: _sha(entry.read_bytes()) if entry.is_file() else "<dir>"
        for entry in sorted(directory.iterdir())
    }


def _env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("ABLATION_") and key != "PYTHONPYCACHEPREFIX"
    }
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(extra or {})
    return env


def _ablate(
    args: Sequence[str], cwd: Path, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- the current interpreter on the bench
        [sys.executable, str(_ABLATE), *args],
        cwd=str(cwd),
        env=_env(extra_env),
        capture_output=True,
        text=True,
        timeout=300,
    )


def _harness(
    seam: str, tree: Path, args: Sequence[str], cwd: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- the current interpreter on a fixed script
        [sys.executable, "-c", _HARNESS, str(_ABLATE), seam, str(tree), *args],
        cwd=str(cwd),
        env=_env(),
        capture_output=True,
        text=True,
        timeout=300,
    )


def _kill_a_holder(tree: Path, mutations: list[tuple[str, str, str]]) -> None:
    killed = subprocess.run(  # noqa: S603 -- the current interpreter on a fixed script
        [sys.executable, "-c", _KILLED_HOLDER, str(_JOURNAL), str(tree), json.dumps(mutations)],
        cwd=str(tree.parent),
        env=_env(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert killed.returncode == -signal.SIGKILL, killed.stdout + killed.stderr


def _fixture_spec() -> dict[str, Any]:
    spec: dict[str, Any] = json.loads(_SPEC_FIXTURE.read_text(encoding="utf-8"))
    return spec


def _write_spec(path: Path, spec: dict[str, Any]) -> Path:
    path.write_text(json.dumps(spec, indent=1), encoding="utf-8")
    return path


def _single_row_spec(
    tmp_path: Path, name: str, expect_verdict: str, *, launcher: list[str] | None = None
) -> Path:
    spec = _fixture_spec()
    spec["mutants"] = [dict(spec["mutants"][0], expect_verdict=expect_verdict)]
    if launcher is not None:
        spec["launcher"] = launcher
    return _write_spec(tmp_path / f"{name}.json", spec)


def _launcher(tmp_path: Path) -> list[str]:
    script = tmp_path / "launcher.py"
    script.write_text(_LAUNCHER, encoding="utf-8")
    return ["{python}", str(script)]


def _handlers() -> dict[int, Any]:
    return {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}


def _seam_lines(stderr: str) -> list[str]:
    return [line for line in stderr.splitlines() if line.startswith("[seam] ")]


# --- item 0 ---------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def item_zero_tree(tmp_path_factory: pytest.TempPathFactory, generator: ModuleType) -> Path:
    """A fixture tree with a tracked file that is not UTF-8 and an untracked file.

    The untracked file makes the tree dirty: a spec that item 0 wrongly let through
    would stop at the dirty-tree check, before anything could be mutated.
    """
    built = _make_tree(generator, tmp_path_factory.mktemp("item-zero") / "fixture")
    _commit(built, {"latin1.py": b"# caf\xe9\nx = 1\n", "empty.py": b""})
    (built / "untracked.py").write_text("VALUE = 2\n", encoding="utf-8")
    return built


class _Variant(NamedTuple):
    name: str
    build: Callable[[dict[str, Any], Path], None]
    label: str
    key: str
    problems: int


def _on_row(index: int, **changes: Any) -> Callable[[dict[str, Any], Path], None]:
    def build(spec: dict[str, Any], tree: Path) -> None:
        spec["mutants"][index].update(changes)

    return build


def _without(index: int, *keys: str) -> Callable[[dict[str, Any], Path], None]:
    def build(spec: dict[str, Any], tree: Path) -> None:
        for key in keys:
            spec["mutants"][index].pop(key)

    return build


def _then(
    *builds: Callable[[dict[str, Any], Path], None],
) -> Callable[[dict[str, Any], Path], None]:
    def build(spec: dict[str, Any], tree: Path) -> None:
        for step in builds:
            step(spec, tree)

    return build


def _absolute_file(spec: dict[str, Any], tree: Path) -> None:
    spec["mutants"][0]["file"] = str(tree / "sample.py")


# A value of the wrong JSON type for every key a mutant can carry, applied to ST3.
_WRONG_TYPES: dict[str, Any] = {
    "id": 7,
    "property": ["prose"],
    "kind": 1,
    "file": 1,
    "old": 1,
    "new": None,
    "plugin": 1,
    "runner": True,
    "pkg": 1,
    "suite": "test_sample.py",
    "expect_red": "test_helper",
    "expect_verdict": 1,
    "property_red_is_crash": "yes",
    "direction": 1,
}
_REQUIRED_FOR_A_SOURCE_ROW = ("id", "property", "file", "old", "new", "suite", "expect_red")

_MUTANT_VARIANTS = [
    *(
        _Variant(
            f"wrong-type-{key}",
            _on_row(1, **{key: value}),
            "mutants[1]" if key == "id" else "ST3-form-red",
            key,
            1,
        )
        for key, value in _WRONG_TYPES.items()
    ),
    *(
        _Variant(
            f"missing-{key}",
            _without(1, key),
            "mutants[1]" if key == "id" else "ST3-form-red",
            key,
            1,
        )
        for key in _REQUIRED_FOR_A_SOURCE_ROW
    ),
    _Variant("unknown-key", _on_row(0, olds="VALUE = 2"), "ST2-property-red", "olds", 1),
    _Variant("duplicate-id", _on_row(1, id="ST2-property-red"), "ST2-property-red", "id", 1),
    _Variant(
        "verdict-outside-enum",
        _on_row(0, expect_verdict="DEAD"),
        "ST2-property-red",
        "expect_verdict",
        1,
    ),
    _Variant("empty-suite", _on_row(0, suite=[]), "ST2-property-red", "suite", 1),
    _Variant("kind-outside-enum", _on_row(0, kind="patch"), "ST2-property-red", "kind", 1),
    _Variant("runner-outside-enum", _on_row(0, runner="jest"), "ST2-property-red", "runner", 1),
    _Variant(
        "plugin-with-old-and-new",
        _on_row(0, kind="plugin", plugin="sample"),
        "ST2-property-red",
        "old",
        2,
    ),
    _Variant(
        "plugin-missing",
        _then(_without(0, "file", "old", "new"), _on_row(0, kind="plugin")),
        "ST2-property-red",
        "plugin",
        1,
    ),
    _Variant(
        "plugin-not-a-module-name",
        _then(_without(0, "file", "old", "new"), _on_row(0, kind="plugin", plugin="not a name")),
        "ST2-property-red",
        "plugin",
        1,
    ),
    _Variant(
        "plugin-file-absent",
        _then(
            _without(0, "file", "old", "new"), _on_row(0, kind="plugin", plugin="no_such_plugin")
        ),
        "ST2-property-red",
        "plugin",
        1,
    ),
    _Variant(
        "plugin-with-vitest",
        _then(
            _without(0, "file", "old", "new"),
            _on_row(0, kind="plugin", plugin="sample", runner="vitest", pkg="."),
        ),
        "ST2-property-red",
        "kind",
        1,
    ),
    _Variant("vitest-without-pkg", _on_row(0, runner="vitest"), "ST2-property-red", "pkg", 1),
    _Variant(
        "vitest-pkg-without-tools",
        _on_row(0, runner="vitest", pkg="."),
        "ST2-property-red",
        "pkg",
        2,
    ),
    _Variant("anchor-absent", _on_row(0, old="VALUE = 99"), "ST2-property-red", "old", 1),
    _Variant(
        "anchor-repeated",
        _on_row(0, file="test_sample.py", old="def test_", new="def check_"),
        "ST2-property-red",
        "old",
        1,
    ),
    _Variant("anchor-mid-line", _on_row(0, old="= 2", new="= 0"), "ST2-property-red", "old", 1),
    # An empty anchor occurs once, at index 0, in an empty file: only the schema can refuse it.
    _Variant(
        "anchor-empty",
        _on_row(0, file="empty.py", old="", new="x = 1\n"),
        "ST2-property-red",
        "old",
        1,
    ),
    _Variant("old-equals-new", _on_row(0, new="VALUE = 2"), "ST2-property-red", "new", 1),
    _Variant("file-untracked", _on_row(0, file="untracked.py"), "ST2-property-red", "file", 1),
    _Variant("file-absent", _on_row(0, file="no_such_file.py"), "ST2-property-red", "file", 1),
    _Variant("file-absolute", _absolute_file, "ST2-property-red", "file", 1),
    _Variant("file-outside", _on_row(0, file="../sample.py"), "ST2-property-red", "file", 1),
    _Variant(
        "file-not-utf8",
        _on_row(0, file="latin1.py", old="x = 1", new="x = 2"),
        "ST2-property-red",
        "file",
        1,
    ),
]


@pytest.mark.parametrize(
    "variant", _MUTANT_VARIANTS, ids=[variant.name for variant in _MUTANT_VARIANTS]
)
def test_item_zero_refuses_a_malformed_mutant_by_id_and_key_and_touches_nothing(
    item_zero_tree: Path, tmp_path: Path, variant: _Variant
) -> None:
    spec = copy.deepcopy(_fixture_spec())
    variant.build(spec, item_zero_tree)
    spec_path = _write_spec(tmp_path / "spec.json", spec)
    before = _tree_state(item_zero_tree)

    result = _ablate(
        [str(spec_path), "--tree", str(item_zero_tree), "--out", str(tmp_path / "r.json")], tmp_path
    )

    problems = [line for line in result.stderr.splitlines() if line.startswith("item 0: ")]
    assert result.returncode == 3, result.stdout + result.stderr
    assert any(
        line.startswith(f"item 0: mutant {variant.label}: key {variant.key}: ") for line in problems
    ), problems
    assert len(problems) == variant.problems, problems
    assert f"problems: {variant.problems}" in result.stdout
    assert _tree_state(item_zero_tree) == before
    assert not (item_zero_tree / JOURNAL_DIRNAME).exists()
    assert not (tmp_path / "r.json").exists()


_SPEC_VARIANTS: list[tuple[str, Callable[[dict[str, Any]], Any], str]] = [
    ("unknown-key", lambda spec: spec.update(notes="x"), "notes"),
    ("note-not-a-string", lambda spec: spec.update(note=1), "note"),
    ("launcher-not-an-array", lambda spec: spec.update(launcher="pytest"), "launcher"),
    ("launcher-empty", lambda spec: spec.update(launcher=[]), "launcher"),
    ("launcher-not-strings", lambda spec: spec.update(launcher=[1]), "launcher"),
    (
        "unmeasured-malformed",
        lambda spec: spec.update(unmeasured={"why": "x", "suites": "y"}),
        "unmeasured",
    ),
    ("mutants-missing", lambda spec: spec.pop("mutants"), "mutants"),
    ("mutants-not-an-array", lambda spec: spec.update(mutants={}), "mutants"),
    ("mutants-empty", lambda spec: spec.update(mutants=[]), "mutants"),
]


@pytest.mark.parametrize(
    ("name", "build", "key"), _SPEC_VARIANTS, ids=[v[0] for v in _SPEC_VARIANTS]
)
def test_item_zero_refuses_a_malformed_spec_by_key_and_touches_nothing(
    item_zero_tree: Path,
    tmp_path: Path,
    name: str,
    build: Callable[[dict[str, Any]], Any],
    key: str,
) -> None:
    spec = copy.deepcopy(_fixture_spec())
    build(spec)
    spec_path = _write_spec(tmp_path / "spec.json", spec)
    before = _tree_state(item_zero_tree)

    result = _ablate([str(spec_path), "--tree", str(item_zero_tree)], tmp_path)

    problems = [line for line in result.stderr.splitlines() if line.startswith("item 0: ")]
    assert result.returncode == 3, result.stdout + result.stderr
    assert problems == [line for line in problems if line.startswith(f"item 0: spec: key {key}: ")]
    assert len(problems) == 1, problems
    assert _tree_state(item_zero_tree) == before
    assert not (item_zero_tree / JOURNAL_DIRNAME).exists()


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (b"{not json", "is not valid JSON"),
        (b"[1, 2]", "must be a JSON object, found array"),
        (b'{"mutants": [5]}', "item 0: mutant mutants[0]: must be a JSON object, found integer"),
        (
            b'{"mutants": [{"id": "D1", "property": "p", "file": "sample.py", "old": "VALUE = 99",'
            b' "old": "VALUE = 2", "new": "VALUE = 0", "suite": ["test_sample.py"],'
            b' "expect_red": []}]}',
            "item 0: mutant D1: key old: appears more than once in its JSON object",
        ),
        (
            b'{"mutants": [], "mutants": [{"id": "D2", "property": "p", "file": "sample.py",'
            b' "old": "VALUE = 2", "new": "VALUE = 0", "suite": ["test_sample.py"],'
            b' "expect_red": []}]}',
            "item 0: spec: key mutants: appears more than once in its JSON object",
        ),
    ],
)
def test_item_zero_refuses_a_spec_that_is_not_a_spec(
    item_zero_tree: Path, tmp_path: Path, content: bytes, reason: str
) -> None:
    spec_path = tmp_path / "spec.json"
    spec_path.write_bytes(content)
    before = _tree_state(item_zero_tree)

    result = _ablate([str(spec_path), "--tree", str(item_zero_tree)], tmp_path)

    assert result.returncode == 3, result.stdout + result.stderr
    assert reason in result.stderr
    assert _tree_state(item_zero_tree) == before


def test_preflight_accepts_the_fixture_spec_and_refuses_the_absent_anchor_row(
    item_zero_tree: Path, tmp_path: Path
) -> None:
    accepted = _ablate([str(_SPEC_FIXTURE), "--tree", str(item_zero_tree), "--preflight"], tmp_path)
    refused = _ablate([str(_SPEC_ST1), "--tree", str(item_zero_tree), "--preflight"], tmp_path)

    assert (accepted.returncode, accepted.stdout.splitlines()) == (
        0,
        ["preflight: 5 mutants, problems: 0"],
    ), accepted.stderr
    assert refused.returncode == 3
    assert refused.stdout.splitlines() == ["preflight: 1 mutants, problems: 1"]
    assert refused.stderr.splitlines() == [
        "item 0: mutant ST1-anchor-absent: key old: the anchor is absent from sample.py"
    ]


# --- the command line -----------------------------------------------------------------------------


def test_skip_preflight_without_an_explicit_tree_is_refused_with_3(tmp_path: Path) -> None:
    result = _ablate([str(_SPEC_ST1), "--skip-preflight"], tmp_path)

    assert result.returncode == 3
    assert "--skip-preflight is allowed only with an explicit --tree" in result.stderr


@pytest.mark.parametrize("where", ["subdirectory", "not-a-repository"])
def test_a_tree_that_is_not_a_git_top_level_is_refused_with_3(
    tree: Path, tmp_path: Path, where: str
) -> None:
    target = tree / "sub" if where == "subdirectory" else tmp_path / "plain"
    target.mkdir()

    result = _ablate([str(_SPEC_FIXTURE), "--tree", str(target)], tmp_path)

    assert result.returncode == 3, result.stdout + result.stderr
    assert f"--tree {target} is not the top level of a git working tree" in result.stderr
    assert not (target / JOURNAL_DIRNAME).exists()


@pytest.mark.parametrize(
    "args",
    [
        ["--restore", "SPEC"],
        [],
        ["SPEC", "--bogus"],
        ["SPEC", "--preflight", "--skip-preflight", "--tree", "TREE"],
    ],
    ids=["restore-with-a-spec", "no-spec", "unknown-flag", "preflight-and-skip"],
)
def test_a_command_line_outside_the_two_forms_is_refused_with_3(
    tree: Path, tmp_path: Path, args: list[str]
) -> None:
    concrete = [
        str(_SPEC_FIXTURE) if arg == "SPEC" else str(tree) if arg == "TREE" else arg for arg in args
    ]
    before = _tree_state(tree)

    result = _ablate(concrete, tmp_path)

    assert result.returncode == 3, result.stdout + result.stderr
    assert result.stderr.startswith("ablate.py: error: ")
    assert _tree_state(tree) == before


@pytest.mark.parametrize(
    ("only", "unknown"),
    [("NO-SUCH-ID", "['NO-SUCH-ID']"), ("ST2-property-red,ST9", "['ST9']")],
    ids=["unknown-alone", "unknown-next-to-a-known-id"],
)
def test_only_naming_an_id_not_in_the_spec_exits_4_before_touching_anything(
    tree: Path, tmp_path: Path, only: str, unknown: str
) -> None:
    before = _tree_state(tree)

    result = _ablate([str(_SPEC_FIXTURE), "--tree", str(tree), "--only", only], tmp_path)

    assert result.returncode == 4, (
        f"--only {only} exited {result.returncode}: {result.stdout}{result.stderr}"
    )
    assert f"REFUSING: --only names ids that are not in the spec: {unknown}" in result.stderr
    assert "[mutant]" not in result.stdout
    assert not (tree / JOURNAL_DIRNAME).exists()
    assert _tree_state(tree) == before


def test_only_selecting_no_mutant_exits_4(tree: Path, tmp_path: Path) -> None:
    result = _ablate([str(_SPEC_FIXTURE), "--tree", str(tree), "--only", ","], tmp_path)

    assert result.returncode == 4, result.stdout + result.stderr
    assert "REFUSING: --only selects no mutant of the spec" in result.stderr
    assert not (tree / JOURNAL_DIRNAME).exists()


def test_a_journal_left_with_its_owner_file_exits_8_and_stays_as_it_was(
    tree: Path, tmp_path: Path
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    journal_dir.mkdir()
    (journal_dir / "owner.json").write_text('{"pid": 999999999, "started_utc": "x"}\n')
    snapshot = _snapshot(journal_dir)

    result = _ablate([str(_SPEC_FIXTURE), "--tree", str(tree)], tmp_path)

    assert result.returncode == 8, result.stdout + result.stderr
    assert f"REFUSING: {journal_dir} exists (owner pid=999999999" in result.stderr
    assert _snapshot(journal_dir) == snapshot


def test_an_empty_journal_directory_that_git_cannot_see_exits_5(tree: Path, tmp_path: Path) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    journal_dir.mkdir()
    # git lists files, not directories: an empty directory leaves the tree clean for it.
    assert _porcelain(tree) == ""

    result = _ablate([str(_SPEC_FIXTURE), "--tree", str(tree)], tmp_path)

    assert result.returncode == 5, (
        f"an empty {JOURNAL_DIRNAME} exited {result.returncode}: {result.stderr}"
    )
    assert f"REFUSING: {journal_dir} exists without owner.json" in result.stderr
    assert journal_dir.is_dir() and not any(journal_dir.iterdir())


def test_restore_needs_no_spec_and_reports_nothing_to_do_on_a_tree_without_journal(
    tree: Path, tmp_path: Path
) -> None:
    result = _ablate(["--restore", "--tree", str(tree)], tmp_path)

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "restored=0 already_original=0 unknown_state=0 tmp_removed=0 exchange_unavailable=0"
    ]
    assert not (tree / JOURNAL_DIRNAME).exists()


# --- the order of the entry checks ----------------------------------------------------------------


def test_a_journal_left_by_a_killed_run_exits_8_before_item_0_reads_the_mutated_file(
    tree: Path, tmp_path: Path
) -> None:
    _kill_a_holder(tree, [("sample.py", "VALUE = 2", "VALUE = 0")])
    journal_dir = tree / JOURNAL_DIRNAME
    snapshot = _snapshot(journal_dir)
    mutated = _head_blob(tree, "sample.py").replace(b"VALUE = 2", b"VALUE = 0", 1)
    assert (tree / "sample.py").read_bytes() == mutated
    # Item 0 would find the anchor of every row absent from the mutated file.
    assert b"VALUE = 2" not in mutated

    result = _ablate([str(_SPEC_FIXTURE), "--tree", str(tree)], tmp_path)

    assert result.returncode == 8, (
        f"exited {result.returncode} with a journal holding a mutation: {result.stderr}"
    )
    assert "item 0:" not in result.stderr
    assert _snapshot(journal_dir) == snapshot
    assert (tree / "sample.py").read_bytes() == mutated


@pytest.mark.parametrize("with_owner", [True, False], ids=["owner-file", "no-owner-file"])
def test_preflight_takes_the_journal_check_before_item_0(
    tree: Path, tmp_path: Path, with_owner: bool
) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    if with_owner:
        # A killed holder: its mutation is still on disk, so item 0 would call every anchor absent.
        _kill_a_holder(tree, [("sample.py", "VALUE = 2", "VALUE = 0")])
        assert b"VALUE = 2" not in (tree / "sample.py").read_bytes()
    else:
        journal_dir.mkdir()
    snapshot = _snapshot(journal_dir)
    sample = (tree / "sample.py").read_bytes()

    result = _ablate([str(_SPEC_FIXTURE), "--tree", str(tree), "--preflight"], tmp_path)

    expected = 8 if with_owner else 5
    assert result.returncode == expected, (
        f"--preflight with a journal present exited {result.returncode}: {result.stderr}"
    )
    assert "item 0:" not in result.stderr
    assert "preflight:" not in result.stdout
    assert _snapshot(journal_dir) == snapshot
    assert (tree / "sample.py").read_bytes() == sample


_ORDER_CASES = [
    "arguments-before-journal",
    "tolerate-dirty-argument-before-journal",
    "journal-before-item-0",
    "item-0-before-only",
    "only-before-dirty",
    "dirty-before-acquisition",
]


@pytest.mark.parametrize("case", _ORDER_CASES)
def test_the_entry_checks_run_in_their_order(tree: Path, tmp_path: Path, case: str) -> None:
    journal_dir = tree / JOURNAL_DIRNAME
    invalid = copy.deepcopy(_fixture_spec())
    invalid["mutants"][0]["olds"] = "VALUE = 2"
    invalid_path = _write_spec(tmp_path / "invalid.json", invalid)
    base = [str(_SPEC_FIXTURE), "--tree", str(tree)]
    if case == "arguments-before-journal":
        journal_dir.mkdir()
        (journal_dir / "owner.json").write_text('{"pid": 1}\n')
        args, code, marker = [*base, "--bogus"], 3, "ablate.py: error: "
    elif case == "tolerate-dirty-argument-before-journal":
        journal_dir.mkdir()
        (journal_dir / "owner.json").write_text('{"pid": 1}\n')
        args, code, marker = (
            [*base, "--tolerate-dirty", "."],
            3,
            "ablate.py: error: --tolerate-dirty '.': resolves to the root of the tree",
        )
    elif case == "journal-before-item-0":
        journal_dir.mkdir()
        args, code, marker = (
            [str(invalid_path), "--tree", str(tree)],
            5,
            "exists without owner.json",
        )
    elif case == "item-0-before-only":
        args, code, marker = (
            [str(invalid_path), "--tree", str(tree), "--only", "NOPE"],
            3,
            "key olds",
        )
    elif case == "only-before-dirty":
        (tree / "stray.txt").write_text("stray\n")
        args, code, marker = [*base, "--only", "NOPE"], 4, "--only names ids that are not in"
    else:
        (tree / "stray.txt").write_text("stray\n")
        args, code, marker = base, 5, "is dirty before the run"

    result = _ablate(args, tmp_path)

    assert (result.returncode, marker in result.stderr) == (code, True), result.stderr
    assert "[mutant]" not in result.stdout
    if case in ("only-before-dirty", "dirty-before-acquisition"):
        assert not journal_dir.exists()


def test_a_journal_acquired_by_another_process_after_the_checks_exits_8(
    tree: Path, tmp_path: Path
) -> None:
    result = _harness("acquire-race", tree, [str(_SPEC_FIXTURE), "--tree", str(tree)], tmp_path)

    assert _seam_lines(result.stderr) == ["[seam] acquire-race: another holder created the journal"]
    assert result.returncode == 8, result.stdout + result.stderr
    assert _snapshot(tree / JOURNAL_DIRNAME) == {
        "owner.json": _sha(b'{"pid": 1, "started_utc": "x"}\n')
    }
    assert "[mutant]" not in result.stdout


# --- errors of the journal against the checks after the run ---------------------------------------


@pytest.mark.parametrize(
    ("refusal", "code"),
    [("unknown-state", 9), ("exchange-unavailable", 12), ("journal-busy", 8)],
)
def test_a_journal_refusal_decides_the_exit_before_the_checks_after_the_run(
    tmp_path: Path, generator: ModuleType, refusal: str, code: int
) -> None:
    control_tree = _make_tree(generator, tmp_path / "control")
    tree = _make_tree(generator, tmp_path / "refused")
    # ST2 goes KILLED: a declared SURVIVED makes the expectation check fire.
    if refusal == "unknown-state":
        spec = _single_row_spec(tmp_path, "spec", "SURVIVED", launcher=_launcher(tmp_path))
        args = [str(spec), "--tree"]
        control = _ablate([*args, str(control_tree)], tmp_path)
        result = _ablate(
            [*args, str(tree)], tmp_path, {"ABLATION_TEST_LAUNCHER_MODE": "concurrent-writer"}
        )
    else:
        spec = _single_row_spec(tmp_path, "spec", "SURVIVED")
        seam = "restore-exchange-refused" if refusal == "exchange-unavailable" else "acquire-race"
        control = _harness("none", control_tree, [str(spec), "--tree", str(control_tree)], tmp_path)
        result = _harness(seam, tree, [str(spec), "--tree", str(tree)], tmp_path)
        assert _seam_lines(result.stderr), result.stderr

    assert control.returncode == 7, control.stdout + control.stderr
    assert "EXPECTATION FAILED ST2-property-red" in control.stderr
    assert result.returncode == code, (
        f"{refusal}: exited {result.returncode}, expected {code}: {result.stderr}"
    )
    assert "EXPECTATION FAILED" not in result.stderr
    assert "=== SUMMARY ===" not in result.stdout
    if refusal != "journal-busy":
        # The tree is left dirty, so the check after the run would have fired too.
        assert _porcelain(tree) != ""


@pytest.mark.parametrize(
    ("seam", "acts"),
    [
        (
            "refused-then-unknown",
            [
                "[seam] refused-then-unknown: EXDEV, target untouched",
                "[seam] refused-then-unknown: wrote the target, then EXDEV",
            ],
        ),
        (
            "unknown-then-refused",
            [
                "[seam] unknown-then-refused: wrote the target, then EXDEV",
                "[seam] unknown-then-refused: put the mutated bytes back once the hash was taken",
                "[seam] unknown-then-refused: EXDEV, target untouched",
            ],
        ),
    ],
)
def test_an_unknown_state_and_an_unavailable_exchange_in_one_chain_exit_9(
    tree: Path, tmp_path: Path, seam: str, acts: list[str]
) -> None:
    spec = _single_row_spec(tmp_path, "spec", "KILLED")

    result = _harness(seam, tree, [str(spec), "--tree", str(tree)], tmp_path)

    assert _seam_lines(result.stderr) == acts
    assert result.returncode == 9, (
        f"{seam}: exited {result.returncode} with both refusals in one chain: {result.stderr}"
    )
    # Both refusals are reported, the one carried only as context included.
    assert "failed with EXDEV" in result.stderr
    assert "sample.py is in an unknown state after its exchange was refused" in result.stderr


def test_a_mutation_that_did_not_land_whose_record_is_restored_reads_not_applied(
    tree: Path, tmp_path: Path
) -> None:
    spec = _single_row_spec(tmp_path, "spec", "NOT_APPLIED")
    out = tmp_path / "r.json"

    result = _harness(
        "apply-write-lost", tree, [str(spec), "--tree", str(tree), "--out", str(out)], tmp_path
    )

    assert _seam_lines(result.stderr) == [
        "[seam] apply-write-lost: dropped the write of the mutation"
    ]
    assert result.returncode == 0, result.stdout + result.stderr
    assert "[restore] already original: sample.py" in result.stderr
    row = json.loads(out.read_text())["results"][0]
    assert (row["verdict"], row["confirmed"]) == ("NOT_APPLIED", False)
    assert (row["ledger"]["record"], row["ledger"]["confirmed_on_disk"]) == ("01-sample.py", False)
    assert "applications_confirmed=0/1" in result.stdout.splitlines()
    assert _porcelain(tree) == ""
    assert not (tree / JOURNAL_DIRNAME).exists()


def test_a_mutation_that_did_not_land_whose_record_cannot_be_restored_exits_9_and_stops(
    tree: Path, tmp_path: Path
) -> None:
    spec = _fixture_spec()
    spec["mutants"] = spec["mutants"][:2]
    spec_path = _write_spec(tmp_path / "spec.json", spec)

    result = _harness(
        "apply-target-vanishes", tree, [str(spec_path), "--tree", str(tree)], tmp_path
    )

    assert _seam_lines(result.stderr) == [
        "[seam] apply-target-vanishes: removed sample.py while the mutation was staged"
    ]
    assert result.returncode == 9, (
        f"exited {result.returncode} for a record whose restore refused: {result.stderr}"
    )
    assert "REFUSING: sample.py is in an unknown state (sha=absent" in result.stderr
    assert "[mutant] ST3-form-red" not in result.stdout, "the run went on past the refused record"
    assert "NOT_APPLIED" not in result.stdout
    assert sorted(entry.name for entry in (tree / JOURNAL_DIRNAME).iterdir()) == [
        "01-sample.py.json",
        "01-sample.py.orig",
        "owner.json",
    ]
    assert (tree / "helper.py").read_bytes() == _head_blob(tree, "helper.py")


_PARTIAL_HEADER = "=== PARTIAL SUMMARY: the run stopped on a journal refusal ==="
_PARTIAL_RESULTS = (
    "results: not written (the run stopped on a journal refusal); this summary is the only "
    "record of the run"
)


@pytest.mark.parametrize(
    ("stop", "code", "partial"),
    [
        (
            "unknown-state-midway",
            9,
            [
                _PARTIAL_HEADER,
                'mutant_ids: ["ST2-property-red"]',
                "applications_confirmed=0/1",
                'records_left: ["01-sample.py"]',
                _PARTIAL_RESULTS,
            ],
        ),
        (
            "lost-acquisition",
            8,
            [
                _PARTIAL_HEADER,
                "mutant_ids: []",
                "applications_confirmed=0/0",
                "records_left: []",
                _PARTIAL_RESULTS,
            ],
        ),
        ("journal-present-at-entry", 8, None),
    ],
)
def test_a_journal_refusal_that_stops_the_run_prints_a_partial_summary_and_writes_no_results(
    tree: Path, tmp_path: Path, stop: str, code: int, partial: list[str] | None
) -> None:
    spec = _fixture_spec()
    spec["mutants"] = spec["mutants"][:2]
    spec_path = _write_spec(tmp_path / "spec.json", spec)
    out = tmp_path / "results.json"
    args = [str(spec_path), "--tree", str(tree), "--out", str(out)]
    if stop == "unknown-state-midway":
        result = _harness("apply-target-vanishes", tree, args, tmp_path)
    elif stop == "lost-acquisition":
        result = _harness("acquire-race", tree, args, tmp_path)
    else:
        journal_dir = tree / JOURNAL_DIRNAME
        journal_dir.mkdir()
        (journal_dir / "owner.json").write_text('{"pid": 999999999, "started_utc": "x"}\n')
        result = _ablate(args, tmp_path)

    assert result.returncode == code, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    if partial is None:
        assert _PARTIAL_HEADER not in lines, "an entry check is not a run stopped midway"
    else:
        assert _PARTIAL_HEADER in lines, f"{stop}: no partial summary in {lines}"
        start = lines.index(_PARTIAL_HEADER)
        assert lines[start : start + len(partial)] == partial
    assert not out.exists()


# --- the results file -----------------------------------------------------------------------------


def test_without_out_no_results_file_is_written_and_the_summary_says_so(
    tree: Path, tmp_path: Path
) -> None:
    spec_dir = tmp_path / "spec"
    spec_dir.mkdir()
    spec = spec_dir / "spec_fixture_st1.json"
    spec.write_bytes(_SPEC_ST1.read_bytes())
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    before = (_tree_state(tree), _snapshot(spec_dir), _snapshot(cwd))

    result = _ablate([str(spec), "--tree", str(tree), "--skip-preflight"], cwd)

    assert result.returncode == 0, result.stdout + result.stderr
    assert (
        "results: not written (no --out given); this summary is the only record of the run"
        in result.stdout.splitlines()
    )
    assert (_tree_state(tree), _snapshot(spec_dir), _snapshot(cwd)) == before


# --- the exits of --restore, measured in this process ---------------------------------------------


@pytest.fixture
def ablate_module() -> Iterator[ModuleType]:
    """The bench loaded by path into this process, and removed again afterwards."""
    added = [
        name for name in (_ABLATE_MODULE_NAME, "journal", "classify") if name not in sys.modules
    ]
    path_before = list(sys.path)
    try:
        yield _load_by_path(_ABLATE, _ABLATE_MODULE_NAME, register=True)
    finally:
        for name in added:
            sys.modules.pop(name, None)
        sys.path[:] = path_before


def test_loading_the_bench_installs_no_signal_handler() -> None:
    handlers = _handlers()
    added = [
        name for name in (_ABLATE_MODULE_NAME, "journal", "classify") if name not in sys.modules
    ]
    path_before = list(sys.path)
    try:
        module = _load_by_path(_ABLATE, _ABLATE_MODULE_NAME, register=True)
        assert _handlers() == handlers
        assert Path(module.journal.__file__).resolve() == _JOURNAL
    finally:
        for name in added:
            sys.modules.pop(name, None)
        sys.path[:] = path_before


# What `tsc --noEmit --pretty false -p tsconfig.json` printed, run in the package directory of
# the TypeScript verifier: with the type-invalid mutation of the TS self-test applied (exit 2),
# and in a directory with no tsconfig.json (exit 1).
_TSC_TYPE_ERRORS = (
    "src/revocation.ts(480,11): error TS2322: Type 'JsonValue | undefined' is not assignable "
    "to type 'number'.\n"
    "  Type 'undefined' is not assignable to type 'number'.\n"
    "src/revocation.ts(481,9): error TS2367: This comparison appears to be unintentional "
    "because the types 'number' and 'string' have no overlap.\n"
    "src/revocation.ts(481,33): error TS2367: This comparison appears to be unintentional "
    "because the types 'number' and 'string' have no overlap.\n"
)
_TSC_MISSING_CONFIG = "error TS5058: The specified path does not exist: 'tsconfig.json'.\n"


@pytest.mark.parametrize(
    ("output", "codes"),
    [
        (_TSC_TYPE_ERRORS, ["TS2322", "TS2367"]),
        (_TSC_MISSING_CONFIG, []),
        (
            "b.ts(2,2): error TS2322: one.\na.ts(1,1): error TS18048: two.\n"
            "b.ts(3,3): error TS2322: three.\n",
            ["TS2322", "TS18048"],
        ),
        ("the previous run reported error TS2322 in src/a.ts\n", []),
        ("src/a.ts(1,1): error TS2322 without the colon that ends a code\n", []),
        ("", []),
    ],
    ids=[
        "type-errors",
        "missing-config",
        "repeated-and-numeric-order",
        "code-quoted-in-prose",
        "code-without-closing-colon",
        "empty",
    ],
)
def test_tsc_form_codes_reads_only_the_located_error_diagnostics(
    ablate_module: ModuleType, output: str, codes: list[str]
) -> None:
    assert ablate_module.tsc_form_codes(output) == codes


# A stand-in for a package's `tsc`. In mode `type-errors` it prints two diagnostics of the kind
# in `_TSC_TYPE_ERRORS`, in the located form only when invoked with `--pretty false`, and in the
# pretty form `file:line:col - error TS...` otherwise; in mode `no-diagnostic` it fails the
# way a missing configuration does. Either way it exits non-zero, as tsc does on an error.
_FAKE_TSC = """
import sys

args = sys.argv[1:]
mode = MODE
if mode == "no-diagnostic":
    sys.stdout.write("error TS5058: The specified path does not exist: 'tsconfig.json'.\\n")
    sys.exit(1)
located = "--pretty" in args and args[args.index("--pretty") + 1 :][:1] == ["false"]
if located:
    sys.stdout.write(
        "src/revocation.ts(480,11): error TS2322: Type 'JsonValue | undefined' is not "
        "assignable to type 'number'.\\n"
        "src/revocation.ts(481,9): error TS2367: This comparison appears to be unintentional.\\n"
    )
else:
    sys.stdout.write(
        "src/revocation.ts:480:11 - error TS2322: Type 'JsonValue | undefined' is not "
        "assignable to type 'number'.\\n"
        "src/revocation.ts:481:9 - error TS2367: This comparison appears to be unintentional.\\n"
    )
sys.exit(2)
"""


def _package_with_a_tsc(root: Path, mode: str) -> None:
    bin_dir = root / "pkg" / "node_modules" / ".bin"
    bin_dir.mkdir(parents=True)
    tsc = bin_dir / "tsc"
    tsc.write_text(
        f"#!{sys.executable}\n" + _FAKE_TSC.replace("MODE", repr(mode)), encoding="utf-8"
    )
    tsc.chmod(0o755)


@pytest.mark.parametrize(
    ("mode", "codes", "measured"),
    [("type-errors", ["TS2322", "TS2367"], True), ("no-diagnostic", [], False)],
)
def test_a_vitest_run_stopped_by_tsc_is_measured_only_by_located_diagnostics(
    ablate_module: ModuleType, tmp_path: Path, mode: str, codes: list[str], measured: bool
) -> None:
    _package_with_a_tsc(tmp_path, mode)

    run = ablate_module.run_vitest(tmp_path, "pkg", ["test/a.test.ts"], typecheck=True)

    assert run.typecheck is not None, f"{mode}: tsc exited non-zero and no typecheck trace"
    assert (run.nonce_echoed, run.typecheck["tsc_returncode"]) == (None, 2 if measured else 1)
    assert run.typecheck["form_codes"] == codes, (
        f"{mode}: form_codes={run.typecheck['form_codes']}: tsc was not asked for "
        "--pretty false, so its diagnostics came in the pretty form the codes are not read from"
    )
    problems = ablate_module._measurement_problems(run, "TS-X mutated")
    if measured:
        assert problems == [], problems
    else:
        assert [problem.split(" (output sha256")[0] for problem in problems] == [
            "typecheck: TS-X mutated: tsc exited 1 with source diagnostic codes []"
        ], f"a tsc stop without a located diagnostic was counted as measured: {problems}"


def _refuse_restore_exchange(
    module: ModuleType, monkeypatch: pytest.MonkeyPatch, staging_name: str
) -> list[str]:
    """Make the exchange of one restore staging file fail with EXDEV, on the bench's journal."""
    acted: list[str] = []
    real_exchange = module.journal._exchange

    def exchange(first: Path, second: Path) -> None:
        if Path(first).name == staging_name:
            acted.append(Path(first).name)
            raise OSError(errno.EXDEV, os.strerror(errno.EXDEV), str(first), None, str(second))
        real_exchange(first, second)

    monkeypatch.setattr(module.journal, "_exchange", exchange)
    return acted


def test_restore_exits_9_when_a_record_is_in_an_unknown_state(
    ablate_module: ModuleType, tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _kill_a_holder(tree, [("sample.py", "VALUE = 2", "VALUE = 0")])
    (tree / "sample.py").write_bytes(b"VALUE = 5\n")
    snapshot = _snapshot(tree / JOURNAL_DIRNAME)

    code = ablate_module.main(["--restore", "--tree", str(tree)])

    captured = capsys.readouterr()
    assert captured.out.splitlines() == [
        "restored=0 already_original=0 unknown_state=1 tmp_removed=0 exchange_unavailable=0"
    ]
    assert code == 9
    assert _snapshot(tree / JOURNAL_DIRNAME) == snapshot


def test_restore_exits_12_when_an_exchange_is_unavailable_and_no_state_is_unknown(
    ablate_module: ModuleType,
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _kill_a_holder(tree, [("sample.py", "VALUE = 2", "VALUE = 0")])
    acted = _refuse_restore_exchange(ablate_module, monkeypatch, "01-sample.py.restore.tmp")

    code = ablate_module.main(["--restore", "--tree", str(tree)])

    captured = capsys.readouterr()
    assert acted == ["01-sample.py.restore.tmp"]
    assert captured.out.splitlines() == [
        "restored=0 already_original=0 unknown_state=0 tmp_removed=0 exchange_unavailable=1"
    ]
    assert code == 12


def test_restore_exits_9_when_one_journal_holds_both_and_counts_both(
    ablate_module: ModuleType,
    tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _kill_a_holder(
        tree,
        [
            ("sample.py", "VALUE = 2", "VALUE = 0"),
            ("helper.py", "    return VALUE_NAME", "    return VALUE_NAME_TYPO"),
        ],
    )
    (tree / "sample.py").write_bytes(b"VALUE = 5\n")
    acted = _refuse_restore_exchange(ablate_module, monkeypatch, "02-helper.py.restore.tmp")

    code = ablate_module.main(["--restore", "--tree", str(tree)])

    captured = capsys.readouterr()
    assert acted == ["02-helper.py.restore.tmp"]
    assert captured.out.splitlines() == [
        "restored=0 already_original=0 unknown_state=1 tmp_removed=0 exchange_unavailable=1"
    ]
    assert code == 9, f"a journal with both refusals exited {code}"


# --- short integration on the fixture tree --------------------------------------------------------


def test_the_fixture_spec_confirms_five_applications_and_meets_its_expectations(
    tree: Path, tmp_path: Path
) -> None:
    out = tmp_path / "results.json"
    run_nonce = "a-nonce-this-test-chose"

    result = _ablate(
        [str(_SPEC_FIXTURE), "--tree", str(tree), "--out", str(out)],
        tmp_path,
        {"ABLATION_RUN_NONCE": run_nonce},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    assert "applications_confirmed=5/5" in lines
    assert "expectations: 5 declared, 5 met, 0 unmeasured" in lines
    assert (
        lines.index("mutant_ids: " + json.dumps(FIXTURE_IDS))
        < lines.index("applications_confirmed=5/5")
        < lines.index(f"{FIXTURE_IDS[0]}: KILLED (1/5 red)")
    )
    payload = json.loads(out.read_text())
    # Without --tolerate-dirty nothing of it shows: no marker line, no field.
    assert not [line for line in lines if line.startswith("dirty tolerated:")]
    assert list(payload) == ["summary", "results"]
    summary = payload["summary"]
    assert summary["nonce_of_run"] == run_nonce
    assert summary["mutant_ids"] == FIXTURE_IDS
    assert (summary["applications_confirmed"], summary["applications_attempted"]) == (5, 5)
    assert (
        summary["expectations_declared"],
        summary["expectations_failed"],
        summary["expectations_unmeasured"],
    ) == (5, 0, 0)
    rows = {row["id"]: row for row in payload["results"]}
    for mutant_id in FIXTURE_IDS:
        row = rows[mutant_id]
        target = "helper.py" if mutant_id == "ST3-form-red" else "sample.py"
        assert row["git_dirty_during"] == [f" M {target}"], mutant_id
        assert row["nonce"]["echoed"] == row["nonce"]["issued"], mutant_id
        # A pytest row is measured by its nonce and never carries the trace of a tsc stop.
        assert row["typecheck"] is None, mutant_id
        assert row["verdict"] == FIXTURE_VERDICTS[mutant_id], mutant_id
    head = _head_blob(tree, "sample.py")
    assert rows["ST2-property-red"]["ledger"]["sha_after"] == _sha(
        head.replace(b"VALUE = 2", b"VALUE = 0", 1)
    )
    assert rows["ST2-property-red"]["named_reds"] == {
        "test_guard": {"test_sample.py::test_guard": "AssertionError"}
    }
    assert _porcelain(tree) == ""
    assert not (tree / JOURNAL_DIRNAME).exists()


def test_the_absent_anchor_spec_reads_not_applied_with_no_application_confirmed(
    tree: Path, tmp_path: Path
) -> None:
    out = tmp_path / "results.json"

    result = _ablate(
        [str(_SPEC_ST1), "--tree", str(tree), "--skip-preflight", "--out", str(out)], tmp_path
    )

    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    assert "applications_confirmed=0/1" in lines
    assert "expectations: 1 declared, 1 met, 0 unmeasured" in lines
    summary = json.loads(out.read_text())["summary"]
    assert (summary["not_applied"], summary["applications_confirmed"]) == (1, 0)
    assert summary["mutant_ids"] == ["ST1-anchor-absent"]
    assert _porcelain(tree) == ""


def test_a_plugin_mutant_is_confirmed_by_plugins_loaded_and_a_clean_git_status(
    tree: Path, tmp_path: Path
) -> None:
    _commit(tree, {"value_zero_plugin.py": b"import sample\n\nsample.VALUE = 0\n"})
    spec = _fixture_spec()
    spec["mutants"] = [
        {
            "id": "PL1-plugin",
            "kind": "plugin",
            "plugin": "value_zero_plugin",
            "property": "a plugin that sets the value the guard pins",
            "suite": ["test_sample.py"],
            "expect_red": ["test_guard"],
            "expect_verdict": "KILLED",
        }
    ]
    spec_path = _write_spec(tmp_path / "spec.json", spec)
    out = tmp_path / "results.json"

    result = _ablate([str(spec_path), "--tree", str(tree), "--out", str(out)], tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    row = json.loads(out.read_text())["results"][0]
    assert (row["verdict"], row["confirmed"], row["git_dirty_during"]) == ("KILLED", True, [])
    assert row["ledger"] == {
        "plugin": "value_zero_plugin",
        "sha_of_plugin_file": _sha(b"import sample\n\nsample.VALUE = 0\n"),
    }


@pytest.mark.parametrize(
    ("mode", "reason"),
    [
        ("drop-nonce", "nonce: ST2-property-red mutated: the outcomes read from "),
        ("incoherent-outcomes", "outcomes: ST2-property-red mutated ("),
    ],
)
def test_a_mutated_run_without_a_measurement_leaves_the_row_unmeasured_and_exits_10(
    tree: Path, tmp_path: Path, mode: str, reason: str
) -> None:
    spec = _single_row_spec(tmp_path, "spec", "KILLED", launcher=_launcher(tmp_path))
    out = tmp_path / "results.json"

    result = _ablate(
        [str(spec), "--tree", str(tree), "--out", str(out)],
        tmp_path,
        {"ABLATION_TEST_LAUNCHER_MODE": mode},
    )

    assert result.returncode == 10, result.stdout + result.stderr
    row_lines = [
        line for line in result.stdout.splitlines() if line.startswith("ST2-property-red:")
    ]
    assert len(row_lines) == 1 and row_lines[0].startswith("ST2-property-red: UNMEASURED -- ")
    assert reason in row_lines[0]
    payload = json.loads(out.read_text())
    assert payload["results"][0]["verdict"] is None
    assert payload["summary"]["expectations_unmeasured"] == 1
    assert "applications_confirmed=0/1" in result.stdout.splitlines()
    assert _porcelain(tree) == ""


def test_a_tree_left_dirty_by_the_suite_exits_6_before_the_expectation_check(
    tree: Path, tmp_path: Path
) -> None:
    spec = _single_row_spec(tmp_path, "spec", "SURVIVED", launcher=_launcher(tmp_path))

    result = _ablate(
        [str(spec), "--tree", str(tree)], tmp_path, {"ABLATION_TEST_LAUNCHER_MODE": "stray-file"}
    )

    assert result.returncode == 6, result.stdout + result.stderr
    assert "is dirty after the run" in result.stderr
    assert "EXPECTATION FAILED" not in result.stderr


def test_more_than_one_mutant_all_surviving_exits_11_and_prints_their_traces(
    tree: Path, tmp_path: Path
) -> None:
    spec = _fixture_spec()
    spec["mutants"] = [
        spec["mutants"][4],
        {
            "id": "ST6b-inert-helper",
            "property": "a comment added to the helper",
            "file": "helper.py",
            "old": "VALUE_NAME = 1",
            "new": "VALUE_NAME = 1  # inert",
            "suite": ["test_sample.py"],
            "expect_red": [],
        },
    ]
    spec_path = _write_spec(tmp_path / "spec.json", spec)

    result = _ablate([str(spec_path), "--tree", str(tree)], tmp_path)

    assert result.returncode == 11, result.stdout + result.stderr
    assert "ALL SURVIVED: 2 of 2 mutants survived" in result.stderr
    for mutant_id, target in (("ST6-inert", "sample.py"), ("ST6b-inert-helper", "helper.py")):
        traces = [
            line for line in result.stderr.splitlines() if line.startswith(f"  {mutant_id}: ")
        ]
        assert len(traces) == 1 and f'git_dirty_during=[" M {target}"]' in traces[0]
    assert _porcelain(tree) == ""


# --- --tolerate-dirty -----------------------------------------------------------------------------

# Every expected line below is written from the rule it pins, never from what the
# predicate under test answers.
_TOLERATED = "logs"
_TOLERATED_MARKER = "dirty tolerated: {n} line(s) under logs"
_ROOT_REASON = (
    "resolves to the root of the tree {tree}, and tolerating the root would switch the "
    "dirty-tree check off instead of narrowing it"
)


def _tolerating_tree(tree: Path) -> Path:
    """The fixture tree with `logs/` tracked, so git lists what changes there file by file."""
    (tree / _TOLERATED).mkdir()
    _commit(tree, {"logs/kept.log": b"kept\n", "logs/mod.py": b"VALUE = 2\n"})
    return tree


def _tolerating(spec: Path, tree: Path, *extra: str) -> list[str]:
    return [str(spec), "--tree", str(tree), "--tolerate-dirty", _TOLERATED, *extra]


def _refusals(stderr: str) -> list[str]:
    return [line for line in stderr.splitlines() if line.startswith("REFUSING")]


_TOLERATE_ARGUMENT_REFUSALS = [
    (
        "empty",
        "",
        "an empty path names the root of the tree, and tolerating the root would switch "
        "the dirty-tree check off instead of narrowing it",
    ),
    ("dot", ".", _ROOT_REASON),
    ("dot-slash", "./", _ROOT_REASON),
    ("sub-dotdot", "logs/..", _ROOT_REASON),
    ("absolute-root", "<ROOT>", _ROOT_REASON),
    ("link-to-root", "root-link", _ROOT_REASON),
    ("dotdot", "..", "resolves to {parent}, outside the tree {tree}"),
    ("absolute-outside", "<OUTSIDE>", "resolves to {outside}, outside the tree {tree}"),
    ("link-outside", "out-link", "resolves to {outside}, outside the tree {tree}"),
    ("absent", "no-such-dir", "{tree}/no-such-dir does not exist"),
    ("not-a-directory", "sample.py", "{tree}/sample.py is not a directory"),
]


@pytest.mark.parametrize(
    ("given", "reason"),
    [(given, reason) for _name, given, reason in _TOLERATE_ARGUMENT_REFUSALS],
    ids=[name for name, _given, _reason in _TOLERATE_ARGUMENT_REFUSALS],
)
def test_a_tolerate_dirty_argument_that_is_the_root_or_not_a_directory_of_the_tree_exits_3(
    tree: Path, tmp_path: Path, given: str, reason: str
) -> None:
    _tolerating_tree(tree)
    (tmp_path / "elsewhere").mkdir()
    outside = (tmp_path / "elsewhere").resolve()
    (tree / "root-link").symlink_to(tree)
    (tree / "out-link").symlink_to(outside)
    argument = given.replace("<ROOT>", str(tree)).replace("<OUTSIDE>", str(outside))
    expected = f"ablate.py: error: --tolerate-dirty {argument!r}: " + reason.format(
        tree=tree, parent=tree.parent, outside=outside
    )
    porcelain = _porcelain(tree)

    result = _ablate(
        [str(_SPEC_FIXTURE), "--tree", str(tree), "--tolerate-dirty", argument], tmp_path
    )

    assert (result.returncode, result.stderr.splitlines()) == (3, [expected]), (
        f"--tolerate-dirty {argument!r} was not refused as an argument: exited "
        f"{result.returncode}: {result.stderr}"
    )
    assert "[mutant]" not in result.stdout
    assert not (tree / JOURNAL_DIRNAME).exists()
    assert _porcelain(tree) == porcelain


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (
            ["SPEC", "--tolerate-dirty", "logs"],
            "ablate.py: error: --tolerate-dirty is allowed only with an explicit --tree",
        ),
        (
            ["--restore", "--tree", "TREE", "--tolerate-dirty", "logs"],
            "ablate.py: error: --restore takes only --tree, found ['--tolerate-dirty']",
        ),
        (
            ["SPEC", "--tree", "TREE", "--preflight", "--tolerate-dirty", "logs"],
            "ablate.py: error: --tolerate-dirty has no effect with --preflight, which never "
            "reads git status",
        ),
    ],
    ids=["without-tree", "with-restore", "with-preflight"],
)
def test_tolerate_dirty_without_a_tree_or_where_it_changes_nothing_exits_3(
    tree: Path, tmp_path: Path, args: list[str], message: str
) -> None:
    _tolerating_tree(tree)
    concrete = [
        str(_SPEC_FIXTURE) if arg == "SPEC" else str(tree) if arg == "TREE" else arg for arg in args
    ]

    result = _ablate(concrete, tmp_path)

    assert (result.returncode, result.stderr.splitlines()) == (3, [message]), result.stderr
    assert not (tree / JOURNAL_DIRNAME).exists()


@pytest.mark.parametrize(
    ("line", "tolerated"),
    [
        ("?? logs/new.log", True),
        (" M logs/kept.log", True),
        (" D logs/kept.log", True),
        # An untracked directory git collapsed into one line, the tolerated one or one
        # inside it: what appears inside would leave the line as it is, so it cannot be
        # compared. And the tolerated directory named alone, as git names a submodule.
        ("?? logs/", False),
        ("?? logs/sub/", False),
        (" M logs", False),
        ("?? deep/inner/x.log", True),
        ("R  logs/kept.log -> logs/moved.log", True),
        ("?? logs2/x.log", False),
        ("?? logs2/", False),
        ("?? deep/", False),
        ("?? sample.py", False),
        ('?? "logs/sp ace.log"', False),
        ("R  logs/kept.log -> kept.log", False),
        ("R  notes.txt -> logs/notes.txt", False),
        ("R  logs/kept.log", False),
        ("?? logs/a -> logs/b", False),
        ("?? logs/../sample.py", False),
        ("X  logs/new.log", False),
        ("??logs/new.log", False),
    ],
)
def test_a_status_line_is_tolerated_only_when_every_path_it_names_lies_under_a_directory(
    ablate_module: ModuleType, line: str, tolerated: bool
) -> None:
    split = ablate_module._split_tolerated([line], ("logs", "deep/inner"))

    assert split == (([line], []) if tolerated else ([], [line])), (
        f"{line!r} should be {'tolerated' if tolerated else 'refused'}"
    )


def test_without_tolerate_dirty_a_dirty_file_in_the_directory_exits_5_as_before(
    tree: Path, tmp_path: Path
) -> None:
    _tolerating_tree(tree)
    (tree / "logs" / "new.log").write_text("new\n")
    spec = _single_row_spec(tmp_path, "spec", "KILLED")

    result = _ablate([str(spec), "--tree", str(tree)], tmp_path)

    assert result.returncode == 5, result.stdout + result.stderr
    assert result.stderr.splitlines() == [
        f"REFUSING: {tree} is dirty before the run, or git cannot say "
        "(git status --porcelain --untracked-files=normal): ['?? logs/new.log']"
    ]
    assert "dirty tolerated" not in result.stdout
    assert not (tree / JOURNAL_DIRNAME).exists()


@pytest.mark.parametrize("dirty", [True, False], ids=["one-line", "no-line"])
def test_with_tolerate_dirty_a_dirty_file_in_the_directory_is_tolerated_and_declared(
    tree: Path, tmp_path: Path, dirty: bool
) -> None:
    _tolerating_tree(tree)
    if dirty:
        (tree / "logs" / "new.log").write_text("new\n")
    reference = ["?? logs/new.log"] if dirty else []
    spec = _single_row_spec(tmp_path, "spec", "KILLED")
    out = tmp_path / "results.json"

    result = _ablate(_tolerating(spec, tree, "--out", str(out)), tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    assert _TOLERATED_MARKER.format(n=len(reference)) in lines
    assert "applications_confirmed=1/1" in lines
    payload = json.loads(out.read_text())
    assert list(payload) == ["summary", "dirty_tolerated", "results"]
    assert payload["dirty_tolerated"] == {"dirs": ["logs"], "lines": reference}
    row = payload["results"][0]
    assert (row["verdict"], row["confirmed"], row["git_dirty_during"]) == (
        "KILLED",
        True,
        [" M sample.py"],
    )
    assert _porcelain(tree) == "".join(f"{line}\n" for line in reference)


def test_tolerate_dirty_arguments_that_resolve_to_one_directory_count_once(
    tree: Path, tmp_path: Path
) -> None:
    _tolerating_tree(tree)
    spec = _single_row_spec(tmp_path, "spec", "KILLED")
    out = tmp_path / "results.json"
    aliases = ["--tolerate-dirty", "logs/", "--tolerate-dirty", "./logs"]

    result = _ablate(_tolerating(spec, tree, *aliases, "--out", str(out)), tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert _TOLERATED_MARKER.format(n=0) in result.stdout.splitlines()
    assert json.loads(out.read_text())["dirty_tolerated"]["dirs"] == ["logs"]


@pytest.mark.parametrize(
    ("dirt", "tolerate", "line"),
    [
        ("stray.txt", "logs", "?? stray.txt"),
        # A file, so git names it alone: a collapsed `?? logs2/` is refused before the
        # comparison of components is ever reached.
        ("logs2.log", "logs", "?? logs2.log"),
        ("deep/x.log", "deep/inner", "?? deep/"),
        ("logs/sp ace.log", "logs", '?? "logs/sp ace.log"'),
        ("fresh/x.log", "fresh", "?? fresh/"),
        ("logs/sub/x.log", "logs", "?? logs/sub/"),
    ],
    ids=[
        "outside",
        "sibling-sharing-a-prefix",
        "directory-containing-it",
        "quoted-by-git",
        "the-tolerated-directory-collapsed",
        "a-directory-collapsed-inside-it",
    ],
)
def test_with_tolerate_dirty_a_line_outside_the_directory_exits_5_naming_it(
    tree: Path, tmp_path: Path, dirt: str, tolerate: str, line: str
) -> None:
    _tolerating_tree(tree)
    (tree / "deep" / "inner").mkdir(parents=True)
    (tree / dirt).parent.mkdir(parents=True, exist_ok=True)
    (tree / dirt).write_text("dirt\n")
    spec = _single_row_spec(tmp_path, "spec", "KILLED")

    result = _ablate([str(spec), "--tree", str(tree), "--tolerate-dirty", tolerate], tmp_path)

    assert result.returncode == 5, result.stdout + result.stderr
    assert _refusals(result.stderr) == [
        f"REFUSING: {tree} is dirty before the run outside the tolerated directories "
        f"[{tolerate!r}] (git status --porcelain --untracked-files=normal): [{line!r}]"
    ]
    assert f"dirty tolerated: 0 line(s) under {tolerate}" in result.stdout.splitlines()
    assert "[mutant]" not in result.stdout
    assert not (tree / JOURNAL_DIRNAME).exists()


@pytest.mark.parametrize(
    ("move", "line", "tolerated"),
    [
        (("logs/kept.log", "kept.log"), "R  logs/kept.log -> kept.log", False),
        (("notes.txt", "logs/notes.txt"), "R  notes.txt -> logs/notes.txt", False),
        (("logs/kept.log", "logs/moved.log"), "R  logs/kept.log -> logs/moved.log", True),
    ],
    ids=["out-of-the-directory", "into-the-directory", "within-the-directory"],
)
def test_a_rename_is_tolerated_only_when_both_of_its_paths_are(
    tree: Path, tmp_path: Path, move: tuple[str, str], line: str, tolerated: bool
) -> None:
    _tolerating_tree(tree)
    _commit(tree, {"notes.txt": b"notes\n"})
    _git(tree, "mv", *move)
    assert _porcelain(tree) == f"{line}\n"
    spec = _single_row_spec(tmp_path, "spec", "KILLED")
    out = tmp_path / "results.json"

    result = _ablate(_tolerating(spec, tree, "--out", str(out)), tmp_path)

    if tolerated:
        assert result.returncode == 0, result.stdout + result.stderr
        assert _TOLERATED_MARKER.format(n=1) in result.stdout.splitlines()
        assert json.loads(out.read_text())["dirty_tolerated"]["lines"] == [line]
    else:
        assert result.returncode == 5, result.stdout + result.stderr
        assert _refusals(result.stderr) == [
            f"REFUSING: {tree} is dirty before the run outside the tolerated directories "
            f"['logs'] (git status --porcelain --untracked-files=normal): [{line!r}]"
        ]
        assert not out.exists()


@pytest.mark.parametrize("skip_preflight", [False, True], ids=["item-0", "skip-preflight"])
@pytest.mark.parametrize("file", ["logs/mod.py", "lnk/mod.py"], ids=["as-written", "via-a-link"])
def test_a_mutant_whose_file_lies_under_a_tolerated_directory_is_refused_by_item_0(
    tree: Path, tmp_path: Path, file: str, skip_preflight: bool
) -> None:
    _tolerating_tree(tree)
    (tree / "lnk").symlink_to("logs")
    _git(tree, "add", "lnk")
    _git(tree, "commit", "-m", "Add a link to the tolerated directory")
    spec = _fixture_spec()
    spec["mutants"] = [
        {
            "id": "TD1-under-tolerated",
            "property": "a mutation where the bench no longer reads git status in absolute terms",
            "file": file,
            "old": "VALUE = 2",
            "new": "VALUE = 0",
            "suite": ["test_sample.py"],
            "expect_red": [],
        }
    ]
    spec_path = _write_spec(tmp_path / "spec.json", spec)
    # `_tree_state` reads every tracked path as a file, and the tracked link is a directory.
    before = (_porcelain(tree), (tree / "logs" / "mod.py").read_bytes())

    result = _ablate(
        _tolerating(spec_path, tree, *(["--skip-preflight"] if skip_preflight else [])), tmp_path
    )

    assert result.returncode == 3, (
        f"{file} under the tolerated directory was not refused by item 0: exited "
        f"{result.returncode}: {result.stdout}{result.stderr}"
    )
    assert (
        f"item 0: mutant TD1-under-tolerated: key file: {file} lies under the tolerated "
        "directory logs, where the bench does not read git status in absolute terms, so a "
        "mutation there would not be seen"
    ) in result.stderr.splitlines()
    assert "[mutant]" not in result.stdout
    assert not (tree / JOURNAL_DIRNAME).exists()
    assert (_porcelain(tree), (tree / "logs" / "mod.py").read_bytes()) == before


# Each verse of a change under the tolerated directory, the state it starts from, and how
# the refusal names it: path, kind, and the directory it lies under.
_TOLERATED_VERSES = [
    ("appears", None, "logs/new.log under tolerated directory logs: appeared '??'"),
    (
        "disappears",
        ("logs/old.log", "old\n"),
        "logs/old.log under tolerated directory logs: disappeared '??'",
    ),
    (
        "changes",
        ("logs/kept.log", "kept, edited\n"),
        "logs/kept.log under tolerated directory logs: changed ' M'->' D'",
    ),
]


@pytest.mark.parametrize(
    ("verse", "start", "change"),
    _TOLERATED_VERSES,
    ids=[verse for verse, _start, _change in _TOLERATED_VERSES],
)
def test_a_tolerated_line_that_changes_during_the_run_exits_6_naming_path_and_kind(
    tree: Path, tmp_path: Path, verse: str, start: tuple[str, str] | None, change: str
) -> None:
    _tolerating_tree(tree)
    if start is not None:
        (tree / start[0]).write_text(start[1])
    reference = _porcelain(tree)
    spec = _single_row_spec(tmp_path, "spec", "KILLED", launcher=_launcher(tmp_path))
    out = tmp_path / "results.json"

    result = _ablate(
        _tolerating(spec, tree, "--out", str(out)),
        tmp_path,
        {"ABLATION_TEST_LAUNCHER_MODE": f"tolerated-{verse}-after"},
    )

    assert result.returncode == 6, (
        f"a tolerated line that {verse} during the run exited {result.returncode}: "
        f"{result.stdout}{result.stderr}"
    )
    refusals = _refusals(result.stderr)
    assert len(refusals) == 1, refusals
    assert refusals[0].startswith(
        f"REFUSING: {tree} is dirty after the run under the tolerated directories ['logs'], "
        "whose lines are not those of the start of the run: "
    ), refusals
    assert change in refusals[0], f"the refusal deciding exit 6 does not name {change!r}"
    assert _porcelain(tree) != reference
    row = json.loads(out.read_text())["results"][0]
    # The change came after the snapshot taken during the mutation: the row stands.
    assert (row["verdict"], row["confirmed"]) == ("KILLED", True)


@pytest.mark.parametrize(
    ("verse", "start", "change"),
    _TOLERATED_VERSES,
    ids=[verse for verse, _start, _change in _TOLERATED_VERSES],
)
def test_a_tolerated_line_changed_before_the_mutation_snapshot_leaves_the_row_unmeasured(
    tree: Path, tmp_path: Path, verse: str, start: tuple[str, str] | None, change: str
) -> None:
    _tolerating_tree(tree)
    if start is not None:
        (tree / start[0]).write_text(start[1])
    reference = _porcelain(tree)
    spec = _single_row_spec(tmp_path, "spec", "KILLED", launcher=_launcher(tmp_path))

    result = _ablate(
        _tolerating(spec, tree),
        tmp_path,
        {"ABLATION_TEST_LAUNCHER_MODE": f"tolerated-{verse}-during"},
    )

    assert result.returncode == 10, (
        f"a tolerated line that {verse} before the mutation snapshot exited "
        f"{result.returncode}: {result.stdout}{result.stderr}"
    )
    refusals = _refusals(result.stderr)
    assert len(refusals) == 1 and refusals[0].startswith("REFUSING TO CERTIFY: "), refusals
    assert (
        "the git trace of ST2-property-red failed on the tolerated directories, not on its "
        "mutation, because their lines are not those of the start of the run: "
    ) in refusals[0], refusals
    assert change in refusals[0], f"the refusal deciding exit 10 does not name {change!r}"
    row_lines = [
        line for line in result.stdout.splitlines() if line.startswith("ST2-property-red:")
    ]
    assert len(row_lines) == 1 and row_lines[0].startswith("ST2-property-red: UNMEASURED -- ")
    assert change in row_lines[0]
    # The mutated run undid the change: the tree after the run is the tree before it.
    assert _porcelain(tree) == reference


def test_with_tolerate_dirty_a_file_left_outside_the_directory_after_the_run_exits_6(
    tree: Path, tmp_path: Path
) -> None:
    _tolerating_tree(tree)
    spec = _single_row_spec(tmp_path, "spec", "KILLED", launcher=_launcher(tmp_path))

    result = _ablate(
        _tolerating(spec, tree), tmp_path, {"ABLATION_TEST_LAUNCHER_MODE": "stray-file"}
    )

    assert result.returncode == 6, result.stdout + result.stderr
    assert _refusals(result.stderr) == [
        f"REFUSING: {tree} is dirty after the run outside the tolerated directories "
        "['logs']: ['?? stray.txt'] -- a restore failed somewhere, and no verdict above can "
        "be trusted"
    ]


def test_with_tolerate_dirty_a_file_outside_the_directory_during_the_mutation_exits_10(
    tree: Path, tmp_path: Path
) -> None:
    _tolerating_tree(tree)
    spec = _single_row_spec(tmp_path, "spec", "KILLED", launcher=_launcher(tmp_path))

    result = _ablate(
        _tolerating(spec, tree),
        tmp_path,
        {"ABLATION_TEST_LAUNCHER_MODE": "stray-before-snapshot"},
    )

    assert result.returncode == 10, result.stdout + result.stderr
    row_lines = [
        line for line in result.stdout.splitlines() if line.startswith("ST2-property-red:")
    ]
    assert len(row_lines) == 1 and row_lines[0].startswith("ST2-property-red: UNMEASURED -- ")
    assert (
        "git_dirty_during: ST2-property-red mutated: git status showed "
        "[' M sample.py', '?? stray.txt'] outside the tolerated directories ['logs'], "
        "expected [' M sample.py']"
    ) in row_lines[0]
    assert _porcelain(tree) == ""


def test_with_tolerate_dirty_git_that_cannot_read_the_tree_before_the_run_exits_5(
    tree: Path, tmp_path: Path
) -> None:
    _tolerating_tree(tree)
    (tree / ".git" / "index").write_bytes(b"not an index\n")
    spec = _single_row_spec(tmp_path, "spec", "KILLED")

    result = _ablate(_tolerating(spec, tree, "--skip-preflight"), tmp_path)

    assert result.returncode == 5, result.stdout + result.stderr
    assert _refusals(result.stderr) == [
        f"REFUSING: git cannot say whether {tree} is dirty before the run "
        "(git status --porcelain --untracked-files=normal): None"
    ]
    assert "[mutant]" not in result.stdout
    assert not (tree / JOURNAL_DIRNAME).exists()


def test_with_tolerate_dirty_git_that_cannot_read_the_tree_after_the_run_exits_6(
    tree: Path, tmp_path: Path
) -> None:
    _tolerating_tree(tree)
    spec = _single_row_spec(tmp_path, "spec", "KILLED", launcher=_launcher(tmp_path))

    result = _ablate(
        _tolerating(spec, tree), tmp_path, {"ABLATION_TEST_LAUNCHER_MODE": "break-index"}
    )

    assert result.returncode == 6, result.stdout + result.stderr
    assert _refusals(result.stderr) == [
        f"REFUSING: git cannot say whether {tree} is dirty after the run: None -- no verdict "
        "above can be trusted"
    ]
