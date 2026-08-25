"""Fixtures and builders for the reference-witness tests.

This is deliberately NOT a conftest.py. `bridge/tests/` and this directory
are both non-package test trees, so a second conftest.py here becomes a
second top-level module named `conftest` -- and the bridge's own
`from conftest import ...` then resolves to whichever of the two landed in
sys.modules first. Measured, not theorised: adding one broke nine bridge
test modules at collection. Importing fixtures from a uniquely named module
costs one import line per test file and cannot collide with anything.

Key material is REAL (no mocks): the witness signs with a genuine hybrid
pair and pinned logs are genuine hybrid pairs, because the core accepts
nothing fabricated. Generation is session-scoped -- ML-DSA-65 keygen is the
slowest thing in this suite by an order of magnitude.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from attest import anchor, keys, pq, tlog

WITNESS_NAME = "witness.example/w1"


@pytest.fixture(scope="session")
def witness_keys() -> pq.HybridSigningKeys:
    return pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())


@pytest.fixture(scope="session")
def log_keys() -> pq.HybridSigningKeys:
    return pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())


@pytest.fixture(scope="session")
def other_log_keys() -> pq.HybridSigningKeys:
    return pq.HybridSigningKeys(ed=keys.generate(), mldsa=pq.generate())


def write_key_files(directory: Path, signing_keys: pq.HybridSigningKeys) -> tuple[Path, Path]:
    """Write the on-disk shapes `attest keygen` produces, and return their paths."""
    seed_path = directory / "ed25519.seed"
    seed_path.write_text(keys.b64u(signing_keys.ed.seed), encoding="utf-8")
    mldsa_path = directory / "mldsa65.json"
    mldsa_path.write_text(
        json.dumps(
            {
                "alg": pq.ML_DSA_65_ALG,
                "sk": keys.b64u(signing_keys.mldsa.sk),
                "pub": keys.b64u(signing_keys.mldsa.pub),
            }
        ),
        encoding="utf-8",
    )
    return seed_path, mldsa_path


def log_table(origin: str, name: str, signing_keys: pq.HybridSigningKeys) -> dict[str, Any]:
    return {
        "origin": origin,
        "name": name,
        "ed25519_pub_b64u": keys.b64u(signing_keys.ed.pub),
        "mldsa_65_pub_b64u": keys.b64u(signing_keys.mldsa.pub),
    }


def render_toml(document: dict[str, Any]) -> str:
    """Minimal TOML writer for the shapes these tests build.

    Hand-rolled rather than pulled in as a dependency: the test config is a
    handful of string/int scalars plus an array of tables, and a real writer
    would be a runtime dependency of a package that must not grow any.
    """
    lines: list[str] = []
    for key, value in document.items():
        if isinstance(value, list):
            continue
        if isinstance(value, dict):
            lines.append(f"[{key}]")
            for sub_key, sub_value in value.items():
                lines.append(f"{sub_key} = {_scalar(sub_value)}")
            lines.append("")
    for key, value in document.items():
        if not isinstance(value, list):
            continue
        for entry in value:
            lines.append(f"[[{key}]]")
            for sub_key, sub_value in entry.items():
                lines.append(f"{sub_key} = {_scalar(sub_value)}")
            lines.append("")
    return "\n".join(lines)


def _scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(str(value))


def write_config(
    directory: Path,
    *,
    witness_signing_keys: pq.HybridSigningKeys,
    logs: list[dict[str, Any]],
    name: str = WITNESS_NAME,
    server: dict[str, Any] | None = None,
    seed_path: str | None = None,
    mldsa_key_path: str | None = None,
    database_path: str | None = None,
) -> Path:
    """Write key files plus a witness.toml into `directory`; return the config path."""
    written_seed, written_mldsa = write_key_files(directory, witness_signing_keys)
    document: dict[str, Any] = {
        "witness": {
            "name": name,
            "seed_path": seed_path if seed_path is not None else str(written_seed),
            "mldsa_key_path": (
                mldsa_key_path if mldsa_key_path is not None else str(written_mldsa)
            ),
        },
        "storage": {
            "database_path": (
                database_path if database_path is not None else str(directory / "state.sqlite3")
            ),
        },
        "server": server
        if server is not None
        else {
            "submission_prefix": "/witness/v0",
            "monitoring_prefix": "/witness/v0/monitoring",
        },
        "log": logs,
    }
    config_path = directory / "witness.toml"
    config_path.write_text(render_toml(document), encoding="utf-8")
    return config_path


def log_key_of(origin: str, name: str, signing_keys: pq.HybridSigningKeys) -> tlog.LogKey:
    return tlog.LogKey(
        origin=origin,
        name=name,
        ed25519_pub=signing_keys.ed.pub,
        mldsa_pub=signing_keys.mldsa.pub,
    )


# --- Checkpoint, policy and anchor builders ---------------------------------
#
# The anchor shape mirrors `tools/witness_parity_cases.py`: a `signed-note-v2`
# accumulator seeded from the WHOLE signed note (cosignature lines included),
# which is why an anchor has to be built AFTER the lines are appended.

HEADER_HASH = "3a" * 32
BOOTSTRAP_EPOCH = "bootstrap-1"
OPERATOR = "witness.example"


def signed_checkpoint(
    origin: str, tree_size: int, root: bytes, log_signing_keys: pq.HybridSigningKeys, name: str
) -> str:
    return tlog.sign_checkpoint(origin, tree_size, root, log_signing_keys, name)


def witness_pin(
    signing_keys: pq.HybridSigningKeys,
    *,
    name: str = WITNESS_NAME,
    roles: list[str] | None = None,
    with_pq: bool = False,
    operator: str = OPERATOR,
    control_group: str | None = None,
    not_before: str = "2020-01-01T00:00:00Z",
    not_after: str | None = None,
) -> dict[str, Any]:
    return {
        "operator_id": operator,
        "control_group": control_group if control_group is not None else operator,
        "name": name,
        "ed25519_pub_b64u": keys.b64u(signing_keys.ed.pub),
        "mldsa_65_pub_b64u": keys.b64u(signing_keys.mldsa.pub) if with_pq else None,
        "roles": sorted(roles if roles is not None else ["corroboration"]),
        "not_before": not_before,
        "not_after": not_after,
        "affiliated_domains": [operator],
    }


def witness_policy_document(
    pins: list[dict[str, Any]],
    *,
    epoch_id: str = BOOTSTRAP_EPOCH,
    threshold: tuple[int, int] = (1, 1),
    not_before: str = "2020-01-01T00:00:00Z",
    not_after: str | None = None,
    log_origins: list[str] | None = None,
) -> dict[str, Any]:
    """An epoch pinning `pins` for `log_origins`.

    `log_origins` is not decoration: the core is fail-closed on it — an epoch
    that does not list a checkpoint's origin corroborates nothing for it, so
    an empty list is a policy that pins nobody for anything.
    """
    return {
        "schema": "attest-witness-policy-v1",
        "epochs": [
            {
                "epoch_id": epoch_id,
                "not_before": not_before,
                "not_after": not_after,
                "log_origins": sorted(log_origins if log_origins is not None else ["log.example"]),
                "threshold": {"n": threshold[0], "m": threshold[1]},
                "witnesses": pins,
            }
        ],
    }


def anchor_for(text: str, header_time: int) -> dict[str, Any]:
    """A verifying OTS op-chain over this exact signed note, plus its trust store."""
    checkpoint = tlog.parse_checkpoint(text)
    sibling = bytes.fromhex("ab" * 32)
    prefix = bytes.fromhex("cd" * 16)
    accumulator = hashlib.sha256(checkpoint.signed_note_bytes).digest()
    accumulator = hashlib.sha256(accumulator + sibling).digest()
    accumulator = hashlib.sha256(prefix + accumulator).digest()
    root = accumulator.hex()
    return {
        "evidence": {
            "checkpoint": text,
            "anchor_profile": "signed-note-v2",
            "proofs": [
                {
                    "kind": "ots",
                    "ops": [
                        ["append", sibling.hex()],
                        ["sha256"],
                        ["prepend", prefix.hex()],
                        ["sha256"],
                    ],
                    "header_merkle_root": root,
                    "header_time": header_time,
                    "header_hash": HEADER_HASH,
                }
            ],
        },
        "policy": anchor.AnchorPolicy(
            pinned_headers={
                HEADER_HASH: anchor.PinnedHeader(
                    header_hash=HEADER_HASH, merkle_root=root, time=header_time
                )
            },
            crqc_horizon=None,
        ),
    }


class FakeLog:
    """A real RFC 6962 log with real hybrid keys — small, and entirely honest.

    Nothing here is a stub: leaves are hashed by the core, roots come from
    `tlog.build_tree`, consistency proofs from `tlog.consistency_proof`, and
    checkpoints are signed by `tlog.sign_checkpoint`. A witness tested against
    a fabricated log would only ever prove that our fabrication matches our
    expectation.

    `checkpoint_text` takes optional `tree_size`/`root` overrides so a test can
    sign a checkpoint the log could never have produced — a fork, a rollback,
    an empty tree with an invented root. Those are GENUINE signatures over
    dishonest contents, which is exactly the adversary a witness faces: the log
    holds its own keys.
    """

    def __init__(
        self, origin: str, signing_keys: pq.HybridSigningKeys, *, name: str | None = None
    ) -> None:
        self.origin = origin
        self.name = name if name is not None else origin
        self.signing_keys = signing_keys
        self.leaves: list[bytes] = []

    @property
    def log_key(self) -> tlog.LogKey:
        return tlog.LogKey(
            origin=self.origin,
            name=self.name,
            ed25519_pub=self.signing_keys.ed.pub,
            mldsa_pub=self.signing_keys.mldsa.pub,
        )

    def append(self, count: int, *, filler: bytes = b"") -> None:
        start = len(self.leaves)
        for index in range(start, start + count):
            self.leaves.append(filler + f"entry-{index}".encode())

    def fork(self, size: int) -> FakeLog:
        """A second log sharing this one's first `size` leaves and its keys."""
        branch = FakeLog(self.origin, self.signing_keys, name=self.name)
        branch.leaves = list(self.leaves[:size])
        return branch

    def root_at(self, size: int) -> bytes:
        return tlog.build_tree(self.leaves[:size])

    def checkpoint_text(self, *, tree_size: int | None = None, root: bytes | None = None) -> str:
        size = len(self.leaves) if tree_size is None else tree_size
        return tlog.sign_checkpoint(
            self.origin,
            size,
            self.root_at(size) if root is None else root,
            self.signing_keys,
            self.name,
        )

    def consistency_proof_from(self, size: int) -> list[bytes]:
        return tlog.consistency_proof(self.leaves, size)
