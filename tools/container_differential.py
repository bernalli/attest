#!/usr/bin/env python3
"""Feed the same archives to both container readers and compare their verdicts.

The corpus is a closed list, and the two readers were written by the same hand
against the same specification: they can share a mistake as easily as they share
a step number. This runner is the measurement that catches that — it generates
archives nobody chose, asks both implementations what they hold, and stops on
the first disagreement, keeping the file that produced it.

A disagreement here is precisely the defect this whole exercise exists to close:
same bytes, two conforming verifiers, two different answers.

    python3 tools/container_differential.py --count 2000 --seed 20260902
    python3 tools/container_differential.py --count 50 --keep /tmp/divergences

Stdlib plus `attest.container` (stdlib-only) plus `tools.gen_container_corpus`;
the TypeScript side is bundled with the site's own esbuild and driven through
`tools/container_adapter_ts.mjs`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from attest import container  # noqa: E402
from tools import gen_container_corpus as gen  # noqa: E402

ESBUILD = REPO_ROOT / "site" / "node_modules" / ".bin" / "esbuild"
CONTAINER_TS = REPO_ROOT / "site" / "src" / "container.ts"
ADAPTER = REPO_ROOT / "tools" / "container_adapter_ts.mjs"

DEFAULT_CAPS = {
    "maxEntries": 10_000,
    "maxMemberBytes": 64 * 1024 * 1024,
    "maxTotalBytes": 256 * 1024 * 1024,
}
#: Small caps for half the archives: the fuzzer writes small files, so the four
#: cap codes would never fire under the production numbers and the two readers
#: would agree about them by never reaching them.
TIGHT_CAPS = {"maxEntries": 8, "maxMemberBytes": 512, "maxTotalBytes": 2048}


def python_verdict(raw: bytes, caps: dict[str, int]) -> dict[str, Any]:
    try:
        members = container.canonical_members(
            raw,
            max_entries=caps["maxEntries"],
            max_member_bytes=caps["maxMemberBytes"],
            max_total_bytes=caps["maxTotalBytes"],
        )
        budget = container.ReadBudget(caps["maxMemberBytes"], caps["maxTotalBytes"])
        read = []
        for member in members:
            data = container.read_member(raw, member, budget)
            read.append(
                {
                    "name": member.name,
                    "method": member.method,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
    except container.ContainerError as error:
        return {"verdict": "reject", "code": error.code, "member": error.member}
    return {"verdict": "accept", "members": read}


def build_ts_bundle(out_dir: Path) -> Path:
    if not ESBUILD.exists():
        raise SystemExit(
            f"missing {ESBUILD} — run `npm ci --prefix site` before the differential gate"
        )
    bundle = out_dir / "container.mjs"
    subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        [
            str(ESBUILD),
            str(CONTAINER_TS),
            "--bundle",
            "--format=esm",
            "--platform=node",
            f"--outfile={bundle}",
        ],
        check=True,
        capture_output=True,
        cwd=REPO_ROOT,
    )
    return bundle


def ts_verdicts(bundle: Path, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    payload = "".join(json.dumps(request) + "\n" for request in requests)
    result = subprocess.run(  # noqa: S603 -- fixed argv list, no shell
        ["node", str(ADAPTER), str(bundle)],  # noqa: S607 -- node resolved from PATH, as every other node call in this repo
        input=payload,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    if result.returncode != 0:
        raise SystemExit(f"the TypeScript adapter failed:\n{result.stderr}")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != len(requests):
        raise SystemExit(f"expected {len(requests)} verdicts, got {len(lines)}")
    return [json.loads(line) for line in lines]


def run(count: int, seed: int, keep: Path | None) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        archives = work / "archives"
        gen.write_fuzz(archives, count, seed)
        paths = sorted(archives.glob("*.zip"))
        bundle = build_ts_bundle(work)

        requests = []
        for index, path in enumerate(paths):
            requests.append({"path": str(path), "caps": DEFAULT_CAPS if index % 2 else TIGHT_CAPS})
        ts = ts_verdicts(bundle, requests)

        divergences = 0
        accepted = 0
        codes: dict[str, int] = {}
        for request, ts_result in zip(requests, ts, strict=True):
            path = Path(request["path"])
            py_result = python_verdict(path.read_bytes(), request["caps"])
            if py_result["verdict"] == "accept":
                accepted += 1
            else:
                codes[py_result["code"]] = codes.get(py_result["code"], 0) + 1
            if py_result != ts_result:
                divergences += 1
                destination = keep or Path(tempfile.mkdtemp(prefix="container-divergence-"))
                destination.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, destination / path.name)
                (destination / f"{path.stem}.json").write_text(
                    json.dumps(
                        {"caps": request["caps"], "python": py_result, "typescript": ts_result},
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                print(
                    f"DIVERGENCE on {path.name} (kept in {destination}):\n"
                    f"  python:     {py_result}\n"
                    f"  typescript: {ts_result}",
                    file=sys.stderr,
                )

    print(
        f"{len(paths)} archives, {accepted} accepted, {len(paths) - accepted} refused, "
        f"{len(codes)} distinct codes, {divergences} divergences"
    )
    print("codes: " + ", ".join(f"{code}={n}" for code, n in sorted(codes.items())))
    return 1 if divergences else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20260902)
    parser.add_argument("--keep", type=Path, default=None)
    args = parser.parse_args(argv)
    return run(args.count, args.seed, args.keep)


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
