# Census of type errors in the verifier tests

Validation of the implementation; merge approval remains a separate review.
The base is `fix/verifiers-test-census`, verified before modifying the files:

```sh
git rev-parse HEAD fix/verifiers-test-census origin/fix/verifiers-test-census
```

```text
ff2198f038606abe1eb98f05f11b5a35ae59d880
ff2198f038606abe1eb98f05f11b5a35ae59d880
ff2198f038606abe1eb98f05f11b5a35ae59d880
```

## Contract

`tools/check_verifier_test_types.py` runs the probe and compares the result with
`tools/verifier-test-types-census.json`. From the earlier `check_test_census.py` it reuses
the discovery of tests on disk, the strict JSON admission and the reading/writing of the
`suites -> verifiers/ts -> total, files` format. It also records files without
errors. Per-file and total counts must match in both directions: a decrease
names the file and requires `--update` just as an increase requires a fix.

The choice not to pin the codes is also justified in the docstring: it keeps the
format of the earlier tool and allows diagnostics to be reclassified without
mistaking that for a change in the debt. The limit is explicit: replacing one
diagnostic with another in the same file, keeping its count, is outside
coverage. A compensation across different files, on the other hand, fails.

The marker `MEASURED: ... test file(s) compiled by the verifier probe` comes from
`--listFiles` in the same run that produces the diagnostics. It does not come from the
census or from the number of errors. `--update` compares disk and compilation before
writing: complete new files are admitted, a file that is present but not compiled
prevents the update. An intentional deletion from disk can be
recorded explicitly, as in the earlier tool.

| Exit | Meaning |
| --- | --- |
| `0` | Census matches, complete update succeeded, or selftest passed. |
| `1` | Difference from the census, census missing/invalid, update refused, or selftest failed. |
| `2` | Measurement impossible: empty/unreadable output, process cannot be started, timeout, inconsistent state, no test compiled, or diagnostics outside the perimeter. argparse also uses this exit for invalid arguments. |
| `78` | Missing precondition: `node_modules`, `tsc` or `node` on the PATH. |

The committed pin is admitted before the preconditions: deleting it remains a
census violation. An executable that is present but cannot be started is an impossible
measurement, distinct from a missing executable. No unmeasured case prints
a success; when the list returns only sources, the marker shows
that no test file was compiled and the command fails.

The normal command occupies the line immediately after the verifier
build in the `test` job of `pages.yml`; `--selftest` follows. Both
invocations are replicated in the same job of `tools/verify-all.sh`.

## Initial measurement and green

The dependencies were installed from the lockfile with:

```sh
npm ci --prefix verifiers/ts --cache /tmp/attest-type-census-npm-cache --no-audit --no-fund --fetch-retries=0
```

Before writing code the requested command was run, collected through
`subprocess.run` to count the lines and the per-code sum separately:

```sh
python3 - <<'PYBASE'
import collections, re, subprocess
result = subprocess.run(['./verifiers/ts/node_modules/.bin/tsc', '-p', 'verifiers/ts/tsconfig.t3b-probe.json'], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
print('$ ./verifiers/ts/node_modules/.bin/tsc -p verifiers/ts/tsconfig.t3b-probe.json')
print(f'rc: {result.returncode}')
lines = [line for line in result.stdout.splitlines() if 'error TS' in line]
codes = collections.Counter(re.search(r'error (TS\d+)', line).group(1) for line in lines)
print(f'lines containing error TS: {len(lines)}')
for code, count in sorted(codes.items()):
    print(f'{code}: {count}')
print(f'sum by code: {sum(codes.values())}')
print(result.stdout)
PYBASE
```

Excerpt of the output, before the individual diagnostics:

```text
$ ./verifiers/ts/node_modules/.bin/tsc -p verifiers/ts/tsconfig.t3b-probe.json
rc: 2
lines containing error TS: 57
TS2322: 15
TS2345: 21
TS2532: 8
TS2740: 13
sum by code: 57
```

A further count on the same probe with the compilation list:

```sh
./verifiers/ts/node_modules/.bin/tsc -p verifiers/ts/tsconfig.t3b-probe.json --listFiles --pretty false --noEmit --incremental false > /tmp/attest-type-census-baseline.txt
rg -c 'error TS' /tmp/attest-type-census-baseline.txt
```

```text
57
```

Creation of the pin and verification; the latter was repeated on the tree
restored after the injections:

```sh
python3 tools/check_verifier_test_types.py --update
python3 tools/check_verifier_test_types.py
```

```text
MEASURED: 55 test file(s) compiled by the verifier probe
census updated for verifiers/ts: 55 file(s), 57 diagnostic(s)
MEASURED: 55 test file(s) compiled by the verifier probe
verifiers/ts: 57 diagnostic(s) -- matches the census
```

## Required reds, executed

The following commands use the program given in the reproduction section.
Each injection into the tests starts from a backup copy and restores it in `finally`,
verifying that the bytes are identical. The program also measures the raw probe and
compares the diagnostic headers before and after: exactly one error added
or removed, with compilation still working. It does not use `git checkout`.

### R1: one diagnostic added

Appended to the end of `verifiers/ts/test/canon-parse.test.ts`:
`const typeCensusRegression: string = 1;`.

```sh
python3 /tmp/attest-type-census-evidence/red_checks.py R1
```

```text
$ python3 tools/check_verifier_test_types.py
MEASURED: 55 test file(s) compiled by the verifier probe
verifiers/ts: test/canon-parse.test.ts: diagnostics increased to 2, the census records 1 (regression).
verifiers/ts: total diagnostics 58, the census records 57; an intended change requires --update.
gate rc: 1
$ ./verifiers/ts/node_modules/.bin/tsc -p verifiers/ts/tsconfig.t3b-probe.json
probe rc: 2
probe diagnostic headers: 58
added: verifiers/ts/test/canon-parse.test.ts(55,7): error TS2322: Type 'number' is not assignable to type 'string'.
restored from backup: byte-identical
```

### R2: one diagnostic removed

Temporary replacement of `expect(v['t'].length).toBe(5)` with
`expect(v['t']?.length).toBe(5)`: guarded access to the possibly absent value,
with the same test expectation. The removed diagnostic is named in the output.

```sh
python3 /tmp/attest-type-census-evidence/red_checks.py R2
```

```text
$ python3 tools/check_verifier_test_types.py
MEASURED: 55 test file(s) compiled by the verifier probe
verifiers/ts: test/canon-parse.test.ts: diagnostics decreased to 0, the census records 1; update the census with --update.
verifiers/ts: total diagnostics 56, the census records 57; an intended change requires --update.
gate rc: 1
$ ./verifiers/ts/node_modules/.bin/tsc -p verifiers/ts/tsconfig.t3b-probe.json
probe rc: 2
probe diagnostic headers: 56
removed: verifiers/ts/test/canon-parse.test.ts(31,12): error TS2532: Object is possibly 'undefined'.
restored from backup: byte-identical
```

### R3: missing precondition

The alternative `tsc` path is verified to be absent before the invocation.

```sh
python3 /tmp/attest-type-census-evidence/red_checks.py R3
```

```text
$ python3 tools/check_verifier_test_types.py --tsc /tmp/attest-type-census-evidence/missing-tsc
unable to measure: missing prerequisite tsc executable: /tmp/attest-type-census-evidence/missing-tsc; install Node.js and run npm ci --prefix verifiers/ts
gate rc: 78
```

### Update refused on a real absence

The probe temporarily excludes `test/dates.test.ts`, a test without diagnostics.
The file stays on disk. The update uses a copy of the census and verifies its
bytes after the refusal; the tsconfig is restored from its backup copy.

```sh
python3 /tmp/attest-type-census-evidence/update_absence.py
```

```text
$ python3 tools/check_verifier_test_types.py --census /tmp/attest-type-census-evidence/update-census.json --update
MEASURED: 54 test file(s) compiled by the verifier probe
refusing to update the census:
verifiers/ts: test/dates.test.ts is on disk but was NOT compiled by the probe.
gate rc: 1
census bytes changed: False
probe config restored from backup: byte-identical
```

## Selftest and single disablements

```sh
python3 tools/check_verifier_test_types.py --selftest
```

```text
  ok   healthy input, including a clean compiled file, reports nothing
  ok   no test files compiled -> named ('unable to measure: no test files compiled')
  ok   disk file absent even during update -> named ('test/b.test.ts is on disk but was NOT compiled')
  ok   compiled file absent from disk -> named ('compiled test test/b.test.ts is not on disk')
  ok   pinned clean file deleted -> named ('census file test/b.test.ts was not compiled')
  ok   new clean file unregistered -> named ('compiled test test/c.test.ts is not in the census')
  ok   diagnostic increase -> named ('test/a.test.ts: diagnostics increased to 4')
  ok   diagnostic decrease requires update -> named ('test/a.test.ts: diagnostics decreased to 2, the census records 3; update the census with --update')
  ok   per-file drift despite unchanged total -> named ('test/b.test.ts: diagnostics increased to 1')
  ok   total drift -> named ('total diagnostics 4, the census records 3')
selftest: 10/10
```

The following check recompiles the real `compare` function in memory, removing
only the named property each time. The remaining comparisons and the selftest
stay the originals. Each replacement must find exactly one spot in the source;
a syntax error does not count as a caught defect. The test requires that
the summary loses named cases, even if other checks still make
the same input fail. No disablement switch is exposed by the gate.

```sh
.venv/bin/pytest -q -s tests/tools/test_verifier_test_types.py -k selftest_loses_cases
```

```text
disabled nonempty: selftest: 10/10 -> selftest: 9/10; exit 1
.disabled disk-presence: selftest: 10/10 -> selftest: 9/10; exit 1
.disabled compiled-on-disk: selftest: 10/10 -> selftest: 9/10; exit 1
.disabled pinned-file: selftest: 10/10 -> selftest: 9/10; exit 1
.disabled registered-file: selftest: 10/10 -> selftest: 9/10; exit 1
.disabled increase: selftest: 10/10 -> selftest: 8/10; exit 1
.disabled decrease: selftest: 10/10 -> selftest: 9/10; exit 1
.disabled total: selftest: 10/10 -> selftest: 9/10; exit 1
.
8 passed, 26 deselected in 0.23s
```

## Other checks run

Preparation of the Python environment from the lockfile:

```sh
UV_CACHE_DIR=/tmp/attest-type-census-uv-cache uv sync --locked --extra dev --all-packages
```

```sh
.venv/bin/pytest -q tests/tools/test_verifier_test_types.py tests/tools/test_test_census.py tests/test_verify_all.py
```

Verbatim summary:

```text
284 passed, 50 skipped in 6.54s
```

The skips come from the `provisioning` exclusions expected in
`tests/test_verify_all.py`; the parity tests for the commands that were run pass.
The new tests also exercise output admission, preconditions, update
in both directions, refusal without writing, and actual use of the pin in the caller.

```sh
npm run build --prefix verifiers/ts
```

```text
> attest-verifier@0.9.6 build
> tsc -p tsconfig.json
```

```sh
npm test --prefix verifiers/ts -- --reporter=default --reporter=json --outputFile.json=/tmp/attest-type-census-evidence/verifier-tests.json
python3 tools/check_test_census.py verifiers/ts --report /tmp/attest-type-census-evidence/verifier-tests.json
```

Suite summary and output of the earlier census:

```text
 Test Files  55 passed (55)
      Tests  2244 passed (2244)
verifiers/ts: 55 test file(s), 2244 test(s) -- matches the census
```

```sh
.venv/bin/ruff check .
.venv/bin/ruff format --check .
bash -n tools/verify-all.sh
git diff --check
git diff --exit-code -- verifiers/ts/test
```

```text
All checks passed!
232 files already formatted
```

The last commands produce no output and succeed. The TypeScript tests are
restored; no permanent fix of the debt is part of the change.

## What I know that is not written elsewhere

- The first installation in the sandbox failed with DNS `EAI_AGAIN`; the
  Python download also hit the blocked DNS. The installations from the lockfiles
  succeeded with network access. It was not a red result of the product.
- TypeScript's indented lines explain the preceding diagnostic: counting them
  as errors would inflate the pin. The parser admits these continuations only after
  a valid header, forces output without colours and rejects unknown lines.
- The compilation list includes libraries, sources and helpers. The marker
  selects the real test names with the same rule as the Vitest census;
  diagnostics on helpers or sources are not ignored or absorbed into the test
  debt, but prevent accepting the measurement or updating the pin.
- An excluded healthy test does not change the number of errors. The update check
  uses exactly this case to prevent the comparison of totals from hiding a
  hole in the presence check.
- Vitest's JSON report appears at the end of the run. A first, premature local
  read found the file still absent; the read after completion
  succeeded. The CI and local wiring keeps the sequential order.
- The synthetic disablement cases keep the inputs of the comparison;
  they look for the specific message of the removed property. Settling for
  any red would let a mutilated guard pass, because the total can
  still notice a change that the per-file comparison no longer names.

## Reproducing the real checks

From the repository root, with dependencies installed, prepare the following programs.
Pre-existing backups are refused so as not to overwrite an earlier copy.
The expectations are those of the base given at the top.

```sh
mkdir -p /tmp/attest-type-census-evidence
cat > /tmp/attest-type-census-evidence/red_checks.py <<'PY'
from collections import Counter
from pathlib import Path
import shutil
import subprocess
import sys

label = sys.argv[1]
evidence = Path('/tmp/attest-type-census-evidence')
target = Path('verifiers/ts/test/canon-parse.test.ts')
backup = evidence / f'{label}-canon-parse.test.ts.backup'
gate = ['python3', 'tools/check_verifier_test_types.py']
probe = ['./verifiers/ts/node_modules/.bin/tsc', '-p',
         'verifiers/ts/tsconfig.t3b-probe.json']

def execute(command):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    return result

def headers(text):
    return Counter(line for line in text.splitlines() if 'error TS' in line)

if label == 'R3':
    missing = evidence / 'missing-tsc'
    assert not missing.exists()
    command = [*gate, '--tsc', str(missing)]
    print('$ ' + ' '.join(command), flush=True)
    result = execute(command)
    print(result.stdout, end='')
    print(f'gate rc: {result.returncode}')
    assert result.returncode == 78 and 'missing prerequisite' in result.stdout
    sys.exit(0)

assert label in ('R1', 'R2') and not backup.exists()
shutil.copy2(target, backup)
baseline = execute(probe)
assert baseline.returncode == 2 and sum(headers(baseline.stdout).values()) == 57
try:
    original = target.read_text()
    if label == 'R1':
        target.write_text(original + '\nconst typeCensusRegression: string = 1;\n')
    else:
        old = "expect(v['t'].length).toBe(5)"
        assert original.count(old) == 1
        target.write_text(original.replace(old, "expect(v['t']?.length).toBe(5)"))
    print('$ ' + ' '.join(gate), flush=True)
    result = execute(gate)
    print(result.stdout, end='')
    print(f'gate rc: {result.returncode}')
    raw = execute(probe)
    print('$ ' + ' '.join(probe))
    print(f'probe rc: {raw.returncode}')
    before, after = headers(baseline.stdout), headers(raw.stdout)
    print(f'probe diagnostic headers: {sum(after.values())}')
    for line in (after - before).elements():
        print('added: ' + line)
    for line in (before - after).elements():
        print('removed: ' + line)
    assert result.returncode == 1 and target.name in result.stdout
    assert raw.returncode == 2
    assert sum(after.values()) == (58 if label == 'R1' else 56)
    assert sum((after - before).values()) == (1 if label == 'R1' else 0)
    assert sum((before - after).values()) == (0 if label == 'R1' else 1)
    if label == 'R2':
        assert '--update' in result.stdout
finally:
    shutil.copy2(backup, target)
    assert target.read_bytes() == backup.read_bytes()
    print('restored from backup: byte-identical')
PY
cat > /tmp/attest-type-census-evidence/update_absence.py <<'PY'
from pathlib import Path
import shutil
import subprocess

config = Path('verifiers/ts/tsconfig.t3b-probe.json')
evidence = Path('/tmp/attest-type-census-evidence')
backup = evidence / 'probe-config.backup'
pin = evidence / 'update-census.json'
assert not backup.exists()
shutil.copy2(config, backup)
shutil.copy2('tools/verifier-test-types-census.json', pin)
before = pin.read_bytes()
try:
    text = config.read_text()
    assert text.count('  "include":') == 1
    config.write_text(text.replace('  "include":', '  "exclude": ["test/dates.test.ts"],\n  "include":'))
    command = ['python3', 'tools/check_verifier_test_types.py', '--census', str(pin), '--update']
    print('$ ' + ' '.join(command), flush=True)
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end='')
    print(f'gate rc: {result.returncode}')
    print(f'census bytes changed: {pin.read_bytes() != before}')
    assert result.returncode == 1
    assert 'MEASURED: 54 test file(s)' in result.stdout
    assert 'test/dates.test.ts is on disk but was NOT compiled' in result.stdout
    assert pin.read_bytes() == before
finally:
    shutil.copy2(backup, config)
    assert config.read_bytes() == backup.read_bytes()
    print('probe config restored from backup: byte-identical')
PY
```
