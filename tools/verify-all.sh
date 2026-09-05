#!/usr/bin/env bash
# Run locally, in one command, exactly what `ci.yml` and `pages.yml` run.
#
# WHY THIS EXISTS. The repository has separate Python, TypeScript, site and
# desktop verification commands. This script groups their workflow checks,
# including both end-to-end suites and the site build's typecheck.
# `site/package.json` runs `tsc --noEmit` in `build`; `test` runs Vitest.
#
# WHAT IT GUARANTEES, AND WHAT IT DOES NOT. Every `run:` line of both workflows
# appears here verbatim, in the order the jobs run them, with the same flags,
# under the same shell both workflows name (`bash --noprofile --norc -eo
# pipefail`). `tests/test_verify_all.py` runs this script against stubbed
# commands and compares seven things with the workflows: the command text with
# its flags, the job it is attributed to, how many times it runs there, the
# order within that job, the environment the step's own process receives, the
# shell each `run:` step resolves to, and the five proof shards the formal
# matrix expands into. The environment is compared in both directions, so a
# variable CI sets and this script does not is red, and so is one this script
# hands a step and CI never sets; it is read at workflow, job and step level,
# because a runner hands all three to the step.
#
# It does NOT check the directory a step runs in, and it does NOT refuse a step
# CI always runs being made conditional on a tool this machine may lack. That
# second one is reported as SKIPPED with exit 2 where the tool is absent, so it
# is stated rather than hidden — but the gate will not stop the change.
#
# Steps that only provision a toolchain (downloading a prover, a scanner, a
# browser engine) are the exception: this script reports what is missing and
# prints browser installation hints; it does not install those toolchains.
#
# HOW IT REPORTS. No `set -e`: every step is timed, its outcome recorded, and a
# table printed at the end. Execution stops at the first failure — the steps
# after it are reported NOT RUN rather than silently dropped. Environment
# restoration still runs and cannot erase an earlier failure.
#
#   ./tools/verify-all.sh            everything this machine can run
#   ./tools/verify-all.sh --quick    same, minus the steps that need a
#                                    toolchain CI installs and a laptop
#                                    usually does not (Maude/Tamarin,
#                                    syft/grype/grant, the Internet-Draft
#                                    build); each one named as SKIPPED
#
# Exit status: 0 every step ran and passed; 1 a step or restoration failed;
# 2 nothing failed but a step was SKIPPED or PARTIAL; 64 invalid invocation, a
# missing base tool, or a `ci.yml` whose formal shard matrix this script
# refuses to read. SKIPPED/PARTIAL means unverified, not verified.
# The third code matters: a skip inside a total of passes reads exactly like a
# step that ran, which is the defect this whole script exists to remove.

set -u -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

QUICK=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    -h | --help)
      awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "verify-all: unknown option '$arg' (try --help)" >&2
      exit 64
      ;;
  esac
done

# The Internet-Draft step names this variable, and GitHub sets it. Setting it
# here is what lets that step be copied across unchanged rather than rewritten.
RUNNER_TEMP="$(mktemp -d)"
export RUNNER_TEMP
trap 'rm -rf "$RUNNER_TEMP"' EXIT

BOLD=""
DIM=""
RESET=""
if [ -t 1 ]; then
  BOLD="$(printf '\033[1m')"
  DIM="$(printf '\033[2m')"
  RESET="$(printf '\033[0m')"
fi

ORIGINS=()
COMMANDS=()
OUTCOMES=()
MILLIS=()
NOTES=()
FAILED=0
SKIPPED=0
# A step that RAN, but not the way CI runs it. Neither a pass of what CI runs
# nor a step that did not run, and reporting it as either is the defect this
# script exists to remove.
PARTIAL=0
SBOM_ENV_TOUCHED=0

note() { printf '%s>> %s%s\n' "$DIM" "$1" "$RESET"; }

_record() {
  ORIGINS+=("$1")
  COMMANDS+=("$2")
  OUTCOMES+=("$3")
  MILLIS+=("$4")
  NOTES+=("$5")
}

_skip() {
  # origin, command, reason
  if [ "$FAILED" -ne 0 ]; then
    _record "$1" "$2" "NOT RUN" "0" "stopped at the first failure"
    return
  fi
  printf '%s--- SKIP %s%s  %s\n' "$DIM" "$1" "$RESET" "$2"
  printf '%s         %s%s\n' "$DIM" "$3" "$RESET"
  SKIPPED=$((SKIPPED + 1))
  _record "$1" "$2" "SKIPPED" "0" "$3"
}

# run <origin> <env-assignments|-> <command>
run() {
  local origin="$1" envs="$2" command="$3"
  if [ "$FAILED" -ne 0 ]; then
    _record "$origin" "$command" "NOT RUN" "0" "stopped at the first failure"
    return
  fi
  local shown="$command"
  [ "$envs" != "-" ] && shown="$envs $command"
  printf '\n%s=== %s%s  %s\n' "$BOLD" "$origin" "$RESET" "$shown"
  local start finish rc
  start="$(date +%s%N)"
  # The same shell both workflows name. `shell: bash` is
  # `bash --noprofile --norc -eo pipefail {0}`, and the flags that matter are
  # the last two: without pipefail a pipeline reports its LAST command only, so
  # a step that pipes would be green here on precisely the failure CI can now
  # see. tests/test_verify_all.py reads these flags back and proves it.
  if [ "$envs" = "-" ]; then
    bash --noprofile --norc -eo pipefail -c "$command"
  else
    env $envs bash --noprofile --norc -eo pipefail -c "$command"
  fi
  rc=$?
  finish="$(date +%s%N)"
  local ms=$(((finish - start) / 1000000))
  if [ "$rc" -eq 0 ]; then
    printf '%s--- OK   %s (%s ms)%s\n' "$DIM" "$origin" "$ms" "$RESET"
    _record "$origin" "$command" "OK" "$ms" ""
  else
    printf '\n*** FAILED %s (exit %s, %s ms)\n' "$origin" "$rc" "$ms"
    _record "$origin" "$command" "FAIL" "$ms" "exit $rc"
    FAILED=1
  fi
}

# external <origin> <tools> <command> — a step whose toolchain CI installs and
# this machine may not have. `--quick` skips it even when the tools are here.
external() {
  local origin="$1" tools="$2" command="$3"
  if [ "$QUICK" -eq 1 ]; then
    _skip "$origin" "$command" "--quick: skipped by request"
    return
  fi
  local missing=""
  for tool in $tools; do
    command -v "$tool" > /dev/null 2>&1 || missing="$missing $tool"
  done
  if [ -n "$missing" ]; then
    _skip "$origin" "$command" "not on PATH:$missing"
    return
  fi
  run "$origin" "-" "$command"
}

# Environment restoration must run even after a verification failure.
restore() {
  local previous_failed="$FAILED"
  FAILED=0
  run verify-all:restore - "$1"
  if [ "$previous_failed" -ne 0 ]; then FAILED="$previous_failed"; fi
}

# browser_missing <npm root> <engine...> — echoes the engines whose Playwright
# build is absent. Checked instead of installed: `npx playwright install
# --with-deps` is not invoked here. The probe below checks for the executable;
# a missing engine is reported with an installation hint.
browser_missing() {
  local root="$1"
  shift
  local absent=""
  for engine in "$@"; do
    if ! (cd "$REPO_ROOT/$root" && node -e '
      const fs = require("fs");
      try {
        const p = require("playwright-core")[process.argv[1]].executablePath();
        process.exit(fs.existsSync(p) ? 0 : 1);
      } catch (error) { process.exit(1); }
    ' "$engine" > /dev/null 2>&1); then
      absent="$absent $engine"
    fi
  done
  echo "$absent"
}

# The proof shards are READ out of ci.yml rather than copied here, so this
# reader is part of the gate rather than a convenience: a reader that returns
# nothing where the matrix declares five shards runs no proof and still reaches
# the OK line, which is the shape of failure this whole script exists to
# remove. So it admits one written-out shape and refuses everything else by
# name, with the line number, before any step runs — and zero entries is a
# refusal, never a success.
#
# Admitted, and nothing else: `jobs:` at column 0; at most one `formal:` job;
# inside it `strategy:`, `matrix:` and `include:`, each nested deeper than the
# one before; under `include:` a `- ` sequence whose entries carry `shard:`,
# `timeout:`, `checker_timeout:` and `lemmas:`, each exactly once, aligned two
# columns past the dash. A `lemmas:` key anywhere else is refused rather than
# folded into whichever entry was read last.
FORMAL_SHARDS=()
FORMAL_TIMEOUTS=()
FORMAL_LEMMAS=()
FORMAL_FIELD_SEP="$(printf '\037')"

formal_refuse() {
  echo "verify-all: .github/workflows/ci.yml: $1" >&2
  echo "verify-all: the shard matrix is the proof gate, so a matrix this script" \
    "cannot read is refused rather than skipped." >&2
  exit 64
}

read_formal_matrix() {
  local records status shard checker lemmas seen
  records="$(awk -v sep="$FORMAL_FIELD_SEP" '
    function refuse(why) {
      printf "verify-all: .github/workflows/ci.yml:%d: %s\n", NR, why > "/dev/stderr"
      refused = 1
      exit 1
    }
    function value(text,   found) {
      found = text
      sub(/^[^:]*:[[:space:]]*/, "", found)
      return found
    }
    function close_entry() {
      if (!open) return
      if (shard == "") refuse("a matrix entry with no shard: name")
      if (runner == "") refuse("matrix entry " shard " has no timeout:")
      if (checker == "") refuse("matrix entry " shard " has no checker_timeout:")
      if (lemmas == "") refuse("matrix entry " shard " has no lemmas:")
      print shard sep checker sep lemmas
      entries++
      open = 0
    }
    /^[[:space:]]*(#|$)/ { next }
    /\t/ { refuse("a tab in the indentation; this reader admits spaces only") }
    {
      match($0, /^ */)
      indent = RLENGTH
      text = substr($0, indent + 1)
      sub(/[[:space:]]+$/, "", text)

      if (in_include && indent <= at_include) { close_entry(); in_include = 0 }
      if (in_matrix && indent <= at_matrix) { in_matrix = 0 }
      if (in_strategy && indent <= at_strategy) { in_strategy = 0 }
      if (in_formal && indent <= at_formal) { in_formal = 0 }
      if (in_jobs && indent == 0) { in_jobs = 0 }

      if (!in_include && text ~ /^lemmas:/) {
        refuse("a lemmas: key outside jobs.formal.strategy.matrix.include")
      }
      if (indent == 0) {
        if (text == "jobs:") {
          if (jobs_seen++) refuse("a second top-level jobs: key")
          in_jobs = 1
        }
        next
      }
      if (!in_jobs) next
      if (!in_formal) {
        if (text == "formal:") {
          if (formal_seen++) refuse("a second formal: job")
          in_formal = 1
          at_formal = indent
        }
        next
      }
      if (!in_strategy) {
        if (text == "strategy:" && indent > at_formal) { in_strategy = 1; at_strategy = indent }
        next
      }
      if (!in_matrix) {
        if (text == "matrix:" && indent > at_strategy) { in_matrix = 1; at_matrix = indent }
        next
      }
      if (!in_include) {
        if (text == "include:" && indent > at_matrix) { in_include = 1; at_include = indent }
        next
      }
      if (substr(text, 1, 2) == "- ") {
        close_entry()
        open = 1
        shard = ""
        runner = ""
        checker = ""
        lemmas = ""
        at_entry = indent
        text = substr(text, 3)
        sub(/^ +/, "", text)
        indent = at_entry + 2
      } else if (!open) {
        refuse("a mapping under include: that is not a - sequence entry")
      } else if (indent != at_entry + 2) {
        refuse("a field at column " indent " where this entry has its fields at " at_entry + 2)
      }
      if (text ~ /^shard:/) {
        if (shard != "") refuse("a second shard: in one matrix entry")
        if (text !~ /^shard:[[:space:]]*[A-Za-z0-9][A-Za-z0-9._-]*$/) {
          refuse("a shard: that is not a bare name: " text)
        }
        shard = value(text)
      } else if (text ~ /^timeout:/) {
        if (runner != "") refuse("a second timeout: in one matrix entry")
        if (text !~ /^timeout:[[:space:]]*[0-9]+$/) {
          refuse("a timeout: that is not a whole number: " text)
        }
        runner = value(text)
      } else if (text ~ /^checker_timeout:/) {
        if (checker != "") refuse("a second checker_timeout: in one matrix entry")
        if (text !~ /^checker_timeout:[[:space:]]*[0-9]+$/) {
          refuse("a checker_timeout: that is not a whole number: " text)
        }
        checker = value(text)
      } else if (text ~ /^lemmas:/) {
        if (lemmas != "") refuse("a second lemmas: in one matrix entry")
        if (text !~ /^lemmas:[[:space:]]*"[A-Za-z0-9_]+(,[A-Za-z0-9_]+)*"$/) {
          refuse("a lemmas: that is not a quoted comma-separated list of names: " text)
        }
        lemmas = value(text)
        sub(/^"/, "", lemmas)
        sub(/"$/, "", lemmas)
      } else {
        refuse("a field this reader does not admit in a matrix entry: " text)
      }
    }
    END {
      if (refused) exit 1
      close_entry()
      if (refused) exit 1
      if (entries == 0) exit 3
    }
  ' .github/workflows/ci.yml)"
  status=$?
  # 3 is this reader saying it read the file and found no entries; awk uses 2
  # for a file it could not open, and the two must not read as one thing.
  if [ "$status" -eq 3 ]; then
    formal_refuse "no shard entries under jobs.formal.strategy.matrix.include"
  fi
  if [ "$status" -ne 0 ]; then
    formal_refuse "the shard matrix could not be read (reader exit $status)"
  fi
  if [ -z "$records" ]; then
    formal_refuse "the shard matrix reader returned nothing"
  fi
  while IFS="$FORMAL_FIELD_SEP" read -r shard checker lemmas; do
    case "$shard" in
      "" | *[!A-Za-z0-9._-]*) formal_refuse "shard name '$shard' is not a bare name" ;;
    esac
    case "$checker" in
      "" | *[!0-9]*) formal_refuse "shard $shard has a non-numeric checker_timeout '$checker'" ;;
    esac
    if [ "$checker" -lt 1 ] || [ "$checker" -gt 86400 ]; then
      formal_refuse "shard $shard has checker_timeout $checker outside 1..86400 seconds"
    fi
    case "$lemmas" in
      "" | *[!A-Za-z0-9_,]* | ,* | *, | *,,*)
        formal_refuse "shard $shard has a malformed lemma list '$lemmas'"
        ;;
    esac
    for seen in "${FORMAL_SHARDS[@]}"; do
      if [ "$seen" = "$shard" ]; then
        formal_refuse "shard name $shard appears twice in the matrix"
      fi
    done
    FORMAL_SHARDS+=("$shard")
    FORMAL_TIMEOUTS+=("$checker")
    FORMAL_LEMMAS+=("$lemmas")
  done <<< "$records"
  if [ "${#FORMAL_SHARDS[@]}" -eq 0 ]; then
    formal_refuse "no shard entries under jobs.formal.strategy.matrix.include"
  fi
}

echo "${BOLD}verify-all${RESET} — $REPO_ROOT"
[ "$QUICK" -eq 1 ] && note "--quick: the externally-provisioned steps will be listed as SKIPPED."
for tool in uv node npm python3; do
  command -v "$tool" > /dev/null 2>&1 || {
    echo "verify-all: required base tool '$tool' is not on PATH." >&2
    exit 64
  }
done
read_formal_matrix

# ---------------------------------------------------------------- ci.yml: python
run ci.yml:python - "npm ci --prefix verifiers/ts"
run ci.yml:python - "npm run build --prefix verifiers/ts"
run ci.yml:python - "npm ci --prefix site"
run ci.yml:python - "uv sync --locked --extra dev --all-packages"
run ci.yml:python "ATTEST_CI_REQUIRED=1" "uv run --frozen pytest -q"
run ci.yml:python - "uv run --frozen ruff check ."
run ci.yml:python - "uv run --frozen ruff format --check ."
run ci.yml:python - "uv run --frozen mypy --strict src bridge/src witness/src"
run ci.yml:python - "uv run --frozen python tools/check_spec_docs.py"
run ci.yml:python - "uv run --frozen python tools/gen_container_corpus.py --check"
run ci.yml:python - "uv run --frozen python tools/importer_differential.py"
run ci.yml:python - "uv run --frozen python tools/gen_vectors.py --check"
run ci.yml:python - "uv run --frozen python -m demo.store_dies"
run ci.yml:python - "uv run --frozen python -m demo.pledge_dies"
# uvx downloads the pinned xml2rfc on first use, so this one needs the network
# even though the build itself is offline (--no-network).
external ci.yml:python "uvx" \
  'cp ietf/draft-martinalli-open-purchase-receipts.xml "$RUNNER_TEMP/draft-martinalli-open-purchase-receipts-00.xml"'
external ci.yml:python "uvx" \
  'uvx --from xml2rfc==3.34.0 xml2rfc "$RUNNER_TEMP/draft-martinalli-open-purchase-receipts-00.xml" --text --path "$RUNNER_TEMP" --no-network'
external ci.yml:python "uvx" \
  'test -s "$RUNNER_TEMP/draft-martinalli-open-purchase-receipts-00.txt"'

# ---------------------------------------------------------- ci.yml: supply-chain
run ci.yml:supply-chain - "uv build"
run ci.yml:supply-chain - "uv run --frozen python tools/assert_artifacts.py --wheel dist/*.whl --sdist dist/*.tar.gz"
run ci.yml:supply-chain - "npm ci --prefix verifiers/ts"
run ci.yml:supply-chain - "npm run build --prefix verifiers/ts"
run ci.yml:supply-chain - "(cd verifiers/ts && npm pack --json > /tmp/pack.json)"
run ci.yml:supply-chain - "uv run --frozen python tools/assert_artifacts.py --npm-pack-json /tmp/pack.json"
run ci.yml:supply-chain - 'python3 tools/conformance_runner.py --adapter "node tools/conformance_adapter_ts.mjs {leaf}" --subset v0.2'
# The SBOM group strips both environments down to runtime dependencies, which
# is what CI measures and what a developer does not want left behind. It runs
# only when syft is here, and the restore below puts the dev toolchain back.
if [ "$FAILED" -eq 0 ] && [ "$QUICK" -eq 0 ] && command -v syft > /dev/null 2>&1; then
  SBOM_ENV_TOUCHED=1
fi
external ci.yml:supply-chain "syft" "uv sync --locked"
external ci.yml:supply-chain "syft" "syft dir:.venv -o cyclonedx-json=sbom-python.cdx.json"
external ci.yml:supply-chain "syft" "(cd verifiers/ts && npm ci --omit=dev)"
external ci.yml:supply-chain "syft" "syft dir:verifiers/ts -o cyclonedx-json=sbom-npm.cdx.json"
external ci.yml:supply-chain "grype" "grype sbom:sbom-python.cdx.json --fail-on high"
external ci.yml:supply-chain "grype" "grype sbom:sbom-npm.cdx.json --fail-on high"
external ci.yml:supply-chain "grant" "grant check -c .grant.yaml sbom-python.cdx.json"
external ci.yml:supply-chain "grant" "grant check -c .grant.yaml sbom-npm.cdx.json"
if [ "$SBOM_ENV_TOUCHED" -eq 1 ]; then
  restore "uv sync --locked --extra dev --all-packages"
  restore "npm ci --prefix verifiers/ts"
fi

# ------------------------------------------------------------- pages.yml: test
run pages.yml:test - "npm ci --prefix verifiers/ts"
run pages.yml:test - "npm run build --prefix verifiers/ts"
run pages.yml:test - "npm test --prefix verifiers/ts"
run pages.yml:test - "npm ci --prefix site"
run pages.yml:test - "npm test --prefix site"
# The typecheck runs here because `npm test` does not run it: site/package.json
# puts `tsc --noEmit` in `build`, and `test` is `vitest run` alone. So the site
# build includes a separate typecheck that `npm test` does not invoke.
run pages.yml:test - "npm run build --prefix site"
run pages.yml:test - "python3 tools/container_differential.py --count 500 --seed 20260902"
SITE_ABSENT="$(browser_missing site chromium)"
if [ -n "$SITE_ABSENT" ]; then
  _skip pages.yml:test "npm run e2e --prefix site" \
    "Playwright engine absent:$SITE_ABSENT — install with: npx playwright install --with-deps$SITE_ABSENT"
else
  run pages.yml:test "CI=1" "npm run e2e --prefix site"
fi

# ---------------------------------------------------------- pages.yml: desktop
run pages.yml:desktop - "npm ci --prefix verifiers/ts"
run pages.yml:desktop - "npm run build --prefix verifiers/ts"
run pages.yml:desktop - "npm ci --prefix site"
run pages.yml:desktop - "npm ci --prefix desktop"
run pages.yml:desktop - "npm run typecheck --prefix desktop"
run pages.yml:desktop - "npm test --prefix desktop"
run pages.yml:desktop - "npm run build --prefix desktop"
# desktop/playwright.config.ts adds WebKit only when CI is set, so CI is enabled
# here only when WebKit is actually installed and cleared otherwise. Running with CI=1 and no WebKit
# would turn a missing engine into a red suite; running without saying so would
# report three engines' worth of green earned by two.
DESKTOP_ABSENT="$(browser_missing desktop chromium firefox)"
WEBKIT_ABSENT="$(browser_missing desktop webkit)"
if [ -n "$DESKTOP_ABSENT" ]; then
  _skip pages.yml:desktop "npm run e2e --prefix desktop" \
    "Playwright engine absent:$DESKTOP_ABSENT — install with: npx playwright install --with-deps$DESKTOP_ABSENT"
elif [ -n "$WEBKIT_ABSENT" ]; then
  note "WebKit is not installed, so this run exercises chromium and firefox and CI is cleared."
  note "CI exercises three engines; to match it: npx playwright install --with-deps webkit"
  run pages.yml:desktop "CI=" "npm run e2e --prefix desktop"
  # Two engines where CI runs three. The step passed, so `run` recorded OK, and
  # an OK here would be counted in a total of passes and exit 0 — three engines'
  # worth of green earned by two, which the comment above says this branch
  # exists to avoid saying. Re-label the record it just wrote and count it, so
  # the exit code carries the difference instead of two stdout notes nobody
  # greps. A FAIL is left alone: it is already the stronger sentence.
  _last=$((${#OUTCOMES[@]} - 1))
  if [ "${OUTCOMES[$_last]}" = "OK" ]; then
    OUTCOMES[$_last]="PARTIAL"
    NOTES[$_last]="ran chromium and firefox; CI also runs webkit"
    PARTIAL=$((PARTIAL + 1))
  fi
  unset _last
else
  run pages.yml:desktop "CI=1" "npm run e2e --prefix desktop"
fi
DESKTOP_ENV_TOUCHED=0
if [ "$FAILED" -eq 0 ] && [ "$QUICK" -eq 0 ] && command -v syft > /dev/null 2>&1; then
  DESKTOP_ENV_TOUCHED=1
fi
external pages.yml:desktop "syft" "npm ci --omit=dev --prefix desktop"
external pages.yml:desktop "syft" "syft dir:desktop -o cyclonedx-json=sbom-desktop.cdx.json"
external pages.yml:desktop "grype" "grype sbom:sbom-desktop.cdx.json --fail-on high"
external pages.yml:desktop "grant" "grant check -c .grant.yaml sbom-desktop.cdx.json"
if [ "$DESKTOP_ENV_TOUCHED" -eq 1 ]; then
  restore "npm ci --prefix desktop"
fi
run pages.yml:desktop - "sha256sum desktop/dist/attest-verifier.html | tee desktop/dist/attest-verifier.html.sha256"

# ---------------------------------------------------------------- ci.yml: formal
# The shard list is read from ci.yml rather than copied: the lemma names are
# split across five shards whose union must equal the checker's contract, and a
# second copy here would be a second thing to keep in step. `read_formal_matrix`
# ran before the first step and refused the file if it could not read that list,
# so this loop either expands the entries it admitted or never runs at all.
for shard_index in "${!FORMAL_SHARDS[@]}"; do
  external "ci.yml:formal(${FORMAL_SHARDS[$shard_index]})" "maude tamarin-prover" \
    "python3 tools/check_formal.py formal/attest.spthy --only \"${FORMAL_LEMMAS[$shard_index]}\" --timeout ${FORMAL_TIMEOUTS[$shard_index]}"
done

# Build and scan artifacts remain available for inspection. They may predate
# this invocation, so verification must not delete them by filename or glob.

# ----------------------------------------------------------------------- report
echo
echo "${BOLD}summary${RESET}"
printf '%-8s %-28s %8s  %s\n' "RESULT" "ORIGIN" "MS" "STEP"
for i in "${!ORIGINS[@]}"; do
  printf '%-8s %-28s %8s  %s\n' "${OUTCOMES[$i]}" "${ORIGINS[$i]}" "${MILLIS[$i]}" "${COMMANDS[$i]}"
  [ -n "${NOTES[$i]}" ] && printf '%s         %s%s\n' "$DIM" "${NOTES[$i]}" "$RESET"
done

total_ms=0
for ms in "${MILLIS[@]}"; do total_ms=$((total_ms + ms)); done
echo
printf '%s steps, %s skipped, %s partial, %s ms total\n' \
  "${#ORIGINS[@]}" "$SKIPPED" "$PARTIAL" "$total_ms"

if [ "$FAILED" -ne 0 ]; then
  echo "${BOLD}FAIL${RESET} — a step CI runs failed here."
  exit 1
fi
if [ "$SKIPPED" -ne 0 ] || [ "$PARTIAL" -ne 0 ]; then
  echo "${BOLD}INCOMPLETE${RESET} — nothing failed, but $SKIPPED step(s) did not run and" \
    "$PARTIAL ran on less than CI runs them. See SKIPPED and PARTIAL above."
  exit 2
fi
echo "${BOLD}OK${RESET} — every step both workflows run passed here."
exit 0
