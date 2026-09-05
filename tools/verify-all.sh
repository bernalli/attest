#!/usr/bin/env bash
# Run locally, in one command, exactly what `ci.yml` and `pages.yml` run.
#
# WHY THIS EXISTS. The steps that break are the steps nobody types. Measured
# 2026-09-04 over the last ninety-nine runs of each workflow: `site` failed
# twelve times, `ci` once, and none of the twelve was flaky. They were the
# three things a developer never runs by hand — the two end-to-end suites,
# because they are slow, and the typecheck inside `npm run build --prefix
# site`, because `npm test` is the command people know and it is green while
# `tsc` is red. Until this script there was no single command that ran what CI
# runs: three npm roots with their own scripts, a Python project with its own,
# and no Makefile tying them together.
#
# WHAT IT GUARANTEES. Every `run:` line of both workflows appears here
# verbatim, in the order the jobs run them, with the same flags, under the same
# shell both workflows name (`bash --noprofile --norc -eo pipefail`) — and
# `tests/test_verify_all.py` fails if one of them stops being true. Steps that
# only provision a toolchain (downloading a prover, a scanner, a browser
# engine) are the exception: this script reports what is missing and prints the
# command, rather than installing software behind you.
#
# HOW IT REPORTS. No `set -e`: every step is timed, its outcome recorded, and a
# table printed at the end. Execution stops at the first failure — the steps
# after it are reported NOT RUN rather than silently dropped.
#
#   ./tools/verify-all.sh            everything this machine can run
#   ./tools/verify-all.sh --quick    same, minus the steps that need a
#                                    toolchain CI installs and a laptop
#                                    usually does not (Maude/Tamarin,
#                                    syft/grype/grant, the Internet-Draft
#                                    build); each one named as SKIPPED
#
# Exit status: 0 every step ran and passed; 1 a step failed; 2 nothing failed
# but something was skipped, so the tree is unverified rather than verified.
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

# browser_missing <npm root> <engine...> — echoes the engines whose Playwright
# build is absent. Checked instead of installed: `npx playwright install
# --with-deps` runs apt and pulls in over two hundred packages for WebKit
# alone, which is not something a verification command should do to a machine.
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

echo "${BOLD}verify-all${RESET} — $REPO_ROOT"
[ "$QUICK" -eq 1 ] && note "--quick: the externally-provisioned steps will be listed as SKIPPED."
for tool in uv node npm python3; do
  command -v "$tool" > /dev/null 2>&1 || {
    echo "verify-all: '$tool' is not on PATH; every workflow job needs it." >&2
    exit 64
  }
done

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
if [ "$QUICK" -eq 0 ] && command -v syft > /dev/null 2>&1; then SBOM_ENV_TOUCHED=1; fi
external ci.yml:supply-chain "syft" "uv sync --locked"
external ci.yml:supply-chain "syft" "syft dir:.venv -o cyclonedx-json=sbom-python.cdx.json"
external ci.yml:supply-chain "syft" "(cd verifiers/ts && npm ci --omit=dev)"
external ci.yml:supply-chain "syft" "syft dir:verifiers/ts -o cyclonedx-json=sbom-npm.cdx.json"
external ci.yml:supply-chain "grype" "grype sbom:sbom-python.cdx.json --fail-on high"
external ci.yml:supply-chain "grype" "grype sbom:sbom-npm.cdx.json --fail-on high"
external ci.yml:supply-chain "grant" "grant check -c .grant.yaml sbom-python.cdx.json"
external ci.yml:supply-chain "grant" "grant check -c .grant.yaml sbom-npm.cdx.json"
if [ "$SBOM_ENV_TOUCHED" -eq 1 ]; then
  run verify-all:restore - "uv sync --locked --extra dev --all-packages"
fi

# ------------------------------------------------------------- pages.yml: test
run pages.yml:test - "npm ci --prefix verifiers/ts"
run pages.yml:test - "npm run build --prefix verifiers/ts"
run pages.yml:test - "npm test --prefix verifiers/ts"
run pages.yml:test - "npm ci --prefix site"
run pages.yml:test - "npm test --prefix site"
# The typecheck lives inside this script, not inside `npm test`. Four failures
# in the site workflow were `tsc` red while `npm test` was green.
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
# desktop/playwright.config.ts adds WebKit only when CI is set, so CI is set
# here only when WebKit is actually installed. Running with CI=1 and no WebKit
# would turn a missing engine into a red suite; running without saying so would
# report three engines' worth of green earned by two.
DESKTOP_ABSENT="$(browser_missing desktop chromium firefox)"
WEBKIT_ABSENT="$(browser_missing desktop webkit)"
if [ -n "$DESKTOP_ABSENT" ]; then
  _skip pages.yml:desktop "npm run e2e --prefix desktop" \
    "Playwright engine absent:$DESKTOP_ABSENT — install with: npx playwright install --with-deps$DESKTOP_ABSENT"
elif [ -n "$WEBKIT_ABSENT" ]; then
  note "WebKit is not installed, so this run exercises chromium and firefox and CI stays unset."
  note "CI exercises three engines; to match it: npx playwright install --with-deps webkit"
  run pages.yml:desktop - "npm run e2e --prefix desktop"
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
external pages.yml:desktop "syft" "npm ci --omit=dev --prefix desktop"
external pages.yml:desktop "syft" "syft dir:desktop -o cyclonedx-json=sbom-desktop.cdx.json"
external pages.yml:desktop "grype" "grype sbom:sbom-desktop.cdx.json --fail-on high"
external pages.yml:desktop "grant" "grant check -c .grant.yaml sbom-desktop.cdx.json"
run pages.yml:desktop - "sha256sum desktop/dist/attest-verifier.html | tee desktop/dist/attest-verifier.html.sha256"

# ---------------------------------------------------------------- ci.yml: formal
# The shard list is read from ci.yml rather than copied: the lemma names are
# split across five shards whose union must equal the checker's contract, and a
# second copy here would be a second thing to keep in step.
while IFS="$(printf '\t')" read -r shard checker_timeout lemmas; do
  [ -z "${shard:-}" ] && continue
  external "ci.yml:formal($shard)" "maude tamarin-prover" \
    "python3 tools/check_formal.py formal/attest.spthy --only \"$lemmas\" --timeout $checker_timeout"
done < <(awk '
  $1 == "-" && $2 == "shard:" { shard = $3 }
  $1 == "checker_timeout:" { timeout = $2 }
  $1 == "lemmas:" {
    line = $0
    sub(/^[[:space:]]*lemmas:[[:space:]]*"/, "", line)
    sub(/"[[:space:]]*$/, "", line)
    print shard "\t" timeout "\t" line
  }
' .github/workflows/ci.yml)

# ---------------------------------------------------------------------- tidy up
# `uv build`, `npm pack` and syft leave artefacts in the tree. dist/ is ignored
# by git; these are not, and a verification command that leaves the working
# tree dirty gets typed once.
rm -f "$REPO_ROOT"/sbom-python.cdx.json "$REPO_ROOT"/sbom-npm.cdx.json "$REPO_ROOT"/sbom-desktop.cdx.json
rm -f "$REPO_ROOT"/verifiers/ts/*.tgz

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
