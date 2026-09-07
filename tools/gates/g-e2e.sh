#!/usr/bin/env bash
# G-E2E <site|desktop>: the named tree's Playwright suite runs under CI=1 and reports more
# than zero tests passed.
#
# "more than zero" is the property, not "N passed" for whatever N happens to print: a run
# that collects nothing and launches nothing still prints a summary line, and a bare
# `grep -q ' passed'` would call that green. The count is read from Playwright's own summary
# and compared to zero at runtime — never written down, because the number of e2e scenarios
# is exactly the kind of figure that goes stale the moment someone adds one.
#
# The precondition this gate exists to keep out of the red/green verdict: Playwright browsers
# are versioned build IDs (chromium-1234, webkit-2336, ...) pinned by the exact @playwright/
# test release each tree's node_modules resolves to, and the two trees here pin different
# releases (measured 2026-09-07: site -> 1.61.1, desktop -> 1.62.1), so their webkit build ID
# differs even though package.json's semver range is identical. A missing browser is not a
# product defect: on this tree, before webkit-2336 existed in the cache, `CI=1 npm run e2e`
# on desktop produced exactly 35 failures, all `[webkit] ...`, all
# "browserType.launch: Executable doesn't exist at .../webkit-2336/pw_run.sh" — a gate that
# reported those as red would be measuring a download that never happened, not the code
# (D-G1c). So every browser type the suite is about to launch is checked BEFORE launching,
# and its build ID is derived from `playwright install --dry-run`'s own output on THIS tree's
# THIS node_modules, right now — never a version pinned in this script, which would drift the
# next time either tree's package-lock.json moves.
#
# Which browser TYPES each suite launches is read from its own playwright.config.ts, current
# as of this gate's writing: site declares no `projects`, so Playwright runs its one implicit
# project on the default browser, chromium, only. desktop declares `projects: [chromium,
# firefox, ...(CI ? [webkit] : [])]` (desktop/playwright.config.ts) — webkit only under CI,
# which is exactly the invocation this gate always uses (CI=1), so desktop's precondition
# always includes webkit.
#
# npm ci is a precondition (installs state), not this gate's job: gate_need, 78 if absent.
# `playwright install <browser>` is the same kind of precondition and is likewise never run
# here — this gate only reports what to run.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_TREE="${GATE_TREE:-<tree>}"

SUITE="${1:-}"
case "$SUITE" in
  site) GATE_ID="G-E2E-SITE"; BROWSER_TYPES=(chromium) ;;
  desktop) GATE_ID="G-E2E-DESKTOP"; BROWSER_TYPES=(chromium firefox webkit) ;;
  *)
    echo "usage: g-e2e.sh <site|desktop>" >&2
    exit 2
    ;;
esac
export GATE_ID GATE_TREE

# shellcheck source=./_lib.sh
source "$HERE/_lib.sh"

SUITE_DIR="$GATE_TREE/$SUITE"
TRANSCRIPTS="$HERE/transcripts"
mkdir -p "$TRANSCRIPTS"
TAG="$(date -u +%Y%m%dT%H%M%SZ)"
PW_CACHE="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"

gate_head
gate_say "suite: $SUITE"
gate_say "browser types this suite launches under CI=1 (from $SUITE/playwright.config.ts): ${BROWSER_TYPES[*]}"

# The BUILD ID of each browser is derived at run time -- that is the part that
# matters and it is done below. The SET of browsers above is enumerated, and an
# enumeration is exempt by construction from whatever is added after it (C-222):
# if this suite's config acquired a browser not listed here, the gate would launch
# it without checking its precondition and report "executable doesn't exist" as a
# RED OF THE PRODUCT -- the exact lie the 78 exists to prevent.
#
# Deriving the set properly means reading the config's `projects`, which is a
# design choice about HOW to derive it. Until that is made, the enumeration stops
# being silent: the config is read now, and any browser name in it that this gate
# does not know about stops the gate by name. The exemption stays enumerated; it
# no longer hides.
PW_CONFIG="$SUITE_DIR/playwright.config.ts"
if [ -r "$PW_CONFIG" ]; then
  for known in chromium firefox webkit; do
    if grep -qE "(^|[^a-zA-Z])$known([^a-zA-Z]|$)" "$PW_CONFIG"; then
      case " ${BROWSER_TYPES[*]} " in
        *" $known "*) ;;
        *)
          gate_say "PRECONDITION MISSING: $SUITE/playwright.config.ts names the browser"
          gate_say "  '$known', which this gate's enumeration for '$SUITE' does not include."
          gate_say "  Launching it unchecked would report a missing executable as a product failure."
          gate_say "GATE $GATE_ID SKIPPED precondition=enumeration-stale"
          exit 78
          ;;
      esac
    fi
  done
fi
gate_say ""

gate_need "$SUITE/node_modules present (run: npm ci --prefix $SUITE_DIR)" -- test -d "$SUITE_DIR/node_modules"
gate_need "npm available" -- command -v npm

# --- Precondition: every browser type this run will launch is installed, checked BEFORE
# launching. The build ID comes from this tree's own playwright package, derived now. ------
DRYRUN_LOG="$TRANSCRIPTS/${TAG}-e2e-${SUITE}.install-dry-run.log"
npx --prefix "$SUITE_DIR" playwright install --dry-run > "$DRYRUN_LOG" 2>&1
DRYRUN_RC=$?
gate_say "--- playwright install --dry-run ($SUITE), to read the pinned build IDs off"
cat "$DRYRUN_LOG"
gate_say "exit: $DRYRUN_RC"
gate_need "playwright install --dry-run ($SUITE) ran (its own manifest is how build IDs are read, not a version pinned in this script)" -- \
  test "$DRYRUN_RC" -eq 0

for bt in "${BROWSER_TYPES[@]}"; do
  bid="$(grep -oP "\(playwright $bt v\K[0-9]+" "$DRYRUN_LOG" | head -1)"
  gate_need "playwright install --dry-run ($SUITE) named a build id for $bt" -- test -n "$bid"
  bdir="$PW_CACHE/${bt}-${bid}"
  gate_say "checking: $bdir/INSTALLATION_COMPLETE"
  gate_say "if missing, install with: npx --prefix $SUITE_DIR playwright install $bt"
  gate_need "$bt (build $bid) is installed for $SUITE" -- test -f "$bdir/INSTALLATION_COMPLETE"
done

# --- Property: the suite runs under CI=1 and reports more than zero passed -----------------
LOG="$TRANSCRIPTS/${TAG}-e2e-${SUITE}.log"
gate_run "CI=1 npm run e2e ($SUITE)" -- env CI=1 npm --prefix "$SUITE_DIR" run e2e
RUN_OUT="$GATE_OUT"
printf '%s\n' "$RUN_OUT" > "$LOG"
gate_expect_rc 0 "CI=1 npm run e2e ($SUITE) exits 0"

PASSED="$(printf '%s\n' "$RUN_OUT" | grep -oP '\K[0-9]+(?= passed)' | tail -1)"
gate_say "passed count, read off Playwright's own summary line just now (never written down here): ${PASSED:-<none found>}"
if [ -n "${PASSED:-}" ] && [ "$PASSED" -gt 0 ]; then
  gate_say "ok: Playwright reported more than zero passed tests"
else
  gate_say "FAIL: no '<N> passed' with N>0 in Playwright's output -- a run that passed nothing proves nothing, whatever its exit code"
  _gate_failures=$((_gate_failures + 1))
fi

gate_verdict "the $SUITE Playwright e2e suite runs under CI=1, on every browser it configures, and reports more than zero tests passed"
