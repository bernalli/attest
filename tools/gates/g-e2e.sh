#!/usr/bin/env bash
# gate-order: 120
# gate-order-why: runs after the suites that build each app
# gate-invocations: site desktop
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
# (D-G1c). So every browser type the suite is about to launch is checked and launch-probed
# BEFORE the suite, and its build ID is derived from `playwright install --dry-run`'s own
# output on THIS tree's THIS node_modules, right now — never a version pinned in this script,
# which would drift the next time either tree's package-lock.json moves. An installed browser
# that cannot start is the same missing precondition as an absent executable, not a product red.
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
GATE_TREE="${GATE_TREE:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd))}"

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
#
# AND THE LIST OF KNOWN NAMES BELOW IS ITSELF AN ENUMERATION -- say it plainly,
# because this guard recognises a SPELLING. Playwright names the same browser
# through presets: `devices['Desktop Safari']` IS webkit, and measured on site's
# config, `projects: [{ name: 'safari', use: { ...devices['Desktop Safari'] } }]`
# does NOT trip this check. Latent today (desktop names all three literally), and
# it is the same defect one layer in: the guard against a stale enumeration is
# itself enumerated. Closing it properly means reading `projects` -- the decision
# this comment already says has not been taken.
PW_CONFIG="$SUITE_DIR/playwright.config.ts"
if [ ! -r "$PW_CONFIG" ]; then
  # Silence here would be the guard failing open: Playwright also accepts .js/.mjs/.cjs/
  # .mts/.cts, so a renamed config makes the staleness check do nothing while the gate
  # goes on launching an enumerated browser set nobody has compared to anything.
  # Measured: with `if [ -r ]` and no else, the config renamed to .js left the check
  # silent and the gate proceeded. A precondition that cannot be read is a 78.
  gate_say "PRECONDITION MISSING: $SUITE/playwright.config.ts is not readable — the"
  gate_say "  browser enumeration for '$SUITE' cannot be compared against the config,"
  gate_say "  so this gate cannot know which browsers the suite will launch."
  gate_say "GATE $GATE_ID SKIPPED precondition=config-unreadable"
  exit 78
fi
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

  executable="$(cd "$SUITE_DIR" && node -e '
    const browserType = require("playwright-core")[process.argv[1]];
    if (!browserType) process.exit(1);
    process.stdout.write(browserType.executablePath());
  ' "$bt" 2>/dev/null)"
  executable_rc=$?
  if [ "$executable_rc" -ne 0 ] || [ -z "$executable" ] || [ ! -x "$executable" ]; then
    gate_say "PRECONDITION MISSING: $bt browser executable is absent or not executable."
    gate_say "expected: ${executable:-<playwright could not resolve a path>}"
    gate_say "install with: npx --prefix $SUITE_DIR playwright install $bt"
    gate_say "GATE $GATE_ID SKIPPED precondition=browser-executable-absent browser=$bt"
    exit 78
  fi

  LAUNCH_LOG="$TRANSCRIPTS/${TAG}-e2e-${SUITE}.${bt}-launch.log"
  (cd "$SUITE_DIR" && node -e '
    const browserType = require("playwright-core")[process.argv[1]];
    (async () => {
      const browser = await browserType.launch({ headless: true });
      await browser.close();
    })().catch((error) => {
      process.stderr.write((error instanceof Error ? error.stack : String(error)) + "\n");
      process.exit(1);
    });
  ' "$bt") > "$LAUNCH_LOG" 2>&1
  launch_rc=$?
  gate_say "--- $bt browser launch probe ($SUITE)"
  [ ! -s "$LAUNCH_LOG" ] || gate_say "$(cat "$LAUNCH_LOG")"
  gate_say "exit: $launch_rc"
  if [ "$launch_rc" -ne 0 ]; then
    gate_say "PRECONDITION MISSING: $bt browser executable exists but will not launch."
    gate_say "executable: $executable"
    gate_say "GATE $GATE_ID SKIPPED precondition=browser-launch-failed browser=$bt"
    exit 78
  fi
  gate_say "precondition ok: $bt browser executable launches for $SUITE"
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
