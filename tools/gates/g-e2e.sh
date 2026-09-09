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
# A missing browser executable or recognised missing system library is a precondition,
# not a product defect. An unexplained launch failure blocks measurement instead of
# disappearing among run-all.sh's nonfatal skips. Probe the same default headless
# launcher as Playwright, using this tree's installed version; never infer its path
# from the full Chromium binary or a separately parsed install manifest.
#
# Which browser TYPES each suite launches is read from its own playwright.config.ts, current
# as of this gate's writing: site declares no `projects`, so Playwright runs its one implicit
# project on the default browser, chromium, only. desktop declares `projects: [chromium,
# firefox, ...(CI ? [webkit] : [])]` (desktop/playwright.config.ts) — webkit only under CI,
# which is exactly the invocation this gate always uses (CI=1), so desktop's precondition
# always includes webkit.
#
# Dependencies are installed outside this gate. It never runs npm ci or downloads
# browsers; a broken or missing Node installation blocks the probe by name.
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
gate_block() {
  gate_say "GATE $GATE_ID BLOCKED code=$1 failure=$2"
  exit "$1"
}
mkdir -p "$TRANSCRIPTS" || gate_block 73 "transcript-directory-failed"
TAG="$(date -u +%Y%m%dT%H%M%SZ)" || gate_block 73 "transcript-timestamp-failed"

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
  gate_block 70 "config-unreadable: $PW_CONFIG"
fi
for known in chromium firefox webkit; do
  grep -qE "(^|[^a-zA-Z])$known([^a-zA-Z]|$)" "$PW_CONFIG"
  config_rc=$?
  [ "$config_rc" -le 1 ] || gate_block 70 "config-read-failed: $PW_CONFIG"
  if [ "$config_rc" -eq 0 ]; then
    case " ${BROWSER_TYPES[*]} " in
      *" $known "*) ;;
      *)
        gate_block 70 "browser-enumeration-stale: $PW_CONFIG names $known"
        ;;
    esac
  fi
done
gate_say ""

# Missing tools needed by the probe are its own failure, not a browser skip.
command -v node >/dev/null 2>&1 || gate_block 70 "probe-node-unavailable"
command -v npm >/dev/null 2>&1 || gate_block 70 "suite-npm-unavailable"

# A nonzero probe is not evidence of an absent precondition. Only the worker's
# named missing-executable / missing-library signatures may skip. Everything
# else blocks measurement: 70 probe/config/Node, 71 launch/crash, 73 log,
# 74 temporary/profile/cleanup, 75 close, 124 timeout (product failures remain 1).
# The supervisor owns TMPDIR before Playwright loads, including pre-spawn leaks.
# Its 15s watchdog covers import, launch AND close; PWDEBUG cannot disable it.
# Playwright's browser debug stream records the actual executable and spawned PID,
# including Chromium's headless shell (executablePath() names a different binary).
for bt in "${BROWSER_TYPES[@]}"; do
  LAUNCH_LOG="$TRANSCRIPTS/${TAG}-e2e-${SUITE}.${bt}-launch.log"
  probe_out="$(node - "$bt" "$SUITE_DIR" "$LAUNCH_LOG" "$GATE_ID" <<'NODE'
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const [bt, suiteDir, logPath, gateId] = process.argv.slice(2);
const limitMs = 15000;
let root, log, worker, result, failure, timer, killer;
let phase = 'setup', finished = false, browserOutput = '';
const browserPids = new Set();

function kill(pid, signal) {
  try { process.kill(process.platform === 'win32' ? pid : -pid, signal); }
  catch (error) { if (error.code !== 'ESRCH') throw error; }
}
function finish() {
  if (finished) return;
  finished = true;
  clearTimeout(timer);
  clearTimeout(killer);
  let outcome = failure || result || { code: 70, reason: 'probe-result-missing' };
  try {
    // Playwright launches browsers in separate process groups. The worker's
    // group alone does not own them; reap both before removing their profiles.
    for (const pid of browserPids) kill(pid, 'SIGKILL');
    if (root) fs.rmSync(root, { recursive: true, force: true });
  } catch (error) {
    outcome = { code: 74, reason: 'probe-cleanup-failed: ' + error.message };
  }
  try { if (log !== undefined) fs.closeSync(log); }
  catch (error) { outcome = { code: 73, reason: 'probe-log-close-failed: ' + error.message }; }
  console.log(`probe cleanup: ${root || '<not allocated>'}`);
  if (outcome.code === 0) {
    console.log(`probe ok: browser=${bt} launched and closed`);
  } else if (outcome.code === 78) {
    console.log(`PRECONDITION MISSING: ${outcome.reason}`);
    console.log(`GATE ${gateId} SKIPPED precondition=${outcome.reason} browser=${bt}`);
  } else {
    console.log(`GATE ${gateId} BLOCKED code=${outcome.code} failure=${outcome.reason} browser=${bt}`);
  }
  process.exitCode = outcome.code;
}
function stop(code, reason) {
  failure ||= { code, reason };
  if (!worker || !worker.pid) return finish();
  // Kill the browsers first so the still-running worker can reap them.
  try {
    for (const pid of browserPids) kill(pid, 'SIGKILL');
    kill(worker.pid, 'SIGTERM');
  } catch (error) { failure = { code: 70, reason: 'probe-kill-failed: ' + error.message }; }
  killer ||= setTimeout(() => {
    try { kill(worker.pid, 'SIGKILL'); }
    catch (error) { failure = { code: 70, reason: 'probe-kill-failed: ' + error.message }; }
  }, 1000);
}
function record(chunk) {
  const text = chunk.toString();
  browserOutput += text;
  for (const match of browserOutput.matchAll(/<launched> pid=(\d+)/g)) browserPids.add(Number(match[1]));
  try {
    if (fs.writeSync(log, chunk) !== chunk.length) throw new Error('short write');
  }
  catch (error) { stop(73, 'probe-log-write-failed: ' + error.message); }
  process.stdout.write(text);
}
process.on('SIGINT', () => stop(70, 'probe-interrupted: SIGINT'));
process.on('SIGTERM', () => stop(70, 'probe-interrupted: SIGTERM'));
process.on('uncaughtException', error => stop(70, 'probe-node-error: ' + error.message));

// A separate Node process keeps the watchdog independent of Playwright's event
// loop and debug settings. A result is accepted only after a clean worker exit.
function launchWorker() {
  const fs = require('node:fs');
  let phase = 'node-load';
  const send = message => process.send(message);
  const outcome = (code, reason) => send({ code, reason });
  (async () => {
    const bt = process.argv[1];
    const { createRequire } = require('node:module');
    const localRequire = createRequire(process.cwd() + '/package.json');
    const browserType = localRequire('playwright-core')[bt];
    if (!browserType) throw new Error('unknown browser type: ' + bt);
    phase = 'launch'; send({ phase });
    const browser = await browserType.launch({ headless: true, timeout: 10000 });
    console.log(`probe launched: browser=${bt} version=${browser.version()}`);
    phase = 'close'; send({ phase });
    await browser.close();
    outcome(0, 'browser-launched-and-closed');
  })().catch(error => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(error instanceof Error ? error.stack : message);
    if (phase === 'node-load') return outcome(70, 'probe-node-error: ' + message);
    if (phase === 'close') return outcome(75, 'browser-close-failed: ' + message);
    if (error.name === 'TimeoutError') return outcome(124, 'browser-launch-timeout: 10000ms');
    if (/signal=SIG(?:SEGV|ABRT|BUS|ILL|TRAP|KILL|TERM)/.test(message))
      return outcome(71, 'browser-crash: ' + message.match(/signal=SIG\w+/)[0]);
    if (/(?:mkdtemp|mkdir|playwright[^\n]*profile).*?(?:EACCES|ENOENT|ENOTDIR|ENOSPC)|(?:EACCES|ENOENT|ENOTDIR|ENOSPC).*?(?:mkdtemp|mkdir|profile)/s.test(message))
      return outcome(74, 'browser-profile-failed: ' + message);
    const absent = message.match(/^(?:browserType\.launch: )?Executable doesn't exist at ([^\r\n]+)/m);
    if (absent) {
      try { fs.statSync(absent[1]); }
      catch (statError) {
        if (statError.code === 'ENOENT') return outcome(78, 'browser-executable-absent: ' + absent[1]);
        return outcome(70, 'browser-executable-stat-failed: ' + statError.message);
      }
      return outcome(71, 'browser-executable-absence-unconfirmed: ' + absent[1]);
    }
    // Recognised Playwright dependency validator and Linux dynamic-loader
    // signatures. Other platforms/messages block until explicitly understood.
    if (/Host system is missing dependencies to run browsers\./.test(message))
      return outcome(78, 'browser-system-libraries-absent: playwright-host-dependencies');
    const library = message.match(/error while loading shared libraries: ([^:\s]+): cannot open shared object file: No such file or directory/);
    if (library) return outcome(78, 'browser-system-libraries-absent: linux-loader ' + library[1]);
    outcome(71, 'browser-launch-failed: ' + message);
  });
}
try {
  console.log(`probe: browser=${bt} headless=true launch-timeout=10000ms watchdog=${limitMs}ms`);
  phase = 'log';
  log = fs.openSync(logPath, 'wx');
  phase = 'temporary-directory';
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'attest-e2e-probe-'));
  console.log(`probe temporary root: ${root}`);
  phase = 'node-spawn';
  timer = setTimeout(() => stop(124, `probe-watchdog-timeout: ${limitMs}ms phase=${phase}`), limitMs);
  worker = spawn(process.execPath, ['-e', `(${launchWorker.toString()})()`, bt], {
    cwd: suiteDir,
    detached: process.platform !== 'win32',
    env: { ...process.env, TMPDIR: root, TMP: root, TEMP: root, DEBUG: 'pw:browser', DEBUG_COLORS: '0' },
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  worker.stdout.on('data', record);
  worker.stderr.on('data', record);
  worker.on('message', message => {
    if (message.phase) { phase = message.phase; return; }
    if (result || ![0, 70, 71, 74, 75, 78, 124].includes(message.code) || typeof message.reason !== 'string')
      return stop(70, 'probe-result-invalid');
    result = message;
  });
  worker.on('error', error => stop(70, 'probe-node-spawn-failed: ' + error.message));
  worker.on('close', (code, signal) => {
    if (code !== 0 || signal) failure ||= { code: 70, reason: `probe-node-exit: code=${code} signal=${signal}` };
    finish();
  });
} catch (error) {
  stop(phase === 'log' ? 73 : phase === 'temporary-directory' ? 74 : 70,
    `probe-${phase}-failed: ${error.message}`);
}
NODE
)"
  launch_rc=$?
  gate_say "--- $bt browser launch probe ($SUITE)"
  gate_say "$probe_out"
  gate_say "exit: $launch_rc"
  case "$launch_rc" in
    0)
      if ! grep -qF "probe ok: browser=$bt launched and closed" <<< "$probe_out"; then
        gate_block 70 "probe-result-missing browser=$bt"
      fi ;;
    78)
      if ! grep -qE "^GATE $GATE_ID SKIPPED precondition=browser-(executable-absent|system-libraries-absent):" <<< "$probe_out"; then
        gate_block 70 "probe-skip-evidence-missing browser=$bt"
      fi
      exit 78 ;;
    70|71|73|74|75|124)
      if ! grep -qF "GATE $GATE_ID BLOCKED code=$launch_rc " <<< "$probe_out"; then
        gate_block 70 "probe-node-failed exit=$launch_rc browser=$bt"
      fi
      exit "$launch_rc" ;;
    *) gate_block 70 "probe-node-failed exit=$launch_rc browser=$bt" ;;
  esac
done

# --- Property: the suite runs under CI=1 and reports more than zero passed -----------------
LOG="$TRANSCRIPTS/${TAG}-e2e-${SUITE}.log"
gate_run "CI=1 npm run e2e ($SUITE)" -- env CI=1 npm --prefix "$SUITE_DIR" run e2e
RUN_OUT="$GATE_OUT"
printf '%s\n' "$RUN_OUT" > "$LOG" || gate_block 73 "suite-log-write-failed: $LOG"
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
