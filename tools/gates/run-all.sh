#!/usr/bin/env bash
# Run every gate on disk, in the order they declare, and report three NAMED sets.
#
# TWO STRUCTURAL PROPERTIES, and the first version of this file had neither.
#
# 1. THE GATES ARE DISCOVERED, NOT LISTED. The previous version carried an array
#    of gate names. A list is exempt by construction from whatever lands after it,
#    so a gate added tomorrow would simply never run -- measured: a red
#    g-brand-new.sh sitting on disk produced RUN-ALL PASS, exit 0, and was never
#    named. That is the same defect the gates themselves exist to catch, in the
#    file that runs them. Now the glob finds them and each gate declares its own
#    position (`# gate-order:`) and its own invocations (`# gate-invocations:`)
#    in its header. A gate WITHOUT a declaration is not skipped and not assumed
#    last: it stops this runner by name, because "I do not know where this goes"
#    must never be spelled "I will leave it out".
#
# 2. THE TRANSCRIPT IS THE RUN'S STREAM, IN APPEND -- not a file written at the
#    end. The previous version captured the output, waited for the verdict, and
#    then wrote the file; a gate that died before printing its verdict left the
#    PREVIOUS run's transcript untouched on disk. The screen said FAIL and the
#    file said PASS, which is an artefact of measurement asserting something
#    false. Now each run streams into its own transcript as it goes: a run that
#    dies leaves a TRUNCATED transcript with no verdict line, and the absence of
#    the verdict is the verdict.
#
# Exit status: non-zero if any gate is RED. A 78 does not fail the run -- a
# missing browser or an unbuilt dependency is not a defect of the product -- but
# it is always listed with its reason, because a gate that did not measure has to
# stay visible even when everything else is green.
#
# THE WHOLE RUN MAY NOT FIT IN MEMORY on a small host, and that is a fact about
# the machine, not about the gates. Measured twice in a row on a 8 GiB box with
# other work resident: killed by the OOM killer partway through g-ts-test.sh
# (vitest over the whole TS suite). When that happens, do NOT relaunch first: an
# OOM kill takes the small process that orchestrates and leaves the heavy work it
# spawned alive, so hunt the orphans (`ps -eo pid,ppid,rss --sort=-rss`, looking
# for PPID 1) before starting anything. Then run the gates in GROUPS -- the light
# ones together, each suite on its own -- exactly as the project's rule for
# segmented suites already prescribes. Each gate writes its own transcript either
# way, so a grouped run leaves the same evidence as a whole one.
set -uo pipefail

GATE_TREE="${GATE_TREE:-$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd))}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRANSCRIPTS="$HERE/transcripts"
mkdir -p "$TRANSCRIPTS"

green=(); red=(); skipped=(); undeclared=()

# --- Discovery: every g-*.sh on disk, ordered by its own declaration ----------
declare -a ENTRIES=()
for script in "$HERE"/g-*.sh; do
  [ -f "$script" ] || continue
  name="$(basename "$script")"
  if [ ! -x "$script" ]; then
    # A gate that cannot be executed is not a gate that passed. Taken from the
    # reviewer's patch: without this it would fail as rc=126 among the reds, which
    # is true but says "the property does not hold" about a file nobody ran.
    undeclared+=("$name (not executable: chmod +x)")
    continue
  fi
  order="$(sed -n 's/^# gate-order: *\([0-9][0-9]*\).*/\1/p' "$script" | head -1)"
  if [ -z "$order" ]; then
    undeclared+=("$name")
    continue
  fi
  invocations="$(sed -n 's/^# gate-invocations: *//p' "$script" | head -1)"
  if [ -z "$invocations" ]; then
    ENTRIES+=("$order $name")
  else
    for arg in $invocations; do
      ENTRIES+=("$order $name $arg")
    done
  fi
done

if [ "${#undeclared[@]}" -gt 0 ]; then
  echo "RUN-ALL REFUSES TO START: gate(s) without a '# gate-order:' declaration"
  printf '  %s\n' "${undeclared[@]}"
  echo
  echo "A gate whose position is unknown must not be silently left out, and must not"
  echo "be silently appended: declare '# gate-order: NN' in its header, beside the"
  echo "reason, and rerun."
  exit 2
fi

if [ "${#ENTRIES[@]}" -eq 0 ]; then
  echo "RUN-ALL REFUSES TO PASS: discovery found no gate at all in $HERE"
  echo "(an empty set of gates would otherwise report a clean run)"
  exit 2
fi

mapfile -t SORTED < <(printf '%s\n' "${ENTRIES[@]}" | sort -n -k1,1 -k2,2 -k3,3)
echo "discovered ${#SORTED[@]} gate invocation(s) from $HERE/g-*.sh"
echo

for entry in "${SORTED[@]}"; do
  # shellcheck disable=SC2206 - deliberate splitting: "order name [arg]"
  parts=($entry)
  name="${parts[1]}"
  arg="${parts[2]:-}"
  label="$name${arg:+ $arg}"
  # The transcript name is derived from the invocation, which is known BEFORE the
  # run -- it cannot depend on a verdict the run may never print.
  slug="${name%.sh}${arg:+--$arg}"
  log="$TRANSCRIPTS/$slug.log"

  printf '%-28s ' "$label"
  # Streamed, not captured-then-written. PIPESTATUS[0] because the pipeline's own
  # status is tee's, and the gate's exit IS the measurement here.
  "$HERE/$name" ${arg:+"$arg"} > "$log" 2>&1
  rc=$?

  verdict="$(grep -E '^GATE ' "$log" | tail -1)"
  if [ -z "$verdict" ]; then
    # No verdict line: the run did not reach its own conclusion. Whatever the
    # exit status says, this transcript is truncated and must not read as a pass.
    red+=("$label — no verdict line: run ended before concluding (transcript truncated)")
    printf 'NO VERDICT (rc=%s, transcript truncated)\n' "$rc"
    continue
  fi
  case "$rc" in
    0)  green+=("$label");   printf 'PASS\n' ;;
    78) reason="$(sed -n 's/.*precondition=\(.*\)/\1/p' <<< "$verdict")"
        skipped+=("$label — precondition: ${reason:-unknown}")
        printf 'DID NOT MEASURE (78, %s)\n' "${reason:-unknown}" ;;
    *)  red+=("$label (rc=$rc)"); printf 'FAIL (rc=%s)\n' "$rc" ;;
  esac
done

echo
echo "=== GREEN (${#green[@]}) ==="
if [ "${#green[@]}" -eq 0 ]; then echo "  (none)"; else printf '  %s\n' "${green[@]}"; fi
echo "=== DID NOT MEASURE (${#skipped[@]}) — neither green nor red ==="
if [ "${#skipped[@]}" -eq 0 ]; then echo "  (none)"; else printf '  %s\n' "${skipped[@]}"; fi
echo "=== RED (${#red[@]}) ==="
if [ "${#red[@]}" -eq 0 ]; then echo "  (none)"; else printf '  %s\n' "${red[@]}"; fi

if [ "${#red[@]}" -gt 0 ]; then
  echo
  echo "RUN-ALL FAIL: ${#red[@]} gate(s) red"
  exit 1
fi
echo
echo "RUN-ALL PASS: no gate is red; ${#skipped[@]} did not measure and are named above"
