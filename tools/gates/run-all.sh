#!/usr/bin/env bash
# Run every gate in dependency order and report THREE named sets, not three numbers.
#
# The contract each gate implements -- 0 the property holds, 1 it does not, 78 it
# could not measure -- had no consumer. A contract with no consumer dies the first
# time someone reads 78 as "not 1, so we are fine", and that reading is the whole
# reason the third status exists. So the summary never prints a count on its own:
# it names which gates are green, which are red, and which did not measure, because
# a gate that did not measure has to stay visible even when everything else is green.
#
# Exit status: non-zero if any gate is RED. A 78 does not fail the run -- a missing
# browser or an unbuilt dependency is not a defect of the product -- but it is always
# listed, and the reason comes with it.
set -uo pipefail

GATE_TREE="${GATE_TREE:-<tree>}"
HERE="$GATE_TREE/tools/gates"
TRANSCRIPTS="$HERE/transcripts"

# Dependency order, and the reasons are real: G-TS-B first because dist feeds
# G-PY-BW, G-CI-PY and the consumer suites, and a gate downstream of a stale dist
# measures the wrong tree without saying so. The order is written here and nowhere
# else; T0 points at this file rather than repeating it.
GATES=(
  "g-ts-build.sh"
  "g-ts-typecheck.sh"
  "g-ts-test.sh"
  "g-py-suite.sh ah"
  "g-py-suite.sh iz"
  "g-py-suite.sh sub"
  "g-py-suite.sh bw"
  "g-py-cover.sh"
  "g-lint.sh"
  "g-vec.sh"
  "g-ci-py.sh"
  "g-cont-diff.sh"
  "g-site.sh"
  "g-desk.sh"
  "g-e2e.sh site"
  "g-e2e.sh desktop"
  "g-compare.sh"
  "g-ci-cover.sh"
  "g-plan-code.sh"
  "g-ts-typecheck-f6.sh"
)

green=(); red=(); skipped=()

for entry in "${GATES[@]}"; do
  # shellcheck disable=SC2206 - deliberate word splitting: the entry carries its argument
  parts=($entry)
  script="${parts[0]}"
  label="$entry"
  printf '%-28s ' "$label"
  out="$("$HERE/$script" "${parts[@]:1}" 2>&1)"
  rc=$?
  verdict="$(printf '%s\n' "$out" | grep -E '^GATE ' | tail -1)"
  case "$rc" in
    0)  green+=("$label");   printf 'PASS\n' ;;
    78) reason="$(printf '%s\n' "$verdict" | sed -n 's/.*precondition=\(.*\)/\1/p')"
        skipped+=("$label — precondition: ${reason:-unknown}")
        printf 'DID NOT MEASURE (78, %s)\n' "${reason:-unknown}" ;;
    *)  red+=("$label");     printf 'FAIL (rc=%s)\n' "$rc" ;;
  esac
  # The transcript name is derived from the gate id, never written down: see the
  # correspondence rule in section 7.0 of the plan.
  id="$(printf '%s\n' "$verdict" | awk '{print $2}')"
  if [ -n "$id" ]; then
    printf '%s\n' "$out" > "$TRANSCRIPTS/$(printf '%s' "$id" | tr 'A-Z' 'a-z').log"
  fi
done

echo
echo "=== GREEN (${#green[@]}) ==="
printf '  %s\n' "${green[@]}"
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
