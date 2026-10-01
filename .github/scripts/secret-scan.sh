#!/bin/bash
# secret-scan.sh -- run gitleaks over the commits one change adds.
#
#   secret-scan.sh            scan SCAN_BASE..SCAN_HEAD in the current repository
#   secret-scan.sh --selftest prove, on throwaway repositories, that the scan
#                             refuses a change adding a credential and accepts
#                             one that does not
#
# SCAN_BASE and SCAN_HEAD arrive through the environment, never through the
# workflow's `${{ }}` inside a script. When SCAN_BASE is empty, all zeros (a new
# ref) or not in the clone (history rewritten), the scan falls back to the
# head commit alone, so it never reports "clean" over an empty range.
#
# The rule set is the repository's .gitleaks.toml (gitleaks defaults plus two
# narrow, documented exemptions). Findings are printed with --redact: the
# public log names the file, line, commit and rule, never the value.
set -euo pipefail

scan() {
  local base="${SCAN_BASE:-}" head="${SCAN_HEAD:?SCAN_HEAD is required}" range
  git cat-file -e "${head}^{commit}"
  if [[ -n "$base" && "$base" != 0000000000000000000000000000000000000000 ]] \
     && git cat-file -e "${base}^{commit}" 2>/dev/null; then
    range="${base}..${head}"
  else
    echo "no usable base (${base:-<empty>}); scanning ${head} alone"
    range="-1 ${head}"
  fi
  local count
  count="$(git rev-list --count ${range})"
  echo "scanning ${count} commit(s): ${range}"
  test "$count" -gt 0 || { echo "empty range: nothing would be scanned"; exit 1; }
  gitleaks git --config .gitleaks.toml --redact --no-banner --exit-code 1 \
    --log-opts="${range}" .
}

selftest() {
  local self tmp token
  self="$(readlink -f "$0")"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  # Built at run time: no credential-shaped string is ever committed here.
  token="ghp_$(head -c 512 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 36)"
  test "${#token}" -eq 40
  for case in dirty clean; do
    local repo="$tmp/$case"
    git init -q "$repo"
    cp .gitleaks.toml "$repo/.gitleaks.toml"
    (
      cd "$repo"
      export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid
      export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
      echo base > README && git add README && git commit -qm base
      if [[ "$case" == dirty ]]; then echo "token = ${token}" > config.txt
      else echo "colour = blue" > config.txt; fi
      git add config.txt && git commit -qm change
    )
    local rc=0
    (cd "$repo" && SCAN_BASE="$(git rev-parse HEAD~1)" SCAN_HEAD="$(git rev-parse HEAD)" \
      bash "$self" >/dev/null 2>&1) || rc=$?
    if [[ "$case" == dirty && "$rc" -eq 0 ]]; then
      echo "selftest: a change adding a token was accepted"; exit 1
    fi
    if [[ "$case" == clean && "$rc" -ne 0 ]]; then
      echo "selftest: a clean change was refused (exit $rc)"; exit 1
    fi
  done
  echo "selftest: refuses a planted token, accepts a clean change"
}

case "${1:-}" in
  --selftest) selftest ;;
  "") scan ;;
  *) echo "usage: $0 [--selftest]"; exit 2 ;;
esac
