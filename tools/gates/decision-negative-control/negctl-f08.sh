#!/usr/bin/env bash
# CONTROLLO NEGATIVO DELLA DECISIONE — fantoccio F-08.
#
# Stessa domanda del fantoccio F-06, sull'altro finding: sotto D-G1, e' ancora
# esprimibile "senza argomenti pytest esce 4 e raccoglie zero file"?
#
# Il piano non puo' piu' contenere quella frase (D-G1 la vieta come esito non
# eseguito). Qui la stessa affermazione e' messa dentro uno script, che e' il
# posto dove D-G1 la manda: la domanda e' se lo script possa restare verde
# portandola.
set -uo pipefail

W="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd))"
PY="$W/.venv/bin/python"

echo "== negativo 'argomento tolto' di G-PY-COVER (fantoccio) =="
out=$(cd "$W" && PYTHONDONTWRITEBYTECODE=1 "$PY" -m pytest -p no:cacheprovider -q --collect-only 2>&1)
rc=$?
files=$(printf '%s\n' "$out" | sed -n 's/::.*//p' | sort -u | grep -c . || true)
echo "exit osservato: $rc"
echo "file raccolti osservati: $files"

# L'affermazione che F-08 mette nel piano, qui messa nello script.
if [ "$rc" -eq 4 ] && [ "$files" -eq 0 ]; then
  echo "NEG-OK: senza argomenti il comando non raccoglie nulla ed esce 4"
  echo "GATE-MARKER: negativo eseguito"
  exit 0
fi
echo "NEG-FAIL: l'esito dichiarato non e' quello prodotto"
exit 1
