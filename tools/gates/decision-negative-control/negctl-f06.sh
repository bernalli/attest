#!/usr/bin/env bash
# CONTROLLO NEGATIVO DELLA DECISIONE — fantoccio F-06.
#
# Questo file NON e' un gate del progetto: e' un fantoccio scritto per rispondere
# alla domanda del passo 1 del brief F6 — "F-06 resta esprimibile sotto D-G1/D-G2?".
#
# Conformita' formale a D-G1, punto per punto:
#   - e' un file eseguibile, non una riga di tabella;
#   - il suo esito e' PRODOTTO da un'esecuzione, non descritto;
#   - il transcript va agli atti.
# Conformita' a D-G2: nessun conteggio scritto nel file.
#
# Contiene il difetto F-06: il controllo negativo asserisce che il comando
# fallisce, senza asserire DOVE fallisce.
set -uo pipefail

W="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd))"
PY="$W/.venv/bin/python"

echo "== controllo negativo di G-CI-PY (fantoccio) =="
"$PY" "$W/tools/conformance_runner.py" --adapter false --subset v0.2
rc=$?
echo "exit osservato: $rc"

if [ "$rc" -ne 0 ]; then
  echo "NEG-OK: il gate sa fallire su un adapter fallente"
  echo "GATE-MARKER: negativo eseguito"
  exit 0
fi
echo "NEG-FAIL: il gate non ha rilevato l'adapter fallente"
exit 1
