# OL-18: censimento dei tipi nei test del verificatore

Validazione dell'implementazione; l'approvazione di merge resta una review separata.
La base e' `fix/verifiers-test-census`, verificata prima di modificare i file:

```sh
git rev-parse HEAD fix/verifiers-test-census origin/fix/verifiers-test-census
```

```text
ff2198f038606abe1eb98f05f11b5a35ae59d880
ff2198f038606abe1eb98f05f11b5a35ae59d880
ff2198f038606abe1eb98f05f11b5a35ae59d880
```

## Contratto

`tools/check_verifier_test_types.py` esegue il probe e confronta il risultato con
`tools/verifier-test-types-census.json`. Riusa dal precedente `check_test_census.py`
la scoperta dei test su disco, l'ammissione JSON stretta e la lettura/scrittura del
formato `suites -> verifiers/ts -> total, files`. Registra anche i file senza
errori. Per-file e totale devono coincidere in entrambi i versi: una riduzione
nomina il file e richiede `--update` quanto un aumento richiede un intervento.

La scelta di non pinnare i codici e' motivata anche nel docstring: conserva il
formato del precedente e ammette riclassificazioni della diagnostica senza
confonderle con una variazione del debito. Il limite e' esplicito: sostituire una
diagnostica con un'altra nello stesso file, conservandone il conteggio, e' fuori
copertura. Una compensazione fra file diversi invece fallisce.

Il marcatore `MEASURED: ... test file(s) compiled by the verifier probe` deriva da
`--listFiles` nella stessa esecuzione che produce le diagnostiche. Non deriva dal
censimento o dal numero di errori. `--update` confronta disco e compilazione prima
di scrivere: i file nuovi completi sono ammessi, un file presente ma non compilato
impedisce l'aggiornamento. Una cancellazione intenzionale dal disco puo' essere
registrata esplicitamente, come nel precedente.

| Uscita | Significato |
| --- | --- |
| `0` | Censimento corrispondente, aggiornamento completo riuscito, oppure selftest passato. |
| `1` | Differenza dal censimento, censimento assente/invalido, aggiornamento rifiutato, oppure selftest fallito. |
| `2` | Misura impossibile: output vuoto/illeggibile, processo non avviabile, timeout, stato incoerente, nessun test compilato o diagnostiche esterne al perimetro. Anche argparse usa questa uscita per argomenti invalidi. |
| `78` | Precondizione assente: `node_modules`, `tsc` o `node` sul PATH. |

Il pin committato viene ammesso prima delle precondizioni: cancellarlo resta una
violazione del censimento. Un eseguibile presente ma non avviabile e' una misura
impossibile, distinta da un eseguibile assente. Nessun caso non misurato stampa
un successo; quando la lista restituisce soltanto sorgenti, il marcatore espone
che nessun file di test e' stato compilato e il comando fallisce.

Il comando normale occupa la riga immediatamente successiva al build del
verificatore nel job `test` di `pages.yml`; segue `--selftest`. Entrambe le
invocazioni sono replicate nello stesso job di `tools/verify-all.sh`.

## Misura iniziale e verde

Le dipendenze sono state installate dal lockfile con:

```sh
npm ci --prefix verifiers/ts --cache /tmp/attest-ol18-npm-cache --no-audit --no-fund --fetch-retries=0
```

Prima di scrivere codice e' stato eseguito il comando richiesto, raccolto da
`subprocess.run` per contare separatamente le righe e la somma per codice:

```sh
python3 - <<'PYBASE'
import collections, re, subprocess
result = subprocess.run(['./verifiers/ts/node_modules/.bin/tsc', '-p', 'verifiers/ts/tsconfig.t3b-probe.json'], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
print('$ ./verifiers/ts/node_modules/.bin/tsc -p verifiers/ts/tsconfig.t3b-probe.json')
print(f'rc: {result.returncode}')
lines = [line for line in result.stdout.splitlines() if 'error TS' in line]
codes = collections.Counter(re.search(r'error (TS\d+)', line).group(1) for line in lines)
print(f'lines containing error TS: {len(lines)}')
for code, count in sorted(codes.items()):
    print(f'{code}: {count}')
print(f'sum by code: {sum(codes.values())}')
print(result.stdout)
PYBASE
```

Estratto dell'output, prima delle diagnostiche individuali:

```text
$ ./verifiers/ts/node_modules/.bin/tsc -p verifiers/ts/tsconfig.t3b-probe.json
rc: 2
lines containing error TS: 57
TS2322: 15
TS2345: 21
TS2532: 8
TS2740: 13
sum by code: 57
```

Un ulteriore conteggio sullo stesso probe con la lista di compilazione:

```sh
./verifiers/ts/node_modules/.bin/tsc -p verifiers/ts/tsconfig.t3b-probe.json --listFiles --pretty false --noEmit --incremental false > /tmp/attest-ol18-baseline.txt
rg -c 'error TS' /tmp/attest-ol18-baseline.txt
```

```text
57
```

Creazione del pin e verifica; quest'ultima e' stata ripetuta sull'albero
ripristinato dopo le iniezioni:

```sh
python3 tools/check_verifier_test_types.py --update
python3 tools/check_verifier_test_types.py
```

```text
MEASURED: 55 test file(s) compiled by the verifier probe
census updated for verifiers/ts: 55 file(s), 57 diagnostic(s)
MEASURED: 55 test file(s) compiled by the verifier probe
verifiers/ts: 57 diagnostic(s) -- matches the census
```

## Rossi richiesti, eseguiti

I comandi seguenti usano il programma riportato nella sezione di riproduzione.
Ogni iniezione ai test parte da una copia di backup e la ripristina in `finally`,
verificando l'identita' dei byte. Il programma misura anche il probe grezzo e
confronta le intestazioni delle diagnostiche prima e dopo: un solo errore aggiunto
o rimosso, con compilazione ancora funzionante. Non usa `git checkout`.

### R1: una diagnostica aggiunta

Aggiunta in coda a `verifiers/ts/test/canon-parse.test.ts`:
`const ol18TypeRegression: string = 1;`.

```sh
python3 /tmp/attest-ol18-evidence/red_checks.py R1
```

```text
$ python3 tools/check_verifier_test_types.py
MEASURED: 55 test file(s) compiled by the verifier probe
verifiers/ts: test/canon-parse.test.ts: diagnostics increased to 2, the census records 1 (regression).
verifiers/ts: total diagnostics 58, the census records 57; an intended change requires --update.
gate rc: 1
$ ./verifiers/ts/node_modules/.bin/tsc -p verifiers/ts/tsconfig.t3b-probe.json
probe rc: 2
probe diagnostic headers: 58
added: verifiers/ts/test/canon-parse.test.ts(55,7): error TS2322: Type 'number' is not assignable to type 'string'.
restored from backup: byte-identical
```

### R2: una diagnostica tolta

Sostituzione temporanea di `expect(v['t'].length).toBe(5)` con
`expect(v['t']?.length).toBe(5)`: accesso protetto al valore possibilmente assente,
con la stessa aspettativa del test. La diagnostica rimossa e' nominata nell'output.

```sh
python3 /tmp/attest-ol18-evidence/red_checks.py R2
```

```text
$ python3 tools/check_verifier_test_types.py
MEASURED: 55 test file(s) compiled by the verifier probe
verifiers/ts: test/canon-parse.test.ts: diagnostics decreased to 0, the census records 1; update the census with --update.
verifiers/ts: total diagnostics 56, the census records 57; an intended change requires --update.
gate rc: 1
$ ./verifiers/ts/node_modules/.bin/tsc -p verifiers/ts/tsconfig.t3b-probe.json
probe rc: 2
probe diagnostic headers: 56
removed: verifiers/ts/test/canon-parse.test.ts(31,12): error TS2532: Object is possibly 'undefined'.
restored from backup: byte-identical
```

### R3: precondizione assente

Il percorso alternativo di `tsc` e' verificato assente prima dell'invocazione.

```sh
python3 /tmp/attest-ol18-evidence/red_checks.py R3
```

```text
$ python3 tools/check_verifier_test_types.py --tsc /tmp/attest-ol18-evidence/missing-tsc
unable to measure: missing prerequisite tsc executable: /tmp/attest-ol18-evidence/missing-tsc; install Node.js and run npm ci --prefix verifiers/ts
gate rc: 78
```

### Aggiornamento rifiutato su un'assenza reale

Il probe esclude temporaneamente `test/dates.test.ts`, un test senza diagnostiche.
Il file resta sul disco. L'aggiornamento usa una copia del censimento e ne verifica
i byte dopo il rifiuto; il tsconfig viene ripristinato dalla sua copia di backup.

```sh
python3 /tmp/attest-ol18-evidence/update_absence.py
```

```text
$ python3 tools/check_verifier_test_types.py --census /tmp/attest-ol18-evidence/update-census.json --update
MEASURED: 54 test file(s) compiled by the verifier probe
refusing to update the census:
verifiers/ts: test/dates.test.ts is on disk but was NOT compiled by the probe.
gate rc: 1
census bytes changed: False
probe config restored from backup: byte-identical
```

## Selftest e disattivazioni singole

```sh
python3 tools/check_verifier_test_types.py --selftest
```

```text
  ok   healthy input, including a clean compiled file, reports nothing
  ok   no test files compiled -> named ('unable to measure: no test files compiled')
  ok   disk file absent even during update -> named ('test/b.test.ts is on disk but was NOT compiled')
  ok   compiled file absent from disk -> named ('compiled test test/b.test.ts is not on disk')
  ok   pinned clean file deleted -> named ('census file test/b.test.ts was not compiled')
  ok   new clean file unregistered -> named ('compiled test test/c.test.ts is not in the census')
  ok   diagnostic increase -> named ('test/a.test.ts: diagnostics increased to 4')
  ok   diagnostic decrease requires update -> named ('test/a.test.ts: diagnostics decreased to 2, the census records 3; update the census with --update')
  ok   per-file drift despite unchanged total -> named ('test/b.test.ts: diagnostics increased to 1')
  ok   total drift -> named ('total diagnostics 4, the census records 3')
selftest: 10/10
```

La prova seguente ricompila in memoria la funzione `compare` reale, rimuovendo
ogni volta soltanto la proprieta' nominata. I restanti confronti e il selftest
rimangono gli originali. Ogni sostituzione deve trovare un solo punto nel sorgente;
un errore di sintassi non conta come difetto intercettato. Il test pretende che
il riepilogo perda casi nominati, anche se altri controlli fanno ancora fallire
lo stesso ingresso. Nessun interruttore di disattivazione e' esposto dal gate.

```sh
.venv/bin/pytest -q -s tests/tools/test_verifier_test_types.py -k selftest_loses_cases
```

```text
disabled nonempty: selftest: 10/10 -> selftest: 9/10; exit 1
.disabled disk-presence: selftest: 10/10 -> selftest: 9/10; exit 1
.disabled compiled-on-disk: selftest: 10/10 -> selftest: 9/10; exit 1
.disabled pinned-file: selftest: 10/10 -> selftest: 9/10; exit 1
.disabled registered-file: selftest: 10/10 -> selftest: 9/10; exit 1
.disabled increase: selftest: 10/10 -> selftest: 8/10; exit 1
.disabled decrease: selftest: 10/10 -> selftest: 9/10; exit 1
.disabled total: selftest: 10/10 -> selftest: 9/10; exit 1
.
8 passed, 26 deselected in 0.23s
```

## Altre verifiche eseguite

Preparazione dell'ambiente Python dal lockfile:

```sh
UV_CACHE_DIR=/tmp/attest-ol18-uv-cache uv sync --locked --extra dev --all-packages
```

```sh
.venv/bin/pytest -q tests/tools/test_verifier_test_types.py tests/tools/test_test_census.py tests/test_verify_all.py
```

Riepilogo verbatim:

```text
284 passed, 50 skipped in 6.54s
```

Gli skip provengono dalle esclusioni `provisioning` previste in
`tests/test_verify_all.py`; i test di parita' dei comandi eseguiti passano.
I test nuovi esercitano inoltre ammissione dell'output, precondizioni, aggiornamento
in entrambi i versi, rifiuto senza scrittura e uso effettivo del pin nel chiamante.

```sh
npm run build --prefix verifiers/ts
```

```text
> attest-verifier@0.9.6 build
> tsc -p tsconfig.json
```

```sh
npm test --prefix verifiers/ts -- --reporter=default --reporter=json --outputFile.json=/tmp/attest-ol18-evidence/verifier-tests.json
python3 tools/check_test_census.py verifiers/ts --report /tmp/attest-ol18-evidence/verifier-tests.json
```

Riepilogo della suite e output del censimento precedente:

```text
 Test Files  55 passed (55)
      Tests  2244 passed (2244)
verifiers/ts: 55 test file(s), 2244 test(s) -- matches the census
```

```sh
.venv/bin/ruff check .
.venv/bin/ruff format --check .
bash -n tools/verify-all.sh
git diff --check
git diff --exit-code -- verifiers/ts/test
```

```text
All checks passed!
232 files already formatted
```

Gli ultimi comandi non producono output e riescono. I test TypeScript sono
ripristinati; nessuna correzione permanente del debito fa parte della modifica.

## quello che so io e non e' scritto altrove

- La prima installazione in sandbox ha fallito per DNS `EAI_AGAIN`; anche il
  download Python ha incontrato il DNS bloccato. Le installazioni dai lockfile
  sono riuscite con accesso di rete. Non era un risultato rosso del prodotto.
- Le righe indentate di TypeScript spiegano la diagnostica precedente: contarle
  come errori gonfierebbe il pin. Il parser ammette queste continuazioni solo dopo
  un'intestazione valida, forza output senza colori e rifiuta righe sconosciute.
- La lista di compilazione include librerie, sorgenti e helper. Il marcatore
  seleziona i veri nomi di test con la stessa regola del censimento Vitest; le
  diagnostiche su helper o sorgenti non vengono ignorate o assorbite dal debito
  dei test, ma impediscono di accettare la misura o aggiornare il pin.
- Un test sano escluso non cambia il numero di errori. La prova sull'aggiornamento
  usa proprio questo caso per evitare che il confronto dei totali nasconda un
  buco nel controllo di presenza.
- Il report JSON di Vitest compare a fine esecuzione. Un primo consumo locale
  anticipato ha trovato il file ancora assente; la lettura dopo il completamento
  e' riuscita. Il cablaggio CI e locale conserva l'ordine sequenziale.
- I casi sintetici della disattivazione conservano gli ingressi del confronto;
  cercano il messaggio specifico della proprieta' rimossa. Accontentarsi di un
  qualsiasi rosso lascerebbe passare una guardia mutilata, perche' il totale puo'
  ancora accorgersi di un cambiamento che il confronto per-file non nomina piu'.

## Riproduzione dei controlli reali

Da root del repository, con dipendenze installate, preparare i programmi seguenti.
I backup preesistenti vengono rifiutati per non sovrascrivere una copia precedente.
Le aspettative sono quelle della base riportata in apertura.

```sh
mkdir -p /tmp/attest-ol18-evidence
cat > /tmp/attest-ol18-evidence/red_checks.py <<'PY'
from collections import Counter
from pathlib import Path
import shutil
import subprocess
import sys

label = sys.argv[1]
evidence = Path('/tmp/attest-ol18-evidence')
target = Path('verifiers/ts/test/canon-parse.test.ts')
backup = evidence / f'{label}-canon-parse.test.ts.backup'
gate = ['python3', 'tools/check_verifier_test_types.py']
probe = ['./verifiers/ts/node_modules/.bin/tsc', '-p',
         'verifiers/ts/tsconfig.t3b-probe.json']

def execute(command):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    return result

def headers(text):
    return Counter(line for line in text.splitlines() if 'error TS' in line)

if label == 'R3':
    missing = evidence / 'missing-tsc'
    assert not missing.exists()
    command = [*gate, '--tsc', str(missing)]
    print('$ ' + ' '.join(command), flush=True)
    result = execute(command)
    print(result.stdout, end='')
    print(f'gate rc: {result.returncode}')
    assert result.returncode == 78 and 'missing prerequisite' in result.stdout
    sys.exit(0)

assert label in ('R1', 'R2') and not backup.exists()
shutil.copy2(target, backup)
baseline = execute(probe)
assert baseline.returncode == 2 and sum(headers(baseline.stdout).values()) == 57
try:
    original = target.read_text()
    if label == 'R1':
        target.write_text(original + '\nconst ol18TypeRegression: string = 1;\n')
    else:
        old = "expect(v['t'].length).toBe(5)"
        assert original.count(old) == 1
        target.write_text(original.replace(old, "expect(v['t']?.length).toBe(5)"))
    print('$ ' + ' '.join(gate), flush=True)
    result = execute(gate)
    print(result.stdout, end='')
    print(f'gate rc: {result.returncode}')
    raw = execute(probe)
    print('$ ' + ' '.join(probe))
    print(f'probe rc: {raw.returncode}')
    before, after = headers(baseline.stdout), headers(raw.stdout)
    print(f'probe diagnostic headers: {sum(after.values())}')
    for line in (after - before).elements():
        print('added: ' + line)
    for line in (before - after).elements():
        print('removed: ' + line)
    assert result.returncode == 1 and target.name in result.stdout
    assert raw.returncode == 2
    assert sum(after.values()) == (58 if label == 'R1' else 56)
    assert sum((after - before).values()) == (1 if label == 'R1' else 0)
    assert sum((before - after).values()) == (0 if label == 'R1' else 1)
    if label == 'R2':
        assert '--update' in result.stdout
finally:
    shutil.copy2(backup, target)
    assert target.read_bytes() == backup.read_bytes()
    print('restored from backup: byte-identical')
PY
cat > /tmp/attest-ol18-evidence/update_absence.py <<'PY'
from pathlib import Path
import shutil
import subprocess

config = Path('verifiers/ts/tsconfig.t3b-probe.json')
evidence = Path('/tmp/attest-ol18-evidence')
backup = evidence / 'probe-config.backup'
pin = evidence / 'update-census.json'
assert not backup.exists()
shutil.copy2(config, backup)
shutil.copy2('tools/verifier-test-types-census.json', pin)
before = pin.read_bytes()
try:
    text = config.read_text()
    assert text.count('  "include":') == 1
    config.write_text(text.replace('  "include":', '  "exclude": ["test/dates.test.ts"],\n  "include":'))
    command = ['python3', 'tools/check_verifier_test_types.py', '--census', str(pin), '--update']
    print('$ ' + ' '.join(command), flush=True)
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end='')
    print(f'gate rc: {result.returncode}')
    print(f'census bytes changed: {pin.read_bytes() != before}')
    assert result.returncode == 1
    assert 'MEASURED: 54 test file(s)' in result.stdout
    assert 'test/dates.test.ts is on disk but was NOT compiled' in result.stdout
    assert pin.read_bytes() == before
finally:
    shutil.copy2(backup, config)
    assert config.read_bytes() == backup.read_bytes()
    print('probe config restored from backup: byte-identical')
PY
```
