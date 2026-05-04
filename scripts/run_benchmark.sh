#!/usr/bin/env bash
# Benchmark end-to-end de la pipeline Phase 2
# Usage: bash scripts/run_benchmark.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== CND Phase 2 — Benchmark Pipeline ==="
echo ""

# 1. Lancer la pipeline en dry-run
echo "[1/4] Lancement de la pipeline (dry-run)..."
python3 -m pipeline --reset-state --submit-dry-run 2>&1 | tee /tmp/pipeline_benchmark.log
echo ""

# 2. Verifier les detections
echo "[2/4] Verification des detections..."
python3 -c "
import json, sys
with open('detections.json') as f:
    dets = json.load(f)

print(f'Nombre de detections: {len(dets)}')
expected = {'credential_stuffing', 'ssh_brute_force', 'sql_injection', 'directory_traversal', 'ssrf'}
found = {d.get('challenge_id') for d in dets}
missing = expected - found
extra = found - expected

if missing:
    print(f'MANQUANTES: {missing}')
    sys.exit(1)
if extra:
    print(f'ATTENTION faux positifs: {extra}')

for d in dets:
    cid = d.get('challenge_id', '?')
    dts = d.get('detection_time_seconds', -1)
    det = d.get('detection', {})
    print(f'  {cid}: {det.get(\"attack_type\")} | IPs={det.get(\"attacker_ips\")} | dts={dts}s')
    if dts != 0:
        print(f'    INFO: detection_time_seconds={dts} (mode finale attendu: 0)')
    else:
        print(f'    OK: detection_time_seconds=0 (mode finale)')

print()
print('Toutes les detections DS1 sont presentes!' if not missing else 'ECHEC')
"
echo ""

# 3. Valider le format JSON
echo "[3/4] Validation du format JSON..."
python3 -c "
import json, re, sys
with open('detections.json') as f:
    dets = json.load(f)

ts_re = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
errors = []
for i, d in enumerate(dets):
    cid = d.get('challenge_id', '')
    if not cid:
        errors.append(f'[{i}] challenge_id manquant')
    det = d.get('detection', {})
    if not isinstance(det, dict):
        errors.append(f'[{i}] detection n est pas un objet')
        continue
    for tk in ('attack_start_time', 'attack_end_time'):
        tv = det.get(tk, '')
        if not ts_re.match(str(tv)):
            errors.append(f'[{i}] {tk} invalide: {tv}')
    if not isinstance(det.get('attacker_ips'), list):
        errors.append(f'[{i}] attacker_ips n est pas une liste')
    if not isinstance(det.get('victim_accounts'), list):
        errors.append(f'[{i}] victim_accounts n est pas une liste')
    if not isinstance(det.get('indicators'), dict):
        errors.append(f'[{i}] indicators n est pas un objet')
    dts = d.get('detection_time_seconds')
    if not isinstance(dts, int):
        errors.append(f'[{i}] detection_time_seconds n est pas un entier: {dts}')

if errors:
    for e in errors:
        print(f'ERREUR: {e}')
    sys.exit(1)
print(f'Format JSON valide pour {len(dets)} detection(s)')
"
echo ""

# 4. Comparer avec le ground truth
echo "[4/4] Comparaison avec ground-truth-ds1.json..."
python3 -c "
import json
with open('detections.json') as f:
    dets = json.load(f)
with open('Dataset_log/ground-truth-ds1.json') as f:
    gt = json.load(f)

for cid, truth in gt.items():
    found = [d for d in dets if d.get('challenge_id') == cid]
    if not found:
        print(f'{cid}: NON DETECTE')
        continue
    d = found[0]
    det = d.get('detection', {})
    gt_ips = set(truth.get('attacker_ips', []))
    det_ips = set(det.get('attacker_ips', []))
    ip_match = gt_ips == det_ips
    print(f'{cid}: IPs={\"OK\" if ip_match else f\"DIFF gt={gt_ips} det={det_ips}\"} | dts={d.get(\"detection_time_seconds\", \"?\")}s')
print()
print('Benchmark termine.')
" 2>/dev/null || echo "(ground-truth non disponible, skip)"

echo ""
echo "=== Benchmark termine ==="
