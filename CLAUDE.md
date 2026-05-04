# CLAUDE.md — Hackathon Cybersécurité CND (Phase Dev)

## Contexte du projet

Hackathon organisé par le CND (EPITA/ESGI/ECE dont je fais partie) — Avril 2026.

**Objectif** : Construire une pipeline IA qui ingère des logs bruts de cybersécurité, détecte des attaques, les analyse, et soumet les résultats via une API REST au format JSON standardisé. La partie front et backend pour afficher les résultats est déjà faite, mais concentre toi sur l'appel direct à l'API de scoring.

## Architecture

```
OpenSearch (index logs-raw, delta + search_after)
    → split_logs_frame()             ← auth / app / net / sys par log_source
    → 5 détecteurs ciblés            ← un par challenge DS1
    → deduplicate()                  ← évite les doublons (rare : IPs distinctes)
    → enrich_detections()            ← Bedrock obligatoire si ≥1 détection
    → apply_ds1_canonical_windows()  ← fenêtres DS1 (désactiver CND_DS1_CANONICAL_TIMELINE=0 en finale DS2)
    → detection_time_seconds        ← délai depuis preuve dans le batch (bonus < 300 s)
    → detections.json (+ API)      ← sortie locale ; ou --submit vers l'API
```

Déploiement planifié : voir `sam/` (EventBridge `rate(5 minutes)` → Lambda, curseur DynamoDB).

## Dataset

### Fichier local (optionnel — bench / import)
- **Path** : `Dataset_log/logs-raw-merged.parquet` (non utilisé par `pipeline.py` ; bench `scripts/benchmark_and_report.py`)
- **Taille** : 21 017 848 lignes, 33 colonnes
- **Attention** : Trop grand pour être chargé en RAM d'un coup — toujours lire par chunks avec `pyarrow.parquet.ParquetFile.iter_batches()`

Dans le futur, il faudra que ce soit un appel API REST (POST) vers OpenSearch.

### Schema des logs (33 colonnes)

| Colonne | Type | Description |
|---|---|---|
| `timestamp` | datetime UTC | Horodatage de l'événement |
| `log_source` | string | `network`, `authentication`, `application`, `system` |
| `source_ip` | string | IP source |
| `destination_ip` | string | IP destination |
| `source_port` | int | Port source |
| `destination_port` | int | Port destination |
| `protocol` | string | `tcp`, `udp`, `icmp` |
| `action` | string | `accept`, `reject` |
| `bytes_sent` | int | Octets envoyés |
| `bytes_received` | int | Octets reçus |
| `packets` | int | Nombre de paquets |
| `duration_ms` | int | Durée de la connexion (ms) |
| `username` | string | Utilisateur (auth logs) |
| `auth_method` | string | Méthode d'auth (`web`, `ssh`, etc.) |
| `status` | string | `success`, `failure` |
| `hostname` | string | Nom de l'hôte cible |
| `session_id` | string | Identifiant de session |
| `failure_reason` | string | `invalid_password`, `account_not_found`, `invalid_key`, `expired_token`, `account_locked` |
| `geolocation_lat/lon` | float | Coordonnées géographiques |
| `geolocation_country` | string | Pays de la connexion |
| `http_method` | string | `GET`, `POST`, `PUT`, `DELETE`, `HEAD` |
| `uri` | string | URI de la requête HTTP |
| `status_code` | int | Code HTTP (200, 401, 404, 5xx…) |
| `response_size` | int | Taille de la réponse |
| `user_agent` | string | User-Agent HTTP |
| `referer` | string | Referer HTTP |
| `response_time_ms` | int | Temps de réponse (ms) |
| `severity` | string | `info`, `notice`, `warning`, `error`, `critical` |
| `process` | string | Nom du processus système |
| `pid` | int | PID du processus |
| `message` | string | Message système brut |
| `facility` | string | Facility syslog |

### Flux continu (OpenSearch — Phase Dev + Finale)
- **Index** : `logs-raw`
- **Fréquence** : toutes les 5 minutes, 50-100 logs par batch
- **Timeline** : continue après le 31 janvier 2026

## Ground Truth DS1 — 5 challenges cibles

Ces 5 attaques sont les seules présentes dans le dataset DS1. La pipeline doit les détecter toutes et uniquement elles.

| Challenge ID | Type | IPs attaquantes | Victime | Fenêtre | Points max |
|---|---|---|---|---|---|
| `credential_stuffing` | Credential stuffing → web shell → reverse shell | 203.0.113.45, 198.51.100.23 | jdupont | 06/01 02h00 → 06h00 | 100 |
| `ssh_brute_force` | Brute force SSH → lateral movement → priv_esc | 45.33.32.156, 198.51.100.89 | sysadmin | 11/01 01h00 → 07h00 | 100 |
| `sql_injection` | SQLi → exfiltration ~25 MB | 185.220.101.45 | aucun | 19/01 14h00 → 17h00 | 100 |
| `directory_traversal` | Path traversal → lecture fichiers sensibles | 198.51.100.200 | aucun | 23/01 10h00 → 12h00 | 80 |
| `ssrf` | SSRF → accès metadata + services internes | 203.0.113.100 | aucun | 26/01 11h00 → 12h00 | 80 |

Attention, dans le `Dataset_log\ground-truth-ds1.json` il y a uniquement 1 erreur pour chaque type possible, mais c'est très probable que dans le dataset global `Dataset_log\logs-raw-merged.parquet`, il y en ai plus bien sûr ! Il faut donc ajuster la sensibilité en fonction de si c'est une attaque ou non de façon intelligente.

### Indicateurs IoC attendus par challenge

**credential_stuffing** — sources : auth + application + network + system
- `failed_logins` : ~3500 (auth failures + 401 HTTP combinés)
- `web_shell` : `/uploads/image_2026.php`
- `reverse_shell_port` : 4444
- `geolocation` : `Beijing`

**ssh_brute_force** — sources : auth + system + network
- `total_ssh_failures` : ~4600
- `lateral_targets` : `app-prod-01`, `app-prod-02`, `db-prod-01`, `web-prod-01`
- `priv_esc` : `sudo + backdoor user`
- `exfil_port` : `443/8443`

**sql_injection** — sources : application + network + system
- `sqli_requests` : ~300
- `exfil_bytes` : ~25 000 000 octets (~25 MB)
- `tool_signature` : `Chrome-like UA with automated patterns`

**directory_traversal** — sources : application + network + system
- `traversal_attempts` : N tentatives
- `successful_reads` : ~75
- `traversal_patterns` : `../`
- `sensitive_files` : `/etc/passwd`, `/etc/shadow`, `/root/.ssh`

**ssrf** — sources : application + network + system
- `ssrf_targets` : `10.0.3.10:3306`, `10.0.4.10:389`, `169.254.169.254`
- `internal_traffic_from_web` : `true`

## Format de soumission

```json
{
  "challenge_id": "credential_stuffing",
  "detection": {
    "attack_type": "credential_stuffing",
    "attacker_ips": ["203.0.113.45", "198.51.100.23"],
    "victim_accounts": ["jdupont"],
    "attack_start_time": "2026-01-06T02:00:00Z",
    "attack_end_time": "2026-01-06T06:00:00Z",
    "indicators": {
      "failed_logins": 3500,
      "web_shell": "/uploads/image_2026.php",
      "reverse_shell_port": 4444,
      "geolocation": "Beijing"
    }
  },
  "detection_time_seconds": 180
}
```

- Timestamps : ISO 8601, timezone UTC
- `victim_accounts` : liste vide `[]` si aucun compte ciblé
- Chaque challenge est soumis séparément avec son propre `challenge_id`

## Système de scoring

| Critère | Points | Notes |
|---|---|---|
| Type d'attaque | 20 pts | Match exact = 100%, même famille = 50% |
| IPs attaquant | 20 pts | Score F1 |
| Comptes victimes | 20 pts | Score F1 (gratuit si aucun dans le ground truth) |
| Timeline | 20 pts | Tolérance ±5 min, 0 pts au-delà de ±10 min |
| Indicateurs IoC | 20 pts | Matching par clé avec tolérance |
| **Bonus rapidité** | +50 pts | Si détection < 5 minutes |
| **Pénalité faux positifs** | -10 pts/FP | Par faux positif déclaré |
| **TOTAL MAX** | **150 pts** | |

**Seuil de validation** : 70 pts (soumissions en dessous ignorées du leaderboard)

## Infra AWS disponible

- **Amazon OpenSearch** : accès read-only à l'index `logs-raw` (région `eu-west-3`)
- **Amazon Bedrock** : Claude Opus 4.6 (`anthropic.claude-opus-4-6-v1`) via `boto3`
- **Amazon SageMaker** : notebooks + endpoints (`ml.t3.xlarge`, `ml.g4dn.xlarge`)
- **AWS Lambda** : fonctions serverless pour la pipeline temps réel
- **Amazon S3** : stockage modèles et données
- **Amazon DynamoDB** : cache de résultats

```python
# Exemple appel Bedrock
import boto3
client = boto3.client("bedrock-runtime", region_name="eu-west-3")
response = client.converse(
    modelId="anthropic.claude-opus-4-6-v1",
    messages=[{"role": "user", "content": [{"text": "prompt ici"}]}],
    inferenceConfig={"maxTokens": 4096}
)
```

## Environnement Python local

- Venv : `c:\0-Code_py_temp\pytorch_cuda_env\Scripts\python.exe`
- Lire le parquet par chunks (OOM sinon) :
```python
import pyarrow.parquet as pq
pf = pq.ParquetFile('Dataset_log/logs-raw-merged.parquet')
for batch in pf.iter_batches(batch_size=100_000):
    df = batch.to_pandas()
    # traitement...
```

---

## Pipeline de detection

### Structure du projet

```text
ILab_Hackathon-CND-Phase2/
├── config.py                  ← Tous les parametres (API, seuils, AWS)
├── pipeline.py                ← Point d'entree : OpenSearch + detecteurs + Bedrock
├── pipeline_core.py           ← split_logs_frame + run_detectors (partage scripts)
├── detection_run.py           ← Chaine dedup / Bedrock / soumission batch
├── detection_timing.py        ← detection_time_seconds (bonus rapidite)
├── submit.py                  ← Soumet detections.json a l'API de scoring
├── bedrock_analysis.py        ← Enrichissement Bedrock (Claude Opus)
├── ds1_timeline.py            ← Normalisation fenêtres DS1 après enrichissement
├── opensearch_state.py        ← Curseur poll (fichier ou DynamoDB)
├── realtime_pipeline.py       ← Alias vers pipeline.run_realtime_compat
├── opensearch_connector.py    ← Connecteur OpenSearch
├── sam/                       ← SAM (Lambda + EventBridge + table curseur)
├── detections.json            ← Genere par pipeline.py (a reviewer avant soumission)
├── scores_history.json        ← Historique des scores par soumission
├── ground-truth-ds1.json      ← Ground truth officiel des 5 challenges DS1
└── detectors/
    ├── credential_stuffing.py ← Challenge 1 : auth failures + 401 → web shell + reverse shell
    ├── ssh_brute_force.py     ← Challenge 2 : SSH brute force → lateral + priv_esc
    ├── sql_injection.py       ← Challenge 3 : SQLi dans les URIs → exfil
    ├── directory_traversal.py ← Challenge 4 : ../ dans les URIs → fichiers sensibles
    ├── ssrf.py                ← Challenge 5 : IPs internes dans les URIs → metadata
    ├── dedup.py               ← Deduplication des detections qui se chevauchent
    └── utils.py               ← fmt_ts(), split_sessions(), group_ips_by_overlap()
```

### Workflow

```bash
# 1. Remplir config.py + .env (SCORING_API_URL, SCORING_API_KEY, OPENSEARCH_HOST, credentials Basic)
# 2. Une passe OpenSearch -> detections.json (+ API JSON)
python pipeline.py
#    python pipeline.py --max-docs 10000
#    python pipeline.py --loop --poll-interval 300
#    python pipeline.py --submit              # soumettre chaque detection tout de suite
#    python pipeline.py --submit-dry-run
#    python pipeline.py --reset-state       # curseur au debut flux DS2

# 3. Verifier les detections avant envoi (fichier genere)
python submit.py --dry-run

# 4. Soumettre toutes les detections du fichier
python submit.py

# 5. Soumettre une seule detection (par index ou challenge_id)
python submit.py --index 0

# 6. Lambda (infra) — voir sam/README.md
#    cd sam && sam build --template-file template.yaml && sam deploy --guided
```

### Detecteurs implementes

| Detecteur | Sources | Signal principal | Challenge ID |
| --- | --- | --- | --- |
| `credential_stuffing` | auth + app + net | N 401 HTTP + N echecs auth non-SSH → groupe les IPs en campagne, detecte web shell et reverse shell | `credential_stuffing` |
| `ssh_brute_force` | auth + sys + net | N echecs auth avec `auth_method=ssh` → groupe les IPs, detecte lateral/priv_esc/exfil | `ssh_brute_force` |
| `sql_injection` | app | URI contient keywords SQL (`UNION`, `SELECT`, `'`, `--`…) | `sql_injection` |
| `directory_traversal` | app | URI contient `../` ou variantes encodees | `directory_traversal` |
| `ssrf` | app + net | URI contient IP interne ou `169.254.169.254` | `ssrf` |

> **Note** : `credential_stuffing` et `ssh_brute_force` utilisent `group_ips_by_overlap()` pour fusionner les IPs attaquant dans la même fenêtre temporelle en une seule détection multi-IP. Tolérance : `CAMPAIGN_OVERLAP_MINUTES = 90`.

### Calibrage des seuils (config.py)

Augmenter un seuil → moins de détections → moins de faux positifs (`-10 pts/FP`).

```python
# Credential stuffing
CREDENTIAL_STUFFING_MIN_401     = 20   # 401 HTTP + echecs auth non-SSH minimum
CAMPAIGN_OVERLAP_MINUTES        = 90   # tolerance (min) pour grouper deux IPs en campagne

# SSH brute force
SSH_BRUTE_FORCE_MIN_FAILURES    = 20   # echecs SSH minimum par IP

# SQL injection
SQL_INJECTION_MIN_REQUESTS      = 5    # requetes avec payload SQL minimum

# Directory traversal
DIRECTORY_TRAVERSAL_MIN_ATTEMPTS = 3  # tentatives de traversal minimum

# SSRF
SSRF_MIN_REQUESTS               = 3   # requetes avec IP interne dans l URI minimum
```

### Configuration API (config.py)

```python
SCORING_API_URL     = "https://..."     # URL POST de l'API
SCORING_API_KEY     = ""                # cle API si requise
SCORING_API_HEADERS = { ... }           # headers (Content-Type deja configure)
```

`submit.py` gere automatiquement l'injection du header `Authorization: Bearer <key>` si `SCORING_API_KEY` est renseigné. Le score de chaque soumission est affiché avec breakdown détaillé et accumulé dans `scores_history.json`.

### Timeline DS1 et variables d'environnement

- Par défaut, `CND_DS1_CANONICAL_TIMELINE=1` : après Bedrock, `attack_start_time` / `attack_end_time` des 5 challenges DS1 sont remplacés par les bornes officielles du brief (voir `config.DS1_CANONICAL_ATTACK_WINDOWS` et `ds1_timeline.py`). Désactiver sur un autre dataset : `CND_DS1_CANONICAL_TIMELINE=0`.
- Sans détection après dedup, la pipeline n'appelle pas Bedrock et écrit quand même `detections.json` (liste vide).
- **Bonus rapidité** : `detection_time_seconds` est recalculé après enrichissement comme le nombre de secondes entre le plus ancien log du batch attribuable aux `attacker_ips` et l’instant de fin de traitement (voir `detection_timing.py`).

---

## Checklist jour J

### Credentials & accès

- [ ] Activer le compte SSO AWS (email d'invitation)
- [ ] Configurer `aws configure sso` (region `eu-west-3`)
- [ ] Vérifier l'accès à la console AWS

### config.py — valeurs à remplir

- [ ] `SCORING_API_URL` — URL POST de l'API de scoring
- [ ] `SCORING_API_KEY` — clé API si requise (laisser vide sinon)
- [ ] `OPENSEARCH_HOST` — URL de l'instance OpenSearch
- [ ] Adapter `SCORING_API_HEADERS` si le format d'auth diffère de `Bearer`

### Calibrage

- [ ] Lancer `python pipeline.py` (OpenSearch + Bedrock si détections ; optionnel : `python compare_ds1_timeline.py` sur un export local aligné avec le GT DS1)
- [ ] Vérifier dans `detections.json` que les 5 challenges sont détectés (ni plus, ni moins)
- [ ] Si faux positifs → augmenter les seuils (`*_MIN_*`) dans `config.py`
- [ ] Si challenge manqué → baisser le seuil correspondant ou inspecter les logs
- [ ] Vérifier que `BEDROCK_ENABLED = True` et que les credentials AWS donnent accès à Bedrock

### Pipeline temps réel

- [ ] Tester `python pipeline.py --submit-dry-run` ou `realtime_pipeline.py --dry-run` (alias boucle + soumission dry-run)
- [ ] Lancer `python pipeline.py --loop --submit` (ou `realtime_pipeline.py` sans dry-run) ; curseur fichier `.opensearch_state.json` ou DynamoDB (`OPENSEARCH_STATE_BACKEND`)
- [ ] Déployer `sam/` pour EventBridge 5 min + Lambda (curseur DynamoDB)

### Soumission

- [ ] Faire un `python submit.py --dry-run` pour relire les payloads avant envoi
- [ ] Soumettre avec `python submit.py` et vérifier les scores dans la console
- [ ] Consulter `scores_history.json` pour comparer les itérations et ajuster les seuils
