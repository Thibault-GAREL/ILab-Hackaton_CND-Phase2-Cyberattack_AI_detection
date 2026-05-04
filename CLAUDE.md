# CLAUDE.md — Hackathon Cybersécurité CND (Phase 2)

## Contexte du projet

Hackathon organisé par le CND (EPITA/ESGI/ECE) — Mai 2026.

**Objectif** : Pipeline IA qui ingère des logs bruts de cybersécurité depuis OpenSearch, détecte 5 types d'attaques, enrichit via Bedrock Claude Opus 4.6, et soumet les résultats à l'API de scoring.

## Architecture

```
OpenSearch (index logs-raw, delta + search_after)
 → split_logs_frame()               ← auth / app / net / sys par log_source
 → 5 détecteurs ciblés              ← un par challenge DS1
 → deduplicate()                    ← keep_most_specific (par IP/fenêtre)
 → enrich_detections()              ← Bedrock si BEDROCK_ENABLED=1 (kill switch off)
 → apply_ds1_canonical_windows()    ← fenêtres DS1 (CND_DS1_CANONICAL_TIMELINE=0 pour DS2)
 → apply_ds1_ioc_canonicalization() ← noms de clés alignés sur ground truth
 → attach_remediation_plans()       ← plans d'action par type d'attaque
 → detection_time_seconds           ← 0 en finale ; chrono optionnel si SCORING_BONUS_RAPIDITE_ENABLED=1
 → detections.json (+ API)          ← sortie locale ; ou --submit vers l'API
```

## Structure du projet

```text
ILab-Hackaton_CND-Phase2-Cyberattack_AI_detection/
├── pipeline/                       ← Package Python — pipeline de détection
│   ├── __init__.py
│   ├── __main__.py                 ← python -m pipeline
│   ├── config.py                   ← Tous les paramètres (API, seuils, AWS)
│   ├── pipeline.py                 ← Point d'entrée : OpenSearch + détecteurs + Bedrock
│   ├── pipeline_core.py            ← split_logs_frame + run_detectors
│   ├── detection_run.py            ← Chaîne dedup / Bedrock / DS1 / soumission batch
│   ├── detection_timing.py         ← detection_time_seconds (0 par défaut, mode slices)
│   ├── detection_api.py            ← Conversion format API
│   ├── bedrock_analysis.py         ← Enrichissement Bedrock (Claude Opus 4.6)
│   ├── bedrock_os_context.py       ← Contexte OpenSearch élargi pour Bedrock
│   ├── ds1_timeline.py             ← Normalisation fenêtres DS1 après enrichissement
│   ├── ds1_ioc_canonical.py        ← Normalisation des clés IoC
│   ├── remediation.py              ← Plans de remédiation par challenge
│   ├── submit.py                   ← Soumet detections.json à l'API de scoring
│   ├── submit_cache.py             ← Fingerprint + cache anti-doublons
│   ├── opensearch_connector.py     ← Connecteur OpenSearch (Basic / SigV4)
│   ├── opensearch_state.py         ← Curseur poll (fichier ou DynamoDB)
│   ├── realtime_pipeline.py        ← Alias vers pipeline.run_realtime_compat
│   ├── compare_ds1_timeline.py     ← Comparaison timeline vs ground truth
│   └── detectors/                  ← 5 détecteurs DS1 + dedup + utils
│       ├── __init__.py
│       ├── credential_stuffing.py  ← Challenge 1 : auth failures + 401 → web shell + reverse shell
│       ├── ssh_brute_force.py      ← Challenge 2 : SSH brute force → lateral + priv_esc
│       ├── sql_injection.py        ← Challenge 3 : SQLi dans les URIs → exfil
│       ├── directory_traversal.py  ← Challenge 4 : ../ dans les URIs → fichiers sensibles
│       ├── ssrf.py                 ← Challenge 5 : IPs internes dans les URIs → metadata
│       ├── dedup.py                ← Déduplication des détections chevauchantes
│       └── utils.py                ← fmt_ts(), split_sessions(), group_ips_by_overlap()
├── backend/                        ← API FastAPI
│   └── src/app/
│       ├── main.py                 ← Application FastAPI
│       ├── config.py               ← Settings Pydantic
│       ├── security.py             ← Middleware sécurité
│       ├── routers/
│       │   ├── health.py           ← GET /health
│       │   └── logs.py             ← POST /v1/logs/search, GET /v1/logs/stats
│       ├── schemas/                ← Modèles Pydantic (ingest, prediction, topology, etc.)
│       ├── services/               ← Logique métier (modeling, planning, explainability, etc.)
│       └── utils/                  ← Helpers (seed, timers)
├── frontend/                       ← Interface Streamlit
│   ├── streamlit_app.py            ← Application principale (3 pages)
│   └── src/fixtures/               ← Données mockées pour le développement
├── sam/                            ← AWS SAM (Lambda + EventBridge + table curseur)
│   ├── template.yaml
│   └── handler.py
├── scripts/                        ← Benchmarks, vérifications, tests
│   ├── benchmark_and_report.py
│   ├── benchmark_opensearch_report.py
│   ├── smoke_bedrock_timeline.py
│   ├── test_ds1_ioc_canonical.py
│   └── opensearch_verify_sample.py
├── docs/                           ← Documentation complète
│   ├── README.md
│   ├── architecture.md
│   ├── pipeline.md
│   ├── api-reference.md
│   ├── deployment.md
│   └── scoring-format.md
├── datasets/results/               ← CSV classifiés (phase 1)
├── CLAUDE.md                       ← Ce fichier
└── README.md
```

**Imports** : Le package `pipeline/` utilise des imports relatifs (ex. `from .config import ...`, `from .detectors.dedup import ...`). Lancer la pipeline via `python -m pipeline` depuis la racine du projet.

## Dataset

### Flux continu (OpenSearch — Phase Dev + Finale)
- **Index** : `logs-raw`
- **Fréquence** : toutes les 5 minutes, 50-100 logs par batch
- **Region** : `eu-west-3`
- **Auth** : FGAC Basic (user `etudiant`)

### Fichier local (optionnel — bench)
- **Path** : `Dataset_log/logs-raw-merged.parquet`
- **Taille** : 21 017 848 lignes, 33 colonnes
- **Attention** : Trop grand pour la RAM — lire par chunks avec `pyarrow.parquet.ParquetFile.iter_batches()`

### Schéma des logs (33 colonnes)

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

## Ground Truth DS1 — 5 challenges cibles

| Challenge ID | Type | IPs attaquantes | Victime | Fenêtre | Points max |
|---|---|---|---|---|---|
| `credential_stuffing` | Credential stuffing → web shell → reverse shell | 203.0.113.45, 198.51.100.23 | jdupont | 06/01 02h00 → 06h00 | 100 |
| `ssh_brute_force` | Brute force SSH → lateral movement → priv_esc | 45.33.32.156, 198.51.100.89 | sysadmin | 11/01 01h00 → 07h00 | 100 |
| `sql_injection` | SQLi → exfiltration ~25 MB | 185.220.101.45 | aucun | 19/01 14h00 → 17h00 | 100 |
| `directory_traversal` | Path traversal → lecture fichiers sensibles | 198.51.100.200 | aucun | 23/01 10h00 → 12h00 | 80 |
| `ssrf` | SSRF → accès metadata + services internes | 203.0.113.100 | aucun | 26/01 11h00 → 12h00 | 80 |

### Indicateurs IoC attendus par challenge

**credential_stuffing** — sources : auth + application + network + system
- `failed_logins` : ~3500
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
- `exfil_bytes` : ~25 000 000
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
- Chaque challenge est soumis séparément

## Système de scoring

| Critère | Points | Notes |
|---|---|---|
| Type d'attaque | 20 pts | Match exact = 100%, même famille = 50% |
| IPs attaquant | 20 pts | Score F1 |
| Comptes victimes | 20 pts | Score F1 (gratuit si aucun dans le ground truth) |
| Timeline | 20 pts | Tolérance ±5 min, 0 pts au-delà de ±10 min |
| Indicateurs IoC | 20 pts | Matching par clé avec tolérance |
| **Pénalité faux positifs** | -10 pts/FP | Par faux positif déclaré |
| **TOTAL MAX** | **100 pts** | Par challenge (mode finale, 5 × 20 pts) |

**Seuil de validation** : 70 pts.

## Mode finale : ingestion par slices

Les logs sont injectés en **3 lots successifs** (slices). Le payload fixe **`detection_time_seconds = 0`** ; le score par challenge reste **100 pts** max (5 critères).

- `CND_DS1_CANONICAL_TIMELINE=0` et `CND_DS1_CANONICAL_IOCS=0` par défaut
- `SCORING_BONUS_RAPIDITE_ENABLED=0` par défaut
- `SUBMIT_SKIP_DUPLICATES=1` avec fingerprint robuste (challenge_id + IPs, sans fenêtres)
- Option `--accumulate` : merger les détections entre slices (fenêtres élargies)
- La pipeline peut être relancée après chaque lot ; le cache anti-doublons empêche les re-soumissions

## Infra AWS disponible

- **Amazon OpenSearch** : index `logs-raw` (région `eu-west-3`)
- **Amazon Bedrock** : Claude Opus 4.6 (`eu.anthropic.claude-opus-4-6-v1`) via `boto3`
- **Amazon SageMaker** : notebooks + endpoints
- **AWS Lambda** : pipeline temps réel (SAM)
- **Amazon S3** : stockage artefacts
- **Amazon DynamoDB** : curseur pipeline
- **ECS Fargate** : backend + frontend

```python
import boto3
client = boto3.client("bedrock-runtime", region_name="eu-west-3")
response = client.converse(
    modelId="eu.anthropic.claude-opus-4-6-v1",
    messages=[{"role": "user", "content": [{"text": "prompt ici"}]}],
    inferenceConfig={"maxTokens": 4096}
)
```

## Pipeline de détection

### Workflow

```bash
# Lancer la pipeline (une passe)
python -m pipeline

# Options
python -m pipeline --max-docs 10000
python -m pipeline --loop --poll-interval 300
python -m pipeline --submit
python -m pipeline --submit-dry-run
python -m pipeline --reset-state
python -m pipeline --no-dedup
```

### Détecteurs implémentés

| Détecteur | Sources | Signal principal | Challenge ID |
|---|---|---|---|
| `credential_stuffing` | auth + app + net | 401 HTTP + échecs auth non-SSH → campagne multi-IP | `credential_stuffing` |
| `ssh_brute_force` | auth + sys + net | Échecs SSH → lateral/priv_esc/exfil | `ssh_brute_force` |
| `sql_injection` | app | URI contient payloads SQL (`UNION`, `SELECT`, `'`, `--`) | `sql_injection` |
| `directory_traversal` | app | URI contient `../` ou variantes encodées | `directory_traversal` |
| `ssrf` | app + net | URI contient IP interne ou `169.254.169.254` | `ssrf` |

`credential_stuffing` et `ssh_brute_force` utilisent `group_ips_by_overlap()` pour fusionner les IPs en campagne. Tolérance : `CAMPAIGN_OVERLAP_MINUTES = 90`.

### Calibrage des seuils (pipeline/config.py)

```python
CREDENTIAL_STUFFING_MIN_401      = 20
SSH_BRUTE_FORCE_MIN_FAILURES     = 20
SQL_INJECTION_MIN_REQUESTS       = 50
SQL_INJECTION_MIN_EXFIL_BYTES    = 1_000_000
DIRECTORY_TRAVERSAL_MIN_ATTEMPTS = 100
SSRF_MIN_REQUESTS                = 100
CAMPAIGN_OVERLAP_MINUTES         = 90
```

### Soumission

```bash
python -m pipeline.submit --dry-run   # vérifier les payloads
python -m pipeline.submit             # soumettre tout
python -m pipeline.submit --index 0   # soumettre #0 uniquement
```

### Variables d'environnement clés

- `CND_DS1_CANONICAL_TIMELINE=1` : fenêtres DS1 officielles (désactiver pour DS2 : `=0`)
- `CND_DS1_CANONICAL_IOCS=1` : noms de clés IoC alignés sur ground truth (désactiver pour DS2 : `=0`)
- `BEDROCK_DROP_LOW_ENRICHMENT_CONFIDENCE=1` : retirer les détections `confidence=low`
- `OPENSEARCH_STATE_BACKEND=file|dynamodb` : stockage du curseur

## Backend FastAPI

Routes principales :
- `GET /health` — état du service
- `GET /v1/detections` — liste des détections
- `GET /v1/detections/{id}` — détail d'une détection
- `GET /v1/detections/stats/summary` — statistiques agrégées
- `POST /v1/pipeline/run` — déclencher un poll
- `GET /v1/remediation/catalog` — catalogue remédiation
- `GET /v1/remediation/{challenge_id}` — plan par type d'attaque
- `POST /v1/remediation/validate` — valider un plan

## Frontend Streamlit

3 pages : détections (tableau de bord), remédiation (plans d'action), architecture (diagramme).

## Checklist jour J

### Credentials & accès
- [ ] `aws configure sso` (region `eu-west-3`)
- [ ] Vérifier `aws sts get-caller-identity`

### Configuration (pipeline/.env)
- [ ] `OPENSEARCH_BASIC_PASSWORD`
- [ ] `SCORING_API_URL`
- [ ] `SCORING_API_KEY` (si requise)

### Calibrage
- [ ] `python -m pipeline` → vérifier `detections.json` (5 challenges exactement)
- [ ] Si faux positifs → augmenter les seuils dans `pipeline/config.py`
- [ ] Vérifier `BEDROCK_ENABLED = True`

### Pipeline temps réel
- [ ] `python -m pipeline --submit-dry-run` (test)
- [ ] `python -m pipeline --loop --submit` (production)

### Soumission
- [ ] `python -m pipeline.submit --dry-run`
- [ ] `python -m pipeline.submit`
- [ ] Consulter `scores_history.json`
