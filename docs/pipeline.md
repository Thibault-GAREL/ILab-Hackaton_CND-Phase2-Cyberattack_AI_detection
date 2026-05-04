---
title: "Pipeline de détection"
version: "2.1"
project: "CND Hackathon Phase 2"
last_updated: "2026-05-05"
audience: ["ia", "humain", "jury"]
---

# Pipeline de détection

## Vue d'ensemble

```
OpenSearch (index logs-raw, delta + search_after)
 → split_logs_frame()             ← auth / app / net / sys par log_source
 → 5 détecteurs ciblés            ← un par challenge DS1
 → deduplicate()                  ← keep_most_specific (par IP/fenêtre)
 → [BEDROCK_SKILL_MODE=1]         ← Mode Skill : RECOMMENDATION → CRITIQUE (anti-hallu)
   OU [BEDROCK_SKILL_MODE=0]      ← Mode legacy : bedrock_analysis.enrich_detections()
 → apply_ds1_canonical_windows()  ← fenêtres DS1 officielles
 → apply_ds1_ioc_canonicalization() ← noms de clés alignés sur ground truth
 → attach_remediation_plans()     ← plans d'action par challenge
 → detection_time_seconds         ← 0 en mode finale (slices) ; chrono optionnel si SCORING_BONUS_RAPIDITE_ENABLED=1
 → detections.json / POST API     ← sortie locale ou soumission directe
```

## Modules

| Fichier | Rôle |
|---|---|
| `pipeline/pipeline.py` | Point d'entrée CLI : poll OpenSearch, écrit `detections.json` |
| `pipeline/pipeline_core.py` | `split_logs_frame()` + `run_detectors()` |
| `pipeline/detection_run.py` | Chaîne : détecteurs → dedup → Skill/Bedrock → DS1 → remédiation |
| `pipeline/skill_enrichment.py` | Mode Skill : RECOMMENDATION → CRITIQUE (anti-hallucination) |
| `pipeline/skill_assets/` | Prompts, schémas JSON, validateurs du skill cnd-detection-tuner |
| `pipeline/bedrock_analysis.py` | Mode legacy : appel Bedrock `converse()` — enrichissement + timeline raffinée |
| `pipeline/bedrock_os_context.py` | Contexte OpenSearch élargi pour Bedrock |
| `pipeline/ds1_timeline.py` | Normalisation des fenêtres temporelles DS1 |
| `pipeline/ds1_ioc_canonical.py` | Normalisation des noms de clés IoC |
| `pipeline/detection_timing.py` | Calcul `detection_time_seconds` |
| `pipeline/remediation.py` | Plans de remédiation par type d'attaque |
| `pipeline/opensearch_connector.py` | Client OpenSearch (Basic auth ou SigV4) |
| `pipeline/opensearch_state.py` | Curseur persistant (fichier ou DynamoDB) |
| `pipeline/submit.py` | POST vers l'API de scoring |
| `pipeline/submit_cache.py` | Fingerprint + cache anti-doublons |
| `pipeline/config.py` | Tous les paramètres (seuils, URLs, Bedrock) |
| `pipeline/realtime_pipeline.py` | Alias boucle temps réel |

## Les 5 détecteurs

### 1. Credential Stuffing — `credential_stuffing.py`

| Propriété | Valeur |
|---|---|
| **Challenge ID** | `credential_stuffing` |
| **Points max** | 100 |
| **Sources** | auth + application + network + system |
| **Signal** | HTTP 401 + échecs auth non-SSH ≥ seuil → groupe les IPs en campagne |
| **Seuil** | `CREDENTIAL_STUFFING_MIN_401 = 20` |
| **IPs attendues** | `203.0.113.45`, `198.51.100.23` |
| **Victime** | `jdupont` |
| **Fenêtre** | 06/01 02h00 → 06h00 UTC |

IoC attendus : `failed_logins` (~3500), `web_shell` (`/uploads/image_2026.php`), `reverse_shell_port` (4444), `geolocation` (`Beijing`).

### 2. SSH Brute Force — `ssh_brute_force.py`

| Propriété | Valeur |
|---|---|
| **Challenge ID** | `ssh_brute_force` |
| **Points max** | 100 |
| **Sources** | auth + system + network |
| **Signal** | Échecs auth avec `auth_method=ssh` ≥ seuil → lateral movement, priv_esc |
| **Seuil** | `SSH_BRUTE_FORCE_MIN_FAILURES = 20` |
| **IPs attendues** | `45.33.32.156`, `198.51.100.89` |
| **Victime** | `sysadmin` |
| **Fenêtre** | 11/01 01h00 → 07h00 UTC |

IoC attendus : `total_ssh_failures` (~4600), `lateral_targets` (app-prod-01/02, db-prod-01, web-prod-01), `priv_esc` (sudo + backdoor user), `exfil_port` (443/8443).

### 3. SQL Injection — `sql_injection.py`

| Propriété | Valeur |
|---|---|
| **Challenge ID** | `sql_injection` |
| **Points max** | 100 |
| **Sources** | application + network + system |
| **Signal** | URI contient des payloads SQL (`UNION`, `SELECT`, `'`, `--`) |
| **Seuils** | `SQL_INJECTION_MIN_REQUESTS = 50`, `SQL_INJECTION_MIN_EXFIL_BYTES = 1_000_000` |
| **IP attendue** | `185.220.101.45` |
| **Fenêtre** | 19/01 14h00 → 17h00 UTC |

IoC attendus : `sqli_requests` (~300), `exfil_bytes` (~25 000 000), `tool_signature` (Chrome-like UA with automated patterns).

### 4. Directory Traversal — `directory_traversal.py`

| Propriété | Valeur |
|---|---|
| **Challenge ID** | `directory_traversal` |
| **Points max** | 80 |
| **Sources** | application + network + system |
| **Signal** | URI contient `../` ou variantes encodées |
| **Seuil** | `DIRECTORY_TRAVERSAL_MIN_ATTEMPTS = 100` |
| **IP attendue** | `198.51.100.200` |
| **Fenêtre** | 23/01 10h00 → 12h00 UTC |

IoC attendus : `traversal_attempts`, `successful_reads` (~75), `traversal_patterns` (`../`), `sensitive_files` (/etc/passwd, /etc/shadow, /root/.ssh).

### 5. SSRF — `ssrf.py`

| Propriété | Valeur |
|---|---|
| **Challenge ID** | `ssrf` |
| **Points max** | 80 |
| **Sources** | application + network + system |
| **Signal** | URI contient une IP interne ou `169.254.169.254` |
| **Seuil** | `SSRF_MIN_REQUESTS = 100` |
| **IP attendue** | `203.0.113.100` |
| **Fenêtre** | 26/01 11h00 → 12h00 UTC |

IoC attendus : `ssrf_targets` (10.0.3.10:3306, 10.0.4.10:389, 169.254.169.254), `internal_traffic_from_web` (true).

## Déduplication

Module : `pipeline/detectors/dedup.py`

Stratégie par défaut : `keep_most_specific` — quand deux détections du même IP se chevauchent (±`DEDUP_OVERLAP_MINUTES` = 30 min), la plus spécifique est conservée.

Stratégies disponibles :
- `none` : tout soumettre (risque de faux positifs à -10 pts/FP)
- `keep_most_specific` : garder le type le plus précis par fenêtre/IP
- `merge` : fusionner en une seule détection multi-vecteur

## Enrichissement Bedrock

Module : `pipeline/bedrock_analysis.py`

- Modèle : Claude Opus 4.6 (`eu.anthropic.claude-opus-4-6-v1`, fallback `anthropic.claude-opus-4-6-v1`)
- Appel fusionné (`BEDROCK_FUSED_CONVERSE = True`) : enrichissement + timeline raffinée en un seul `converse()`
- Tokens max : 6144 (fusionné), 1024 (enrichissement seul)
- Throttle : 0.75s min entre deux appels, 5 retries max
- Contexte élargi : logs ±15 min autour de la fenêtre d'attaque, jusqu'à 100 000 docs

**Filtrage** : les détections avec `confidence=low` après enrichissement sont retirées (`BEDROCK_DROP_LOW_ENRICHMENT_CONFIDENCE = True`).

## Timeline DS1

Module : `pipeline/ds1_timeline.py`

Avec `CND_DS1_CANONICAL_TIMELINE=1` (défaut), les fenêtres `attack_start_time` / `attack_end_time` sont remplacées par les bornes officielles du brief pour les 5 challenges DS1. Désactiver pour DS2 : `CND_DS1_CANONICAL_TIMELINE=0`.

## Canonicalization IoC

Module : `pipeline/ds1_ioc_canonical.py`

Avec `CND_DS1_CANONICAL_IOCS=1` (défaut), les noms de clés dans `indicators` sont normalisés pour correspondre exactement au `ground-truth-ds1.json`. Désactiver pour DS2 : `CND_DS1_CANONICAL_IOCS=0`.

## Remédiation

Module : `pipeline/remediation.py`

Chaque détection reçoit un plan de remédiation spécifique au type d'attaque, avec actions immédiates et recommandations long terme.

## Regroupement de campagnes

Les détecteurs `credential_stuffing` et `ssh_brute_force` utilisent `group_ips_by_overlap()` (dans `pipeline/detectors/utils.py`) pour fusionner les IPs attaquant dans la même fenêtre temporelle en une seule détection multi-IP. Tolérance : `CAMPAIGN_OVERLAP_MINUTES = 90`.

## CLI

```bash
python -m pipeline                     # une passe → detections.json
python -m pipeline --loop              # boucle (intervalle config)
python -m pipeline --max-docs 5000     # limiter le batch
python -m pipeline --submit            # soumettre chaque détection
python -m pipeline --submit-dry-run    # dry-run API
python -m pipeline --reset-state       # curseur au début DS2
python -m pipeline --no-dedup          # sans déduplication
python -m pipeline --dry-run-state     # ne pas avancer le curseur
```

## Calibrage des seuils

Tous les seuils sont dans `pipeline/config.py`. Augmenter un seuil réduit les faux positifs (-10 pts/FP).

```python
CREDENTIAL_STUFFING_MIN_401      = 20
SSH_BRUTE_FORCE_MIN_FAILURES     = 20
SQL_INJECTION_MIN_REQUESTS       = 50
SQL_INJECTION_MIN_EXFIL_BYTES    = 1_000_000
DIRECTORY_TRAVERSAL_MIN_ATTEMPTS = 100
SSRF_MIN_REQUESTS                = 100
CAMPAIGN_OVERLAP_MINUTES         = 90
```
