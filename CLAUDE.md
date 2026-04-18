# CLAUDE.md — Hackathon Cybersécurité CND (Phase Dev)

## Contexte du projet

Hackathon organisé par le CND (EPITA/ESGI/ECE dont je fais partie) — Avril 2026.

**Objectif** : Construire une pipeline IA qui ingère des logs bruts de cybersécurité, détecte des attaques, les analyse, et soumet les résultats via une API REST au format JSON standardisé. La partie front et backend pour afficher les résultats est déjà faite, mais concentre toi sur l'appel direct à l'API de scoring.

## Architecture attendue de l'application

```
OpenSearch (logs-raw / .parquet télécharger du site)
    → Détection (règles + IA)
    → Analyse (type, IPs, timeline, IoC)
    → Soumission JSON via API REST
    → Propositions de remédiation (futur avec l'exemple appel Bedrock plus bas où on lui donne le json de soumission)
```

## Dataset

### Fichier local (Phase Dev)
- **Path** : `Dataset_log/logs-raw-merged.parquet`
- **Taille** : 21 017 848 lignes, 33 colonnes
- **Attention** : Trop grand pour être chargé en RAM d'un coup — toujours lire par chunks avec `pyarrow.parquet.ParquetFile.iter_batches()`

Dans le futur, il faudra que ce soit un appel API REST (POST).

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

## Format de soumission

```json
{
  "challenge_id": "NOM_DU_CHALLENGE",
  "detection": {
    "attack_type": "type_attaque_detectee",
    "attacker_ips": ["ip1", "ip2"],
    "victim_accounts": ["user1"],
    "attack_start_time": "2026-01-06T02:00:00Z",
    "attack_end_time": "2026-01-06T06:00:00Z",
    "indicators": {
      "cle1": "valeur1",
      "cle2": 42
    }
  },
  "detection_time_seconds": 180
}
```

- Timestamps : ISO 8601, timezone UTC
- `victim_accounts` : liste vide `[]` si aucun compte ciblé
- Soumission via POST à l'API REST (URL communiquée par les organisateurs)

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
for batch in pf.iter_batches(batch_size=50000):
    df = batch.to_pandas()
    # traitement...
```

## Signaux d'attaques observés dans les données

Observés sur un échantillon de 10 000 logs :
- **Auth failures massives** : 60% de `status=failure`, dominé par `invalid_password` → brute force probable
- **Ratio 401 HTTP élevé** : 1311 / 2847 requêtes HTTP retournent 401 → credential stuffing
- **IP externe suspecte** : `203.0.113.45` génère beaucoup de `reject` réseau
- **User-agents scripts** : `curl/7.88.1`, `python-requests/2.31.0` en masse
- **Ports ciblés** : SSH (22), HTTPS (443), MySQL (3306), SMTP (587) — surface d'attaque variée

---

## Pipeline de detection construite

### Structure du projet

```text
ILab_Hackathon-CND-Phase2/
├── config.py          ← Tous les parametres (CHALLENGE_ID, API, seuils)
├── pipeline.py        ← Point d'entree : lit le parquet, lance les detecteurs
├── submit.py          ← Soumet detections.json a l'API de scoring
├── detections.json    ← Genere par pipeline.py (a reviewer avant soumission)
├── scores_history.json← Historique des scores par soumission (iterations)
└── detectors/
    ├── brute_force.py
    ├── credential_stuffing.py
    ├── port_scan.py
    ├── network_recon.py
    └── utils.py       ← fmt_ts(), split_sessions()
```

### Workflow

```bash
# 1. Remplir config.py (CHALLENGE_ID, SCORING_API_URL, SCORING_API_KEY)
# 2. Lancer la detection sur le dataset complet (~5-10 min)
python pipeline.py

# 3. Verifier les detections avant envoi
python submit.py --dry-run

# 4. Soumettre toutes les detections
python submit.py

# 5. Soumettre une seule detection (par index)
python submit.py --index 0
```

### Detecteurs heuristiques implementes

| Detecteur | Log source | Signal detecte | Fichier |
| --- | --- | --- | --- |
| `brute_force` | `authentication` | N echecs auth (status=failure) depuis la meme IP par session | `detectors/brute_force.py` |
| `credential_stuffing` | `application` | N reponses 401 HTTP depuis la meme IP, souvent avec user-agents scripts | `detectors/credential_stuffing.py` |
| `port_scan` | `network` | IP externe → N ports distincts avec taux de reject eleve | `detectors/port_scan.py` |
| `network_recon` | `network` | IP externe → N connexions rejetees en rafale (recon avant attaque) | `detectors/network_recon.py` |

### Attaques confirmees sur echantillon (300k logs)

| Type | IP attaquante | Timeline | Detail |
| --- | --- | --- | --- |
| `network_recon` | `203.0.113.45` | 06/01 02h01 → 02h59 | Recon reseau avant l'attaque principale |
| `brute_force` | `203.0.113.45` | 06/01 03h02 → 04h55 | 800 echecs web (invalid_password) |
| `brute_force` | `198.51.100.23` | 06/01 03h02 → 04h56 | 346 echecs web |
| `brute_force` | `198.51.100.89` | 11/01 01h00 → 02h57 | 599 echecs SSH (invalid_key) |
| `brute_force` | `45.33.32.156` | 11/01 01h00 → 02h57 | SSH |
| `credential_stuffing` | `203.0.113.45` | 06/01 03h02 → 04h55 | 401 HTTP massifs |
| `credential_stuffing` | `198.51.100.23` | 06/01 03h02 → 04h56 | 401 HTTP massifs |

> Pattern notable : `203.0.113.45` fait d'abord du recon (2h01) puis lance brute force + credential stuffing (3h02) — attaque coordonnee en 2 phases.

### Calibrage de la sensibilite

Tous les seuils sont dans `config.py`. Augmenter = moins de detections = moins de faux positifs.

```python
BRUTE_FORCE_MIN_FAILURES    = 20    # echecs auth minimum par session/IP
CREDENTIAL_STUFFING_MIN_401 = 20    # 401 HTTP minimum par session/IP
PORT_SCAN_MIN_PORTS         = 10    # ports distincts minimum
PORT_SCAN_MIN_REJECT_RATIO  = 0.4   # ratio rejet/total minimum (0.0 a 1.0)
PORT_SCAN_EXTERNAL_ONLY     = True  # ignorer les IPs internes RFC-1918
NETWORK_RECON_MIN_REJECTS   = 15    # connexions rejetees minimum
SESSION_GAP_MINUTES         = 30    # gap pour separer deux sessions d'attaque
```

### Configuration API (config.py)

```python
CHALLENGE_ID        = "NOM_A_REMPLIR"   # communique par les organisateurs
SCORING_API_URL     = "https://..."     # URL POST de l'API
SCORING_API_KEY     = ""                # cle API si requise
SCORING_API_HEADERS = { ... }           # headers (Content-Type deja configure)
```

`submit.py` gere automatiquement l'injection du header `Authorization: Bearer <key>` si `SCORING_API_KEY` est renseigne. Le score de chaque soumission est affiche avec breakdown detaille, et accumule dans `scores_history.json` pour comparer les iterations.

---

## Taches a venir

### 1. Grid search des configurations (tuning automatique)

Ecrire un script `tune_config.py` qui teste toutes les combinaisons de seuils possibles et identifie les configurations qui maximisent le score (minimisent les faux positifs, maximisent la precision de la timeline).

Logique attendue :
- Definir une grille de valeurs pour chaque parametre sensible (`BRUTE_FORCE_MIN_FAILURES`, `SESSION_GAP_MINUTES`, `DEDUP_STRATEGY`, etc.)
- Lancer la pipeline de detection pour chaque combinaison
- Si le ground truth est disponible, calculer le score F1 simule
- Sinon, utiliser des metriques proxy (nb de detections, ratio IP externes/internes, couverture de la timeline)
- Sauvegarder le classement des configs dans `tune_results.json`

### 2. README du projet

Generer un README.md complet et synthetique en utilisant le skill `thibault-readme`.

Contenu attendu : architecture, prerequis, commandes pour lancer chaque composant (pipeline, realtime, submit), explication des parametres config, workflow jour J.

### 3. Checklist jour J — ce qu'il faut regler avant de lancer

Liste exhaustive de tout ce qui doit etre configure ou verifie au moment du hackathon :

#### Credentials & acces

- [ ] Activer le compte SSO AWS (email d'invitation)
- [ ] Configurer `aws configure sso` (region `eu-west-3`)
- [ ] Verifier l'acces a la console AWS

#### config.py — valeurs a remplir

- [ ] `CHALLENGE_ID` — communique par les organisateurs
- [ ] `SCORING_API_URL` — URL POST de l'API de scoring
- [ ] `SCORING_API_KEY` — cle API si requise (laisser vide sinon)
- [ ] `OPENSEARCH_HOST` — URL de l'instance OpenSearch
- [ ] Adapter `SCORING_API_HEADERS` si le format d'auth differe de `Bearer`

#### Calibrage

- [ ] Relancer `pipeline.py --no-bedrock` sur le dataset complet apres avoir vu le ground truth
- [ ] Ajuster les seuils (`BRUTE_FORCE_MIN_FAILURES`, `DEDUP_STRATEGY`, `*_EXTERNAL_ONLY`) selon les premiers scores obtenus
- [ ] Verifier que `BEDROCK_ENABLED = True` et que les credentials AWS donnent acces a Bedrock

#### Pipeline temps reel

- [ ] Tester `realtime_pipeline.py --dry-run` pour valider la connexion OpenSearch
- [ ] Lancer `realtime_pipeline.py --reset` pour repartir depuis le debut du flux
- [ ] Verifier que `.opensearch_state.json` est cree et mis a jour

#### Soumission

- [ ] Faire un `python submit.py --dry-run` pour relire les payloads avant envoi
- [ ] Soumettre avec `python submit.py` et verifier les scores dans la console
- [ ] Consulter `scores_history.json` pour comparer les iterations

#### Vérification
- [ ] Lire l'input et l'output des logs pour voir si notre détection est bonne