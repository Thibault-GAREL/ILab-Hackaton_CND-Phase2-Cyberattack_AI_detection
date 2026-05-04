---
title: "Référence API"
version: "2.0"
project: "CND Hackathon Phase 2"
last_updated: "2026-05-04"
audience: ["ia", "humain", "jury"]
---

# Référence API — Backend FastAPI

Base URL : `http://localhost:8080` (dev) ou URL ECS Fargate (prod).

Documentation interactive : `GET /docs` (Swagger UI).

## Endpoints

### Health

#### `GET /health`

Vérification de l'état du service.

```bash
curl http://localhost:8080/health
```

```json
{
  "status": "ok",
  "version": "1.0.0",
  "mode": "offline",
  "env": "development"
}
```

#### `GET /`

Endpoint racine.

```bash
curl http://localhost:8080/
```

```json
{
  "service": "DIRISI 2025 Hackathon Backend",
  "version": "1.0.0",
  "status": "operational",
  "docs": "/docs"
}
```

---

### Détections

#### `GET /v1/detections`

Liste toutes les détections depuis `detections_api.json`.

```bash
curl http://localhost:8080/v1/detections
```

```json
[
  {
    "id": "det-001",
    "challenge_id": "credential_stuffing",
    "attack_type": "credential_stuffing",
    "attacker_ips": ["203.0.113.45", "198.51.100.23"],
    "victim_accounts": ["jdupont"],
    "attack_start_time": "2026-01-06T02:00:00Z",
    "attack_end_time": "2026-01-06T06:00:00Z",
    "severity": "critical",
    "confidence": "high",
    "indicators": { "..." },
    "remediation": { "..." }
  }
]
```

#### `GET /v1/detections/{id}`

Détail d'une détection par identifiant.

```bash
curl http://localhost:8080/v1/detections/det-001
```

#### `GET /v1/detections/stats/summary`

Statistiques agrégées des détections.

```bash
curl http://localhost:8080/v1/detections/stats/summary
```

```json
{
  "total_detections": 5,
  "by_type": {
    "credential_stuffing": 1,
    "ssh_brute_force": 1,
    "sql_injection": 1,
    "directory_traversal": 1,
    "ssrf": 1
  },
  "by_severity": {
    "critical": 3,
    "high": 2
  }
}
```

---

### Pipeline

#### `POST /v1/detections/pipeline/run`

Lance une analyse : **OpenSearch** (`python -m pipeline`) ou **bench Parquet** (`scripts/run_pipeline_full_parquet.py`).

Champs utiles : `source` (`opensearch` | `parquet`), `max_lines` (plafond lignes), `accumulate`, `reset_state`, `dry_run_state`, `no_dedup`, `submit_dry_run`, `submit` (soumission live : exige `PIPELINE_ALLOW_SUBMIT=1` sur le backend), `parquet_path`, `parquet_batch_rows`, `bedrock_enabled`, `model_id`, `timeout_seconds`.

```bash
curl -X POST http://localhost:8080/v1/detections/pipeline/run \
  -H "Content-Type: application/json" \
  -d '{"source":"opensearch","max_lines":5000,"reset_state":false}'

curl -X POST http://localhost:8080/v1/detections/pipeline/run \
  -H "Content-Type: application/json" \
  -d '{"source":"parquet","parquet_path":"data/opensearch-export/logs-raw-merged.parquet","max_lines":10000}'
```

```json
{
  "status": "success",
  "detections_count": 5,
  "message": "5 détection(s) — terminé (code 0).",
  "source": "opensearch",
  "stdout_tail": "",
  "stderr_tail": ""
}
```

---

### Remédiation

#### `GET /v1/remediation/catalog`

Catalogue complet des plans de remédiation disponibles.

```bash
curl http://localhost:8080/v1/remediation/catalog
```

#### `GET /v1/remediation/{challenge_id}`

Plan de remédiation pour un type d'attaque spécifique.

```bash
curl http://localhost:8080/v1/remediation/credential_stuffing
```

```json
{
  "challenge_id": "credential_stuffing",
  "immediate_actions": [
    "Bloquer les IPs attaquantes au niveau du WAF",
    "Réinitialiser les credentials du compte compromis",
    "Supprimer le web shell /uploads/image_2026.php"
  ],
  "long_term_recommendations": [
    "Implémenter le rate limiting sur les endpoints d'authentification",
    "Activer le MFA pour tous les comptes",
    "Déployer un WAF avec règles anti-bot"
  ]
}
```

#### `POST /v1/remediation/validate`

Valider qu'un plan de remédiation est complet et cohérent.

```bash
curl -X POST http://localhost:8080/v1/remediation/validate \
  -H "Content-Type: application/json" \
  -d '{"challenge_id": "sql_injection", "actions_taken": ["blocked_ip", "patched_endpoint"]}'
```

---

### Logs (héritage Phase 1)

#### `POST /v1/logs/search`

Recherche de logs firewall par plage de dates (données CSV Phase 1).

```bash
curl -X POST http://localhost:8080/v1/logs/search \
  -H "Content-Type: application/json" \
  -d '{
    "start_timestamp": "2025-02-01T00:00:00Z",
    "end_timestamp": "2025-02-28T23:59:59Z",
    "incident_types": ["Bug", "Attack"]
  }'
```

#### `GET /v1/logs/stats`

Statistiques globales des logs disponibles.

```bash
curl http://localhost:8080/v1/logs/stats
```

---

## Authentification

Pas d'authentification requise en développement local. En production ECS, la sécurité est gérée au niveau du middleware FastAPI (`security.py`) et du réseau (security groups VPC).

## CORS

Origines autorisées par défaut : `localhost:3000`, `127.0.0.1:3000`. Configurable via la variable d'environnement `CORS_ORIGINS`.
