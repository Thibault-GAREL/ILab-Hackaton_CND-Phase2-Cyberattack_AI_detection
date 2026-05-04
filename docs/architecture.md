---
title: "Architecture AWS"
version: "2.1"
project: "CND Hackathon Phase 2"
last_updated: "2026-05-05"
audience: ["ia", "humain", "jury"]
---

# Architecture

Région AWS : **eu-west-3** (Paris).

## Diagramme de flux

```mermaid
flowchart TD
    OS[(OpenSearch<br/>index logs-raw)] -->|search_after + delta| Pipeline

    subgraph Pipeline["Pipeline de détection"]
        direction TB
        Split[split_logs_frame] --> D1[credential_stuffing]
        Split --> D2[ssh_brute_force]
        Split --> D3[sql_injection]
        Split --> D4[directory_traversal]
        Split --> D5[ssrf]
        D1 & D2 & D3 & D4 & D5 --> Dedup[deduplicate]
        Dedup --> SkillSwitch{BEDROCK_SKILL_MODE?}
        SkillSwitch -->|oui| Recommend[RECOMMENDATION<br/>enrichissement structure]
        Recommend --> Critic[CRITIQUE<br/>anti-hallucination]
        Critic -->|approved| DS1
        Critic -->|rejected| FallbackRaw[Fallback detection brute]
        FallbackRaw --> DS1
        SkillSwitch -->|non| LegacyBedrock[Legacy bedrock_analysis<br/>enrichissement + timeline]
        LegacyBedrock --> DS1[DS1 timeline + IoC canonicalization]
        DS1 --> Remed[Remediation]
        Remed --> Submit[submit.py]
    end

    Submit -->|POST JSON| API[API de Scoring CND]
    Submit -->|detections.json| Files[(Fichiers locaux)]

    subgraph Backend["Backend FastAPI"]
        direction TB
        Health[GET /health]
        Detections[GET /v1/detections]
        PipelineRun[POST /v1/detections/pipeline/run]
        RemCatalog[GET /v1/remediation/catalog]
    end

    Files --> Backend

    subgraph Infra["Infra AWS"]
        ALB[ALB<br/>URL stable]
        ECS[ECS Fargate<br/>backend + frontend]
        Lambda[Lambda<br/>pipeline temps reel]
        EB[EventBridge<br/>rate 5 min]
        DDB[(DynamoDB<br/>curseur pipeline)]
    end

    ALB --> ECS
    ECS --> Backend
    Backend --> Frontend[Frontend Streamlit]

    EB -->|trigger| Lambda
    Lambda --> OS
    Lambda --> DDB
```

## Services AWS utilisés

| Service | Rôle | Configuration |
|---|---|---|
| **OpenSearch** | Index `logs-raw`, ingestion continue (~50-100 logs / 5 min) | FGAC Basic auth, `search_after` paginé |
| **Bedrock** | Claude Opus 4.6 (`eu.anthropic.claude-opus-4-6-v1`) — enrichissement + timeline raffinée | `converse()`, 6144 tokens max, throttle 0.75s |
| **ALB** | Load balancer stable (DNS fixe) devant ECS | Port 80 (frontend), port 8080 (API) |
| **ECS Fargate** | Backend FastAPI + Frontend Streamlit | 1 service, 2 conteneurs, derrière ALB |
| **Lambda** | Pipeline temps réel (poll OpenSearch → détection → soumission) | SAM, timeout 300s |
| **EventBridge** | Déclenchement périodique de la Lambda | `rate(5 minutes)` |
| **DynamoDB** | Curseur `search_after` persistant pour Lambda | Clé `PIPELINE_CURSOR` |
| **S3** | Stockage modèles et artefacts | Bucket projet |
| **ECR** | Images Docker backend/frontend | 2 repositories |

## Flux de données

1. **Ingestion** : OpenSearch reçoit des logs bruts (33 colonnes) toutes les 5 minutes
2. **Poll** : La pipeline lit les nouveaux logs via `search_after` avec un curseur persistant (fichier local ou DynamoDB)
3. **Détection** : `split_logs_frame()` répartit par `log_source` (auth/app/net/sys), puis 5 détecteurs heuristiques analysent les sous-ensembles
4. **Déduplication** : Stratégie `keep_most_specific` — élimine les détections redondantes par IP/fenêtre temporelle
5. **Enrichissement** : Mode Skill (RECOMMENDATION + CRITIQUE anti-hallucination) par défaut, ou enrichissement legacy via `converse()` fusionné
6. **Canonicalization DS1** : Timeline et IoC normalisés sur les fenêtres officielles du brief
7. **Remédiation** : Plans d'action attachés à chaque détection
8. **Soumission** : POST JSON vers l'API de scoring avec déduplication par fingerprint (cache fichier)

## Sécurité

- **Guardrails** : `guardrails.py` maintient des dictionnaires `ALLOWED_AWS_ACTIONS` et `BLOCKED_ACTIONS` pour limiter les appels AWS
- **Auth OpenSearch** : FGAC Basic (user `etudiant`), credentials dans `.env`
- **Bedrock** : IAM via SSO, profil `eu-west-3`
- **CORS** : Backend restreint au domaine ALB + origines configurables via `CORS_ORIGINS`
- **Anti-hallucination** : Mode CRITIQUE du skill rejette les enrichissements non ancrés dans les logs (fallback sur détection brute)
