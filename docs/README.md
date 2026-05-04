---
title: "Documentation — CND Hackathon Phase 2"
version: "2.1"
project: "CND Hackathon Phase 2"
last_updated: "2026-05-05"
audience: ["ia", "humain", "jury"]
---

# Documentation du projet

Pipeline IA de détection de cyberattaques — Hackathon CND (EPITA / ESGI / ECE), mai 2026.

## Index

| Document | Description |
|---|---|
| [architecture.md](architecture.md) | Architecture AWS, diagramme Mermaid, ALB, flux de données |
| [pipeline.md](pipeline.md) | Pipeline de détection : 5 détecteurs, dedup, Skill mode (RECOMMENDATION + CRITIQUE), timeline DS1 |
| [api-reference.md](api-reference.md) | Endpoints FastAPI avec exemples `curl` |
| [deployment.md](deployment.md) | Guide de déploiement AWS (ALB, ECS Fargate, ECR, IAM, Lambda) |
| [scoring-format.md](scoring-format.md) | Format JSON de soumission et checklist de validation |

## Structure du dépôt

```
ILab-Hackaton_CND-Phase2-Cyberattack_AI_detection/
├── pipeline/               # Pipeline de détection (package Python)
│   ├── config.py           # Paramètres, seuils, credentials AWS
│   ├── pipeline.py         # Point d'entrée OpenSearch → détection
│   ├── pipeline_core.py    # split_logs_frame + run_detectors
│   ├── detection_run.py    # Chaîne dedup → Bedrock (skill ou legacy) → soumission
│   ├── skill_enrichment.py # Mode Skill : RECOMMENDATION → CRITIQUE (anti-hallu)
│   ├── bedrock_analysis.py # Enrichissement legacy (fallback si skill désactivé)
│   ├── skill_assets/       # Prompts, schémas, validateurs du skill cnd-detection-tuner
│   ├── remediation.py      # Plans de remédiation par challenge
│   ├── submit.py           # POST vers l'API de scoring
│   └── detectors/          # 5 détecteurs DS1 + dedup + utils
├── cnd-detection-skill/    # Skill Bedrock : prompts, schémas, orchestrateur
├── backend/                # API FastAPI (détections, remédiation, stats)
│   └── src/app/
├── frontend/               # Interface Streamlit (3 pages, toggle skill mode)
├── infra/                  # ECS task definition + ALB CloudFormation
├── sam/                    # AWS SAM (Lambda + EventBridge)
├── scripts/                # Déploiement, benchmarks, tests
├── docs/                   # Cette documentation
└── datasets/               # Données de résultats
```

## Démarrage rapide

```bash
# 1. Configurer les credentials AWS
aws configure sso --region eu-west-3

# 2. Créer le .env à la racine de pipeline/
cp pipeline/.env.example pipeline/.env
# Remplir OPENSEARCH_BASIC_PASSWORD, SCORING_API_URL, etc.

# 3. Lancer la pipeline (une passe, skill mode activé par défaut)
python -m pipeline

# 4. Lancer en boucle temps réel avec soumission
python -m pipeline --loop --submit

# 5. Désactiver le skill mode (enrichissement legacy)
BEDROCK_SKILL_MODE=0 python -m pipeline
```

## Accès stable (ALB)

Après déploiement ALB (`bash infra/deploy_alb.sh`), l'URL reste fixe :
- Frontend : `http://<alb-dns>.eu-west-3.elb.amazonaws.com`
- API : `http://<alb-dns>.eu-west-3.elb.amazonaws.com:8080/docs`
