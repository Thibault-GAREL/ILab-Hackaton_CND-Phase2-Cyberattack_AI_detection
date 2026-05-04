# Cyberattack AI Detection — CND Hackathon Phase 2

![Python](https://img.shields.io/badge/python-3.10-blue.svg)
![AWS](https://img.shields.io/badge/AWS-eu--west--3-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Pipeline IA de détection de cyberattaques pour le hackathon CND (EPITA / ESGI / ECE) — Mai 2026.

Ingestion temps réel depuis **Amazon OpenSearch**, détection heuristique de 5 types d'attaques, enrichissement structuré via **Claude Opus 4.6** (Amazon Bedrock) avec anti-hallucination (RECOMMENDATION + CRITIQUE), soumission automatique vers l'API de scoring.

**Documentation complète** : [`docs/`](docs/README.md)

---

## Structure du projet

```
├── pipeline/               # Pipeline de détection (package Python)
│   ├── config.py           # Paramètres, seuils, credentials AWS
│   ├── pipeline.py         # Point d'entrée : OpenSearch → détection → soumission
│   ├── pipeline_core.py    # split_logs_frame + run_detectors
│   ├── detection_run.py    # Chaîne dedup → Skill/Bedrock → DS1 → remédiation
│   ├── skill_enrichment.py # Mode Skill : RECOMMENDATION → CRITIQUE (anti-hallu)
│   ├── skill_assets/       # Prompts, schémas, validateurs du skill
│   ├── bedrock_analysis.py # Mode legacy : enrichissement LLM (Claude Opus 4.6)
│   ├── remediation.py      # Plans de remédiation par challenge
│   ├── submit.py           # POST vers l'API de scoring
│   └── detectors/          # 5 détecteurs + dedup + utils
│       ├── credential_stuffing.py
│       ├── ssh_brute_force.py
│       ├── sql_injection.py
│       ├── directory_traversal.py
│       ├── ssrf.py
│       ├── dedup.py
│       └── utils.py
├── backend/                # API FastAPI (détections, remédiation, stats)
│   └── src/app/
│       ├── main.py
│       ├── routers/        # health, logs, detections, remediation, pipeline
│       ├── schemas/
│       ├── services/
│       └── security.py
├── cnd-detection-skill/    # Skill Bedrock (prompts, schemas, orchestrateur)
├── frontend/               # Interface Streamlit (3 pages, toggle skill mode)
│   └── streamlit_app.py
├── infra/                  # ECS task def + ALB CloudFormation
│   ├── ecs-task-definition.json
│   ├── alb-cloudformation.yaml
│   └── deploy_alb.sh
├── sam/                    # AWS SAM (Lambda + EventBridge rate(5 min))
│   ├── template.yaml
│   └── handler.py
├── scripts/                # Benchmarks et vérifications
│   ├── benchmark_and_report.py
│   ├── benchmark_opensearch_report.py
│   └── smoke_bedrock_timeline.py
├── docs/                   # Documentation complète
│   ├── README.md           # Index de la documentation
│   ├── architecture.md     # Architecture AWS + diagramme Mermaid
│   ├── pipeline.md         # Pipeline de détection (5 détecteurs)
│   ├── api-reference.md    # Endpoints FastAPI + exemples curl
│   ├── deployment.md       # Guide de déploiement AWS
│   └── scoring-format.md   # Format JSON + scoring
└── datasets/               # Données de résultats
```

## Démarrage rapide

```bash
# 1. Configurer AWS
aws configure sso --region eu-west-3

# 2. Installer les dépendances
pip install pyarrow pandas boto3 requests python-dotenv opensearch-py

# 3. Configurer l'environnement
cp pipeline/.env.example pipeline/.env
# Remplir OPENSEARCH_BASIC_PASSWORD, SCORING_API_URL, etc.

# 4. Lancer la pipeline (une passe)
python -m pipeline

# 5. Boucle temps réel avec soumission
python -m pipeline --loop --submit
```

## Les 5 challenges DS1

| Challenge | Points | IPs attaquantes | Fenêtre |
|---|---|---|---|
| `credential_stuffing` | 100 | 203.0.113.45, 198.51.100.23 | 06/01 02h–06h |
| `ssh_brute_force` | 100 | 45.33.32.156, 198.51.100.89 | 11/01 01h–07h |
| `sql_injection` | 100 | 185.220.101.45 | 19/01 14h–17h |
| `directory_traversal` | 80 | 198.51.100.200 | 23/01 10h–12h |
| `ssrf` | 80 | 203.0.113.100 | 26/01 11h–12h |

Scoring (mode finale / slices) : 20 pts type + 20 pts IPs (F1) + 20 pts victimes (F1) + 20 pts timeline (±5 min) + 20 pts IoC − 10 pts/FP. **Total max : 100 pts par challenge**.

## Web UI

```bash
# Docker (recommandé)
cd frontend && make docker-up
# Backend : http://localhost:8080/docs  |  Frontend : http://localhost:3000

# Développement local
cd backend && PYTHONPATH=src uvicorn app.main:app --port 8080 --reload
cd frontend && BACKEND_URL=http://127.0.0.1:8080 streamlit run streamlit_app.py --server.port 3000
```

La navigation multipage **native** Streamlit est désactivée (`frontend/.streamlit/config.toml` et flag dans `make streamlit`) pour n’afficher qu’**une** barre latérale (celle du projet avec `st.page_link`).

### URL stable (ALB)

Après déploiement : `bash infra/deploy_alb.sh` — donne un DNS ALB fixe (`cnd-phase2-alb-*.eu-west-3.elb.amazonaws.com`) qui ne change plus entre les redéploiements ECS.

## Documentation

| Document | Description |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Architecture AWS, ALB, diagramme Mermaid |
| [docs/pipeline.md](docs/pipeline.md) | 5 détecteurs, dedup, Skill mode (RECOMMENDATION + CRITIQUE) |
| [docs/api-reference.md](docs/api-reference.md) | Endpoints FastAPI + curl |
| [docs/deployment.md](docs/deployment.md) | Déploiement ALB, ECS Fargate, ECR, Lambda |
| [docs/scoring-format.md](docs/scoring-format.md) | Format JSON + anti-hallucination + scoring |

---

Projet créé par Thibault GAREL — [GitHub](https://github.com/Thibault-GAREL)
