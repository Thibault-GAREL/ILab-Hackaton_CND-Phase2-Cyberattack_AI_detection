# 🛡️ Cyberattack AI Detection — CND Hackathon Phase 2

![Python](https://img.shields.io/badge/python-3.10-blue.svg)
![AWS](https://img.shields.io/badge/AWS-eu--west--3-orange.svg)
![Bedrock](https://img.shields.io/badge/Bedrock-Claude%20Opus%204.6-8A2BE2.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.33-FF4B4B.svg)
![OpenSearch](https://img.shields.io/badge/OpenSearch-2.x-005EB8.svg)

![License](https://img.shields.io/badge/license-MIT-green.svg)
![Contributions](https://img.shields.io/badge/contributions-welcome-orange.svg)

<p align="center">
  <img src="img/hackathon-cnd-p01.png" alt="CND Hackathon 2025-2026 — cover" width="600">
</p>

<details>
<summary>📄 See the full hackathon brief (38 more pages)</summary>

<p align="center">
  <img src="img/hackathon-cnd-p02.png" alt="page 2" width="600"><br/>
  <img src="img/hackathon-cnd-p03.png" alt="page 3" width="600"><br/>
  <img src="img/hackathon-cnd-p04.png" alt="page 4" width="600"><br/>
  <img src="img/hackathon-cnd-p05.png" alt="page 5" width="600"><br/>
  <img src="img/hackathon-cnd-p06.png" alt="page 6" width="600"><br/>
  <img src="img/hackathon-cnd-p07.png" alt="page 7" width="600"><br/>
  <img src="img/hackathon-cnd-p08.png" alt="page 8" width="600"><br/>
  <img src="img/hackathon-cnd-p09.png" alt="page 9" width="600"><br/>
  <img src="img/hackathon-cnd-p10.png" alt="page 10" width="600"><br/>
  <img src="img/hackathon-cnd-p11.png" alt="page 11" width="600"><br/>
  <img src="img/hackathon-cnd-p12.png" alt="page 12" width="600"><br/>
  <img src="img/hackathon-cnd-p13.png" alt="page 13" width="600"><br/>
  <img src="img/hackathon-cnd-p14.png" alt="page 14" width="600"><br/>
  <img src="img/hackathon-cnd-p15.png" alt="page 15" width="600"><br/>
  <img src="img/hackathon-cnd-p16.png" alt="page 16" width="600"><br/>
  <img src="img/hackathon-cnd-p17.png" alt="page 17" width="600"><br/>
  <img src="img/hackathon-cnd-p18.png" alt="page 18" width="600"><br/>
  <img src="img/hackathon-cnd-p19.png" alt="page 19" width="600"><br/>
  <img src="img/hackathon-cnd-p20.png" alt="page 20" width="600"><br/>
  <img src="img/hackathon-cnd-p21.png" alt="page 21" width="600"><br/>
  <img src="img/hackathon-cnd-p22.png" alt="page 22" width="600"><br/>
  <img src="img/hackathon-cnd-p23.png" alt="page 23" width="600"><br/>
  <img src="img/hackathon-cnd-p24.png" alt="page 24" width="600"><br/>
  <img src="img/hackathon-cnd-p25.png" alt="page 25" width="600"><br/>
  <img src="img/hackathon-cnd-p26.png" alt="page 26" width="600"><br/>
  <img src="img/hackathon-cnd-p27.png" alt="page 27" width="600"><br/>
  <img src="img/hackathon-cnd-p28.png" alt="page 28" width="600"><br/>
  <img src="img/hackathon-cnd-p29.png" alt="page 29" width="600"><br/>
  <img src="img/hackathon-cnd-p30.png" alt="page 30" width="600"><br/>
  <img src="img/hackathon-cnd-p31.png" alt="page 31" width="600"><br/>
  <img src="img/hackathon-cnd-p32.png" alt="page 32" width="600"><br/>
  <img src="img/hackathon-cnd-p33.png" alt="page 33" width="600"><br/>
  <img src="img/hackathon-cnd-p34.png" alt="page 34" width="600"><br/>
  <img src="img/hackathon-cnd-p35.png" alt="page 35" width="600"><br/>
  <img src="img/hackathon-cnd-p36.png" alt="page 36" width="600"><br/>
  <img src="img/hackathon-cnd-p37.png" alt="page 37" width="600"><br/>
  <img src="img/hackathon-cnd-p38.png" alt="page 38" width="600"><br/>
  <img src="img/hackathon-cnd-p39.png" alt="page 39" width="600">
</p>

</details>

---

## 📝 Project Description

End-to-end **AI pipeline** that ingests raw security logs from **Amazon OpenSearch**, detects **5 types of cyberattacks** (credential stuffing, SSH brute force, SQL injection, directory traversal, SSRF), enriches each detection through **Claude Opus 4.6** on **Amazon Bedrock** with a custom **anti-hallucination skill** (RECOMMENDATION → CRITIQUE), and auto-submits results to the scoring API.

Built for the **CND Hackathon 2026** (EPITA / ESGI / ECE). The goal was to design a **production-grade** pipeline — not a notebook — running 24/7 on AWS Lambda + ECS Fargate behind an ALB, with a FastAPI backend and a Streamlit dashboard for the jury.

---

## ⚙️ Features

  🛰️ Real-time ingestion from **Amazon OpenSearch** (`search_after` + persistent cursor in DynamoDB)

  🧠 LLM enrichment via **Claude Opus 4.6** on Bedrock, with a **two-stage anti-hallucination skill** (RECOMMENDATION → CRITIQUE)

  🎯 **5 targeted detectors** — one per DS1 challenge, with calibrated thresholds and campaign grouping by IP overlap

  🧹 Smart deduplication (`keep_most_specific`) to avoid the **−10 pts / false-positive** penalty

  🗓️ DS1 timeline + IoC **canonicalization** to align outputs with the official ground truth

  🛠️ Per-attack **remediation playbooks** attached to every detection

  🌐 **FastAPI** backend + **Streamlit** dashboard, both deployed on ECS Fargate behind a stable **ALB** DNS

  ☁️ Real-time loop runnable locally, in a Docker container, or as an **AWS Lambda** triggered by EventBridge every 5 min

---

## Example Outputs

A submitted detection looks like this:

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
  "detection_time_seconds": 0
}
```

### The 5 DS1 challenges

| Challenge | Max pts | Attacker IPs | Time window |
|---|---|---|---|
| `credential_stuffing` | 100 | 203.0.113.45, 198.51.100.23 | 06/01 02h → 06h |
| `ssh_brute_force` | 100 | 45.33.32.156, 198.51.100.89 | 11/01 01h → 07h |
| `sql_injection` | 100 | 185.220.101.45 | 19/01 14h → 17h |
| `directory_traversal` | 80 | 198.51.100.200 | 23/01 10h → 12h |
| `ssrf` | 80 | 203.0.113.100 | 26/01 11h → 12h |

Scoring (slices mode): 20 pts type + 20 pts IPs (F1) + 20 pts victims (F1) + 20 pts timeline (±5 min) + 20 pts IoC − 10 pts/FP. **100 pts max per challenge**.

---

## ⚙️ How it works

  🛰️ A poller (CLI, Docker, or Lambda) reads new logs from **OpenSearch** using a persisted `search_after` cursor.

  📊 `split_logs_frame()` shards the batch by `log_source` (auth / app / net / sys) so each detector only sees what it needs.

  🎯 **5 heuristic detectors** scan their slice in parallel, group attacker IPs by time overlap, and emit raw detection candidates.

  🧹 `deduplicate()` removes overlapping detections on the same IP / window with the **most-specific-wins** strategy.

  🧠 Each detection is enriched by **Claude Opus 4.6**: the **RECOMMENDATION** pass proposes richer IoCs; the **CRITIQUE** pass rejects anything not grounded in the actual logs.

  🗓️ `apply_ds1_canonical_windows()` + `apply_ds1_ioc_canonicalization()` align timestamps and IoC key names with the official ground truth.

  🛠️ `attach_remediation_plans()` adds an action plan tailored to each attack family.

  📤 `submit.py` POSTs every detection to the scoring API, with a **fingerprint cache** to prevent re-submissions across the 3 ingestion slices.

---

## 🗺️ Architecture Diagram

End-to-end flow — from raw logs in OpenSearch to the scoring API, including the anti-hallucination skill loop:

```mermaid
flowchart TD
    OS[(OpenSearch<br/>logs-raw)] -->|search_after + delta| Split

    subgraph Pipeline["Detection Pipeline"]
        direction TB
        Split[split_logs_frame] --> D1[credential_stuffing]
        Split --> D2[ssh_brute_force]
        Split --> D3[sql_injection]
        Split --> D4[directory_traversal]
        Split --> D5[ssrf]
        D1 & D2 & D3 & D4 & D5 --> Dedup[deduplicate]
        Dedup --> Skill{BEDROCK_SKILL_MODE}
        Skill -->|on| Reco[RECOMMENDATION<br/>structured enrichment]
        Reco --> Crit[CRITIQUE<br/>anti-hallucination]
        Crit -->|approved| DS1[DS1 timeline + IoC canon.]
        Crit -->|rejected| Raw[Raw fallback]
        Raw --> DS1
        Skill -->|off| Legacy[Legacy bedrock_analysis]
        Legacy --> DS1
        DS1 --> Remed[Remediation plans]
        Remed --> Submit[submit.py]
    end

    Submit -->|POST JSON| API[CND Scoring API]
    Submit -->|detections.json| Files[(Local files)]

    Files --> Backend[FastAPI backend]
    Backend --> Frontend[Streamlit dashboard]

    subgraph Infra["AWS Infra (eu-west-3)"]
        ALB[ALB — stable DNS] --> ECS[ECS Fargate]
        EB[EventBridge<br/>rate 5 min] --> Lambda
        Lambda[Lambda runtime] --> OS
        Lambda --> DDB[(DynamoDB<br/>cursor)]
    end
    ECS --> Backend
```

**Key components:**
- Model: `eu.anthropic.claude-opus-4-6-v1` (Bedrock, region `eu-west-3`)
- LLM call: `converse()`, 6144 max tokens, 0.75s throttle, 5 retries
- Detection thresholds calibrated in `pipeline/config.py`
- Campaign IP grouping window: `CAMPAIGN_OVERLAP_MINUTES = 90`

---

## 📂 Repository structure

```bash
├── pipeline/                       # Detection pipeline (Python package)
│   ├── __main__.py                 # python -m pipeline
│   ├── config.py                   # All thresholds, AWS, API settings
│   ├── pipeline.py                 # CLI entry point
│   ├── pipeline_core.py            # split_logs_frame + run_detectors
│   ├── detection_run.py            # dedup → Skill/Bedrock → DS1 → submit chain
│   ├── skill_enrichment.py         # Skill mode (RECOMMENDATION → CRITIQUE)
│   ├── skill_assets/               # Prompts, JSON schemas, validators
│   ├── bedrock_analysis.py         # Legacy LLM enrichment
│   ├── ds1_timeline.py             # DS1 canonical windows
│   ├── ds1_ioc_canonical.py        # DS1 canonical IoC keys
│   ├── remediation.py              # Per-attack remediation playbooks
│   ├── submit.py                   # POST to scoring API + cache
│   └── detectors/                  # 5 detectors + dedup + utils
│       ├── credential_stuffing.py
│       ├── ssh_brute_force.py
│       ├── sql_injection.py
│       ├── directory_traversal.py
│       ├── ssrf.py
│       ├── dedup.py
│       └── utils.py
│
├── backend/                        # FastAPI backend
│   └── src/app/
│       ├── main.py
│       ├── routers/                # health, logs, detections, remediation
│       ├── schemas/                # Pydantic models
│       ├── services/
│       └── security.py
│
├── frontend/                       # Streamlit dashboard (3 pages)
│   └── streamlit_app.py
│
├── cnd-detection-skill/            # Bedrock skill (prompts + schemas)
├── infra/                          # ECS task def + ALB CloudFormation
├── sam/                            # AWS SAM (Lambda + EventBridge)
├── scripts/                        # Benchmarks + smoke tests
├── docs/                           # Full documentation
├── datasets/                       # Result CSVs
│
├── requirements.txt
├── CLAUDE.md                       # Project instructions for Claude Code
├── LICENSE
└── README.md
```

---

## 💻 Run it on Your PC

Clone the repository and install dependencies:

```bash
git clone https://github.com/Thibault-GAREL/ILab-Hackaton_CND-Phase2-Cyberattack_AI_detection.git
cd ILab-Hackaton_CND-Phase2-Cyberattack_AI_detection

python -m venv .venv # if you don't have a virtual environment
source .venv/bin/activate   # Linux / macOS
.venv\Scripts\activate      # Windows

pip install -r requirements.txt
```

Configure AWS + environment:

```bash
aws configure sso --region eu-west-3

cp pipeline/.env.example pipeline/.env
# Fill OPENSEARCH_BASIC_PASSWORD, SCORING_API_URL, (SCORING_API_KEY)
```

### Run the detection pipeline

```bash
python -m pipeline                     # one pass → detections.json
python -m pipeline --loop              # poll forever
python -m pipeline --submit            # submit every detection
python -m pipeline --submit-dry-run    # dry-run the API
python -m pipeline --reset-state       # rewind cursor to DS2 start
```

### Run the web UI (backend + frontend)

```bash
# Recommended — Docker
cd frontend && make docker-up
# Backend: http://localhost:8080/docs   Frontend: http://localhost:3000

# Or locally
cd backend && PYTHONPATH=src uvicorn app.main:app --port 8080 --reload
cd frontend && BACKEND_URL=http://127.0.0.1:8080 streamlit run streamlit_app.py --server.port 3000
```

### Deploy on AWS (stable ALB URL)

```bash
bash infra/deploy_alb.sh
# Returns a fixed DNS: cnd-phase2-alb-*.eu-west-3.elb.amazonaws.com
```

⚠️ Bedrock calls require an **AWS account with Claude Opus 4.6 access** in `eu-west-3`. The pipeline gracefully falls back to raw detections if Bedrock is unreachable.

---

## 📖 Inspiration / Sources

Built for the **CND Hackathon 2026** (EPITA / ESGI / ECE — May 2026). I used **Claude (Opus 4.6 + Claude Code)** as a coding companion on the skill design (RECOMMENDATION + CRITIQUE pattern) and the ALB / ECS infrastructure scripts.

Full documentation lives in [`docs/`](docs/README.md):
- 📄 [docs/architecture.md](docs/architecture.md) — AWS architecture
- 📄 [docs/pipeline.md](docs/pipeline.md) — 5 detectors + skill mode
- 📄 [docs/api-reference.md](docs/api-reference.md) — FastAPI endpoints
- 📄 [docs/deployment.md](docs/deployment.md) — AWS deployment guide
- 📄 [docs/scoring-format.md](docs/scoring-format.md) — Submission JSON format

Code created by me 😎, Thibault GAREL - [Github](https://github.com/Thibault-GAREL)
