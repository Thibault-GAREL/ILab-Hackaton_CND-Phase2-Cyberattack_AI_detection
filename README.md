# 🔐🤖 Cyberattack AI Detection — CND Hackathon

![Python](https://img.shields.io/badge/python-3.10-blue.svg)
![PyArrow](https://img.shields.io/badge/pyarrow-latest-red.svg)
![Pandas](https://img.shields.io/badge/pandas-latest-red.svg)
![Boto3](https://img.shields.io/badge/boto3-AWS_SDK-orange.svg)

![License](https://img.shields.io/badge/license-MIT-green.svg)
![Contributions](https://img.shields.io/badge/contributions-welcome-orange.svg)

<p align="center">
  <img src="img/demo.gif" alt="Detection pipeline demo" width="600">
</p>

---

## 📝 Project Description

This project is an **AI-powered cybersecurity detection pipeline** built for the CND Hackathon (EPITA / ESGI / ECE — April 2026). It pulls **incremental batches from Amazon OpenSearch** (`logs-raw`), detects cyberattacks using **heuristic rules**, enriches each detection with **Claude Opus 4.6 via Amazon Bedrock**, and can write `detections.json` and/or **POST** to the scoring REST API. Optional Parquet tooling remains for local benchmarks only (`scripts/benchmark_and_report.py`).

---

## ⚙️ Features

  🔍 **5 heuristic detectors** covering the main attack patterns seen in the dataset

  🛡️ **Brute Force** — detects mass auth failures from the same external IP

  🎣 **Credential Stuffing** — detects mass HTTP 401s with script user-agents

  🔓 **Account Takeover** — detects a successful login after N failures from the same IP

  📡 **Port Scan** — detects external IPs hitting many distinct ports with high reject ratio

  🌐 **Network Recon** — detects external IPs doing connection sweeps before an attack

  🧹 **Smart deduplication** with 3 configurable strategies: `none`, `keep_most_specific`, `merge`

  🤖 **LLM enrichment** via Claude Opus 4.6 (Bedrock) — refines attack type, adds MITRE technique, suggests remediation

  ⏱️ **Real-time pipeline** polling OpenSearch every 5 minutes with state persistence

  🎛️ **All thresholds in one place** (`config.py`) — tune sensitivity without touching detector code

---

## ⚙️ How it works

  📡 **Fetch** — `pipeline.py` queries OpenSearch with `search_after` and a persisted cursor (file or DynamoDB)

  🔎 **Detect** — each detector runs on its filtered log subset (auth failures, HTTP 401s, network events)

  🧹 **Deduplicate** — overlapping detections from the same IP are resolved by the configured strategy

  🤖 **Enrich** — Claude Opus 4.6 refines the attack type and adds IoC indicators for each detection

  ⏱️ **Latency field** — `detection_time_seconds` is derived from the earliest attacker-related log timestamp in the batch (speed bonus under 300 seconds)

  📤 **Submit** — use `pipeline.py --submit`, `submit.py`, or the SAM Lambda (`sam/`)

  🔁 **Loop** — `python pipeline.py --loop` or `realtime_pipeline.py` (alias) for continuous polling

---

## 🗺️ Schema

```text
OpenSearch (logs-raw)
         ↓
   [ pipeline.py ]
         ↓
  ┌──────────────────────────────────┐
  │  brute_force       (auth logs)   │
  │  credential_stuffing (app logs)  │
  │  account_takeover  (auth logs)   │
  │  port_scan         (net logs)    │
  │  network_recon     (net logs)    │
  └──────────────────────────────────┘
         ↓
  [ dedup.py ]  →  keep_most_specific / merge / none
         ↓
  [ bedrock_analysis.py ]  →  Claude Opus 4.6
         ↓
  [ submit.py ]  →  POST scoring API
         ↓
  scores_history.json
```

# 🛡️ Cyber Attack Summary - Log Detection

### 1. Credential Stuffing (`credential_stuffing`)
* **Concept**: An automated attack using lists of stolen credentials to gain unauthorized access to user accounts.
* **Log Indicators**:
    * High volume of failed login attempts (e.g., ~3,500).
    * Unexpected geolocation of the source IP (e.g., Beijing).
    * Presence of unauthorized files like web shells (e.g., `/uploads/image_2026.php`).

### 2. SSH Brute Force (`ssh_brute_force`)
* **Concept**: Repeatedly attempting to guess SSH credentials to gain remote system access.
* **Log Indicators**:
    * Massive spike in failed SSH authentication attempts (e.g., ~4,600).
    * Evidence of privilege escalation, such as unauthorized sudo usage or backdoor user creation.
    * Lateral movement attempts toward internal targets like `db-prod-01` or `web-prod-01`.

### 3. SQL Injection (`sql_injection`)
* **Concept**: Injecting malicious SQL queries into input fields to manipulate or extract database information.
* **Log Indicators**:
    * Detection of numerous SQLi payloads (e.g., ~300 patterns).
    * Significant data exfiltration volume (e.g., ~25MB).
    * Automated tool signatures found within browser User-Agent strings.

### 4. Directory Traversal (`directory_traversal`)
* **Concept**: Exploiting path vulnerabilities to access restricted files and directories on the server.
* **Log Indicators**:
    * Request patterns containing sequences like `../../../etc/passwd`.
    * Successful unauthorized reads of sensitive files such as `/etc/shadow` or `/root/.ssh/id_rsa`.

### 5. SSRF (`ssrf`)
* **Concept**: Manipulating a server to make requests to its own internal network or cloud metadata services.
* **Log Indicators**:
    * Internal network traffic originating from the web server (e.g., targeting `10.0.3.10:3306`).
    * Requests directed at Cloud Instance Metadata Services (e.g., `169.254.169.254`).

---

## 📂 Repository structure

```bash
├── config.py                  # All parameters: API, thresholds, flags
├── pipeline.py                # Main entry point (Parquet dataset)
├── realtime_pipeline.py       # Real-time loop (OpenSearch stream)
├── submit.py                  # POST detections to scoring API
├── opensearch_connector.py    # AWS SigV4 OpenSearch client
├── bedrock_analysis.py        # LLM enrichment via Claude Opus 4.6
│
├── detectors/
│   ├── brute_force.py
│   ├── credential_stuffing.py
│   ├── account_takeover.py
│   ├── port_scan.py
│   ├── network_recon.py
│   ├── dedup.py               # Deduplication logic (3 strategies)
│   └── utils.py               # fmt_ts(), split_sessions()
│
├── detections.json            # Generated by pipeline.py (gitignored)
├── scores_history.json        # Score history per submission (gitignored)
│
├── CLAUDE.md                  # Project context for Claude Code
├── README.md
└── .gitignore
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

pip install pyarrow pandas boto3 requests
```

> Optional: a large Parquet mirror is **not** required for `pipeline.py` (OpenSearch-only). For local perf benchmarks, place a Parquet export under `Dataset_log/` or `data/` if needed.

### Run the detection pipeline (OpenSearch)

```bash
python pipeline.py                      # one poll → detections.json + cursor advance
python pipeline.py --max-docs 5000     # cap batch size
python pipeline.py --loop              # continuous polling (interval from config)
python pipeline.py --submit            # submit each detection immediately
python pipeline.py --submit-dry-run    # scoring API dry-run
python pipeline.py --reset-state      # reset OpenSearch cursor
python pipeline.py --no-dedup
```

### Review and submit detections

```bash
python submit.py --dry-run      # print payloads without sending
python submit.py                # submit all detections in detections.json
python submit.py --index 0      # submit only detection #0
```

### Real-time loop (alias)

```bash
python pipeline.py --loop --submit       # recommended
python realtime_pipeline.py             # same loop (wrapper)
python realtime_pipeline.py --dry-run   # soumission API en dry-run ; curseur non avancé
python realtime_pipeline.py --reset     # reset cursor then loop
```

### AWS Lambda (EventBridge every 5 minutes)

See [`sam/README.md`](sam/README.md) and `sam/template.yaml` — packages the repo root, DynamoDB cursor, Bedrock + OpenSearch env vars.

### Configure before running

Edit `config.py` and fill in:

```python
CHALLENGE_ID    = "NAME_FROM_ORGANIZERS"
SCORING_API_URL = "https://..."
SCORING_API_KEY = ""               # leave empty if not required
OPENSEARCH_HOST = "https://..."    # for real-time pipeline
```

> ⚠️ AWS credentials (SSO or env vars) are required for **Bedrock** and **OpenSearch** access.

---

## 📖 Inspiration / Sources

This project was built for the **CND Hackathon** organized by EPITA / ESGI / ECE.
I used **Claude AI** (via Claude Code) to help design and implement the detection pipeline architecture.

Code created by me 😎, Thibault GAREL - [Github](https://github.com/Thibault-GAREL)
