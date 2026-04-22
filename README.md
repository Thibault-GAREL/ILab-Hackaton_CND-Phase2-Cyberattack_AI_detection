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

This project is an **AI-powered cybersecurity detection pipeline** built for the CND Hackathon (EPITA / ESGI / ECE — April 2026). It ingests raw security logs (network, authentication, application, system), detects cyberattacks using **heuristic rules**, enriches each detection with **Claude Opus 4.6 via Amazon Bedrock**, and submits results to a scoring REST API in standardized JSON format. The pipeline handles both a static dataset (21M logs in Parquet) and a real-time OpenSearch stream for the final day.

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

  📂 **Load** — reads the Parquet dataset in chunks of 100k rows to avoid OOM (21M rows, 411 MB)

  🔎 **Detect** — each detector runs on its filtered log subset (auth failures, HTTP 401s, network events)

  🧹 **Deduplicate** — overlapping detections from the same IP are resolved by the configured strategy

  🤖 **Enrich** — Claude Opus 4.6 refines the attack type and adds IoC indicators for each detection

  📤 **Submit** — each detection is POSTed to the scoring API; scores are logged in `scores_history.json`

  🔁 **Real-time** — `realtime_pipeline.py` polls OpenSearch, processes new batches, and auto-submits

---

## 🗺️ Schema

```text
OpenSearch (logs-raw) / Parquet (local)
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

> ⚠️ The dataset (`Dataset_log/logs-raw-merged.parquet`, 411 MB) is **not included** in the repo — place it manually in the `Dataset_log/` folder.

### Run the detection pipeline (local dataset)

```bash
python pipeline.py              # full run with Bedrock enrichment
python pipeline.py --no-bedrock # skip LLM (no AWS credentials needed)
python pipeline.py --no-dedup   # skip deduplication
```

### Review and submit detections

```bash
python submit.py --dry-run      # print payloads without sending
python submit.py                # submit all detections in detections.json
python submit.py --index 0      # submit only detection #0
```

### Run the real-time pipeline (OpenSearch stream — finale)

```bash
python realtime_pipeline.py             # start polling every 5 min
python realtime_pipeline.py --dry-run   # detect without submitting
python realtime_pipeline.py --reset     # restart from beginning of stream
```

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
