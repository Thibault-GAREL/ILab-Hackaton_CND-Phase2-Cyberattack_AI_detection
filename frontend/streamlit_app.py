#!/usr/bin/env python3
"""CND Phase 2 — Détection IA : point d'entrée Streamlit (multi-pages)."""

import os
import sys
from pathlib import Path

import requests
import streamlit as st

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8080").rstrip("/")

_FD = Path(__file__).resolve().parent
if str(_FD) not in sys.path:
    sys.path.insert(0, str(_FD))
from src.demo_ui import init_demo_session, render_full_sidebar

st.set_page_config(
    page_title="CND Phase 2 — Détection IA",
    page_icon="\U0001F6E1",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Dark / cybersecurity CSS
# ---------------------------------------------------------------------------
st.markdown(
    """
<style>
/* ---------- global dark overrides ---------- */
[data-testid="stAppViewContainer"] {
    background: linear-gradient(180deg, #0a0e17 0%, #111827 100%);
    color: #e2e8f0;
}
[data-testid="stSidebar"] {
    background: #0d1117 !important;
    border-right: 1px solid #1e293b;
}
[data-testid="stSidebar"] * { color: #cbd5e1 !important; }

/* sidebar title area */
.sidebar-title {
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 1.25rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    color: #10b981 !important;
    border-bottom: 1px solid #1e293b;
    padding-bottom: .6rem;
    margin-bottom: .8rem;
}
.sidebar-subtitle {
    font-size: .8rem;
    color: #64748b !important;
    margin-top: -0.5rem;
}

/* status badge */
.status-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 999px;
    font-size: .78rem;
    font-weight: 600;
}
.status-online  { background: #064e3b; color: #10b981; }
.status-offline { background: #450a0a; color: #ef4444; }

/* metric cards */
[data-testid="stMetric"] {
    background: rgba(30, 41, 59, .55);
    border: 1px solid #334155;
    border-radius: .5rem;
    padding: .8rem 1rem !important;
}
[data-testid="stMetricLabel"] { color: #94a3b8 !important; }
[data-testid="stMetricValue"] { color: #f1f5f9 !important; }

/* headings */
h1, h2, h3 { color: #f1f5f9 !important; }

/* expander */
[data-testid="stExpander"] {
    background: rgba(30,41,59,.4);
    border: 1px solid #334155;
    border-radius: .4rem;
}

/* tables */
.stDataFrame { background: rgba(15,23,42,.6) !important; border-radius: .4rem; }

/* scrollbar */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0f172a; }
::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
</style>
""",
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Sidebar (navigation + kill switch + modèle + lancement rapide)
# ---------------------------------------------------------------------------
with st.sidebar:
    init_demo_session()
    render_full_sidebar(BACKEND_URL)


# ---------------------------------------------------------------------------
# Home page content
# ---------------------------------------------------------------------------
st.markdown("# \U0001F6E1 CND Phase 2 — Détection IA de Cyberattaques")
st.markdown(
    """
> **Pipeline** : ingestion OpenSearch (dont **3 slices** en finale) \u2192 détecteurs \u2192
> enrichissement Bedrock (désactivable via kill switch) \u2192 garde-fous \u2192 scoring (**100 pts** / challenge, mode finale).
"""
)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Détecteurs", "5", help="credential_stuffing, ssh_brute_force, sql_injection, directory_traversal, ssrf")
_mid = st.session_state.get("bedrock_model_id", "—")
if isinstance(_mid, str) and len(_mid) > 40:
    _mid = _mid[:37] + "…"
col2.metric(
    "Modèle cible (démo)",
    _mid,
    help="Modifiable dans la barre latérale — utilisé au prochain poll pipeline (BEDROCK_MODEL_ID).",
)
col3.metric(
    "Run manuel",
    "UI / API",
    help="Lancement contrôlé (lignes, Parquet) depuis la page Détections — distinct du flux injecté organisateur.",
)
col4.metric("Scoring max", "100 pts", help="100 pts détection (5 critères × 20 pts)")

st.markdown("---")

c1, c2 = st.columns(2)
with c1:
    st.markdown("### \U0001F3AF Challenges DS1")
    st.markdown(
        """
| Challenge | Type | Points |
|---|---|---|
| `credential_stuffing` | Credential stuffing \u2192 web shell \u2192 reverse shell | 100 |
| `ssh_brute_force` | Brute force SSH \u2192 mouvement latéral \u2192 priv-esc | 100 |
| `sql_injection` | SQLi \u2192 exfiltration ~25 MB | 100 |
| `directory_traversal` | Path traversal \u2192 fichiers sensibles | 80 |
| `ssrf` | SSRF \u2192 metadata + services internes | 80 |
"""
    )

with c2:
    st.markdown("### \u2699\ufe0f Stack technique")
    st.markdown(
        """
- **Ingestion** : Amazon OpenSearch (`logs-raw`, delta `search_after`)
- **Détection** : 5 détecteurs heuristiques Python
- **Enrichissement** : Amazon Bedrock — Claude Opus 4.6
- **Déduplication** : fenêtre temporelle + IPs chevauchantes
- **Déploiement** : ECS Fargate / Lambda + EventBridge
- **Scoring** : API REST POST avec breakdown détaillé
"""
    )

st.markdown("---")
st.info(
    "\U0001F449 Utilisez la **barre latérale** pour naviguer vers les pages "
    "Détections, Remédiation et Architecture."
)
