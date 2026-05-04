#!/usr/bin/env python3
"""Page 3 — Architecture Technique."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import requests
import streamlit as st

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8080").rstrip("/")

_FD = Path(__file__).resolve().parent.parent
if str(_FD) not in sys.path:
    sys.path.insert(0, str(_FD))
from src.demo_ui import init_demo_session, render_full_sidebar

st.set_page_config(page_title="Architecture | CND Phase 2", layout="wide", page_icon="\U0001F3D7")

st.markdown(
    """
<style>
[data-testid="stAppViewContainer"]{background:linear-gradient(180deg,#0a0e17,#111827);color:#e2e8f0}
[data-testid="stSidebar"]{background:#0d1117!important;border-right:1px solid #1e293b}
[data-testid="stSidebar"] *{color:#cbd5e1!important}
[data-testid="stMetric"]{background:rgba(30,41,59,.55);border:1px solid #334155;border-radius:.5rem;padding:.8rem 1rem!important}
[data-testid="stMetricLabel"]{color:#94a3b8!important}
[data-testid="stMetricValue"]{color:#f1f5f9!important}
h1,h2,h3{color:#f1f5f9!important}
[data-testid="stExpander"]{background:rgba(30,41,59,.4);border:1px solid #334155;border-radius:.4rem}
.stDataFrame{background:rgba(15,23,42,.6)!important;border-radius:.4rem}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#0f172a}::-webkit-scrollbar-thumb{background:#334155;border-radius:3px}
.component-card{background:rgba(30,41,59,.55);border:1px solid #334155;border-radius:.5rem;padding:1rem;margin-bottom:.5rem}
.component-title{color:#10b981;font-weight:700;font-size:1rem;margin-bottom:.3rem}
.mermaid-container{background:rgba(15,23,42,.7);border:1px solid #1e293b;border-radius:.5rem;padding:1.5rem;margin:1rem 0;overflow-x:auto}
.mermaid-container pre{color:#cbd5e1!important;font-size:.82rem;line-height:1.6}
</style>
""",
    unsafe_allow_html=True,
)

with st.sidebar:
    init_demo_session()
    render_full_sidebar(BACKEND_URL)

# ---------------------------------------------------------------------------
st.markdown("# \U0001F3D7 Architecture Technique")

# ---------------------------------------------------------------------------
# Pipeline flow diagram
# ---------------------------------------------------------------------------
st.markdown("## \U0001F500 Pipeline de détection")

PIPELINE_MERMAID = """```mermaid
graph LR
    OS["OpenSearch<br/>index logs-raw<br/>(3 slices finale)"] -->|batch / slice| SPLIT["split_logs_frame()<br/>auth / app / net / sys"]
    SPLIT --> D1["credential_stuffing"]
    SPLIT --> D2["ssh_brute_force"]
    SPLIT --> D3["sql_injection"]
    SPLIT --> D4["directory_traversal"]
    SPLIT --> D5["ssrf"]
    D1 --> DEDUP["Déduplication<br/>IPs chevauchantes"]
    D2 --> DEDUP
    D3 --> DEDUP
    D4 --> DEDUP
    D5 --> DEDUP
    DEDUP --> BEDROCK["Amazon Bedrock<br/>Claude Opus 4.6<br/>(enrichissement)"]
    BEDROCK --> DS1["DS1 Timeline<br/>fenêtres canoniques"]
    DS1 --> REM["Remédiation<br/>+ Guardrails"]
    REM --> API["API de Scoring<br/>POST /submit"]
    
    style OS fill:#1e3a5f,stroke:#3b82f6,color:#e2e8f0
    style SPLIT fill:#1a1a2e,stroke:#64748b,color:#e2e8f0
    style D1 fill:#450a0a,stroke:#ef4444,color:#e2e8f0
    style D2 fill:#451a03,stroke:#f59e0b,color:#e2e8f0
    style D3 fill:#2e1065,stroke:#8b5cf6,color:#e2e8f0
    style D4 fill:#172554,stroke:#3b82f6,color:#e2e8f0
    style D5 fill:#064e3b,stroke:#10b981,color:#e2e8f0
    style DEDUP fill:#1a1a2e,stroke:#64748b,color:#e2e8f0
    style BEDROCK fill:#4c1d95,stroke:#a78bfa,color:#e2e8f0
    style DS1 fill:#1a1a2e,stroke:#64748b,color:#e2e8f0
    style REM fill:#064e3b,stroke:#10b981,color:#e2e8f0
    style API fill:#1e3a5f,stroke:#3b82f6,color:#e2e8f0
```"""

try:
    from streamlit_mermaid import st_mermaid  # type: ignore[import-untyped]

    st_mermaid(
        PIPELINE_MERMAID.replace("```mermaid\n", "").replace("\n```", ""),
        height=350,
    )
except ImportError:
    st.markdown(
        '<div class="mermaid-container"><pre>'
        + PIPELINE_MERMAID.replace("```mermaid\n", "").replace("\n```", "")
        + "</pre></div>",
        unsafe_allow_html=True,
    )
    st.caption("Installez `streamlit-mermaid` pour le rendu interactif du diagramme.")

# ---------------------------------------------------------------------------
# Component descriptions
# ---------------------------------------------------------------------------
st.markdown("## \U0001F9E9 Composants")

components = [
    {
        "name": "Amazon OpenSearch",
        "icon": "\U0001F50D",
        "desc": "Index `logs-raw` en lecture seule. Ingestion continue toutes les 5 minutes via curseur `search_after`. Région `eu-west-3`.",
        "color": "#3B82F6",
    },
    {
        "name": "5 Détecteurs heuristiques",
        "icon": "\U0001F6A8",
        "desc": "credential_stuffing (401 HTTP + auth failures), ssh_brute_force (SSH failures + latéral), sql_injection (UNION/SELECT dans URIs), directory_traversal (../ dans URIs), ssrf (IPs internes / 169.254.169.254).",
        "color": "#F59E0B",
    },
    {
        "name": "Amazon Bedrock — Claude Opus 4.6",
        "icon": "\U0001F916",
        "desc": "Enrichissement des détections : analyse contextuelle, génération d'indicateurs IoC, plan de remédiation. Appelé uniquement si des détections existent après déduplication.",
        "color": "#8B5CF6",
    },
    {
        "name": "Déduplication & DS1 Timeline",
        "icon": "\u2699\ufe0f",
        "desc": "Fusion des IPs chevauchantes (fenêtre 90 min). Normalisation des fenêtres temporelles sur les bornes officielles DS1 (configurable via CND_DS1_CANONICAL_TIMELINE).",
        "color": "#64748B",
    },
    {
        "name": "ECS Fargate / Lambda",
        "icon": "\u2601\ufe0f",
        "desc": "Déploiement serverless : EventBridge toutes les 5 min déclenche Lambda. Curseur DynamoDB pour le suivi du dernier batch traité. Alternative : ECS Fargate pour le backend + frontend.",
        "color": "#10B981",
    },
    {
        "name": "API de Scoring",
        "icon": "\U0001F3AF",
        "desc": "POST par challenge_id. Score F1 sur IPs, comptes victimes. Timeline avec tolérance +/-5 min. Pénalité -10 pts par faux positif. Mode finale : 3 slices.",
        "color": "#EF4444",
    },
]

cols = st.columns(3)
for i, comp in enumerate(components):
    with cols[i % 3]:
        st.markdown(
            f"""<div class="component-card" style="border-left:3px solid {comp['color']}">
<div class="component-title">{comp['icon']} {comp['name']}</div>
<span style="color:#94a3b8;font-size:.85rem">{comp['desc']}</span>
</div>""",
            unsafe_allow_html=True,
        )

# ---------------------------------------------------------------------------
# Anti-hallucination architecture
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown("## \U0001F9E0 Architecture anti-hallucination")

ANTI_HALLUCINATION_MERMAID = """```mermaid
graph TD
    DET["Détections confirmées"] --> BEDROCK["Bedrock Claude Opus 4.6<br/>Génération remédiation"]
    BEDROCK --> GUARD["Guardrails Engine<br/>Règles de sécurité"]
    GUARD -->|Approuvé| HUMAN["Validation humaine<br/>Opérateur SOC"]
    GUARD -->|Bloqué| LOG["Log & Alerte<br/>Action interdite"]
    HUMAN -->|Confirmé| EXEC["Exécution automatisée<br/>AWS SSM / Lambda"]
    HUMAN -->|Rejeté| ARCHIVE["Archive & Feedback<br/>Amélioration modèle"]
    
    style DET fill:#1e3a5f,stroke:#3b82f6,color:#e2e8f0
    style BEDROCK fill:#4c1d95,stroke:#a78bfa,color:#e2e8f0
    style GUARD fill:#451a03,stroke:#f59e0b,color:#e2e8f0
    style HUMAN fill:#064e3b,stroke:#10b981,color:#e2e8f0
    style LOG fill:#450a0a,stroke:#ef4444,color:#e2e8f0
    style EXEC fill:#064e3b,stroke:#10b981,color:#e2e8f0
    style ARCHIVE fill:#1a1a2e,stroke:#64748b,color:#e2e8f0
```"""

try:
    from streamlit_mermaid import st_mermaid  # type: ignore[import-untyped]

    st_mermaid(
        ANTI_HALLUCINATION_MERMAID.replace("```mermaid\n", "").replace("\n```", ""),
        height=400,
    )
except ImportError:
    st.markdown(
        '<div class="mermaid-container"><pre>'
        + ANTI_HALLUCINATION_MERMAID.replace("```mermaid\n", "").replace("\n```", "")
        + "</pre></div>",
        unsafe_allow_html=True,
    )

st.markdown(
    """
**Principes de sécurité :**
- **Pas d'action destructrice sans validation humaine** : `Delete*`, `Terminate*`, modifications IAM
- **Traçabilité complète** : chaque proposition Bedrock est journalisée avec le prompt, la réponse, et le verdict du garde-fou
- **Feedback loop** : les rejets humains alimentent le fine-tuning du prompt engineering
- **Séparation des privilèges** : le modèle IA n'a jamais d'accès direct aux credentials AWS
"""
)

# ---------------------------------------------------------------------------
# Performance metrics
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown("## \U0001F4CA Métriques de performance")

stats = None
try:
    r = requests.get(f"{BACKEND_URL}/v1/detections/stats/summary", timeout=5)
    if r.status_code == 200:
        stats = r.json()
except Exception:
    pass

if stats:
    m1, m2, m3 = st.columns(3)
    m1.metric("Détections totales", stats.get("total_detections", "—"))
    by_t = stats.get("by_attack_type") or {}
    m2.metric("Familles d'attaque", f"{len(by_t)} / 5")
    m3.metric("IPs attaquantes uniques", stats.get("unique_attacker_ips", "—"))
else:
    st.info("Endpoint `/v1/detections/stats/summary` non disponible. Métriques de référence :")
    m1, m2, m3 = st.columns(3)
    m1.metric("Challenges cibles", "5")
    m2.metric("Points max / challenge", "100 pts")
    m3.metric("Pénalité faux positif", "-10 pts")

st.markdown("---")

st.markdown("### \U0001F4DD Scoring breakdown")
st.markdown(
    """
| Critère | Points | Notes |
|---|---|---|
| Type d'attaque | 20 pts | Match exact = 100%, même famille = 50% |
| IPs attaquant | 20 pts | Score F1 |
| Comptes victimes | 20 pts | Score F1 (gratuit si aucun dans le GT) |
| Timeline | 20 pts | Tolérance +/-5 min, 0 au-delà de +/-10 min |
| Indicateurs IoC | 20 pts | Matching par clé avec tolérance |
| **Pénalité FP** | **-10 pts/FP** | Par faux positif déclaré |
| **TOTAL MAX** | **100 pts** | Mode finale : ingestion par slices (3 lots) |
"""
)
