#!/usr/bin/env python3
"""Page 1 — Détections et lancement d'analyse (OpenSearch / Parquet)."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8080").rstrip("/")

_FD = Path(__file__).resolve().parent.parent
if str(_FD) not in sys.path:
    sys.path.insert(0, str(_FD))
from src.demo_ui import (
    SESSION_KILL,
    SESSION_MODEL,
    init_demo_session,
    normalize_detections_list,
    render_full_sidebar,
    render_static_action_row,
    STATIC_QUICK_ACTIONS,
    trigger_pipeline_run,
)

st.set_page_config(page_title="Détections | CND Phase 2", layout="wide", page_icon="\U0001F6A8")

# ---------------------------------------------------------------------------
# Shared dark CSS (injected per page since Streamlit isolates pages)
# ---------------------------------------------------------------------------
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
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.78rem;font-weight:700}
.badge-green{background:#064e3b;color:#10b981}
.badge-red{background:#450a0a;color:#ef4444}
.badge-orange{background:#451a03;color:#f59e0b}
.badge-blue{background:#172554;color:#3b82f6}
</style>
""",
    unsafe_allow_html=True,
)

with st.sidebar:
    init_demo_session()
    render_full_sidebar(BACKEND_URL)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
CHALLENGE_COLORS = {
    "credential_stuffing": "#EF4444",
    "ssh_brute_force": "#F59E0B",
    "sql_injection": "#8B5CF6",
    "directory_traversal": "#3B82F6",
    "ssrf": "#10B981",
}


def _fetch_detections() -> list[dict] | None:
    try:
        r = requests.get(f"{BACKEND_URL}/v1/detections", timeout=10)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                raw = data
            else:
                raw = data.get("detections", data.get("items", []))
            return normalize_detections_list(raw)
    except Exception:
        pass
    return None


def _load_local_detections() -> list[dict] | None:
    candidates = [
        Path(__file__).resolve().parents[2] / "detections.json",
        Path(__file__).resolve().parents[2] / "pipeline" / "detections.json",
    ]
    for p in candidates:
        if p.is_file():
            try:
                return normalize_detections_list(json.loads(p.read_text()))
            except Exception:
                continue
    return None


def _fmt_ts(ts: str | None) -> str:
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return str(ts)[:16]


# ---------------------------------------------------------------------------
# Page header + tableau de bord lancement analyse
# ---------------------------------------------------------------------------
st.markdown("# Détections & lancement d'analyse")
st.caption(
    "Ingestion organisateur (flux continu) distincte : ici vous contrôlez un **run manuel** "
    "sur OpenSearch (delta + curseur) ou un **bench Parquet** local."
)

with st.expander("Tableau de bord — lancer une analyse", expanded=True):
    tab_os, tab_pq = st.tabs(["OpenSearch (delta)", "Parquet (bench local)"])

    with tab_os:
        st.markdown("**Nombre de lignes** (`max-docs`) : plafond de logs lus par pagination `search_after`.")
        c_presets = st.columns(4)
        if c_presets[0].button("500", key="pre_os_500"):
            st.session_state["_os_lines"] = 500
        if c_presets[1].button("5 000", key="pre_os_5k"):
            st.session_state["_os_lines"] = 5000
        if c_presets[2].button("50 000", key="pre_os_50k"):
            st.session_state["_os_lines"] = 50000
        if c_presets[3].button("500 000 (max)", key="pre_os_500k"):
            st.session_state["_os_lines"] = 500000

        default_lines = int(st.session_state.get("_os_lines", 50_000))
        unlimited_os = st.checkbox("Sans limite de lignes (tout le delta disponible)", value=False, key="os_unlim")
        max_lines_os = st.number_input(
            "Plafond de lignes OpenSearch",
            min_value=1,
            max_value=500_000,
            value=min(default_lines, 500_000),
            step=500,
            disabled=unlimited_os,
            key="os_max_lines",
        )

        o1, o2 = st.columns(2)
        acc = o1.checkbox("Accumuler avec detections.json (slices)", value=False, key="os_acc")
        rst = o2.checkbox("Réinitialiser le curseur avant le run", value=False, key="os_rst")
        o3, o4 = st.columns(2)
        dry_c = o3.checkbox("Ne pas avancer le curseur après run (dry-run état)", value=False, key="os_dry")
        nd = o4.checkbox("Désactiver la dédup", value=False, key="os_nd")

        st.markdown("**Soumission scoring** (live nécessite PIPELINE_ALLOW_SUBMIT sur le backend)")
        s1, s2 = st.columns(2)
        sub_dry = s1.checkbox("Dry-run soumission API (--submit-dry-run)", value=False, key="os_sdry")
        sub_live = s2.checkbox("Soumission live (--submit)", value=False, key="os_sub")
        timeout_os = st.number_input(
            "Timeout (secondes)",
            30,
            7200,
            1800,
            30,
            key="os_to",
            help="30 min par défaut (enrichissement Bedrock / Opus sur gros delta).",
        )

        if st.button("Exécuter pipeline OpenSearch", type="primary", key="run_os"):
            mid = (st.session_state.get(SESSION_MODEL) or "").strip()
            if not mid:
                mid = "eu.anthropic.claude-opus-4-6-v1"
            body: dict = {
                "source": "opensearch",
                "accumulate": acc,
                "reset_state": rst,
                "dry_run_state": dry_c,
                "no_dedup": nd,
                "submit_dry_run": sub_dry,
                "submit": sub_live,
                "timeout_seconds": int(timeout_os),
                "bedrock_enabled": not st.session_state.get(SESSION_KILL, False),
                "model_id": mid,
            }
            if not unlimited_os:
                body["max_lines"] = int(max_lines_os)
            with st.spinner("Pipeline OpenSearch…"):
                res = trigger_pipeline_run(BACKEND_URL, body)
            if res.get("status") == "success":
                st.success(res.get("message", "OK"))
            else:
                st.error(res.get("message", "Erreur"))
            if res.get("stdout_tail"):
                with st.expander("stdout"):
                    st.code(res["stdout_tail"])
            if res.get("stderr_tail"):
                with st.expander("stderr"):
                    st.code(res["stderr_tail"])

    with tab_pq:
        st.markdown(
            "**Bench hors OpenSearch** : lit un export Parquet sous la racine du dépôt backend "
            "(conteneur). Utile pour valider détecteurs sur un extrait."
        )
        pq_path = st.text_input(
            "Chemin relatif au dépôt",
            value="data/opensearch-export/logs-raw-merged.parquet",
            key="pq_path",
        )
        c2p = st.columns(4)
        if c2p[0].button("1 000 lignes", key="pq_1k"):
            st.session_state["_pq_lines"] = 1000
        if c2p[1].button("10 000", key="pq_10k"):
            st.session_state["_pq_lines"] = 10000
        if c2p[2].button("100 000", key="pq_100k"):
            st.session_state["_pq_lines"] = 100000
        if c2p[3].button("1 M lignes", key="pq_1m"):
            st.session_state["_pq_lines"] = 1_000_000

        default_pq = int(st.session_state.get("_pq_lines", 100_000))
        unlimited_pq = st.checkbox("Lire tout le fichier Parquet (peut être très long / RAM)", value=False, key="pq_unlim")
        max_lines_pq = st.number_input(
            "Plafond de lignes Parquet",
            min_value=1,
            max_value=2_000_000,
            value=min(default_pq, 2_000_000),
            step=1000,
            disabled=unlimited_pq,
            key="pq_max",
        )
        batch_pq = st.number_input("Taille de lot lecture PyArrow (--batch-rows)", 1000, 2_000_000, 400_000, 1000, key="pq_batch")
        timeout_pq = st.number_input("Timeout (secondes)", 60, 7200, 3600, 60, key="pq_to")

        if st.button("Exécuter bench Parquet", type="primary", key="run_pq"):
            mid_p = (st.session_state.get(SESSION_MODEL) or "").strip()
            if not mid_p:
                mid_p = "eu.anthropic.claude-opus-4-6-v1"
            body = {
                "source": "parquet",
                "parquet_path": pq_path.strip(),
                "parquet_batch_rows": int(batch_pq),
                "timeout_seconds": int(timeout_pq),
                "bedrock_enabled": not st.session_state.get(SESSION_KILL, False),
                "model_id": mid_p,
            }
            if not unlimited_pq:
                body["max_lines"] = int(max_lines_pq)
            with st.spinner("Bench Parquet…"):
                res = trigger_pipeline_run(BACKEND_URL, body)
            if res.get("status") == "success":
                st.success(res.get("message", "OK"))
            else:
                st.error(res.get("message", "Erreur"))
            if res.get("stdout_tail"):
                with st.expander("stdout"):
                    st.code(res["stdout_tail"])
            if res.get("stderr_tail"):
                with st.expander("stderr"):
                    st.code(res["stderr_tail"])

    st.info(
        "**Arrêt de la recherche OpenSearch** : plus de résultats dans la fenêtre, plafond "
        "`max_lines` atteint, ou erreur HTTP. **Parquet** : fin de fichier ou plafond lignes."
    )

col_refresh, col_status = st.columns([1, 5])
with col_refresh:
    if st.button("\U0001F504 Rafraîchir", type="primary"):
        st.rerun()

detections = _fetch_detections()
source = "backend"
if detections is None:
    st.warning("\u26A0\ufe0f Backend injoignable — tentative de chargement local (`detections.json`).")
    detections = _load_local_detections()
    source = "fichier local"

if not detections:
    st.info(
        "Aucune détection disponible. Utilisez le tableau de bord ci-dessus ou la sidebar "
        "(lancement rapide), puis **Rafraîchir**."
    )
    st.stop()

with col_status:
    st.caption(f"Source : **{source}** \u2022 {len(detections)} détection(s)")

# ---------------------------------------------------------------------------
# KPI row (pas de métriques liées au temps)
# ---------------------------------------------------------------------------
st.markdown("---")
k1, k2, k3 = st.columns(3)
k1.metric("Détections", len(detections))

challenges_found = {d.get("challenge_id") or d.get("detection", {}).get("attack_type", "?") for d in detections}
k2.metric("Challenges couverts", f"{len(challenges_found)} / 5")

k3.metric("Score max / challenge", "100 pts")

# ---------------------------------------------------------------------------
# Timeline chart — attack windows
# ---------------------------------------------------------------------------
st.markdown("### \U0001F4C8 Timeline des attaques")

rows = []
for det in detections:
    inner = det.get("detection", {})
    cid = det.get("challenge_id") or inner.get("attack_type", "unknown")
    start = inner.get("attack_start_time") or det.get("attack_start_time")
    end = inner.get("attack_end_time") or det.get("attack_end_time")
    if start and end:
        rows.append(
            {
                "Challenge": cid,
                "Début": start,
                "Fin": end,
            }
        )

if rows:
    df_tl = pd.DataFrame(rows)
    df_tl["Début"] = pd.to_datetime(df_tl["Début"], utc=True, errors="coerce")
    df_tl["Fin"] = pd.to_datetime(df_tl["Fin"], utc=True, errors="coerce")
    df_tl = df_tl.dropna(subset=["Début", "Fin"])

    if not df_tl.empty:
        fig = px.timeline(
            df_tl,
            x_start="Début",
            x_end="Fin",
            y="Challenge",
            color="Challenge",
            color_discrete_map=CHALLENGE_COLORS,
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.6)",
            font_color="#cbd5e1",
            height=280,
            margin=dict(l=10, r=10, t=30, b=10),
            showlegend=False,
            xaxis=dict(gridcolor="#1e293b"),
            yaxis=dict(gridcolor="#1e293b"),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("Pas de données temporelles exploitables pour le graphique.")
else:
    st.caption("Aucune fenêtre temporelle dans les détections.")

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------
st.markdown("### \U0001F4CB Tableau des détections")

table_rows = []
for det in detections:
    inner = det.get("detection", {})
    cid = det.get("challenge_id") or inner.get("attack_type", "?")
    attack_type = inner.get("attack_type", cid)
    ips = inner.get("attacker_ips", det.get("attacker_ips", []))
    victims = inner.get("victim_accounts", det.get("victim_accounts", []))
    start = inner.get("attack_start_time") or det.get("attack_start_time")
    end = inner.get("attack_end_time") or det.get("attack_end_time")
    severity = inner.get("severity") or det.get("severity", "high")
    table_rows.append(
        {
            "Challenge": cid,
            "Type": attack_type,
            "IPs attaquantes": ", ".join(ips) if isinstance(ips, list) else str(ips),
            "Victimes": ", ".join(victims) if isinstance(victims, list) else str(victims),
            "Début": _fmt_ts(start),
            "Fin": _fmt_ts(end),
            "Sévérité": severity,
        }
    )

if table_rows:
    st.dataframe(
        pd.DataFrame(table_rows),
        use_container_width=True,
        hide_index=True,
    )

# ---------------------------------------------------------------------------
# Detailed cards per detection
# ---------------------------------------------------------------------------
st.markdown("### \U0001F50D Détails par détection")

for i, det in enumerate(detections):
    inner = det.get("detection", {})
    cid = det.get("challenge_id") or inner.get("attack_type", f"detection_{i}")

    with st.expander(f"\u25B6 {cid.upper().replace('_', ' ')}  —  {inner.get('attack_type', cid)}", expanded=False):
        c1, c2, c3 = st.columns(3)
        c1.markdown(f"**IPs attaquantes** : {', '.join(inner.get('attacker_ips', []))}")
        c2.markdown(f"**Victimes** : {', '.join(inner.get('victim_accounts', [])) or '—'}")
        c3.markdown(f"**Fenêtre** : {_fmt_ts(inner.get('attack_start_time'))} \u2192 {_fmt_ts(inner.get('attack_end_time'))}")

        indicators = inner.get("indicators", {})
        if indicators:
            st.markdown("**Indicateurs (IoC)**")
            ind_cols = st.columns(min(len(indicators), 4))
            for j, (k, v) in enumerate(indicators.items()):
                ind_cols[j % len(ind_cols)].code(f"{k}: {v}")
        else:
            st.caption("Aucun indicateur disponible.")

        st.markdown("**Playbooks statiques (démo jury)**")
        st.caption(
            "Pour chaque action : choisissez une exécution **manuelle** (SOC / change) ou **automatisée** "
            "(runbook — aucun appel AWS réel depuis cette UI)."
        )
        static_list = STATIC_QUICK_ACTIONS.get(cid, [])
        for idx, act in enumerate(static_list):
            render_static_action_row(cid, idx, act, detection_index=i)

# ---------------------------------------------------------------------------
# Actions de remédiation regroupées (vue synthétique)
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown("### \U0001F6E1 Synthèse des choix Manuel / Auto par challenge")
for di, det in enumerate(detections):
    cid = det.get("challenge_id") or det.get("detection", {}).get("attack_type", "?")
    st.markdown(f"**{cid}** (détection #{di})")
    for idx, act in enumerate(STATIC_QUICK_ACTIONS.get(cid, [])):
        aid = act.get("id", str(idx))
        mode = st.session_state.get(f"exec_mode_d{di}_{cid}_{aid}_{idx}", "—")
        st.write(f"- `{aid}` → mode sélectionné : **{mode}**")
