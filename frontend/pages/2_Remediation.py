#!/usr/bin/env python3
"""Page 2 — Remédiation & Garde-fous IA."""

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
from src.demo_ui import (
    init_demo_session,
    normalize_detections_list,
    render_full_sidebar,
    render_static_action_row,
    STATIC_QUICK_ACTIONS,
)

st.set_page_config(page_title="Remédiation | CND Phase 2", layout="wide", page_icon="\U0001F6E1")

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
.action-card{background:rgba(30,41,59,.55);border:1px solid #334155;border-radius:.5rem;padding:1rem;margin-bottom:.6rem}
.guardrail-flow{background:rgba(15,23,42,.7);border:1px solid #1e293b;border-radius:.5rem;padding:1.2rem;margin:.8rem 0}
</style>
""",
    unsafe_allow_html=True,
)

with st.sidebar:
    init_demo_session()
    render_full_sidebar(BACKEND_URL)

BLOCKED_ACTIONS = [
    "iam:DeleteUser",
    "iam:DeleteRole",
    "ec2:TerminateInstances",
    "rds:DeleteDBInstance",
    "s3:DeleteBucket",
    "lambda:DeleteFunction",
    "dynamodb:DeleteTable",
    "kms:DisableKey",
]

GUARDRAIL_BADGES = {
    "approved": ('<span class="badge badge-green">Approuvé</span>', "\u2705"),
    "blocked": ('<span class="badge badge-red">Bloqué</span>', "\U0001F6AB"),
    "pending_review": ('<span class="badge badge-orange">À valider</span>', "\u26A0\ufe0f"),
    "needs_review": ('<span class="badge badge-orange">Revue requise</span>', "\u26A0\ufe0f"),
}


def _fetch_detections() -> list[dict]:
    try:
        r = requests.get(f"{BACKEND_URL}/v1/detections", timeout=10)
        if r.status_code == 200:
            data = r.json()
            raw = data if isinstance(data, list) else data.get("detections", data.get("items", []))
            return normalize_detections_list(raw)
    except Exception:
        pass
    return []


def _guard_status_ui(status: str) -> str:
    if status == "needs_review":
        return "needs_review"
    return status


def _validate_plan(plan: dict) -> dict:
    try:
        body = {"remediation_plan": plan}
        r = requests.post(f"{BACKEND_URL}/v1/remediation/validate", json=body, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {"validated": False, "actions": [], "approved": 0, "blocked": 0, "needs_review": 0}


def _fetch_catalog() -> dict | None:
    try:
        r = requests.get(f"{BACKEND_URL}/v1/remediation/catalog", timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


st.markdown("# \U0001F6E1 Remédiation & Garde-fous IA")

detections = _fetch_detections()

st.markdown("## \U0001F4CB Plans de remédiation")

if not detections:
    st.warning("Aucune détection disponible depuis le backend. Lancez la pipeline ou chargez `detections.json`.")
else:
    for det_i, det in enumerate(detections):
        inner = det.get("detection", {})
        cid = det.get("challenge_id") or inner.get("attack_type", "?")
        remediation = det.get("remediation") or inner.get("remediation")

        with st.expander(f"\u25B6 {cid.upper().replace('_', ' ')} (#{det_i})", expanded=False):
            st.markdown("### Actions du playbook statique (dictionnaire projet)")
            st.caption("Choix d’application : manuel vs automatisé (démo jury).")
            for idx, act in enumerate(STATIC_QUICK_ACTIONS.get(cid, [])):
                render_static_action_row(cid, idx, act, detection_index=det_i)

            if not remediation:
                st.caption("Aucun plan enrichi `remediation` dans le JSON pour cette détection.")
                continue

            st.markdown("### Plan structuré (JSON pipeline)")
            actions = remediation if isinstance(remediation, list) else remediation.get("actions", [remediation])
            if isinstance(remediation, dict):
                plan_for_api = {**remediation, "challenge_id": cid, "actions": actions}
            else:
                plan_for_api = {"challenge_id": cid, "actions": actions, "version": "1.0"}
            validation = _validate_plan(plan_for_api)
            if validation.get("blocked", 0) > 0:
                overall = "blocked"
            elif validation.get("validated"):
                overall = "approved"
            else:
                overall = "needs_review"

            ui_overall = _guard_status_ui(overall)
            badge_html, _ = GUARDRAIL_BADGES.get(ui_overall, GUARDRAIL_BADGES["pending_review"])
            st.markdown(f"**Synthèse garde-fou (API)** : {badge_html}", unsafe_allow_html=True)

            val_actions = validation.get("actions") or []
            for idx, action in enumerate(actions):
                if not isinstance(action, dict):
                    st.code(str(action))
                    continue

                title = action.get("title", action.get("type", f"Action {idx + 1}"))
                service = action.get("aws_service", action.get("service", "—"))
                desc = action.get("description", "—")
                hint = action.get("automation_hint", "")
                action_status = action.get("guardrail_status")
                if idx < len(val_actions) and isinstance(val_actions[idx], dict):
                    action_status = val_actions[idx].get("guardrail_status", action_status)
                action_status = _guard_status_ui(action_status or overall)
                a_badge, _ = GUARDRAIL_BADGES.get(action_status, GUARDRAIL_BADGES["pending_review"])

                st.markdown(
                    f"""<div class="action-card">
<strong>{title}</strong> {a_badge}<br/>
<span style="color:#94a3b8;font-size:.85rem">Service AWS : <code>{service}</code></span><br/>
<span style="color:#cbd5e1">{desc}</span>
{"<br/><span style='color:#64748b;font-size:.8rem'>Hint : <code>" + hint + "</code></span>" if hint else ""}
</div>""",
                    unsafe_allow_html=True,
                )
                aid = action.get("id", f"plan_{idx}")
                st.radio(
                    "Application",
                    ["Manuel (SOC / change)", "Automatisé (runbook / Step Functions)"],
                    horizontal=True,
                    key=f"rem_plan_mode_d{det_i}_{cid}_{aid}_{idx}",
                )

st.markdown("---")
st.markdown("## \U0001F9E0 Protection contre les hallucinations IA")

st.markdown(
    """<div class="guardrail-flow">
<h4 style="color:#10b981;margin-top:0">Workflow de validation en 3 étapes</h4>
<table style="width:100%;border-collapse:collapse;color:#cbd5e1">
<tr>
<td style="text-align:center;padding:1rem;border-right:1px solid #334155;width:33%">
<div style="font-size:2rem">\U0001F916</div>
<strong style="color:#3b82f6">1. Bedrock propose</strong><br/>
<span style="font-size:.85rem;color:#94a3b8">Claude analyse les détections et génère un plan structuré.</span>
</td>
<td style="text-align:center;padding:1rem;border-right:1px solid #334155;width:33%">
<div style="font-size:2rem">\U0001F6E1</div>
<strong style="color:#f59e0b">2. Guardrails filtre</strong><br/>
<span style="font-size:.85rem;color:#94a3b8">Chaque action est validée contre une liste d'actions interdites.</span>
</td>
<td style="text-align:center;padding:1rem;width:33%">
<div style="font-size:2rem">\U0001F464</div>
<strong style="color:#10b981">3. Humain valide</strong><br/>
<span style="font-size:.85rem;color:#94a3b8">Un opérateur humain approuve ou rejette les actions avant exécution.</span>
</td>
</tr>
</table>
</div>""",
    unsafe_allow_html=True,
)

st.markdown("### \U0001F6AB Actions bloquées automatiquement")
st.markdown("Les actions AWS suivantes sont **systématiquement bloquées** par les garde-fous :")

cols = st.columns(4)
for i, action in enumerate(BLOCKED_ACTIONS):
    cols[i % 4].markdown(
        f'<span class="badge badge-red">{action}</span>',
        unsafe_allow_html=True,
    )

st.markdown("")
st.markdown(
    """
**Règles supplémentaires :**
- Toute action `Delete*` ou `Terminate*` est bloquée sans approbation explicite
- Les modifications IAM (`iam:Create*`, `iam:Attach*`) nécessitent une validation humaine
- Les opérations de chiffrement (`kms:*`) sont tracées et auditées
- Les actions sur les données de production (`rds:*`, `dynamodb:*`) requièrent un double contrôle
"""
)

st.markdown("---")
st.markdown("## \U0001F4DA Catalogue de playbooks")

catalog = _fetch_catalog()

if catalog:
    playbooks = catalog if isinstance(catalog, list) else catalog.get("playbooks", catalog.get("items", []))
    if playbooks:
        for pb in playbooks:
            if isinstance(pb, dict):
                name = pb.get("name", pb.get("id", "Playbook"))
                desc = pb.get("description", "—")
                st.markdown(f"**{name}** — {desc}")
            else:
                st.markdown(f"- {pb}")
    else:
        st.caption("Catalogue vide.")
else:
    st.info(
        "Le catalogue de playbooks n'est pas disponible (endpoint `/v1/remediation/catalog` non accessible). "
        "Voir les playbooks intégrés sur la page Détections."
    )
