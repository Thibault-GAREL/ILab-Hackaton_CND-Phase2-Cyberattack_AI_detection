"""
Contrôles démo jury : sidebar (kill switch, modèle), normalisation API, playbooks statiques.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import requests
import streamlit as st

# ---------------------------------------------------------------------------
# Chemins
# ---------------------------------------------------------------------------


def frontend_dir() -> Path:
    p = Path(__file__).resolve().parent.parent
    return p


def repo_root() -> Path:
    return frontend_dir().parent


# ---------------------------------------------------------------------------
# Session (kill switch = désactiver Bedrock au prochain poll ; modèle cible)
# ---------------------------------------------------------------------------

SESSION_KILL = "ia_kill_switch"
SESSION_MODEL = "bedrock_model_id"


def init_demo_session() -> None:
    # Défauts « pleine qualité » : Bedrock activé, Claude Opus 4.6 (profil EU hackathon).
    if SESSION_KILL not in st.session_state:
        st.session_state[SESSION_KILL] = False
    if SESSION_MODEL not in st.session_state:
        st.session_state[SESSION_MODEL] = "eu.anthropic.claude-opus-4-6-v1"
    if "_os_lines" not in st.session_state:
        st.session_state["_os_lines"] = 50_000
    if "_pq_lines" not in st.session_state:
        st.session_state["_pq_lines"] = 100_000


# Playbooks statiques affichés au jury (alignés sur les ids guardrails backend)
STATIC_QUICK_ACTIONS: dict[str, list[dict[str, str]]] = {
    "credential_stuffing": [
        {"id": "waf-ip-block", "title": "Blocage IP au bord (WAF)", "service": "AWS WAFv2"},
        {"id": "cognito-rate", "title": "Renforcer Cognito (MFA / débit)", "service": "Amazon Cognito"},
        {"id": "s3-remove-malware", "title": "Retirer web shell / malware S3", "service": "Amazon S3"},
    ],
    "ssh_brute_force": [
        {"id": "nacl-deny-source", "title": "NACL deny sur IP sources", "service": "Amazon VPC"},
        {"id": "sg-ssh-bastion-only", "title": "SSH limité au bastion", "service": "Amazon EC2 (SG)"},
        {"id": "ssm-audit-keys", "title": "Audit authorized_keys / sudoers", "service": "AWS SSM"},
    ],
    "sql_injection": [
        {"id": "waf-sqli-managed", "title": "Règles managées SQLi (WAF)", "service": "AWS WAFv2"},
        {"id": "rds-sg-least-privilege", "title": "SG RDS moindre privilège", "service": "Amazon RDS"},
        {"id": "waf-rate-uri", "title": "Rate limit URI sensibles", "service": "AWS WAFv2"},
    ],
    "directory_traversal": [
        {"id": "waf-path-traversal", "title": "Bloquer traversal (WAF)", "service": "AWS WAFv2"},
        {"id": "s3-block-public", "title": "S3 Block Public Access", "service": "Amazon S3"},
        {"id": "iam-app-role-tighten", "title": "Revoir rôle IAM applicatif", "service": "AWS IAM"},
    ],
    "ssrf": [
        {"id": "waf-ssrf-metadata", "title": "Bloquer metadata / RFC1918 (WAF)", "service": "AWS WAFv2"},
        {"id": "vpc-endpoint-imds", "title": "Imposer IMDSv2", "service": "Amazon EC2"},
        {"id": "sg-egress-review", "title": "Audit egress SG", "service": "Amazon EC2 (SG)"},
    ],
}

MODEL_PRESETS: list[dict[str, str]] = [
    {
        "key": "opus_eu",
        "label": "Claude Opus 4.6 (EU — imposé hackathon)",
        "id": "eu.anthropic.claude-opus-4-6-v1",
    },
    {
        "key": "opus_us",
        "label": "Claude Opus 4.6 (global)",
        "id": "anthropic.claude-opus-4-6-v1",
    },
    {
        "key": "sonnet_eu",
        "label": "Claude 3.5 Sonnet (plus rapide / moins cher — profil EU)",
        "id": "eu.anthropic.claude-3-5-sonnet-20240620-v1:0",
    },
]


def normalize_detection_payload(d: dict[str, Any]) -> dict[str, Any]:
    """Aplatit la réponse API (DetectionSummary) vers la forme nested attendue par les pages."""
    if isinstance(d.get("detection"), dict):
        return d
    return {
        "id": d.get("id"),
        "challenge_id": d.get("challenge_id", ""),
        "remediation": d.get("remediation"),
        "detection": {
            "attack_type": d.get("attack_type", ""),
            "attacker_ips": d.get("attacker_ips") or [],
            "victim_accounts": d.get("victim_accounts") or [],
            "attack_start_time": d.get("start_time") or "",
            "attack_end_time": d.get("end_time") or "",
            "indicators": d.get("indicators") or {},
        },
    }


def normalize_detections_list(items: list[dict]) -> list[dict]:
    return [normalize_detection_payload(x) for x in items]


def _fetch_health(backend_url: str) -> dict | None:
    try:
        r = requests.get(f"{backend_url}/health", timeout=2)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def trigger_pipeline_run(backend_url: str, body: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/detections/pipeline/run — timeout client adapté (runs Parquet longs)."""
    to = int(body.get("timeout_seconds") or 3600)
    client_timeout = min(max(to + 120, 600), 7300)
    try:
        r = requests.post(
            f"{backend_url}/v1/detections/pipeline/run",
            json=body,
            timeout=client_timeout,
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 403:
            try:
                detail = r.json().get("detail", r.text)
            except Exception:
                detail = r.text[:800]
            return {"status": "error", "message": str(detail), "detections_count": 0}
        return {"status": "error", "message": r.text[:800], "detections_count": 0}
    except Exception as e:
        return {"status": "error", "message": str(e), "detections_count": 0}


def trigger_pipeline_poll(
    backend_url: str,
    *,
    bedrock_enabled: bool | None,
    model_id: str | None,
) -> dict[str, Any]:
    mid = (model_id or "").strip() or "eu.anthropic.claude-opus-4-6-v1"
    body: dict[str, Any] = {"source": "opensearch", "model_id": mid}
    if bedrock_enabled is not None:
        body["bedrock_enabled"] = bedrock_enabled
    return trigger_pipeline_run(backend_url, body)


def render_operational_sidebar(backend_url: str) -> None:
    """Barre latérale : kill switch IA, choix de modèle Bedrock, lancement rapide OpenSearch."""
    init_demo_session()

    st.markdown("---")
    st.markdown("**Contrôles démo**")

    st.session_state[SESSION_KILL] = st.checkbox(
        "Kill switch IA (Bedrock désactivé au prochain lancement)",
        value=st.session_state[SESSION_KILL],
        help="En cas de dérive du modèle ou de panne Bedrock : la pipeline "
        "s'appuie uniquement sur les détecteurs heuristiques et les playbooks statiques.",
    )

    labels = [m["label"] for m in MODEL_PRESETS]
    default_idx = 0
    cur = st.session_state[SESSION_MODEL]
    for i, m in enumerate(MODEL_PRESETS):
        if m["id"] == cur:
            default_idx = i
            break
    choice = st.selectbox(
        "Modèle Bedrock cible",
        options=range(len(MODEL_PRESETS)),
        format_func=lambda i: labels[i],
        index=default_idx,
        help="Utilisé par les lancements depuis le tableau de bord ou le bouton rapide ci-dessous.",
    )
    st.session_state[SESSION_MODEL] = MODEL_PRESETS[choice]["id"]

    st.caption("Lancements détaillés (lignes, Parquet, curseur) : **voir la page Détections**.")

    if st.button("Lancement rapide OpenSearch (sans limite de lignes)", type="secondary"):
        with st.spinner("Pipeline OpenSearch…"):
            res = trigger_pipeline_poll(
                backend_url,
                bedrock_enabled=not st.session_state[SESSION_KILL],
                model_id=st.session_state[SESSION_MODEL],
            )
        if res.get("status") == "success":
            st.success(res.get("message", "OK"))
        else:
            st.error(res.get("message", "Erreur inconnue"))
        st.session_state["_pipeline_last_result"] = res


def render_navigation_sidebar() -> None:
    st.markdown("**Navigation**")
    st.page_link("streamlit_app.py", label="Accueil", icon=None)
    st.page_link("pages/1_Detections.py", label="Détections & lancement analyse")
    st.page_link("pages/2_Remediation.py", label="Remédiation & Garde-fous")
    st.page_link("pages/3_Architecture.py", label="Architecture technique")


def render_full_sidebar(backend_url: str) -> None:
    """Titre, santé backend, navigation, contrôles démo, légende."""
    st.markdown(
        """
<style>
.status-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:999px;
font-size:.78rem;font-weight:600}
.status-online{background:#064e3b;color:#10b981}
.status-offline{background:#450a0a;color:#ef4444}
.sidebar-title{font-family:'JetBrains Mono','Fira Code',monospace;font-size:1.25rem;font-weight:700;
letter-spacing:.05em;color:#10b981!important;border-bottom:1px solid #1e293b;padding-bottom:.6rem;margin-bottom:.8rem}
.sidebar-subtitle{font-size:.8rem;color:#64748b!important;margin-top:-0.5rem}
</style>
""",
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="sidebar-title">CND Phase 2</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="sidebar-subtitle">Détection IA — Cyberattaques</div>',
        unsafe_allow_html=True,
    )
    st.markdown("---")

    health = _fetch_health(backend_url)
    if health:
        st.markdown(
            '<span class="status-badge status-online">● Backend en ligne</span>',
            unsafe_allow_html=True,
        )
        st.caption(
            f"v{health.get('version', '?')} · {health.get('mode', '?')} · {health.get('env', '?')}"
        )
    else:
        st.markdown(
            '<span class="status-badge status-offline">● Backend hors ligne</span>',
            unsafe_allow_html=True,
        )

    st.markdown("---")
    render_navigation_sidebar()
    render_operational_sidebar(backend_url)

    st.markdown("---")
    st.caption("Hackathon CND — EPITA / ESGI / ECE")
    st.caption(f"Backend : `{backend_url}`")


def render_static_action_row(
    challenge_id: str,
    action_idx: int,
    action: dict[str, str],
    *,
    detection_index: int = 0,
) -> None:
    """Une ligne playbook statique + choix Manuel vs Automatisé.

    `detection_index` évite les clés Streamlit dupliquées lorsque plusieurs lignes
    partagent le même challenge_id (ex. plusieurs détections sql_injection).
    """
    aid = action.get("id", f"a{action_idx}")
    st.markdown(
        f"**{action.get('title', aid)}** · `{action.get('service', '—')}` · id `{aid}`"
    )
    st.radio(
        "Application",
        ["Manuel (SOC / change)", "Automatisé (runbook / Step Functions)"],
        horizontal=True,
        key=f"exec_mode_d{detection_index}_{challenge_id}_{aid}_{action_idx}",
        help="Démo jury : aucune exécution AWS réelle ; le choix documente l'intention opérationnelle.",
    )

