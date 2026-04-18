import pandas as pd
from config import (
    CHALLENGE_ID,
    CREDENTIAL_STUFFING_MIN_401,
    CREDENTIAL_STUFFING_EXTERNAL_ONLY,
    CREDENTIAL_STUFFING_SPLIT_SESSIONS,
)
from .utils import fmt_ts, split_sessions
from .network_recon import _is_private_ip

SCRIPT_USER_AGENTS = {"curl", "python-requests", "wget", "go-http-client", "libwww-perl"}


def _is_script_ua(ua: str) -> bool:
    if not isinstance(ua, str):
        return False
    return any(s in ua.lower() for s in SCRIPT_USER_AGENTS)


def detect_credential_stuffing(app_df: pd.DataFrame) -> list[dict]:
    """
    Detecte du credential stuffing :
    meme IP -> N reponses 401 HTTP.

    Si CREDENTIAL_STUFFING_SPLIT_SESSIONS=False (recommande) : 1 detection par IP.

    Entree : logs application filtres sur status_code=401.
    """
    if app_df.empty:
        return []

    attacks = []

    for ip, ip_df in app_df.groupby("source_ip"):
        if CREDENTIAL_STUFFING_EXTERNAL_ONLY and _is_private_ip(str(ip)):
            continue

        if CREDENTIAL_STUFFING_SPLIT_SESSIONS:
            groups = split_sessions(ip_df)
        else:
            groups = [ip_df.sort_values("timestamp").reset_index(drop=True)]

        for group in groups:
            if len(group) < CREDENTIAL_STUFFING_MIN_401:
                continue

            victims = sorted(group["username"].dropna().unique().tolist())
            user_agents = group["user_agent"].dropna().unique().tolist()
            script_uas = [ua for ua in user_agents if _is_script_ua(ua)]
            targeted_uris = group["uri"].dropna().value_counts().head(5).to_dict()

            attacks.append({
                "challenge_id": CHALLENGE_ID,
                "detection": {
                    "attack_type": "credential_stuffing",
                    "attacker_ips": [str(ip)],
                    "victim_accounts": victims,
                    "attack_start_time": fmt_ts(group["timestamp"].min()),
                    "attack_end_time": fmt_ts(group["timestamp"].max()),
                    "indicators": {
                        "total_401": len(group),
                        "script_user_agents": script_uas,
                        "targeted_uris": targeted_uris,
                    },
                },
                "detection_time_seconds": 0,
            })

    return attacks
