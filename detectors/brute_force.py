import pandas as pd
from config import (
    CHALLENGE_ID,
    BRUTE_FORCE_MIN_FAILURES,
    BRUTE_FORCE_EXTERNAL_ONLY,
    BRUTE_FORCE_SPLIT_SESSIONS,
)
from .utils import fmt_ts, split_sessions
from .network_recon import _is_private_ip


def detect_brute_force(auth_df: pd.DataFrame) -> list[dict]:
    """
    Detecte des campagnes de brute force :
    meme IP source -> N echecs auth.

    Si BRUTE_FORCE_SPLIT_SESSIONS=False (recommande) : 1 detection par IP,
    couvre toute la duree de la campagne — evite le sur-decoupage.

    Entree : logs authentication filtres sur status=failure.
    """
    if auth_df.empty:
        return []

    attacks = []

    for ip, ip_df in auth_df.groupby("source_ip"):
        if BRUTE_FORCE_EXTERNAL_ONLY and _is_private_ip(str(ip)):
            continue

        if BRUTE_FORCE_SPLIT_SESSIONS:
            groups = split_sessions(ip_df)
        else:
            groups = [ip_df.sort_values("timestamp").reset_index(drop=True)]

        for group in groups:
            if len(group) < BRUTE_FORCE_MIN_FAILURES:
                continue

            victims = sorted(group["username"].dropna().unique().tolist())
            targeted_ports = sorted(
                group["destination_port"].dropna().astype(int).unique().tolist()
            )
            failure_counts = group["failure_reason"].value_counts().to_dict()
            auth_methods = group["auth_method"].dropna().unique().tolist()

            attacks.append({
                "challenge_id": CHALLENGE_ID,
                "detection": {
                    "attack_type": "brute_force",
                    "attacker_ips": [str(ip)],
                    "victim_accounts": victims,
                    "attack_start_time": fmt_ts(group["timestamp"].min()),
                    "attack_end_time": fmt_ts(group["timestamp"].max()),
                    "indicators": {
                        "total_failures": len(group),
                        "failure_reasons": failure_counts,
                        "targeted_ports": targeted_ports,
                        "auth_methods": auth_methods,
                    },
                },
                "detection_time_seconds": 0,
            })

    return attacks
