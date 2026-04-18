import pandas as pd
from config import (
    CHALLENGE_ID,
    ACCOUNT_TAKEOVER_MIN_FAILURES_BEFORE,
    ACCOUNT_TAKEOVER_MAX_DELAY_MINUTES,
    ACCOUNT_TAKEOVER_EXTERNAL_ONLY,
)
from .utils import fmt_ts
from .network_recon import _is_private_ip


def detect_account_takeover(auth_df: pd.DataFrame) -> list[dict]:
    """
    Detecte un Account Takeover :
    meme IP source -> N echecs auth suivis d'un login reussi dans la meme fenetre.

    Entree : tous les logs authentication (status=failure ET success).
    """
    if auth_df.empty:
        return []

    max_delay = pd.Timedelta(minutes=ACCOUNT_TAKEOVER_MAX_DELAY_MINUTES)
    attacks = []

    for ip, ip_df in auth_df.groupby("source_ip"):
        if ACCOUNT_TAKEOVER_EXTERNAL_ONLY and _is_private_ip(str(ip)):
            continue
        ip_df = ip_df.sort_values("timestamp").reset_index(drop=True)

        failures = ip_df[ip_df["status"] == "failure"]
        successes = ip_df[ip_df["status"] == "success"]

        if failures.empty or successes.empty:
            continue

        # Pour chaque succes, chercher si assez d'echecs precedents dans la fenetre
        for _, success_row in successes.iterrows():
            t_success = success_row["timestamp"]
            t_window_start = t_success - max_delay

            prior_failures = failures[
                (failures["timestamp"] >= t_window_start)
                & (failures["timestamp"] < t_success)
            ]

            if len(prior_failures) < ACCOUNT_TAKEOVER_MIN_FAILURES_BEFORE:
                continue

            compromised_account = success_row.get("username")
            victim_accounts = (
                [str(compromised_account)] if pd.notna(compromised_account) else []
            )

            targeted_accounts = sorted(
                prior_failures["username"].dropna().unique().tolist()
            )
            failure_reasons = prior_failures["failure_reason"].value_counts().to_dict()
            auth_method = success_row.get("auth_method", "unknown")

            attacks.append({
                "challenge_id": CHALLENGE_ID,
                "detection": {
                    "attack_type": "account_takeover",
                    "attacker_ips": [str(ip)],
                    "victim_accounts": victim_accounts,
                    "attack_start_time": fmt_ts(prior_failures["timestamp"].min()),
                    "attack_end_time": fmt_ts(t_success),
                    "indicators": {
                        "failures_before_success": len(prior_failures),
                        "compromised_account": compromised_account,
                        "targeted_accounts_during_attack": targeted_accounts,
                        "failure_reasons": failure_reasons,
                        "auth_method": auth_method,
                    },
                },
                "detection_time_seconds": 0,
            })

    return attacks
