import pandas as pd
from config import (
    SSH_BRUTE_FORCE_MIN_FAILURES,
    SSH_BRUTE_FORCE_EXTERNAL_ONLY,
    CAMPAIGN_OVERLAP_MINUTES,
)
from .utils import fmt_ts, group_ips_by_overlap
from .utils import _is_private_ip

CHALLENGE = "ssh_brute_force"
EXFIL_PORTS = {443, 8443}


def detect_ssh_brute_force(
    auth_failures: pd.DataFrame,
    sys_df: pd.DataFrame | None = None,
    net_df: pd.DataFrame | None = None,
    auth_all: pd.DataFrame | None = None,
) -> list[dict]:
    """
    Détecte du brute force SSH :
    mêmes IPs externes → N échecs auth SSH → accès réussi (sysadmin).
    Enrichi avec mouvement latéral, escalade de privilèges, exfiltration réseau.
    """
    if auth_failures.empty or "auth_method" not in auth_failures.columns:
        return []

    ssh_fail = auth_failures[auth_failures["auth_method"] == "ssh"].copy()
    if ssh_fail.empty:
        return []

    # Fenêtres par IP
    ip_windows: dict = {}
    ip_data: dict = {}
    for ip, grp in ssh_fail.groupby("source_ip"):
        if SSH_BRUTE_FORCE_EXTERNAL_ONLY and _is_private_ip(str(ip)):
            continue
        if len(grp) < SSH_BRUTE_FORCE_MIN_FAILURES:
            continue
        grp = grp.sort_values("timestamp").reset_index(drop=True)
        ip_windows[ip] = (grp["timestamp"].min(), grp["timestamp"].max())
        ip_data[ip] = grp

    if not ip_windows:
        return []

    attacks = []
    for campaign_ips in group_ips_by_overlap(ip_windows, CAMPAIGN_OVERLAP_MINUTES):
        merged = pd.concat(
            [ip_data[ip] for ip in campaign_ips], ignore_index=True
        ).sort_values("timestamp")
        t0, t1 = merged["timestamp"].min(), merged["timestamp"].max()
        post = pd.Timedelta(hours=3)

        # Victime : premier login SSH réussi depuis ces IPs
        victim_accounts = []
        if auth_all is not None and not auth_all.empty and "status" in auth_all.columns:
            q = auth_all[
                (auth_all["status"] == "success")
                & (auth_all["source_ip"].isin(campaign_ips))
            ]
            if "auth_method" in q.columns:
                q = q[q["auth_method"] == "ssh"]
            victim_accounts = sorted(q["username"].dropna().unique().tolist())

        # Cibles latérales : hostnames dans les logs system post-compromis
        lateral_targets = []
        if sys_df is not None and not sys_df.empty and "hostname" in sys_df.columns:
            q = sys_df[(sys_df["timestamp"] >= t0) & (sys_df["timestamp"] <= t1 + post)]
            lateral_targets = sorted(q["hostname"].dropna().unique().tolist())

        # Escalade de privilèges : sudo + création d'utilisateur backdoor
        priv_esc = None
        if sys_df is not None and not sys_df.empty:
            q = sys_df[(sys_df["timestamp"] >= t0) & (sys_df["timestamp"] <= t1 + post)]
            has_sudo = (
                "process" in q.columns
                and q["process"].str.lower().str.contains("sudo", na=False).any()
            )
            has_backdoor = (
                "message" in q.columns
                and q["message"].str.lower().str.contains(
                    r"useradd|adduser|new user|backdoor", na=False, regex=True
                ).any()
            )
            if has_sudo or has_backdoor:
                priv_esc = "sudo + backdoor user"

        # Exfiltration : connexions sur ports 443/8443
        exfil_port = None
        if net_df is not None and not net_df.empty and "destination_port" in net_df.columns:
            q = net_df[(net_df["timestamp"] >= t0) & (net_df["timestamp"] <= t1 + post)]
            found = sorted(
                q[q["destination_port"].isin(EXFIL_PORTS)]["destination_port"]
                .dropna().astype(int).unique().tolist()
            )
            if found:
                exfil_port = "/".join(str(p) for p in found)

        indicators: dict = {"total_ssh_failures": len(merged)}
        if lateral_targets:
            indicators["lateral_targets"] = lateral_targets
        if priv_esc:
            indicators["priv_esc"] = priv_esc
        if exfil_port:
            indicators["exfil_port"] = exfil_port

        attacks.append({
            "challenge_id": CHALLENGE,
            "detection": {
                "attack_type": "ssh_brute_force",
                "attacker_ips": sorted(str(ip) for ip in campaign_ips),
                "victim_accounts": victim_accounts,
                "attack_start_time": fmt_ts(t0),
                "attack_end_time": fmt_ts(t1),
                "indicators": indicators,
            },
            "detection_time_seconds": 0,
        })

    return attacks
