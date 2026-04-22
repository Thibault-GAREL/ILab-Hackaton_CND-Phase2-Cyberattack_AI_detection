import pandas as pd
from config import (
    SSH_BRUTE_FORCE_MIN_FAILURES,
    SSH_BRUTE_FORCE_EXTERNAL_ONLY,
    CAMPAIGN_OVERLAP_MINUTES,
)
from .utils import fmt_ts, split_sessions, group_ips_by_overlap, _is_private_ip

CHALLENGE = "ssh_brute_force"
EXFIL_PORTS = {443, 8443}
# Minimum de tentatives par minute pour considérer une session comme une attaque
# (filtre le bruit de fond des botnets lents : ~0.1/min)
MIN_RATE_PER_MINUTE = 1.0


def detect_ssh_brute_force(
    auth_failures: pd.DataFrame,
    sys_df: pd.DataFrame | None = None,
    net_df: pd.DataFrame | None = None,
    auth_all: pd.DataFrame | None = None,
) -> list[dict]:
    """
    Détecte du brute force SSH.
    Chaque IP est découpée en sessions. Seules les sessions avec un taux
    de tentatives suffisant sont retenues (filtre le bruit de fond).
    Les sessions qui se chevauchent sont regroupées en campagnes.
    """
    if auth_failures.empty or "auth_method" not in auth_failures.columns:
        return []

    ssh_fail = auth_failures[auth_failures["auth_method"] == "ssh"].copy()
    if ssh_fail.empty:
        return []

    session_windows: dict = {}
    session_data: dict = {}
    for ip, grp in ssh_fail.groupby("source_ip"):
        if SSH_BRUTE_FORCE_EXTERNAL_ONLY and _is_private_ip(str(ip)):
            continue
        for idx, session in enumerate(split_sessions(grp)):
            if len(session) < SSH_BRUTE_FORCE_MIN_FAILURES:
                continue
            t0, t1 = session["timestamp"].min(), session["timestamp"].max()
            duration_min = max((t1 - t0).total_seconds() / 60, 1)
            rate = len(session) / duration_min
            if rate < MIN_RATE_PER_MINUTE:
                continue
            key = (str(ip), idx)
            session_windows[key] = (t0, t1)
            session_data[key] = session

    if not session_windows:
        return []

    campaigns = group_ips_by_overlap(session_windows, CAMPAIGN_OVERLAP_MINUTES)

    attacks = []
    for campaign_keys in campaigns:
        merged = pd.concat(
            [session_data[k] for k in campaign_keys], ignore_index=True
        ).sort_values("timestamp")
        t0, t1 = merged["timestamp"].min(), merged["timestamp"].max()
        post = pd.Timedelta(hours=3)
        campaign_ips = sorted(set(k[0] for k in campaign_keys))

        # Victime : comptes les plus ciblés par les échecs SSH
        victim_accounts = sorted(merged["username"].dropna().unique().tolist())

        # Cibles latérales
        lateral_targets = []
        if sys_df is not None and not sys_df.empty and "hostname" in sys_df.columns:
            q = sys_df[(sys_df["timestamp"] >= t0) & (sys_df["timestamp"] <= t1 + post)]
            lateral_targets = sorted(q["hostname"].dropna().unique().tolist())

        # Escalade de privilèges
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

        # Exfiltration
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
                "attacker_ips": campaign_ips,
                "victim_accounts": victim_accounts,
                "attack_start_time": fmt_ts(t0),
                "attack_end_time": fmt_ts(t1),
                "indicators": indicators,
            },
            "detection_time_seconds": 0,
        })

    return attacks
