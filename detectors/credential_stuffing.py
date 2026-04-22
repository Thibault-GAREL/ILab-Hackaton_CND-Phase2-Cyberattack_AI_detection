import re
import pandas as pd
from config import (
    CREDENTIAL_STUFFING_MIN_401,
    CREDENTIAL_STUFFING_EXTERNAL_ONLY,
    CAMPAIGN_OVERLAP_MINUTES,
)
from .utils import fmt_ts, group_ips_by_overlap
from .utils import _is_private_ip

CHALLENGE = "credential_stuffing"
WEB_SHELL_RE = re.compile(r"/uploads/[^?#\s]*\.php", re.IGNORECASE)
REVERSE_SHELL_PORT = 4444


def detect_credential_stuffing(
    app_all: pd.DataFrame,
    auth_failures: pd.DataFrame | None = None,
    net_all: pd.DataFrame | None = None,
    auth_all: pd.DataFrame | None = None,
) -> list[dict]:
    """
    Détecte du credential stuffing :
    mêmes IPs → N requêtes 401 HTTP + N échecs auth web → compte compromis.
    Enrichi avec : web shell uploadé (/uploads/*.php), reverse shell (port 4444),
    compte victime, géolocalisation.
    """
    if app_all.empty:
        return []

    # Signal 1 : 401 HTTP depuis les logs application
    app_401 = (
        app_all[app_all["status_code"] == 401]
        if "status_code" in app_all.columns
        else pd.DataFrame(columns=app_all.columns)
    )

    # Signal 2 : échecs auth non-SSH (web, form, api…)
    auth_web = pd.DataFrame()
    if auth_failures is not None and not auth_failures.empty:
        auth_web = (
            auth_failures[auth_failures["auth_method"] != "ssh"]
            if "auth_method" in auth_failures.columns
            else auth_failures.copy()
        )

    # Pré-groupement par IP pour éviter O(n²)
    app_401_by_ip = (
        {ip: grp for ip, grp in app_401.groupby("source_ip")}
        if not app_401.empty else {}
    )
    auth_web_by_ip = (
        {ip: grp for ip, grp in auth_web.groupby("source_ip")}
        if not auth_web.empty else {}
    )
    all_ips = set(app_401_by_ip) | set(auth_web_by_ip)

    # Fenêtres et comptes par IP
    ip_windows: dict = {}
    ip_counts: dict = {}
    for ip in all_ips:
        if CREDENTIAL_STUFFING_EXTERNAL_ONLY and _is_private_ip(str(ip)):
            continue
        parts = []
        if ip in app_401_by_ip:
            parts.append(app_401_by_ip[ip][["timestamp"]])
        if ip in auth_web_by_ip:
            parts.append(auth_web_by_ip[ip][["timestamp"]])
        if not parts:
            continue
        combined = pd.concat(parts, ignore_index=True).sort_values("timestamp")
        if len(combined) < CREDENTIAL_STUFFING_MIN_401:
            continue
        ip_windows[ip] = (combined["timestamp"].min(), combined["timestamp"].max())
        ip_counts[ip] = len(combined)

    if not ip_windows:
        return []

    attacks = []
    for campaign_ips in group_ips_by_overlap(ip_windows, CAMPAIGN_OVERLAP_MINUTES):
        t0 = min(ip_windows[ip][0] for ip in campaign_ips)
        t1 = max(ip_windows[ip][1] for ip in campaign_ips)
        total_failures = sum(ip_counts[ip] for ip in campaign_ips)
        post = pd.Timedelta(hours=2)

        # Victime : premier login réussi non-SSH depuis ces IPs dans la fenêtre
        victim_accounts = []
        if auth_all is not None and not auth_all.empty and "status" in auth_all.columns:
            q = auth_all[
                (auth_all["status"] == "success")
                & (auth_all["source_ip"].isin(campaign_ips))
                & (auth_all["timestamp"] >= t0)
                & (auth_all["timestamp"] <= t1 + post)
            ]
            if "auth_method" in q.columns:
                q = q[q["auth_method"] != "ssh"]
            victim_accounts = sorted(q["username"].dropna().unique().tolist())

        # Web shell : URI /uploads/*.php pendant la fenêtre (+2h)
        web_shell = None
        if "uri" in app_all.columns:
            ws = app_all[
                (app_all["timestamp"] >= t0)
                & (app_all["timestamp"] <= t1 + post)
                & app_all["uri"].str.contains(
                    WEB_SHELL_RE.pattern, na=False, case=False, regex=True
                )
            ]
            if not ws.empty:
                web_shell = str(ws["uri"].iloc[0])

        # Reverse shell : trafic réseau vers le port 4444
        reverse_shell_port = None
        if net_all is not None and not net_all.empty and "destination_port" in net_all.columns:
            rs = net_all[
                (net_all["timestamp"] >= t0)
                & (net_all["timestamp"] <= t1 + post)
                & (net_all["destination_port"] == REVERSE_SHELL_PORT)
            ]
            if not rs.empty:
                reverse_shell_port = REVERSE_SHELL_PORT

        # Géolocalisation : pays dominant dans les logs auth pour ces IPs
        geolocation = None
        if (
            auth_failures is not None
            and not auth_failures.empty
            and "geolocation_country" in auth_failures.columns
        ):
            geo_q = auth_failures[auth_failures["source_ip"].isin(campaign_ips)]
            counts = geo_q["geolocation_country"].dropna().value_counts()
            if not counts.empty:
                geolocation = str(counts.index[0])

        indicators: dict = {"failed_logins": total_failures}
        if web_shell:
            indicators["web_shell"] = web_shell
        if reverse_shell_port:
            indicators["reverse_shell_port"] = reverse_shell_port
        if geolocation:
            indicators["geolocation"] = geolocation

        attacks.append({
            "challenge_id": CHALLENGE,
            "detection": {
                "attack_type": "credential_stuffing",
                "attacker_ips": sorted(str(ip) for ip in campaign_ips),
                "victim_accounts": victim_accounts,
                "attack_start_time": fmt_ts(t0),
                "attack_end_time": fmt_ts(t1),
                "indicators": indicators,
            },
            "detection_time_seconds": 0,
        })

    return attacks
