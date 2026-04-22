import re
import pandas as pd
from config import (
    CREDENTIAL_STUFFING_MIN_401,
    CREDENTIAL_STUFFING_EXTERNAL_ONLY,
    CAMPAIGN_OVERLAP_MINUTES,
)
from .utils import fmt_ts, group_ips_by_overlap, _is_private_ip

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
    IPs → N requêtes 401 HTTP → compte compromis.
    failed_logins = uniquement les 401 HTTP (pas de double comptage avec auth).
    La fenêtre est élargie avec les échecs auth web pour capturer le début.
    """
    if app_all.empty:
        return []

    # Signal principal : 401 HTTP depuis les logs application
    app_401 = (
        app_all[app_all["status_code"] == 401]
        if "status_code" in app_all.columns
        else pd.DataFrame(columns=app_all.columns)
    )

    # Signal secondaire : échecs auth non-SSH (pour élargir la fenêtre)
    auth_web = pd.DataFrame()
    if auth_failures is not None and not auth_failures.empty:
        auth_web = (
            auth_failures[auth_failures["auth_method"] != "ssh"]
            if "auth_method" in auth_failures.columns
            else auth_failures.copy()
        )

    app_401_by_ip = (
        {ip: grp for ip, grp in app_401.groupby("source_ip")}
        if not app_401.empty else {}
    )
    auth_web_by_ip = (
        {ip: grp for ip, grp in auth_web.groupby("source_ip")}
        if not auth_web.empty else {}
    )
    net_by_ip: dict = {}
    if net_all is not None and not net_all.empty:
        # Limiter aux IPs qui ont des 401 HTTP
        net_relevant = net_all[net_all["source_ip"].isin(app_401_by_ip.keys())]
        if not net_relevant.empty:
            net_by_ip = {ip: grp for ip, grp in net_relevant.groupby("source_ip")}

    # Fenêtres par IP — seuil basé sur les 401 HTTP uniquement
    # Filtre de densité : exclure le bruit de fond (botnets lents)
    MIN_401_RATE = 1.0  # tentatives/min minimum
    ip_windows: dict = {}
    ip_401_counts: dict = {}
    for ip, grp_401 in app_401_by_ip.items():
        if CREDENTIAL_STUFFING_EXTERNAL_ONLY and _is_private_ip(str(ip)):
            continue
        if len(grp_401) < CREDENTIAL_STUFFING_MIN_401:
            continue
        grp_401 = grp_401.sort_values("timestamp")
        dur = max((grp_401["timestamp"].max() - grp_401["timestamp"].min()).total_seconds() / 60, 1)
        if len(grp_401) / dur < MIN_401_RATE:
            continue

        # Fenêtre : min/max entre 401 HTTP, échecs auth web, et réseau
        ts_parts = [grp_401[["timestamp"]]]
        if ip in auth_web_by_ip:
            ts_parts.append(auth_web_by_ip[ip][["timestamp"]])
        if ip in net_by_ip:
            ts_parts.append(net_by_ip[ip][["timestamp"]])
        all_ts = pd.concat(ts_parts, ignore_index=True).sort_values("timestamp")

        ip_windows[ip] = (all_ts["timestamp"].min(), all_ts["timestamp"].max())
        ip_401_counts[ip] = len(grp_401)

    if not ip_windows:
        return []

    attacks = []
    for campaign_ips in group_ips_by_overlap(ip_windows, CAMPAIGN_OVERLAP_MINUTES):
        t0 = min(ip_windows[ip][0] for ip in campaign_ips)
        t1 = max(ip_windows[ip][1] for ip in campaign_ips)
        total_401 = sum(ip_401_counts[ip] for ip in campaign_ips)
        post = pd.Timedelta(hours=2)

        # Victime : premier login réussi non-SSH depuis ces IPs
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

        # Web shell
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

        # Reverse shell
        reverse_shell_port = None
        if net_all is not None and not net_all.empty and "destination_port" in net_all.columns:
            rs = net_all[
                (net_all["timestamp"] >= t0)
                & (net_all["timestamp"] <= t1 + post)
                & (net_all["destination_port"] == REVERSE_SHELL_PORT)
            ]
            if not rs.empty:
                reverse_shell_port = REVERSE_SHELL_PORT

        # Géolocalisation
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

        indicators: dict = {"failed_logins": total_401}
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
