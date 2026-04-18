import pandas as pd
from config import (
    CHALLENGE_ID,
    PORT_SCAN_MIN_PORTS,
    PORT_SCAN_MIN_REJECT_RATIO,
    PORT_SCAN_EXTERNAL_ONLY,
)
from .utils import fmt_ts, split_sessions
from .network_recon import _is_private_ip


def detect_port_scan(net_df: pd.DataFrame) -> list[dict]:
    """
    Détecte du port scanning :
    IP (externe si PORT_SCAN_EXTERNAL_ONLY) → N ports distincts
    avec un taux de rejet >= PORT_SCAN_MIN_REJECT_RATIO.

    Entrée : logs network (tous actions confondus).
    """
    if net_df.empty:
        return []

    attacks = []

    for ip, ip_df in net_df.groupby("source_ip"):
        if PORT_SCAN_EXTERNAL_ONLY and _is_private_ip(str(ip)):
            continue

        sessions = split_sessions(ip_df)

        for session in sessions:
            total = len(session)
            reject_count = int((session["action"] == "reject").sum())
            distinct_ports = session["destination_port"].dropna().nunique()

            if distinct_ports < PORT_SCAN_MIN_PORTS:
                continue
            if total == 0 or reject_count / total < PORT_SCAN_MIN_REJECT_RATIO:
                continue

            targeted_ips = sorted(session["destination_ip"].dropna().unique().tolist())
            protocols = session["protocol"].dropna().unique().tolist()
            scanned_ports = sorted(
                session["destination_port"].dropna().astype(int).unique().tolist()
            )

            attacks.append({
                "challenge_id": CHALLENGE_ID,
                "detection": {
                    "attack_type": "port_scan",
                    "attacker_ips": [str(ip)],
                    "victim_accounts": [],
                    "attack_start_time": fmt_ts(session["timestamp"].min()),
                    "attack_end_time": fmt_ts(session["timestamp"].max()),
                    "indicators": {
                        "distinct_ports_scanned": distinct_ports,
                        "total_connections": total,
                        "rejected_connections": reject_count,
                        "reject_ratio": round(reject_count / total, 3),
                        "targeted_ips": targeted_ips,
                        "protocols": protocols,
                        "scanned_ports_sample": scanned_ports[:20],
                    },
                },
                "detection_time_seconds": 0,
            })

    return attacks
