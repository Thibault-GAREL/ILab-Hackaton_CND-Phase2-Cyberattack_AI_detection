import pandas as pd
from config import CHALLENGE_ID, NETWORK_RECON_MIN_REJECTS
from .utils import fmt_ts, split_sessions


def detect_network_recon(net_df: pd.DataFrame) -> list[dict]:
    """
    Détecte de la reconnaissance réseau :
    même IP externe → N connexions rejetées (typique d'un scan de surface).

    Entrée : logs network filtrés sur action=reject.
    """
    if net_df.empty:
        return []

    attacks = []

    for ip, ip_df in net_df.groupby("source_ip"):
        # Ignorer les IPs internes RFC-1918
        if _is_private_ip(str(ip)):
            continue

        sessions = split_sessions(ip_df)

        for session in sessions:
            if len(session) < NETWORK_RECON_MIN_REJECTS:
                continue

            targeted_ports = sorted(
                session["destination_port"].dropna().astype(int).unique().tolist()
            )
            targeted_ips = sorted(session["destination_ip"].dropna().unique().tolist())
            protocols = session["protocol"].dropna().unique().tolist()

            attacks.append({
                "challenge_id": CHALLENGE_ID,
                "detection": {
                    "attack_type": "network_recon",
                    "attacker_ips": [str(ip)],
                    "victim_accounts": [],
                    "attack_start_time": fmt_ts(session["timestamp"].min()),
                    "attack_end_time": fmt_ts(session["timestamp"].max()),
                    "indicators": {
                        "total_rejected": len(session),
                        "targeted_ports": targeted_ports,
                        "targeted_ips": targeted_ips,
                        "protocols": protocols,
                    },
                },
                "detection_time_seconds": 0,
            })

    return attacks


def _is_private_ip(ip: str) -> bool:
    """Retourne True si l'IP appartient aux plages RFC-1918 ou loopback."""
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.2")
        or ip.startswith("172.3")
        or ip == "127.0.0.1"
    )
