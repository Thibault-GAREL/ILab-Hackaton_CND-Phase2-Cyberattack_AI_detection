import re
import pandas as pd
from .utils import fmt_ts, _is_private_ip

CHALLENGE = "reconnaissance"

# Seuils calibrés sur DS2 : 103.235.46.10 = 35 conn, 71% reject, 9 ports, scan multi-services
MIN_CONNECTIONS = 10
MIN_REJECT_RATE = 0.4
MIN_UNIQUE_PORTS = 3


def detect_reconnaissance(net_all: pd.DataFrame) -> list[dict]:
    """Détecte de la reconnaissance externe : IP externe qui scanne des ports avec un haut taux de reject."""
    if net_all.empty:
        return []

    # Filtrer uniquement les IPs externes
    external_mask = net_all['source_ip'].apply(lambda ip: not _is_private_ip(str(ip)) if pd.notna(ip) else False)
    ext_net = net_all[external_mask]
    if ext_net.empty:
        return []

    stats = ext_net.groupby('source_ip').agg(
        total=('timestamp', 'count'),
        unique_ports=('destination_port', 'nunique'),
        unique_dests=('destination_ip', 'nunique'),
        rejects=('action', lambda x: (x == 'reject').sum()),
        start=('timestamp', 'min'),
        end=('timestamp', 'max'),
    )
    stats['reject_rate'] = stats['rejects'] / stats['total']

    recon_ips = stats[
        (stats['total'] >= MIN_CONNECTIONS) &
        (stats['reject_rate'] >= MIN_REJECT_RATE) &
        (stats['unique_ports'] >= MIN_UNIQUE_PORTS)
    ]

    if recon_ips.empty:
        return []

    attacks = []
    for ip, row in recon_ips.iterrows():
        ip_data = ext_net[ext_net['source_ip'] == ip]
        ports_scanned = sorted(ip_data['destination_port'].dropna().astype(int).unique().tolist())
        targets = sorted(ip_data['destination_ip'].dropna().unique().tolist())

        attacks.append({
            "challenge_id": CHALLENGE,
            "detection": {
                "attack_type": "reconnaissance",
                "attacker_ips": [str(ip)],
                "victim_accounts": [],
                "attack_start_time": fmt_ts(row['start']),
                "attack_end_time": fmt_ts(row['end']),
                "indicators": {
                    "ports_scanned": ports_scanned,
                    "targets": targets,
                    "total_connections": int(row['total']),
                    "reject_rate": round(float(row['reject_rate']), 2),
                },
            },
            "detection_time_seconds": 0,
        })

    return attacks
