import pandas as pd
from .utils import fmt_ts, _is_private_ip

CHALLENGE = "port_scan"

# Seuils calibrés sur les données DS2 (10.0.6.50/51 : 9 ports, 12 dests, 49% reject, ~1800 conn)
MIN_UNIQUE_PORTS = 6
MIN_CONNECTIONS = 50
MIN_REJECT_RATE = 0.25
MIN_UNIQUE_DESTINATIONS = 3


def detect_port_scan(net_all: pd.DataFrame) -> list[dict]:
    """Détecte du port scanning : IP qui touche beaucoup de ports/destinations avec un haut taux de reject."""
    if net_all.empty:
        return []

    stats = net_all.groupby('source_ip').agg(
        total=('timestamp', 'count'),
        unique_ports=('destination_port', 'nunique'),
        unique_dests=('destination_ip', 'nunique'),
        rejects=('action', lambda x: (x == 'reject').sum()),
        start=('timestamp', 'min'),
        end=('timestamp', 'max'),
    )
    stats['reject_rate'] = stats['rejects'] / stats['total']

    scanners = stats[
        (stats['unique_ports'] >= MIN_UNIQUE_PORTS) &
        (stats['total'] >= MIN_CONNECTIONS) &
        (stats['reject_rate'] >= MIN_REJECT_RATE) &
        (stats['unique_dests'] >= MIN_UNIQUE_DESTINATIONS)
    ]

    if scanners.empty:
        return []

    attacks = []
    for ip, row in scanners.iterrows():
        ip_data = net_all[net_all['source_ip'] == ip]
        ports_scanned = sorted(ip_data['destination_port'].dropna().astype(int).unique().tolist())
        targets = sorted(ip_data['destination_ip'].dropna().unique().tolist())

        attacks.append({
            "challenge_id": CHALLENGE,
            "detection": {
                "attack_type": "port_scan",
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
