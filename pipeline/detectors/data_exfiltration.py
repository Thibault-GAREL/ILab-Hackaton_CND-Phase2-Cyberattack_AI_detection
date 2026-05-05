import pandas as pd
from .utils import fmt_ts, _is_private_ip

CHALLENGE = "data_exfiltration"

# Seuils calibrés sur DS2 : 10.0.7.10 reçoit 70 GB depuis 12 sources via ports 22/443/873
MIN_TOTAL_BYTES = 1_000_000_000  # 1 GB minimum vers une même destination
MIN_TRANSFER_SIZE = 5_000_000    # 5 MB par connexion pour être considéré comme gros transfert
MIN_SOURCES = 2                  # Au moins 2 sources différentes
EXFIL_PORTS = {22, 443, 873, 8443, 21}  # SCP/SFTP, HTTPS, rsync, FTPS, FTP


def detect_data_exfiltration(net_all: pd.DataFrame) -> list[dict]:
    """Détecte de l'exfiltration de données : gros volumes vers une même destination depuis plusieurs sources."""
    if net_all.empty or 'bytes_sent' not in net_all.columns:
        return []

    # Filtrer les gros transferts sur des ports d'exfiltration
    big = net_all[
        (net_all['bytes_sent'] > MIN_TRANSFER_SIZE) &
        (net_all['destination_port'].isin(EXFIL_PORTS))
    ]
    if big.empty:
        return []

    # Agréger par destination
    by_dest = big.groupby('destination_ip').agg(
        total_bytes=('bytes_sent', 'sum'),
        count=('timestamp', 'count'),
        sources=('source_ip', 'nunique'),
        source_list=('source_ip', lambda x: sorted(x.unique().tolist())),
        ports=('destination_port', lambda x: sorted(x.dropna().astype(int).unique().tolist())),
        start=('timestamp', 'min'),
        end=('timestamp', 'max'),
    )

    exfil_targets = by_dest[
        (by_dest['total_bytes'] >= MIN_TOTAL_BYTES) &
        (by_dest['sources'] >= MIN_SOURCES)
    ]

    if exfil_targets.empty:
        return []

    attacks = []
    for dest_ip, row in exfil_targets.iterrows():
        attacks.append({
            "challenge_id": CHALLENGE,
            "detection": {
                "attack_type": "data_exfiltration",
                "attacker_ips": row['source_list'],
                "victim_accounts": [],
                "attack_start_time": fmt_ts(row['start']),
                "attack_end_time": fmt_ts(row['end']),
                "indicators": {
                    "destination": str(dest_ip),
                    "total_bytes": int(row['total_bytes']),
                    "exfil_ports": row['ports'],
                    "source_count": int(row['sources']),
                    "transfer_count": int(row['count']),
                },
            },
            "detection_time_seconds": 0,
        })

    return attacks
