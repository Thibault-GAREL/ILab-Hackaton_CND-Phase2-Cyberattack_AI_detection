import pandas as pd
from .utils import fmt_ts

CHALLENGE = "resource_exhaustion"

# Seuils calibrés sur DS2 : 143 OOM kills + 637 restarts sur 12 hosts en 13 min
MIN_OOM_KILLS = 10
MIN_AFFECTED_HOSTS = 3


def detect_resource_exhaustion(
    sys_all: pd.DataFrame,
    net_all: pd.DataFrame | None = None,
) -> list[dict]:
    """Détecte de l'épuisement de ressources : OOM kills massifs + service restarts sur plusieurs hosts."""
    if sys_all.empty or 'message' not in sys_all.columns:
        return []

    oom = sys_all[sys_all['message'].str.contains(
        r'Out of memory|killed process|OOM', case=False, na=False, regex=True
    )]
    restarts = sys_all[sys_all['message'].str.contains(
        r'restarted.*exit code', case=False, na=False, regex=True
    )]

    if len(oom) < MIN_OOM_KILLS:
        return []

    affected_hosts = sorted(oom['hostname'].dropna().unique().tolist()) if 'hostname' in oom.columns else []
    if len(affected_hosts) < MIN_AFFECTED_HOSTS:
        return []

    t0 = oom['timestamp'].min()
    t1 = oom['timestamp'].max()
    if not restarts.empty:
        t1 = max(t1, restarts['timestamp'].max())

    # Processus tués
    killed_processes = []
    import re
    for msg in oom['message'].dropna().unique():
        m = re.search(r'killed process (\S+)', str(msg))
        if m:
            killed_processes.append(m.group(1))
    killed_processes = sorted(set(killed_processes))

    # Corrélation réseau : trafic anormalement élevé pendant la période
    network_indicator = {}
    if net_all is not None and not net_all.empty:
        window_net = net_all[(net_all['timestamp'] >= t0) & (net_all['timestamp'] <= t1)]
        if not window_net.empty:
            total_bytes = int(window_net['bytes_sent'].sum() + window_net['bytes_received'].sum())
            network_indicator = {"total_network_bytes_during_attack": total_bytes}

    indicators = {
        "oom_kills": len(oom),
        "service_restarts": len(restarts),
        "affected_hosts": affected_hosts,
        "killed_processes": killed_processes,
    }
    indicators.update(network_indicator)

    return [{
        "challenge_id": CHALLENGE,
        "detection": {
            "attack_type": "resource_exhaustion",
            "attacker_ips": [],
            "victim_accounts": [],
            "attack_start_time": fmt_ts(t0),
            "attack_end_time": fmt_ts(t1),
            "indicators": indicators,
        },
        "detection_time_seconds": 0,
    }]
