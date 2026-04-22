import pandas as pd
from config import SESSION_GAP_MINUTES


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


def fmt_ts(ts) -> str:
    """Convertit un timestamp pandas en ISO 8601 UTC."""
    return pd.Timestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")


def split_sessions(df: pd.DataFrame, time_col: str = "timestamp") -> list[pd.DataFrame]:
    """
    Découpe un DataFrame trié par timestamp en sessions distinctes.
    Deux événements séparés par plus de SESSION_GAP_MINUTES → sessions différentes.
    """
    if df.empty:
        return []

    df = df.sort_values(time_col).reset_index(drop=True)
    gap = pd.Timedelta(minutes=SESSION_GAP_MINUTES)

    breaks = df[time_col].diff() > gap
    session_id = breaks.cumsum()

    sessions = []
    for _, group in df.groupby(session_id):
        sessions.append(group.reset_index(drop=True))
    return sessions


def group_ips_by_overlap(ip_windows: dict, tolerance_minutes: int) -> list[list]:
    """
    Groupe les IPs dont les fenêtres d'attaque se chevauchent en campagnes.
    ip_windows = {ip: (pd.Timestamp start, pd.Timestamp end)}
    Retourne une liste de listes d'IPs (une liste = une campagne).
    """
    tol = pd.Timedelta(minutes=tolerance_minutes)
    ips = list(ip_windows.keys())
    visited: set = set()
    campaigns = []
    for ip in ips:
        if ip in visited:
            continue
        group = [ip]
        visited.add(ip)
        s1, e1 = ip_windows[ip]
        for other_ip in ips:
            if other_ip in visited:
                continue
            s2, e2 = ip_windows[other_ip]
            if s1 <= e2 + tol and s2 <= e1 + tol:
                group.append(other_ip)
                visited.add(other_ip)
        campaigns.append(group)
    return campaigns
