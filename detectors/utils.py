import pandas as pd
from config import SESSION_GAP_MINUTES


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
