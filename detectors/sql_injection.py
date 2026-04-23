import re
import pandas as pd
from config import SQL_INJECTION_MIN_REQUESTS, SQL_INJECTION_MIN_EXFIL_BYTES
from .utils import fmt_ts, _is_private_ip

CHALLENGE = "sql_injection"

SQL_RE = re.compile(
    r"(?:'|%27|%22|\"|;|%3B|--|%2D%2D|#|%23|/\*|\*/)"
    r"|(?:\b(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|"
    r"SLEEP|BENCHMARK|WAITFOR|CHAR|ASCII|INFORMATION_SCHEMA|VERSION|DATABASE|USER"
    r"|CONCAT|EXTRACTVALUE|LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE"
    r"|OR\s+\d+\s*=\s*\d+|AND\s+\d+\s*=\s*\d+)\b)"
    r"|(?:%55NION|%53ELECT|%4FR\b)"
    r"|(?:0x[0-9a-fA-F]{4,})",
    re.IGNORECASE,
)

CHROME_RE = re.compile(r"chrome", re.IGNORECASE)

# Durée max de la phase de reconnaissance avant le premier payload
RECON_WINDOW = pd.Timedelta(hours=1)


def detect_sql_injection(app_all: pd.DataFrame) -> list[dict]:
    """
    Détecte des attaques SQL injection.
    La fenêtre inclut la phase de reconnaissance (requêtes normales
    depuis la même IP juste avant les payloads SQLi).
    """
    if app_all.empty or "uri" not in app_all.columns:
        return []

    sqli_mask = app_all["uri"].apply(
        lambda u: bool(SQL_RE.search(str(u))) if pd.notna(u) else False
    )
    sqli_df = app_all[sqli_mask].copy()
    if sqli_df.empty:
        return []

    attacks = []
    for ip, grp in sqli_df.groupby("source_ip"):
        if _is_private_ip(str(ip)):
            continue
        if len(grp) < SQL_INJECTION_MIN_REQUESTS:
            continue

        grp = grp.sort_values("timestamp").reset_index(drop=True)
        sqli_start = grp["timestamp"].min()
        sqli_end = grp["timestamp"].max()

        # Élargir la fenêtre avec la phase de reconnaissance
        recon_start = sqli_start - RECON_WINDOW
        recon = app_all[
            (app_all["source_ip"] == ip)
            & (app_all["timestamp"] >= recon_start)
            & (app_all["timestamp"] < sqli_start)
        ]
        t0 = recon["timestamp"].min() if not recon.empty else sqli_start
        t1 = sqli_end

        exfil_bytes = None
        if "response_size" in grp.columns:
            total = int(grp["response_size"].dropna().sum())
            if total > 0:
                exfil_bytes = total

        # Filtrer les petits scans automatiques (peu de requêtes ET peu d'exfil)
        if (exfil_bytes or 0) < SQL_INJECTION_MIN_EXFIL_BYTES and len(grp) < 200:
            continue

        tool_signature = None
        if "user_agent" in grp.columns:
            if grp["user_agent"].dropna().apply(lambda u: bool(CHROME_RE.search(str(u)))).any():
                tool_signature = "Chrome-like UA with automated patterns"

        indicators: dict = {"sqli_requests": len(grp)}
        if exfil_bytes:
            indicators["exfil_bytes"] = exfil_bytes
        if tool_signature:
            indicators["tool_signature"] = tool_signature

        attacks.append({
            "challenge_id": CHALLENGE,
            "detection": {
                "attack_type": "sql_injection",
                "attacker_ips": [str(ip)],
                "victim_accounts": [],
                "attack_start_time": fmt_ts(t0),
                "attack_end_time": fmt_ts(t1),
                "indicators": indicators,
            },
            "detection_time_seconds": 0,
        })

    return attacks
