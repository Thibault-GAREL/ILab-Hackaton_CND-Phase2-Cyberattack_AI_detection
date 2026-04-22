import re
import pandas as pd
from config import SQL_INJECTION_MIN_REQUESTS
from .utils import fmt_ts
from .utils import _is_private_ip

CHALLENGE = "sql_injection"

SQL_RE = re.compile(
    r"(?:'|%27|%22|\"|;|%3B|--|%2D%2D|#|%23|/\*|\*/)"
    r"|(?i:\b(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|"
    r"SLEEP|BENCHMARK|WAITFOR|CHAR|ASCII|INFORMATION_SCHEMA|VERSION|DATABASE|USER)\s*[\(\b])",
    re.IGNORECASE,
)

CHROME_RE = re.compile(r"chrome", re.IGNORECASE)


def detect_sql_injection(app_all: pd.DataFrame) -> list[dict]:
    """
    Détecte des attaques SQL injection :
    même IP externe → N requêtes avec payloads SQL dans l'URI.
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
        t0, t1 = grp["timestamp"].min(), grp["timestamp"].max()

        # Exfiltration : total octets reçus
        exfil_bytes = None
        if "response_size" in grp.columns:
            total = int(grp["response_size"].dropna().sum())
            if total > 0:
                exfil_bytes = total

        # Signature outil : Chrome-like avec patterns automatisés
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
