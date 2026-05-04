import re
import pandas as pd
from pipeline.config import DIRECTORY_TRAVERSAL_MIN_ATTEMPTS
from .utils import fmt_ts
from .utils import _is_private_ip

CHALLENGE = "directory_traversal"

TRAVERSAL_RE = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e[%2f/\\]|\.\.%2f|\.\.%5c|%252e%252e)",
    re.IGNORECASE,
)

SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/root/.ssh/id_rsa",
    "/root/.ssh/authorized_keys",
    "/etc/hosts",
    "/etc/ssh/sshd_config",
    "/proc/self/environ",
    "/var/log/auth.log",
]


def _find_sensitive(uris: pd.Series) -> list[str]:
    found = set()
    for uri in uris.dropna():
        u = str(uri)
        for path in SENSITIVE_FILES:
            if path in u:
                found.add(path)
    return sorted(found)


def detect_directory_traversal(app_all: pd.DataFrame) -> list[dict]:
    """
    Détecte des attaques path traversal :
    même IP externe → N requêtes avec ../../../ dans l'URI.
    """
    if app_all.empty or "uri" not in app_all.columns:
        return []

    trav_mask = app_all["uri"].apply(
        lambda u: bool(TRAVERSAL_RE.search(str(u))) if pd.notna(u) else False
    )
    trav_df = app_all[trav_mask].copy()
    if trav_df.empty:
        return []

    attacks = []
    for ip, grp in trav_df.groupby("source_ip"):
        if _is_private_ip(str(ip)):
            continue
        if len(grp) < DIRECTORY_TRAVERSAL_MIN_ATTEMPTS:
            continue

        grp = grp.sort_values("timestamp").reset_index(drop=True)
        t0, t1 = grp["timestamp"].min(), grp["timestamp"].max()

        # Lectures réussies (HTTP 200)
        successful_reads = 0
        if "status_code" in grp.columns:
            successful_reads = int((grp["status_code"] == 200).sum())

        # Fichiers sensibles accédés
        sensitive = _find_sensitive(grp["uri"])

        # Premier pattern de traversal complet trouvé
        traversal_pattern = None
        for uri in grp["uri"].dropna():
            u = str(uri)
            # Chercher le pattern complet ../../../etc/passwd etc.
            m = re.search(r"(?:\.\./|\.\.\\|%2e%2e[%2f/\\])+[^\s?#&]*", u, re.IGNORECASE)
            if m:
                traversal_pattern = m.group(0)
                break

        indicators: dict = {
            "traversal_attempts": len(grp),
            "successful_reads": successful_reads,
        }
        if traversal_pattern:
            indicators["traversal_patterns"] = traversal_pattern
        if sensitive:
            indicators["sensitive_files"] = sensitive

        attacks.append({
            "challenge_id": CHALLENGE,
            "detection": {
                "attack_type": "directory_traversal",
                "attacker_ips": [str(ip)],
                "victim_accounts": [],
                "attack_start_time": fmt_ts(t0),
                "attack_end_time": fmt_ts(t1),
                "indicators": indicators,
            },
            "detection_time_seconds": 0,
        })

    return attacks
