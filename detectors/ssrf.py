import re
import pandas as pd
from config import SSRF_MIN_REQUESTS
from .utils import fmt_ts
from .utils import _is_private_ip

CHALLENGE = "ssrf"
METADATA_IP = "169.254.169.254"

SSRF_URI_RE = re.compile(
    r"(?:"
    r"169\.254\.169\.254|"
    r"127\.0\.0\.1|"
    r"localhost|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r")(?::\d+)?",
    re.IGNORECASE,
)

SSRF_INTERNAL_PORTS = {3306, 389, 6379, 5432, 27017, 22, 80, 8080, 443}


def _extract_target(uri: str) -> str | None:
    m = SSRF_URI_RE.search(str(uri))
    return m.group(0) if m else None


def detect_ssrf(
    app_all: pd.DataFrame,
    net_df: pd.DataFrame | None = None,
) -> list[dict]:
    """
    Détecte du SSRF :
    IP externe → requêtes HTTP dont l'URI contient une IP interne ou le metadata endpoint AWS.
    Enrichi avec les connexions réseau internes déclenchées par le serveur web.
    """
    if app_all.empty or "uri" not in app_all.columns:
        return []

    ssrf_mask = app_all["uri"].apply(
        lambda u: bool(SSRF_URI_RE.search(str(u))) if pd.notna(u) else False
    )
    ssrf_df = app_all[ssrf_mask].copy()
    if ssrf_df.empty:
        return []

    attacks = []
    for ip, grp in ssrf_df.groupby("source_ip"):
        if _is_private_ip(str(ip)):
            continue
        if len(grp) < SSRF_MIN_REQUESTS:
            continue

        grp = grp.sort_values("timestamp").reset_index(drop=True)
        t0, t1 = grp["timestamp"].min(), grp["timestamp"].max()
        post = pd.Timedelta(hours=1)

        # Cibles extraites des URIs
        targets_from_uri = sorted(set(
            t for t in grp["uri"].apply(_extract_target) if t is not None
        ))

        # Trafic réseau interne déclenché (web server → services internes)
        internal_targets: list[str] = []
        internal_traffic = False
        if net_df is not None and not net_df.empty:
            net_w = net_df[
                (net_df["timestamp"] >= t0) & (net_df["timestamp"] <= t1 + post)
            ]
            if "source_ip" in net_w.columns and "destination_ip" in net_w.columns:
                internal_src = net_w[net_w["source_ip"].apply(_is_private_ip)]
                if not internal_src.empty:
                    dest_is_internal = internal_src["destination_ip"].apply(_is_private_ip)
                    dest_is_metadata = internal_src["destination_ip"] == METADATA_IP
                    ssrf_net = internal_src[dest_is_internal | dest_is_metadata]
                    if "destination_port" in ssrf_net.columns:
                        ssrf_net = ssrf_net[
                            ssrf_net["destination_port"].isin(SSRF_INTERNAL_PORTS)
                        ]
                    if not ssrf_net.empty:
                        internal_traffic = True
                        for _, row in ssrf_net.head(20).iterrows():
                            dst_ip = row.get("destination_ip", "")
                            dst_port = row.get("destination_port")
                            entry = (
                                f"{dst_ip}:{int(dst_port)}"
                                if pd.notna(dst_port) else str(dst_ip)
                            )
                            internal_targets.append(entry)
                        internal_targets = sorted(set(internal_targets))

        all_targets = sorted(set(targets_from_uri + internal_targets))

        indicators: dict = {}
        if all_targets:
            indicators["ssrf_targets"] = all_targets
        if internal_traffic:
            indicators["internal_traffic_from_web"] = True

        attacks.append({
            "challenge_id": CHALLENGE,
            "detection": {
                "attack_type": "ssrf",
                "attacker_ips": [str(ip)],
                "victim_accounts": [],
                "attack_start_time": fmt_ts(t0),
                "attack_end_time": fmt_ts(t1),
                "indicators": indicators,
            },
            "detection_time_seconds": 0,
        })

    return attacks
