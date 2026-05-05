import pandas as pd
from pipeline.config import CAMPAIGN_OVERLAP_MINUTES
from .utils import fmt_ts, group_ips_by_overlap, _is_private_ip

CHALLENGE = "ldap_brute_force"

# Seuils calibrés sur DS2 : IPs internes avec ~130 échecs LDAP ciblant 3 comptes de service
MIN_FAILURES = 30
MIN_RATE_PER_MINUTE = 0.5  # Au moins 0.5 tentatives/min


def detect_ldap_brute_force(
    auth_failures: pd.DataFrame,
    auth_all: pd.DataFrame | None = None,
) -> list[dict]:
    """Détecte du brute force LDAP : IPs avec beaucoup d'échecs auth_method=ldap."""
    if auth_failures.empty or 'auth_method' not in auth_failures.columns:
        return []

    ldap_fail = auth_failures[auth_failures['auth_method'] == 'ldap'].copy()
    if ldap_fail.empty:
        return []

    # Filtrer les expired_token (bruit de service, pas du brute force)
    if 'failure_reason' in ldap_fail.columns:
        ldap_fail = ldap_fail[ldap_fail['failure_reason'] != 'expired_token']
    if ldap_fail.empty:
        return []

    ip_windows: dict = {}
    ip_data: dict = {}

    for ip, grp in ldap_fail.groupby('source_ip'):
        if len(grp) < MIN_FAILURES:
            continue
        grp = grp.sort_values('timestamp')
        t0, t1 = grp['timestamp'].min(), grp['timestamp'].max()
        duration_min = max((t1 - t0).total_seconds() / 60, 1)
        if len(grp) / duration_min < MIN_RATE_PER_MINUTE:
            continue
        ip_windows[str(ip)] = (t0, t1)
        ip_data[str(ip)] = grp

    if not ip_windows:
        return []

    campaigns = group_ips_by_overlap(ip_windows, CAMPAIGN_OVERLAP_MINUTES)

    attacks = []
    for campaign_ips in campaigns:
        merged = pd.concat([ip_data[ip] for ip in campaign_ips], ignore_index=True)
        t0 = merged['timestamp'].min()
        t1 = merged['timestamp'].max()

        targeted_accounts = sorted(merged['username'].dropna().unique().tolist())
        failure_reasons = merged['failure_reason'].value_counts().to_dict() if 'failure_reason' in merged.columns else {}

        # Comptes compromis : succès LDAP depuis ces IPs après les échecs
        victim_accounts = []
        if auth_all is not None and not auth_all.empty:
            success = auth_all[
                (auth_all['status'] == 'success') &
                (auth_all['auth_method'] == 'ldap') &
                (auth_all['source_ip'].isin(campaign_ips)) &
                (auth_all['timestamp'] >= t0)
            ]
            victim_accounts = sorted(success['username'].dropna().unique().tolist())

        attacks.append({
            "challenge_id": CHALLENGE,
            "detection": {
                "attack_type": "ldap_brute_force",
                "attacker_ips": sorted(campaign_ips),
                "victim_accounts": victim_accounts,
                "attack_start_time": fmt_ts(t0),
                "attack_end_time": fmt_ts(t1),
                "indicators": {
                    "total_ldap_failures": len(merged),
                    "targeted_accounts": targeted_accounts,
                    "failure_reasons": failure_reasons,
                },
            },
            "detection_time_seconds": 0,
        })

    return attacks
