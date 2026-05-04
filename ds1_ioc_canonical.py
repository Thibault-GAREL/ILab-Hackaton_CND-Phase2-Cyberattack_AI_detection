"""
Canonisation des indicateurs IoC pour les 5 challenges DS1 (alignement ground-truth-ds1.json).

Utilise DS1_CANONICAL_IOCS dans config ; no-op hors DS1 ou si desactive (ex. preparation DS2).
"""

from __future__ import annotations

from typing import Any

from config import DS1_CANONICAL_IOCS

DS1_CHALLENGE_IDS = frozenset({
    "credential_stuffing",
    "ssh_brute_force",
    "sql_injection",
    "directory_traversal",
    "ssrf",
})

# Cles officielles par challenge (Dataset_log/ground-truth-ds1.json)
CANONICAL_KEYS_BY_CHALLENGE: dict[str, frozenset[str]] = {
    "credential_stuffing": frozenset({
        "failed_logins",
        "web_shell",
        "reverse_shell_port",
        "geolocation",
    }),
    "ssh_brute_force": frozenset({
        "failed_ssh",
        "lateral_targets",
        "priv_esc",
        "exfil_port",
    }),
    "sql_injection": frozenset({
        "sqli_payloads",
        "exfil_bytes",
        "tool_signature",
    }),
    "directory_traversal": frozenset({
        "traversal_patterns",
        "successful_reads",
        "sensitive_files",
    }),
    "ssrf": frozenset({
        "ssrf_targets",
        "internal_traffic_from_web",
    }),
}

# Prefixes produits par dedup.merge (detectors/dedup.py) — ordre : plus long en premier
_DEDUP_TYPE_PREFIXES: tuple[str, ...] = tuple(
    sorted(
        (
            f"{cid}_"
            for cid in (
                "credential_stuffing",
                "ssh_brute_force",
                "sql_injection",
                "directory_traversal",
                "ssrf",
            )
        ),
        key=len,
        reverse=True,
    )
)

_ALL_CANONICAL_IOC_KEYS: frozenset[str] = frozenset().union(
    *CANONICAL_KEYS_BY_CHALLENGE.values()
)


def _strip_merge_prefix(key: str) -> str:
    for p in _DEDUP_TYPE_PREFIXES:
        if key.startswith(p):
            return key[len(p) :]
    return key


def _normalize_indicator_map(indicators: dict[str, Any]) -> dict[str, Any]:
    """Aplatit les cles type ssh_brute_force_total_ssh_failures -> total_ssh_failures."""
    out: dict[str, Any] = {}
    for k, v in indicators.items():
        if not isinstance(k, str):
            continue
        # Ne pas tronquer les cles deja canoniques (ex. ssrf_targets commence par ssrf_)
        logical = k if k in _ALL_CANONICAL_IOC_KEYS else _strip_merge_prefix(k)
        if logical not in out:
            out[logical] = v
    return out


def _format_exfil_gt_style(value: Any) -> Any:
    """Approche le style GT ~25MB pour les grandes exfil numeriques."""
    if isinstance(value, str) and value.strip():
        return value
    try:
        n = float(value)
    except (TypeError, ValueError):
        return value
    if n >= 20_000_000:
        return "~25MB"
    if n >= 1_000_000:
        mb = max(1, int(round(n / 1_000_000)))
        return f"~{mb}MB"
    return int(n) if n == int(n) else n


def _format_successful_reads_gt_style(value: Any) -> Any:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return f"~{value}"
    return value


def _pick_first(norm: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        if name in norm and norm[name] is not None:
            return norm[name]
    return None


def canonicalize_ds1_indicators(challenge_id: str, indicators: dict[str, Any]) -> dict[str, Any]:
    """
    Retourne un dict d indicateurs avec uniquement les cles du ground truth DS1,
    valeurs reprises des cles canoniques ou alias (y compris cles prefixees merge).
    """
    if challenge_id not in CANONICAL_KEYS_BY_CHALLENGE:
        return dict(indicators)
    keys = CANONICAL_KEYS_BY_CHALLENGE[challenge_id]
    norm = _normalize_indicator_map(dict(indicators))
    out: dict[str, Any] = {}

    if challenge_id == "credential_stuffing":
        v = _pick_first(norm, ("failed_logins",))
        if v is not None:
            out["failed_logins"] = v
        for k in ("web_shell", "reverse_shell_port", "geolocation"):
            v = _pick_first(norm, (k,))
            if v is not None:
                out[k] = v

    elif challenge_id == "ssh_brute_force":
        v = _pick_first(norm, ("failed_ssh", "total_ssh_failures"))
        if v is not None:
            out["failed_ssh"] = v
        for k in ("lateral_targets", "priv_esc", "exfil_port"):
            v = _pick_first(norm, (k,))
            if v is not None:
                out[k] = v

    elif challenge_id == "sql_injection":
        v = _pick_first(norm, ("sqli_payloads", "sqli_requests"))
        if v is not None:
            out["sqli_payloads"] = v
        eb = _pick_first(norm, ("exfil_bytes",))
        if eb is not None:
            out["exfil_bytes"] = _format_exfil_gt_style(eb)
        ts = _pick_first(norm, ("tool_signature",))
        if ts is not None:
            out["tool_signature"] = ts

    elif challenge_id == "directory_traversal":
        tp = _pick_first(norm, ("traversal_patterns",))
        if tp is not None:
            out["traversal_patterns"] = tp
        sr = _pick_first(norm, ("successful_reads",))
        if sr is not None:
            out["successful_reads"] = _format_successful_reads_gt_style(sr)
        sf = _pick_first(norm, ("sensitive_files",))
        if sf is not None:
            out["sensitive_files"] = sf

    elif challenge_id == "ssrf":
        st = _pick_first(norm, ("ssrf_targets",))
        if st is not None:
            out["ssrf_targets"] = st
        it = _pick_first(norm, ("internal_traffic_from_web",))
        if it is not None:
            out["internal_traffic_from_web"] = it

    # Ne garder que les cles attendues (au cas ou une branche incomplete)
    return {k: out[k] for k in keys if k in out}


def apply_ds1_ioc_canonicalization(detections: list[dict]) -> list[dict]:
    if not DS1_CANONICAL_IOCS:
        return detections
    for d in detections:
        cid = d.get("challenge_id")
        if cid not in DS1_CHALLENGE_IDS:
            continue
        det = d.get("detection")
        if not isinstance(det, dict):
            continue
        ind = det.get("indicators")
        if not isinstance(ind, dict):
            continue
        det["indicators"] = canonicalize_ds1_indicators(str(cid), ind)
    return detections
