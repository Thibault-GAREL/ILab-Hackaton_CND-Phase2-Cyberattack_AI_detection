#!/usr/bin/env python3
"""Tests sans reseau : canonisation IoC DS1, payload public, filtre confiance (logique)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Desactiver canon globale pour tester le module avec monkeypatch local
os.environ.setdefault("CND_DS1_CANONICAL_IOCS", "1")

from ds1_ioc_canonical import (  # noqa: E402
    apply_ds1_ioc_canonicalization,
    canonicalize_ds1_indicators,
)
from detection_run import public_detection_payload  # noqa: E402


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def test_ssh_alias_and_merge_prefix() -> None:
    ind = {"total_ssh_failures": 123, "lateral_targets": ["a"], "noise": 1}
    out = canonicalize_ds1_indicators("ssh_brute_force", ind)
    _assert(out.get("failed_ssh") == 123, f"failed_ssh: {out!r}")
    _assert("noise" not in out, f"noise stripped: {out!r}")
    merged = canonicalize_ds1_indicators(
        "ssh_brute_force",
        {"ssh_brute_force_total_ssh_failures": 99, "lateral_targets": ["x"]},
    )
    _assert(merged.get("failed_ssh") == 99, f"merge prefix: {merged!r}")


def test_sqli_alias_exfil() -> None:
    out = canonicalize_ds1_indicators(
        "sql_injection",
        {"sqli_requests": 300, "exfil_bytes": 25_000_000, "tool_signature": "Chrome-like"},
    )
    _assert(out.get("sqli_payloads") == 300, f"sqli_payloads: {out!r}")
    _assert(out.get("exfil_bytes") == "~25MB", f"exfil_bytes: {out!r}")
    _assert(out.get("tool_signature") == "Chrome-like", f"tool_signature: {out!r}")


def test_directory_reads_format() -> None:
    out = canonicalize_ds1_indicators(
        "directory_traversal",
        {
            "traversal_patterns": "../../../etc/passwd",
            "successful_reads": 75,
            "sensitive_files": ["/etc/passwd"],
        },
    )
    _assert(out["successful_reads"] == "~75", f"successful_reads: {out!r}")


def test_ssrf_no_extra_keys() -> None:
    out = canonicalize_ds1_indicators(
        "ssrf",
        {"ssrf_targets": ["169.254.169.254"], "ssrf_requests": 99, "internal_traffic_from_web": True},
    )
    _assert("ssrf_requests" not in out, f"ssrf_requests stripped: {out!r}")
    _assert(len(out["ssrf_targets"]) == 1, f"targets: {out!r}")


def test_apply_list_and_public_payload() -> None:
    d = {
        "challenge_id": "ssh_brute_force",
        "detection": {
            "attack_type": "ssh_brute_force",
            "attacker_ips": ["1.1.1.1"],
            "victim_accounts": [],
            "attack_start_time": "2026-01-11T01:00:00Z",
            "attack_end_time": "2026-01-11T07:00:00Z",
            "indicators": {"total_ssh_failures": 5},
        },
        "detection_time_seconds": 1,
        "_bedrock_enrichment_confidence": "high",
    }
    apply_ds1_ioc_canonicalization([d])
    _assert("failed_ssh" in d["detection"]["indicators"], str(d))
    pub = public_detection_payload(d)
    _assert("_bedrock_enrichment_confidence" not in pub, str(pub))
    _assert(pub["challenge_id"] == "ssh_brute_force", str(pub))


def test_drop_low_logic() -> None:
    from config import BEDROCK_DROP_LOW_ENRICHMENT_CONFIDENCE  # noqa: E402

    def drop(meta: str) -> bool:
        return BEDROCK_DROP_LOW_ENRICHMENT_CONFIDENCE and meta == "low"

    _assert(drop("low") is True, "default drop low")
    _assert(drop("high") is False, "keep high")
    _assert(drop("unavailable") is False, "keep unavailable")


def main() -> None:
    test_ssh_alias_and_merge_prefix()
    test_sqli_alias_exfil()
    test_directory_reads_format()
    test_ssrf_no_extra_keys()
    test_apply_list_and_public_payload()
    test_drop_low_logic()
    print("OK — scripts/test_ds1_ioc_canonical.py (6 groupes)")


if __name__ == "__main__":
    main()
