"""
Decoupage des logs par source et lancement des 5 detecteurs DS1 (sans OpenSearch / sans Bedrock).
"""

from __future__ import annotations

import time

import pandas as pd

from detectors import (
    detect_credential_stuffing,
    detect_ssh_brute_force,
    detect_sql_injection,
    detect_directory_traversal,
    detect_ssrf,
)

AUTH_COLS = [
    "timestamp", "source_ip", "username", "status", "failure_reason",
    "auth_method", "destination_port", "geolocation_country",
]
APP_COLS = [
    "timestamp", "source_ip", "username", "status_code",
    "http_method", "uri", "user_agent", "response_size",
]
NET_COLS = [
    "timestamp", "source_ip", "destination_ip", "destination_port",
    "action", "protocol", "bytes_sent", "bytes_received",
]
SYS_COLS = [
    "timestamp", "source_ip", "hostname", "process", "pid",
    "message", "severity", "username",
]


def _safe_cols(df: pd.DataFrame, cols: list[str]) -> list[str]:
    return [c for c in cols if c in df.columns]


def split_logs_frame(df: pd.DataFrame):
    if df.empty:
        empty = pd.DataFrame()
        return empty, empty, empty, empty, empty
    if "log_source" not in df.columns:
        empty = pd.DataFrame()
        return empty, empty, empty, empty, empty

    src = df["log_source"]
    auth_all = df[src == "authentication"][_safe_cols(df, AUTH_COLS)].copy()
    auth_failures = (
        auth_all[auth_all["status"] == "failure"]
        if not auth_all.empty and "status" in auth_all.columns
        else pd.DataFrame()
    )
    app_all = df[src == "application"][_safe_cols(df, APP_COLS)].copy()
    net_all = df[src == "network"][_safe_cols(df, NET_COLS)].copy()
    sys_all = df[src == "system"][_safe_cols(df, SYS_COLS)].copy()
    return auth_all, auth_failures, app_all, net_all, sys_all


def run_detectors(
    auth_failures: pd.DataFrame,
    app_all: pd.DataFrame,
    net_all: pd.DataFrame,
    sys_all: pd.DataFrame,
    auth_all: pd.DataFrame | None = None,
) -> list[dict]:
    t0 = time.time()

    steps = [
        ("Credential stuffing", lambda: detect_credential_stuffing(
            app_all,
            auth_failures=auth_failures,
            net_all=net_all,
            auth_all=auth_all,
        )),
        ("SSH brute force", lambda: detect_ssh_brute_force(
            auth_failures,
            sys_df=sys_all,
            net_df=net_all,
            auth_all=auth_all,
        )),
        ("SQL injection", lambda: detect_sql_injection(app_all)),
        ("Directory traversal", lambda: detect_directory_traversal(app_all)),
        ("SSRF", lambda: detect_ssrf(app_all, net_df=net_all)),
    ]

    attacks = []
    for name, fn in steps:
        print(f"[Detection] {name}...")
        found = fn()
        print(f"  -> {len(found)} attack(s)")
        attacks.extend(found)

    elapsed = int(time.time() - t0)
    for a in attacks:
        a["detection_time_seconds"] = elapsed

    return attacks
