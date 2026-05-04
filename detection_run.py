"""
Chaine commune : detecteurs -> dedup -> Bedrock -> fenetres DS1 -> detection_time_seconds.
"""

from __future__ import annotations

import sys

import pandas as pd

from config import BEDROCK_ENABLED, SUBMIT_SKIP_DUPLICATES
from bedrock_analysis import enrich_detections
from ds1_ioc_canonical import apply_ds1_ioc_canonicalization
from bedrock_os_context import fetch_bedrock_context
from detectors.dedup import deduplicate
from detection_timing import apply_detection_latency_seconds
from ds1_timeline import apply_ds1_canonical_windows
from opensearch_connector import OpenSearchConnector
from remediation import attach_remediation_plans
from pipeline_core import run_detectors, split_logs_frame
from submit import submit_detection
from submit_cache import (
    fingerprint_detection,
    already_submitted,
    record_submission,
)


def public_detection_payload(d: dict) -> dict:
    """Payload sans cles internes Bedrock (ne pas serialiser _bedrock_*)."""
    return {k: v for k, v in d.items() if not str(k).startswith("_bedrock")}


def run_detection_chain(
    auth_all: pd.DataFrame,
    auth_failures: pd.DataFrame,
    app_all: pd.DataFrame,
    net_all: pd.DataFrame,
    sys_all: pd.DataFrame,
    *,
    use_dedup: bool,
    connector: OpenSearchConnector | None,
    batch_df: pd.DataFrame,
) -> list[dict]:
    """
    batch_df : logs bruts du poll (pour detection_time_seconds / bonus rapidite).
    """
    attacks = run_detectors(
        auth_failures, app_all, net_all, sys_all, auth_all=auth_all
    )
    if use_dedup:
        attacks = deduplicate(attacks)

    if attacks:
        if not BEDROCK_ENABLED:
            print(
                "ERREUR: au moins une detection mais BEDROCK_ENABLED=False dans config.",
                file=sys.stderr,
            )
            sys.exit(1)
        sample_df = pd.concat(
            [auth_all, app_all, net_all, sys_all], ignore_index=True
        )
        if connector is not None:
            ctx_df = fetch_bedrock_context(connector, attacks, sample_df)
        else:
            ctx_df = sample_df
        attacks = enrich_detections(attacks, ctx_df)
        apply_ds1_canonical_windows(attacks)
        apply_ds1_ioc_canonicalization(attacks)

    apply_detection_latency_seconds(attacks, batch_df)
    attach_remediation_plans(attacks)
    return attacks


def run_single_poll_submit(
    connector: OpenSearchConnector,
    *,
    since_ts: str,
    max_docs: int | None,
    use_dedup: bool,
    dry_run: bool,
) -> tuple[list[dict], pd.DataFrame, str]:
    """
    Un poll OpenSearch : fetch -> chaine -> soumission par detection.
    Retourne (attacks, df, new_last_ts_str pour curseur).
    """
    df = connector.fetch_since(since_ts, max_docs=max_docs)
    if df.empty:
        return [], df, since_ts

    auth_all, auth_failures, app_all, net_all, sys_all = split_logs_frame(df)
    attacks = run_detection_chain(
        auth_all,
        auth_failures,
        app_all,
        net_all,
        sys_all,
        use_dedup=use_dedup,
        connector=connector,
        batch_df=df,
    )

    for attack in attacks:
        attack["detection_time_seconds"] = max(
            0, int(attack.get("detection_time_seconds", 0))
        )

    submitted = 0
    for attack in attacks:
        fp = fingerprint_detection(attack)
        if SUBMIT_SKIP_DUPLICATES and not dry_run and already_submitted(fp):
            print(
                f"[Poll] Skip duplicate (cache) {fp[:12]}... "
                f"challenge_id={attack.get('challenge_id')}"
            )
            continue
        result = submit_detection(attack, dry_run=dry_run)
        if result and not dry_run and SUBMIT_SKIP_DUPLICATES:
            record_submission(fp)
        if dry_run or result:
            submitted += 1

    new_ts = since_ts
    if "timestamp" in df.columns and not df.empty:
        mx = df["timestamp"].max()
        if pd.notna(mx):
            new_ts = pd.Timestamp(mx).strftime("%Y-%m-%dT%H:%M:%SZ")

    return attacks, df, new_ts
