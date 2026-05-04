"""
Pipeline principale : ingestion OpenSearch uniquement (delta + search_after).

Usage :
    python pipeline.py                    # une passe, ecrit detections.json, avance le curseur
    python pipeline.py --loop           # boucle (intervalle OPENSEARCH_POLL_INTERVAL_S)
    python pipeline.py --max-docs 5000  # limite de documents par poll
    python pipeline.py --submit         # soumettre chaque detection (API scoring)
    python pipeline.py --submit-dry-run # payloads soumission sans POST
    python pipeline.py --reset-state    # curseur au debut du flux DS2
    python pipeline.py --no-dedup

Curseur : OPENSEARCH_STATE_BACKEND=file|dynamodb (voir opensearch_state.py).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import pandas as pd

from .config import OPENSEARCH_POLL_INTERVAL_S
from .detection_run import public_detection_payload, run_detection_chain, run_single_poll_submit
from .opensearch_connector import OpenSearchConnector
from .opensearch_state import load_last_timestamp, save_last_timestamp
from .pipeline_core import split_logs_frame


def _merge_detection_into(existing: dict, new: dict) -> dict:
    """Fusionne *new* dans *existing* (même challenge_id) : élargit la fenêtre, fusionne les IoC."""
    e_det = existing.get("detection") or {}
    n_det = new.get("detection") or {}

    e_start = e_det.get("attack_start_time", "")
    n_start = n_det.get("attack_start_time", "")
    e_end = e_det.get("attack_end_time", "")
    n_end = n_det.get("attack_end_time", "")
    if n_start and (not e_start or n_start < e_start):
        e_det["attack_start_time"] = n_start
    if n_end and (not e_end or n_end > e_end):
        e_det["attack_end_time"] = n_end

    e_ips = set(e_det.get("attacker_ips") or [])
    e_ips.update(n_det.get("attacker_ips") or [])
    e_det["attacker_ips"] = sorted(e_ips)

    e_victims = set(e_det.get("victim_accounts") or [])
    e_victims.update(n_det.get("victim_accounts") or [])
    e_det["victim_accounts"] = sorted(e_victims)

    e_ind = e_det.get("indicators") or {}
    n_ind = n_det.get("indicators") or {}
    for k, v in n_ind.items():
        if k not in e_ind:
            e_ind[k] = v
        elif isinstance(v, (int, float)) and isinstance(e_ind[k], (int, float)):
            e_ind[k] = max(e_ind[k], v)
        elif isinstance(v, list) and isinstance(e_ind[k], list):
            merged = list(dict.fromkeys(e_ind[k] + v))
            e_ind[k] = merged
    e_det["indicators"] = e_ind
    existing["detection"] = e_det
    return existing


def _accumulate_detections(attacks: list[dict]) -> list[dict]:
    """Charge detections.json existant et fusionne par challenge_id."""
    det_path = os.environ.get("DETECTIONS_JSON_PATH", "detections.json")
    existing: list[dict] = []
    if os.path.isfile(det_path):
        try:
            with open(det_path) as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            existing = []
    by_cid: dict[str, dict] = {}
    for e in existing:
        cid = e.get("challenge_id", "")
        if cid:
            by_cid[cid] = e
    for a in attacks:
        cid = a.get("challenge_id", "")
        if cid in by_cid:
            by_cid[cid] = _merge_detection_into(by_cid[cid], a)
        else:
            by_cid[cid] = a
    return list(by_cid.values())


def write_detection_files(attacks: list[dict], *, accumulate: bool = False) -> None:
    if accumulate:
        attacks = _accumulate_detections(attacks)
    det_path = os.environ.get("DETECTIONS_JSON_PATH", "detections.json")
    api_path = os.environ.get("DETECTIONS_API_JSON_PATH", "detections_api.json")
    public_attacks = [public_detection_payload(a) for a in attacks]
    with open(det_path, "w") as f:
        json.dump(public_attacks, f, indent=2, ensure_ascii=False)
    print(f"Saved to {det_path}")
    from .detection_api import to_api_format

    api_items = [d.model_dump() for d in to_api_format(public_attacks)]
    with open(api_path, "w") as f:
        json.dump(api_items, f, indent=2, ensure_ascii=False)
    print(f"Saved to {api_path} (API format)")


def process_one_poll(
    connector: OpenSearchConnector,
    *,
    max_docs: int | None,
    use_dedup: bool,
    submit_live: bool,
    submit_dry: bool,
    dry_run_state: bool,
    accumulate: bool = False,
) -> list[dict]:
    """
    dry_run_state : si True, ne pas avancer le curseur OpenSearch (comportement dry-run global).
    accumulate : si True, merger avec les détections existantes dans detections.json.
    """
    last_ts = load_last_timestamp()
    if submit_live or submit_dry:
        attacks, df, new_ts = run_single_poll_submit(
            connector,
            since_ts=last_ts,
            max_docs=max_docs,
            use_dedup=use_dedup,
            dry_run=submit_dry,
        )
    else:
        df = connector.fetch_since(last_ts, max_docs=max_docs)
        if df.empty:
            return []
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
        new_ts = last_ts
        if "timestamp" in df.columns and not df.empty:
            mx = df["timestamp"].max()
            if pd.notna(mx):
                new_ts = pd.Timestamp(mx).strftime("%Y-%m-%dT%H:%M:%SZ")

    write_detection_files(attacks, accumulate=accumulate)
    if not dry_run_state and not df.empty:
        save_last_timestamp(new_ts)
    return attacks


def run_realtime_compat(*, dry_run: bool = False, reset: bool = False) -> None:
    """Compatibilite avec realtime_pipeline.py : boucle + soumission API."""
    connector = OpenSearchConnector()
    if reset:
        save_last_timestamp("2026-01-31T00:00:00Z")
        print("[Reset] Timestamp reinitialise au debut du flux.")
    print(f"[Realtime] Polling toutes les {OPENSEARCH_POLL_INTERVAL_S}s (dry_run={dry_run})")
    while True:
        try:
            process_one_poll(
                connector,
                max_docs=None,
                use_dedup=True,
                submit_live=not dry_run,
                submit_dry=dry_run,
                dry_run_state=dry_run,
            )
        except Exception as e:
            print(f"[Realtime] Erreur: {e} — retry dans {OPENSEARCH_POLL_INTERVAL_S}s")
        time.sleep(OPENSEARCH_POLL_INTERVAL_S)


def main() -> None:
    parser = argparse.ArgumentParser(description="Pipeline detection via OpenSearch")
    parser.add_argument("--no-dedup", action="store_true")
    parser.add_argument(
        "--max-docs",
        type=int,
        default=None,
        help="Nombre max de documents par poll (defaut : illimite)",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Boucle infinie avec sleep(OPENSEARCH_POLL_INTERVAL_S)",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=None,
        help="Secondes entre polls si --loop (defaut : config OPENSEARCH_POLL_INTERVAL_S)",
    )
    parser.add_argument(
        "--reset-state",
        action="store_true",
        help="Reinitialise le curseur (2026-01-31T00:00:00Z) avant le premier poll",
    )
    parser.add_argument(
        "--submit",
        action="store_true",
        help="Soumettre chaque detection a l API (voir submit.py)",
    )
    parser.add_argument(
        "--submit-dry-run",
        action="store_true",
        dest="submit_dry_run",
        help="Meme flux que --submit mais dry-run cote API",
    )
    parser.add_argument(
        "--dry-run-state",
        action="store_true",
        help="Ne pas ecrire le curseur (relecture des memes logs au prochain poll)",
    )
    parser.add_argument(
        "--accumulate",
        action="store_true",
        help="Merger les nouvelles detections avec celles deja dans detections.json (mode slices)",
    )
    args = parser.parse_args()

    if args.submit and args.submit_dry_run:
        print("--submit et --submit-dry-run sont mutuellement exclusifs.", file=sys.stderr)
        sys.exit(2)

    poll_s = args.poll_interval if args.poll_interval is not None else OPENSEARCH_POLL_INTERVAL_S
    connector = OpenSearchConnector()

    if args.reset_state:
        save_last_timestamp("2026-01-31T00:00:00Z")
        print("[Reset] Curseur reinitialise.")

    def one() -> list[dict]:
        t0 = time.time()
        attacks = process_one_poll(
            connector,
            max_docs=args.max_docs,
            use_dedup=not args.no_dedup,
            submit_live=args.submit,
            submit_dry=args.submit_dry_run,
            dry_run_state=args.dry_run_state,
            accumulate=args.accumulate,
        )
        print(f"\n{len(attacks)} detection(s) in {int(time.time() - t0)}s")
        return attacks

    if args.loop:
        print(f"[Pipeline] Boucle — intervalle {poll_s}s")
        while True:
            try:
                one()
            except KeyboardInterrupt:
                print("\n[Pipeline] Arret.")
                sys.exit(0)
            except Exception as e:
                print(f"[Pipeline] Erreur: {e} — retry dans {poll_s}s")
            time.sleep(poll_s)
    else:
        try:
            one()
        except Exception as e:
            print(f"[Pipeline] Erreur: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
