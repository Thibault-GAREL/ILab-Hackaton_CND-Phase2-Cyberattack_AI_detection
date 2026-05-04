#!/usr/bin/env python3
"""
Fetch N logs depuis OpenSearch, lance detecteurs + dedup + Bedrock (defaut Opus 4.6 EU).

Strategy ds1 : repartition ponderee (credential/sql plus lourds). Attention : avec tri asc
OpenSearch, les 401 « bruit » (IPs internes) precedent souvent les IP attaquantes dans la
fenêtre credential — compter ~20k+ lignes sur cette seule fenêtre pour declencher
credential_stuffing (fenêtre lourde en 401). Pour un 5/5 proche du
full dataset, viser plutot --max-docs 120000 ou plus.

Usage :
  .venv/bin/python scripts/validate_pipeline_opensearch_n.py --max-docs 10000
  .venv/bin/python scripts/validate_pipeline_opensearch_n.py --max-docs 120000 --strategy ds1

Forcer le modelId avant import de config :
  BEDROCK_TIMELINE_MODEL_ID=eu.anthropic.claude-opus-4-6-v1 ...
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Repartition des docs DS1 (total = max_docs) : SQLi / cred ont besoin de plus de lignes avec tri asc.
_DS1_FETCH_WEIGHTS: dict[str, int] = {
    "credential_stuffing": 4,
    "ssh_brute_force": 3,
    "sql_injection": 5,
    "directory_traversal": 2,
    "ssrf": 2,
}


def _parse_iso_utc(s: str) -> datetime:
    s = str(s).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).astimezone(timezone.utc)


def _fmt_iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _allocate_per_window(
    windows: list[tuple[str, str, str]], max_docs: int
) -> list[int]:
    weights = [_DS1_FETCH_WEIGHTS.get(cid, 1) for cid, _, _ in windows]
    s = sum(weights)
    raw = [max_docs * w / s for w in weights]
    ints = [int(x) for x in raw]
    rem = max_docs - sum(ints)
    frac_idx = sorted(
        range(len(ints)), key=lambda i: raw[i] - ints[i], reverse=True
    )
    for j in range(rem):
        ints[frac_idx[j % len(ints)]] += 1
    return [max(1, n) for n in ints]


def fetch_ds1_weighted(
    oc,
    windows: list[tuple[str, str, str]],
    max_docs: int,
    pad_hours: float,
):
    """Comme fetch_ds1_windows mais budget pondere par fenetre (total exact max_docs)."""
    import pandas as pd

    per_list = _allocate_per_window(windows, max_docs)
    padded_meta: list[tuple[str, str, str]] = []
    dfs: list = []
    for (cid, gte, lte), per in zip(windows, per_list):
        a = _parse_iso_utc(gte) - timedelta(hours=pad_hours)
        b = _parse_iso_utc(lte) + timedelta(hours=pad_hours)
        wg, wl = _fmt_iso_utc(a), _fmt_iso_utc(b)
        padded_meta.append((cid, wg, wl))
        t0 = time.perf_counter()
        chunk = oc.fetch_time_range(wg, wl, max_docs=per)
        print(
            f"[OpenSearch] DS1 `{cid}` : {len(chunk)} lignes "
            f"(budget={per}) en {time.perf_counter() - t0:.2f} s"
        )
        if not chunk.empty:
            dfs.append(chunk)
    if not dfs:
        return pd.DataFrame(), padded_meta

    out = pd.concat(dfs, ignore_index=True)
    if "_id" in out.columns:
        out = out.drop_duplicates(subset=["_id"], ignore_index=True)
    return out, padded_meta


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Fetch OpenSearch (head chronologique ou fenetres DS1), "
            "detecteurs + dedup + Bedrock."
        )
    )
    ap.add_argument("--max-docs", type=int, default=10_000)
    ap.add_argument("--gte", default="2026-01-01T00:00:00Z")
    ap.add_argument("--lte", default="2026-02-01T00:00:00Z")
    ap.add_argument(
        "--strategy",
        choices=("ds1", "head"),
        default="ds1",
        help="ds1 = fenetres ground-truth avec repartition ponderee (total=max_docs). "
        "head = premiers max_docs en ordre chronologique sur [gte,lte].",
    )
    ap.add_argument(
        "--gt-path",
        type=Path,
        default=ROOT / "Dataset_log" / "ground-truth-ds1.json",
    )
    ap.add_argument(
        "--pad-hours",
        type=float,
        default=0.0,
        help="Marge autour des fenetres DS1 (0 recommande pour petits max_docs : "
        "evite de consumer le budget avant le debut d attaque).",
    )
    ap.add_argument(
        "--model-id",
        default="eu.anthropic.claude-opus-4-6-v1",
        help="Un seul candidat Bedrock (inference profile EU Opus 4.6 par defaut).",
    )
    ap.add_argument("--no-bedrock", action="store_true")
    ap.add_argument(
        "--out-md",
        type=Path,
        default=ROOT / "validate_opensearch_pipeline_report.md",
    )
    args = ap.parse_args()

    os.environ["BEDROCK_TIMELINE_MODEL_ID"] = args.model_id
    os.environ["BEDROCK_MODEL_ID"] = args.model_id

    import config as cfg

    import pandas as pd

    from opensearch_connector import OpenSearchConnector
    from pipeline_core import split_logs_frame, run_detectors
    from detectors.dedup import deduplicate
    from bedrock_analysis import enrich_detections, get_bedrock_metrics

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: list[str] = [
        "# Validation pipeline — OpenSearch + Bedrock",
        "",
        f"- **Genere (UTC)** : {now}",
        f"- **max_docs** : {args.max_docs}",
        f"- **strategy** : `{args.strategy}`",
        f"- **Fenetre (_count / head)** : `{args.gte}` .. `{args.lte}`",
        f"- **modelId Bedrock** : `{args.model_id}`",
        f"- **BEDROCK_ENABLED (config)** : {cfg.BEDROCK_ENABLED}",
        f"- **no_bedrock flag** : {args.no_bedrock}",
        "",
    ]

    err = None
    df = None
    t_fetch = 0.0
    ds1_meta: list | None = None
    try:
        oc = OpenSearchConnector()
        t0 = time.perf_counter()
        if args.strategy == "head":
            df = oc.fetch_time_range(args.gte, args.lte, max_docs=args.max_docs)
        else:
            if not args.gt_path.is_file():
                raise FileNotFoundError(f"Ground truth introuvable : {args.gt_path}")
            sys.path.insert(0, str(ROOT / "scripts"))
            from benchmark_opensearch_report import load_ds1_windows  # noqa: E402

            wins = load_ds1_windows(args.gt_path)
            alloc = _allocate_per_window(wins, args.max_docs)
            lines.append(
                f"- **Repartition DS1 (lignes / fenetre)** : "
                + ", ".join(f"`{wins[i][0]}`={alloc[i]}" for i in range(len(wins)))
            )
            df, ds1_meta = fetch_ds1_weighted(
                oc, wins, max_docs=args.max_docs, pad_hours=args.pad_hours
            )
        t_fetch = time.perf_counter() - t0
    except Exception:
        err = traceback.format_exc()

    if err:
        lines += ["## Erreur OpenSearch", "", "```", err.strip(), "```", ""]
        args.out_md.write_text("\n".join(lines), encoding="utf-8")
        print("wrote", args.out_md)
        return 1

    lines += [
        "## Fetch OpenSearch",
        "",
        f"- **Lignes** : {len(df):,}",
        f"- **Duree fetch** : {t_fetch:.2f} s",
        "",
    ]
    if ds1_meta:
        lines.append("### Fenetres DS1 (fetch)")
        lines.append("")
        for cid, wg, wl in ds1_meta:
            lines.append(f"- `{cid}` : `{wg}` → `{wl}`")
        lines.append("")
    if not df.empty and "timestamp" in df.columns:
        ts = df["timestamp"]
        lines.append(f"- **timestamp min/max** : `{ts.min()}` / `{ts.max()}`")
        lines.append("")

    if df.empty:
        lines.append("DataFrame vide — arret.")
        args.out_md.write_text("\n".join(lines), encoding="utf-8")
        return 1

    auth_all, auth_failures, app_all, net_all, sys_all = split_logs_frame(df)
    sample_df = pd.concat([auth_all, app_all, net_all, sys_all], ignore_index=True)

    t_det = time.perf_counter()
    attacks_raw = run_detectors(
        auth_failures, app_all, net_all, sys_all, auth_all=auth_all
    )
    n_raw = len(attacks_raw)
    attacks = deduplicate(attacks_raw)
    t_after_det = time.perf_counter()

    lines += [
        "## Detecteurs + dedup",
        "",
        f"- **Brutes (avant dedup)** : {n_raw}",
        f"- **Apres dedup** : {len(attacks)}",
        f"- **Temps detecteurs + dedup** : {t_after_det - t_det:.2f} s",
        "",
    ]

    for a in attacks:
        lines.append(f"- `{a.get('challenge_id')}`")
    lines.append("")

    bedrock_s = 0.0
    bedrock_calls = 0
    if not args.no_bedrock and cfg.BEDROCK_ENABLED and attacks:
        t_b0 = time.perf_counter()
        try:
            attacks = enrich_detections(attacks, sample_df)
        except Exception:
            err = traceback.format_exc()
            lines += ["## Erreur Bedrock", "", "```", err.strip(), "```", ""]
            args.out_md.write_text("\n".join(lines), encoding="utf-8")
            return 1
        bedrock_s = time.perf_counter() - t_b0
        bm = get_bedrock_metrics()
        bedrock_calls = bm.get("calls", 0)
        lines += [
            "## Bedrock",
            "",
            f"- **Duree enrich_detections** : {bedrock_s:.2f} s",
            f"- **converse_calls** : {bedrock_calls}",
            "",
        ]
    elif args.no_bedrock or not cfg.BEDROCK_ENABLED:
        lines += ["## Bedrock", "", "_Skipped (no-bedrock ou BEDROCK_ENABLED=False)._", ""]
    else:
        lines += ["## Bedrock", "", "_Aucune detection a enrichir._", ""]

    lines += ["## Detections (JSON)", "", "```json", json.dumps(attacks, indent=2, ensure_ascii=False), "```", ""]

    summary = {
        "rows": len(df),
        "fetch_s": round(t_fetch, 3),
        "detections": len(attacks),
        "bedrock_s": round(bedrock_s, 3) if bedrock_s else None,
        "bedrock_converse_calls": bedrock_calls or None,
        "challenge_ids": [a.get("challenge_id") for a in attacks],
    }
    lines += ["## Resume machine", "", "```json", json.dumps(summary, indent=2), "```", ""]

    args.out_md.write_text("\n".join(lines), encoding="utf-8")
    print("wrote", args.out_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
