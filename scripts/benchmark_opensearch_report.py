#!/usr/bin/env python3
"""Benchmark OpenSearch live + pipeline (sans Bedrock dans ce script) -> rapport Markdown."""
from __future__ import annotations

import argparse
import json
import resource
import sys
import time
import traceback
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from pipeline import config  # noqa: E402
from pipeline.pipeline_core import split_logs_frame, run_detectors  # noqa: E402
from pipeline.detectors.dedup import deduplicate  # noqa: E402
from pipeline.opensearch_connector import OpenSearchConnector  # noqa: E402


def _rss_mb() -> float:
    ru = resource.getrusage(resource.RUSAGE_SELF)
    rss = ru.ru_maxrss
    if sys.platform == "darwin":
        return rss / (1024 * 1024)
    return rss / 1024


def expected_columns_union() -> set[str]:
    cols: set[str] = set()
    for name in ("AUTH_COLS", "APP_COLS", "NET_COLS", "SYS_COLS"):
        cols.update(getattr(pipeline, name))
    cols.add("log_source")
    return cols


def analyze_frame(df: pd.DataFrame) -> dict:
    out: dict = {"rows": len(df), "columns": list(df.columns), "log_source": {}}
    if df.empty:
        return out
    if "log_source" in df.columns:
        c = df["log_source"].dropna().astype(str)
        out["log_source"] = dict(Counter(c))
    if "timestamp" in df.columns:
        ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        valid = ts.dropna()
        if not valid.empty:
            out["timestamp_min"] = str(valid.min())
            out["timestamp_max"] = str(valid.max())
    exp = expected_columns_union()
    present = set(df.columns)
    out["expected_cols_missing"] = sorted(exp - present)
    out["extra_cols_vs_pipeline"] = sorted(present - exp)
    return out


def run_pipeline_on_df(df: pd.DataFrame) -> dict:
    rss0 = _rss_mb()
    t0 = time.perf_counter()
    auth_all, auth_failures, app_all, net_all, sys_all = split_logs_frame(df)
    t_split = time.perf_counter() - t0
    t1 = time.perf_counter()
    attacks = run_detectors(
        auth_failures, app_all, net_all, sys_all, auth_all=auth_all
    )
    t_det = time.perf_counter() - t1
    t2 = time.perf_counter()
    attacks_dedup = deduplicate(attacks)
    t_ded = time.perf_counter() - t2
    rss1 = _rss_mb()
    return {
        "split_s": round(t_split, 4),
        "detectors_s": round(t_det, 2),
        "dedup_s": round(t_ded, 4),
        "total_s": round(t_split + t_det + t_ded, 2),
        "rss_start_mb": round(rss0, 1),
        "rss_after_mb": round(rss1, 1),
        "frame_rows": {
            "auth_all": len(auth_all),
            "auth_failures": len(auth_failures),
            "app_all": len(app_all),
            "net_all": len(net_all),
            "sys_all": len(sys_all),
        },
        "detections_raw": len(attacks),
        "detections_after_dedup": len(attacks_dedup),
        "detections": attacks_dedup,
    }


def render_md(**kw) -> str:
    now = kw["now"]
    host = kw["host"]
    index = kw["index"]
    ts_field = kw["ts_field"]
    gte = kw["gte"]
    lte = kw["lte"]
    max_docs = kw["max_docs"]
    count_index = kw["count_index"]
    fetch_error = kw["fetch_error"]
    analysis = kw["analysis"]
    perf = kw["perf"]
    bedrock_enabled = kw["bedrock_enabled"]
    fetch_mode = kw.get("fetch_mode") or "range_head"
    ds1_windows = kw.get("ds1_windows")
    lines = [
        "# Rapport benchmark — OpenSearch live et pipeline (sans Claude / Bedrock)",
        "",
        f"- **Généré (UTC)** : {now}",
        f"- **Source** : index `{index}` (champ `{ts_field}`)",
        f"- **OPENSEARCH_HOST** : `{host}`",
        f"- **Mode fetch** : `{fetch_mode}`",
        f"- **Fenêtre (_count)** : gte=`{gte}`" + (f", lte=`{lte}`" if lte else ""),
        f"- **max_docs** (budget total indicatif) : {max_docs}",
        f"- **_count (plage)** : {count_index}",
        f"- **BEDROCK_ENABLED** : {bedrock_enabled} (aucun appel LLM dans ce benchmark).",
        "",
    ]
    if ds1_windows:
        lines += ["### Fenêtres ground-truth DS1 (fetch agrégé)", ""]
        for cid, wg, wl in ds1_windows:
            lines.append(f"- `{cid}` : `{wg}` → `{wl}`")
        lines.append("")
    if fetch_error:
        lines += ["## Erreur OpenSearch", "", "```", fetch_error.strip(), "```", ""]
        return "\n".join(lines)
    lines += ["## 1. Synthèse logs OpenSearch", "", f"- **Lignes** : {analysis['rows']:,}"]
    if analysis.get("timestamp_min"):
        lines.append(f"- **Période** : `{analysis['timestamp_min']}` → `{analysis['timestamp_max']}`")
    lines += ["", "### log_source", ""]
    tot = analysis["rows"] or 1
    for k, v in sorted(analysis.get("log_source", {}).items(), key=lambda x: -x[1]):
        lines.append(f"- `{k}` : {v:,} ({100.0 * v / tot:.2f} %)")
    lines += ["", "### Colonnes", "", "```", ", ".join(analysis["columns"]), "```", ""]
    if analysis.get("expected_cols_missing"):
        lines += ["### Manquantes vs pipeline", "", ", ".join("`%s`" % c for c in analysis["expected_cols_missing"]), ""]
    ex = analysis.get("extra_cols_vs_pipeline") or []
    if ex:
        lines += ["### Extra (hors AUTH/APP/NET/SYS)", "", ", ".join("`%s`" % c for c in ex[:50]) + (" …" if len(ex) > 50 else ""), ""]
    if perf:
        lines += [
            "## 2. Performance pipeline",
            "",
            f"- split : {perf['split_s']} s",
            f"- run_detectors : {perf['detectors_s']} s",
            f"- dedup : {perf['dedup_s']} s",
            f"- total : {perf['total_s']} s",
            f"- RSS : {perf['rss_start_mb']} → {perf['rss_after_mb']} MiB",
            "",
        ]
        for k, v in perf["frame_rows"].items():
            lines.append(f"- **{k}** : {v:,}")
        lines += ["", f"Brutes : {perf['detections_raw']}, après dedup : {perf['detections_after_dedup']}", "", "## 3. Détections", "", "```json", json.dumps(perf["detections"], indent=2, ensure_ascii=False), "```", ""]
    lines += [
        "## 4. Analyse",
        "",
        "- Source **OpenSearch uniquement** (pas Parquet).",
        "- Avec tri chronologique asc, les `max_docs` premiers documents couvrent **le début** de la plage : pour une fenêtre d’un mois, utiliser `--ds1-windows` ou réduire `--gte`/`--lte`.",
        "- Sans Claude : timelines et indicateurs restent heuristiques.",
        "",
        "## 5. Configuration et commande",
        "",
        "```bash",
        "cp .env.example .env   # puis renseigner OPENSEARCH_BASIC_PASSWORD",
        "# Budget ~1M recommandé pour couvrir les 5 fenêtres DS1 sans tronquer la fenêtre SQLi.",
        ".venv/bin/python scripts/benchmark_opensearch_report.py \\",
        "  --gte 2026-01-01T00:00:00Z --lte 2026-02-01T00:00:00Z --max-docs 1000000 --ds1-windows",
        "```",
        "",
    ]
    return "\n".join(lines)


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


def load_ds1_windows(gt_path: Path) -> list[tuple[str, str, str]]:
    """Retourne [(challenge_id, attack_start, attack_end), ...] depuis ground-truth-ds1.json."""
    text = gt_path.read_text(encoding="utf-8")
    dec = json.JSONDecoder()
    idx = 0
    n = len(text)
    out: list[tuple[str, str, str]] = []
    while idx < n:
        while idx < n and text[idx].isspace():
            idx += 1
        if idx >= n:
            break
        obj, end = dec.raw_decode(text, idx)
        idx = end
        src = obj.get("_source", obj)
        cid = str(src.get("challenge_id", "?"))
        aw = src.get("attack_window") or {}
        out.append((cid, str(aw["start"]), str(aw["end"])))
    return out


def fetch_ds1_windows(
    oc: OpenSearchConnector,
    windows: list[tuple[str, str, str]],
    max_docs: int,
    pad_hours: float,
) -> tuple[pd.DataFrame, list[tuple[str, str, str]]]:
    """Une requête par fenêtre (paddée), budget ~max_docs réparti à parts égales."""
    if not windows:
        return pd.DataFrame(), []
    per = max(1, max_docs // len(windows))
    padded_meta: list[tuple[str, str, str]] = []
    dfs: list[pd.DataFrame] = []
    for cid, gte, lte in windows:
        a = _parse_iso_utc(gte) - timedelta(hours=pad_hours)
        b = _parse_iso_utc(lte) + timedelta(hours=pad_hours)
        wg, wl = _fmt_iso_utc(a), _fmt_iso_utc(b)
        padded_meta.append((cid, wg, wl))
        t0 = time.perf_counter()
        chunk = oc.fetch_time_range(wg, wl, max_docs=per)
        print(
            f"[OpenSearch] DS1 `{cid}` : {len(chunk)} lignes en {time.perf_counter() - t0:.2f} s "
            f"({wg} .. {wl}, max_docs={per})"
        )
        if not chunk.empty:
            dfs.append(chunk)
    if not dfs:
        return pd.DataFrame(), padded_meta
    out = pd.concat(dfs, ignore_index=True)
    # Fenêtres DS1 sont disjointes ; au pire chevauchement de padding négligeable
    if "_id" in out.columns:
        out = out.drop_duplicates(subset=["_id"], ignore_index=True)
    return out, padded_meta


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gte", default="2026-01-01T00:00:00Z")
    ap.add_argument("--lte", default=None)
    ap.add_argument("--max-docs", type=int, default=500_000)
    ap.add_argument(
        "--ds1-windows",
        action="store_true",
        help="Répartir max_docs sur les 5 fenêtres ground-truth DS1 (recommandé si la plage est un mois entier).",
    )
    ap.add_argument(
        "--gt-path",
        type=Path,
        default=ROOT / "Dataset_log" / "ground-truth-ds1.json",
        help="Fichier ground-truth DS1 (JSON concaténé).",
    )
    ap.add_argument(
        "--pad-hours",
        type=float,
        default=1.0,
        help="Marge horaire autour de chaque fenêtre DS1 (défaut : 1 h).",
    )
    ap.add_argument("--skip-count", action="store_true")
    ap.add_argument(
        "--out",
        type=Path,
        default=ROOT / "benchmark_opensearch_report.md",
    )
    args = ap.parse_args()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    oc = OpenSearchConnector()
    err = None
    df = pd.DataFrame()
    cnt = None
    fetch_mode = "ds1_windows" if args.ds1_windows else "range_head"
    ds1_meta: list[tuple[str, str, str]] | None = None
    try:
        if not args.skip_count:
            try:
                t0 = time.perf_counter()
                cnt = oc.count_time_range(args.gte, args.lte)
                print("count", cnt, "in", round(time.perf_counter() - t0, 2), "s")
            except Exception:
                print("[_count] failed:", traceback.format_exc()[-400:])
        t0 = time.perf_counter()
        if args.ds1_windows:
            if not args.gt_path.is_file():
                raise FileNotFoundError(f"Ground truth introuvable : {args.gt_path}")
            wins = load_ds1_windows(args.gt_path)
            df, ds1_meta = fetch_ds1_windows(
                oc, wins, max_docs=args.max_docs, pad_hours=args.pad_hours
            )
            print("fetch rows (DS1 agrégé)", len(df), "in", round(time.perf_counter() - t0, 2), "s")
        else:
            df = oc.fetch_time_range(args.gte, args.lte, max_docs=args.max_docs)
            print("fetch rows", len(df), "in", round(time.perf_counter() - t0, 2), "s")
    except Exception:
        err = traceback.format_exc()
    an = analyze_frame(df)
    perf = None
    if err is None and not df.empty:
        perf = run_pipeline_on_df(df)
    md = render_md(
        now=now,
        host=config.OPENSEARCH_HOST,
        index=config.OPENSEARCH_INDEX,
        ts_field=config.OPENSEARCH_TIMESTAMP_FIELD,
        gte=args.gte,
        lte=args.lte,
        max_docs=args.max_docs,
        count_index=cnt,
        fetch_error=err,
        analysis=an,
        perf=perf,
        bedrock_enabled=config.BEDROCK_ENABLED,
        fetch_mode=fetch_mode,
        ds1_windows=ds1_meta,
    )
    args.out.write_text(md, encoding="utf-8")
    print("wrote", args.out)
    return 0 if err is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
