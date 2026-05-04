"""
Enrichissement des detections via Amazon Bedrock (Claude Opus, profils EU prioritaires).

- Meme liste de modelId pour enrichissement generique et refine timeline (fallback chain).
- Option BEDROCK_FUSED_CONVERSE : un seul appel Converse quand le contexte timeline est disponible.
"""

from __future__ import annotations

import json
import random
import time

import boto3
import numpy as np
import pandas as pd
from botocore.exceptions import ClientError

from config import (
    BEDROCK_DROP_LOW_ENRICHMENT_CONFIDENCE,
    BEDROCK_ENABLED,
    BEDROCK_CONVERSE_MODEL_CANDIDATES,
    BEDROCK_REGION,
    BEDROCK_MAX_TOKENS,
    BEDROCK_SAMPLE_LOGS,
    BEDROCK_REFINE_TIMELINE,
    BEDROCK_FUSED_CONVERSE,
    BEDROCK_FUSED_MAX_TOKENS,
    BEDROCK_MIN_REQUEST_INTERVAL_S,
    BEDROCK_THROTTLE_MAX_RETRIES,
    BEDROCK_TIMELINE_MAX_SHIFT_MINUTES,
    BEDROCK_TIMELINE_LOOKAHEAD_MINUTES,
    BEDROCK_TIMELINE_SAMPLE_LOGS,
    BEDROCK_TIMELINE_MIN_CONFIDENCE,
    BEDROCK_TIMELINE_MAX_TOKENS,
    BEDROCK_TIMELINE_RELEVANT_EPSILON_SECONDS,
)

_client = None
_last_bedrock_end = 0.0
_bedrock_metrics = {"calls": 0, "seconds": 0.0}

# Challenges DS1 : attack_type soumis doit rester aligne sur challenge_id (scoring)
_DS1_CHALLENGE_IDS = frozenset({
    "credential_stuffing",
    "ssh_brute_force",
    "sql_injection",
    "directory_traversal",
    "ssrf",
})


def _get_client():
    global _client
    if _client is None:
        _client = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)
    return _client


def reset_bedrock_metrics() -> None:
    _bedrock_metrics["calls"] = 0
    _bedrock_metrics["seconds"] = 0.0


def get_bedrock_metrics() -> dict:
    return dict(_bedrock_metrics)


def _pace_before_bedrock() -> None:
    global _last_bedrock_end
    gap = time.monotonic() - _last_bedrock_end
    need = BEDROCK_MIN_REQUEST_INTERVAL_S - gap
    if need > 0:
        time.sleep(need)


def _mark_bedrock_end() -> None:
    global _last_bedrock_end
    _last_bedrock_end = time.monotonic()


def _is_throttle(exc: Exception) -> bool:
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("ThrottlingException", "TooManyRequestsException"):
            return True
        if exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 429:
            return True
    return False


def _converse_with_retry(
    model_id: str,
    system_prompt: str,
    user_text: str,
    max_tokens: int,
) -> dict:
    client = _get_client()
    last_exc: Exception | None = None
    for attempt in range(BEDROCK_THROTTLE_MAX_RETRIES + 1):
        _pace_before_bedrock()
        t0 = time.perf_counter()
        try:
            resp = client.converse(
                modelId=model_id,
                system=[{"text": system_prompt}],
                messages=[{"role": "user", "content": [{"text": user_text}]}],
                inferenceConfig={"maxTokens": max_tokens, "temperature": 0},
            )
            _bedrock_metrics["calls"] += 1
            _bedrock_metrics["seconds"] += time.perf_counter() - t0
            _mark_bedrock_end()
            return resp
        except ClientError as e:
            last_exc = e
            _mark_bedrock_end()
            if _is_throttle(e) and attempt < BEDROCK_THROTTLE_MAX_RETRIES:
                time.sleep((2**attempt) * 0.5 + random.uniform(0, 0.25))
                continue
            raise
        except Exception:
            _mark_bedrock_end()
            raise
    raise last_exc  # type: ignore[misc]


def _try_converse_parse_json(
    candidates: tuple[str, ...],
    system_prompt: str,
    user_text: str,
    max_tokens: int,
    label: str,
) -> dict | None:
    seen: set[str] = set()
    first = candidates[0] if candidates else ""
    for model_id in candidates:
        if model_id in seen:
            continue
        seen.add(model_id)
        try:
            response = _converse_with_retry(
                model_id, system_prompt, user_text, max_tokens
            )
            text = _strip_json_fence(
                response["output"]["message"]["content"][0]["text"].strip()
            )
            out = json.loads(text)
            if model_id != first:
                print(f"[Bedrock:{label}] OK avec modele fallback: {model_id}")
            return out
        except json.JSONDecodeError as e:
            print(f"[Bedrock:{label}] JSON parse ({model_id}): {e}")
        except Exception as e:
            print(f"[Bedrock:{label}] Error ({model_id}): {e}")
    return None


def _df_to_records(subset: pd.DataFrame) -> list[dict]:
    records = []
    for _, row in subset.iterrows():
        record = {}
        for col, val in row.items():
            if pd.isna(val):
                continue
            if hasattr(val, "isoformat"):
                record[col] = val.isoformat()
            else:
                record[col] = val
        records.append(record)
    return records


def _sample_logs(detection: dict, full_df: pd.DataFrame) -> list[dict]:
    """Echantillon pour l'appel enrichissement générique (petit)."""
    if full_df.empty:
        return []

    attacker_ips = detection["detection"].get("attacker_ips", [])
    start_ts = pd.Timestamp(detection["detection"]["attack_start_time"], tz="UTC")
    end_ts = pd.Timestamp(detection["detection"]["attack_end_time"], tz="UTC")
    extra = pd.Timedelta(minutes=BEDROCK_TIMELINE_MAX_SHIFT_MINUTES)

    mask = (
        full_df["source_ip"].isin(attacker_ips)
        & (full_df["timestamp"] >= start_ts)
        & (full_df["timestamp"] <= end_ts + extra)
    )
    subset = full_df.loc[mask].sort_values("timestamp")
    if len(subset) > BEDROCK_SAMPLE_LOGS:
        head_n = BEDROCK_SAMPLE_LOGS // 2
        tail_n = BEDROCK_SAMPLE_LOGS - head_n
        subset = pd.concat([subset.head(head_n), subset.tail(tail_n)], ignore_index=True)

    return _df_to_records(subset)


def _timeline_event_slice(detection: dict, full_df: pd.DataFrame) -> pd.DataFrame:
    """Fenetre elargie pour Opus : [attack_start, heuristic_end + LOOKAHEAD]."""
    if full_df.empty or "timestamp" not in full_df.columns:
        return pd.DataFrame()

    attacker_ips = detection["detection"].get("attacker_ips", [])
    start_ts = pd.Timestamp(detection["detection"]["attack_start_time"], tz="UTC")
    end_ts = pd.Timestamp(detection["detection"]["attack_end_time"], tz="UTC")
    lookahead = pd.Timedelta(minutes=BEDROCK_TIMELINE_LOOKAHEAD_MINUTES)
    window_end = end_ts + lookahead

    ts = full_df["timestamp"]
    mask = full_df["source_ip"].isin(attacker_ips) & (ts >= start_ts) & (ts <= window_end)

    cid = detection.get("challenge_id", "")
    if cid == "ssh_brute_force":
        lateral = detection["detection"].get("indicators", {}).get("lateral_targets")
        if lateral and "hostname" in full_df.columns:
            mask = mask | (
                full_df["hostname"].isin(lateral)
                & (ts >= start_ts)
                & (ts <= window_end)
            )

    out = full_df.loc[mask].sort_values("timestamp")
    return out


def _relevance_mask(df_slice: pd.DataFrame, detection: dict) -> pd.Series:
    """Lignes jugees pertinentes pour dater la fin d'incident (par challenge DS1)."""
    cid = detection.get("challenge_id", "")
    idx = df_slice.index
    s = pd.Series(False, index=idx)

    if cid == "credential_stuffing":
        if "status_code" in df_slice.columns:
            s |= df_slice["status_code"].eq(401)
        if "auth_method" in df_slice.columns and "status" in df_slice.columns:
            s |= (
                df_slice["auth_method"].astype(str).ne("ssh")
                & df_slice["status"].astype(str).eq("failure")
            )
        if "destination_port" in df_slice.columns:
            s |= df_slice["destination_port"].eq(4444)
        if "uri" in df_slice.columns:
            s |= df_slice["uri"].astype(str).str.contains(
                r"uploads[/\\][^?\s#]*\.php", case=False, na=False, regex=True
            )

    elif cid == "ssh_brute_force":
        if "auth_method" in df_slice.columns and "status" in df_slice.columns:
            s |= (
                df_slice["auth_method"].astype(str).eq("ssh")
                & df_slice["status"].astype(str).eq("failure")
            )
        if "message" in df_slice.columns:
            s |= df_slice["message"].astype(str).str.contains(
                r"sudo|useradd|adduser|backdoor|scp|rsync",
                na=False,
                case=False,
                regex=True,
            )
        if "destination_port" in df_slice.columns:
            s |= df_slice["destination_port"].isin([443, 8443])

    elif cid == "sql_injection":
        if "uri" in df_slice.columns:
            s |= df_slice["uri"].astype(str).str.contains(
                r"UNION|SELECT|INSERT|DELETE|;--|information_schema|WAITFOR|SLEEP",
                case=False,
                na=False,
                regex=True,
            )

    elif cid == "directory_traversal":
        if "uri" in df_slice.columns:
            s |= df_slice["uri"].astype(str).str.contains(
                r"\.\./|%2e%2e", case=False, na=False, regex=True
            )

    elif cid == "ssrf":
        if "uri" in df_slice.columns:
            s |= df_slice["uri"].astype(str).str.contains(
                r"169\.254\.169\.254|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                r"192\.168\.\d{1,3}\.\d{1,3}|"
                r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
                case=False,
                na=False,
                regex=True,
            )

    return s


def _combined_last_malicious_ts(
    df_slice: pd.DataFrame, detection: dict, start_ts_floor: pd.Timestamp | None
) -> pd.Timestamp | None:
    """
    Dernier instant : signaux stricts, queue HTTP (uri+status_code), derniere activite IP attaquante,
    et pour SSH post-explo sur hotes lateraux uniquement apres start_ts_floor.
    """
    if df_slice.empty:
        return None
    ts_col = df_slice["timestamp"]
    cid = detection.get("challenge_id", "")
    ips = detection["detection"].get("attacker_ips", [])
    candidates: list[pd.Timestamp] = []

    rel = _relevance_mask(df_slice, detection)
    if rel.any():
        candidates.append(ts_col.loc[rel].max())

    if cid in (
        "credential_stuffing",
        "sql_injection",
        "directory_traversal",
        "ssrf",
    ):
        if "uri" in df_slice.columns and "status_code" in df_slice.columns:
            broad = df_slice["uri"].notna() & df_slice["status_code"].notna()
            if broad.any():
                candidates.append(ts_col.loc[broad].max())

    if "source_ip" in df_slice.columns and ips:
        att = df_slice[df_slice["source_ip"].isin(ips)]
        if not att.empty:
            candidates.append(att["timestamp"].max())

    if cid == "ssh_brute_force" and start_ts_floor is not None:
        lateral = detection["detection"].get("indicators", {}).get("lateral_targets")
        if lateral and "hostname" in df_slice.columns:
            lat = df_slice[
                df_slice["hostname"].isin(lateral)
                & (df_slice["timestamp"] >= start_ts_floor)
            ]
            if "message" in lat.columns:
                lat = lat[
                    lat["message"]
                    .astype(str)
                    .str.contains(
                        r"sudo|useradd|adduser|backdoor|scp|rsync",
                        na=False,
                        case=False,
                        regex=True,
                    )
                ]
            if not lat.empty:
                candidates.append(lat["timestamp"].max())

    if not candidates:
        return None
    t = max(candidates)
    if pd.isna(t):
        return None
    out = pd.Timestamp(t)
    if out.tzinfo is None:
        out = out.tz_localize("UTC")
    else:
        out = out.tz_convert("UTC")
    return out


def _last_relevant_timestamp(df_slice: pd.DataFrame, detection: dict) -> pd.Timestamp | None:
    """Dernier horodatage d'activite malveillante plausible dans la tranche."""
    if df_slice.empty:
        return None
    ts_col = df_slice["timestamp"]
    rel = _relevance_mask(df_slice, detection)
    if rel.any():
        ts_max = ts_col.loc[rel].max()
    else:
        ts_max = ts_col.max()
    if pd.isna(ts_max):
        return None
    out = pd.Timestamp(ts_max)
    if out.tzinfo is None:
        out = out.tz_localize("UTC")
    else:
        out = out.tz_convert("UTC")
    return out


def _stratified_sample_df(df_sorted: pd.DataFrame, k: int) -> pd.DataFrame:
    """Sous-echantillon : tete, queue, et points reguliers au milieu."""
    n = len(df_sorted)
    if n <= k:
        return df_sorted

    head_n = max(1, k // 4)
    tail_n = max(1, k // 4)
    mid_k = k - head_n - tail_n

    parts = [df_sorted.iloc[:head_n].copy(), df_sorted.iloc[-tail_n:].copy()]
    middle = df_sorted.iloc[head_n : n - tail_n]
    if mid_k > 0 and not middle.empty:
        take = min(mid_k, len(middle))
        pos = np.unique(
            np.linspace(0, len(middle) - 1, num=take, dtype=int)
        )
        parts.append(middle.iloc[pos].copy())

    out = pd.concat(parts, ignore_index=True)
    out = out.drop_duplicates().sort_values("timestamp")
    if len(out) > k:
        out = out.iloc[:k]
    return out


def _sample_logs_for_timeline(detection: dict, full_df: pd.DataFrame) -> list[dict]:
    """Echantillon stratifie dedie au refine timeline Opus."""
    sl = _timeline_event_slice(detection, full_df)
    if sl.empty:
        return []
    sampled = _stratified_sample_df(sl, BEDROCK_TIMELINE_SAMPLE_LOGS)
    return _df_to_records(sampled)


_SYSTEM_PROMPT = """Tu es un expert en cybersecurite SOC. Analyse la detection fournie et enrichis-la.
Reponds UNIQUEMENT avec un JSON valide, sans markdown, sans explication."""

_TIMELINE_SYSTEM_PROMPT = """Tu es un expert SOC specialise dans la datation precise des incidents cyber.
Ton unique role est d'estimer refined_attack_end_time (fin de l'attaque observable).
Reponds UNIQUEMENT avec un JSON valide, sans markdown, sans explication."""

_DS1_IOC_KEY_GUIDE = """Cles indicators officielles DS1 (noms exacts a privilegier si challenge_id correspond) :
- credential_stuffing : failed_logins, web_shell, reverse_shell_port, geolocation
- ssh_brute_force : failed_ssh, lateral_targets, priv_esc, exfil_port
- sql_injection : sqli_payloads, exfil_bytes, tool_signature
- directory_traversal : traversal_patterns, successful_reads, sensitive_files
- ssrf : ssrf_targets, internal_traffic_from_web
Renomme les compteurs ou mesures existantes vers ces cles (ex. total_ssh_failures -> failed_ssh)."""

_USER_TEMPLATE = """Detection heuristique :
{detection}

Echantillon de logs bruts ({n} logs) :
{logs}

""" + _DS1_IOC_KEY_GUIDE + """

Retourne ce JSON enrichi :
{{
  "attack_type": "type precis (ex: ssh_brute_force, web_credential_stuffing, port_scan_tcp_syn, ...)",
  "confidence": "high | medium | low",
  "indicators": {{
    // Garde tous les indicateurs existants et ajoute les pertinents
    "technique_mitre": "T1110.001",
    "severity": "critical | high | medium | low",
    "remediation": ["action 1", "action 2"]
  }}
}}"""

_TIMELINE_USER_TEMPLATE = """Detection heuristique :
{detection}

Echantillon de logs (contexte temporal stratifie, {n} lignes), ordre chronologique :
{logs}

Consignes strictes :
- Estime refined_attack_end_time : dernier instant ou l'activite malveillante liee a cette detection
  est encore clairement visible dans les logs ci-dessus.
- Si la queue d'activite s'estompe sans evenement net de fin, choisis le dernier evenement
  malveillant non ambigu ; en cas d'incertitude residuelle, reste proche de ce dernier evenement.
- Format EXACT : ISO 8601 UTC avec suffixe Z, secondes entieres : YYYY-MM-DDTHH:MM:SSZ
- refined_attack_end_time >= attack_start_time du JSON de detection.
- Ne depasse pas l'horodatage du dernier log fourni dans l'echantillon.

Retourne exactement ce JSON :
{{
  "refined_attack_end_time": "2026-01-06T06:00:00Z",
  "confidence": "high | medium | low",
  "rationale": "phrase courte"
}}"""

_FUSED_SYSTEM_PROMPT = """Tu es un expert SOC. Enrichis la detection et estime refined_attack_end_time (fin observable dans les logs).
Reponds UNIQUEMENT avec un JSON valide, sans markdown, sans explication."""

_FUSED_USER_TEMPLATE = """Detection heuristique :
{detection}

Echantillon pour enrichissement ({n_small} logs) :
{logs_small}

Echantillon stratifie pour la timeline ({n_tl} logs), ordre chronologique :
{logs_tl}

""" + _DS1_IOC_KEY_GUIDE + """

Retourne exactement ce JSON :
{{
  "attack_type": "type precis (ex: ssh_brute_force, sql_injection, ...)",
  "confidence": "high | medium | low",
  "indicators": {{ }},
  "refined_attack_end_time": "2026-01-06T06:00:00Z",
  "timeline_confidence": "high | medium | low",
  "rationale": "phrase courte"
}}

Contraintes refined_attack_end_time : ISO 8601 UTC suffixe Z, secondes entieres ; >= attack_start_time de la detection ;
<= dernier log de l echantillon timeline ; dernier instant ou l activite malveillante liee a cette detection est encore clairement visible."""


def _strip_json_fence(text: str) -> str:
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    return text.strip()


def _parse_utc_z(ts_value) -> pd.Timestamp | None:
    if not isinstance(ts_value, str) or not ts_value.endswith("Z"):
        return None
    try:
        ts = pd.Timestamp(ts_value)
    except Exception:
        return None
    if ts.tzinfo is None:
        ts = ts.tz_localize("UTC")
    else:
        ts = ts.tz_convert("UTC")
    return ts


def _to_utc_z(ts: pd.Timestamp) -> str:
    if ts.tzinfo is None:
        ts = ts.tz_localize("UTC")
    return ts.tz_convert("UTC").strftime("%Y-%m-%dT%H:%M:%SZ")


def _confidence_rank(level: str) -> int:
    order = {"low": 1, "medium": 2, "high": 3}
    return order.get(str(level).lower(), 0)


def _is_confidence_allowed(level: str) -> bool:
    return _confidence_rank(level) >= _confidence_rank(BEDROCK_TIMELINE_MIN_CONFIDENCE)


def _safe_clamp_end_time(
    start_ts: pd.Timestamp,
    current_end_ts: pd.Timestamp,
    candidate_end_ts: pd.Timestamp,
    max_shift_minutes: int,
    last_relevant_ts: pd.Timestamp | None,
    epsilon_seconds: int,
    timeline_window_end_ts: pd.Timestamp | None,
) -> pd.Timestamp:
    """
    Borne inferieure: start_ts.
    Borne superieure: min(heuristic_end + max_shift, last_relevant + epsilon,
    dernier timestamp dans la fenetre parquet timeline).
    """
    hard_upper = current_end_ts + pd.Timedelta(minutes=max_shift_minutes)
    if last_relevant_ts is not None:
        hard_upper = min(
            hard_upper,
            last_relevant_ts + pd.Timedelta(seconds=epsilon_seconds),
        )
    if timeline_window_end_ts is not None:
        hard_upper = min(hard_upper, timeline_window_end_ts)
    if hard_upper < start_ts:
        hard_upper = start_ts
    return min(max(candidate_end_ts, start_ts), hard_upper)


def _data_driven_attack_end(
    detection: dict,
    timeline_slice_df: pd.DataFrame,
    heuristic_end_ts: pd.Timestamp,
    start_ts: pd.Timestamp,
) -> pd.Timestamp | None:
    """Fin d'attaque derivee des logs (sans LLM), pour combler les echecs Opus ou grandes derives."""
    t_mal = _combined_last_malicious_ts(timeline_slice_df, detection, start_ts)
    if t_mal is None or heuristic_end_ts is None or start_ts is None:
        return None
    cand = t_mal + pd.Timedelta(seconds=BEDROCK_TIMELINE_RELEVANT_EPSILON_SECONDS)
    hi = heuristic_end_ts + pd.Timedelta(minutes=BEDROCK_TIMELINE_MAX_SHIFT_MINUTES)
    cand = min(cand, hi)
    cand = max(cand, start_ts)
    return cand


def _merge_opus_and_data_end(
    opus_ts: pd.Timestamp | None,
    data_ts: pd.Timestamp | None,
    heuristic_ts: pd.Timestamp | None,
    tolerance_s: int = 300,
) -> pd.Timestamp | None:
    """Opus proche des logs -> Opus ; sinon logs. Sans Opus, ne pas avancer la fin de >10 min sans preuve."""
    if opus_ts is None and data_ts is None:
        return None
    if opus_ts is None:
        out = data_ts
    elif data_ts is None:
        out = opus_ts
    elif abs((opus_ts - data_ts).total_seconds()) <= tolerance_s:
        out = opus_ts
    else:
        out = data_ts

    if out is not None and heuristic_ts is not None and opus_ts is None:
        if out < heuristic_ts - pd.Timedelta(minutes=10):
            out = heuristic_ts
    return out


def _fused_response_usable(raw: dict) -> bool:
    if not isinstance(raw, dict):
        return False
    if raw.get("confidence") not in ("high", "medium"):
        return False
    if not _is_confidence_allowed(str(raw.get("timeline_confidence", ""))):
        return False
    te = raw.get("refined_attack_end_time")
    return isinstance(te, str) and te.endswith("Z")


def _call_bedrock_fused(
    detection: dict, sample_small: list[dict], timeline_logs: list[dict]
) -> dict | None:
    prompt = _FUSED_USER_TEMPLATE.format(
        detection=json.dumps(detection, indent=2, ensure_ascii=False),
        logs_small=json.dumps(sample_small, indent=2, ensure_ascii=False),
        n_small=len(sample_small),
        logs_tl=json.dumps(timeline_logs, indent=2, ensure_ascii=False),
        n_tl=len(timeline_logs),
    )
    return _try_converse_parse_json(
        BEDROCK_CONVERSE_MODEL_CANDIDATES,
        _FUSED_SYSTEM_PROMPT,
        prompt,
        BEDROCK_FUSED_MAX_TOKENS,
        "fused",
    )


def _call_bedrock(detection: dict, sample_logs: list[dict]) -> dict | None:
    prompt = _USER_TEMPLATE.format(
        detection=json.dumps(detection, indent=2, ensure_ascii=False),
        logs=json.dumps(sample_logs, indent=2, ensure_ascii=False),
        n=len(sample_logs),
    )
    return _try_converse_parse_json(
        BEDROCK_CONVERSE_MODEL_CANDIDATES,
        _SYSTEM_PROMPT,
        prompt,
        BEDROCK_MAX_TOKENS,
        "enrich",
    )


def _call_bedrock_timeline_refiner(detection: dict, sample_logs: list[dict]) -> dict | None:
    if not sample_logs:
        return None
    prompt = _TIMELINE_USER_TEMPLATE.format(
        detection=json.dumps(detection, indent=2, ensure_ascii=False),
        logs=json.dumps(sample_logs, indent=2, ensure_ascii=False),
        n=len(sample_logs),
    )
    return _try_converse_parse_json(
        BEDROCK_CONVERSE_MODEL_CANDIDATES,
        _TIMELINE_SYSTEM_PROMPT,
        prompt,
        BEDROCK_TIMELINE_MAX_TOKENS,
        "timeline",
    )


def _timeline_window_end_ts(df_slice: pd.DataFrame) -> pd.Timestamp | None:
    if df_slice.empty or "timestamp" not in df_slice.columns:
        return None
    t = pd.Timestamp(df_slice["timestamp"].max())
    if pd.isna(t):
        return None
    if t.tzinfo is None:
        t = t.tz_localize("UTC")
    else:
        t = t.tz_convert("UTC")
    return t


def enrich_detection(detection: dict, full_df: pd.DataFrame) -> dict:
    if not BEDROCK_ENABLED:
        return detection

    heuristic_end_ts = _parse_utc_z(detection["detection"]["attack_end_time"])
    start_ts_orig = _parse_utc_z(detection["detection"]["attack_start_time"])

    sample = _sample_logs(detection, full_df)
    timeline_slice_df = _timeline_event_slice(detection, full_df)
    last_rel = _last_relevant_timestamp(timeline_slice_df, detection)
    window_end_ts = _timeline_window_end_ts(timeline_slice_df)
    timeline_sample = _sample_logs_for_timeline(detection, full_df)

    fused_raw = None
    if (
        BEDROCK_FUSED_CONVERSE
        and BEDROCK_REFINE_TIMELINE
        and timeline_sample
    ):
        fused_raw = _call_bedrock_fused(detection, sample, timeline_sample)

    if fused_raw and _fused_response_usable(fused_raw):
        result = {
            "attack_type": fused_raw.get("attack_type"),
            "confidence": fused_raw["confidence"],
            "indicators": fused_raw.get("indicators") or {},
        }
    else:
        result = _call_bedrock(detection, sample)

    enriched = dict(detection)
    enriched["detection"] = dict(detection["detection"])

    if result is not None and result.get("confidence") in ("high", "medium"):
        enriched["detection"]["attack_type"] = result.get(
            "attack_type", detection["detection"]["attack_type"]
        )
        merged_indicators = dict(detection["detection"]["indicators"])
        merged_indicators.update(result.get("indicators", {}))
        enriched["detection"]["indicators"] = merged_indicators
    else:
        enriched["detection"]["indicators"] = dict(detection["detection"]["indicators"])

    if enriched.get("challenge_id") in _DS1_CHALLENGE_IDS:
        enriched["detection"]["attack_type"] = str(enriched["challenge_id"])

    data_end_ts = None
    if (
        heuristic_end_ts is not None
        and start_ts_orig is not None
        and not timeline_slice_df.empty
    ):
        data_end_ts = _data_driven_attack_end(
            detection, timeline_slice_df, heuristic_end_ts, start_ts_orig
        )

    opus_end_ts: pd.Timestamp | None = None
    if BEDROCK_REFINE_TIMELINE:
        if fused_raw and _fused_response_usable(fused_raw):
            timeline = {
                "refined_attack_end_time": fused_raw["refined_attack_end_time"],
                "confidence": fused_raw["timeline_confidence"],
                "rationale": fused_raw.get("rationale", ""),
            }
        else:
            timeline = _call_bedrock_timeline_refiner(enriched, timeline_sample)
        if timeline is not None and _is_confidence_allowed(timeline.get("confidence", "")):
            start_ts = _parse_utc_z(enriched["detection"]["attack_start_time"])
            current_end_ts = _parse_utc_z(enriched["detection"]["attack_end_time"])
            candidate_end_ts = _parse_utc_z(timeline.get("refined_attack_end_time"))
            if start_ts is not None and current_end_ts is not None and candidate_end_ts is not None:
                safe_end = _safe_clamp_end_time(
                    start_ts=start_ts,
                    current_end_ts=current_end_ts,
                    candidate_end_ts=candidate_end_ts,
                    max_shift_minutes=BEDROCK_TIMELINE_MAX_SHIFT_MINUTES,
                    last_relevant_ts=last_rel,
                    epsilon_seconds=BEDROCK_TIMELINE_RELEVANT_EPSILON_SECONDS,
                    timeline_window_end_ts=window_end_ts,
                )
                opus_end_ts = safe_end
                print(
                    "[Bedrock:timeline] "
                    f"{detection['challenge_id']} -> {_to_utc_z(safe_end)} "
                    f"(confidence={timeline.get('confidence', '?')})"
                )

    merged_end = _merge_opus_and_data_end(
        opus_end_ts, data_end_ts, heuristic_end_ts, tolerance_s=300
    )
    if merged_end is not None:
        enriched["detection"]["attack_end_time"] = _to_utc_z(merged_end)
        if data_end_ts is not None and opus_end_ts is not None:
            if abs((opus_end_ts - data_end_ts).total_seconds()) > 300:
                print(
                    f"[Timeline] {detection['challenge_id']} merged -> "
                    f"{enriched['detection']['attack_end_time']} (data-driven, Opus drift)"
                )
        elif data_end_ts is not None and opus_end_ts is None:
            print(
                f"[Timeline] {detection['challenge_id']} -> "
                f"{enriched['detection']['attack_end_time']} (data-driven fallback)"
            )

    print(
        f"[Bedrock] {detection['detection']['attack_type']} -> "
        f"{enriched['detection']['attack_type']} "
        f"(confidence={result.get('confidence', '?') if result else '?'})"
    )

    if result is None:
        enrich_conf = "unavailable"
    else:
        c = str(result.get("confidence", "")).lower().strip()
        if c == "low":
            enrich_conf = "low"
        elif c in ("high", "medium"):
            enrich_conf = c
        else:
            enrich_conf = "unavailable"
    enriched["_bedrock_enrichment_confidence"] = enrich_conf

    return enriched


def enrich_detections(detections: list[dict], full_df: pd.DataFrame) -> list[dict]:
    if not BEDROCK_ENABLED or not detections:
        return detections

    print(f"\n[Bedrock] Enrichissement de {len(detections)} detection(s)...")
    reset_bedrock_metrics()
    results = [enrich_detection(d, full_df) for d in detections]
    m = get_bedrock_metrics()
    print(
        f"[Bedrock:metrics] converse_calls={m['calls']} "
        f"runtime_s={m['seconds']:.2f} "
        f"min_interval_s={BEDROCK_MIN_REQUEST_INTERVAL_S}"
    )

    kept: list[dict] = []
    for r in results:
        meta = r.pop("_bedrock_enrichment_confidence", "unavailable")
        if BEDROCK_DROP_LOW_ENRICHMENT_CONFIDENCE and meta == "low":
            print(
                "[Bedrock:filter] dropped "
                f"challenge_id={r.get('challenge_id')} "
                "(enrichment_confidence=low)"
            )
            continue
        kept.append(r)
    if len(kept) != len(results):
        print(
            f"[Bedrock:filter] {len(results)} -> {len(kept)} detection(s) "
            "apres filtre confidence=low"
        )
    return kept
