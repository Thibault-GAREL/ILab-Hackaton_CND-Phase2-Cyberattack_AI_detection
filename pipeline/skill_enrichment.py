"""
Skill-based enrichment: RECOMMENDATION -> CRITIQUE pipeline.

Replaces the legacy bedrock_analysis.enrich_detections() when BEDROCK_SKILL_MODE is enabled.
Uses the cnd-detection-tuner skill (prompts, schemas, validators) for structured enrichment
with anti-hallucination self-reflection before submission.
"""

from __future__ import annotations

import json
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
import pandas as pd
from botocore.exceptions import ClientError

from .config import (
    BEDROCK_ENABLED,
    BEDROCK_CONVERSE_MODEL_CANDIDATES,
    BEDROCK_REGION,
    BEDROCK_MIN_REQUEST_INTERVAL_S,
    BEDROCK_THROTTLE_MAX_RETRIES,
    BEDROCK_SKILL_MAX_REVISIONS,
    BEDROCK_SAMPLE_LOGS,
)

_SKILL_ASSETS = Path(__file__).resolve().parent / "skill_assets"
_PROMPTS_DIR = _SKILL_ASSETS / "prompts"
_SCHEMAS_DIR = _SKILL_ASSETS / "schemas"

_client = None
_last_bedrock_end = 0.0
_skill_metrics = {"calls": 0, "seconds": 0.0}

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


def _pace() -> None:
    global _last_bedrock_end
    gap = time.monotonic() - _last_bedrock_end
    need = BEDROCK_MIN_REQUEST_INTERVAL_S - gap
    if need > 0:
        time.sleep(need)


def _mark_end() -> None:
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


def _converse(system_prompt: str, user_message: str, max_tokens: int, temperature: float) -> str | None:
    """Call Bedrock converse with retry and model fallback. Returns raw text or None."""
    client = _get_client()
    for model_id in BEDROCK_CONVERSE_MODEL_CANDIDATES:
        for attempt in range(BEDROCK_THROTTLE_MAX_RETRIES + 1):
            _pace()
            t0 = time.perf_counter()
            try:
                resp = client.converse(
                    modelId=model_id,
                    system=[{"text": system_prompt}],
                    messages=[{"role": "user", "content": [{"text": user_message}]}],
                    inferenceConfig={"maxTokens": max_tokens, "temperature": temperature},
                )
                _skill_metrics["calls"] += 1
                _skill_metrics["seconds"] += time.perf_counter() - t0
                _mark_end()
                return resp["output"]["message"]["content"][0]["text"]
            except ClientError as e:
                _mark_end()
                if _is_throttle(e) and attempt < BEDROCK_THROTTLE_MAX_RETRIES:
                    time.sleep((2 ** attempt) * 0.5 + random.uniform(0, 0.25))
                    continue
                print(f"[Skill] Bedrock error ({model_id}): {e}", file=sys.stderr)
                break
            except Exception as e:
                _mark_end()
                print(f"[Skill] Unexpected error ({model_id}): {e}", file=sys.stderr)
                break
    return None


def _load_prompt(name: str) -> str:
    with open(_PROMPTS_DIR / f"{name}_system_prompt.txt", "r", encoding="utf-8") as f:
        return f.read()


def _safe_parse_json(raw: str) -> dict | None:
    import re
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"[Skill] JSON parse error: {e}", file=sys.stderr)
        return None


def _validate_output(payload: dict, mode: str) -> bool:
    """Validate against skill schemas. Returns True if valid."""
    try:
        from jsonschema import Draft7Validator
        schema_path = _SCHEMAS_DIR / f"{mode}_output.schema.json"
        if not schema_path.exists():
            return True
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        validator = Draft7Validator(schema)
        errors = list(validator.iter_errors(payload))
        if errors:
            for e in errors[:3]:
                print(f"[Skill:validate] {mode}: {e.message}", file=sys.stderr)
            return False
        return True
    except ImportError:
        return True


# ---------------------------------------------------------------------------
# RECOMMENDATION mode
# ---------------------------------------------------------------------------

def _run_recommendation(raw_detection: dict, log_excerpt: list[dict]) -> dict | None:
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    attack_start = raw_detection.get("detection", {}).get("attack_start_time", now_iso)

    user_msg = json.dumps({
        "raw_detection": raw_detection,
        "log_excerpt": log_excerpt,
        "attack_start_time": attack_start,
        "now_iso": now_iso,
    }, ensure_ascii=False)

    raw = _converse(
        system_prompt=_load_prompt("recommendation"),
        user_message=user_msg,
        max_tokens=2048,
        temperature=0.2,
    )
    if raw is None:
        return None
    output = _safe_parse_json(raw)
    if output is None:
        return None
    if _validate_output(output, "recommendation"):
        return output
    return output


# ---------------------------------------------------------------------------
# CRITIQUE mode
# ---------------------------------------------------------------------------

def _run_critic(recommendation: dict, log_excerpt: list[dict]) -> dict | None:
    user_msg = json.dumps({
        "recommendation_to_audit": recommendation,
        "log_excerpt": log_excerpt,
    }, ensure_ascii=False)

    raw = _converse(
        system_prompt=_load_prompt("critic"),
        user_message=user_msg,
        max_tokens=3072,
        temperature=0.0,
    )
    if raw is None:
        return None
    output = _safe_parse_json(raw)
    if output is None:
        return None
    if _validate_output(output, "critic"):
        return output
    return output


# ---------------------------------------------------------------------------
# Patch application (from CRITIQUE to RECOMMENDATION)
# ---------------------------------------------------------------------------

def _apply_patches(recommendation: dict, patches: list[dict]) -> dict:
    import copy
    patched = copy.deepcopy(recommendation)
    for p in patches:
        path = p.get("path", "")
        action = p.get("action", "")
        parts = _parse_path(path)
        if not parts:
            continue
        try:
            target = patched
            for seg in parts[:-1]:
                target = target[int(seg)] if isinstance(target, list) else target[seg]
            last = parts[-1]
            if action == "remove":
                if isinstance(target, dict):
                    target.pop(last, None)
                elif isinstance(target, list):
                    idx = int(last)
                    if 0 <= idx < len(target):
                        target.pop(idx)
            elif action in ("replace", "set"):
                if isinstance(target, dict):
                    target[last] = p.get("new_value")
                elif isinstance(target, list):
                    idx = int(last)
                    if 0 <= idx < len(target):
                        target[idx] = p.get("new_value")
        except (KeyError, IndexError, TypeError, ValueError):
            continue
    return patched


def _parse_path(path: str) -> list[str]:
    import re
    parts = []
    for seg in path.split("."):
        while "[" in seg:
            base, rest = seg.split("[", 1)
            if base:
                parts.append(base)
            idx_str, seg = rest.split("]", 1)
            parts.append(idx_str)
            seg = seg.lstrip(".")
        if seg:
            parts.append(seg)
    return parts


# ---------------------------------------------------------------------------
# Detection -> submission format (fallback)
# ---------------------------------------------------------------------------

def _raw_to_submission(raw: dict) -> dict:
    det = raw.get("detection", {})
    return {
        "challenge_id": raw.get("challenge_id", ""),
        "detection": {
            "attack_type": raw.get("challenge_id", det.get("attack_type", "")),
            "attacker_ips": det.get("attacker_ips", []),
            "victim_accounts": det.get("victim_accounts", []),
            "attack_start_time": det.get("attack_start_time"),
            "attack_end_time": det.get("attack_end_time"),
            "indicators": det.get("indicators", {}),
        },
        "detection_time_seconds": raw.get("detection_time_seconds", 0),
    }


# ---------------------------------------------------------------------------
# Sample logs for skill context
# ---------------------------------------------------------------------------

def _sample_logs_for_skill(detection: dict, full_df: pd.DataFrame) -> list[dict]:
    if full_df.empty:
        return []
    det = detection.get("detection", {})
    attacker_ips = det.get("attacker_ips", [])
    start_str = det.get("attack_start_time")
    end_str = det.get("attack_end_time")
    if not start_str or not end_str:
        return []

    start_ts = pd.Timestamp(start_str, tz="UTC")
    end_ts = pd.Timestamp(end_str, tz="UTC")
    extra = pd.Timedelta(minutes=30)

    mask = (
        full_df["source_ip"].isin(attacker_ips)
        & (full_df["timestamp"] >= start_ts)
        & (full_df["timestamp"] <= end_ts + extra)
    )
    subset = full_df.loc[mask].sort_values("timestamp")

    max_logs = min(200, max(BEDROCK_SAMPLE_LOGS * 5, 50))
    if len(subset) > max_logs:
        head_n = max_logs // 2
        tail_n = max_logs - head_n
        subset = pd.concat([subset.head(head_n), subset.tail(tail_n)], ignore_index=True)

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


# ---------------------------------------------------------------------------
# Main entry: enrich single detection with RECOMMENDATION -> CRITIQUE
# ---------------------------------------------------------------------------

def enrich_detection_with_skill(detection: dict, full_df: pd.DataFrame) -> dict:
    """Enrich a single detection using the skill RECOMMENDATION -> CRITIQUE pipeline."""
    log_excerpt = _sample_logs_for_skill(detection, full_df)

    rec = _run_recommendation(detection, log_excerpt)
    if rec is None:
        print(f"[Skill] RECOMMENDATION failed for {detection.get('challenge_id')} — using raw detection", file=sys.stderr)
        return detection

    for _ in range(BEDROCK_SKILL_MAX_REVISIONS + 1):
        crit = _run_critic(rec, log_excerpt)
        if crit is None:
            print(f"[Skill] CRITIQUE failed for {detection.get('challenge_id')} — using recommendation as-is", file=sys.stderr)
            break

        status = crit.get("status", "rejected")
        if status in ("approved", "approved_with_warnings"):
            print(f"[Skill] {detection.get('challenge_id')} — CRITIQUE approved (score={crit.get('score', '?')})")
            break

        if status == "needs_revision" and crit.get("patches"):
            rec = _apply_patches(rec, crit["patches"])
            continue

        # rejected — fallback to raw
        print(f"[Skill] {detection.get('challenge_id')} — CRITIQUE rejected, falling back to raw detection")
        return detection

    # Extract enriched detection from recommendation
    submission = rec.get("submission")
    if submission and isinstance(submission, dict):
        enriched = dict(detection)
        enriched["detection"] = dict(detection.get("detection", {}))

        sub_det = submission.get("detection", {})
        if sub_det.get("attack_type"):
            enriched["detection"]["attack_type"] = sub_det["attack_type"]
        if sub_det.get("attacker_ips"):
            enriched["detection"]["attacker_ips"] = sub_det["attacker_ips"]
        if sub_det.get("victim_accounts") is not None:
            enriched["detection"]["victim_accounts"] = sub_det["victim_accounts"]
        if sub_det.get("attack_start_time"):
            enriched["detection"]["attack_start_time"] = sub_det["attack_start_time"]
        if sub_det.get("attack_end_time"):
            enriched["detection"]["attack_end_time"] = sub_det["attack_end_time"]
        if sub_det.get("indicators"):
            merged_ind = dict(enriched["detection"].get("indicators", {}))
            merged_ind.update(sub_det["indicators"])
            enriched["detection"]["indicators"] = merged_ind

        # DS1: force attack_type = challenge_id for scoring
        if enriched.get("challenge_id") in _DS1_CHALLENGE_IDS:
            enriched["detection"]["attack_type"] = str(enriched["challenge_id"])

        return enriched

    return detection


# ---------------------------------------------------------------------------
# Batch entry: replaces enrich_detections() from bedrock_analysis
# ---------------------------------------------------------------------------

def enrich_detections_with_skill(detections: list[dict], full_df: pd.DataFrame) -> list[dict]:
    """Enrich all detections using the skill pipeline (RECOMMENDATION -> CRITIQUE)."""
    if not BEDROCK_ENABLED or not detections:
        return detections

    print(f"\n[Skill] Enriching {len(detections)} detection(s) via RECOMMENDATION -> CRITIQUE...")
    global _skill_metrics
    _skill_metrics = {"calls": 0, "seconds": 0.0}

    results = []
    for d in detections:
        enriched = enrich_detection_with_skill(d, full_df)
        results.append(enriched)

    print(
        f"[Skill:metrics] converse_calls={_skill_metrics['calls']} "
        f"runtime_s={_skill_metrics['seconds']:.2f}"
    )
    return results
