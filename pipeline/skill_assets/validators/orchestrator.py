"""
Pipeline d'orchestration des 3 modes du skill cnd-detection-tuner.

Architecture :
    detection brute (déterministe)
        → MODE RECOMMANDATION  (Bedrock claude-opus-4-6)
        → MODE CRITIQUE         (Bedrock claude-opus-4-6, prompt opposé)
        → submit ou fallback

Le mode TUNING tourne séparément (offline ou batch).

Dépendances : boto3, jsonschema
Usage : voir les fonctions main_*.

À adapter au projet : importer le validator depuis votre arborescence
(ici on suppose que les fichiers du skill sont copiés à côté).
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3

# Adapter ces imports selon où le skill est installé
from validators.validate_outputs import validate, safe_parse_llm_json


BEDROCK_REGION = "eu-west-3"
MODEL_ID = "anthropic.claude-opus-4-6-v1"

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"


# ---------------------------------------------------------------------------
# Bedrock client
# ---------------------------------------------------------------------------

def _get_client():
    return boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)


def _converse(system_prompt: str, user_message: str, max_tokens: int, temperature: float) -> str:
    """Appel synchrone Bedrock converse, retourne le texte brut."""
    client = _get_client()
    response = client.converse(
        modelId=MODEL_ID,
        system=[{"text": system_prompt}],
        messages=[{"role": "user", "content": [{"text": user_message}]}],
        inferenceConfig={"maxTokens": max_tokens, "temperature": temperature},
    )
    return response["output"]["message"]["content"][0]["text"]


def _load_prompt(name: str) -> str:
    with open(PROMPTS_DIR / f"{name}_system_prompt.txt", "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Mode TUNING
# ---------------------------------------------------------------------------

def run_tuning(
    current_thresholds: dict,
    signal_distributions: dict,
    recent_detections: list,
    scores_history_summary: dict,
) -> dict:
    """Exécute un cycle de tuning. Retourne un dict conforme à tuning_output.schema.json."""
    user_msg = json.dumps({
        "current_thresholds": current_thresholds,
        "signal_distributions": signal_distributions,
        "recent_detections": recent_detections,
        "scores_history_summary": scores_history_summary,
    }, ensure_ascii=False)

    raw = _converse(
        system_prompt=_load_prompt("tuning"),
        user_message=user_msg,
        max_tokens=4096,
        temperature=0.0,
    )
    output = safe_parse_llm_json(raw)
    validate(output, mode="tuning")
    return output


# ---------------------------------------------------------------------------
# Mode RECOMMANDATION
# ---------------------------------------------------------------------------

def run_recommendation(
    raw_detection: dict,
    log_excerpt: list[str],
    attack_start_time: str,
    now_iso: str | None = None,
) -> dict:
    """Enrichit une détection brute. Retourne un dict conforme à recommendation_output.schema.json."""
    if now_iso is None:
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    user_msg = json.dumps({
        "raw_detection": raw_detection,
        "log_excerpt": log_excerpt,
        "attack_start_time": attack_start_time,
        "now_iso": now_iso,
    }, ensure_ascii=False)

    raw = _converse(
        system_prompt=_load_prompt("recommendation"),
        user_message=user_msg,
        max_tokens=2048,
        temperature=0.2,
    )
    output = safe_parse_llm_json(raw)
    validate(output, mode="recommendation")
    return output


# ---------------------------------------------------------------------------
# Mode CRITIQUE
# ---------------------------------------------------------------------------

def run_critic(recommendation: dict, log_excerpt: list[str]) -> dict:
    """Audite une recommandation. Retourne un dict conforme à critic_output.schema.json."""
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
    output = safe_parse_llm_json(raw)
    validate(output, mode="critic")
    return output


# ---------------------------------------------------------------------------
# Application des patches CRITIQUE → submission
# ---------------------------------------------------------------------------

def apply_patches(recommendation: dict, patches: list[dict]) -> dict:
    """Applique les patches du critic à la recommandation. Modifie une copie."""
    import copy
    patched = copy.deepcopy(recommendation)

    for p in patches:
        path = p["path"]
        action = p["action"]
        target, last_key = _resolve_path(patched, path)

        if action == "remove":
            if isinstance(target, dict):
                target.pop(last_key, None)
            elif isinstance(target, list):
                idx = int(last_key)
                if 0 <= idx < len(target):
                    target.pop(idx)
        elif action == "replace" or action == "set":
            if isinstance(target, dict):
                target[last_key] = p.get("new_value")
            elif isinstance(target, list):
                idx = int(last_key)
                if 0 <= idx < len(target):
                    target[idx] = p.get("new_value")
                else:
                    target.append(p.get("new_value"))

    return patched


def _resolve_path(obj: Any, path: str) -> tuple[Any, Any]:
    """Résout 'submission.detection.attacker_ips[0]' → (parent, last_key).

    Implémentation simple ; remplacer par jsonpath-ng si besoin de robustesse.
    """
    parts = []
    for seg in path.split("."):
        # gérer indices [N]
        while "[" in seg:
            base, rest = seg.split("[", 1)
            if base:
                parts.append(base)
            idx_str, seg = rest.split("]", 1)
            parts.append(int(idx_str))
            seg = seg.lstrip(".")
        if seg:
            parts.append(seg)

    target = obj
    for p in parts[:-1]:
        if isinstance(p, int):
            target = target[p]
        else:
            target = target[p]
    return target, parts[-1]


# ---------------------------------------------------------------------------
# Pipeline complet : raw_detection → submission validée
# ---------------------------------------------------------------------------

def enrich_and_audit(
    raw_detection: dict,
    log_excerpt: list[str],
    attack_start_time: str,
    *,
    max_revisions: int = 1,
) -> dict:
    """Pipeline RECOMMANDATION → CRITIQUE avec retry une fois si needs_revision.

    Retourne un dict :
    {
        "submission": <payload jury>,
        "critic": <résultat audit>,
        "fallback_used": bool,
        "duration_ms": int
    }
    """
    t0 = time.time()
    fallback_used = False

    rec = run_recommendation(raw_detection, log_excerpt, attack_start_time)

    for _ in range(max_revisions + 1):
        crit = run_critic(rec, log_excerpt)

        if crit["status"] in ("approved", "approved_with_warnings"):
            return {
                "submission": rec["submission"],
                "critic": crit,
                "fallback_used": False,
                "duration_ms": int((time.time() - t0) * 1000),
            }

        if crit["status"] == "needs_revision" and crit.get("patches"):
            rec = apply_patches(rec, crit["patches"])
            try:
                validate(rec, mode="recommendation")
            except ValueError:
                # patch a cassé le schéma → fallback
                break
            continue

        # rejected
        break

    # Fallback : soumettre la détection brute sans enrichissement LLM
    fallback_used = True
    return {
        "submission": _raw_to_submission(raw_detection),
        "critic": crit,
        "fallback_used": True,
        "duration_ms": int((time.time() - t0) * 1000),
    }


def _raw_to_submission(raw: dict) -> dict:
    """Convertit une détection brute du détecteur déterministe en payload jury minimal.

    À adapter au format exact produit par les détecteurs Python.
    """
    return {
        "challenge_id": raw["challenge_id"],
        "detection": {
            "attack_type": raw["challenge_id"],
            "attacker_ips": raw.get("attacker_ips", []),
            "victim_accounts": raw.get("victim_accounts", []),
            "attack_start_time": raw.get("attack_start_time"),
            "attack_end_time": raw.get("attack_end_time"),
            "indicators": raw.get("indicators", {}),
        },
        "detection_time_seconds": raw.get("detection_time_seconds", 0),
    }


# ---------------------------------------------------------------------------
# Démo / sanity test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Démo (sans appel Bedrock) — vérifie juste que les modules s'importent.
    from validators.validate_outputs import validate as _v

    examples = Path(__file__).resolve().parent.parent / "examples"
    for f, mode in [
        (examples / "tuning_output_example.json", "tuning"),
        (examples / "recommendation_output_example.json", "recommendation"),
        (examples / "critic_output_example.json", "critic"),
    ]:
        if f.exists():
            with open(f) as fh:
                _v(json.load(fh), mode=mode)
            print(f"OK  {f.name}")
    print("Sanity test passé.")
