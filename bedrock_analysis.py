"""
Enrichissement des detections via Claude Opus 4.6 (Amazon Bedrock).

Pour chaque detection heuristique, envoie a Claude :
  - Le JSON de detection
  - Un echantillon des logs bruts impliques

Claude retourne :
  - attack_type affine (ex: "ssh_brute_force" plutot que "brute_force")
  - indicators enrichis
  - remediation proposee (stockee dans les indicators)
"""

import json
import boto3
import pandas as pd

from config import (
    BEDROCK_ENABLED,
    BEDROCK_MODEL_ID,
    BEDROCK_REGION,
    BEDROCK_MAX_TOKENS,
    BEDROCK_SAMPLE_LOGS,
)


_client = None


def _get_client():
    global _client
    if _client is None:
        _client = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)
    return _client


def _sample_logs(detection: dict, full_df: pd.DataFrame) -> list[dict]:
    """Extrait un echantillon de logs bruts lies a la detection."""
    if full_df.empty:
        return []

    attacker_ips = detection["detection"].get("attacker_ips", [])
    start_ts = pd.Timestamp(detection["detection"]["attack_start_time"], tz="UTC")
    end_ts   = pd.Timestamp(detection["detection"]["attack_end_time"],   tz="UTC")

    mask = (
        full_df["source_ip"].isin(attacker_ips)
        & (full_df["timestamp"] >= start_ts)
        & (full_df["timestamp"] <= end_ts)
    )
    subset = full_df[mask].head(BEDROCK_SAMPLE_LOGS)

    # Serialisation propre (timestamps -> str)
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


_SYSTEM_PROMPT = """Tu es un expert en cybersecurite SOC. Analyse la detection fournie et enrichis-la.
Reponds UNIQUEMENT avec un JSON valide, sans markdown, sans explication."""

_USER_TEMPLATE = """Detection heuristique :
{detection}

Echantillon de logs bruts ({n} logs) :
{logs}

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


def _call_bedrock(detection: dict, sample_logs: list[dict]) -> dict | None:
    """Appelle Claude via Bedrock et parse la reponse JSON."""
    prompt = _USER_TEMPLATE.format(
        detection=json.dumps(detection, indent=2, ensure_ascii=False),
        logs=json.dumps(sample_logs, indent=2, ensure_ascii=False),
        n=len(sample_logs),
    )

    try:
        response = _get_client().converse(
            modelId=BEDROCK_MODEL_ID,
            system=[{"text": _SYSTEM_PROMPT}],
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": BEDROCK_MAX_TOKENS, "temperature": 0},
        )
        text = response["output"]["message"]["content"][0]["text"].strip()

        # Nettoyage au cas ou Claude ajoute des balises markdown
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]

        return json.loads(text)

    except json.JSONDecodeError as e:
        print(f"[Bedrock] JSON parse error: {e}")
    except Exception as e:
        print(f"[Bedrock] Error: {e}")

    return None


def enrich_detection(detection: dict, full_df: pd.DataFrame) -> dict:
    """
    Enrichit une seule detection avec l'analyse de Claude.
    Retourne la detection enrichie (ou originale si Bedrock echoue).
    """
    if not BEDROCK_ENABLED:
        return detection

    sample = _sample_logs(detection, full_df)
    result = _call_bedrock(detection, sample)

    if result is None:
        return detection

    enriched = dict(detection)  # copie superficielle

    # Affine le type si Claude est confiant
    if result.get("confidence") in ("high", "medium"):
        enriched["detection"] = dict(detection["detection"])
        enriched["detection"]["attack_type"] = result.get(
            "attack_type", detection["detection"]["attack_type"]
        )
        # Fusionne les indicators (les originaux restent, Claude en ajoute)
        merged_indicators = dict(detection["detection"]["indicators"])
        merged_indicators.update(result.get("indicators", {}))
        enriched["detection"]["indicators"] = merged_indicators

    print(f"[Bedrock] {detection['detection']['attack_type']} -> "
          f"{enriched['detection']['attack_type']} "
          f"(confidence={result.get('confidence', '?')})")

    return enriched


def enrich_detections(detections: list[dict], full_df: pd.DataFrame) -> list[dict]:
    """Enrichit toutes les detections. Appels Bedrock sequentiels (pas de quota)."""
    if not BEDROCK_ENABLED or not detections:
        return detections

    print(f"\n[Bedrock] Enrichissement de {len(detections)} detection(s)...")
    return [enrich_detection(d, full_df) for d in detections]
