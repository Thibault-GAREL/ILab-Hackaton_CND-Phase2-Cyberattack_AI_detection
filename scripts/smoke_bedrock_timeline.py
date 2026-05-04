#!/usr/bin/env python3
"""
Test minimal Bedrock Converse sur la pile Opus (config).

Ordre par défaut : eu.anthropic.claude-opus-4-6-v1 puis anthropic.claude-opus-4-6-v1 (config).

Usage (profil SSO / credentials AWS, région Paris) :
  AWS_PROFILE=entreprise AWS_DEFAULT_REGION=eu-west-3 .venv/bin/python scripts/smoke_bedrock_timeline.py

Variables utiles :
  BEDROCK_REGION — surcharge la région runtime (défaut : env AWS ou eu-west-3)
  BEDROCK_TIMELINE_MODEL_ID ou BEDROCK_MODEL_ID — un seul modelId forcé (sinon liste depuis config)
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import boto3  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

from config import BEDROCK_REGION, BEDROCK_TIMELINE_MODEL_CANDIDATES  # noqa: E402


def _hint_after_error(exc: ClientError) -> None:
    code = exc.response.get("Error", {}).get("Code", "")
    msg = exc.response.get("Error", {}).get("Message", str(exc))
    low = msg.lower()
    print(f"  → Code AWS: {code}")
    if code == "ValidationException" and "inference profile" in low:
        print(
            "  → Conseil: utiliser un inference profile (ex. eu.anthropic.claude-opus-4-6-v1), "
            "pas l'ID foundation nu."
        )
    if code == "ResourceNotFoundException" and "use case" in low:
        print(
            "  → Bloquant: formulaire Anthropic (use case) non validé pour ce compte.\n"
            "    Console: Amazon Bedrock → Model catalog / Model access → Anthropic → remplir le formulaire.\n"
            "    Vérif CLI: AWS_PROFILE=... AWS_DEFAULT_REGION=eu-west-3 "
            "aws bedrock get-use-case-for-model-access\n"
            "    Attendre la propagation (~15 min) puis relancer ce script."
        )


def _print_post_mortem() -> None:
    print("\nVérifications rapides (même région que ci-dessus, idéalement eu-west-3) :")
    print("  aws sts get-caller-identity --profile entreprise")
    print("  AWS_PROFILE=entreprise AWS_DEFAULT_REGION=eu-west-3 aws bedrock get-use-case-for-model-access")
    print("  AWS_PROFILE=entreprise AWS_DEFAULT_REGION=eu-west-3 aws bedrock list-foundation-models | head")


def main() -> int:
    print(f"Bedrock runtime region: {BEDROCK_REGION!r} (AWS_DEFAULT_REGION / BEDROCK_REGION)")
    print(f"Candidates: {BEDROCK_TIMELINE_MODEL_CANDIDATES}\n")

    client = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)
    prompt = (
        'Reponds uniquement avec un JSON valide sans markdown : '
        '{"refined_attack_end_time":"2026-01-06T06:00:00Z","confidence":"high","rationale":"smoke"}'
    )
    for model_id in BEDROCK_TIMELINE_MODEL_CANDIDATES:
        print(f"Trying modelId={model_id!r} ...")
        try:
            resp = client.converse(
                modelId=model_id,
                messages=[{"role": "user", "content": [{"text": prompt}]}],
                inferenceConfig={"maxTokens": 256, "temperature": 0},
            )
            text = resp["output"]["message"]["content"][0]["text"]
            print(f"OK ({model_id}): {text[:200]}...")
            return 0
        except ClientError as e:
            print(f"FAIL ({model_id}): {e}")
            _hint_after_error(e)
        except Exception as e:
            print(f"FAIL ({model_id}): {e}")

    print("\nAll candidates failed.")
    _print_post_mortem()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
