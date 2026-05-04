"""
Soumission des detections a l'API de scoring.

Usage:
    python submit.py                  # soumet detections.json
    python submit.py --dry-run        # affiche les payloads sans envoyer
    python submit.py --file other.json
    python submit.py --skip-validation # envoyer le JSON brut sans normaliser

Configuration : SCORING_API_URL, SCORING_API_KEY, SCORING_REQUEST_TIMEOUT_S (voir config.py + env).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone

import requests

from .config import (
    SCORING_API_URL,
    SCORING_API_KEY,
    SCORING_API_HEADERS,
    SCORING_REQUEST_TIMEOUT_S,
)

_TS_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class PayloadValidationError(ValueError):
    """Payload incompatible avec le format attendu par l API de scoring."""


def normalize_scoring_payload(raw: dict) -> dict:
    """
    Normalise et valide la structure avant POST : challenge_id, detection imbrique,
    victim_accounts toujours une liste [], timestamps ISO 8601 UTC en secondes avec suffixe Z.
    """
    if not isinstance(raw, dict):
        raise PayloadValidationError("Le payload doit etre un objet JSON")

    cid = raw.get("challenge_id")
    if cid is None or not str(cid).strip():
        raise PayloadValidationError("challenge_id manquant ou vide")

    det = raw.get("detection")
    if not isinstance(det, dict):
        raise PayloadValidationError("detection doit etre un objet")

    atk = det.get("attack_type")
    if atk is None or not str(atk).strip():
        raise PayloadValidationError("detection.attack_type manquant ou vide")

    for tkey in ("attack_start_time", "attack_end_time"):
        tv = det.get(tkey)
        if tv is None:
            raise PayloadValidationError(f"detection.{tkey} manquant")
        ts = tv if isinstance(tv, str) else str(tv)
        if not _TS_Z.match(ts):
            raise PayloadValidationError(
                f"detection.{tkey} doit etre ISO 8601 UTC (YYYY-MM-DDTHH:MM:SSZ), "
                f"recu : {tv!r}"
            )

    ips = det.get("attacker_ips")
    if ips is None:
        ips = []
    if not isinstance(ips, list):
        raise PayloadValidationError("detection.attacker_ips doit etre une liste")

    victims = det.get("victim_accounts")
    if victims is None:
        victims = []
    if not isinstance(victims, list):
        raise PayloadValidationError("detection.victim_accounts doit etre une liste")

    indicators = det.get("indicators")
    if indicators is None:
        indicators = {}
    if not isinstance(indicators, dict):
        raise PayloadValidationError("detection.indicators doit etre un objet")

    dts = raw.get("detection_time_seconds")
    if dts is None:
        raise PayloadValidationError("detection_time_seconds manquant")
    try:
        dts_int = int(dts)
    except (TypeError, ValueError) as e:
        raise PayloadValidationError(
            "detection_time_seconds doit etre un entier"
        ) from e

    out = {
        "challenge_id": str(cid).strip(),
        "detection": {
            "attack_type": str(atk).strip(),
            "attacker_ips": [str(x) for x in ips],
            "victim_accounts": [str(x) for x in victims],
            "attack_start_time": det["attack_start_time"],
            "attack_end_time": det["attack_end_time"],
            "indicators": indicators,
        },
        "detection_time_seconds": dts_int,
    }
    # Re-valider les cles timestamps apres coup (cas str non-string original)
    for tkey in ("attack_start_time", "attack_end_time"):
        tv = str(out["detection"][tkey])
        if not _TS_Z.match(tv):
            raise PayloadValidationError(
                f"detection.{tkey} doit terminer par Z avec secondes entieres"
            )
        out["detection"][tkey] = tv

    return out


def _build_headers() -> dict:
    headers = dict(SCORING_API_HEADERS)
    if SCORING_API_KEY:
        headers["Authorization"] = f"Bearer {SCORING_API_KEY}"
    return headers


def _parse_response_body(resp: requests.Response) -> dict | str:
    txt = resp.text or ""
    if not txt.strip():
        return ""
    try:
        return resp.json()
    except json.JSONDecodeError:
        return txt


def _extract_score_numeric(result: dict | str) -> float:
    """Extrait un score numerique depuis la reponse JSON (schemas variables)."""
    if not isinstance(result, dict):
        return 0.0
    for k in ("score", "total_score"):
        if k not in result:
            continue
        v = result[k]
        if isinstance(v, (int, float)):
            return float(v)
        try:
            return float(v)
        except (TypeError, ValueError):
            continue
    return 0.0


def submit_detection(payload: dict, dry_run: bool = False) -> dict | None:
    challenge_id = payload.get("challenge_id", "?")
    attack_type = payload.get("detection", {}).get("attack_type", "?")

    if dry_run:
        print(f"[DRY-RUN] {challenge_id} / {attack_type}")
        print(json.dumps(payload, indent=2))
        return None

    try:
        resp = requests.post(
            SCORING_API_URL,
            json=payload,
            headers=_build_headers(),
            timeout=SCORING_REQUEST_TIMEOUT_S,
        )
        body = _parse_response_body(resp)
        if not resp.ok:
            print(f"[HTTP ERROR] {resp.status_code} — {body}")
            return None

        if isinstance(body, str):
            print(f"[WARN] Reponse non-JSON (ignoree pour le total) : {body[:500]}")
            return None

        if not isinstance(body, dict):
            return None

        _print_score(challenge_id, attack_type, body)
        return body
    except requests.RequestException as e:
        print(f"[NETWORK ERROR] {e}")

    return None


def _print_score(challenge_id: str, attack_type: str, result: dict) -> None:
    score = result.get("score", result.get("total_score", "?"))
    breakdown = result.get("breakdown", result.get("details", {}))
    status = result.get("status", "ok")

    print(f"\n{'='*55}")
    print(f"  {challenge_id}  /  {attack_type}")
    print(f"  Status : {status}  |  Score : {score} pts")
    if isinstance(breakdown, dict) and breakdown:
        print("  --- Breakdown ---")
        for key, val in breakdown.items():
            print(f"    {key:<25} {val}")
    print(f"{'='*55}")


def _summary(results: list[dict]) -> None:
    if not results:
        return

    total = sum(_extract_score_numeric(r) for r in results)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"\n{'='*55}")
    print(f"  TOTAL : {len(results)} soumission(s)  |  {total:.0f} pts cumules")
    print(f"  Timestamp : {ts}")
    print(f"{'='*55}\n")

    entry = {
        "timestamp": ts,
        "total_score": total,
        "submissions": len(results),
        "results": results,
    }
    with open("scores_history.json", "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print("Scores appended to scores_history.json")


def main():
    parser = argparse.ArgumentParser(description="Submit detections to scoring API")
    parser.add_argument("--file", default="detections.json", help="JSON file to submit")
    parser.add_argument("--dry-run", action="store_true", help="Print without sending")
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Ne pas normaliser ni valider (JSON brut depuis le fichier)",
    )
    parser.add_argument("--index", type=int, default=None,
                        help="Submit only detection at this index (0-based)")
    args = parser.parse_args()

    with open(args.file) as f:
        detections = json.load(f)

    if args.index is not None:
        detections = [detections[args.index]]
        print(f"Submitting detection #{args.index} only\n")
    else:
        print(f"{len(detections)} detection(s) to submit from {args.file}\n")

    if (
        not args.dry_run
        and SCORING_API_URL in ("", "https://TO_FILL")
    ):
        print(
            "[ERROR] SCORING_API_URL non configure (voir config ou variable SCORING_API_URL).",
            file=sys.stderr,
        )
        sys.exit(1)

    results: list[dict] = []
    for raw in detections:
        try:
            payload = raw if args.skip_validation else normalize_scoring_payload(raw)
        except PayloadValidationError as e:
            print(f"[VALIDATION ERROR] {e}", file=sys.stderr)
            sys.exit(2)

        result = submit_detection(payload, dry_run=args.dry_run)
        if result is not None:
            results.append(result)

    if not args.dry_run:
        _summary(results)


if __name__ == "__main__":
    main()
