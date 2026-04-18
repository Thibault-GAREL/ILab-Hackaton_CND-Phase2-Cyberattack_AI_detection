"""
Soumission des detections a l'API de scoring.

Usage:
    python submit.py                  # soumet detections.json
    python submit.py --dry-run        # affiche les payloads sans envoyer
    python submit.py --file other.json
"""

import json
import argparse
import requests
from datetime import datetime
from config import SCORING_API_URL, SCORING_API_KEY, SCORING_API_HEADERS


def _build_headers() -> dict:
    headers = dict(SCORING_API_HEADERS)
    if SCORING_API_KEY:
        # Adapter selon ce que les organisateurs communiquent
        headers["Authorization"] = f"Bearer {SCORING_API_KEY}"
    return headers


def submit_detection(payload: dict, dry_run: bool = False) -> dict | None:
    challenge_id = payload.get("challenge_id", "?")
    attack_type  = payload.get("detection", {}).get("attack_type", "?")

    if dry_run:
        print(f"[DRY-RUN] {challenge_id} / {attack_type}")
        print(json.dumps(payload, indent=2))
        return None

    try:
        resp = requests.post(
            SCORING_API_URL,
            json=payload,
            headers=_build_headers(),
            timeout=15,
        )
        resp.raise_for_status()
        result = resp.json()
        _print_score(challenge_id, attack_type, result)
        return result
    except requests.HTTPError as e:
        body = e.response.text if e.response else ""
        print(f"[HTTP ERROR] {e.response.status_code} — {body}")
    except requests.RequestException as e:
        print(f"[NETWORK ERROR] {e}")

    return None


def _print_score(challenge_id: str, attack_type: str, result: dict) -> None:
    score       = result.get("score", result.get("total_score", "?"))
    breakdown   = result.get("breakdown", result.get("details", {}))
    status      = result.get("status", "ok")

    print(f"\n{'='*55}")
    print(f"  {challenge_id}  /  {attack_type}")
    print(f"  Status : {status}  |  Score : {score} pts")
    if breakdown:
        print("  --- Breakdown ---")
        for key, val in breakdown.items():
            print(f"    {key:<25} {val}")
    print(f"{'='*55}")


def _summary(results: list[dict]) -> None:
    if not results:
        return

    total = sum(r.get("score", r.get("total_score", 0)) for r in results)
    print(f"\n{'='*55}")
    print(f"  TOTAL : {len(results)} soumission(s)  |  {total} pts cumules")
    print(f"  Timestamp : {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"{'='*55}\n")

    # Sauvegarde des scores pour comparaison entre iterations
    with open("scores_history.json", "a") as f:
        entry = {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_score": total,
            "submissions": len(results),
            "results": results,
        }
        f.write(json.dumps(entry) + "\n")
    print("Scores appended to scores_history.json")


def main():
    parser = argparse.ArgumentParser(description="Submit detections to scoring API")
    parser.add_argument("--file", default="detections.json", help="JSON file to submit")
    parser.add_argument("--dry-run", action="store_true", help="Print without sending")
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

    results = []
    for payload in detections:
        result = submit_detection(payload, dry_run=args.dry_run)
        if result:
            results.append(result)

    if not args.dry_run:
        _summary(results)


if __name__ == "__main__":
    main()
