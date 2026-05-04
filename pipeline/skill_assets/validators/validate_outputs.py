"""
Validator des sorties JSON pour les 3 modes du skill cnd-detection-tuner.

Usage :
    from validators.validate_outputs import validate
    validate(payload, mode="tuning"|"recommendation"|"critic"|"submission")

Léve ValueError avec message explicite si invalide.

Dépendance unique : jsonschema (pip install jsonschema)
"""

import json
import re
from datetime import datetime
from pathlib import Path

try:
    from jsonschema import Draft7Validator
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "jsonschema est requis : pip install jsonschema"
    ) from e


SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"

VALID_CHALLENGE_IDS = {
    "credential_stuffing",
    "ssh_brute_force",
    "sql_injection",
    "directory_traversal",
    "ssrf",
}

# Clés IoC critiques par challenge — warning si absentes
CRITICAL_IOC_KEYS = {
    "credential_stuffing": ["failed_logins"],
    "ssh_brute_force": ["total_ssh_failures"],
    "sql_injection": ["sqli_requests"],
    "directory_traversal": ["traversal_attempts"],
    "ssrf": ["ssrf_targets"],
}


def _load_schema(name: str) -> dict:
    path = SCHEMAS_DIR / f"{name}_output.schema.json"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _check_jsonschema(payload: dict, schema_name: str) -> list:
    schema = _load_schema(schema_name)
    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda e: e.path)
    return [f"{list(e.path)}: {e.message}" for e in errors]


def _validate_tuning(payload: dict) -> list:
    errors = _check_jsonschema(payload, "tuning")

    # delta_pct cohérent avec current_value et recommended_value
    for i, rec in enumerate(payload.get("recommendations", [])):
        cv = rec.get("current_value")
        rv = rec.get("recommended_value")
        dp = rec.get("delta_pct")
        if cv and rv is not None and dp is not None:
            expected = round((rv - cv) / cv * 100) if cv else 0
            if abs(expected - dp) > 2:  # tolérance arrondi
                errors.append(
                    f"recommendations[{i}]: delta_pct={dp} incohérent avec "
                    f"current={cv} recommended={rv} (attendu ~{expected})"
                )
        # direction cohérente
        if rv is not None and cv is not None:
            direction = rec.get("direction")
            if direction == "raise" and rv <= cv:
                errors.append(f"recommendations[{i}]: direction=raise mais rv≤cv")
            if direction == "lower" and rv >= cv:
                errors.append(f"recommendations[{i}]: direction=lower mais rv≥cv")
            if direction == "hold" and rv != cv:
                errors.append(f"recommendations[{i}]: direction=hold mais rv≠cv")
    return errors


def _validate_recommendation(payload: dict) -> list:
    errors = _check_jsonschema(payload, "recommendation")

    # Cohérence challenge_id ↔ submission.challenge_id ↔ submission.detection.attack_type
    cid = payload.get("challenge_id")
    sub = payload.get("submission", {})
    sub_cid = sub.get("challenge_id")
    detection = sub.get("detection", {})
    atype = detection.get("attack_type")

    if cid != sub_cid:
        errors.append(f"challenge_id ({cid}) ≠ submission.challenge_id ({sub_cid})")
    if cid != atype:
        errors.append(f"challenge_id ({cid}) ≠ submission.detection.attack_type ({atype})")

    # Window start ≤ end
    start = detection.get("attack_start_time")
    end = detection.get("attack_end_time")
    if start and end and start > end:
        errors.append(f"attack_start_time ({start}) > attack_end_time ({end})")

    # Chaque attacker_ip a une evidence
    evidence_ips = {e["value"] for e in payload.get("evidence", {}).get("attacker_ips", [])}
    for ip in detection.get("attacker_ips", []):
        if ip not in evidence_ips:
            errors.append(f"attacker_ip {ip} absent de evidence.attacker_ips")

    # Chaque victim_account a une evidence (sauf si liste vide)
    evidence_victims = {e["value"] for e in payload.get("evidence", {}).get("victim_accounts", [])}
    for v in detection.get("victim_accounts", []):
        if v not in evidence_victims:
            errors.append(f"victim_account {v} absent de evidence.victim_accounts")

    return errors


def _validate_critic(payload: dict) -> list:
    errors = _check_jsonschema(payload, "critic")

    grounded = payload.get("claims_grounded", 0)
    inferred = payload.get("claims_inferred", 0)
    unsupported = payload.get("claims_unsupported", 0)
    audited = payload.get("claims_audited", 0)

    if grounded + inferred + unsupported != audited:
        errors.append(
            f"Somme des verdicts ({grounded}+{inferred}+{unsupported}={grounded+inferred+unsupported}) "
            f"≠ claims_audited ({audited})"
        )

    if audited > 0:
        expected_score = round(100 * (grounded + 0.5 * inferred) / audited)
        if abs(payload.get("score", 0) - expected_score) > 2:
            errors.append(f"score incohérent : attendu ~{expected_score}, got {payload.get('score')}")

    # Cohérence status ↔ verdicts
    status = payload.get("status")
    if unsupported >= 3 and status != "rejected":
        errors.append(f"status={status} mais {unsupported} unsupported (attendu 'rejected')")
    elif 1 <= unsupported <= 2 and status != "needs_revision":
        errors.append(f"status={status} mais {unsupported} unsupported (attendu 'needs_revision')")
    elif unsupported == 0 and inferred > 2 and status != "approved_with_warnings":
        errors.append(f"status={status} mais {inferred} inferred sans unsupported (attendu 'approved_with_warnings')")
    elif unsupported == 0 and inferred <= 2 and status != "approved":
        errors.append(f"status={status} mais 0 unsupported, ≤2 inferred (attendu 'approved')")

    # patches non-vide si needs_revision
    if status == "needs_revision" and not payload.get("patches"):
        errors.append("status=needs_revision mais patches est vide")

    # audit_id cohérent
    audit_id = payload.get("audit_id", "")
    if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", audit_id):
        errors.append(f"audit_id mal formaté : {audit_id}")

    return errors


def _validate_submission(payload: dict) -> list:
    """Validation du payload final qui part au jury (POST API scoring)."""
    errors = []

    cid = payload.get("challenge_id")
    if cid not in VALID_CHALLENGE_IDS:
        errors.append(f"challenge_id invalide : {cid}")

    detection = payload.get("detection", {})

    # Champs obligatoires
    for k in ("attack_type", "attacker_ips", "victim_accounts", "attack_start_time", "attack_end_time", "indicators"):
        if k not in detection:
            errors.append(f"detection.{k} manquant")

    # IPs valides + dédupliquées
    ips = detection.get("attacker_ips", [])
    if not isinstance(ips, list) or not ips:
        errors.append("attacker_ips doit être une liste non vide")
    else:
        if len(ips) != len(set(ips)):
            errors.append("attacker_ips contient des doublons")
        for ip in ips:
            if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
                errors.append(f"IP invalide : {ip}")

    # Timestamps UTC ISO 8601
    for tkey in ("attack_start_time", "attack_end_time"):
        ts = detection.get(tkey)
        if ts and not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", str(ts)):
            errors.append(f"{tkey} mal formaté (attendu ISO 8601 UTC avec Z) : {ts}")

    # detection_time_seconds
    dts = payload.get("detection_time_seconds")
    if dts is None or not isinstance(dts, int) or dts < 0:
        errors.append(f"detection_time_seconds invalide : {dts}")

    # IoC critiques (warning, pas erreur bloquante)
    if cid in CRITICAL_IOC_KEYS:
        indicators = detection.get("indicators", {})
        for k in CRITICAL_IOC_KEYS[cid]:
            if k not in indicators:
                errors.append(f"WARN: IoC critique '{k}' manquant pour challenge '{cid}'")

    return errors


def validate(payload: dict, mode: str) -> None:
    """Valide payload selon le mode. Lève ValueError si invalide.

    mode ∈ {"tuning", "recommendation", "critic", "submission"}
    """
    if mode == "tuning":
        errors = _validate_tuning(payload)
    elif mode == "recommendation":
        errors = _validate_recommendation(payload)
    elif mode == "critic":
        errors = _validate_critic(payload)
    elif mode == "submission":
        errors = _validate_submission(payload)
    else:
        raise ValueError(f"Mode inconnu : {mode}")

    # Séparer warnings (préfixe WARN:) des erreurs
    blocking = [e for e in errors if not e.startswith("WARN:")]
    warnings = [e for e in errors if e.startswith("WARN:")]

    if blocking:
        msg = "\n  - ".join(blocking)
        raise ValueError(f"Validation [{mode}] échouée :\n  - {msg}")

    if warnings:
        for w in warnings:
            print(f"[validate_outputs] {w}")


def safe_parse_llm_json(raw: str) -> dict:
    """Parse une sortie LLM en JSON. Retire backticks Markdown si présents (au cas où)."""
    raw = raw.strip()
    if raw.startswith("```"):
        # retirer ```json ... ``` ou ``` ... ```
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    return json.loads(raw)


if __name__ == "__main__":
    # Smoke test : valider chaque exemple s'il existe
    import sys
    examples_dir = Path(__file__).resolve().parent.parent / "examples"
    if not examples_dir.exists():
        print("Pas de dossier examples/, smoke test sauté.")
        sys.exit(0)
    for f in examples_dir.glob("*_output_example.json"):
        mode = f.stem.replace("_output_example", "")
        try:
            with open(f) as fh:
                payload = json.load(fh)
            validate(payload, mode=mode)
            print(f"OK  {f.name}")
        except (ValueError, json.JSONDecodeError) as e:
            print(f"FAIL {f.name}: {e}")
            sys.exit(1)
    print("Tous les exemples valident.")
