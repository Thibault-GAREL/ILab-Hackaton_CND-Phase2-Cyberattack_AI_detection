---
title: "Format de soumission et scoring"
version: "2.1"
project: "CND Hackathon Phase 2"
last_updated: "2026-05-05"
audience: ["ia", "humain", "jury"]
---

# Format de soumission

Chaque challenge est soumis séparément via un POST JSON à l'API de scoring.

## Structure JSON

```json
{
  "challenge_id": "credential_stuffing",
  "detection": {
    "attack_type": "credential_stuffing",
    "attacker_ips": ["203.0.113.45", "198.51.100.23"],
    "victim_accounts": ["jdupont"],
    "attack_start_time": "2026-01-06T02:00:00Z",
    "attack_end_time": "2026-01-06T06:00:00Z",
    "indicators": {
      "failed_logins": 3500,
      "web_shell": "/uploads/image_2026.php",
      "reverse_shell_port": 4444,
      "geolocation": "Beijing"
    }
  },
  "detection_time_seconds": 180
}
```

## Champs obligatoires

| Champ | Type | Contraintes |
|---|---|---|
| `challenge_id` | string | Un des 5 : `credential_stuffing`, `ssh_brute_force`, `sql_injection`, `directory_traversal`, `ssrf` |
| `detection.attack_type` | string | Doit correspondre au `challenge_id` |
| `detection.attacker_ips` | string[] | Liste non vide d'IPv4 |
| `detection.victim_accounts` | string[] | Liste vide `[]` si aucun compte ciblé |
| `detection.attack_start_time` | string | ISO 8601 UTC (`2026-01-06T02:00:00Z`) |
| `detection.attack_end_time` | string | ISO 8601 UTC, postérieur à `start_time` |
| `detection.indicators` | object | Clés spécifiques par challenge (voir ci-dessous) |
| `detection_time_seconds` | integer | 0 en mode finale (slices) — non pris en compte pour le score |

## Indicateurs attendus par challenge

### credential_stuffing

```json
{
  "failed_logins": 3500,
  "web_shell": "/uploads/image_2026.php",
  "reverse_shell_port": 4444,
  "geolocation": "Beijing"
}
```

### ssh_brute_force

```json
{
  "total_ssh_failures": 4600,
  "lateral_targets": ["app-prod-01", "app-prod-02", "db-prod-01", "web-prod-01"],
  "priv_esc": "sudo + backdoor user",
  "exfil_port": "443/8443"
}
```

### sql_injection

```json
{
  "sqli_requests": 300,
  "exfil_bytes": 25000000,
  "tool_signature": "Chrome-like UA with automated patterns"
}
```

### directory_traversal

```json
{
  "traversal_attempts": 250,
  "successful_reads": 75,
  "traversal_patterns": "../",
  "sensitive_files": ["/etc/passwd", "/etc/shadow", "/root/.ssh"]
}
```

### ssrf

```json
{
  "ssrf_targets": ["10.0.3.10:3306", "10.0.4.10:389", "169.254.169.254"],
  "internal_traffic_from_web": true
}
```

## Système de scoring

| Critère | Points | Évaluation |
|---|---|---|
| Type d'attaque | 20 pts | Match exact = 100 %, même famille = 50 % |
| IPs attaquant | 20 pts | Score F1 (précision × rappel) |
| Comptes victimes | 20 pts | Score F1 (gratuit si aucun dans le ground truth) |
| Timeline | 20 pts | Tolérance ±5 min = 100 %, ±10 min = 0 % |
| Indicateurs IoC | 20 pts | Matching par clé avec tolérance numérique |
| **Pénalité faux positifs** | -10 pts/FP | Par soumission ne correspondant à aucun challenge |
| **TOTAL MAX** | **100 pts** | Par challenge (5 critères × 20 pts) |

**Seuil de validation** : 70 pts minimum (soumissions en dessous ignorées du leaderboard).

**Total maximum global** : 5 challenges × 100 pts = **500 pts**.

> **Mode finale — ingestion par slices** : les logs sont injectés en 3 lots successifs.
> Le score par challenge est plafonné à **100 pts** ; `detection_time_seconds` est fixé à `0`.

## Soumission via CLI

```bash
# Vérifier les payloads avant envoi
python -m pipeline.submit --dry-run

# Soumettre toutes les détections
python -m pipeline.submit

# Soumettre une seule détection (par index)
python -m pipeline.submit --index 0
```

## Checklist de validation avant soumission

- [ ] **5 détections exactement** — ni plus (faux positifs à -10 pts), ni moins (challenges manqués)
- [ ] **challenge_id** correspond à un des 5 challenges DS1
- [ ] **attack_type** est identique au `challenge_id`
- [ ] **attacker_ips** contient les bonnes IPs (vérifier par rapport au brief)
- [ ] **victim_accounts** : `["jdupont"]` pour credential_stuffing, `["sysadmin"]` pour ssh_brute_force, `[]` pour les 3 autres
- [ ] **Timestamps ISO 8601 UTC** avec suffixe `Z` (pas de timezone locale)
- [ ] **attack_start_time < attack_end_time**
- [ ] **Fenêtres temporelles** dans la tolérance ±5 min du ground truth
- [ ] **Indicateurs** : les clés correspondent exactement à celles du ground truth
- [ ] **detection_time_seconds** = 0 (mode finale, non utilisé pour le score)
- [ ] **Pas de doublons** : vérifier le cache `.submit_fingerprint_cache.json`
- [ ] **Mode slices** : `--accumulate` pour merger les détections entre les 3 lots

## Anti-doublons

La pipeline maintient un cache de fingerprints (`.submit_fingerprint_cache.json`). Chaque détection est hachée avant soumission ; si le hash existe déjà, la soumission est ignorée. Désactiver : `SUBMIT_SKIP_DUPLICATES=0`.

## Anti-hallucination (Mode Skill)

Quand `BEDROCK_SKILL_MODE=1` (défaut), chaque détection passe par :

1. **RECOMMENDATION** : enrichit la détection brute (MITRE ATT&CK, IoC, timeline, remédiation) avec Claude Opus
2. **CRITIQUE** : prompt opposé qui audite l'enrichissement — vérifie que chaque affirmation est ancrée dans les logs

Si CRITIQUE rejette (claims_unsupported >= 3), la pipeline utilise la détection brute (sans enrichissement LLM) comme fallback. Cela protège contre les pénalités IoC hallucinés tout en préservant les points du détecteur déterministe.

Toggle : `BEDROCK_SKILL_MODE=0` pour revenir à l'enrichissement legacy (`bedrock_analysis.py`).
