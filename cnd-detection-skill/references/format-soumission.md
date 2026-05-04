# Référence — Format de soumission au jury

Toute sortie qui finit en `submit.py → POST API` doit respecter ce schéma. C'est lui qui détermine le score.

## Schéma de soumission

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

## Règles strictes

- `challenge_id` ∈ {`credential_stuffing`, `ssh_brute_force`, `sql_injection`, `directory_traversal`, `ssrf`}. **Jamais autre chose**.
- `attack_type` doit matcher exactement le `challenge_id` pour les 20 pts max sur le critère "Type d'attaque" (sinon 50% si même famille).
- `attacker_ips` : array, dédupliqué, IPv4 textuel.
- `victim_accounts` : array vide `[]` autorisé (gratuit pour les challenges sans victime nommée : `sql_injection`, `directory_traversal`, `ssrf`).
- Timestamps ISO 8601 **UTC** avec `Z` final. Tolérance jury : ±5 min pour 100% des points timeline, 0 pts au-delà de ±10 min.
- `indicators` : objet libre — les clés sont matchées par nom avec tolérance par le scoreur.

## Indicateurs IoC attendus par challenge

Ces clés sont celles que le scoreur jury cherche en priorité. Les remplir maximise les 20 pts IoC.

### `credential_stuffing`
```json
{
  "failed_logins": 3500,
  "web_shell": "/uploads/image_2026.php",
  "reverse_shell_port": 4444,
  "geolocation": "Beijing"
}
```

### `ssh_brute_force`
```json
{
  "total_ssh_failures": 4600,
  "lateral_targets": ["app-prod-01", "app-prod-02", "db-prod-01", "web-prod-01"],
  "priv_esc": "sudo + backdoor user",
  "exfil_port": "443/8443"
}
```

### `sql_injection`
```json
{
  "sqli_requests": 300,
  "exfil_bytes": 25000000,
  "tool_signature": "Chrome-like UA with automated patterns"
}
```

### `directory_traversal`
```json
{
  "traversal_attempts": 120,
  "successful_reads": 75,
  "traversal_patterns": "../",
  "sensitive_files": ["/etc/passwd", "/etc/shadow", "/root/.ssh"]
}
```

### `ssrf`
```json
{
  "ssrf_targets": ["10.0.3.10:3306", "10.0.4.10:389", "169.254.169.254"],
  "internal_traffic_from_web": true
}
```

## Barème (à connaître pour arbitrer)

| Critère | Points | Mode skill principalement concerné |
|---|---|---|
| Type d'attaque | 20 | RECOMMANDATION (refine attack_type) |
| IPs attaquant | 20 (F1) | TUNING (seuils trop hauts → IPs ratées) + RECOMMANDATION |
| Comptes victimes | 20 (F1) | RECOMMANDATION |
| Timeline | 20 | RECOMMANDATION (start/end time) |
| Indicateurs IoC | 20 | RECOMMANDATION + CRITIQUE |
| **Bonus rapidité** | +50 | détection < 5 min après apparition |
| **Pénalité FP** | −10 / FP | TUNING + CRITIQUE |
| **Total max** | **150** | |

Seuil de validation jury : **70 pts**. En dessous, la soumission est ignorée du leaderboard.

## Pré-validation avant POST

Toujours faire passer la soumission par `assets/validators/validate_outputs.py` avec `mode="submission"`. Refuser de POSTer si :

- Au moins un timestamp n'est pas en UTC ISO 8601
- `challenge_id` n'est pas dans la liste fermée
- `attacker_ips` contient des doublons ou des chaînes non-IPv4
- Une clé IoC critique pour le challenge concerné est manquante (warning, pas blocage)
