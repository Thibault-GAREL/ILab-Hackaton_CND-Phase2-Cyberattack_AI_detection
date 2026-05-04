# Mode RECOMMANDATION — Enrichissement et action par détection

Ce mode prend en entrée une **détection brute** produite par un détecteur déterministe et la transforme en **payload de soumission** prêt pour le jury, augmenté d'une recommandation de remédiation.

## Pipeline d'enrichissement

```
Détection brute (du détecteur déterministe)
    + extrait pertinent des logs (max ~200 lignes)
    + connaissance MITRE ATT&CK
        ↓
   [ APPEL Bedrock ]
        ↓
Détection enrichie (challenge_id, attack_type raffiné, IPs, victimes, fenêtre, IoC, MITRE, remédiation)
        ↓
   [ Mode CRITIQUE — passe obligatoire ]
        ↓
   submit ou rejet
```

## Ce que le modèle doit produire

Pour chaque détection en entrée, sortir un objet conforme à `assets/schemas/recommendation_output.schema.json` :

```json
{
  "challenge_id": "credential_stuffing",
  "submission": {
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
  },
  "enrichment": {
    "mitre_techniques": [
      {"id": "T1110.004", "name": "Credential Stuffing"},
      {"id": "T1505.003", "name": "Web Shell"}
    ],
    "kill_chain_phase": "Initial Access → Persistence",
    "severity": "critical",
    "remediation": [
      "Bloquer immédiatement 203.0.113.45 et 198.51.100.23 au niveau du WAF/firewall",
      "Forcer la réinitialisation du mot de passe du compte jdupont et invalider les sessions actives",
      "Supprimer le fichier /uploads/image_2026.php et auditer le répertoire /uploads pour d'autres web shells",
      "Bloquer le port 4444 sortant sur les serveurs web et investiguer les processus en écoute",
      "Activer la MFA sur tous les comptes ayant connu des tentatives 401 dans la fenêtre"
    ]
  },
  "evidence": {
    "attacker_ips": [
      {
        "value": "203.0.113.45",
        "support": [
          "2026-01-06T02:14:33Z auth.log status=failure username=jdupont",
          "2026-01-06T03:42:11Z app.log status_code=401 uri=/login",
          "count=2842 sur la fenêtre"
        ]
      },
      {
        "value": "198.51.100.23",
        "support": [
          "2026-01-06T02:51:08Z auth.log status=failure username=jdupont",
          "count=658 sur la fenêtre"
        ]
      }
    ],
    "victim_accounts": [
      {
        "value": "jdupont",
        "support": ["3500 échecs combinés sur le username 'jdupont' dans la fenêtre"]
      }
    ],
    "attack_window": {
      "start_support": "Premier échec 401 sur jdupont à 02:00:14Z",
      "end_support": "Dernier événement de la chaîne (reverse shell tentative) à 05:58:42Z"
    },
    "indicators_support": {
      "failed_logins": "count combiné auth_fail + http 401 sur les 2 IPs = 3500",
      "web_shell": "POST /uploads/image_2026.php observé à 04:23:12Z",
      "reverse_shell_port": "Tentative de connexion sortante destination_port=4444 à 04:24:01Z",
      "geolocation": "Les 2 IPs résolvent geolocation_country=China, principal node Beijing"
    }
  },
  "confidence": "high",
  "reasoning": "Pattern classique credential stuffing : haute volumétrie d'échecs sur un seul compte, depuis plusieurs IPs externes coordonnées, suivi d'un succès puis dépôt de web shell et tentative de reverse shell. Les 4 IoC du jury sont tous observés dans les logs."
}
```

## Règles de production

### 1. Ancrage strict (zéro hallucination)

Pour **chaque** valeur dans `submission.detection`, fournir une entrée dans `evidence` qui pointe vers les logs. Si le modèle ne trouve pas de support pour une valeur, il doit **omettre la clé** plutôt qu'inventer. Une omission peut coûter quelques points IoC mais une hallucination coûte le critère anti-hallu en plus du matching IoC.

### 2. Raffinement du `attack_type`

Le détecteur déterministe peut donner un `challenge_id` générique. Le rôle du modèle est de **confirmer** ce type ou le **raffiner** (en respectant la liste fermée des 5 challenges). Si le modèle pense qu'aucun des 5 ne s'applique, il met `confidence: "low"` + `attack_type: <le challenge_id le plus proche>` + remarque dans `reasoning`. Il ne crée **jamais** un nouveau type.

### 3. MITRE ATT&CK — choisir parmi un catalogue connu

Pour chaque challenge DS1, voici les techniques MITRE typiquement attendues :

| Challenge | Techniques principales |
|---|---|
| credential_stuffing | T1110.004 (Credential Stuffing), T1505.003 (Web Shell), T1059 (Command Execution) |
| ssh_brute_force | T1110.001 (Password Guessing), T1021.004 (SSH), T1068 (Privilege Escalation), T1136 (Create Account) |
| sql_injection | T1190 (Exploit Public-Facing App), T1213 (Data from Information Repos), T1041 (Exfiltration over C2) |
| directory_traversal | T1083 (File and Directory Discovery), T1552.001 (Credentials In Files) |
| ssrf | T1190 (Exploit Public-Facing App), T1552.005 (Cloud Instance Metadata API) |

Le modèle peut élargir mais doit citer un T-id valide MITRE ATT&CK. Pas de techniques inventées.

### 4. Remédiation actionnable

Chaque action de `remediation` doit être :
- **Spécifique** — référencer une IP, un fichier, un port, un compte précis observé dans les logs
- **Exécutable** — un sysadmin doit savoir quoi faire en lisant la phrase
- **Ordonnée par priorité** (la plus critique en premier)

Pas de phrases génériques type "améliorer la sécurité" ou "former les utilisateurs". Si le modèle n'a pas de cible spécifique pour une recommandation, il l'omet.

### 5. Bonus rapidité

`detection_time_seconds` doit refléter le temps réel entre l'apparition de l'attaque dans le flux et la production du payload. Côté Python, c'est `now() - attack_start_time` (en secondes) au moment de l'appel. Le modèle ne doit **pas** inventer cette valeur — elle est fournie en entrée.

### 6. Comportement par challenge sans victime

Pour `sql_injection`, `directory_traversal`, `ssrf` : `victim_accounts: []` est correct et n'enlève pas de points. Le modèle ne doit **pas** inventer un username pour remplir le champ.

## Format d'appel API

```python
import boto3, json

client = boto3.client("bedrock-runtime", region_name="eu-west-3")

with open("assets/prompts/recommendation_system_prompt.txt") as f:
    system_prompt = f.read()

user_message = json.dumps({
    "raw_detection": raw_detection_dict,
    "log_excerpt": log_lines_list,        # max 200 lignes pertinentes
    "now_iso": "2026-01-06T06:03:00Z",
    "attack_start_time": "2026-01-06T02:00:00Z"
})

response = client.converse(
    modelId="anthropic.claude-opus-4-6-v1",
    system=[{"text": system_prompt}],
    messages=[{"role": "user", "content": [{"text": user_message}]}],
    inferenceConfig={"maxTokens": 2048, "temperature": 0.2}
)

raw_output = response["output"]["message"]["content"][0]["text"]
recommendation = json.loads(raw_output)  # le prompt système force le JSON pur

# Validation
from assets.validators.validate_outputs import validate
validate(recommendation, mode="recommendation")

# Toujours enchaîner avec CRITIQUE avant submit
```

## Limite d'extrait de logs

Le `log_excerpt` doit être pré-filtré côté Python : ne pas envoyer les 21M lignes. Heuristique :
- toutes les lignes des `attacker_ips` candidats sur la fenêtre
- + 50 lignes de contexte avant/après
- limité à 200 lignes total ou ~30k tokens

Si plus, échantillonner en gardant : début, milieu, fin, plus toutes les lignes avec `severity ∈ {error, critical}`.
