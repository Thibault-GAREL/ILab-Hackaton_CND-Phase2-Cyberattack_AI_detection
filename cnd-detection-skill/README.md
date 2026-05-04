# cnd-detection-tuner

Skill modulaire pour pipeline de détection de cyberattaques (hackathon CND).

## TL;DR

Trois modes complémentaires appelables via l'API Bedrock (Claude Opus 4.6) :

| Mode | Rôle | Quand l'appeler |
|---|---|---|
| **TUNING** | Ajuste les seuils des règles déterministes | Batch nocturne, ou après chaque cycle de scoring |
| **RECOMMANDATION** | Enrichit une détection brute en payload jury (MITRE, IoC, remédiation) | Une fois par détection produite |
| **CRITIQUE** | Audit anti-hallucination de la recommandation | Toujours, juste avant submit |

Pipeline complet : `détecteur → RECOMMANDATION → CRITIQUE → submit`. Le mode TUNING tourne séparément.

## Arborescence

```
cnd-detection-tuner/
├── SKILL.md                          ← Routeur principal (à lire en premier)
├── README.md                         ← Ce fichier
├── references/
│   ├── format-logs.md                ← Schéma 33 colonnes
│   ├── format-soumission.md          ← Format JSON jury + barème
│   ├── tuning-sensibilite.md         ← Mode TUNING
│   ├── recommandation-action.md      ← Mode RECOMMANDATION
│   └── critique-remediation.md       ← Mode CRITIQUE
└── assets/
    ├── prompts/
    │   ├── tuning_system_prompt.txt
    │   ├── recommendation_system_prompt.txt
    │   └── critic_system_prompt.txt
    ├── schemas/
    │   ├── tuning_output.schema.json
    │   ├── recommendation_output.schema.json
    │   └── critic_output.schema.json
    ├── validators/
    │   ├── validate_outputs.py       ← Validation des sorties JSON
    │   └── orchestrator.py           ← Pipeline Python prêt à l'emploi
    └── examples/
        ├── tuning_input_example.json
        ├── tuning_output_example.json
        ├── recommendation_output_example.json
        └── critic_output_example.json
```

## Démarrage rapide

```python
# 1. Copier le dossier assets/ à côté de bedrock_analysis.py
# 2. Installer les deps
pip install boto3 jsonschema

# 3. Utiliser l'orchestrator
from validators.orchestrator import enrich_and_audit

raw_detection = {...}        # sortie d'un détecteur Python
log_excerpt   = [...]        # max 200 lignes pertinentes
attack_start  = "2026-01-06T02:00:00Z"

result = enrich_and_audit(raw_detection, log_excerpt, attack_start)

if not result["fallback_used"]:
    submit(result["submission"])         # → POST API jury
else:
    print("Fallback : critic a rejeté", result["critic"]["status"])
    submit(result["submission"])         # détection brute, sans enrichissement
```

## Pourquoi 3 modes séparés ?

1. **Économie d'inférence** : on ne lance pas l'audit anti-hallu sur les seuils, ni la recommandation MITRE sur du tuning de threshold.
2. **Anti-sycophancie** : faire la critique dans un appel API séparé, avec un prompt opposé, multiplie ~3x le taux de détection d'hallucinations vs un prompt "génère puis vérifie".
3. **Défense en profondeur** : si CRITIQUE rejette, fallback automatique sur la détection brute → on ne perd jamais les points du détecteur déterministe.

## Barème CND intégré

Chaque mode connaît la structure du scoring (max 150 pts/challenge, −10/FP, +50 si <5 min) et arbitre en conséquence. Les heuristiques de tuning sont calibrées sur l'asymétrie −100 (FN) vs −10 (FP).

## Vérification locale (sans Bedrock)

```bash
cd assets && PYTHONPATH=. python validators/validate_outputs.py
# Doit afficher : Tous les exemples valident.
```

## À adapter à ton projet

- Dans `orchestrator.py`, fonction `_raw_to_submission` : ajuster pour matcher le format de sortie exact de tes détecteurs Python.
- Dans `validate_outputs.py`, constante `CRITICAL_IOC_KEYS` : ajouter d'autres clés IoC si tu en attends.
- Dans `recommendation_system_prompt.txt`, section "Indicateurs IoC" : si le ground truth évolue, ajuster.
