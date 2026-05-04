---
name: cnd-detection-tuner
description: Skill modulaire pour pipeline de détection de cyberattaques CND. Couvre trois modes complémentaires utilisés via Bedrock/Claude API — (1) réglage automatique de la sensibilité des règles déterministes à partir des logs et de l'historique de scoring, (2) enrichissement et recommandation d'action pour chaque détection (raffinement du type d'attaque, technique MITRE ATT&CK, IoC, remédiation), (3) critique de remédiation en self-reflection pour bloquer toute hallucination avant soumission au jury. Toujours utiliser ce skill quand l'utilisateur travaille sur le hackathon CND, ajuste des seuils de détection, enrichit des détections d'attaques, ou veut vérifier que les recommandations générées par Claude sont bien ancrées dans les logs sources. Optimisé pour le barème -10 pts/FP vs -100 pts/challenge raté.
---

# CND Detection Tuner — Skill modulaire pour pipeline de détection

Ce skill équipe une pipeline de détection de cyberattaques (hackathon CND, dataset 21M logs Parquet + flux temps réel OpenSearch) avec trois capacités IA générative qui s'enchaînent et se vérifient mutuellement :

1. **Mode TUNING** — ajuste les seuils des 5 détecteurs déterministes (`*_MIN_*` dans `config.py`)
2. **Mode RECOMMANDATION** — enrichit chaque détection (type, MITRE, IoC, remédiation)
3. **Mode CRITIQUE** — passe de self-reflection qui rejette toute affirmation non ancrée dans les logs

Les trois modes partagent un format de logs commun (33 colonnes — voir `references/format-logs.md`) et un format de soumission commun (voir `references/format-soumission.md`).

## Quand utiliser quel mode

| Symptôme / besoin utilisateur | Mode à activer |
|---|---|
| « J'ai trop de FP », « j'ai raté un challenge », « ajuste mes seuils » | TUNING |
| « Enrichis cette détection », « ajoute le MITRE », « suggère une remédiation » | RECOMMANDATION |
| « Vérifie que je n'hallucine pas », « anti-hallu », « relis avant soumission » | CRITIQUE |
| Soumission imminente au jury | RECOMMANDATION → CRITIQUE (toujours dans cet ordre) |

Dans la pipeline complète : **détecteurs déterministes → RECOMMANDATION → CRITIQUE → submit**. Le mode TUNING tourne séparément (offline ou batch nocturne) pour mettre à jour `config.py`.

## Règle de priorité économique (à mémoriser)

Le barème CND est asymétrique :

- **Faux positif (FP)** : −10 pts par FP soumis
- **Challenge raté (FN)** : jusqu'à −100 pts (les 100 pts du challenge non gagnés)
- **Bonus rapidité** : +50 pts si détection < 5 min

**Conséquence pour les 3 modes** : il faut **10 FP pour égaler 1 FN**. Donc en cas de doute, **préférer la sur-détection à la sous-détection**. Mais une fois qu'une détection est faite, **CRITIQUE doit être stricte** car un IoC halluciné fait à la fois perdre des points (mauvais matching IoC) et discrédite la soumission.

Cette règle gouverne tous les arbitrages du skill. À chaque proposition de seuil ou d'enrichissement, Claude doit explicitement nommer le risque (FP vs FN) et trancher en conséquence.

## Architecture en deux passes (Génération → Critique)

Pour les modes RECOMMANDATION et CRITIQUE, la pipeline doit toujours être :

```
détection brute (déterministe)
       ↓
[ APPEL 1 — RECOMMANDATION ]   ← claude-opus-4-6 sur Bedrock
       ↓
{recommendation_v1.json}
       ↓
[ APPEL 2 — CRITIQUE ]          ← claude-opus-4-6 sur Bedrock, prompt différent
       ↓
{critique.json}
       ↓
       ├─ status="approved"  → submit
       ├─ status="needs_revision" → relance RECOMMANDATION avec patches
       └─ status="rejected"  → fallback sur la détection brute (sans enrichissement LLM)
```

**Ne jamais soumettre sans passer par CRITIQUE.** C'est ce qui blinde le critère anti-hallucination du jury.

## Choix du mode

Quand l'utilisateur demande quelque chose, identifie le mode puis charge la référence correspondante :

- TUNING → lis `references/tuning-sensibilite.md`
- RECOMMANDATION → lis `references/recommandation-action.md`
- CRITIQUE → lis `references/critique-remediation.md`

Dans tous les cas, charge aussi `references/format-logs.md` (schéma des 33 colonnes) et `references/format-soumission.md` (format JSON jury).

## Templates de prompts prêts à l'emploi

Pour chaque mode, un prompt système optimisé est fourni dans `assets/prompts/` :

- `tuning_system_prompt.txt` — pour l'appel Bedrock du tuner
- `recommendation_system_prompt.txt` — pour l'enrichissement
- `critic_system_prompt.txt` — pour la self-reflection

Ces prompts sont à charger côté Python avec `open().read()` puis à passer comme `system` dans `client.converse()`. Les schémas JSON correspondants sont dans `assets/schemas/`.

## Validation locale

Le script `assets/validators/validate_outputs.py` vérifie que la sortie d'un mode respecte son schéma JSON. **Toujours** valider avant de passer au mode suivant ou de soumettre. Usage :

```python
from validators.validate_outputs import validate
validate(payload, mode="recommendation")  # raise ValueError si invalide
```

## Principes transverses

Ces principes s'appliquent aux trois modes et doivent être rappelés au modèle dans chaque prompt système :

1. **Pas d'invention de champ.** Si un IoC n'est pas extractible des logs fournis, il vaut mieux omettre le champ que mettre une valeur plausible mais non vérifiée.
2. **Citer les preuves.** Pour chaque affirmation factuelle (un nombre, une IP, un username, une URI), donner la source — soit l'index de la ligne de log, soit un session_id, soit un timestamp précis.
3. **Borner les chiffres.** Les estimations doivent être données comme intervalles (ex. `failed_logins: 3500` est OK seulement si on a compté ; sinon utiliser `~3000-4000`).
4. **Préserver les IDs.** Ne jamais renommer ou réécrire les `challenge_id` du jury (`credential_stuffing`, `ssh_brute_force`, `sql_injection`, `directory_traversal`, `ssrf`).
5. **Conservatisme contrôlé.** Toute action destructive (baisser fortement un seuil, marquer une détection comme à ignorer) doit être justifiée par au moins 2 signaux indépendants.
6. **Auditabilité.** Toutes les sorties JSON contiennent un champ `reasoning` lisible par un humain.

## Modèle cible

Bedrock `anthropic.claude-opus-4-6-v1` en `eu-west-3`. Les prompts du skill sont calibrés pour ce modèle. `inferenceConfig.maxTokens` recommandé :

- TUNING : 4096 (sortie potentiellement longue avec recommandations multiples)
- RECOMMANDATION : 2048
- CRITIQUE : 3072 (besoin de citer beaucoup de preuves)

Température : 0 pour CRITIQUE et TUNING (déterministe), 0.2 pour RECOMMANDATION.

## Exemples concrets

`assets/examples/` contient des exemples bout-en-bout pour les 5 challenges DS1 — utile pour calibrer le few-shot ou pour tester localement sans Bedrock.

---

**Pour démarrer** : identifie le mode demandé par l'utilisateur, charge la référence correspondante (`references/<mode>.md`) en plus des deux références de format, et applique la méthodologie qui y est décrite.
