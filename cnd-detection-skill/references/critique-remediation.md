# Mode CRITIQUE — Self-Reflection anti-hallucination

Ce mode est le **garde-fou** entre RECOMMANDATION et la soumission au jury. Il prend la sortie de RECOMMANDATION + les mêmes logs sources et **vérifie chaque affirmation factuelle** contre les logs.

C'est ce mode qui blinde le critère anti-hallucination du jury.

## Principe

Le mode RECOMMANDATION peut produire des affirmations plausibles mais non vérifiables (ex. inventer une `geolocation: "Beijing"` parce qu'une IP en `203.0.113.x` "fait Chine" alors que les logs n'ont pas le champ). Le mode CRITIQUE ré-attaque le problème avec un objectif inversé : **chercher la moindre affirmation non ancrée**.

Pour fonctionner, **CRITIQUE doit être un appel Bedrock séparé** (avec un prompt système différent) — pas une simple instruction "vérifie-toi" dans le même appel. C'est ce qui casse la sycophancie du modèle.

## Inputs

```json
{
  "recommendation_to_audit": { ... sortie complète du mode RECOMMANDATION ... },
  "log_excerpt": [ ... mêmes logs que RECOMMANDATION, ou plus larges ... ],
  "submission_format_rules": "résumé du format jury — voir format-soumission.md"
}
```

## Output

Conforme à `assets/schemas/critic_output.schema.json` :

```json
{
  "audit_id": "2026-01-06T06:04:12Z",
  "status": "approved",
  "claims_audited": 12,
  "claims_grounded": 11,
  "claims_inferred": 1,
  "claims_unsupported": 0,
  "score": 95,
  "audited_claims": [
    {
      "path": "submission.detection.attacker_ips[0]",
      "value": "203.0.113.45",
      "verdict": "grounded",
      "evidence_in_logs": "Première occurrence à 02:14:33Z avec status=failure ; total 2842 occurrences distinctes sur la fenêtre.",
      "comment": ""
    },
    {
      "path": "submission.detection.indicators.geolocation",
      "value": "Beijing",
      "verdict": "grounded",
      "evidence_in_logs": "Les 2 IPs ont geolocation_country=China dans les logs auth ; geolocation_lat/lon résolvent à Pékin.",
      "comment": ""
    },
    {
      "path": "enrichment.remediation[3]",
      "value": "Bloquer le port 4444 sortant sur les serveurs web",
      "verdict": "inferred",
      "evidence_in_logs": "Une tentative destination_port=4444 observée à 04:24:01Z.",
      "comment": "Recommandation actionnable mais l'extrapolation 'sur les serveurs web' n'est pas explicite — c'est une inférence raisonnable."
    }
  ],
  "issues": [],
  "patches": []
}
```

## Verdicts possibles

Pour chaque affirmation, un des trois verdicts :

| Verdict | Définition | Action |
|---|---|---|
| `grounded` | Au moins une ligne de log supporte directement la valeur | OK |
| `inferred` | Pas de support direct mais inférence raisonnable depuis plusieurs lignes | OK si reasoning explicité, sinon downgrade |
| `unsupported` | Aucun support et inférence non triviale (= hallucination) | **Bloquant** |

## Statut global

Calculé à partir des verdicts :

```python
unsupported_count = sum(1 for c in audited_claims if c.verdict == "unsupported")
inferred_count    = sum(1 for c in audited_claims if c.verdict == "inferred")

if unsupported_count == 0 and inferred_count <= 2:
    status = "approved"
elif unsupported_count == 0 and inferred_count > 2:
    status = "approved_with_warnings"
elif unsupported_count <= 2:
    status = "needs_revision"   # patcher les claims unsupported et relancer
else:
    status = "rejected"          # fallback : soumettre la détection brute sans enrichissement
```

## Champs critiques à auditer en priorité

Ces champs ont le plus d'impact sur le scoring jury — le modèle CRITIQUE doit s'y attarder :

1. `submission.detection.attacker_ips` — chaque IP doit être grounded (sinon F1 chute)
2. `submission.detection.victim_accounts` — un username inventé tue le critère
3. `submission.detection.attack_start_time` / `attack_end_time` — ±5 min sinon perte
4. `submission.detection.indicators.*` — chaque clé/valeur doit être grounded
5. `enrichment.mitre_techniques[].id` — doit être un vrai T-id (pas T9999.99)

## Patches en cas de `needs_revision`

Si `status = "needs_revision"`, le mode CRITIQUE doit produire un array `patches` qui dit **comment** corriger :

```json
"patches": [
  {
    "path": "submission.detection.indicators.web_shell",
    "current_value": "/admin/shell.php",
    "action": "remove",
    "reason": "Aucune occurrence de /admin/shell.php dans les logs. Le seul fichier suspect observé est /uploads/image_2026.php."
  },
  {
    "path": "submission.detection.indicators.web_shell",
    "current_value": null,
    "action": "set",
    "new_value": "/uploads/image_2026.php",
    "reason": "Observé en POST à 04:23:12Z."
  }
]
```

Le code Python applique les patches automatiquement et relance soit RECOMMANDATION (régénérer), soit submit directement (si patches simples).

## Garde-fous

CRITIQUE doit lui-même éviter les pièges :

1. **Ne pas inventer de preuves**. Si une affirmation semble vraie mais que les logs fournis ne la supportent pas, verdict = `unsupported`, pas `grounded`.
2. **Ne pas faire confiance au reasoning de RECOMMANDATION**. Auditer les valeurs, pas la justification.
3. **Distinguer omission et hallucination**. Si RECOMMANDATION omet `web_shell` parce qu'il n'a pas trouvé, c'est OK. Si RECOMMANDATION l'invente, c'est `unsupported`.
4. **Toujours produire au moins un audited_claim par valeur soumise**. Pas de "j'ai relu, ça va" générique.

## Coût et bénéfice

CRITIQUE rajoute un appel Bedrock supplémentaire par détection (~3000-5000 tokens). Sur 5 challenges DS1 c'est ~25k tokens additionnels — négligeable face à l'enjeu (le critère anti-hallucination du jury peut peser 20+ pts).

**À ne pas zapper même sous pression de temps.** Si vraiment urgent (< 30s avant le buzzer), faire CRITIQUE en mode dégradé : ne vérifier que les 5 champs critiques (cf. liste ci-dessus) au lieu de tout.

## Format d'appel API

```python
import boto3, json

client = boto3.client("bedrock-runtime", region_name="eu-west-3")

with open("assets/prompts/critic_system_prompt.txt") as f:
    system_prompt = f.read()

user_message = json.dumps({
    "recommendation_to_audit": recommendation_dict,
    "log_excerpt": log_lines_list
})

response = client.converse(
    modelId="anthropic.claude-opus-4-6-v1",
    system=[{"text": system_prompt}],
    messages=[{"role": "user", "content": [{"text": user_message}]}],
    inferenceConfig={"maxTokens": 3072, "temperature": 0}
)

critique = json.loads(response["output"]["message"]["content"][0]["text"])

if critique["status"] == "approved":
    submit(recommendation_dict["submission"])
elif critique["status"] == "approved_with_warnings":
    log_warnings(critique)
    submit(recommendation_dict["submission"])
elif critique["status"] == "needs_revision":
    patched = apply_patches(recommendation_dict, critique["patches"])
    # option 1: re-soumettre directement
    submit(patched["submission"])
    # option 2: relancer RECOMMANDATION avec un hint
elif critique["status"] == "rejected":
    # Fallback : soumettre la détection brute sans enrichissement LLM
    submit(raw_detection_to_submission(raw_detection))
```

## Pourquoi un appel séparé et pas un seul appel "génère + critique"

Test empirique : un seul appel "fais X puis vérifie X" produit ~3x moins de détections d'hallucinations qu'un appel séparé avec un prompt opposé. Le modèle a tendance à confirmer ce qu'il vient de produire (sycophancie). La séparation force un point de vue extérieur.

**Donc : ne jamais merger les deux appels, même pour gagner du temps ou des tokens.**
