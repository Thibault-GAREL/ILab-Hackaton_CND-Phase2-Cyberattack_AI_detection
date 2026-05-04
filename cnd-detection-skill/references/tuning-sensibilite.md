# Mode TUNING — Réglage automatique de la sensibilité

Ce mode pilote l'ajustement des 5 seuils déterministes de `config.py` à partir de :
1. les logs de la fenêtre récente,
2. l'historique des scores (`scores_history.json`),
3. (optionnel) le ground truth si disponible (calibrage offline avec `ground-truth-ds1.json`).

## Objectif

Maximiser le score total = `Σ (pts par challenge gagné) − 10 × Σ FP + bonus_rapidité`.

Compte tenu du barème (−10 pts/FP, jusqu'à −100 pts par challenge raté), la fonction de coût est asymétrique :

```
coût(seuil) = 100 × P(rater_challenge | seuil) + 10 × E[nb_FP | seuil]
```

Donc : **un seuil n'est trop bas que s'il génère plus de 10 FP par challenge supplémentaire détecté**. C'est le break-even économique.

## Les 5 seuils gouvernés

```python
CREDENTIAL_STUFFING_MIN_401      = 20   # 401 + auth fail non-SSH par IP
CAMPAIGN_OVERLAP_MINUTES         = 90   # tolérance pour fusionner deux IPs
SSH_BRUTE_FORCE_MIN_FAILURES     = 20   # échecs SSH par IP
SQL_INJECTION_MIN_REQUESTS       = 5    # requêtes payload SQL
DIRECTORY_TRAVERSAL_MIN_ATTEMPTS = 3    # tentatives ../
SSRF_MIN_REQUESTS                = 3    # requêtes IP interne
```

## Méthodologie en 4 étapes

### Étape 1 — Mesurer la distribution actuelle

Pour chaque détecteur, calculer (côté Python, à fournir au LLM en entrée) :

- distribution du **signal par IP source** (histogramme : combien d'IPs ont déclenché 1, 5, 10, 50, 100, 500, 5000 fois ?)
- nombre de détections actuelles (avec le seuil courant)
- estimation du nombre de FP potentiels (IPs qui dépassent le seuil mais qui sont des sources connues bénignes : monitoring interne, scanners de vuln, healthchecks)

### Étape 2 — Identifier les modes (vrai signal vs bruit)

Sur un dataset d'attaques réelles, la distribution est typiquement bimodale :

- **mode "bruit"** : 1-10 événements par IP, des centaines de milliers d'IPs
- **mode "attaque"** : 100-10000 événements par une poignée d'IPs

Le seuil optimal vit dans la vallée entre les deux modes. Sur DS1, les ordres de grandeur attendus :

| Détecteur | Vallée typique | Seuil sûr |
|---|---|---|
| credential_stuffing | 20-100 | 20-50 |
| ssh_brute_force | 20-100 | 20-50 |
| sql_injection | 5-30 | 5-10 |
| directory_traversal | 3-20 | 3-5 |
| ssrf | 3-15 | 3-5 |

### Étape 3 — Proposer un ajustement borné

Règles pour chaque proposition :

- **Variation max** : ±50% du seuil courant **par cycle**. Pas de saut brutal.
- **Justification obligatoire** : citer les 2 chiffres clés (volume actuel, FP estimés ou challenge raté).
- **Direction** :
  - Si historique récent montre un FN (challenge connu raté) → **baisser**.
  - Si historique récent montre des FP (>5 détections par challenge présumé) → **monter**.
  - Si pas de signal clair → **ne pas toucher**.

### Étape 4 — Exporter en JSON

Voir `assets/schemas/tuning_output.schema.json`. Format synthétique :

```json
{
  "tuning_cycle_id": "2026-01-15T12:00:00Z",
  "rules_analyzed": 5,
  "recommendations": [
    {
      "rule_id": "CREDENTIAL_STUFFING_MIN_401",
      "current_value": 20,
      "recommended_value": 30,
      "delta_pct": 50,
      "direction": "raise",
      "confidence": "high",
      "evidence": {
        "current_detections": 14,
        "estimated_true_positives": 2,
        "estimated_false_positives": 12,
        "signal_distribution": "Mode bruit jusqu'à 25 ; mode attaque ≥ 200. Seuil 20 capte la queue du bruit."
      },
      "expected_impact": {
        "expected_fp_reduction": 10,
        "expected_fn_risk": "low",
        "score_delta_estimate": "+100 pts (10 FP × 10 pts évités)"
      },
      "reasoning": "Sur les 14 IPs qui dépassent 20 actuellement, 12 ont entre 20 et 30 événements. Aucune n'a de cluster de geolocation suspect ni de pattern temporel typique d'attaque. Monter à 30 garde le challenge réel (>3500 événements pour les vraies IPs) et coupe le bruit.",
      "rollback_criteria": "Si le challenge credential_stuffing n'est plus détecté sur le prochain cycle, redescendre à 20."
    }
  ],
  "rules_skipped": [
    {
      "rule_id": "SSRF_MIN_REQUESTS",
      "reason": "Volume insuffisant dans la fenêtre (3 IPs candidates) pour distinguer signal et bruit."
    }
  ]
}
```

## Garde-fous

Le mode TUNING refuse de produire une recommandation si :

1. **Pas assez de données** — moins de 20 IPs candidates sur la fenêtre pour le détecteur concerné (renvoie `rules_skipped`).
2. **Variation > ±50%** — coupe et propose la borne supérieure du delta autorisé.
3. **Aucune preuve qualitative** — si le modèle ne peut pas citer un fait précis (un ordre de grandeur, une catégorie de FP identifiée), il doit `skip` plutôt qu'inventer.
4. **Conflit avec un score historique connu** — si `scores_history.json` montre que le challenge concerné a été gagné au seuil actuel, monter le seuil exige une preuve forte (mode bruit clairement séparé).

## Cycle de tuning recommandé

- **Avant le hackathon** (offline) : tuning sur le Parquet complet avec `ground-truth-ds1.json` chargé en mémoire pour calibrer les FN.
- **Pendant le hackathon** (en ligne) : tuning toutes les 30-60 min à partir de `scores_history.json` + dernières détections. Le modèle ne touche **jamais** `config.py` directement — il propose, un humain (ou une CI script-only) applique.

## Format d'appel API

Pour appeler ce mode via Bedrock :

1. Charger le prompt système : `assets/prompts/tuning_system_prompt.txt`
2. Construire le user message avec :
   - `current_thresholds` : dict des 5 seuils actuels
   - `signal_distributions` : dict des histogrammes par détecteur (binnés côté Python)
   - `recent_detections` : 20 dernières détections (résumé)
   - `scores_history` : 5 derniers scores avec breakdown
3. Forcer la sortie JSON (mentionné dans le prompt système). Parser et valider via `validate_outputs.py mode="tuning"`.

Voir `assets/examples/tuning_input_example.json` et `assets/examples/tuning_output_example.json`.
