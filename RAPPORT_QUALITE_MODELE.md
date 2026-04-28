# Rapport de qualite du modele de detection (DS1)

Date: 2026-04-28  
Dataset evalue: `data/opensearch-export/logs-raw-merged.parquet` (21,017,848 lignes)  
Mode d'execution: `pipeline.py --no-bedrock` (dedup active)

## 1) Resume executif

La pipeline detecte correctement les 5 attaques attendues du ground truth DS1, sans faux positifs apres deduplication.  
La precision sur le type d'attaque, les IPs attaquantes et les comptes victimes est excellente.  
La faiblesse principale reste le calage temporel de fin d'attaque (`attack_end_time`), souvent trop tot ou trop tard par rapport a la fenetre officielle.

## 2) Resultats globaux

- Logs lus: 21,017,848
- Repartition:
  - Auth total: 4,421,439 (failures: 459,154)
  - Application: 4,992,297
  - Network: 8,610,311
  - System: 2,993,801
- Detections finales: 5
- Couverture challenges DS1: 5/5
- Faux positifs finaux: 0

## 3) Comparaison vs ground truth

### Match global

- Attack type: 5/5 correct
- Attacker IPs: F1 = 1.00 sur les 5 challenges
- Victim accounts: F1 = 1.00 sur les 5 challenges
- IoC (presence des bons indicateurs): tres bon alignement

### Ecart temporel observe (point faible principal)

- `credential_stuffing`: fin detectee ~52 min trop tot
- `ssh_brute_force`: fin detectee ~62 min trop tot
- `sql_injection`: fin detectee ~29 min trop tot
- `directory_traversal`: fin detectee ~37 min trop tot
- `ssrf`: fin detectee ~13 min trop tard

Impact: risque de perte de points sur le critere timeline (meme avec un excellent match sur le reste).

## 4) Qualite du modele: forces

- Regles heuristiques bien calibrees pour DS1 (1 detection pertinente par challenge).
- Bon compromis precision/rappel sur ce dataset, sans sur-generation finale.
- Deduplication efficace (`keep_most_specific`) pour eliminer les detections redondantes.
- IoC techniques utiles et exploitables pour l'analyse (exfiltration, cibles internes, web shell, etc.).
- Latence de traitement faible pour la phase detection.

## 5) Faiblesses a corriger en priorite

1. **Fenetre temporelle imparfaite**
   - `attack_end_time` est parfois coupee trop tot ou prolongee trop tard.
   - C'est le principal facteur limitant le score maximal.

2. **Generalisation non prouvee hors DS1**
   - Le systeme est tres bon sur les 5 patterns connus, mais on manque d'evaluation OOD (attaques proches, bruit, variations).

3. **Dependance aux seuils statiques**
   - Les seuils fixes fonctionnent ici, mais peuvent se degrader si la distribution des logs change.

4. **Sensibilite au format IoC attendu**
   - Certains indicateurs ont des noms differents de ceux du ground truth (`failed_ssh` vs `total_ssh_failures`, etc.), ce qui peut etre tolere ou non selon la logique de scoring.

## 6) Axes d'amelioration concrets

### Court terme (gains score rapides)

- Ajouter un post-traitement de timeline par type d'attaque:
  - etendre/reduire `attack_end_time` avec une regle de stabilite (ex: "dernier evenement malveillant + buffer borne").
  - borner dans la campagne active plutot que sur le dernier evenement brut.
- Normaliser les noms d'indicateurs vers les cles attendues par la spec de soumission.
- Ajouter un script de "pre-score local" pour verifier type/IP/accounts/timeline/IoC avant envoi API.

### Moyen terme (robustesse)

- Mettre en place une calibration automatique des seuils par tranche temporelle ou par baseline de trafic.
- Ajouter un mode de validation croisee sur des sous-periodes du dataset.
- Journaliser des metriques de qualite a chaque run (precision challenge, ecarts timeline, FP/FN estimes).

### Long terme (qualite modele)

- Introduire un scoring de confiance par detection et un calibrage de confiance.
- Enrichir la dedup avec une logique de causalite multi-sources (auth/app/net/sys) pour mieux fixer debut/fin.
- Construire un banc de tests de regression securite (jeu de cas synthetiques + cas limites).

## 7) Conclusion

Le modele est deja performant pour l'objectif hackathon DS1: detection complete, propre, et sans faux positifs finaux.  
Pour viser un score plus proche du maximum, la priorite est claire: ameliorer la precision de la timeline, surtout la fin d'attaque, tout en conservant les excellents resultats actuels sur type/IP/comptes/IoC.
