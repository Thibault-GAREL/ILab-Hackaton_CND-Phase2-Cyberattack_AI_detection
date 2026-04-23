# Synthèse — Détection des 5 types d'attaques
## Analyse manuelle vs détecteurs heuristiques + recommandations IA

Date : 2026-04-23 | Dataset : 21M logs (Parquet DS1)

---

## 1. Résultats de l'analyse manuelle

### 1.1 Credential Stuffing
| Élément | Valeur |
|---|---|
| **Attaquants** | `203.0.113.45` (2540 req, 4 succès) + `198.51.100.23` (1056 req, 2 succès) |
| **Victime** | `jdupont` (6 logins réussis via `web` à 04:14) |
| **Fenêtre** | 06 jan 02:00 → 06:00 (ground truth) |
| **Post-exploitation** | Web shell `/uploads/image_2026.php` (05:02-05:07), reverse shell port 4444 |
| **Bruit filtré** | `185.220.101.1/2` : 22K 401 chacune mais 288K succès, 25 failures/h constant sur 30 jours, multi-méthodes (ldap, ssh, certificate, web, api_key) → trafic légitime |

### 1.2 SSH Brute Force
| Élément | Valeur |
|---|---|
| **Attaquants** | `45.33.32.156` (2814 failures) + `198.51.100.89` (1836 failures) |
| **Fenêtre brute force** | 11 jan 01:00 → 02:57 |
| **Post-exploitation** | `sysadmin` sur `bastion-01` : sudo -l (03:03), sudo -i (03:07), cat /etc/sudoers (03:27), useradd backdoor (03:34), sudoers modifié (03:35) |
| **Fenêtre complète** | 11 jan 01:00 → ~07:00 (avec mouvement latéral + exfil 443/8443) |
| **Victime** | `sysadmin` (compromis via escalade de privilèges, pas via login SSH réussi direct) |
| **Bruit filtré** | `185.220.101.1/2` : 3600+ échecs SSH chacune mais étalés sur 30 jours (~5/h) → bruit de fond |

### 1.3 SQL Injection
| Élément | Valeur |
|---|---|
| **Attaquant** | `185.220.101.45` uniquement |
| **Volume** | 367 payloads SQLi, 27.9 MB exfiltrés |
| **Fenêtre** | 19 jan 14:00 → 16:30 |
| **Signature** | Chrome UA automatisé, payloads UNION SELECT, INFORMATION_SCHEMA |
| **Bruit filtré** | 5 IPs scanners (3-8 requêtes SQLi chacune, 0 MB exfil, UAs sqlmap/python-requests) |

### 1.4 Directory Traversal
| Élément | Valeur |
|---|---|
| **Attaquant principal** | `198.51.100.200` (250 req, 77 succès HTTP 200) |
| **Fenêtre** | 23 jan 10:00 → 11:23 (ground truth → 12:00) |
| **Fichiers sensibles** | /etc/passwd, /etc/shadow, /root/.ssh/id_rsa, /var/log/auth.log, /etc/hosts |
| **Bruit** | 5 IPs scanners (10-25 req, 1-6 succès, UAs DirBuster/python-requests) |

### 1.5 SSRF
| Élément | Valeur |
|---|---|
| **Attaquant** | `203.0.113.100` (300 req) |
| **Fenêtre** | 26 jan 11:00 → 12:13 |
| **Cibles** | 10.0.3.10:3306, 10.0.4.10:389, 169.254.169.254 (AWS metadata) |
| **Bruit** | 5 IPs scanners (10-17 req chacune) |

---

## 2. Comparaison : détecteurs actuels vs analyse manuelle

### Ce qui fonctionne bien ✅
- **Credential stuffing** : IPs, victime, web shell, reverse shell correctement détectés
- **SSH brute force** : IPs, volume, mouvement latéral, escalade de privilèges détectés
- **SQL injection** : après ajustement (seuil 50 + filtre exfil 1MB), seule la vraie attaque est détectée
- **SSRF** : IP et cibles correctement détectées

### Écarts identifiés ⚠️

| Problème | Impact | Cause racine |
|---|---|---|
| **Directory traversal : 6 détections au lieu de 1** | 5 faux positifs (scanners) | Le seuil de 10 requêtes est trop bas pour filtrer les scanners automatiques qui font 10-25 req |
| **SSH victim_accounts : 10 comptes au lieu de `sysadmin`** | Score réduit | Le détecteur cherche un login SSH réussi, mais sysadmin a été compromis via escalade de privilèges (sudo), pas via login SSH direct depuis les IPs attaquantes |
| **Credential stuffing end_time : 04:56 vs 06:00** | Fenêtre trop courte | La post-exploitation (web shell 05:02-05:07) n'est pas incluse dans la fenêtre car elle vient de l'IP attaquante sur les logs app, pas réseau |
| **185.220.101.1/2 non filtrées** | Risque de FP si seuils baissés | Ces IPs ont un profil unique : 288K succès + 18K échecs sur 30 jours, multi-méthodes → trafic légitime (probablement un proxy/VPN d'entreprise) |

---

## 3. Règles de détection actuelles

### Credential Stuffing
```
SI  IP externe
ET  nb_401_HTTP >= 20
ET  taux >= 1 req/min
ALORS  détection
+ regroupement en campagne si fenêtres se chevauchent (±90 min)
+ enrichissement : login réussi post-attaque, web shell, reverse shell, géolocalisation
```

### SSH Brute Force
```
SI  IP externe
ET  auth_method == "ssh"
ET  status == "failure"
ET  nb_failures >= 20 par session (gap 30 min)
ET  taux >= 1 failure/min
ALORS  détection
+ regroupement en campagne
+ enrichissement : mouvement latéral (sys logs), escalade (sudo/useradd), exfil (443/8443)
```

### SQL Injection
```
SI  IP externe
ET  URI matche regex SQLi (UNION, SELECT, SLEEP, etc.)
ET  nb_requêtes >= 50
ET  (exfil_bytes >= 1 MB  OU  nb_requêtes >= 200)
ALORS  détection
+ enrichissement : phase de reconnaissance (1h avant), tool signature
```

### Directory Traversal
```
SI  IP externe
ET  URI contient ../ (ou variantes encodées)
ET  nb_requêtes >= 10
ALORS  détection
+ enrichissement : fichiers sensibles accédés, taux de succès HTTP 200
```

### SSRF
```
SI  IP externe
ET  URI contient IP interne (10.x, 192.168.x, 172.16-31.x) ou 169.254.169.254
ET  nb_requêtes >= 10
ALORS  détection
+ enrichissement : trafic réseau interne déclenché, ports ciblés
```

---

## 4. Limites des règles heuristiques

### Ce que les règles ne savent PAS faire :

1. **Distinguer bruit de fond vs attaque réelle** — Les 5 IPs scanners (DirBuster, sqlmap) font 10-25 requêtes de traversal/SSRF. Le seuil seul ne suffit pas : il faudrait analyser le *profil comportemental* (diversité des outils, patterns d'exploration vs exploitation ciblée).

2. **Identifier la victime d'un brute force** — Le ground truth attend `sysadmin` mais ce compte n'a jamais eu de login SSH réussi depuis les IPs attaquantes. La compromission est passée par l'escalade de privilèges (sudo). Relier "brute force → login réussi d'un autre compte → sudo → useradd" nécessite un raisonnement en chaîne.

3. **Calculer la fenêtre temporelle complète** — La post-exploitation (web shell, mouvement latéral, exfil) se produit après l'attaque initiale. Savoir quand s'arrêter nécessite de comprendre la *narration* de l'attaque.

4. **Filtrer les IPs légitimes à fort volume** — 185.220.101.1/2 ont 22K 401 mais aussi 288K succès. Un humain voit immédiatement que c'est un proxy. Une règle doit encoder ce ratio explicitement.

5. **Corréler entre sources de logs** — L'attaque SSH brute force implique auth + system + network. La credential stuffing implique app + auth + network. Les règles traitent chaque source séparément puis tentent de fusionner.

---

## 5. Recommandations : où l'IA apporte de la valeur

### 5.1 Scoring de confiance par LLM (déjà en place via Bedrock)
**Valeur** : Affiner le type d'attaque, ajouter la technique MITRE, proposer une remédiation.
**Limite** : Le LLM voit un échantillon de 10 logs, pas le contexte complet. Il ne peut pas recalculer les seuils.

### 5.2 Classification bruit vs attaque (recommandé — ML léger)
**Idée** : Entraîner un classifieur simple (Random Forest / XGBoost) sur des features par IP :
- Nombre de requêtes
- Durée de l'activité
- Diversité des user-agents
- Ratio succès/échecs
- Nombre de méthodes d'auth distinctes
- Taux de requêtes par minute
- Volume d'exfiltration

**Pourquoi** : Les 5 IPs scanners ont un profil très différent des vraies attaques (multi-outils, peu de requêtes, étalées dans le temps). Un classifieur séparerait ça facilement.

**Implémentation** : ~50 lignes de code, entraînable sur le ground truth DS1, applicable en temps réel.

### 5.3 Chaîne d'attaque par LLM (recommandé — enrichissement)
**Idée** : Après détection heuristique, envoyer à Claude non pas 10 logs mais la *timeline complète* de l'IP (auth + app + sys + net) et lui demander :
- Quel est le compte compromis ?
- Quelle est la fenêtre complète incluant la post-exploitation ?
- Y a-t-il eu mouvement latéral ?

**Pourquoi** : C'est exactement ce qu'un analyste SOC fait. Le LLM excelle à ce type de raisonnement narratif.

**Coût** : ~1 appel Bedrock par détection, ~500 tokens input, ~200 tokens output.

### 5.4 Baseline comportementale (optionnel — si temps réel)
**Idée** : Pour le flux OpenSearch, calculer une baseline par IP (taux normal d'échecs/h) et alerter sur les déviations.

**Pourquoi** : Filtrerait automatiquement 185.220.101.1/2 (baseline stable à 25/h) tout en détectant les pics (3000/h le 11 jan).

### 5.5 Résumé des priorités

| Action | Effort | Impact sur le score | Priorité |
|---|---|---|---|
| Augmenter seuil directory_traversal à 50+ | 1 min | Élimine 5 FP | 🔴 Immédiat |
| Augmenter seuil SSRF à 50+ | 1 min | Élimine 5 FP | 🔴 Immédiat |
| Étendre fenêtre credential stuffing avec web shell | 10 min | +points fenêtre | 🟡 Court terme |
| Identifier victime SSH via logs système (sudo user) | 30 min | +points victime | 🟡 Court terme |
| Classifieur ML bruit/attaque | 2h | Élimine tous les FP | 🟢 Moyen terme |
| Chaîne d'attaque LLM | 1h | +points fenêtre + victime | 🟢 Moyen terme |

---

## 6. Données brutes de l'analyse

### Profil des IPs par catégorie

**Vraies attaques (ground truth) :**
| IP | Type | Requêtes | Exfil | Fenêtre |
|---|---|---|---|---|
| 203.0.113.45 | Credential stuffing | 2540 (4 succès) | Web shell | 06 jan 03:02-05:07 |
| 198.51.100.23 | Credential stuffing | 1056 (2 succès) | — | 06 jan 03:02-04:56 |
| 45.33.32.156 | SSH brute force | 2814 failures | — | 11 jan 01:00-02:57 |
| 198.51.100.89 | SSH brute force | 1836 failures | — | 11 jan 01:00-02:57 |
| 185.220.101.45 | SQL injection | 367 payloads | 27.9 MB | 19 jan 14:30-16:30 |
| 198.51.100.200 | Directory traversal | 250 (77 succès) | Fichiers sensibles | 23 jan 10:00-11:23 |
| 203.0.113.100 | SSRF | 300 | Metadata AWS | 26 jan 11:00-12:13 |

**Scanners automatiques (bruit) :**
| IP | Requêtes app | User-agents | Auth failures |
|---|---|---|---|
| 185.220.101.42 | 56 | python-requests, DirBuster, sqlmap | 41 |
| 194.26.29.100 | 54 | python-requests, DirBuster, sqlmap | 24 |
| 45.155.205.233 | 50 | DirBuster, python-requests, sqlmap | 27 |
| 5.188.86.10 | 53 | python-requests, DirBuster, sqlmap | 32 |
| 91.219.236.100 | 43 | python-requests, DirBuster, sqlmap | 37 |

**Trafic légitime (proxy/VPN) :**
| IP | App requests | 401s | Auth succès | Auth échecs | Méthodes | Durée |
|---|---|---|---|---|---|---|
| 185.220.101.1 | 384K | 22K | 288K | 18K | ldap, ssh, cert, web, api_key | 30 jours |
| 185.220.101.2 | 383K | 22K | 288K | 18K | web, api_key, ldap, ssh, cert | 30 jours |
