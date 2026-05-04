# Référence — Format des logs (CND DS1)

Tous les modes du skill consomment ce format. Il provient du Parquet `Dataset_log/logs-raw-merged.parquet` (21M lignes, 33 colonnes) et du flux OpenSearch `logs-raw` (mêmes colonnes).

## Schéma complet

| Colonne | Type | Notes |
|---|---|---|
| `timestamp` | datetime UTC | ISO 8601 attendu en sortie |
| `log_source` | enum | `network` \| `authentication` \| `application` \| `system` |
| `source_ip` | string | IP source (IPv4) |
| `destination_ip` | string | IP destination |
| `source_port` | int | |
| `destination_port` | int | |
| `protocol` | enum | `tcp` \| `udp` \| `icmp` |
| `action` | enum | `accept` \| `reject` |
| `bytes_sent` | int | |
| `bytes_received` | int | |
| `packets` | int | |
| `duration_ms` | int | |
| `username` | string | Auth logs |
| `auth_method` | enum | `web` \| `ssh` \| autres |
| `status` | enum | `success` \| `failure` |
| `hostname` | string | Cible |
| `session_id` | string | |
| `failure_reason` | enum | `invalid_password` \| `account_not_found` \| `invalid_key` \| `expired_token` \| `account_locked` |
| `geolocation_lat` | float | |
| `geolocation_lon` | float | |
| `geolocation_country` | string | |
| `http_method` | enum | `GET` \| `POST` \| `PUT` \| `DELETE` \| `HEAD` |
| `uri` | string | URI HTTP |
| `status_code` | int | Code HTTP |
| `response_size` | int | |
| `user_agent` | string | |
| `referer` | string | |
| `response_time_ms` | int | |
| `severity` | enum | `info` \| `notice` \| `warning` \| `error` \| `critical` |
| `process` | string | Logs système |
| `pid` | int | |
| `message` | string | Message brut système |
| `facility` | string | Facility syslog |

## Filtres rapides par log_source

```python
auth_logs = df[df.log_source == "authentication"]
app_logs  = df[df.log_source == "application"]
net_logs  = df[df.log_source == "network"]
sys_logs  = df[df.log_source == "system"]
```

## Convention de citation dans les sorties LLM

Pour ancrer une affirmation, le modèle doit citer **soit** :
- un timestamp précis ISO 8601 + une IP : `"2026-01-06T02:14:33Z source_ip=203.0.113.45"`
- un `session_id`
- un range de timestamps : `"2026-01-06T02:00:00Z..06:00:00Z"` avec un compteur (`count=3500`)

**Ne jamais** citer un numéro de ligne brut du Parquet — il n'est pas stable d'une exécution à l'autre.

## Dimensionnement attendu (DS1)

Volumes typiques par challenge (utiles pour calibrer les seuils) :

| Challenge | Volume signal | IP attaquante typique | Fenêtre |
|---|---|---|---|
| credential_stuffing | ~3500 échecs (auth fail + 401) | externe non européenne | 4h |
| ssh_brute_force | ~4600 échecs SSH | externe | 6h |
| sql_injection | ~300 requêtes payload SQL | externe | 3h |
| directory_traversal | N tentatives (~75 lectures réussies) | externe | 2h |
| ssrf | Quelques dizaines de requêtes vers IPs internes | externe | 1h |

Le bruit de fond sur le dataset complet est large (21M logs), donc des seuils trop bas génèrent vite des FP. Voir `tuning-sensibilite.md` pour le calibrage.
