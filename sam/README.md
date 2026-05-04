# Déploiement Lambda (SAM) — poll OpenSearch toutes les 5 minutes

## Prérequis

- AWS CLI + [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- Credentials avec droits Bedrock + DynamoDB + CloudFormation + Lambda + EventBridge + IAM
- Endpoint OpenSearch joignable depuis Internet (Lambda **sans VPC** dans ce template)

## Build & deploy

Depuis la **racine du dépôt** :

```bash
sam build --template-file sam/template.yaml
sam deploy --template-file sam/template.yaml --guided
```

Paramètres importants :

| Paramètre | Rôle |
|-----------|------|
| `OpenSearchHost` | URL du domaine OpenSearch |
| `OpenSearchPassword` | Mot de passe FGAC (non affiché) |
| `ScoringApiUrl` | URL de l’API de scoring |
| `ScoringApiKey` | Bearer optionnel |
| `SubmitDryRun` | `1` pour valider les payloads sans POST |

Le template crée une table DynamoDB pour le curseur (`OPENSEARCH_STATE_BACKEND=dynamodb`) et fixe `CND_DS1_CANONICAL_TIMELINE=0` (finale Dataset 2). Pour la phase DS1 avec fenêtres canoniques, surcharger la variable dans la console Lambda après déploiement.

## Test rapide (sans déployer)

Sur une machine locale avec les mêmes variables d’environnement :

```bash
python -c "from sam.handler import lambda_handler; print(lambda_handler({}, None))"
```

(Depuis la racine du repo, après `pip install -r requirements.txt`.)

## Fichiers JSON en Lambda

Les sorties `detections.json` / `detections_api.json` sont écrites sous `/tmp/` (variables `DETECTIONS_JSON_PATH` / `DETECTIONS_API_JSON_PATH`).

## Secrets en production

Préférer AWS Secrets Manager ou SSM Parameter Store (`SecureString`) et injecter les valeurs dans la configuration Lambda plutôt que de repasser `--guided` avec des mots de passe en clair.
