---
title: "Guide de déploiement AWS"
version: "2.0"
project: "CND Hackathon Phase 2"
last_updated: "2026-05-04"
audience: ["ia", "humain", "jury"]
---

# Déploiement AWS

Région : **eu-west-3** (Paris).

## Prérequis

- Compte AWS avec accès SSO (invitation CND)
- AWS CLI v2 + SAM CLI installés
- Docker (pour build des images ECR)
- Python 3.10+

```bash
aws configure sso --region eu-west-3
aws sts get-caller-identity  # vérifier l'accès
```

## 1. Pipeline temps réel — Lambda + EventBridge

Déploiement via AWS SAM depuis `sam/`.

```bash
cd sam
sam build --template-file template.yaml
sam deploy --guided \
  --stack-name cnd-pipeline \
  --region eu-west-3 \
  --capabilities CAPABILITY_IAM
```

**Configuration SAM** :
- **Runtime** : Python 3.10
- **Timeout** : 300s
- **Mémoire** : 512 MB
- **Trigger** : EventBridge `rate(5 minutes)`
- **Curseur** : DynamoDB (table `cnd-pipeline-cursor`, clé `PIPELINE_CURSOR`)

Variables d'environnement Lambda :

| Variable | Description |
|---|---|
| `OPENSEARCH_HOST` | URL du domaine OpenSearch |
| `OPENSEARCH_BASIC_USER` | Utilisateur FGAC |
| `OPENSEARCH_BASIC_PASSWORD` | Mot de passe (via Secrets Manager recommandé) |
| `OPENSEARCH_STATE_BACKEND` | `dynamodb` |
| `OPENSEARCH_STATE_DYNAMODB_TABLE` | Nom de la table DynamoDB |
| `BEDROCK_REGION` | `eu-west-3` |
| `SCORING_API_URL` | URL POST de l'API de scoring |
| `SCORING_API_KEY` | Clé API (optionnelle) |

## 2. Backend + Frontend — ECS Fargate

### 2.1 Build et push des images ECR

Le **contexte Docker** est la **racine du dépôt** (les `Dockerfile` font `COPY backend/...` et `COPY pipeline/...` / `COPY frontend/...`).

```bash
# Depuis la racine du repo
aws ecr get-login-password --region eu-west-3 | \
  docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.eu-west-3.amazonaws.com

docker build -f backend/docker/Dockerfile -t backend:local .
docker build -f frontend/Dockerfile.streamlit -t frontend:local .

# Repos ECR utilisés par le service ECS `dirisi-hackathon-service` : **dirisi-backend** / **dirisi-frontend**
docker tag backend:local <ACCOUNT_ID>.dkr.ecr.eu-west-3.amazonaws.com/dirisi-backend:latest
docker tag frontend:local <ACCOUNT_ID>.dkr.ecr.eu-west-3.amazonaws.com/dirisi-frontend:latest
docker push <ACCOUNT_ID>.dkr.ecr.eu-west-3.amazonaws.com/dirisi-backend:latest
docker push <ACCOUNT_ID>.dkr.ecr.eu-west-3.amazonaws.com/dirisi-frontend:latest
```

Script tout-en-un (build, push, `update-service`) : `bash scripts/deploy_aws.sh`  
Variables optionnelles : `ECS_CLUSTER` (défaut `dirisi-hackathon-cluster`), `ECS_SERVICE` (défaut `dirisi-hackathon-service`).

**Backend dans l’image** : le code est sous `/app/src/` pour correspondre à la commande ECS `uvicorn src.app.main:app` (`PYTHONPATH=/app/src:/app`). Ne pas utiliser `app.main:app` seul dans la task si la structure copiée est celle du Dockerfile du repo.

**Fargate ARM64 (Graviton)** : si la capacité est `ARM64` et que vous buildez sur une machine d’une autre architecture, utilisez par exemple  
`DOCKER_PLATFORM=linux/arm64 bash scripts/deploy_aws.sh` (nécessite Docker Buildx).

### 2.2 ECS Fargate — service dirisi-hackathon (sans ALB)

Déploiement de référence hackathon :

| Élément | Valeur |
|---|---|
| Région | `eu-west-3` |
| Compte (exemple) | `432837989348` |
| Cluster | `dirisi-hackathon-cluster` |
| Cluster ARN | `arn:aws:ecs:eu-west-3:432837989348:cluster/dirisi-hackathon-cluster` |
| Service | `dirisi-hackathon-service` |
| Load balancer | **Aucun** (`loadBalancers` vide) |
| IP publique tâche | **Activée** (`assignPublicIp: ENABLED`) — accès par **ENI** (pas d’ALB) |

**Tâche multi-conteneurs (recommandé)** : backend + frontend dans la même définition de tâche, même namespace réseau.

- **Backend** : port conteneur **8080** (mappé sur l’hôte en **8080**).
- **Frontend Streamlit** : port conteneur **3000** (sur Fargate awsvpc, l’ENI publique expose ce même port — pas de translation `3000→8501`).

**`BACKEND_URL` côté conteneur frontend** (appels `requests` Python **depuis le pod** vers l’API) :  
`http://127.0.0.1:8080` (ou `http://localhost:8080`). Ne pas utiliser l’IP publique de l’ENI pour le trafic interne conteneur → conteneur.

**`CORS_ORIGINS` côté backend** (origine **du navigateur**, page Streamlit sur le port **3000**), par exemple :

```text
CORS_ORIGINS=http://51.44.250.151:3000,http://ec2-51-44-250-151.eu-west-3.compute.amazonaws.com:3000
```

L’IP **change** à chaque redéploiement. Exemples d’URL (à mettre à jour après chaque déploiement) :

| Usage | URL (exemple documenté) |
|---|---|
| Frontend | `http://51.44.250.151:3000` |
| API / docs | `http://51.44.250.151:8080` |
| DNS public (équivalent) | `http://ec2-51-44-250-151.eu-west-3.compute.amazonaws.com:3000` / `:8080` |

**Récupérer l’IP publique actuelle de la tâche** :

```bash
AWS_PROFILE=entreprise aws ecs list-tasks --region eu-west-3 \
  --cluster dirisi-hackathon-cluster --service-name dirisi-hackathon-service --desired-status RUNNING \
  --query 'taskArns[0]' --output text | xargs -I{} aws ecs describe-tasks --region eu-west-3 \
  --cluster dirisi-hackathon-cluster --tasks {} \
  --query 'tasks[0].attachments[0].details[?name==`networkInterfaceId`].value | [0]' --output text \
| xargs -I{} aws ec2 describe-network-interfaces --region eu-west-3 --network-interface-ids {} \
  --query 'NetworkInterfaces[0].Association.PublicIp' --output text
```

Mettre à jour **`CORS_ORIGINS`** sur le backend quand l’IP change, ou utiliser un hostname stable si vous en ajoutez un.

**Docker Compose local** : conserver `BACKEND_URL=http://backend:8080` (réseau bridge du compose).

Exemple de définition de tâche : [`infra/ecs-task-definition.json`](infra/ecs-task-definition.json) (adapter les ARNs IAM et les images ECR à votre compte / rôles réels).

#### OpenSearch — mot de passe FGAC sur ECS

Le fichier `.env` **n’est pas** dans l’image Docker : la pipeline (`POST .../pipeline/run`) lit **`OPENSEARCH_BASIC_PASSWORD`** depuis **l’environnement du conteneur backend** (comme en local avec `export`).

À faire dans **ECS** → **Task definition** → conteneur **backend** :

1. **Nouvelle révision** de la définition de tâche utilisée par `dirisi-hackathon-service`.
2. Ajouter une variable sensible (recommandé : **Secrets Manager**) :
   - Créer un secret dans **AWS Secrets Manager** (ex. nom `cnd/opensearch`, clé JSON `password` ou secret texte brut).
   - Dans la définition du conteneur backend, section **Secrets** :  
     `OPENSEARCH_BASIC_PASSWORD` → ARN du secret (suffixe `-xxxxxx` inclus dans la console).
   - Le rôle d’**exécution** ECS (`ecsTaskExecutionRole`) doit autoriser `secretsmanager:GetSecretValue` sur ce secret.

   Ou, pour un test rapide : **Environment** → ajouter `OPENSEARCH_BASIC_PASSWORD` avec la valeur fournie par l’organisation (éviter de committer cette valeur dans Git).

3. Variables déjà prévues dans le dépôt ([`infra/ecs-task-definition.json`](infra/ecs-task-definition.json)) :  
   `OPENSEARCH_AUTH=basic`, `OPENSEARCH_BASIC_USER=etudiant`. Il manque volontairement le mot de passe dans le JSON versionné.

4. Redéployer le service (**Deploy** ou `bash scripts/deploy_aws.sh` après `register-task-definition` si vous versionnez la définition).

Sans `OPENSEARCH_BASIC_PASSWORD`, l’erreur côté pipeline est du type :  
`OPENSEARCH_AUTH=basic requiert OPENSEARCH_BASIC_USER et OPENSEARCH_BASIC_PASSWORD`.

### 2.3 Réseau et sécurité (schéma général)

- VPC : subnets publics pour ENI avec IP publique (service sans ALB).
- Security group de la tâche : ouvertures inbound **3000** et **8080** depuis les clients (jury / Internet) selon politique du hackathon.
- Sortie Internet : NAT ou subnet public pour OpenSearch, Bedrock, API de scoring.

## 3. Permissions IAM

### Rôle Lambda (`cnd-pipeline-lambda-role`)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:Converse"
      ],
      "Resource": "arn:aws:bedrock:eu-west-3::foundation-model/anthropic.claude-*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem"
      ],
      "Resource": "arn:aws:dynamodb:eu-west-3:*:table/cnd-pipeline-cursor"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

### Rôle ECS Task (`cnd-ecs-task-role`)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:Converse"
      ],
      "Resource": "arn:aws:bedrock:eu-west-3::foundation-model/anthropic.claude-*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::cnd-hackathon-*/*"
    }
  ]
}
```

## 4. Développement local

### Docker Compose

```bash
cd frontend
make docker-up
# Backend : http://localhost:8080/docs
# Frontend : http://localhost:3000
```

### Sans Docker

Terminal 1 — Backend :
```bash
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
PYTHONPATH=src uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

Terminal 2 — Frontend :
```bash
cd frontend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
BACKEND_URL=http://127.0.0.1:8080 streamlit run streamlit_app.py --server.port 3000
```

Terminal 3 — Pipeline :
```bash
python -m pipeline --loop --submit
```

## 5. Checklist jour J

- [ ] `aws configure sso` + vérifier `aws sts get-caller-identity`
- [ ] Remplir `pipeline/.env` (OPENSEARCH_BASIC_PASSWORD, SCORING_API_URL)
- [ ] Tester `python -m pipeline --submit-dry-run`
- [ ] Lancer `python -m pipeline --loop --submit`
- [ ] (Optionnel) Déployer SAM pour la Lambda EventBridge
- [ ] Vérifier `detections.json` : 5 challenges, ni plus ni moins
- [ ] Consulter `scores_history.json` après soumission
