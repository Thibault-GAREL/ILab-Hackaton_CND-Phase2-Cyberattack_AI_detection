#!/usr/bin/env bash
# =============================================================================
# Déploiement complet : ECR + ECS Fargate (dirisi-hackathon)
#
# Usage (depuis la racine du dépôt) :
#   bash scripts/deploy_aws.sh
#   DOCKER_NO_CACHE=0 bash scripts/deploy_aws.sh          # build plus rapide
#   DEPLOY_SKIP_WAIT=1 bash scripts/deploy_aws.sh         # ne pas attendre ECS stable
#
# Par défaut : task definition dirisi-hackathon-task:6 (secrets OpenSearch, etc.)
# Pour ne pas passer --task-definition (garder celle du service) :
#   ECS_NO_TASK_DEFINITION=1 bash scripts/deploy_aws.sh
#
# ARM64 Fargate : DOCKER_PLATFORM=linux/arm64 bash scripts/deploy_aws.sh
#
# Variables : AWS_REGION, AWS_PROFILE, ECS_CLUSTER, ECS_SERVICE, ECS_TASK_DEFINITION
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
URL_FILE="${DEPLOY_URL_FILE:-${REPO_ROOT}/deploy-urls.env}"

REGION="${AWS_REGION:-eu-west-3}"
ECS_CLUSTER="${ECS_CLUSTER:-dirisi-hackathon-cluster}"
ECS_SERVICE="${ECS_SERVICE:-dirisi-hackathon-service}"
# Révision connue (secrets + ports) — surcharge possible : ECS_TASK_DEFINITION=dirisi-hackathon-task:7
ECS_TASK_DEFINITION="${ECS_TASK_DEFINITION:-dirisi-hackathon-task:6}"
ECS_NO_TASK_DEFINITION="${ECS_NO_TASK_DEFINITION:-0}"

DEPLOY_SKIP_WAIT="${DEPLOY_SKIP_WAIT:-0}"
DOCKER_NO_CACHE="${DOCKER_NO_CACHE:-1}"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-}"

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "UNKNOWN")
ECR_BACKEND_REPO="${ECR_BACKEND_REPO:-dirisi-backend}"
ECR_FRONTEND_REPO="${ECR_FRONTEND_REPO:-dirisi-frontend}"
ECR_BACKEND="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_BACKEND_REPO}"
ECR_FRONTEND="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_FRONTEND_REPO}"

GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo "nogit")"
GIT_DIRTY=""
git diff --quiet 2>/dev/null || GIT_DIRTY="-dirty"

docker_build() {
  local dockerfile="$1"
  local tag="$2"
  if [[ -n "${DOCKER_PLATFORM}" ]]; then
    docker buildx build --platform "${DOCKER_PLATFORM}" --load "${BUILD_EXTRA[@]}" -f "${dockerfile}" -t "${tag}" .
  else
    docker build "${BUILD_EXTRA[@]}" -f "${dockerfile}" -t "${tag}" .
  fi
}

# IP publique de la tâche RUNNING (première) du service
ecs_service_public_ip() {
  local task_arn
  task_arn=$(aws ecs list-tasks \
    --region "${REGION}" \
    --cluster "${ECS_CLUSTER}" \
    --service-name "${ECS_SERVICE}" \
    --desired-status RUNNING \
    --query 'taskArns[0]' \
    --output text 2>/dev/null || true)
  if [[ -z "${task_arn}" || "${task_arn}" == "None" ]]; then
    echo ""
    return 1
  fi
  local eni
  eni=$(aws ecs describe-tasks \
    --region "${REGION}" \
    --cluster "${ECS_CLUSTER}" \
    --tasks "${task_arn}" \
    --query 'tasks[0].attachments[0].details[?name==`networkInterfaceId`].value | [0]' \
    --output text 2>/dev/null || true)
  if [[ -z "${eni}" || "${eni}" == "None" ]]; then
    echo ""
    return 1
  fi
  aws ec2 describe-network-interfaces \
    --region "${REGION}" \
    --network-interface-ids "${eni}" \
    --query 'NetworkInterfaces[0].Association.PublicIp' \
    --output text 2>/dev/null || echo ""
}

ip_to_ec2_hostname() {
  local ip="$1"
  local r="${2:-${REGION}}"
  [[ -z "${ip}" ]] && { echo ""; return; }
  echo "ec2-$(echo "${ip}" | tr '.' '-').${r}.compute.amazonaws.com"
}

write_url_file() {
  local ip="$1"
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local td="${ECS_TASK_DEFINITION:-}"
  [[ "${ECS_NO_TASK_DEFINITION}" == "1" ]] && td="(inchangée — ECS_NO_TASK_DEFINITION=1)"
  if [[ -z "${ip}" ]]; then
    cat > "${URL_FILE}" << EOF
# Généré par scripts/deploy_aws.sh le ${ts}
# PUBLIC_IP indisponible (attendez la fin du déploiement ou relancez le script sans build).
AWS_REGION=${REGION}
ECS_CLUSTER=${ECS_CLUSTER}
ECS_SERVICE=${ECS_SERVICE}
ECS_TASK_DEFINITION=${td}
PUBLIC_IP=
EOF
    return
  fi
  local host
  host=$(ip_to_ec2_hostname "${ip}")
  cat > "${URL_FILE}" << EOF
# Généré par scripts/deploy_aws.sh le ${ts}
# Utilisation : set -a && source deploy-urls.env && set +a
AWS_REGION=${REGION}
ECS_CLUSTER=${ECS_CLUSTER}
ECS_SERVICE=${ECS_SERVICE}
ECS_TASK_DEFINITION=${td}
PUBLIC_IP=${ip}
PUBLIC_HOST=${host}
FRONTEND_URL=http://${ip}:3000
API_URL=http://${ip}:8080
API_DOCS_URL=http://${ip}:8080/docs
API_HEALTH_URL=http://${ip}:8080/health
FRONTEND_URL_DNS=http://${host}:3000
API_URL_DNS=http://${host}:8080
EOF
}

BUILD_EXTRA=()
if [[ "${DOCKER_NO_CACHE}" != "0" ]]; then
  BUILD_EXTRA+=(--no-cache)
fi
BUILD_EXTRA+=(--pull)

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  CND Phase 2 — Déploiement AWS (ECR + ECS)"
echo "═══════════════════════════════════════════════════════════════════"
echo "Dépôt       : ${REPO_ROOT}"
echo "Git         : ${GIT_SHA}${GIT_DIRTY}"
echo "Région      : ${REGION}"
echo "Compte      : ${ACCOUNT_ID}"
echo "Cluster     : ${ECS_CLUSTER}"
echo "Service     : ${ECS_SERVICE}"
if [[ "${ECS_NO_TASK_DEFINITION}" == "1" ]]; then
  echo "Task def    : (inchangée — ECS_NO_TASK_DEFINITION=1)"
else
  echo "Task def    : ${ECS_TASK_DEFINITION}"
fi
echo "ECR         : ${ECR_BACKEND_REPO}, ${ECR_FRONTEND_REPO}"
echo ""

echo "[1/7] Login ECR..."
aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

echo "[2/7] Dépôts ECR..."
aws ecr describe-repositories --repository-names "${ECR_BACKEND_REPO}" --region "${REGION}" 2>/dev/null || \
  aws ecr create-repository --repository-name "${ECR_BACKEND_REPO}" --region "${REGION}"
aws ecr describe-repositories --repository-names "${ECR_FRONTEND_REPO}" --region "${REGION}" 2>/dev/null || \
  aws ecr create-repository --repository-name "${ECR_FRONTEND_REPO}" --region "${REGION}"

echo "[3/7] Build images (contexte = racine du dépôt)..."
if [[ -n "${DOCKER_PLATFORM}" ]]; then
  echo "Plateforme : ${DOCKER_PLATFORM}"
fi
docker_build backend/docker/Dockerfile cnd-backend:latest
docker_build frontend/Dockerfile.streamlit cnd-frontend:latest

echo "[4/7] Push ECR (latest + ${GIT_SHA})..."
docker tag cnd-backend:latest "${ECR_BACKEND}:latest"
docker tag cnd-frontend:latest "${ECR_FRONTEND}:latest"
docker tag cnd-backend:latest "${ECR_BACKEND}:${GIT_SHA}${GIT_DIRTY}"
docker tag cnd-frontend:latest "${ECR_FRONTEND}:${GIT_SHA}${GIT_DIRTY}"

docker push "${ECR_BACKEND}:latest"
docker push "${ECR_FRONTEND}:latest"
docker push "${ECR_BACKEND}:${GIT_SHA}${GIT_DIRTY}" || true
docker push "${ECR_FRONTEND}:${GIT_SHA}${GIT_DIRTY}" || true

echo "[5/7] Mise à jour du service ECS..."
UPDATE_ARGS=(
  --region "${REGION}"
  --cluster "${ECS_CLUSTER}"
  --service "${ECS_SERVICE}"
  --force-new-deployment
)
if [[ "${ECS_NO_TASK_DEFINITION}" != "1" ]]; then
  UPDATE_ARGS+=(--task-definition "${ECS_TASK_DEFINITION}")
  echo "  → task-definition ${ECS_TASK_DEFINITION}"
else
  echo "  → (sans --task-definition, déploiement image uniquement)"
fi

aws ecs update-service "${UPDATE_ARGS[@]}" >/dev/null
echo "  Service mis à jour."

echo "[6/7] Attente stabilisation du service..."
if [[ "${DEPLOY_SKIP_WAIT}" == "1" ]]; then
  echo "  DEPLOY_SKIP_WAIT=1 — attente ignorée (l’IP peut être vide ou ancienne)."
else
  echo "  (peut prendre plusieurs minutes — Ctrl+C pour quitter sans bloquer le déploiement AWS)"
  aws ecs wait services-stable \
    --region "${REGION}" \
    --cluster "${ECS_CLUSTER}" \
    --services "${ECS_SERVICE}" \
    || { echo "  AVERTISSEMENT : timeout ou erreur sur services-stable — vérifiez la console ECS."; }
fi

echo "[7/7] URL publiques..."

# Try ALB DNS first (stable URL)
ALB_STACK="${ALB_STACK_NAME:-cnd-phase2-alb}"
ALB_DNS=$(aws cloudformation describe-stacks \
  --region "${REGION}" \
  --stack-name "${ALB_STACK}" \
  --query 'Stacks[0].Outputs[?OutputKey==`ALBDnsName`].OutputValue | [0]' \
  --output text 2>/dev/null || echo "None")

if [[ -n "${ALB_DNS}" && "${ALB_DNS}" != "None" ]]; then
  _alb_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  cat > "${URL_FILE}" << EOF
# scripts/deploy_aws.sh ${_alb_ts} — ALB stable
AWS_REGION=${REGION}
ECS_CLUSTER=${ECS_CLUSTER}
ECS_SERVICE=${ECS_SERVICE}
ALB_DNS=${ALB_DNS}
FRONTEND_URL=http://${ALB_DNS}
API_URL=http://${ALB_DNS}:8080
API_DOCS_URL=http://${ALB_DNS}:8080/docs
API_HEALTH_URL=http://${ALB_DNS}:8080/health
EOF
  echo ""
  echo "  URL STABLE (ALB) :"
  echo "  Frontend : http://${ALB_DNS}"
  echo "  API docs : http://${ALB_DNS}:8080/docs"
  cat "${URL_FILE}"
else
  # Fallback to task public IP
  PUBLIC_IP=""
  for _try in 1 2 3 4 5 6 7 8 9 10; do
    PUBLIC_IP=$(ecs_service_public_ip || true)
    if [[ -n "${PUBLIC_IP}" && "${PUBLIC_IP}" != "None" ]]; then
      break
    fi
    sleep 6
  done


  if [[ -z "${PUBLIC_IP}" || "${PUBLIC_IP}" == "None" ]]; then
    echo ""
    echo "  IP publique introuvable (tache pas encore RUNNING)."
    echo "  Reessayez : bash scripts/deploy_urls_only.sh"
    echo "  Pour une URL stable : bash infra/deploy_alb.sh"
    write_url_file ""
  else
    write_url_file "${PUBLIC_IP}"
    echo ""
    echo "  Frontend : http://${PUBLIC_IP}:3000"
    echo "  API docs : http://${PUBLIC_IP}:8080/docs"
    echo ""
    echo "  ATTENTION : cette IP change a chaque redeploiement."
    echo "  Pour une URL stable : bash infra/deploy_alb.sh"
    cat "${URL_FILE}"
  fi
fi

echo ""
echo "Digest backend local : $(docker inspect --format='{{index .RepoDigests 0}}' cnd-backend:latest 2>/dev/null || echo '?')"
echo "Termine."
