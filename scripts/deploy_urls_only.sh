#!/usr/bin/env bash
# Rafraîchit uniquement deploy-urls.env (IP publique du service ECS) — sans build Docker.
# Utile si deploy_aws.sh a fini avant que la tâche soit RUNNING.
#
# Usage : bash scripts/deploy_urls_only.sh
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
URL_FILE="${DEPLOY_URL_FILE:-${REPO_ROOT}/deploy-urls.env}"

REGION="${AWS_REGION:-eu-west-3}"
ECS_CLUSTER="${ECS_CLUSTER:-dirisi-hackathon-cluster}"
ECS_SERVICE="${ECS_SERVICE:-dirisi-hackathon-service}"
ECS_TASK_DEFINITION="${ECS_TASK_DEFINITION:-dirisi-hackathon-task:6}"
ECS_NO_TASK_DEFINITION="${ECS_NO_TASK_DEFINITION:-0}"

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

PUBLIC_IP=$(ecs_service_public_ip || true)
ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
td="${ECS_TASK_DEFINITION}"
[[ "${ECS_NO_TASK_DEFINITION}" == "1" ]] && td="(inchangée — ECS_NO_TASK_DEFINITION=1)"

if [[ -z "${PUBLIC_IP}" || "${PUBLIC_IP}" == "None" ]]; then
  cat > "${URL_FILE}" << EOF
# deploy_urls_only.sh ${ts}
# PUBLIC_IP indisponible.
AWS_REGION=${REGION}
ECS_CLUSTER=${ECS_CLUSTER}
ECS_SERVICE=${ECS_SERVICE}
ECS_TASK_DEFINITION=${td}
PUBLIC_IP=
EOF
  echo "IP publique introuvable. Réessayez plus tard ou vérifiez ECS."
  exit 1
fi

host=$(ip_to_ec2_hostname "${PUBLIC_IP}")
cat > "${URL_FILE}" << EOF
# deploy_urls_only.sh ${ts}
AWS_REGION=${REGION}
ECS_CLUSTER=${ECS_CLUSTER}
ECS_SERVICE=${ECS_SERVICE}
ECS_TASK_DEFINITION=${td}
PUBLIC_IP=${PUBLIC_IP}
PUBLIC_HOST=${host}
FRONTEND_URL=http://${PUBLIC_IP}:3000
API_URL=http://${PUBLIC_IP}:8080
API_DOCS_URL=http://${PUBLIC_IP}:8080/docs
API_HEALTH_URL=http://${PUBLIC_IP}:8080/health
FRONTEND_URL_DNS=http://${host}:3000
API_URL_DNS=http://${host}:8080
EOF

echo "Écrit : ${URL_FILE}"
cat "${URL_FILE}"
