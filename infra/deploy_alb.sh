#!/usr/bin/env bash
# =============================================================================
# Deploy ALB for CND Phase 2 ECS service (one-time setup).
#
# Prerequisites:
#   - ECS service already running (dirisi-hackathon-service)
#   - AWS CLI configured (aws configure sso / AWS_PROFILE)
#
# Usage:
#   bash infra/deploy_alb.sh
#
# After deployment:
#   - Update ECS service to use the ALB target groups
#   - The ALB DNS name will be stable across task restarts
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

REGION="${AWS_REGION:-eu-west-3}"
STACK_NAME="${ALB_STACK_NAME:-cnd-phase2-alb}"
ECS_CLUSTER="${ECS_CLUSTER:-dirisi-hackathon-cluster}"
ECS_SERVICE="${ECS_SERVICE:-dirisi-hackathon-service}"

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  CND Phase 2 — Déploiement ALB (CloudFormation)"
echo "═══════════════════════════════════════════════════════════════════"
echo "Région  : ${REGION}"
echo "Stack   : ${STACK_NAME}"
echo ""

# Discover VPC, subnets, and security group from the running ECS task
echo "[1/4] Découverte de l'infrastructure ECS existante..."

TASK_ARN=$(aws ecs list-tasks \
  --region "${REGION}" \
  --cluster "${ECS_CLUSTER}" \
  --service-name "${ECS_SERVICE}" \
  --desired-status RUNNING \
  --query 'taskArns[0]' \
  --output text 2>/dev/null || echo "None")

if [[ -z "${TASK_ARN}" || "${TASK_ARN}" == "None" ]]; then
  echo "ERREUR: Aucune tâche RUNNING trouvée dans ${ECS_CLUSTER}/${ECS_SERVICE}."
  echo "Démarrez le service ECS d'abord : bash scripts/deploy_aws.sh"
  exit 1
fi

ENI=$(aws ecs describe-tasks \
  --region "${REGION}" \
  --cluster "${ECS_CLUSTER}" \
  --tasks "${TASK_ARN}" \
  --query 'tasks[0].attachments[0].details[?name==`networkInterfaceId`].value | [0]' \
  --output text)

ENI_INFO=$(aws ec2 describe-network-interfaces \
  --region "${REGION}" \
  --network-interface-ids "${ENI}" \
  --query 'NetworkInterfaces[0]')

VPC_ID=$(echo "${ENI_INFO}" | python3 -c "import sys,json; print(json.load(sys.stdin)['VpcId'])")
SUBNET_ID=$(echo "${ENI_INFO}" | python3 -c "import sys,json; print(json.load(sys.stdin)['SubnetId'])")
SG_ID=$(echo "${ENI_INFO}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Groups'][0]['GroupId'])")

# Get at least 2 subnets in different AZs for the ALB
ALL_SUBNETS=$(aws ec2 describe-subnets \
  --region "${REGION}" \
  --filters "Name=vpc-id,Values=${VPC_ID}" "Name=map-public-ip-on-launch,Values=true" \
  --query 'Subnets[].SubnetId' \
  --output text | tr '\t' ',')

if [[ -z "${ALL_SUBNETS}" ]]; then
  ALL_SUBNETS="${SUBNET_ID}"
fi

echo "  VPC     : ${VPC_ID}"
echo "  Subnets : ${ALL_SUBNETS}"
echo "  ECS SG  : ${SG_ID}"

echo ""
echo "[2/4] Déploiement du stack CloudFormation ${STACK_NAME}..."

aws cloudformation deploy \
  --region "${REGION}" \
  --stack-name "${STACK_NAME}" \
  --template-file infra/alb-cloudformation.yaml \
  --parameter-overrides \
    "VpcId=${VPC_ID}" \
    "SubnetIds=${ALL_SUBNETS}" \
    "ECSSecurityGroupId=${SG_ID}" \
    "ECSServiceName=${ECS_SERVICE}" \
    "ECSClusterName=${ECS_CLUSTER}" \
  --capabilities CAPABILITY_IAM \
  --no-fail-on-empty-changeset

echo ""
echo "[3/4] Récupération des outputs..."

ALB_DNS=$(aws cloudformation describe-stacks \
  --region "${REGION}" \
  --stack-name "${STACK_NAME}" \
  --query 'Stacks[0].Outputs[?OutputKey==`ALBDnsName`].OutputValue | [0]' \
  --output text)

FRONTEND_TG_ARN=$(aws cloudformation describe-stacks \
  --region "${REGION}" \
  --stack-name "${STACK_NAME}" \
  --query 'Stacks[0].Outputs[?OutputKey==`FrontendTargetGroupArn`].OutputValue | [0]' \
  --output text)

BACKEND_TG_ARN=$(aws cloudformation describe-stacks \
  --region "${REGION}" \
  --stack-name "${STACK_NAME}" \
  --query 'Stacks[0].Outputs[?OutputKey==`BackendTargetGroupArn`].OutputValue | [0]' \
  --output text)

echo "  ALB DNS         : ${ALB_DNS}"
echo "  Frontend TG ARN : ${FRONTEND_TG_ARN}"
echo "  Backend TG ARN  : ${BACKEND_TG_ARN}"

echo ""
echo "[4/4] Mise à jour du service ECS avec les target groups ALB..."

aws ecs update-service \
  --region "${REGION}" \
  --cluster "${ECS_CLUSTER}" \
  --service "${ECS_SERVICE}" \
  --load-balancers \
    "targetGroupArn=${FRONTEND_TG_ARN},containerName=frontend,containerPort=3000" \
    "targetGroupArn=${BACKEND_TG_ARN},containerName=backend,containerPort=8080" \
  --force-new-deployment >/dev/null

echo "  Service ECS mis à jour avec les load balancers."

# Write URLs
URL_FILE="${REPO_ROOT}/deploy-urls.env"
TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
cat > "${URL_FILE}" << EOF
# Généré par infra/deploy_alb.sh le ${TS}
# ALB stable DNS — ne change pas entre les redéploiements
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
echo "───────────────────────────────────────────────────────────────────"
echo "  Fichier écrit : ${URL_FILE}"
echo "───────────────────────────────────────────────────────────────────"
cat "${URL_FILE}"
echo "───────────────────────────────────────────────────────────────────"
echo ""
echo "  Frontend : http://${ALB_DNS}"
echo "  API docs : http://${ALB_DNS}:8080/docs"
echo ""
echo "  Cette URL est STABLE — elle ne change plus entre les redéploiements."
echo ""
echo "  N'oubliez pas de mettre à jour CORS_ORIGINS dans la task definition :"
echo "    http://${ALB_DNS},http://${ALB_DNS}:3000"
echo ""
echo "Terminé."
