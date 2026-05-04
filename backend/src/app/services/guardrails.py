"""
Garde-fou anti-hallucination : dictionnaire statique d'actions AWS autorisees.

Filtre les remédiations proposees par Bedrock pour bloquer toute action
dangereuse (suppression de ressources, escalade de privileges, etc.).
"""

from __future__ import annotations

from typing import Any

ALLOWED_AWS_ACTIONS: dict[str, dict[str, Any]] = {
    "waf-ip-block": {
        "service": "AWS WAFv2",
        "risk": "low",
        "auto_applicable": True,
        "description": "Bloquer des IPs via IPSet WAF",
    },
    "waf-sqli-managed": {
        "service": "AWS WAFv2",
        "risk": "low",
        "auto_applicable": True,
        "description": "Activer les regles SQLi managees",
    },
    "waf-path-traversal": {
        "service": "AWS WAFv2",
        "risk": "low",
        "auto_applicable": True,
        "description": "Bloquer les patterns de traversal",
    },
    "waf-ssrf-metadata": {
        "service": "AWS WAFv2",
        "risk": "low",
        "auto_applicable": True,
        "description": "Bloquer les IPs internes dans les URIs",
    },
    "waf-rate-uri": {
        "service": "AWS WAFv2",
        "risk": "low",
        "auto_applicable": True,
        "description": "Limitation de debit par URI",
    },
    "nacl-deny-source": {
        "service": "Amazon VPC (NACL)",
        "risk": "low",
        "auto_applicable": True,
        "description": "Bloquer le trafic entrant au niveau NACL",
    },
    "sg-ssh-bastion-only": {
        "service": "Amazon EC2 (SG)",
        "risk": "medium",
        "auto_applicable": False,
        "description": "Restreindre SSH aux bastions uniquement",
    },
    "sg-restrict-egress-shell": {
        "service": "Amazon EC2 (SG)",
        "risk": "medium",
        "auto_applicable": False,
        "description": "Bloquer les ports de reverse shell en egress",
    },
    "sg-egress-review": {
        "service": "Amazon EC2 (SG)",
        "risk": "medium",
        "auto_applicable": False,
        "description": "Auditer les regles egress",
    },
    "cognito-rate": {
        "service": "Amazon Cognito",
        "risk": "medium",
        "auto_applicable": False,
        "description": "Renforcer MFA et limitation de debit",
    },
    "s3-remove-malware": {
        "service": "Amazon S3",
        "risk": "medium",
        "auto_applicable": False,
        "description": "Retirer un objet malveillant specifique",
    },
    "s3-block-public": {
        "service": "Amazon S3",
        "risk": "low",
        "auto_applicable": True,
        "description": "Activer Block Public Access",
    },
    "ssm-audit-keys": {
        "service": "AWS Systems Manager",
        "risk": "low",
        "auto_applicable": True,
        "description": "Auditer les cles SSH et sudoers",
    },
    "guardduty-blockmode": {
        "service": "Amazon GuardDuty",
        "risk": "low",
        "auto_applicable": True,
        "description": "Activer les integrations de blocage",
    },
    "guardduty-investigate": {
        "service": "Amazon GuardDuty",
        "risk": "low",
        "auto_applicable": True,
        "description": "Investiguer les findings",
    },
    "rds-sg-least-privilege": {
        "service": "Amazon RDS",
        "risk": "medium",
        "auto_applicable": False,
        "description": "Restreindre le SG de la base de donnees",
    },
    "vpc-endpoint-imds": {
        "service": "Amazon EC2 (IMDSv2)",
        "risk": "low",
        "auto_applicable": True,
        "description": "Imposer IMDSv2 et hop limit=1",
    },
    "iam-app-role-tighten": {
        "service": "AWS IAM",
        "risk": "medium",
        "auto_applicable": False,
        "description": "Revoir les policies applicatives (lecture seule)",
    },
}

BLOCKED_ACTIONS: dict[str, str] = {
    "iam:DeleteUser": "Suppression de comptes utilisateur interdite",
    "iam:DeleteRole": "Suppression de roles IAM interdite",
    "iam:DeletePolicy": "Suppression de policies IAM interdite",
    "iam:CreateUser": "Creation de comptes non autorisee par le systeme",
    "iam:AttachRolePolicy": "Modification de policies de role interdite en auto",
    "sts:AssumeRole": "Changement de role non autorise en automatique",
    "ec2:TerminateInstances": "Arret d'instances interdit — risque de perte de service",
    "rds:DeleteDBInstance": "Suppression de base de donnees interdite",
    "s3:DeleteBucket": "Suppression de bucket interdite",
    "lambda:DeleteFunction": "Suppression de fonctions Lambda interdite",
    "kms:DisableKey": "Desactivation de cles KMS interdite",
    "organizations:LeaveOrganization": "Separation d'organisation interdite",
}


def validate_remediation(plan: dict[str, Any]) -> dict[str, Any]:
    """
    Valide un plan de remediation : chaque action est marquee approved/blocked/needs_review.
    """
    actions = plan.get("actions", [])
    validated_actions = []
    counts = {"approved": 0, "blocked": 0, "needs_review": 0}

    for action in actions:
        action_id = action.get("id", "")
        automation_hint = action.get("automation_hint", "")

        blocked_reason = _check_blocked(automation_hint)
        if blocked_reason:
            status = "blocked"
            counts["blocked"] += 1
        elif action_id in ALLOWED_AWS_ACTIONS:
            allowed = ALLOWED_AWS_ACTIONS[action_id]
            if allowed["risk"] == "low":
                status = "approved"
                counts["approved"] += 1
            else:
                status = "needs_review"
                counts["needs_review"] += 1
        else:
            status = "needs_review"
            counts["needs_review"] += 1

        validated_actions.append({
            **action,
            "guardrail_status": status,
            "blocked_reason": blocked_reason,
        })

    return {
        "validated": counts["blocked"] == 0,
        "total_actions": len(actions),
        **counts,
        "actions": validated_actions,
    }


def _check_blocked(automation_hint: str) -> str | None:
    """Verifie si une action reference une API AWS bloquee."""
    for api_action, reason in BLOCKED_ACTIONS.items():
        if api_action.lower() in automation_hint.lower():
            return reason
    return None


def get_blocked_actions_catalog() -> dict[str, str]:
    """Catalogue des actions bloquees (pour le frontend)."""
    return dict(BLOCKED_ACTIONS)


def get_allowed_actions_catalog() -> dict[str, dict[str, Any]]:
    """Catalogue des actions autorisees (pour le frontend)."""
    return dict(ALLOWED_AWS_ACTIONS)
