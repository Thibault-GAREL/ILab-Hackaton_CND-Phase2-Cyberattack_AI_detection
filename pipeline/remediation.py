"""
Propositions de remédiation AWS par type d'attaque (exigence hackathon).

Ne déclenche aucune action en production : structure informative pour validation
humaine (ex. Streamlit) et pour extension future (Step Functions, SSM Automation).

Les clés racine `remediation` sont ignorées par submit.normalize_scoring_payload.
"""

from __future__ import annotations

from typing import Any

# Types DS1 + clé générique pour fusions dedup (attack_type avec +)
KNOWN_CHALLENGES = frozenset({
    "credential_stuffing",
    "ssh_brute_force",
    "sql_injection",
    "directory_traversal",
    "ssrf",
    "multi_vector",
})


def _ips_param(ips: list[str]) -> dict[str, Any]:
    return {"attacker_ips": [str(x) for x in ips if x]}


def _action(
    action_id: str,
    category: str,
    aws_service: str,
    title: str,
    description: str,
    automation: str,
    parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": action_id,
        "category": category,
        "aws_service": aws_service,
        "title": title,
        "description": description,
        "automation_hint": automation,
        "parameters": parameters or {},
    }


def _playbook_credential_stuffing(ips: list[str], det: dict) -> list[dict[str, Any]]:
    ind = det.get("indicators") or {}
    victims = det.get("victim_accounts") or []
    web_shell = ind.get("web_shell")
    actions = [
        _action(
            "waf-ip-block",
            "contain",
            "AWS WAFv2",
            "Bloquer les IP sources au bord (ALB / API Gateway)",
            "Créer ou mettre à jour une IPSet REGIONAL avec les IP attaquantes, "
            "puis règle de blocage associée au WebACL du load balancer exposé.",
            "wafv2:CreateIPSet / UpdateIPSet ; AssociateWebACL",
            {**_ips_param(ips), "scope": "REGIONAL"},
        ),
        _action(
            "cognito-rate",
            "contain",
            "Amazon Cognito",
            "Renforcer la limitation de débit et la MFA sur le pool concerné",
            "Ajuster AdvancedSecurityMode, limites de tentative et alertes "
            "CloudWatch sur signInThreshold.",
            "cognito-idp:DescribeUserPool / UpdateUserPool",
            {"victim_accounts": list(victims)},
        ),
    ]
    if web_shell:
        actions.append(
            _action(
                "s3-remove-malware",
                "eradicate",
                "Amazon S3",
                "Retirer la web shell référencée des buckets applicatifs",
                f"Invalider l'objet malveillant identifié ({web_shell!r}), "
                "versioning et audit CloudTrail sur préfixe uploads/.",
                "s3:DeleteObject ; s3:GetObjectVersion",
                {"object_uri_or_key": str(web_shell)},
            )
        )
    actions.append(
        _action(
            "sg-restrict-egress-shell",
            "contain",
            "Amazon EC2 (Security Group)",
            "Restreindre le trafic sortant suspect (reverse shell)",
            "Règle egress deny ou alerte sur ports non standards (ex. 4444) "
            "pour les SG des instances web touchées.",
            "ec2:AuthorizeSecurityGroupEgress / RevokeSecurityGroupEgress",
            {"suggested_ports_to_block": [4444]},
        )
    )
    return actions


def _playbook_ssh_brute_force(ips: list[str], det: dict) -> list[dict[str, Any]]:
    ind = det.get("indicators") or {}
    lateral = ind.get("lateral_targets") or []
    return [
        _action(
            "nacl-deny-source",
            "contain",
            "Amazon VPC (Network ACL)",
            "Refuser le trafic entrant des IP attaquantes au niveau sous-réseau",
            "Entrées NACL deny numérotées en basse priorité pour les CIDR sources, "
            "sans impacter le trafic légitime du bastion.",
            "ec2:CreateNetworkAclEntry",
            _ips_param(ips),
        ),
        _action(
            "sg-ssh-bastion-only",
            "contain",
            "Amazon EC2 (Security Group)",
            "Limiter SSH (22) aux bastions / préfixes d'administration uniquement",
            "Retirer 0.0.0.0/0 sur le port 22 ; autoriser uniquement le SG bastion "
            "ou la plage IP du bastion.",
            "ec2:RevokeSecurityGroupIngress ; AuthorizeSecurityGroupIngress",
            {"port": 22, "lateral_targets_observed": list(lateral)[:20]},
        ),
        _action(
            "ssm-audit-keys",
            "eradicate",
            "AWS Systems Manager",
            "Auditer authorized_keys et sudoers sur les hôtes listés",
            "Run Command ou State Manager sur les instances (hostname / tags) "
            "pour détecter clés non autorisées et comptes backdoor.",
            "ssm:SendCommand ; ssm:ListCommandInvocations",
            {"target_hostnames": list(lateral)[:30]},
        ),
        _action(
            "guardduty-blockmode",
            "contain",
            "Amazon GuardDuty",
            "Activer les intégrations de blocage (WAF / NACL) si disponibles",
            "Exporter les findings SSH brute force vers EventBridge puis "
            "remédiation automatisée (playbook).",
            "guardduty:ListFindings ; events:PutRule",
            {},
        ),
    ]


def _playbook_sql_injection(ips: list[str], det: dict) -> list[dict[str, Any]]:
    ind = det.get("indicators") or {}
    return [
        _action(
            "waf-sqli-managed",
            "contain",
            "AWS WAFv2",
            "Activer AWSManagedRulesSQLiRuleSet et règles custom sur URI / corps",
            "Associer le rule set managé au WebACL de l'application concernée.",
            "wafv2:CreateWebACL / UpdateWebACL",
            _ips_param(ips),
        ),
        _action(
            "rds-sg-least-privilege",
            "contain",
            "Amazon RDS",
            "Restreindre le Security Group base de données au tier applicatif",
            "RDS ne doit accepter que le SG des instances applicatives, pas le CIDR VPC entier.",
            "rds:ModifyDBInstance ; ec2:DescribeSecurityGroups",
            {"exfil_bytes_hint": ind.get("exfil_bytes")},
        ),
        _action(
            "waf-rate-uri",
            "contain",
            "AWS WAFv2",
            "Règle à base de débit sur les URI sensibles",
            "Limiter les requêtes par IP sur les endpoints dynamiques (POST /search, etc.).",
            "wafv2:CreateRateBasedRule",
            {},
        ),
    ]


def _playbook_directory_traversal(ips: list[str], det: dict) -> list[dict[str, Any]]:
    return [
        _action(
            "waf-path-traversal",
            "contain",
            "AWS WAFv2",
            "Bloquer les séquences encodées et ../ dans URI",
            "Règles regex sur URI normalisée ; AWSManagedRulesKnownBadInputsRuleSet.",
            "wafv2:UpdateWebACL",
            _ips_param(ips),
        ),
        _action(
            "s3-block-public",
            "recover",
            "Amazon S3",
            "Vérifier Block Public Access sur les buckets exposant du contenu statique",
            "Empêcher la lecture anonyme de chemins sensibles via origine web.",
            "s3:PutPublicAccessBlock",
            {},
        ),
        _action(
            "iam-app-role-tighten",
            "recover",
            "AWS IAM",
            "Revoir les policies du rôle applicatif (s3:GetObject limité par préfixe)",
            "Principe du moindre privilège sur les ARNs de ressources.",
            "iam:GetRolePolicy ; iam:PutRolePolicy",
            {},
        ),
    ]


def _playbook_ssrf(ips: list[str], det: dict) -> list[dict[str, Any]]:
    ind = det.get("indicators") or {}
    targets = ind.get("ssrf_targets") or []
    return [
        _action(
            "waf-ssrf-metadata",
            "contain",
            "AWS WAFv2",
            "Bloquer 169.254.169.254 et plages internes dans les arguments URI",
            "Règles custom sur query string / body ; AWSManagedRulesAnonymousIpList en complément.",
            "wafv2:UpdateWebACL",
            {**_ips_param(ips), "ssrf_targets": list(targets)[:20]},
        ),
        _action(
            "vpc-endpoint-imds",
            "contain",
            "Amazon EC2 (IMDSv2)",
            "Imposer IMDSv2 et hop limit=1 sur les instances applicatives",
            "Réduit l'impact SSRF vers les métadonnées instance.",
            "ec2:ModifyInstanceMetadataOptions",
            {},
        ),
        _action(
            "sg-egress-review",
            "contain",
            "Amazon EC2 (Security Group)",
            "Auditer les règles egress vers metadata / ports internes",
            "Restreindre le trafic sortant des SG des serveurs web vers 3306/389 internes si non requis.",
            "ec2:DescribeSecurityGroups ; RevokeSecurityGroupEgress",
            {},
        ),
    ]


def _playbook_multi_vector(ips: list[str], det: dict) -> list[dict[str, Any]]:
    """Fusion dedup : combiner les actions minimales communes."""
    return [
        _action(
            "waf-ip-block",
            "contain",
            "AWS WAFv2",
            "Bloquer les IP sources (multi-vecteur)",
            "IPSet + règle de blocage prioritaire en attendant l'analyse détaillée.",
            "wafv2:UpdateIPSet",
            _ips_param(ips),
        ),
        _action(
            "guardduty-investigate",
            "recover",
            "Amazon GuardDuty",
            "Créer un finding archivé après investigation et playbook runbook",
            "Coordonner conteneur / EC2 / IAM selon les indicateurs fusionnés.",
            "guardduty:GetFindings",
            {"attack_type": det.get("attack_type", "")},
        ),
    ]


_PLAYBOOK_BUILDERS: dict[str, Any] = {
    "credential_stuffing": _playbook_credential_stuffing,
    "ssh_brute_force": _playbook_ssh_brute_force,
    "sql_injection": _playbook_sql_injection,
    "directory_traversal": _playbook_directory_traversal,
    "ssrf": _playbook_ssrf,
    "multi_vector": _playbook_multi_vector,
}


def build_remediation_plan(detection: dict[str, Any]) -> dict[str, Any]:
    """
    Construit un plan de remédiation AWS à partir d'une détection pipeline
    (challenge_id + detection.*).
    """
    cid = str(detection.get("challenge_id") or "").strip()
    det = detection.get("detection") if isinstance(detection.get("detection"), dict) else {}
    attack_type = str(det.get("attack_type") or cid or "unknown")
    ips = det.get("attacker_ips") if isinstance(det.get("attacker_ips"), list) else []

    key = cid if cid in KNOWN_CHALLENGES else ""
    if not key and "+" in attack_type:
        key = "multi_vector"
    if not key and attack_type in KNOWN_CHALLENGES:
        key = attack_type
    if not key:
        key = "multi_vector" if ips else cid or "unknown"

    builder = _PLAYBOOK_BUILDERS.get(key)
    if builder is None:
        builder = _playbook_multi_vector

    actions = builder([str(x) for x in ips], det)

    return {
        "version": "1.0",
        "challenge_id": cid or attack_type,
        "attack_type": attack_type,
        "summary": (
            "Actions AWS proposées à valider avant exécution ; aucun appel API "
            "n'est effectué par ce module."
        ),
        "actions": actions,
    }


def attach_remediation_plans(detections: list[dict[str, Any]]) -> None:
    """En place : ajoute la clé `remediation` sur chaque détection."""
    for d in detections:
        if not isinstance(d, dict):
            continue
        d["remediation"] = build_remediation_plan(d)


def remediation_playbooks_catalog() -> dict[str, Any]:
    """Aperçu statique des playbooks (pour future route API ou doc)."""
    out: dict[str, Any] = {}
    for cid, builder in _PLAYBOOK_BUILDERS.items():
        sample = builder(
            ["198.51.100.1"],
            {"attack_type": cid, "victim_accounts": [], "indicators": {}},
        )
        out[cid] = {
            "action_count": len(sample),
            "action_ids": [a["id"] for a in sample],
        }
    return out
