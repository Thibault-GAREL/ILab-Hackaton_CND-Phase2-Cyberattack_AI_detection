"""
Lambda : un poll OpenSearch + detections + soumissions API.

Variables d'environnement (voir sam/template.yaml et sam/README.md).
"""

from __future__ import annotations

import json
import os
import sys

_root = os.environ.get("LAMBDA_TASK_ROOT", "/var/task")
if _root not in sys.path:
    sys.path.insert(0, _root)


def lambda_handler(event, context):
    os.environ.setdefault("DETECTIONS_JSON_PATH", "/tmp/detections.json")
    os.environ.setdefault("DETECTIONS_API_JSON_PATH", "/tmp/detections_api.json")

    from pipeline.opensearch_connector import OpenSearchConnector
    from pipeline.pipeline import process_one_poll

    dry = os.environ.get("SUBMIT_DRY_RUN", "").lower() in ("1", "true", "yes")
    md = os.environ.get("POLL_MAX_DOCS", "").strip()
    max_docs = int(md) if md else None

    connector = OpenSearchConnector()
    attacks = process_one_poll(
        connector,
        max_docs=max_docs,
        use_dedup=True,
        submit_live=not dry,
        submit_dry=dry,
        dry_run_state=os.environ.get("SKIP_CURSOR_SAVE", "").lower()
        in ("1", "true", "yes"),
    )
    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "detections": len(attacks),
                "dry_run_submit": dry,
            }
        ),
    }
