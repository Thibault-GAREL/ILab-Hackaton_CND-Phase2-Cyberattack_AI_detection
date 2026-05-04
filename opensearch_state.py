"""
Curseur OpenSearch (dernier timestamp traite) : fichier local ou DynamoDB (Lambda).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import boto3

from config import (
    OPENSEARCH_STATE_BACKEND,
    OPENSEARCH_STATE_DYNAMODB_TABLE,
    OPENSEARCH_STATE_DYNAMODB_PK,
    OPENSEARCH_STATE_FILE,
)

_DEFAULT_LAST = "2026-01-31T00:00:00Z"


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_last_timestamp() -> str:
    backend = (OPENSEARCH_STATE_BACKEND or "file").lower()
    if backend == "dynamodb":
        if not OPENSEARCH_STATE_DYNAMODB_TABLE:
            raise RuntimeError(
                "OPENSEARCH_STATE_BACKEND=dynamodb requiert OPENSEARCH_STATE_DYNAMODB_TABLE"
            )
        client = boto3.client("dynamodb")
        resp = client.get_item(
            TableName=OPENSEARCH_STATE_DYNAMODB_TABLE,
            Key={"pk": {"S": OPENSEARCH_STATE_DYNAMODB_PK}},
        )
        item = resp.get("Item")
        if not item:
            return _DEFAULT_LAST
        return item.get("last_timestamp", {}).get("S", _DEFAULT_LAST)
    try:
        with open(OPENSEARCH_STATE_FILE) as f:
            state = json.load(f)
            return state.get("last_timestamp", _DEFAULT_LAST)
    except FileNotFoundError:
        return _DEFAULT_LAST


def save_last_timestamp(ts: str) -> None:
    backend = (OPENSEARCH_STATE_BACKEND or "file").lower()
    if backend == "dynamodb":
        if not OPENSEARCH_STATE_DYNAMODB_TABLE:
            raise RuntimeError(
                "OPENSEARCH_STATE_BACKEND=dynamodb requiert OPENSEARCH_STATE_DYNAMODB_TABLE"
            )
        client = boto3.client("dynamodb")
        client.put_item(
            TableName=OPENSEARCH_STATE_DYNAMODB_TABLE,
            Item={
                "pk": {"S": OPENSEARCH_STATE_DYNAMODB_PK},
                "last_timestamp": {"S": ts},
                "updated_at": {"S": now_iso_utc()},
            },
        )
        return
    with open(OPENSEARCH_STATE_FILE, "w") as f:
        json.dump({"last_timestamp": ts, "updated_at": now_iso_utc()}, f)
