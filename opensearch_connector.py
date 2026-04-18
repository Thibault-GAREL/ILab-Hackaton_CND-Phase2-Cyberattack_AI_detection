"""
Connecteur OpenSearch pour la pipeline temps reel (finale).

Interroge l'index logs-raw toutes les OPENSEARCH_POLL_INTERVAL_S secondes,
recupere les nouveaux logs via search_after (pagination sans scroll expiry),
et retourne un DataFrame pret pour les detecteurs.

Auth : AWS SigV4 via boto3 (credentials SSO ou env vars).
"""

import json
import time
import boto3
import requests
import pandas as pd
from datetime import datetime, timezone
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from config import (
    OPENSEARCH_HOST,
    OPENSEARCH_INDEX,
    OPENSEARCH_REGION,
    OPENSEARCH_POLL_INTERVAL_S,
    OPENSEARCH_PAGE_SIZE,
    OPENSEARCH_STATE_FILE,
)


class OpenSearchConnector:
    def __init__(self):
        self.host    = OPENSEARCH_HOST.rstrip("/")
        self.index   = OPENSEARCH_INDEX
        self.region  = OPENSEARCH_REGION
        self.session = boto3.Session()

    def _signed_request(self, method: str, url: str, body: dict) -> requests.Response:
        """Envoie une requete signee SigV4 vers OpenSearch."""
        creds = self.session.get_credentials().get_frozen_credentials()
        body_bytes = json.dumps(body).encode("utf-8")

        aws_req = AWSRequest(method=method, url=url, data=body_bytes,
                             headers={"Content-Type": "application/json"})
        SigV4Auth(creds, "es", self.region).add_auth(aws_req)

        return requests.request(
            method=method,
            url=url,
            data=body_bytes,
            headers=dict(aws_req.headers),
            timeout=30,
        )

    def _search(self, query: dict) -> dict:
        url  = f"{self.host}/{self.index}/_search"
        resp = self._signed_request("POST", url, query)
        resp.raise_for_status()
        return resp.json()

    def fetch_since(self, since_ts: str) -> pd.DataFrame:
        """
        Recupere tous les logs posterieurs a since_ts (ISO 8601 UTC).
        Utilise search_after pour paginer sans limite de taille.
        """
        all_docs = []
        sort_values = None  # curseur search_after

        base_query = {
            "query": {
                "range": {"timestamp": {"gt": since_ts}}
            },
            "sort": [
                {"timestamp": {"order": "asc"}},
                {"_id":       {"order": "asc"}},    # tie-breaker stable
            ],
            "size": OPENSEARCH_PAGE_SIZE,
        }

        while True:
            query = dict(base_query)
            if sort_values:
                query["search_after"] = sort_values

            try:
                result = self._search(query)
            except requests.HTTPError as e:
                print(f"[OpenSearch] HTTP error: {e}")
                break

            hits = result.get("hits", {}).get("hits", [])
            if not hits:
                break

            all_docs.extend(h["_source"] for h in hits)
            sort_values = hits[-1]["sort"]

            if len(hits) < OPENSEARCH_PAGE_SIZE:
                break  # derniere page

        if not all_docs:
            return pd.DataFrame()

        df = pd.DataFrame(all_docs)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")

        print(f"[OpenSearch] {len(df)} nouveaux logs depuis {since_ts}")
        return df


# ---------------------------------------------------------------------------
# Gestion de l'etat (dernier timestamp traite)
# ---------------------------------------------------------------------------

def load_last_timestamp() -> str:
    """Charge le dernier timestamp traite depuis le fichier d'etat."""
    try:
        with open(OPENSEARCH_STATE_FILE) as f:
            state = json.load(f)
            return state.get("last_timestamp", "2026-01-31T00:00:00Z")
    except FileNotFoundError:
        return "2026-01-31T00:00:00Z"  # debut du flux continu selon le guide


def save_last_timestamp(ts: str) -> None:
    with open(OPENSEARCH_STATE_FILE, "w") as f:
        json.dump({"last_timestamp": ts, "updated_at": _now_iso()}, f)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
