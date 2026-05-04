"""
Connecteur OpenSearch pour la pipeline temps reel (finale).

Recupere les nouveaux logs via search_after (pagination sans scroll expiry).

Auth :
  - sigv4 (defaut) : IAM / SSO via requests-aws4auth (service es ou aoss)
  - basic : FGAC (OPENSEARCH_BASIC_USER / OPENSEARCH_BASIC_PASSWORD)

403 Forbidden : en general policy du domaine (ARN role manquant) ou FGAC sans mapping ;
  voir commentaires dans config.py (OPENSEARCH_AUTH=basic).
"""

from __future__ import annotations

import json
import boto3
import requests
import pandas as pd
from requests_aws4auth import AWS4Auth

from config import (
    OPENSEARCH_HOST,
    OPENSEARCH_INDEX,
    OPENSEARCH_REGION,
    OPENSEARCH_PAGE_SIZE,
    OPENSEARCH_AUTH,
    OPENSEARCH_BASIC_USER,
    OPENSEARCH_BASIC_PASSWORD,
    OPENSEARCH_TIMESTAMP_FIELD,
    OPENSEARCH_SIGV4_SERVICE,
)


class OpenSearchConnector:
    def __init__(self):
        self.host = OPENSEARCH_HOST.rstrip("/")
        self.index = OPENSEARCH_INDEX
        self.region = OPENSEARCH_REGION
        self.ts_field = OPENSEARCH_TIMESTAMP_FIELD
        self.auth_mode = (OPENSEARCH_AUTH or "sigv4").lower()
        self.sigv4_service = (OPENSEARCH_SIGV4_SERVICE or "es").strip()
        self.session = boto3.Session()

    def _aws4_auth(self) -> AWS4Auth:
        """SigV4 pour Amazon OpenSearch Service (service es) ou Serverless (aoss)."""
        creds = self.session.get_credentials()
        if creds is None:
            raise RuntimeError(
                "Pas de credentials AWS pour SigV4. Exportez AWS_PROFILE ou lancez aws sso login."
            )
        fc = creds.get_frozen_credentials()
        return AWS4Auth(
            fc.access_key,
            fc.secret_key,
            self.region,
            self.sigv4_service,
            session_token=fc.token,
        )

    def _http_post(self, url: str, body: dict) -> requests.Response:
        body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if self.auth_mode == "basic":
            if not OPENSEARCH_BASIC_USER or not OPENSEARCH_BASIC_PASSWORD:
                raise RuntimeError(
                    "OPENSEARCH_AUTH=basic requiert OPENSEARCH_BASIC_USER et "
                    "OPENSEARCH_BASIC_PASSWORD (fichier `.env` depuis `.env.example`)."
                )
            resp = requests.post(
                url,
                data=body_bytes,
                headers=headers,
                auth=(OPENSEARCH_BASIC_USER, OPENSEARCH_BASIC_PASSWORD),
                timeout=120,
            )
        else:
            resp = requests.post(
                url,
                data=body_bytes,
                headers=headers,
                auth=self._aws4_auth(),
                timeout=120,
            )
        if not resp.ok:
            snippet = (resp.text or "")[:2500]
            err = requests.HTTPError(
                f"{resp.status_code} {resp.reason} for {resp.url}\n--- response ---\n{snippet}"
            )
            err.response = resp
            raise err
        return resp

    def _search(self, query: dict) -> dict:
        url = f"{self.host}/{self.index}/_search"
        resp = self._http_post(url, query)
        return resp.json()

    def fetch_since(
        self, since_ts: str, max_docs: int | None = None
    ) -> pd.DataFrame:
        """
        Recupere les logs posterieurs a since_ts (ISO 8601 UTC).
        Pagination search_after ; tronque a max_docs si defini.
        """
        all_docs: list = []
        sort_values = None
        ts = self.ts_field

        base_query = {
            "query": {"range": {ts: {"gt": since_ts}}},
            "sort": [
                {ts: {"order": "asc"}},
                {"_id": {"order": "asc"}},
            ],
            "size": OPENSEARCH_PAGE_SIZE,
        }

        while True:
            if max_docs is not None and len(all_docs) >= max_docs:
                break
            query = dict(base_query)
            if sort_values:
                query["search_after"] = sort_values
            page_size = OPENSEARCH_PAGE_SIZE
            if max_docs is not None:
                remain = max_docs - len(all_docs)
                if remain <= 0:
                    break
                page_size = min(page_size, remain)
            query["size"] = page_size

            try:
                result = self._search(query)
            except requests.HTTPError as e:
                print(f"[OpenSearch] HTTP error: {e}")
                break

            hits = result.get("hits", {}).get("hits", [])
            if not hits:
                break

            for h in hits:
                all_docs.append(h["_source"])
                if max_docs is not None and len(all_docs) >= max_docs:
                    break
            sort_values = hits[-1]["sort"]

            if len(hits) < page_size:
                break

        if not all_docs:
            return pd.DataFrame()

        df = pd.DataFrame(all_docs)
        if ts in df.columns:
            df["timestamp"] = pd.to_datetime(df[ts], utc=True, errors="coerce")
        elif "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")

        print(
            f"[OpenSearch] {len(df)} nouveaux logs depuis {since_ts}"
            + (f" (max_docs={max_docs})" if max_docs is not None else "")
        )
        return df

    def count_time_range(self, gte: str, lte: str | None = None) -> int:
        """Nombre de documents dans [gte, lte] sur le champ temporel configure."""
        ts = self.ts_field
        rng: dict = {"gte": gte}
        if lte:
            rng["lte"] = lte
        body = {"query": {"range": {ts: rng}}}
        url = f"{self.host}/{self.index}/_count"
        resp = self._http_post(url, body)
        return int(resp.json().get("count", 0))

    def fetch_time_range(
        self,
        gte: str,
        lte: str | None = None,
        max_docs: int | None = None,
    ) -> pd.DataFrame:
        """
        Recupere les logs dont timestamp est dans [gte, lte] (lte optionnel = ouvert).
        Pagination search_after ; tronque a max_docs si defini.
        """
        all_docs: list = []
        sort_values = None
        ts = self.ts_field
        rng: dict = {"gte": gte}
        if lte:
            rng["lte"] = lte

        base_query = {
            "query": {"range": {ts: rng}},
            "sort": [
                {ts: {"order": "asc"}},
                {"_id": {"order": "asc"}},
            ],
            "size": OPENSEARCH_PAGE_SIZE,
        }

        while True:
            if max_docs is not None and len(all_docs) >= max_docs:
                break
            query = dict(base_query)
            if sort_values:
                query["search_after"] = sort_values
            page_size = OPENSEARCH_PAGE_SIZE
            if max_docs is not None:
                remain = max_docs - len(all_docs)
                if remain <= 0:
                    break
                page_size = min(page_size, remain)
            query["size"] = page_size

            try:
                result = self._search(query)
            except requests.HTTPError as e:
                print(f"[OpenSearch] HTTP error: {e}")
                break

            hits = result.get("hits", {}).get("hits", [])
            if not hits:
                break

            for h in hits:
                all_docs.append(h["_source"])
                if max_docs is not None and len(all_docs) >= max_docs:
                    break
            sort_values = hits[-1]["sort"]

            if len(hits) < page_size:
                break

        if not all_docs:
            return pd.DataFrame()

        df = pd.DataFrame(all_docs)
        if ts in df.columns:
            df["timestamp"] = pd.to_datetime(df[ts], utc=True, errors="coerce")
        elif "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")

        print(
            f"[OpenSearch] {len(df)} logs dans la fenetre [{gte!r} .. {lte!r}] "
            f"(max_docs={max_docs})"
        )
        return df
