#!/usr/bin/env python3
"""
Echantillon 1 document depuis logs-raw : verifier champ temporel (timestamp vs @timestamp) et cles _source.

  AWS_PROFILE=entreprise AWS_DEFAULT_REGION=eu-west-3 .venv/bin/python scripts/opensearch_verify_sample.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from opensearch_connector import OpenSearchConnector  # noqa: E402
from config import OPENSEARCH_TIMESTAMP_FIELD  # noqa: E402


def main() -> int:
    oc = OpenSearchConnector()
    url = f"{oc.host}/{oc.index}/_search"
    body = {
        "size": 1,
        "query": {"match_all": {}},
        "sort": [{OPENSEARCH_TIMESTAMP_FIELD: "desc"}],
    }
    resp = oc._http_post(url, body)
    print(f"HTTP {resp.status_code}")
    if not resp.ok:
        print(resp.text[:2000])
        return 1
    data = resp.json()
    hits = data.get("hits", {}).get("hits", [])
    if not hits:
        print("Aucun hit.")
        return 0
    src = hits[0].get("_source", {})
    print(f"Champ temporel config: {OPENSEARCH_TIMESTAMP_FIELD!r}")
    print("Cles _source:", sorted(src.keys()))
    print(json.dumps(src, indent=2, default=str)[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
