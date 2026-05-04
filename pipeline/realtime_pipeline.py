"""
Pipeline temps reel — alias vers pipeline.run_realtime_compat.

Prefere : `python pipeline.py --loop --submit` (ou --submit-dry-run).
"""

from __future__ import annotations

import argparse

from .pipeline import run_realtime_compat


def run(dry_run: bool = False, reset: bool = False):
    run_realtime_compat(dry_run=dry_run, reset=reset)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    run(dry_run=args.dry_run, reset=args.reset)
