"""Command line entry point:  python -m app.cli collect urlhaus"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict

from app.collectors.base import CollectorError
from app.config import get_settings
from app.database.session import get_sessionmaker
from app.services.runner import SUPPORTED_COLLECTORS, build_collector, run_collector


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel")
    sub = parser.add_subparsers(dest="command", required=True)
    collect = sub.add_parser("collect", help="run a collector once")
    collect.add_argument("source", choices=SUPPORTED_COLLECTORS)
    args = parser.parse_args(argv)

    settings = get_settings()
    logging.basicConfig(level=settings.log_level)
    try:
        collector = build_collector(args.source, settings)
        with get_sessionmaker()() as session:
            result = run_collector(session, collector)
    except CollectorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(result), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
