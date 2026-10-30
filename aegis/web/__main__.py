"""Run the dashboard: python -m aegis.web [--host H] [--port P]."""

from __future__ import annotations

import argparse
import logging

from aegis.web.app import serve


def main() -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.web")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    serve(a.host, a.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
