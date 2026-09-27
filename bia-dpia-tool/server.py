#!/usr/bin/env python3
"""Entry point for the BIA / DPIA tool.

Usage:
    python3 server.py [--host 0.0.0.0] [--port 8000]

No third-party dependencies required -- Python 3.8+ standard library only.
"""
import argparse
import sys

from app.http_app import serve


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    args = parser.parse_args()
    serve(host=args.host, port=args.port)


if __name__ == "__main__":
    sys.exit(main())
