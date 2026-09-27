#!/usr/bin/env python3
"""Entry point for the BIA / DPIA tool.

Usage:
    python3 server.py [--host 0.0.0.0] [--port 8000]
    python3 server.py --cert cert.pem --key key.pem [--port 8443]   # serve HTTPS directly

No third-party dependencies required -- Python 3.8+ standard library only.

A reverse proxy (nginx, Caddy, your cloud load balancer) terminating TLS in
front of this server is the recommended way to run this over HTTPS -- it
handles certificate renewal for you and is what most environments already
have. --cert/--key are here for the cases where that isn't available (e.g.
a small on-prem deployment with no reverse proxy) and let this process
terminate TLS itself using only the standard library's ssl module.
"""
import argparse
import sys

from app.http_app import serve


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--cert", help="Path to a PEM certificate file. Enables built-in HTTPS.")
    parser.add_argument("--key", help="Path to the PEM private key matching --cert.")
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key):
        parser.error("--cert and --key must be given together.")
    serve(host=args.host, port=args.port, certfile=args.cert, keyfile=args.key)


if __name__ == "__main__":
    sys.exit(main())
