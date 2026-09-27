#!/usr/bin/env python3
"""Create a consistent backup of the BIA/DPIA SQLite database.

Safe to run while the server is live -- uses SQLite's online backup API
(the same one the admin console's "Download backup now" button uses)
rather than copying the file directly, so a backup never captures a
half-written state.

Usage:
    python3 backup.py                    # writes into ./backups/, keeps the last 14
    python3 backup.py --keep 30
    python3 backup.py --out /path/to/backups
    python3 backup.py --db /path/to/other.sqlite3

Schedule it with cron (Linux/macOS), e.g. daily at 2am:
    0 2 * * * cd /path/to/bia-dpia-tool && python3 backup.py >> backups/backup.log 2>&1

Or with Windows Task Scheduler, running:
    python3 C:\\path\\to\\bia-dpia-tool\\backup.py
"""
import argparse
import os
import secrets
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app.db import DB_PATH  # noqa: E402


def backup_once(db_path: str, out_dir: str, keep: int):
    if not os.path.exists(db_path):
        print(f"No database found at {db_path} -- nothing to back up yet.")
        return None

    os.makedirs(out_dir, exist_ok=True)
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    # A short random suffix keeps filenames unique even if this is called
    # more than once within the same second (e.g. back-to-back manual runs).
    dest_path = os.path.join(out_dir, f"bia_dpia-{timestamp}-{secrets.token_hex(3)}.sqlite3")

    source = sqlite3.connect(db_path)
    dest = sqlite3.connect(dest_path)
    try:
        with dest:
            source.backup(dest)
    finally:
        source.close()
        dest.close()
    print(f"Backup written to {dest_path}")

    _prune_old_backups(out_dir, keep)
    return dest_path


def _prune_old_backups(out_dir: str, keep: int):
    backups = sorted(f for f in os.listdir(out_dir) if f.startswith("bia_dpia-") and f.endswith(".sqlite3"))
    excess = len(backups) - keep
    for name in backups[: max(0, excess)]:
        os.remove(os.path.join(out_dir, name))
        print(f"Removed old backup {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default=DB_PATH, help="Path to the source database (default: same as the running server)")
    parser.add_argument(
        "--out",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups"),
        help="Directory to write backups into (default: ./backups)",
    )
    parser.add_argument("--keep", type=int, default=14, help="Number of most recent backups to retain (default: 14)")
    args = parser.parse_args()
    backup_once(args.db, args.out, args.keep)


if __name__ == "__main__":
    main()
