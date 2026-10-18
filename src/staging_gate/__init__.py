"""Python port of the staging-gate workflow (ApplyApproved / LockDown / ImportRisksFromJSON)."""
import sys

if sys.version_info < (3, 10):  # the code uses `X | None` annotations
    raise SystemExit(f"staging_gate needs Python 3.10 or newer (this is {sys.version.split()[0]}). "
                     "On a Mac: brew install python, then use python3.12 / python3.13.")
