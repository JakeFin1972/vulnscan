#!/usr/bin/env bash
# cron.sh — Daily wrapper for enrich_vulns.py
#
# Crontab entry (runs at 01:00 AM every day):
#   0 1 * * * /path/to/tools/kev-enrichment/cron.sh
#
# Add to crontab with:
#   crontab -e
# Or install non-interactively:
#   (crontab -l 2>/dev/null; echo "0 1 * * * $(realpath "$0")") | crontab -

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
LOG_FILE="${LOG_DIR}/enrich_$(date +%Y-%m-%d).log"
PYTHON="${SCRIPT_DIR}/../../.venv/bin/python"

# Fall back to system python3 if the project venv is not present
if [[ ! -x "$PYTHON" ]]; then
    PYTHON="$(command -v python3)"
fi

mkdir -p "$LOG_DIR"

echo "========================================"  >> "$LOG_FILE"
echo "Run started: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$LOG_FILE"
echo "Python: $PYTHON" >> "$LOG_FILE"
echo "========================================"  >> "$LOG_FILE"

"$PYTHON" "${SCRIPT_DIR}/enrich_vulns.py" \
    --input  "${SCRIPT_DIR}/vuln_scan.json" \
    --output "${SCRIPT_DIR}/enriched_vulns.json" \
    >> "$LOG_FILE" 2>&1

EXIT_CODE=$?

echo "Exit code: $EXIT_CODE" >> "$LOG_FILE"
echo "Run finished: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$LOG_FILE"

# Keep only the last 30 daily log files
find "$LOG_DIR" -name "enrich_*.log" -mtime +30 -delete 2>/dev/null || true

exit $EXIT_CODE
