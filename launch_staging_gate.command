#!/bin/bash
# Double-click to launch the CISO staging-gate tool (macOS). First run sets up a private Python
# environment inside this folder (.venv). Leave this window open while you use the tool.
cd "$(dirname "$0")" || exit 1
pause() { echo; read -n 1 -s -r -p "Press any key to close this window."; echo; }
fail()  { echo; echo "PROBLEM: $1"; pause; exit 1; }

# 1. a Python that is new enough (3.10+)
PY=""
for c in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then PY="$c"; break; fi
done
[ -n "$PY" ] || fail "Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/ (or: brew install python), then double-click this file again."

# 2. private environment + the one library the tool needs (anthropic is only for the Run H2/H3 tab)
if [ ! -d .venv ]; then echo "Setting up (first run only)..."; "$PY" -m venv .venv || fail "could not create .venv"; fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -c "import openpyxl" 2>/dev/null || { echo "Installing openpyxl..."; pip install -q openpyxl || fail "pip install openpyxl failed (no internet?)"; }
python -c "import anthropic" 2>/dev/null || pip install -q anthropic >/dev/null 2>&1 || echo "(note: could not install 'anthropic'; the Run H2/H3 tab will not work)"

# 3. which workbook?
WB="$1"
if [ -z "$WB" ]; then
  echo "Work on a COPY of your workbook, not the original."
  echo "Drag the .xlsx file into this window, then press Enter:"
  read -r WB
fi
WB="${WB%\"}"; WB="${WB#\"}"; WB="${WB%\'}"; WB="${WB#\'}"   # strip quotes
WB="${WB//\\ / }"                                            # un-escape dragged spaces
WB="${WB/#\~/$HOME}"
WB="$(echo "$WB" | sed -e 's/[[:space:]]*$//')"
[ -f "$WB" ] || fail "file not found: $WB"
case "$WB" in *.xlsx) ;; *) fail "that is not an .xlsx file: $WB" ;; esac
[ ! -e "$(dirname "$WB")/~\$$(basename "$WB")" ] || echo "WARNING: Excel seems to have this file open. Close it in Excel before applying changes."

# 4. a free port
PORT="$(python - <<'PYEOF'
import socket
for p in range(8780, 8800):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", p)); s.close(); print(p); break
    except OSError:
        pass
PYEOF
)"
[ -n "$PORT" ] || fail "no free port between 8780 and 8799"

export PYTHONPATH=src
echo; echo "Starting on port $PORT ..."
python -m staging_gate serve "$WB" --port "$PORT" --open
echo; echo "The tool has stopped."
pause
