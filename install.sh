#!/usr/bin/env bash
# Install vulnscan: skills → ~/.claude/skills/, CLIs, and optional web UI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SKILLS_SRC="${ROOT}/skills"
SKILLS_DST="${HOME}/.claude/skills"

# ── Skills ─────────────────────────────────────────────────────────────────────
echo "==> Installing skills -> ${SKILLS_DST}/"
mkdir -p "${SKILLS_DST}"
for dir in "${SKILLS_SRC}"/*/; do
  name="$(basename "${dir}")"
  rm -rf "${SKILLS_DST}/${name}"
  cp -R "${dir}" "${SKILLS_DST}/${name}"
  echo "    - ${name}"
done

# ── Python package + CLIs ──────────────────────────────────────────────────────
echo "==> Installing Python package (pip install -e .)"
pip install -e ".[dev]" >/dev/null

# ── Web UI (optional) ─────────────────────────────────────────────────────────
if command -v npm &>/dev/null; then
  echo "==> Building web UI (npm install && npm run build)"
  cd "${ROOT}/ui"
  npm install --silent
  npm run build --silent
  cd "${ROOT}"
  echo "    UI built to ui/dist/  (served by the API automatically)"
else
  echo "==> Skipping web UI build (npm not found)"
  echo "    Install Node.js 18+ and re-run, or build manually: cd ui && npm install && npm run build"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo
echo "==> Done."
echo
echo "  CLI:"
echo "    vulnscan-recon /path/to/authorized/repo --json recon.json"
echo "    vulnscan-runtest --repo . --python 'tests/test_sec.py::test_no_sqli'"
echo
echo "  API + UI:"
echo "    uvicorn vulnscan.api:app --host 127.0.0.1 --port 8765"
echo "    # then open http://localhost:8765/docs   (OpenAPI)"
echo "    # serve the UI:  cd ui && npm run preview  (or point any static server at ui/dist/)"
echo
echo "  Claude Code skills:"
echo "    /vulnscan           # full Hunt -> Disprove -> Report loop"
echo "    /vulnscan-fix       # TDD remediation: RED -> GREEN -> review"
echo "    /vulnscan-verify    # independent, read-only fix verification"
echo
echo "  Run tests:"
echo "    python -m pytest -q"
echo
echo "  Re-run after pulling updates to refresh skills and UI."
