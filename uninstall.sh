#!/usr/bin/env bash
# Remove the installed vulnscan skill. Leaves the pip package alone
# (uninstall it with: pip uninstall vulnscan).
set -euo pipefail

SKILL_DST="${HOME}/.claude/skills/vulnscan"

if [ -d "${SKILL_DST}" ]; then
  echo "==> Removing ${SKILL_DST}"
  rm -rf "${SKILL_DST}"
  echo "==> Done."
else
  echo "Nothing to remove at ${SKILL_DST}"
fi
echo "To remove the recon CLI as well:  pip uninstall vulnscan"
