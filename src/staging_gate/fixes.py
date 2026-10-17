"""One-off workbook fixes found while testing. Writes through the same unprotect -> write -> re-protect
path as apply, and logs each change to ChangeLog. Idempotent."""
import re
from dataclasses import dataclass, field

from . import layout as L
from .lock import protect, unprotect
from .runner import extract_system_prompt
from .xl import ChangeLog, cell, s, stamp

PROMPTS_SHEET = "Prompts"
H3_LABEL = "H3"
STAGING_APPROVE_RANGE = "A7:A160"


@dataclass
class FixResult:
    done: list = field(default_factory=list)
    skipped: list = field(default_factory=list)


def _prompt_version(md: str) -> str:
    m = re.search(r"System prompt\s*\(v([\d.]+)\)", md)
    if not m:
        raise ValueError("H3 file has no 'System prompt (vX.Y)' heading - cannot tell the version")
    return "v" + m[1]


def update_h3_prompt(wb, md: str, log: ChangeLog, res: FixResult):
    version, text = _prompt_version(md), extract_system_prompt(md)
    ws = wb[PROMPTS_SHEET]
    row = next((r for r in range(1, ws.max_row + 1) if s(cell(ws, "A", r).value).startswith(H3_LABEL)), None)
    if row is None:
        raise ValueError(f"no row starting with '{H3_LABEL}' on {PROMPTS_SHEET}")
    old_v, old_text = s(cell(ws, "B", row).value), cell(ws, "C", row).value or ""
    if old_text.strip() == text.strip() and old_v == version:
        res.skipped.append(f"{PROMPTS_SHEET} H3 already {version}")
        return
    was_locked = ws.protection.sheet
    unprotect(ws)
    cell(ws, "B", row).value, cell(ws, "C", row).value = version, text
    if was_locked:
        protect(ws)
    log.write("fix", PROMPTS_SHEET, f"row {row}", "B,C", f"H3 {old_v}", f"H3 {version}", "", "",
              "PROMPT UPDATED")
    res.done.append(f"{PROMPTS_SHEET} H3 {old_v} -> {version}")


def allow_override_token(wb, log: ChangeLog, res: FixResult):
    ws = wb[L.STAGING]
    for dv in ws.data_validations.dataValidation:
        if dv.type == "list" and STAGING_APPROVE_RANGE in str(dv.sqref):
            if "y!" in (dv.formula1 or ""):
                res.skipped.append("Staging approve dropdown already lists y!")
                return
            old = dv.formula1
            dv.formula1 = '"y,n,y!"'
            log.write("fix", L.STAGING, STAGING_APPROVE_RANGE, "A", old, dv.formula1, "", "",
                      "DROPDOWN UPDATED")
            res.done.append(f"Staging approve dropdown {old} -> {dv.formula1}")
            return
    raise ValueError(f"no list validation on {L.STAGING}!{STAGING_APPROVE_RANGE}")


def fix_workbook(wb, h3_md: str | None = None, dropdown: bool = True) -> FixResult:
    res = FixResult()
    ws_log = wb[L.CHANGELOG]
    was_locked = ws_log.protection.sheet
    unprotect(ws_log)
    try:
        log = ChangeLog(wb, stamp())
        if h3_md is not None:
            update_h3_prompt(wb, h3_md, log, res)
        if dropdown:
            allow_override_token(wb, log, res)
    finally:
        if was_locked:
            protect(ws_log)
    return res
