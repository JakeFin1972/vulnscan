"""Workbook layout, taken from ApplyApproved.ts v1.3 / LockDown.ts v1.1 / ImportRisksFromJSON.ts v1.0 and
checked against Test-version36-17Aug-BoardCyberShield.xlsx."""

LOCK_PW = "IDEOINTI-staging-gate"  # must equal LOCK_PW in the Excel scripts
STAMP_SOURCE = "H2 v2.0 / H3 v4.0"  # ChangeLog col J; the Excel scripts still write "H3 v1.0" (stale)

STAGING = "Staging"
STAGING_RISKS = "Staging-Risks"
CHANGELOG = "ChangeLog"
RISKS_SHEET = "8. Risks"
OPEN_SHEETS = [STAGING, STAGING_RISKS]
LOCKED_SHEETS = [
    "Reporting", "1.Govern", "2. Identify", "3. Protect", "4. DETECT",
    "5. RESPOND", "6. RECOVER", "7. Strategic action plan", "8. Risks",
    "ChangeLog", "Config", "Prompts", "Guidance2", "Additional",
]

# --- Staging (controls): data rows 7..160, columns A..O ---
STAGING_FIRST_ROW, STAGING_ROWS = 7, 154
# staging column -> (function-sheet column, is_maturity)
CONTROL_MAP = [("E", "F", False), ("F", "G", False),
               ("G", "S", True), ("H", "T", True), ("I", "U", True)]
COL_APPROVE, COL_SHEET, COL_NR = "A", "B", "C"
COL_EVIDENCE, COL_CONFIDENCE, COL_STAMP = "K", "L", "O"
MATURITY_RANGE = (0, 5)

# --- function sheets: nr in column A, block A9:U40 ---
NR_COL, FIRST_ROW, LAST_ROW = "A", 9, 40

# --- ChangeLog: 11 columns A..K, header in row 3, first free row found via column B.
# ChangeLog.ts-side note: ApplyApproved.ts starts its scan at row 5, so row 4 stays blank; the
# Python port starts at row 4 (the first row under the header). Mixed use is safe.
LOG_FIRST_ROW, LOG_KEY_COL = 4, "B"

# --- Staging-Risks: data rows 7..60, columns A..Q ---
RISK_STAGING_FIRST_ROW, RISK_STAGING_ROWS = 7, 54
RISK_JSON_CELL = "S2"
RISK_COL_APPROVE, RISK_COL_NAME, RISK_COL_APPLIED = "A", "C", "Q"
# staging column -> JSON key, in column order A..Q (None = left empty)
RISK_IMPORT_COLS = [None, "B", "C", "D", "E", "F", "G", "H", "I", "J",
                    "M", "R", "S", "source_rows", "basis_evidence", "confidence", None]
H_OK = ["1-LOW RISK", "2-MEDIUM RISK", "3-HIGH RISK", "Enabler"]
I_OK = ["1-NO IMPACT", "2-TO BE COMMUNICATED", "3-MEANINGFUL IMPACT", "NA"]
J_OK = ["1-LOW HANGING FRUIT", "2-RESOURCES NEEDED", "3-MAJOR EFFORT (PROJECT)", "NA"]

# --- 8. Risks: first free row via column C from row 12 ---
RISK_TARGET_FIRST_ROW, RISK_TARGET_KEY_COL = 12, "C"
# staging column -> 8. Risks column
RISK_APPLY_MAP = {"B": "B", "C": "C", "D": "D", "E": "E", "F": "F", "G": "G",
                  "H": "H", "I": "I", "J": "J", "K": "M", "L": "R", "M": "S"}

# --- roll-up: K/L/M on the first row of each category block are Excel formulas
# =IFERROR(SUMPRODUCT(V,S)/SUMPRODUCT(V,--(S>0)),0); V = weight from Config via column H. ---
MATURITY_COL = "S"  # S, T, U are the control-level maturity columns
CRITICALITY_COL = "H"  # text such as "1-Critical"
ROLLUP_COLS = {"K": "S", "L": "T", "M": "U"}  # category column -> control column
CONFIG_SHEET = "Config"
CONFIG_NAME_COL, CONFIG_WEIGHT_COL, CONFIG_FIRST_ROW, CONFIG_LAST_ROW = "B", "C", 5, 7

# --- H2 helper (02_H2 output contract; staging columns checked against the workbook headers) ---
CONTROL_SHEETS = ["1.Govern", "2. Identify", "3. Protect", "4. DETECT", "5. RESPOND", "6. RECOVER"]
CTRL_TOPIC_COL, CTRL_QUESTION_COL, CTRL_CRIT_COL, CTRL_NIST_COL = "C", "D", "H", "N"
CTRL_CURRENT_STATE_COL = "F"
# Staging column that receives each H2 JSON field. D, M, N are lookups; A, O belong to the human/script.
# E..I, K, L fixed by ApplyApproved.ts; J is the "Rationale" column in the workbook.
H2_STAGING_COLS = {"F": "E", "G": "F", "S": "G", "T_proposed": "H", "U_proposed": "I",
                   "rationale": "J", "evidence": "K", "confidence": "L"}
RISKS_NAME_COL = "C"  # existing risk names on 8. Risks (ApplyApproved.ts uses column C)
