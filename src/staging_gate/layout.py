"""Workbook layout, taken from ApplyApproved.ts v1.3 / LockDown.ts v1.1 / ImportRisksFromJSON.ts v1.0.
Items marked ASSUMED are not in those scripts and need checking against the workbook."""

LOCK_PW = "IDEOINTI-staging-gate"  # must equal LOCK_PW in the Excel scripts
STAMP_SOURCE = "H2 v2.0 / H3 v1.0"  # written to ChangeLog col J, as the script does

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

# --- ChangeLog: 11 columns A..K, first free row found via column B from row 5 ---
LOG_FIRST_ROW, LOG_KEY_COL = 5, "B"
LOG_HEADER = ["Timestamp", "Source", "Sheet", "ID", "Column", "Old", "New",
              "Evidence", "Confidence", "Prompt versions", "Result"]  # ASSUMED header text

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

# --- roll-up (K9 is an Excel formula; this is only a read-only check) ---
ROLLUP_MATURITY_COL = "S"  # ASSUMED: which of S/T/U feeds K9
CRITICALITY_COL = "D"  # ASSUMED

# --- H2 helper (from 02_H2 output contract + architecture doc write-back contract) ---
CONTROL_SHEETS = ["1.Govern", "2. Identify", "3. Protect", "4. DETECT", "5. RESPOND", "6. RECOVER"]
CTRL_TOPIC_COL, CTRL_QUESTION_COL, CTRL_CRIT_COL, CTRL_NIST_COL = "C", "D", "H", "N"
CTRL_CURRENT_STATE_COL = "F"
# Staging column that receives each H2 JSON field. D, M, N are lookups; A, O belong to the human/script.
# E..I and K, L are fixed by ApplyApproved.ts; J (rationale + flags) is ASSUMED.
H2_STAGING_COLS = {"F": "E", "G": "F", "S": "G", "T_proposed": "H", "U_proposed": "I",
                   "rationale": "J", "evidence": "K", "confidence": "L"}
RISKS_NAME_COL = "C"  # existing risk names on 8. Risks (ApplyApproved.ts uses column C)
