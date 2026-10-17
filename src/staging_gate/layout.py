"""Workbook layout. Values marked STATED come from the test plan; ASSUMED ones must be
checked against the real workbook and edited here (nowhere else)."""

LOCK_PW = "IDEOINTI-staging-gate"  # STATED: must match the Excel scripts' LOCK_PW

STAGING = "Staging"  # STATED
STAGING_RISKS = "Staging-Risks"  # STATED
CHANGELOG = "ChangeLog"  # STATED
RISKS_SHEET = "8. Risks"  # STATED
REPORTING = "Reporting"  # STATED
WRITABLE = {STAGING, STAGING_RISKS}  # STATED: LockDown leaves only these writable

# --- control staging (Staging) ---
STAGING_FIRST_ROW = 7  # STATED
COL_APPROVE = "A"  # STATED ('y' / 'y!')
COL_SHEET = "B"  # ASSUMED: target sheet name, e.g. "4. DETECT"
COL_NR = "C"  # ASSUMED: control number
COL_APPLIED = "O"  # STATED: timestamp stamp
# STATED that F/G/S land on the function sheet (E too per Test 2); which staging column
# feeds S is ASSUMED to be H (maturity).
FIELD_MAP = {"E": "E", "F": "F", "G": "G", "H": "S"}  # staging col -> target col
MATURITY_STAGING_COL = "H"  # ASSUMED
MATURITY_RANGE = (0, 5)  # STATED: PRISMA 0-5

# --- function sheets ---
NR_COL = "A"  # ASSUMED (STATED only that the lookup scans A9:U40)
FIRST_ROW, LAST_ROW = 9, 40  # STATED
MATURITY_COL = "S"  # STATED (written column)
CRITICALITY_COL = "D"  # ASSUMED: weight used by the K9 roll-up
ROLLUP_CELL = "K9"  # STATED

# --- risk staging (Staging-Risks) ---
RISK_JSON_CELL = "S2"  # STATED
RISK_FIRST_ROW = 7  # STATED
RISK_COL_APPROVE = "A"  # STATED
RISK_COL_APPLIED = "Q"  # STATED
RISK_COL_BASIS = "O"  # STATED: rating basis + evidence together
# JSON key -> Staging-Risks column (ASSUMED except basis/evidence -> O)
RISK_STAGING_COLS = {"source": "B", "title": "C", "description": "D",
                     "likelihood": "E", "impact": "F"}
RISK_REQUIRED = ("source", "title", "description", "rating_basis", "evidence")
RISK_SCALE = (1, 5)  # ASSUMED for likelihood/impact
# Staging-Risks column -> 8. Risks column (ASSUMED). A, K, L, N stay empty (STATED).
RISK_TARGET_COLS = {"C": "B", "D": "C", "E": "D", "F": "E", "B": "F", "O": "G"}
RISK_TARGET_FIRST_ROW = 12  # STATED
RISK_TARGET_KEY_COL = "B"  # ASSUMED: used to find the next empty row
