# staging_gate

Python port of the staging → approve → apply workflow for the CISO steering workbook
(`ApplyApproved.ts`, `LockDown.ts`, `ImportRisksFromJSON.ts`), plus an H2/H3 runner.
Layout constants live in `layout.py`; they were checked against `Test-version36-17Aug-BoardCyberShield.xlsx`.

    python -m staging_gate lock         wb.xlsx -o scratch.xlsx
    python -m staging_gate apply        wb.xlsx -o scratch.xlsx
    python -m staging_gate import-risks wb.xlsx -o scratch.xlsx
    python -m staging_gate rollup       wb.xlsx "4. DETECT"
    python -m staging_gate h2 wb.xlsx --prompt H2.md --profile profile.md --evidence EvidenceRegister.csv -o scratch.xlsx
    python -m staging_gate h3 wb.xlsx --prompt H3.md --profile profile.md -o scratch.xlsx

Always work on a scratch copy. Saving through openpyxl re-serialises charts and drops cached formula
values until Excel recalculates. Sheet protection uses Excel's SHA-512 scheme and verifies `LOCK_PW`.
