# BIA / DPIA Tool

An easy-to-use, self-service web tool for running **Business Impact
Assessments (BIA)** and **Data Privacy Impact Assessments (DPIA)**. It is
built from the questions, guidance text, scoring formulas and reference
tables in the source spreadsheet (`BIA_DPIA_Tool_Updated_1.xlsm`), turned
into a guided web wizard that anyone in the company can fill in from a
browser -- no Excel, no macros, no training required.

Per the request that created this tool, the `DPIA1`-`DPIA5` tabs from the
source workbook were intentionally left out (their content lives in the
`DPIA` tab instead, which is included). The `DPIA0 - Overview & Scope` tab
(EDPB template alignment) **is** included.

## Highlights

- **Zero install for the people using it.** Pure Python 3 standard library
  on the backend (`sqlite3`, `http.server`) and plain HTML/CSS/JS on the
  frontend -- nothing to `pip install`, no Node/npm build step. Anyone with
  the URL can open it in a browser and start an assessment.
- **Faithful scoring.** Reproduces the workbook's formulas: per-category
  maximum impact (Confidentiality / Integrity / Availability / Uniqueness /
  Consistency / Regulatory compliance), the resulting classification code
  (C1-C4 / I1-I4 / A1-A4) and protection profile, the "Is a DPIA needed?"
  screening logic, and per-question DPIA risk scoring (Likelihood x
  Consequence, bucketed into Critical/High/Medium/Low).
- **A built-in reference guide** (Impact Scales, Classification Matrix,
  Important Information Assets) so people can self-classify consistently
  without needing to ask Security/Privacy every time.
- **Export to Word, PDF or CSV**, in addition to the in-browser report view --
  all three are generated with zero extra dependencies (hand-rolled, minimal
  but valid OOXML/PDF writers using only the standard library).
- **Everything is admin-editable at runtime**, with no code changes:
  every question, its guidance text, input type and options; every dropdown
  list; the impact scale table; the classification matrix; the information
  asset register; the DPIA thresholds and risk buckets; the admin password.
  An "Advanced (JSON)" tab covers anything the dedicated screens don't
  (e.g. reordering sections).

## Running it

```bash
cd bia-dpia-tool
python3 server.py                 # serves on http://127.0.0.1:8000
# or: python3 server.py --host 0.0.0.0 --port 8080
```

Open `http://127.0.0.1:8000/` for the assessment wizard, or
`http://127.0.0.1:8000/admin.html` for the admin console.

Data is stored in a local SQLite file at `bia-dpia-tool/data/bia_dpia.sqlite3`
(created automatically, and git-ignored). Set `BIA_DPIA_DB=/path/to/file.db`
to change the location, e.g. to put it on persistent storage in a container.

### Admin access

The default admin password is **`ChangeMe!123`** (also printed to the
console on startup). **Change it immediately** from the Admin console's
Settings tab -- the console shows a warning banner until you do. You can
also set a different starting password before first run via the
`BIA_DPIA_ADMIN_PASSWORD` environment variable.

There is a single shared admin password (no per-user admin accounts) --
appropriate for a small internal tool. Anyone filling in an assessment does
not need to log in; they just identify themselves via name/email on the
project/tool/application info step (used for "My assessments" lookup and as
the report's "Completed by" field).

> Deployment note: this app has no TLS/session-hardening beyond
> HttpOnly/SameSite cookies and does not attempt to be internet-facing
> hardened. Run it behind your normal internal network controls (VPN,
> reverse proxy with TLS, etc.) if it isn't staying on localhost.

## How it works

- **Scope: BIA only / DPIA only / Both.** Chosen when starting a new
  assessment, and changeable anytime from the project/tool/application info
  step -- the wizard only shows the sections relevant to the selected scope,
  and answers for out-of-scope sections are kept (not deleted) so switching
  back and forth is safe. If a BIA-only assessment's screening answers
  indicate a DPIA is needed, the Results step offers a one-click "Add DPIA
  to this assessment" button that expands scope to Both. BIA and DPIA are
  submitted and reopened independently on the Review & submit step (e.g. you
  can finish and lock the BIA while the DPIA is still in progress); the
  overall status shown elsewhere is "submitted" only once every in-scope
  part is.
- **Employee wizard** (`/`): a step-by-step form covering project/tool/application info, the
  6 BIA impact categories (with per-scenario impact ratings and
  auto-computed maximum impact / classification), the computed "Is a DPIA
  needed?" result, the DPIA0 (EDPB-aligned scope) section, and the 8
  detailed DPIA sections -- each DPIA question carries its own optional risk
  register (risk identified, remediation, likelihood x consequence,
  impact flags, owner, status, due date), exactly like the source
  spreadsheet's per-row risk columns. Answers autosave as you type. A
  printable report is available at any time
  (`/api/assessments/{id}/print`, or "Report" in the UI), and from the
  Review & submit step you can download the same content as a **Word
  (.docx)**, **PDF**, or **CSV** file
  (`/api/assessments/{id}/export.{docx,pdf,csv}`).
- **Admin console** (`/admin.html`): password-gated. Tabs for Settings
  (org name, DPIA thresholds, risk buckets, admin password, factory
  reset), Questions & Sections (add/edit/remove questions per tool),
  Option Lists, the Impact Scale reference table, the Classification
  Matrix, the Information Assets register, a list of all submitted/draft
  Assessments (with a delete action), and an Advanced raw-JSON editor.
  Nothing is saved until you click **Save changes**.
- **Backend**: `app/seed_data.py` holds the initial content (loaded into
  SQLite on first run only); `app/db.py` is the persistence layer;
  `app/scoring.py` reproduces the workbook's formulas; `app/http_app.py` is
  the whole HTTP API + static file server (see its module docstring for the
  full route list).

## Content provenance (for transparency)

Most question text, guidance, and dropdown option lists (impact scale,
delivery model, information sub-domains, legal grounds, "who provided the
data", collection methods, international transfer mechanisms) come
directly from the source workbook's `BIA`, `DPIA`, `Filters`, `Impact
Scales`, `Classification Matrix` and `Important Information Assets` tabs,
including its underlying Excel table formulas (MAX-of-category,
classification lookup, DPIA-needed logic, and the likelihood x consequence
risk-scoring formula), which were inspected directly from the workbook's
XML to make sure the scoring in this tool matches exactly.

A few additions were made, all clearly editable/removable by an admin:

- A `bia.screening.q1b_sensitive_personal_data` yes/no question was added
  to the BIA screening section. The source workbook computed this from a
  `Protection Level!E16` cell ("Will sensitive personal data be processed
  as indicated in S1?") that wasn't itself an answerable question in the
  `BIA` tab -- this makes it one, since it directly feeds the "Is a DPIA
  needed?" result.
- Three DPIA multi-select option lists -- **data subject types**,
  **personal data types**, and **special category data types** -- were
  authored for usability. The source workbook left those particular cells
  (2.1, 2.2, 2.3) as free text with no dropdown validation.
- A **risk Status** list (Open/In progress/Mitigated/Accepted/Closed) was
  authored for the DPIA risk register; the source sheet had a free-text
  "Status" column with no fixed list.

Everything above can be edited, renamed, or removed from the Admin
console -- none of it is hard-coded into the scoring logic except the
handful of stable field "roles" documented in `app/scoring.py`
(`profiles_count`, `cross_border_transfer`, `sensitive_personal_data`,
`art35_criterion`), which only need to point at *some* question with that
role, not a specific hard-coded key.

## Not implemented (out of scope for this pass)

- File attachments (the source workbook references attaching data-flow
  diagrams etc.; this tool captures a comment/reference instead).
- Per-user accounts/SSO (a single shared admin password gates the admin
  console; anyone can start/edit their own assessments without logging in).

## Export format notes

The Word and PDF exporters (`app/docx_writer.py`, `app/pdf_writer.py`) are
small, hand-rolled writers using only the standard library -- no
`python-docx`, `reportlab`, etc. -- to keep the zero-dependency promise.
Tradeoffs versus a full library:

- The PDF uses the 2 standard, non-embedded fonts (Helvetica /
  Helvetica-Bold) and estimates word-wrap from an average character width
  rather than real font metrics, so line breaks are close but not
  typeset-perfect. Text is encoded as WinAnsi (cp1252); characters outside
  that encoding (most non-Latin scripts, some symbols) are replaced with
  `?` rather than crashing the export.
- The Word document skips a `styles.xml` part entirely and uses direct
  run formatting (bold/size) instead of named styles -- it opens cleanly in
  Word, LibreOffice and Google Docs, but "Styles" in Word won't show a
  custom heading style to restyle in bulk.
- The CSV is one flat file (project info, protection level, DPIA-needed
  reasons, then every question/answer/comment/risk field) rather than
  multiple sheets -- there's no multi-sheet equivalent in plain CSV.
