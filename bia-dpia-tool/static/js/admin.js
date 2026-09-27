/* Admin console. Vanilla JS, no build step. Mutates a working copy of the
   config in place; nothing is persisted until "Save changes" is clicked
   (except password changes and factory reset, which are immediate). */

let config = null;
let dirty = false;
let activeTab = "settings";
const appEl = document.getElementById("app");

const INPUT_TYPES = ["text", "textarea", "number", "date", "yesno", "select", "multiselect", "impact"];

async function boot() {
  let session;
  try {
    session = await Api.adminSession();
  } catch (e) {
    session = { authenticated: false };
  }
  if (!session.authenticated) return renderLogin();
  document.getElementById("logout-btn").classList.remove("hidden");
  document.getElementById("logout-btn").onclick = async () => {
    await Api.adminLogout();
    location.reload();
  };
  config = await Api.adminGetConfig();
  dirty = false;
  renderShell(session.default_password);
}

function renderLogin() {
  appEl.innerHTML = `
    <div class="admin-login card">
      <h2>Admin sign in</h2>
      <p class="muted">Sign in to edit questions, option lists, reference content and manage assessments.</p>
      <label>Password</label>
      <input type="password" id="login-password">
      <div style="margin-top:14px"><button class="btn primary" id="login-btn">Sign in</button></div>
      <div id="login-error" class="muted" style="margin-top:10px;color:var(--danger)"></div>
    </div>
  `;
  const submit = async () => {
    const password = document.getElementById("login-password").value;
    try {
      await Api.adminLogin(password);
      boot();
    } catch (e) {
      document.getElementById("login-error").textContent = e.message;
    }
  };
  document.getElementById("login-btn").onclick = submit;
  document.getElementById("login-password").addEventListener("keydown", (e) => {
    if (e.key === "Enter") submit();
  });
}

const TABS = [
  { id: "settings", label: "Settings" },
  { id: "questions", label: "Questions & Sections" },
  { id: "options", label: "Option Lists" },
  { id: "impact_scale", label: "Impact Scale Table" },
  { id: "classification", label: "Classification Matrix" },
  { id: "assets", label: "Information Assets" },
  { id: "assessments", label: "Assessments" },
  { id: "advanced", label: "Advanced (JSON)" },
];

function renderShell(defaultPassword) {
  appEl.innerHTML = `
    <main class="content" style="max-width:1100px">
      ${defaultPassword ? `<div class="warning-banner">You are using the default admin password. Please change it under <strong>Settings</strong> now.</div>` : ""}
      <div class="admin-tabs" id="admin-tabs"></div>
      <div id="tab-panel"></div>
    </main>
    <div class="wizard-footer">
      <div class="save-status" id="save-status">${dirty ? "Unsaved changes" : "All changes saved"}</div>
      <div style="display:flex;gap:10px">
        <button class="btn" id="discard-btn">Discard changes</button>
        <button class="btn primary" id="save-btn">Save changes</button>
      </div>
    </div>
  `;
  document.getElementById("admin-tabs").innerHTML = TABS.map(
    (t) => `<button data-tab="${t.id}" class="${t.id === activeTab ? "active" : ""}">${t.label}</button>`
  ).join("");
  document.querySelectorAll("[data-tab]").forEach((btn) => {
    btn.onclick = () => {
      activeTab = btn.dataset.tab;
      renderShell(defaultPassword);
    };
  });
  document.getElementById("save-btn").onclick = saveConfig;
  document.getElementById("discard-btn").onclick = () => {
    if (!dirty || confirm("Discard all unsaved changes?")) boot();
  };
  renderTabPanel();
}

function markDirty() {
  dirty = true;
  const el = document.getElementById("save-status");
  if (el) el.textContent = "Unsaved changes";
}

async function saveConfig() {
  try {
    config = await Api.adminPutConfig(config);
    dirty = false;
    toast("Changes saved.");
    const el = document.getElementById("save-status");
    if (el) el.textContent = "All changes saved";
  } catch (e) {
    toast(e.message, true);
  }
}

function renderTabPanel() {
  const panel = document.getElementById("tab-panel");
  const renderers = {
    settings: renderSettingsTab,
    questions: renderQuestionsTab,
    options: renderOptionsTab,
    impact_scale: renderImpactScaleTab,
    classification: renderClassificationTab,
    assets: renderAssetsTab,
    assessments: renderAssessmentsTab,
    advanced: renderAdvancedTab,
  };
  renderers[activeTab](panel);
}

// ------------------------------------------------------------- settings --

function renderSettingsTab(panel) {
  const s = config.settings;
  panel.innerHTML = `
    <div class="card">
      <h2>Organization</h2>
      <div class="field-row">
        <div><label>Organization name</label><input id="s-org" type="text" value="${escapeHtml(config.org_name)}"></div>
        <div><label>Support contact</label><input id="s-support" type="text" value="${escapeHtml(s.support_contact)}"></div>
      </div>
    </div>
    <div class="card">
      <h2>DPIA thresholds</h2>
      <p class="desc">These drive the automatic "Is a DPIA needed?" determination and the risk score buckets.</p>
      <div class="field-row">
        <div><label>Individual profile count that triggers a DPIA</label><input id="s-threshold" type="number" min="0" value="${s.dpia_profile_threshold}"></div>
      </div>
      <div class="field-row">
        <div><label>Risk score &gt; this = Critical</label><input id="s-crit" type="number" value="${s.dpia_risk_thresholds.critical}"></div>
        <div><label>Risk score &gt; this = High</label><input id="s-high" type="number" value="${s.dpia_risk_thresholds.high}"></div>
        <div><label>Risk score &gt; this = Medium</label><input id="s-med" type="number" value="${s.dpia_risk_thresholds.medium}"></div>
        <div><label>Risk score &gt; this = Low</label><input id="s-low" type="number" value="${s.dpia_risk_thresholds.low}"></div>
      </div>
    </div>
    <div class="card">
      <h2>Change admin password</h2>
      <div class="field-row">
        <div><label>Current password</label><input id="pw-current" type="password"></div>
        <div><label>New password</label><input id="pw-new" type="password"></div>
        <div><label>Confirm new password</label><input id="pw-confirm" type="password"></div>
      </div>
      <div style="margin-top:10px"><button class="btn" id="pw-save-btn">Update password</button></div>
    </div>
    <div class="card">
      <h2>Factory reset</h2>
      <p class="desc">Discards every customization and restores the original questions, option lists and reference tables extracted from the source workbook.</p>
      <button class="btn danger" id="reset-btn">Reset all content to factory defaults</button>
    </div>
  `;
  const bind = (id, path, parse) => {
    document.getElementById(id).addEventListener("input", (e) => {
      const v = parse ? parse(e.target.value) : e.target.value;
      path(v);
      markDirty();
    });
  };
  bind("s-org", (v) => (config.org_name = v));
  bind("s-support", (v) => (s.support_contact = v));
  bind("s-threshold", (v) => (s.dpia_profile_threshold = Number(v)), (v) => v);
  bind("s-crit", (v) => (s.dpia_risk_thresholds.critical = Number(v)));
  bind("s-high", (v) => (s.dpia_risk_thresholds.high = Number(v)));
  bind("s-med", (v) => (s.dpia_risk_thresholds.medium = Number(v)));
  bind("s-low", (v) => (s.dpia_risk_thresholds.low = Number(v)));

  document.getElementById("pw-save-btn").onclick = async () => {
    const current = document.getElementById("pw-current").value;
    const nw = document.getElementById("pw-new").value;
    const confirm2 = document.getElementById("pw-confirm").value;
    if (nw !== confirm2) return toast("New passwords do not match.", true);
    try {
      await Api.adminChangePassword(current, nw);
      toast("Password updated.");
      document.getElementById("pw-current").value = "";
      document.getElementById("pw-new").value = "";
      document.getElementById("pw-confirm").value = "";
    } catch (e) {
      toast(e.message, true);
    }
  };

  document.getElementById("reset-btn").onclick = async () => {
    if (!confirm("This will discard all customizations and restore factory defaults. Continue?")) return;
    config = await Api.adminResetConfig();
    dirty = false;
    toast("Reset to factory defaults.");
    renderShell(false);
  };
}

// ------------------------------------------------------------ questions --

let questionsTool = "bia";

function renderQuestionsTab(panel) {
  panel.innerHTML = `
    <div class="card">
      <div class="admin-tabs" style="margin-bottom:0">
        ${["bia", "dpia0", "dpia"]
          .map((t) => `<button data-tool="${t}" class="${t === questionsTool ? "active" : ""}">${config.tools[t].title}</button>`)
          .join("")}
      </div>
    </div>
    <div id="tool-editor"></div>
  `;
  panel.querySelectorAll("[data-tool]").forEach((btn) => {
    btn.onclick = () => {
      questionsTool = btn.dataset.tool;
      renderQuestionsTab(panel);
    };
  });
  renderToolEditor(document.getElementById("tool-editor"));
}

function renderToolEditor(container) {
  const tool = config.tools[questionsTool];
  container.innerHTML = `
    <div class="card">
      <div class="field-row">
        <div><label>Tool title</label><input id="tool-title" type="text" value="${escapeHtml(tool.title)}"></div>
      </div>
      <div class="question"><label class="prompt">Tool description</label><textarea id="tool-desc">${escapeHtml(tool.description || "")}</textarea></div>
    </div>
    <div id="sections-container"></div>
    <button class="btn" id="add-section-btn">+ Add section</button>
  `;
  document.getElementById("tool-title").oninput = (e) => { tool.title = e.target.value; markDirty(); };
  document.getElementById("tool-desc").oninput = (e) => { tool.description = e.target.value; markDirty(); };

  const sectionsContainer = document.getElementById("sections-container");
  tool.sections.forEach((section, sIdx) => sectionsContainer.appendChild(renderSectionCard(tool, section, sIdx)));

  document.getElementById("add-section-btn").onclick = () => {
    tool.sections.push({ key: `section_${Date.now()}`, title: "New section", description: "", questions: [] });
    markDirty();
    renderToolEditor(container);
  };
}

function renderSectionCard(tool, section, sIdx) {
  const card = document.createElement("div");
  card.className = "card";
  card.innerHTML = `
    <div class="field-row">
      <div><label>Section key</label><input data-f="key" type="text" value="${escapeHtml(section.key)}"></div>
      <div><label>Section title</label><input data-f="title" type="text" value="${escapeHtml(section.title)}"></div>
    </div>
    <div class="question"><label class="prompt">Section description</label><textarea data-f="description">${escapeHtml(section.description || "")}</textarea></div>
    <div style="display:flex;justify-content:flex-end"><button class="btn small danger" data-remove-section>Remove section</button></div>
    <div class="questions-list"></div>
    <button class="btn small" data-add-question>+ Add question</button>
  `;
  card.querySelector('[data-f="key"]').oninput = (e) => { section.key = e.target.value; markDirty(); };
  card.querySelector('[data-f="title"]').oninput = (e) => { section.title = e.target.value; markDirty(); };
  card.querySelector('[data-f="description"]').oninput = (e) => { section.description = e.target.value; markDirty(); };
  card.querySelector("[data-remove-section]").onclick = () => {
    if (!confirm(`Remove section "${section.title}" and all its questions?`)) return;
    tool.sections.splice(sIdx, 1);
    markDirty();
    renderQuestionsTab(document.getElementById("tab-panel"));
  };

  const list = card.querySelector(".questions-list");
  section.questions.forEach((q, qIdx) => list.appendChild(renderQuestionEditorCard(section, q, qIdx)));

  card.querySelector("[data-add-question]").onclick = () => {
    section.questions.push({ key: `${tool === config.tools.bia ? "bia" : ""}.${section.key}.q${Date.now()}`, prompt: "New question", input_type: "textarea" });
    markDirty();
    renderQuestionsTab(document.getElementById("tab-panel"));
  };

  return card;
}

function renderQuestionEditorCard(section, q, qIdx) {
  const wrap = document.createElement("div");
  wrap.style.cssText = "border:1px solid var(--border);border-radius:6px;padding:12px;margin:10px 0;background:var(--bg)";
  const optionListChoices = Object.keys(config.option_lists);
  wrap.innerHTML = `
    <div class="field-row">
      <div class="col-narrow"><label>ID (display)</label><input data-f="id" type="text" value="${escapeHtml(q.id || "")}"></div>
      <div><label>Key (unique, do not reuse)</label><input data-f="key" type="text" value="${escapeHtml(q.key)}"></div>
      <div class="col-narrow"><label>Input type</label>
        <select data-f="input_type">${INPUT_TYPES.map((t) => `<option value="${t}" ${t === q.input_type ? "selected" : ""}>${t}</option>`).join("")}</select>
      </div>
      <div class="col-narrow"><label>Option list</label>
        <select data-f="option_list"><option value="">(none)</option>${optionListChoices.map((k) => `<option value="${k}" ${k === q.option_list ? "selected" : ""}>${k}</option>`).join("")}</select>
      </div>
    </div>
    <div class="question"><label class="prompt">Prompt</label><textarea data-f="prompt">${escapeHtml(q.prompt)}</textarea></div>
    <div class="question"><label class="prompt">Guidance / help text</label><textarea data-f="guidance">${escapeHtml(q.guidance || "")}</textarea></div>
    <div class="field-row">
      <div class="col-narrow"><label>Scoring category (BIA impact questions only)</label><input data-f="category" type="text" value="${escapeHtml(q.category || "")}"></div>
      <div class="col-narrow"><label>Role (advanced, drives scoring)</label><input data-f="role" type="text" value="${escapeHtml(q.role || "")}"></div>
      <div class="col-narrow"><label><input type="checkbox" data-f="has_risk_register" ${q.has_risk_register ? "checked" : ""}> Has risk register</label></div>
    </div>
    <div style="display:flex;justify-content:flex-end"><button class="btn small danger" data-remove-question>Remove question</button></div>
  `;
  const bindField = (name, transform) => {
    const el = wrap.querySelector(`[data-f="${name}"]`);
    const evt = el.type === "checkbox" ? "change" : "input";
    el.addEventListener(evt, () => {
      const v = el.type === "checkbox" ? el.checked : el.value;
      q[name] = transform ? transform(v) : (v === "" ? undefined : v);
      markDirty();
    });
  };
  ["id", "key", "input_type", "option_list", "prompt", "guidance", "category", "role"].forEach((f) => bindField(f));
  bindField("has_risk_register", (v) => v || undefined);

  wrap.querySelector("[data-remove-question]").onclick = () => {
    if (!confirm("Remove this question?")) return;
    section.questions.splice(qIdx, 1);
    markDirty();
    renderQuestionsTab(document.getElementById("tab-panel"));
  };
  return wrap;
}

// -------------------------------------------------------------- options --

let activeOptionList = null;

function renderOptionsTab(panel) {
  const keys = Object.keys(config.option_lists);
  if (!activeOptionList || !keys.includes(activeOptionList)) activeOptionList = keys[0];
  panel.innerHTML = `
    <div class="card">
      <div class="field-row">
        <div>
          <label>Option list</label>
          <select id="option-list-select">${keys.map((k) => `<option value="${k}" ${k === activeOptionList ? "selected" : ""}>${k}</option>`).join("")}</select>
        </div>
        <div style="flex:0 0 auto;align-self:flex-end;display:flex;gap:8px">
          <button class="btn small" id="new-list-btn">+ New list</button>
          <button class="btn small danger" id="delete-list-btn">Delete this list</button>
        </div>
      </div>
    </div>
    <div class="card" id="option-rows"></div>
  `;
  document.getElementById("option-list-select").onchange = (e) => {
    activeOptionList = e.target.value;
    renderOptionsTab(panel);
  };
  document.getElementById("new-list-btn").onclick = () => {
    const key = prompt("New option list key (lowercase, underscores):");
    if (!key) return;
    if (config.option_lists[key]) return toast("A list with that key already exists.", true);
    config.option_lists[key] = [{ value: "value1", label: "Label 1" }];
    activeOptionList = key;
    markDirty();
    renderOptionsTab(panel);
  };
  document.getElementById("delete-list-btn").onclick = () => {
    if (!confirm(`Delete option list "${activeOptionList}"? Questions using it will show no options until reassigned.`)) return;
    delete config.option_lists[activeOptionList];
    activeOptionList = null;
    markDirty();
    renderOptionsTab(panel);
  };
  renderOptionRows(document.getElementById("option-rows"));
}

function renderOptionRows(container) {
  const rows = config.option_lists[activeOptionList] || [];
  const isImpactScale = activeOptionList === "impact_scale";
  const cols = isImpactScale
    ? [["value", "Value"], ["label", "Label"], ["classification", "Classification"], ["protection_profile", "Protection profile"], ["service_level", "Service level"]]
    : [["value", "Value"], ["label", "Label"]];
  container.innerHTML = `
    <table class="ref-table">
      <tr>${cols.map(([, label]) => `<th>${label}</th>`).join("")}<th></th></tr>
      ${rows
        .map(
          (row, idx) => `
        <tr data-idx="${idx}">
          ${cols.map(([key]) => `<td><input type="text" data-col="${key}" value="${escapeHtml(row[key] ?? "")}" style="border:none;background:transparent;width:100%"></td>`).join("")}
          <td><button class="btn small danger" data-remove-row>x</button></td>
        </tr>`
        )
        .join("")}
    </table>
    <button class="btn small" id="add-option-row">+ Add value</button>
  `;
  container.querySelectorAll("tr[data-idx]").forEach((tr) => {
    const idx = Number(tr.dataset.idx);
    tr.querySelectorAll("[data-col]").forEach((inp) => {
      inp.addEventListener("input", () => {
        let v = inp.value;
        if (["value", "classification"].includes(inp.dataset.col) && v !== "" && !isNaN(Number(v)) && isImpactScale) v = Number(v);
        rows[idx][inp.dataset.col] = v;
        markDirty();
      });
    });
    tr.querySelector("[data-remove-row]").onclick = () => {
      rows.splice(idx, 1);
      markDirty();
      renderOptionRows(container);
    };
  });
  document.getElementById("add-option-row").onclick = () => {
    rows.push(isImpactScale ? { value: 0, label: "New value", classification: "", protection_profile: "", service_level: "" } : { value: "new_value", label: "New label" });
    markDirty();
    renderOptionRows(container);
  };
}

// --------------------------------------------------------- impact scale --

function renderImpactScaleTab(panel) {
  const rows = config.impact_scale_table;
  panel.innerHTML = `<div class="card"><p class="desc">Reference definitions of each impact level, shown to everyone in the Reference guide.</p><div id="impact-rows"></div>
    <button class="btn small" id="add-impact-row">+ Add row</button></div>`;
  const container = document.getElementById("impact-rows");
  const draw = () => {
    container.innerHTML = rows
      .map(
        (row, idx) => `
      <div style="border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:10px;background:var(--bg)" data-idx="${idx}">
        <div class="field-row">
          <div><label>Area</label><input data-f="area" type="text" value="${escapeHtml(row.area)}"></div>
          <div><label>Area description</label><input data-f="area_description" type="text" value="${escapeHtml(row.area_description || "")}"></div>
        </div>
        <div class="question"><label class="prompt">Sub-area</label><textarea data-f="sub_area">${escapeHtml(row.sub_area)}</textarea></div>
        <div class="field-row">
          ${[0, 1, 2, 3, 4].map((i) => `<div><label>Level ${i + 1}</label><textarea data-level="${i}">${escapeHtml(row.levels[i] || "")}</textarea></div>`).join("")}
        </div>
        <div style="display:flex;justify-content:flex-end"><button class="btn small danger" data-remove>Remove row</button></div>
      </div>`
      )
      .join("");
    container.querySelectorAll("[data-idx]").forEach((div) => {
      const idx = Number(div.dataset.idx);
      div.querySelectorAll("[data-f]").forEach((el) => {
        el.addEventListener("input", () => { rows[idx][el.dataset.f] = el.value; markDirty(); });
      });
      div.querySelectorAll("[data-level]").forEach((el) => {
        el.addEventListener("input", () => { rows[idx].levels[Number(el.dataset.level)] = el.value; markDirty(); });
      });
      div.querySelector("[data-remove]").onclick = () => { rows.splice(idx, 1); markDirty(); draw(); };
    });
  };
  draw();
  document.getElementById("add-impact-row").onclick = () => {
    rows.push({ area: "", area_description: "", sub_area: "", levels: ["", "", "", "", ""] });
    markDirty();
    draw();
  };
}

// ----------------------------------------------------- classification ---

function renderClassificationTab(panel) {
  const rows = config.classification_matrix;
  panel.innerHTML = `<div class="card"><p class="desc">Defines what each classification code (e.g. C4, I2, A3) means.</p><div id="class-rows"></div>
    <button class="btn small" id="add-class-row">+ Add row</button></div>`;
  const container = document.getElementById("class-rows");
  const draw = () => {
    container.innerHTML = rows
      .map(
        (row, idx) => `
      <div style="border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:10px;background:var(--bg)" data-idx="${idx}">
        <div class="field-row">
          <div class="col-narrow"><label>Aspect</label><input data-f="aspect" type="text" value="${escapeHtml(row.aspect)}"></div>
          <div class="col-narrow"><label>Code</label><input data-f="code" type="text" value="${escapeHtml(row.code)}"></div>
          <div class="col-narrow"><label>Label</label><input data-f="label" type="text" value="${escapeHtml(row.label)}"></div>
        </div>
        <div class="question"><label class="prompt">Criteria</label><textarea data-f="criteria">${escapeHtml(row.criteria || "")}</textarea></div>
        <div class="question"><label class="prompt">Business impact</label><textarea data-f="business_impact">${escapeHtml(row.business_impact || "")}</textarea></div>
        <div class="question"><label class="prompt">Example controls</label><textarea data-f="controls">${escapeHtml(row.controls || "")}</textarea></div>
        <div class="question"><label class="prompt">Example assets</label><textarea data-f="example_assets">${escapeHtml(row.example_assets || "")}</textarea></div>
        <div style="display:flex;justify-content:flex-end"><button class="btn small danger" data-remove>Remove row</button></div>
      </div>`
      )
      .join("");
    container.querySelectorAll("[data-idx]").forEach((div) => {
      const idx = Number(div.dataset.idx);
      div.querySelectorAll("[data-f]").forEach((el) => {
        el.addEventListener("input", () => { rows[idx][el.dataset.f] = el.value; markDirty(); });
      });
      div.querySelector("[data-remove]").onclick = () => { rows.splice(idx, 1); markDirty(); draw(); };
    });
  };
  draw();
  document.getElementById("add-class-row").onclick = () => {
    rows.push({ aspect: "", code: "", label: "", criteria: "", business_impact: "", controls: "", example_assets: "" });
    markDirty();
    draw();
  };
}

// -------------------------------------------------------------- assets --

function renderAssetsTab(panel) {
  const rows = config.information_assets;
  panel.innerHTML = `
    <div class="card">
      <p class="desc">The pre-classified information asset register shown in the Reference guide. Add your organization's own assets here.</p>
      <table class="ref-table" id="assets-table">
        <tr><th>Domain</th><th>Asset</th><th>Definition</th><th>Suggested confidentiality</th><th>Suggested integrity</th><th>Suggested availability</th><th></th></tr>
      </table>
      <button class="btn small" id="add-asset-row">+ Add asset</button>
    </div>
  `;
  const table = document.getElementById("assets-table");
  const cols = ["domain", "asset", "definition", "suggested_confidentiality", "suggested_integrity", "suggested_availability"];
  const draw = () => {
    table.querySelectorAll("tr[data-idx]").forEach((tr) => tr.remove());
    rows.forEach((row, idx) => {
      const tr = document.createElement("tr");
      tr.dataset.idx = idx;
      tr.innerHTML =
        cols.map((c) => `<td><input type="text" data-col="${c}" value="${escapeHtml(row[c] || "")}" style="border:none;background:transparent;width:100%"></td>`).join("") +
        `<td><button class="btn small danger" data-remove>x</button></td>`;
      table.appendChild(tr);
      cols.forEach((c) => {
        tr.querySelector(`[data-col="${c}"]`).addEventListener("input", (e) => { row[c] = e.target.value; markDirty(); });
      });
      tr.querySelector("[data-remove]").onclick = () => { rows.splice(idx, 1); markDirty(); draw(); };
    });
  };
  draw();
  document.getElementById("add-asset-row").onclick = () => {
    rows.push({ domain: "", asset: "", definition: "", suggested_confidentiality: "", suggested_integrity: "", suggested_availability: "" });
    markDirty();
    draw();
  };
}

// --------------------------------------------------------- assessments --

async function renderAssessmentsTab(panel) {
  panel.innerHTML = `
    <div class="card">
      <div class="field-row">
        <div><label>Filter by status</label>
          <select id="status-filter"><option value="">All</option><option value="draft">Draft</option><option value="submitted">Submitted</option></select>
        </div>
      </div>
      <div id="assessments-list" style="margin-top:14px">Loading...</div>
    </div>
  `;
  const load = async () => {
    const status = document.getElementById("status-filter").value;
    const { assessments } = await Api.adminListAssessments(status);
    const list = document.getElementById("assessments-list");
    if (assessments.length === 0) {
      list.innerHTML = `<p class="muted">No assessments found.</p>`;
      return;
    }
    list.innerHTML = `
      <table class="ref-table">
        <tr><th>Project</th><th>Completed by</th><th>Status</th><th>Updated</th><th></th></tr>
        ${assessments
          .map(
            (a) => `<tr>
          <td>${escapeHtml(a.project_name || "(untitled)")}</td>
          <td>${escapeHtml(a.completed_by)} ${a.completed_by_email ? `&lt;${escapeHtml(a.completed_by_email)}&gt;` : ""}</td>
          <td><span class="pill ${a.status}">${a.status}</span></td>
          <td>${new Date(a.updated_at).toLocaleString()}</td>
          <td style="display:flex;gap:6px">
            <a class="btn small" href="/api/assessments/${a.id}/print" target="_blank">Report</a>
            <button class="btn small danger" data-delete="${a.id}">Delete</button>
          </td>
        </tr>`
          )
          .join("")}
      </table>
    `;
    list.querySelectorAll("[data-delete]").forEach((btn) => {
      btn.onclick = async () => {
        if (!confirm("Delete this assessment permanently?")) return;
        await Api.adminDeleteAssessment(btn.dataset.delete);
        load();
      };
    });
  };
  document.getElementById("status-filter").onchange = load;
  load();
}

// ------------------------------------------------------------- advanced --

function renderAdvancedTab(panel) {
  panel.innerHTML = `
    <div class="card">
      <h2>Advanced: raw JSON</h2>
      <p class="desc">For structural changes not covered by the screens above. Edit the JSON, then click "Apply to form" to load it into the editors, and "Save changes" (bottom bar) to persist it.</p>
      <textarea id="raw-json" style="min-height:420px;font-family:monospace;font-size:0.85em"></textarea>
      <div style="margin-top:10px;display:flex;gap:10px">
        <button class="btn" id="apply-json-btn">Apply to form</button>
        <button class="btn" id="reload-json-btn">Reset textarea from current form</button>
      </div>
    </div>
  `;
  const box = document.getElementById("raw-json");
  box.value = JSON.stringify(config, null, 2);
  document.getElementById("reload-json-btn").onclick = () => { box.value = JSON.stringify(config, null, 2); };
  document.getElementById("apply-json-btn").onclick = () => {
    try {
      const parsed = JSON.parse(box.value);
      config = parsed;
      markDirty();
      toast("Applied. Review the other tabs, then click Save changes.");
    } catch (e) {
      toast("Invalid JSON: " + e.message, true);
    }
  };
}

boot();
