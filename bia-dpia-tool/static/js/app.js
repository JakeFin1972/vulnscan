/* Employee-facing BIA / DPIA wizard. Vanilla JS, no build step. */

const state = {
  config: null,
  assessment: null,
  answers: {},
  results: null,
  steps: [],
  view: "landing",
  visited: new Set(),
};

const saveTimers = new Map();
const RISK_STATUS_OPTIONS = ["Open", "In progress", "Mitigated", "Accepted", "Closed"];
const LIKELIHOOD_LABELS = { 1: "Rare", 2: "Unlikely", 3: "Possible", 4: "Likely", 5: "Almost certain" };
const CONSEQUENCE_LABELS = { 1: "Insignificant", 2: "Minor", 3: "Moderate", 4: "Major", 5: "Critical" };

const appEl = document.getElementById("app");

function findQuestion(tool, key) {
  const t = state.config.tools[tool];
  for (const section of t.sections) {
    for (const q of section.questions) {
      if (q.key === key) return q;
    }
  }
  return null;
}

function findStepTool(stepId) {
  for (const s of state.steps) if (s.id === stepId) return s;
  return null;
}

// -------------------------------------------------------------- routing --

function parseHash() {
  const h = location.hash.replace(/^#\/?/, "");
  const parts = h.split("/").filter(Boolean);
  if (parts.length === 0) return { view: "landing" };
  if (parts[0] === "reference") return { view: "reference" };
  if (parts[0] === "a" && parts[1]) return { view: "wizard", id: Number(parts[1]), step: parts[2] || null };
  return { view: "landing" };
}

function navigate(hash) {
  location.hash = hash;
}

window.addEventListener("hashchange", render);

// ------------------------------------------------------------- bootstrap --

async function boot() {
  state.config = await Api.getConfig();
  document.getElementById("org-name").textContent = state.config.org_name || "";
  state.steps = buildSteps(state.config);
  render();
}

function buildSteps(config) {
  const steps = [{ id: "project_info", group: "Getting started", title: "Project information" }];
  config.tools.bia.sections.forEach((s) =>
    steps.push({ id: "bia." + s.key, group: "Business Impact Assessment", title: s.title, tool: "bia", sectionKey: s.key })
  );
  steps.push({ id: "bia_results", group: "Business Impact Assessment", title: "Results & classification" });
  config.tools.dpia0.sections.forEach((s) =>
    steps.push({ id: "dpia0." + s.key, group: "DPIA — Overview & Scope", title: s.title, tool: "dpia0", sectionKey: s.key })
  );
  config.tools.dpia.sections.forEach((s) =>
    steps.push({ id: "dpia." + s.key, group: "DPIA — Detailed Assessment", title: s.title, tool: "dpia", sectionKey: s.key })
  );
  steps.push({ id: "review", group: "Finish", title: "Review & submit" });
  return steps;
}

// --------------------------------------------------------------- render --

async function render() {
  const route = parseHash();
  document.querySelectorAll("header nav a").forEach((a) => a.classList.remove("active"));

  if (route.view === "landing") {
    document.getElementById("nav-home").classList.add("active");
    return renderLanding();
  }
  if (route.view === "reference") {
    document.getElementById("nav-reference").classList.add("active");
    return renderReference();
  }
  if (route.view === "wizard") {
    return renderWizard(route.id, route.step);
  }
}

// --------------------------------------------------------------- landing --

async function renderLanding() {
  const savedEmail = localStorage.getItem("bia_dpia_email") || "";
  appEl.innerHTML = `
    <main class="content" style="max-width:760px">
      <div class="landing" style="margin-top:20px">
        <h1>Business Impact & Privacy Assessments</h1>
        <p class="muted">Answer a short set of guided questions to assess the business impact of a project or
        solution, and find out whether a full Data Privacy Impact Assessment (DPIA) is needed.</p>
      </div>
      <div class="card">
        <h2>Start a new assessment</h2>
        <div class="field-row">
          <div><label>Project name</label><input id="new-project-name" type="text" placeholder="e.g. Loyalty App Revamp"></div>
        </div>
        <div class="field-row">
          <div><label>Your name</label><input id="new-completed-by" type="text"></div>
          <div><label>Your email</label><input id="new-completed-email" type="email" value="${escapeHtml(savedEmail)}"></div>
        </div>
        <div style="margin-top:14px"><button class="btn primary" id="start-btn">Start assessment</button></div>
      </div>
      <div class="card">
        <h2>My assessments</h2>
        <div class="field-row">
          <div><label>Look up by email</label><input id="lookup-email" type="email" value="${escapeHtml(savedEmail)}" placeholder="you@company.com"></div>
        </div>
        <div style="margin-top:10px"><button class="btn" id="lookup-btn">Show my assessments</button></div>
        <div id="assessment-list" style="margin-top:16px"></div>
      </div>
    </main>
  `;

  document.getElementById("start-btn").onclick = async () => {
    const project_name = document.getElementById("new-project-name").value.trim();
    const completed_by = document.getElementById("new-completed-by").value.trim();
    const completed_by_email = document.getElementById("new-completed-email").value.trim();
    if (completed_by_email) localStorage.setItem("bia_dpia_email", completed_by_email);
    try {
      const res = await Api.createAssessment({ project_name, completed_by, completed_by_email });
      navigate(`#/a/${res.assessment.id}/project_info`);
    } catch (e) {
      toast(e.message, true);
    }
  };

  const doLookup = async () => {
    const email = document.getElementById("lookup-email").value.trim();
    if (!email) return;
    localStorage.setItem("bia_dpia_email", email);
    const listEl = document.getElementById("assessment-list");
    listEl.innerHTML = "Loading...";
    try {
      const { assessments } = await Api.listAssessments(email);
      if (assessments.length === 0) {
        listEl.innerHTML = `<p class="muted">No assessments found for this email yet.</p>`;
        return;
      }
      listEl.innerHTML = assessments
        .map(
          (a) => `
        <div class="row-editable" style="align-items:center;border-bottom:1px solid var(--border);padding:8px 0">
          <div><strong>${escapeHtml(a.project_name || "(untitled)")}</strong>
            <span class="pill ${a.status}">${a.status}</span>
            <div class="muted" style="font-size:0.82em">Updated ${new Date(a.updated_at).toLocaleString()}</div>
          </div>
          <div class="col-narrow" style="flex:0 0 auto;display:flex;gap:6px">
            <a class="btn small" href="#/a/${a.id}/project_info">Open</a>
            <a class="btn small" href="/api/assessments/${a.id}/print" target="_blank">Report</a>
          </div>
        </div>`
        )
        .join("");
    } catch (e) {
      listEl.innerHTML = `<p class="muted">${escapeHtml(e.message)}</p>`;
    }
  };
  document.getElementById("lookup-btn").onclick = doLookup;
  if (savedEmail) doLookup();
}

// ------------------------------------------------------------- reference --

function renderReference() {
  const cfg = state.config;
  appEl.innerHTML = `
    <div class="layout">
      <main class="content" style="max-width:1000px">
        <h1>Reference guide</h1>
        <p class="muted">Use this guide to answer the assessment consistently. It is maintained by your admin team.</p>

        <div class="card">
          <h2>Impact scales</h2>
          <p class="desc">Definitions of Insignificant &rarr; Critical impact used throughout the BIA.</p>
          <table class="ref-table">
            <tr><th>Area</th><th>Sub-area</th><th>1 &mdash; Insignificant</th><th>2 &mdash; Minor</th><th>3 &mdash; Moderate</th><th>4 &mdash; Major</th><th>5 &mdash; Critical</th></tr>
            ${cfg.impact_scale_table
              .map(
                (r) => `<tr><td>${escapeHtml(r.area)}${r.area_description ? `<div class="muted" style="font-size:0.85em">${escapeHtml(r.area_description)}</div>` : ""}</td><td>${escapeHtml(r.sub_area)}</td>${r.levels.map((l) => `<td>${escapeHtml(l)}</td>`).join("")}</tr>`
              )
              .join("")}
          </table>
        </div>

        <div class="card">
          <h2>Classification matrix</h2>
          <p class="desc">What each classification level (C1&ndash;C4, I1&ndash;I4, A1&ndash;A4) means in practice.</p>
          <table class="ref-table">
            <tr><th>Aspect</th><th>Code</th><th>Label</th><th>Criteria</th><th>Business impact</th><th>Example controls</th><th>Example assets</th></tr>
            ${cfg.classification_matrix
              .map(
                (r) => `<tr><td>${escapeHtml(r.aspect)}</td><td><strong>${escapeHtml(r.code)}</strong></td><td>${escapeHtml(r.label)}</td><td>${escapeHtml(r.criteria || "")}</td><td>${escapeHtml(r.business_impact || "")}</td><td>${escapeHtml(r.controls || "")}</td><td>${escapeHtml(r.example_assets || "")}</td></tr>`
              )
              .join("")}
          </table>
        </div>

        <div class="card">
          <h2>Important information assets</h2>
          <p class="desc">Suggested classification for commonly encountered information assets.</p>
          <div class="search-box"><input id="asset-search" type="text" placeholder="Search by domain or asset name..."></div>
          <table class="ref-table" id="asset-table">
            <tr><th>Domain</th><th>Asset</th><th>Definition</th><th>Suggested confidentiality</th></tr>
            ${cfg.information_assets
              .map(
                (r) => `<tr data-search="${escapeHtml((r.domain + " " + r.asset).toLowerCase())}"><td>${escapeHtml(r.domain)}</td><td>${escapeHtml(r.asset)}</td><td>${escapeHtml(r.definition || "")}</td><td>${escapeHtml(r.suggested_confidentiality || "")}</td></tr>`
              )
              .join("")}
          </table>
        </div>
      </main>
    </div>
  `;
  document.getElementById("asset-search").addEventListener("input", (e) => {
    const term = e.target.value.toLowerCase();
    document.querySelectorAll("#asset-table tr[data-search]").forEach((tr) => {
      tr.style.display = tr.dataset.search.includes(term) ? "" : "none";
    });
  });
}

// --------------------------------------------------------------- wizard --

async function renderWizard(id, stepId) {
  try {
    const payload = await Api.getAssessment(id);
    state.assessment = payload.assessment;
    state.answers = payload.answers;
    state.results = payload.results;
  } catch (e) {
    appEl.innerHTML = `<main class="content"><div class="card"><p>${escapeHtml(e.message)}</p><a href="#/">Back to My assessments</a></div></main>`;
    return;
  }

  const step = findStepTool(stepId) || state.steps[0];
  state.visited.add(step.id);

  appEl.innerHTML = `
    <div class="layout">
      <aside class="sidebar" id="sidebar"></aside>
      <main class="content" id="wizard-content"></main>
    </div>
    <div class="wizard-footer">
      <div class="save-status" id="save-status">&nbsp;</div>
      <div style="display:flex;gap:10px">
        <button class="btn" id="btn-back">&larr; Back</button>
        <button class="btn primary" id="btn-next">Next &rarr;</button>
      </div>
    </div>
  `;

  renderSidebar(step.id);
  renderStep(step);

  const idx = state.steps.findIndex((s) => s.id === step.id);
  document.getElementById("btn-back").disabled = idx <= 0;
  document.getElementById("btn-back").onclick = () => {
    if (idx > 0) navigate(`#/a/${id}/${state.steps[idx - 1].id}`);
  };
  document.getElementById("btn-next").textContent = idx === state.steps.length - 1 ? "Finish" : "Next →";
  document.getElementById("btn-next").onclick = () => {
    if (idx < state.steps.length - 1) navigate(`#/a/${id}/${state.steps[idx + 1].id}`);
  };
}

function renderSidebar(activeStepId) {
  const groups = [];
  for (const step of state.steps) {
    let group = groups.find((g) => g.name === step.group);
    if (!group) {
      group = { name: step.group, steps: [] };
      groups.push(group);
    }
    group.steps.push(step);
  }
  const sidebar = document.getElementById("sidebar");
  sidebar.innerHTML = groups
    .map(
      (g) => `
    <div class="group-title">${escapeHtml(g.name)}</div>
    ${g.steps
      .map((s) => {
        const cls = ["step"];
        if (s.id === activeStepId) cls.push("active");
        else if (state.visited.has(s.id)) cls.push("done");
        return `<button class="${cls.join(" ")}" data-step="${s.id}"><span class="dot"></span>${escapeHtml(s.title)}</button>`;
      })
      .join("")}
  `
    )
    .join("");
  sidebar.querySelectorAll("[data-step]").forEach((btn) => {
    btn.onclick = () => navigate(`#/a/${state.assessment.id}/${btn.dataset.step}`);
  });
}

function setSaveStatus(text) {
  const el = document.getElementById("save-status");
  if (el) el.textContent = text;
}

function renderStep(step) {
  const content = document.getElementById("wizard-content");
  if (step.id === "project_info") return renderProjectInfoStep(content);
  if (step.id === "bia_results") return renderResultsStep(content);
  if (step.id === "review") return renderReviewStep(content);

  const tool = state.config.tools[step.tool];
  const section = tool.sections.find((s) => s.key === step.sectionKey);
  content.innerHTML = `
    <div class="card">
      <h2>${escapeHtml(section.title)}</h2>
      ${section.description ? `<p class="desc">${escapeHtml(section.description)}</p>` : ""}
      ${dpiaNeededNoticeHtml(step.tool)}
      <div id="questions"></div>
    </div>
  `;
  const qContainer = document.getElementById("questions");
  qContainer.innerHTML = section.questions.map((q) => renderQuestionHtml(step.tool, q)).join("");
  wireQuestionEvents(qContainer, step.tool);
}

function dpiaNeededNoticeHtml(tool) {
  if (tool !== "dpia0" && tool !== "dpia") return "";
  if (!state.results) return "";
  const dn = state.results.dpia_needed;
  return `<div class="banner ${dn.result === "Yes" ? "yes" : "no"}">
    <strong>Is a full DPIA needed?</strong> ${dn.result}.
    ${dn.reasons.length ? `<ul>${dn.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>` : `<div class="muted">No screening trigger has been hit yet, based on the answers so far. You can still complete this DPIA regardless.</div>`}
  </div>`;
}

// ------------------------------------------------------------ questions --

function renderQuestionHtml(tool, q) {
  const answer = state.answers[q.key] || {};
  const idLabel = q.id ? `<span class="qid">${escapeHtml(q.id)}</span>` : "";
  let inputHtml = "";

  switch (q.input_type) {
    case "text":
      inputHtml = `<input type="text" data-field="value" value="${escapeHtml(answer.value || "")}">`;
      break;
    case "textarea":
      inputHtml = `<textarea data-field="value">${escapeHtml(answer.value || "")}</textarea>`;
      break;
    case "number":
      inputHtml = `<input type="number" min="0" data-field="value" value="${answer.value ?? ""}">`;
      break;
    case "date":
      inputHtml = `<input type="date" data-field="value" value="${escapeHtml(answer.value || "")}">`;
      break;
    case "yesno":
      inputHtml = selectHtml(state.config.option_lists.yes_no, answer.value, "value", "-- select --");
      break;
    case "select":
      inputHtml = selectHtml(state.config.option_lists[q.option_list] || [], answer.value, "value", "-- select --");
      break;
    case "multiselect":
      inputHtml = checkboxListHtml(state.config.option_lists[q.option_list] || [], answer.value || []);
      break;
    case "impact": {
      const opts = (state.config.option_lists.impact_scale || []).filter((o) => o.value >= 0);
      inputHtml = selectHtml(opts, answer.value, "value", "-- select impact --");
      break;
    }
    default:
      inputHtml = `<input type="text" data-field="value" value="${escapeHtml(answer.value || "")}">`;
  }

  const riskHtml = q.has_risk_register ? renderRiskPanel(q, answer) : "";

  return `
    <div class="question" data-key="${escapeHtml(q.key)}">
      <label class="prompt">${idLabel}${escapeHtml(q.prompt)}</label>
      ${q.guidance ? `<div class="guidance">${escapeHtml(q.guidance)}</div>` : ""}
      ${inputHtml}
      <div class="comment-field">
        <label>Comment</label>
        <input type="text" data-field="comment" value="${escapeHtml(answer.comment || "")}" placeholder="Optional notes...">
      </div>
      ${riskHtml}
    </div>
  `;
}

function selectHtml(options, current, field, placeholder) {
  const cur = current === undefined || current === null ? "" : String(current);
  return `<select data-field="${field}">
    <option value="">${placeholder || "-- select --"}</option>
    ${options
      .map((o) => `<option value="${escapeHtml(o.value)}" ${String(o.value) === cur ? "selected" : ""}>${escapeHtml(o.label)}</option>`)
      .join("")}
  </select>`;
}

function checkboxListHtml(options, current) {
  const currentArr = Array.isArray(current) ? current.map(String) : [];
  return `<div class="checkbox-list">
    ${options
      .map(
        (o) => `<label><input type="checkbox" data-field="value" value="${escapeHtml(o.value)}" ${currentArr.includes(String(o.value)) ? "checked" : ""}> ${escapeHtml(o.label)}</label>`
      )
      .join("")}
  </div>`;
}

function renderRiskPanel(q, answer) {
  const hasData = ["risk_identified", "remediation", "likelihood", "consequence", "risk_owner"].some((f) => answer[f]);
  const likelihoodOpts = Object.entries(LIKELIHOOD_LABELS).map(([value, label]) => ({ value, label: `${value} — ${label}` }));
  const consequenceOpts = Object.entries(CONSEQUENCE_LABELS).map(([value, label]) => ({ value, label: `${value} — ${label}` }));
  const statusOpts = RISK_STATUS_OPTIONS.map((s) => ({ value: s, label: s }));
  const yn = state.config.option_lists.yes_no;

  const scoreInfo = state.results && state.results.dpia_risks.by_question[q.key];
  const badge = scoreInfo && scoreInfo.level && scoreInfo.level !== "Not rated"
    ? `<span class="risk-score-badge badge-${scoreInfo.level.toLowerCase()}">${scoreInfo.level} (${scoreInfo.score})</span>`
    : "";

  return `
    <button type="button" class="risk-toggle" data-risk-toggle>${hasData ? "Edit" : "+ Add"} risk & remediation details ${badge}</button>
    <div class="risk-panel ${hasData ? "" : "hidden"}" data-risk-panel>
      <div class="field-row">
        <div><label>Risk identified</label><textarea data-field="risk_identified">${escapeHtml(answer.risk_identified || "")}</textarea></div>
        <div><label>Remediation options</label><textarea data-field="remediation">${escapeHtml(answer.remediation || "")}</textarea></div>
      </div>
      <div class="field-row">
        <div><label>Likelihood</label>${selectHtml(likelihoodOpts, answer.likelihood, "likelihood", "-- select --")}</div>
        <div><label>Consequence to the business</label>${selectHtml(consequenceOpts, answer.consequence, "consequence", "-- select --")}</div>
        <div><label>Risk owner</label><input type="text" data-field="risk_owner" value="${escapeHtml(answer.risk_owner || "")}"></div>
      </div>
      <div class="field-row">
        <div><label>Impact on brand & reputation?</label>${selectHtml(yn, answer.impact_brand, "impact_brand", "-- select --")}</div>
        <div><label>Impact on finance (incl. sales)?</label>${selectHtml(yn, answer.impact_finance, "impact_finance", "-- select --")}</div>
        <div><label>Impact on business & people?</label>${selectHtml(yn, answer.impact_people, "impact_people", "-- select --")}</div>
      </div>
      <div class="field-row">
        <div><label>Rationale (where "yes" was selected above)</label><textarea data-field="rationale">${escapeHtml(answer.rationale || "")}</textarea></div>
        <div><label>Conclusion</label><textarea data-field="conclusion">${escapeHtml(answer.conclusion || "")}</textarea></div>
      </div>
      <div class="field-row">
        <div><label>Status</label>${selectHtml(statusOpts, answer.status, "status", "-- select --")}</div>
        <div><label>Due date</label><input type="date" data-field="due_date" value="${escapeHtml(answer.due_date || "")}"></div>
        <div><label>Completion date</label><input type="date" data-field="completion_date" value="${escapeHtml(answer.completion_date || "")}"></div>
      </div>
      <div><label>Additional comments</label><textarea data-field="risk_comments">${escapeHtml(answer.risk_comments || "")}</textarea></div>
    </div>
  `;
}

const RISK_FIELDS = [
  "risk_identified", "remediation", "likelihood", "consequence", "impact_brand",
  "impact_finance", "impact_people", "rationale", "conclusion", "risk_owner",
  "status", "due_date", "completion_date", "risk_comments",
];

function readAnswerFromContainer(container, q) {
  const obj = {};
  if (q.input_type === "multiselect") {
    obj.value = Array.from(container.querySelectorAll('[data-field="value"]:checked')).map((el) => el.value);
  } else {
    const el = container.querySelector('[data-field="value"]');
    if (el) {
      let v = el.value;
      if ((q.input_type === "number" || q.input_type === "impact") && v !== "") v = Number(v);
      obj.value = v;
    }
  }
  const commentEl = container.querySelector('[data-field="comment"]');
  if (commentEl) obj.comment = commentEl.value;
  if (q.has_risk_register) {
    for (const f of RISK_FIELDS) {
      const fe = container.querySelector(`[data-field="${f}"]`);
      if (fe) {
        let v = fe.value;
        if ((f === "likelihood" || f === "consequence") && v !== "") v = Number(v);
        obj[f] = v;
      }
    }
  }
  return obj;
}

function wireQuestionEvents(qContainer, tool) {
  qContainer.querySelectorAll("[data-risk-toggle]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const panel = btn.parentElement.querySelector("[data-risk-panel]");
      panel.classList.toggle("hidden");
    });
  });

  const handler = (e) => {
    const container = e.target.closest(".question");
    if (!container) return;
    const key = container.dataset.key;
    const q = findQuestion(tool, key);
    if (!q) return;
    const obj = readAnswerFromContainer(container, q);
    state.answers[key] = obj;
    queueSave(tool, key, obj, container, q);
  };

  // Note: both listeners call the same handler directly (no shared debounce
  // here) -- queueSave() below debounces per question key, independently.
  // A single shared debounce across the whole container would let a rapid
  // edit to one field cancel the pending save of another field entirely.
  qContainer.addEventListener("change", handler);
  qContainer.addEventListener("input", handler);
}

function queueSave(tool, key, obj) {
  clearTimeout(saveTimers.get(key));
  setSaveStatus("Typing...");
  const t = setTimeout(async () => {
    setSaveStatus("Saving...");
    try {
      const res = await Api.updateAnswers(state.assessment.id, tool, { [key]: obj });
      state.results = res.results;
      state.answers = res.answers;
      setSaveStatus("Saved ✓");
      refreshRiskBadge(key);
    } catch (e) {
      setSaveStatus("Save failed");
      toast(e.message, true);
    }
  }, 500);
  saveTimers.set(key, t);
}

function refreshRiskBadge(key) {
  const container = document.querySelector(`.question[data-key="${CSS.escape(key)}"]`);
  if (!container) return;
  const btn = container.querySelector("[data-risk-toggle]");
  if (!btn) return;
  const info = state.results.dpia_risks.by_question[key];
  const badge = info && info.level && info.level !== "Not rated" ? `<span class="risk-score-badge badge-${info.level.toLowerCase()}">${info.level} (${info.score})</span>` : "";
  const hasData = container.querySelector("[data-risk-panel]") && !container.querySelector("[data-risk-panel]").classList.contains("hidden");
  btn.innerHTML = `${hasData ? "Edit" : "+ Add"} risk & remediation details ${badge}`;
}

// -------------------------------------------------------- project info --

function renderProjectInfoStep(content) {
  const a = state.assessment;
  content.innerHTML = `
    <div class="card">
      <h2>Project key information</h2>
      <p class="desc">Basic details about the project or solution being assessed.</p>
      <div class="field-row">
        <div><label>Project name</label><input data-f="project_name" type="text" value="${escapeHtml(a.project_name)}"></div>
        <div><label>Country/countries or business unit impacted</label><input data-f="countries" type="text" value="${escapeHtml(a.countries)}"></div>
      </div>
      <div class="question"><label class="prompt">Description of the project</label>
        <div class="guidance">Brief summary indicating the key features of the project.</div>
        <textarea data-f="description">${escapeHtml(a.description)}</textarea>
      </div>
      <div class="field-row">
        <div><label>Name of project manager</label><input data-f="project_manager" type="text" value="${escapeHtml(a.project_manager)}"></div>
        <div><label>Name of the solution (if applicable)</label><input data-f="solution_name" type="text" value="${escapeHtml(a.solution_name)}"></div>
        <div><label>Solution owner (if applicable)</label><input data-f="solution_owner" type="text" value="${escapeHtml(a.solution_owner)}"></div>
      </div>
      <div class="field-row">
        <div><label>Completed by</label><input data-f="completed_by" type="text" value="${escapeHtml(a.completed_by)}"></div>
        <div><label>Completed by (email)</label><input data-f="completed_by_email" type="email" value="${escapeHtml(a.completed_by_email)}"></div>
        <div><label>Form completion date</label><input data-f="form_date" type="date" value="${escapeHtml(a.form_date)}"></div>
      </div>
      <p class="muted">For support with this tool, contact ${escapeHtml(state.config.settings.support_contact || "your Information Security or Data Privacy team")}.</p>
    </div>
  `;
  content.querySelectorAll("[data-f]").forEach((el) => {
    const save = debounce(async () => {
      setSaveStatus("Saving...");
      const fields = {};
      content.querySelectorAll("[data-f]").forEach((e2) => (fields[e2.dataset.f] = e2.value));
      try {
        const res = await Api.updateAssessment(state.assessment.id, fields);
        state.assessment = res.assessment;
        setSaveStatus("Saved ✓");
      } catch (e) {
        setSaveStatus("Save failed");
        toast(e.message, true);
      }
    }, 500);
    el.addEventListener("input", save);
    el.addEventListener("change", save);
  });
}

// ------------------------------------------------------------- results --

function renderResultsStep(content) {
  const r = state.results;
  content.innerHTML = `
    <div class="card">
      <h2>Protection level</h2>
      <p class="desc">Automatically computed from your Confidentiality / Integrity / Availability answers.</p>
      <div class="results-grid">
        ${Object.entries(r.bia_categories)
          .map(
            ([cat, entry]) => `
          <div class="result-tile">
            <h4>${escapeHtml(cat)}</h4>
            <div class="big">${escapeHtml(entry.max_label)}</div>
            ${entry.classification_code ? `<div class="sub">${escapeHtml(entry.classification_label || "")} &mdash; ${escapeHtml(entry.classification_code)}</div><div class="sub">Protection profile: ${escapeHtml(entry.protection_profile || "")} &middot; Service level: ${escapeHtml(entry.service_level || "")}</div>` : ""}
            <div class="sub muted">${entry.answered_count}/${entry.total_questions} scenarios answered</div>
          </div>`
          )
          .join("")}
      </div>
    </div>
    <div class="card">
      ${dpiaNeededNoticeHtml("dpia")}
      <p class="muted">Continue to the DPIA sections below to document processing details, even if a full DPIA isn't strictly required &mdash; it's good practice whenever personal data is involved.</p>
    </div>
  `;
}

// -------------------------------------------------------------- review --

function renderReviewStep(content) {
  const a = state.assessment;
  const submitted = a.status === "submitted";
  content.innerHTML = `
    <div class="card">
      <h2>Review & submit</h2>
      <p class="desc">Status: <span class="pill ${a.status}">${a.status}</span></p>
      <p>Use the <a href="/api/assessments/${a.id}/print" target="_blank">full report view</a> to review every answer, or print/save it as a PDF from your browser.</p>
      <div style="display:flex;gap:10px;margin-top:16px">
        ${submitted
          ? `<button class="btn" id="reopen-btn">Reopen for editing</button>`
          : `<button class="btn primary" id="submit-btn">Submit assessment</button>`}
        <button class="btn danger" id="delete-btn">Delete this assessment</button>
      </div>
    </div>
  `;
  const submitBtn = document.getElementById("submit-btn");
  if (submitBtn) {
    submitBtn.onclick = async () => {
      try {
        const res = await Api.submitAssessment(a.id);
        state.assessment = res.assessment;
        toast("Assessment submitted.");
        renderReviewStep(content);
      } catch (e) {
        toast(e.message, true);
      }
    };
  }
  const reopenBtn = document.getElementById("reopen-btn");
  if (reopenBtn) {
    reopenBtn.onclick = async () => {
      const res = await Api.reopenAssessment(a.id);
      state.assessment = res.assessment;
      renderReviewStep(content);
    };
  }
  document.getElementById("delete-btn").onclick = async () => {
    if (!confirm("Delete this assessment permanently?")) return;
    await Api.deleteAssessment(a.id);
    navigate("#/");
  };
}

boot();
