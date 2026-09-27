const Api = (() => {
  async function req(method, path, body) {
    const opts = { method, headers: {}, credentials: "same-origin" };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    let data = null;
    try { data = await res.json(); } catch (e) { /* no body */ }
    if (!res.ok) {
      const msg = (data && data.error) || `Request failed (${res.status})`;
      throw new Error(msg);
    }
    return data;
  }

  return {
    getConfig: () => req("GET", "/api/config"),
    listAssessments: (ownerEmail) => req("GET", `/api/assessments?owner_email=${encodeURIComponent(ownerEmail)}`),
    createAssessment: (fields) => req("POST", "/api/assessments", fields),
    getAssessment: (id) => req("GET", `/api/assessments/${id}`),
    updateAssessment: (id, fields) => req("PUT", `/api/assessments/${id}`, fields),
    updateAnswers: (id, tool, answers) => req("PUT", `/api/assessments/${id}/answers`, { tool, answers }),
    submitAssessment: (id) => req("POST", `/api/assessments/${id}/submit`),
    reopenAssessment: (id) => req("POST", `/api/assessments/${id}/reopen`),
    deleteAssessment: (id) => req("DELETE", `/api/assessments/${id}`),

    adminLogin: (password) => req("POST", "/api/admin/login", { password }),
    adminLogout: () => req("POST", "/api/admin/logout"),
    adminSession: () => req("GET", "/api/admin/session"),
    adminGetConfig: () => req("GET", "/api/admin/config"),
    adminPutConfig: (config) => req("PUT", "/api/admin/config", config),
    adminResetConfig: () => req("POST", "/api/admin/config/reset"),
    adminChangePassword: (current_password, new_password) =>
      req("PUT", "/api/admin/password", { current_password, new_password }),
    adminListAssessments: (status) => req("GET", `/api/admin/assessments${status ? `?status=${status}` : ""}`),
    adminGetAssessment: (id) => req("GET", `/api/admin/assessments/${id}`),
    adminDeleteAssessment: (id) => req("DELETE", `/api/admin/assessments/${id}`),
  };
})();

function toast(message, isError) {
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " error" : "");
  el.textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

function debounce(fn, ms) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
