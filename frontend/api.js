// ============================================================
//  SafeAIScan — API Layer
//  Central request handler with auth, error handling, retries
// ============================================================

const BASE_URL = "https://rathious-safeaiscan.hf.space";
const MAX_RETRIES = 2;
const RETRY_DELAY_MS = 800;

// ---- AUTH HELPERS ----
const getToken  = () => localStorage.getItem("access_token");
const getApiKey = () => localStorage.getItem("api_key");

function clearAuth() {
  localStorage.clear();
  window.location.replace("login.html");
}

// ---- RETRY HELPER ----
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ---- CORE REQUEST ----
async function apiRequest(endpoint, options = {}, retries = MAX_RETRIES) {
  const token  = getToken();
  const apiKey = getApiKey();

  const headers = {
    "Content-Type": "application/json",
    ...(token  && token  !== "undefined" && { "Authorization": `Bearer ${token}` }),
    ...(apiKey && apiKey !== "undefined" && { "x-api-key": apiKey }),
    ...(options.headers || {})
  };

  try {
    const res = await fetch(BASE_URL + endpoint, { ...options, headers });

    if (res.status === 401) {
      clearAuth();
      throw new Error("Session expired. Please log in again.");
    }

    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new Error(`HTTP ${res.status}: ${text}`);
    }

    return res;

  } catch (err) {
    // Retry on network errors (not auth errors)
    if (retries > 0 && !err.message.includes("Session expired")) {
      await sleep(RETRY_DELAY_MS);
      return apiRequest(endpoint, options, retries - 1);
    }
    throw err;
  }
}

// ---- SAFE JSON PARSE ----
async function safeJson(res) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    console.error("Non-JSON response:", text.substring(0, 300));
    throw new Error("Invalid response from server");
  }
}

// ============================================================
//  API METHODS
// ============================================================

async function analyzeCode(text) {
  const res = await apiRequest("/api/analyze", {
    method: "POST",
    body: JSON.stringify({ text })
  });
  return safeJson(res);
}

async function scanRepoAPI(repoUrl) {
  const res = await apiRequest("/api/scan-repo", {
    method: "POST",
    body: JSON.stringify({ repo_url: repoUrl })
  });
  return safeJson(res);
}

async function getTaskStatus(taskId) {
  const res = await apiRequest(`/api/task/${taskId}`);
  return safeJson(res);
}

async function getUsage() {
  const res = await apiRequest("/api/usage");
  return safeJson(res);
}

async function getHistory() {
  const res = await apiRequest("/api/history");
  return safeJson(res);
}

async function getMe() {
  const res = await apiRequest("/api/me");
  return safeJson(res);
}

async function fetchCVE() {
  const input = document.getElementById("cveInput")?.value?.trim();
  if (!input) return showToast("Enter a CVE ID or keyword", "warning");

  const panel = document.getElementById("cvePanel");
  if (!panel) return;

  panel.innerHTML = `<div class="skeleton" style="height:60px; border-radius:8px;"></div>`;

  try {
    const res = await apiRequest(`/api/cve/search?query=${encodeURIComponent(input)}`);
    const data = await safeJson(res);

    if (!data.cves?.length) {
      panel.innerHTML = `<div style="color:var(--text-muted);font-size:12px;padding:8px 0;">No CVEs found for "${input}"</div>`;
      return;
    }

    panel.innerHTML = data.cves.map(cve => `
      <div class="panel mb-2 pop-in">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <strong style="font-size:12px;color:var(--accent-2);">${cve.id}</strong>
          <span class="badge-pill sev-${cvssSev(cve.cvss)}">${cve.cvss || "N/A"}</span>
        </div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">${cve.description || ""}</div>
      </div>
    `).join("");

  } catch (err) {
    console.error(err);
    panel.innerHTML = `<div style="color:var(--danger);font-size:12px;">Error: ${err.message}</div>`;
  }
}

function cvssSev(score) {
  if (!score) return "low";
  if (score >= 9)  return "critical";
  if (score >= 7)  return "high";
  if (score >= 4)  return "medium";
  return "low";
}

// ============================================================
//  GLOBAL TOAST NOTIFICATION
// ============================================================
function showToast(message, type = "info") {
  const colors = {
    info:    "rgba(91,123,254,0.15)",
    success: "rgba(52,211,153,0.12)",
    warning: "rgba(251,146,60,0.12)",
    error:   "rgba(244,63,94,0.12)"
  };
  const textColors = {
    info: "#93aaff", success: "#6ee7b7", warning: "#fdba74", error: "#fb7185"
  };

  const toast = document.createElement("div");
  toast.style.cssText = `
    position:fixed; bottom:20px; right:20px; z-index:99999;
    background:${colors[type] || colors.info};
    color:${textColors[type] || textColors.info};
    border:1px solid ${textColors[type] || textColors.info}33;
    border-radius:10px; padding:11px 18px; font-size:13px;
    font-family:'DM Sans',sans-serif; font-weight:500;
    backdrop-filter:blur(12px);
    box-shadow:0 8px 32px rgba(0,0,0,0.4);
    animation: toastIn 0.25s ease both;
    max-width: 320px;
  `;
  toast.textContent = message;

  if (!document.querySelector("#toastStyle")) {
    const s = document.createElement("style");
    s.id = "toastStyle";
    s.textContent = `
      @keyframes toastIn { from { opacity:0; transform:translateY(10px); } to { opacity:1; transform:translateY(0); } }
      @keyframes toastOut { from { opacity:1; } to { opacity:0; transform:translateY(10px); } }
    `;
    document.head.appendChild(s);
  }

  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = "toastOut 0.25s ease forwards";
    setTimeout(() => toast.remove(), 260);
  }, 3000);
}

// Global error boundary
window.addEventListener("unhandledrejection", e => {
  console.error("Unhandled rejection:", e.reason);
});
