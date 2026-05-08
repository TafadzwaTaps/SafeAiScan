// ============================================================
//  SecretScan — API Layer v3.0
//  Rewired to new secrets-scanner backend endpoints
// ============================================================

const BASE_URL = "https://rathious-safeaiscan.hf.space";
const MAX_RETRIES = 2;
const RETRY_DELAY_MS = 900;

// ---- AUTH HELPERS ----
const getToken  = () => localStorage.getItem("access_token");
const getApiKey = () => localStorage.getItem("api_key");

function clearAuth() {
  localStorage.clear();
  window.location.replace("login.html");
}

// ---- PRO HELPERS (simple is_pro boolean — no plan tiers) ----
// Source of truth: localStorage "is_pro" = "true" | "false"
// DEV_MODE always acts as Pro.

function isProUser() {
  if (window.DEV_MODE) return true;
  return localStorage.getItem("is_pro") === "true";
}

// Legacy alias kept so any leftover canAccessFeature() calls don't crash
function canAccessFeature(feature) {
  if (window.DEV_MODE) return true;
  // All features (repo_scan, pdf download, full findings) require Pro
  return isProUser();
}

// No-op stubs — kept so existing callers don't throw ReferenceErrors
function getUserPlan()   { return isProUser() ? "pro" : "free"; }
function getUserLimits() { return null; }
function cachePlanData() {}

// ---- RETRY HELPER ----
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ---- CORE REQUEST ----
async function apiRequest(endpoint, options = {}, retries = MAX_RETRIES) {
  const token  = getToken();
  const apiKey = getApiKey();

  // FIX: only attach x-api-key when the caller explicitly opts in via options.useApiKey
  // Sending a stale/rotated api_key on every browser request caused 403 "Invalid API key"
  // which was previously misclassified as a PlanError, breaking all dashboard calls.
  const sendApiKey = options.useApiKey && apiKey && apiKey !== "undefined" && apiKey !== "null";

  const headers = {
    "Content-Type": "application/json",
    ...(token   && token  !== "undefined" && token  !== "null" && { "Authorization": `Bearer ${token}` }),
    ...(sendApiKey && { "x-api-key": apiKey }),
    ...(options.headers || {})
  };

  // Strip internal flag before passing to fetch
  const { useApiKey: _omit, ...fetchOptions } = options;

  try {
    const res = await fetch(BASE_URL + endpoint, { ...fetchOptions, headers });

    if (res.status === 401) {
      clearAuth();
      throw new Error("Session expired. Please log in again.");
    }

    if (res.status === 403) {
      const body = await res.json().catch(() => ({}));
      const msg  = body?.detail?.error || body?.error || "Access denied";

      // FIX: "Invalid API key" is an auth/credential error, NOT a plan restriction.
      // Strip the bad key from storage and retry the request without it so the
      // JWT-only flow takes over — no upgrade modal, no crash.
      if (msg === "Invalid API key") {
        console.warn("[SafeAIScan] Stale API key detected — removing from storage and retrying.");
        localStorage.removeItem("api_key");
        _userLimits = null;
        localStorage.removeItem("user_limits");
        // Retry once without the api key
        if (retries > 0) {
          return apiRequest(endpoint, { ...fetchOptions, headers: options.headers }, retries - 1);
        }
        throw new Error("API key invalid. Please rotate your key in settings.");
      }

      throw new PlanError(msg);
    }

    if (res.status === 429) {
      const body = await res.json().catch(() => ({}));
      const msg  = body?.detail?.error || body?.error || "Usage limit reached";
      throw new LimitError(msg);
    }

    if (!res.ok) {
      const body = await res.json().catch(() => null);
      const msg  = body?.detail?.error || body?.error || res.statusText || `HTTP ${res.status}`;
      throw new Error(msg);
    }

    return res;

  } catch (err) {
    if (err instanceof PlanError || err instanceof LimitError) throw err;
    if (err.message.includes("Session expired")) throw err;
    if (err.message.includes("API key invalid")) throw err;

    if (retries > 0) {
      await sleep(RETRY_DELAY_MS);
      return apiRequest(endpoint, fetchOptions, retries - 1);
    }
    throw err;
  }
}

// ---- CUSTOM ERROR TYPES ----
class PlanError extends Error {
  constructor(message) {
    super(message);
    this.name = "PlanError";
  }
}
class LimitError extends Error {
  constructor(message) {
    super(message);
    this.name = "LimitError";
  }
}

// ---- SAFE JSON PARSE ----
async function safeJson(res) {
  const text = await res.text();
  try {
    const parsed = JSON.parse(text);
    // Unwrap standardized {success, data} envelope
    if (parsed && typeof parsed === "object" && "success" in parsed) {
      if (!parsed.success) throw new Error(parsed.error || "Request failed");
      return parsed.data ?? parsed;
    }
    return parsed;
  } catch (e) {
    if (e.message !== "Request failed") {
      console.error("Non-JSON response:", text.substring(0, 200));
    }
    throw e;
  }
}

// ============================================================
//  API METHODS
// ============================================================

// scanFile: upload a ZIP to POST /scan/file
// (dashboard code-paste scan is replaced by file upload)
async function analyzeCode(text) {
  // Legacy stub — dashboard still calls this; route to /api/analyze for backwards compat
  // Replace with scanFile() when the dashboard UI is updated for ZIP upload
  // NOTE: /api/analyze is a backwards-compatibility stub.
  // For new code, use scanFile() with a ZIP upload instead.
  const res = await apiRequest("/api/analyze", {
    method: "POST",
    body: JSON.stringify({ text })
  });
  return safeJson(res);
}

async function scanFile(formData) {
  // Upload a ZIP file. formData must be a FormData object with key "file".
  const token = getToken();
  const res = await fetch(BASE_URL + "/scan/file", {
    method: "POST",
    headers: {
      ...(token && token !== "undefined" && { "Authorization": `Bearer ${token}` }),
      // NO Content-Type header — browser sets it automatically with boundary for multipart
    },
    body: formData,
  });
  if (res.status === 401) { clearAuth(); throw new Error("Session expired."); }
  if (res.status === 429) {
    const b = await res.json().catch(() => ({}));
    throw new LimitError(b?.detail?.error || b?.error || "Scan limit reached.");
  }
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new Error(b?.detail?.error || b?.error || `HTTP ${res.status}`);
  }
  return safeJson(res);
}

async function scanRepoAPI(repoUrl) {
  // All authenticated users can scan repos — Pro users get full findings
  const res = await apiRequest("/scan/repo", {
    method: "POST",
    body: JSON.stringify({ repo_url: repoUrl })
  });
  return safeJson(res);
}

async function getTaskStatus(taskId) {
  const res = await apiRequest(`/scan/status/${taskId}`);
  return safeJson(res);
}

async function getUsage() {
  // /api/usage removed in refactor — return empty array gracefully
  return [];
}

async function getHistory() {
  const res = await apiRequest("/scan/history");
  return safeJson(res);
}

async function getMe() {
  const res  = await apiRequest("/auth/me");
  const data = await safeJson(res);
  // Persist is_pro so gating works across page loads
  if (!window.DEV_MODE && data?.is_pro !== undefined) {
    localStorage.setItem("is_pro", data.is_pro ? "true" : "false");
  }
  return data;
}

function rotateApiKey() {
  // API key rotation removed in MVP refactor — no-op
  showToast("API key management not available in this version.", "info");
}

async function fetchCVE() {
  // CVE lookup removed in MVP refactor.
  const panel = document.getElementById("cvePanel");
  if (panel) {
    panel.innerHTML = `<div style="color:var(--text-muted);font-size:12px;padding:8px 0;">
      <i class="bi bi-info-circle me-1"></i>CVE lookup is not available in this version.
    </div>`;
  }
}

// FIX: guard with typeof check — app.js and minisky.js also define these helpers
if (typeof window.cvssSev === "undefined") {
  window.cvssSev = function cvssSev(score) {
    if (score == null) return "low";
    if (score >= 9)  return "critical";
    if (score >= 7)  return "high";
    if (score >= 4)  return "medium";
    return "low";
  };
}
function cvssSev(score) { return window.cvssSev(score); }

if (typeof window.escHtml === "undefined") {
  window.escHtml = function escHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  };
}
function escHtml(str) { return window.escHtml(str); }


// ============================================================
//  PAYMENT — PayPal upgrade flow
// ============================================================

async function createPayPalOrder() {
  // POST /payment/create → returns { order_id, approve_url }
  const res  = await apiRequest("/payment/create", { method: "POST" });
  const data = await safeJson(res);
  return data;
}

async function getReport(scanId) {
  const res = await apiRequest(`/report/${scanId}`);
  return safeJson(res);
}

async function downloadPDFReport(scanId) {
  // PDF is gated to Pro users on the backend
  if (!isProUser()) {
    throw new PlanError("PDF reports require a Pro account. Upgrade to download.");
  }
  const token = getToken();
  const res   = await fetch(`${BASE_URL}/report/${scanId}/pdf`, {
    headers: { "Authorization": `Bearer ${token}` }
  });
  if (res.status === 403) throw new PlanError("PDF download requires Pro.");
  if (!res.ok) throw new Error(`PDF download failed: HTTP ${res.status}`);

  // Trigger browser download
  const blob = await res.blob();
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `secretscan-${scanId.slice(0, 8)}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}

// Expose globally
window.scanFile         = scanFile;
window.scanRepoAPI      = scanRepoAPI;
window.createPayPalOrder= createPayPalOrder;
window.getReport        = getReport;
window.downloadPDFReport= downloadPDFReport;
window.isProUser        = isProUser;
// ============================================================
//  UPGRADE PROMPT (shown on PlanError / LimitError)
// ============================================================
function showUpgradePrompt(message) {
  const plan = getUserPlan();
  const modal = document.createElement("div");
  modal.style.cssText = `
    position:fixed;inset:0;z-index:99998;display:flex;align-items:center;justify-content:center;
    background:rgba(0,0,0,0.65);backdrop-filter:blur(6px);
  `;
  modal.innerHTML = `
    <div style="background:var(--bg-2);border:1px solid var(--border-bright);border-radius:18px;
                padding:28px 32px;max-width:400px;width:90%;box-shadow:0 24px 80px rgba(0,0,0,0.6);
                animation:popIn 0.25s cubic-bezier(0.34,1.56,0.64,1) both;">
      <div style="font-family:'Syne',sans-serif;font-size:18px;font-weight:800;margin-bottom:8px;">
        <i class="bi bi-lightning-charge" style="color:var(--warning);"></i> Upgrade Required
      </div>
      <p style="font-size:13px;color:var(--text-muted);margin-bottom:20px;">${escHtml(message)}</p>
      <div style="display:grid;gap:8px;">
        <button onclick="window.location.href='pricing.html'" style="
          background:linear-gradient(135deg,#5b7bfe,#4361ee);color:#fff;border:none;
          padding:11px 20px;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;
          font-family:'DM Sans',sans-serif;">
          <i class="bi bi-lightning-charge me-1"></i>View Upgrade Plans
        </button>
        <button onclick="this.closest('[style]').remove()" style="
          background:transparent;color:var(--text-muted);border:1px solid var(--border);
          padding:9px 20px;border-radius:10px;font-size:13px;cursor:pointer;
          font-family:'DM Sans',sans-serif;">
          Maybe Later
        </button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  modal.addEventListener("click", e => { if (e.target === modal) modal.remove(); });
}

// ============================================================
//  TOAST NOTIFICATIONS
//  FIX: guarded — app.js also defines showToast; only define once
// ============================================================
if (typeof window.showToast === "undefined")
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
  const icons = {
    info: "bi-info-circle", success: "bi-check-circle", warning: "bi-exclamation-triangle", error: "bi-x-circle"
  };

  if (!document.querySelector("#toastStyle")) {
    const s = document.createElement("style");
    s.id = "toastStyle";
    s.textContent = `
      @keyframes toastIn  { from { opacity:0; transform:translateY(12px) scale(0.95); } to { opacity:1; transform:translateY(0) scale(1); } }
      @keyframes toastOut { from { opacity:1; transform:scale(1); } to { opacity:0; transform:translateY(6px) scale(0.95); } }
      .toast-container { position:fixed;bottom:20px;right:20px;z-index:99999;display:flex;flex-direction:column;gap:8px;align-items:flex-end; }
    `;
    document.head.appendChild(s);
  }

  let container = document.querySelector(".toast-container");
  if (!container) {
    container = document.createElement("div");
    container.className = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.style.cssText = `
    background:${colors[type] || colors.info};
    color:${textColors[type] || textColors.info};
    border:1px solid ${textColors[type] || textColors.info}33;
    border-radius:10px;padding:11px 16px;font-size:13px;
    font-family:'DM Sans',sans-serif;font-weight:500;
    backdrop-filter:blur(12px);
    box-shadow:0 8px 32px rgba(0,0,0,0.4);
    animation:toastIn 0.25s ease both;
    max-width:320px;display:flex;align-items:center;gap:8px;cursor:pointer;
  `;
  toast.innerHTML = `<i class="bi ${icons[type] || icons.info}" style="flex-shrink:0;font-size:14px;"></i><span>${escHtml(message)}</span>`;
  toast.addEventListener("click", () => dismiss());

  container.appendChild(toast);

  const dismiss = () => {
    toast.style.animation = "toastOut 0.22s ease forwards";
    setTimeout(() => toast.remove(), 230);
  };
  setTimeout(dismiss, 3800);
}

// Global plan-error handler
window.addEventListener("unhandledrejection", e => {
  if (e.reason instanceof PlanError) {
    showUpgradePrompt(e.reason.message);
    e.preventDefault();
  } else if (e.reason instanceof LimitError) {
    showToast(e.reason.message, "warning");
    e.preventDefault();
  } else {
    console.error("Unhandled rejection:", e.reason);
  }
});

// Expose for dashboard
window.PlanError  = PlanError;
window.LimitError = LimitError;
window.showUpgradePrompt = showUpgradePrompt;
