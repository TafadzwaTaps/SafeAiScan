// ============================================================
//  SafeAIScan — API Layer v2.0
//  Standardized responses, plan-aware gating, retry logic
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

// ── Plan helpers ───────────────────────────────────────────
// Source of truth: localStorage values set by getMe() after every page load.
// pro_trial counts as full Pro access.
let _userPlan   = window.DEV_MODE ? "enterprise" : (localStorage.getItem("user_plan") || "free");
let _userLimits = null;
try {
  if (window.DEV_MODE) {
    _userLimits = { daily_scans:-1, history_limit:9999, ai_depth:"full",
      repo_scan:true, pdf_download:true, advanced_ai:true, api_access:true,
      cve_enrichment:true, scheduled_scans:true, json_export:true };
  } else {
    const s = localStorage.getItem("user_limits");
    if (s) _userLimits = JSON.parse(s);
  }
} catch {}

function isProUser() {
  if (window.DEV_MODE) return true;
  if (localStorage.getItem("is_pro") === "true")     return true;
  if (localStorage.getItem("trial_active") === "true") return true;
  const p = localStorage.getItem("user_plan") || "free";
  return p === "pro_trial" || p === "pro" || p === "enterprise";
}

function isTrialUser() {
  const p = localStorage.getItem("user_plan") || "free";
  return p === "pro_trial" && localStorage.getItem("trial_active") === "true";
}

function getTrialDaysLeft() {
  return parseInt(localStorage.getItem("trial_days_left") || "0");
}

function getUserPlan() {
  if (window.DEV_MODE) return "enterprise";
  return _userPlan;
}

function getUserLimits() { return _userLimits; }

function cachePlanData(plan, limits) {
  if (window.DEV_MODE) return;
  _userPlan   = plan;
  _userLimits = limits;
  localStorage.setItem("user_plan", plan);
  if (limits) localStorage.setItem("user_limits", JSON.stringify(limits));
}

function canAccessFeature(feature) {
  if (window.DEV_MODE) return true;
  if (isProUser()) return true;
  // Free plan has limited access
  const freeFeatures = { repo_scan: true, basic_scan: true };
  return !!freeFeatures[feature];
}

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

async function analyzeCode(text) {
  const res = await apiRequest("/api/analyze", {
    method: "POST",
    body: JSON.stringify({ text })
  });
  const data = await safeJson(res);
  // Only cache plan data in production mode
  if (!window.DEV_MODE && data.plan && data.usage_limit) {
    cachePlanData(data.plan, null);
    document.dispatchEvent(new CustomEvent("planUpdated", { detail: data }));
  }
  return data;
}

async function scanRepoAPI(repoUrl) {
  if (!canAccessFeature("repo_scan")) {
    throw new PlanError("Repo scanning requires Pro or Enterprise. Upgrade to unlock.");
  }
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
  // Backend route: GET /api/me — returns full subscription + trial info
  try {
    const res  = await apiRequest("/api/me");
    const data = await safeJson(res);
    if (!window.DEV_MODE) {
      if (data?.plan)   localStorage.setItem("user_plan", data.plan);
      if (data?.is_pro !== undefined) localStorage.setItem("is_pro", data.is_pro ? "true" : "false");
      if (data?.trial_active !== undefined) localStorage.setItem("trial_active", data.trial_active ? "true" : "false");
      if (data?.days_left !== undefined)    localStorage.setItem("trial_days_left", String(data.days_left));
      cachePlanData(data.plan, data.limits || null);
    }
    return data;
  } catch (err) {
    if (err.message.includes("404")) {
      return {
        plan:         localStorage.getItem("user_plan") || "free",
        is_pro:       localStorage.getItem("is_pro") === "true",
        trial_active: localStorage.getItem("trial_active") === "true",
        days_left:    parseInt(localStorage.getItem("trial_days_left") || "0"),
        user_id:      localStorage.getItem("user_id") || "",
        email:        localStorage.getItem("user_email") || ""
      };
    }
    throw err;
  }
}

async function getTrialStatus() {
  try {
    const res  = await apiRequest("/api/trial/status");
    return safeJson(res);
  } catch (err) {
    console.warn("[SecretScan] trial status unavailable:", err.message);
    return {
      plan:         localStorage.getItem("user_plan") || "free",
      is_pro:       localStorage.getItem("is_pro") === "true",
      trial_active: localStorage.getItem("trial_active") === "true",
      days_left:    parseInt(localStorage.getItem("trial_days_left") || "0"),
      trial_expired: false, days_left: 0
    };
  }
}

function rotateApiKey() {
  // FIX: key rotation now calls the backend, then refreshes UI via initApiKey if available
  apiRequest("/api/auth/rotate-key", { method: "POST" })
    .then(res => safeJson(res))
    .then(data => {
      const newKey = data?.api_key || data?.data?.api_key;
      if (newKey) {
        localStorage.setItem("api_key", newKey);
        // initApiKey lives in app.js — call only if loaded
        if (typeof window.initApiKey === "function") window.initApiKey();
      }
      showToast("API key rotated successfully", "success");
    })
    .catch(err => showToast("Key rotation failed: " + err.message, "error"));
}

async function fetchCVE() {
  const input = document.getElementById("cveInput")?.value?.trim();
  if (!input) return showToast("Enter a CVE ID or keyword", "warning");

  const panel = document.getElementById("cvePanel");
  if (!panel) return;

  panel.innerHTML = `<div class="skeleton" style="height:60px;border-radius:8px;"></div>`;

  try {
    const res  = await apiRequest(`/api/cve/search?query=${encodeURIComponent(input)}`);
    const data = await safeJson(res);
    const cves = data?.cves || data?.data?.cves || [];

    if (!cves.length) {
      panel.innerHTML = `<div style="color:var(--text-muted);font-size:12px;padding:8px 0;">No CVEs found for "<strong>${escHtml(input)}</strong>"</div>`;
      return;
    }

    panel.innerHTML = cves.map(cve => `
      <div class="panel mb-2 pop-in">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <strong style="font-size:12px;color:var(--accent-2);">${escHtml(cve.id || "")}</strong>
          <span class="badge-pill sev-${cvssSev(cve.cvss)}">${cve.cvss ?? "N/A"}</span>
        </div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">${escHtml((cve.description || "").substring(0, 180))}</div>
      </div>
    `).join("");

  } catch (err) {
    console.error(err);
    panel.innerHTML = `<div style="color:var(--danger);font-size:12px;padding:8px 0;">
      <i class="bi bi-exclamation-triangle me-1"></i>${escHtml(err.message)}
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
//  UPGRADE PROMPT (shown on PlanError / LimitError)
// ============================================================
function showUpgradePrompt(message) {
  // Remove any existing upgrade modal
  document.getElementById("_upgradeModal")?.remove();

  const plan       = localStorage.getItem("user_plan") || "free";
  const alreadyTrial = plan === "pro_trial";
  const alreadyPro   = plan === "pro" || plan === "enterprise";
  // Show trial offer to free users who haven't tried it yet
  const offerTrial = !alreadyTrial && !alreadyPro;

  const modal = document.createElement("div");
  modal.id    = "_upgradeModal";
  modal.setAttribute("style",
    "position:fixed;inset:0;z-index:99998;display:flex;align-items:center;" +
    "justify-content:center;background:rgba(0,0,0,0.7);backdrop-filter:blur(6px);padding:20px;"
  );

  const featureList = offerTrial
    ? ["Unlimited scans every day",
       "All findings revealed",
       "GitHub repo scanning",
       "Deep AI analysis & fix suggestions",
       "PDF report download",
       "CVE enrichment & lookup"]
      .map(f => '<div style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text-muted);">' +
                '<i class="bi bi-check-circle-fill" style="color:#00ffa3;font-size:11px;flex-shrink:0;"></i>' + f + '</div>')
      .join("")
    : "";

  const headerHTML = offerTrial
    ? '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">' +
      '<span style="font-size:22px;">🎁</span>' +
      '<div style="font-family:Syne,sans-serif;font-size:18px;font-weight:800;">Try Pro Free — 30 Days</div>' +
      '</div>'
    : '<div style="font-family:Syne,sans-serif;font-size:18px;font-weight:800;margin-bottom:6px;">' +
      '<i class="bi bi-lightning-charge" style="color:var(--warning);"></i> ' +
      (alreadyTrial ? "Keep Your Pro Access" : "Upgrade to Pro") +
      '</div>';

  const featureBlock = featureList
    ? '<div style="background:rgba(0,255,163,.05);border:1px solid rgba(0,255,163,.15);' +
      'border-radius:12px;padding:14px;margin-bottom:16px;display:flex;flex-direction:column;gap:6px;">' +
      featureList + '</div>'
    : "";

  const primaryBtn = offerTrial
    ? '<a href="checkout.html" style="display:block;text-align:center;' +
      'background:linear-gradient(135deg,#00ffa3,#5b7bfe);color:#0f172a;' +
      'padding:13px;border-radius:10px;font-size:14px;font-weight:700;text-decoration:none;' +
      'box-shadow:0 6px 20px rgba(0,255,163,.3);">' +
      '<i class="bi bi-gift-fill me-1"></i>Start Free 30-Day Trial — No Card Needed</a>' +
      '<div style="text-align:center;font-size:11px;color:var(--text-faint);margin-top:4px;">After trial: $1.99/mo · Cancel anytime</div>'
    : '<button onclick="window.location.href=\'checkout.html\'"  style="' +
      'background:linear-gradient(135deg,#5b7bfe,#4361ee);color:#fff;border:none;' +
      'padding:12px 20px;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;width:100%;">' +
      '<i class="bi bi-lightning-charge me-1"></i>Upgrade to Pro — $1.99/mo</button>';

  modal.innerHTML =
    '<div style="background:var(--bg-2);border:1px solid var(--border-bright);border-radius:18px;' +
    'padding:28px 28px;max-width:420px;width:100%;box-shadow:0 24px 80px rgba(0,0,0,0.6);' +
    'animation:popIn 0.25s cubic-bezier(.34,1.56,.64,1) both;">' +
    headerHTML +
    '<p style="font-size:13px;color:var(--text-muted);margin-bottom:14px;line-height:1.55;">' + escHtml(message) + '</p>' +
    featureBlock +
    '<div style="display:grid;gap:8px;">' +
    primaryBtn +
    '<button onclick="document.getElementById(&quot;_upgradeModal&quot;).remove()" style="' +
    'background:transparent;color:var(--text-faint);border:none;padding:8px;font-size:12px;cursor:pointer;">' +
    'Maybe Later</button>' +
    '</div></div>';

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

