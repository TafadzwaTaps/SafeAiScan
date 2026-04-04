// =========================
// CONFIG
// =========================
const BASE_URL = "https://rathious-safeaiscan.hf.space";

// =========================
// TOKEN HELPERS
// =========================
function getToken() {
  return localStorage.getItem("access_token");
}

function getApiKey() {
  return localStorage.getItem("api_key");
}

function setToken(token) {
  localStorage.setItem("access_token", token);
}

function clearAuth() {
  localStorage.clear();
  window.location.replace("login.html");
}

// =========================
// CORE REQUEST WRAPPER
// =========================
async function apiRequest(endpoint, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer " + getToken(),
    ...(getApiKey() && getApiKey() !== "undefined" && {
      "x-api-key": getApiKey()
    }),
    ...(options.headers || {})
  };

  const res = await fetch(BASE_URL + endpoint, {
    ...options,
    headers
  });

  // 🔥 AUTO-LOGOUT ON 401
  if (res.status === 401) {
    console.warn("Session expired → logging out");
    clearAuth();
    return;
  }

  return res;
}

// =========================
// CORE FEATURES
// =========================
async function analyzeCode(text) {
  const res = await apiRequest("/api/analyze", {
    method: "POST",
    body: JSON.stringify({ text })
  });

  return await res.json();
}

async function getUsage() {
  const res = await apiRequest("/api/usage");
  return await res.json();
}

async function getHistory() {
  const res = await apiRequest("/api/history");
  return await res.json();
}