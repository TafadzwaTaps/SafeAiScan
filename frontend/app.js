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
// AUTH API
// =========================
async function login(email, password) {
  const res = await fetch(`${BASE_URL}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();

  if (!data.access_token) {
    throw new Error("Invalid login");
  }

  setToken(data.access_token);

  if (data.api_key) {
    localStorage.setItem("api_key", data.api_key);
  }

  return data;
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