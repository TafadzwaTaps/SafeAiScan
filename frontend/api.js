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

function clearAuth() {
  localStorage.clear();
  window.location.replace("login.html");
}

// =========================
// CORE REQUEST WRAPPER
// =========================
async function apiRequest(endpoint, options = {}) {
  const res = await fetch(BASE_URL + endpoint, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + getToken(),
      ...(getApiKey() && getApiKey() !== "undefined" && {
        "x-api-key": getApiKey()
      }),
      ...(options.headers || {})
    }
  });

  if (res.status === 401) {
    console.warn("Session expired");
    clearAuth();
    return null;
  }

  return res;
}

// =========================
// API FUNCTIONS
// =========================
async function analyzeCode(text) {
  const res = await apiRequest("/api/analyze", {
    method: "POST",
    body: JSON.stringify({ text })
  });

  const raw = await res.text();

  try {
    return JSON.parse(raw);
  } catch {
    console.error("❌ NON-JSON RESPONSE:", raw);
    throw new Error("Server error: " + raw);
  }
}

async function getUsage() {
  const res = await apiRequest("/api/usage");
  return res.json();
}

async function getHistory() {
  const res = await apiRequest("/api/history");
  return res.json();
}