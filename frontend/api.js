const BASE_URL = "https://rathious-safeaiscan.hf.space";

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

  // 🔥 FIX: proper error handling
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text);
  }

  return res;
}

// SAFE JSON
async function safeJson(res) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    console.error("RAW RESPONSE:", text);
    throw new Error("Invalid JSON from server");
  }
}

// =========================
// ANALYZE CODE
// =========================
async function analyzeCode(text) {
  const res = await apiRequest("/api/analyze", {
    method: "POST",
    body: JSON.stringify({ text })
  });

  return safeJson(res); // reuse your helper
}

// =========================
// REPO SCAN
// =========================
async function scanRepoAPI(repoUrl) {
  const res = await apiRequest("/api/scan-repo", {
    method: "POST",
    body: JSON.stringify({ repo_url: repoUrl })
  });

  return safeJson(res);
}

// =========================
// TASK STATUS
// =========================
async function getTaskStatus(taskId) {
  const res = await apiRequest("/api/task/" + taskId);
  return safeJson(res);
}

// =========================
// OTHER API CALLS
// =========================
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