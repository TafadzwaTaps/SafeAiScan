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

  if (res.status === 401) {
    clearAuth();
    return null;
  }

  return res;
}

// SAFE JSON PARSE
async function safeJson(res) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    console.error("RAW ERROR:", text);
    throw new Error("Server error: " + text);
  }
}

// API CALLS
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

// =========================
// REPO SCAN (FIXED)
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