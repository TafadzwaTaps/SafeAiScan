// =========================
// CODE SCAN
// =========================
async function scan() {
  const code = document.getElementById("code").value;

  try {
    document.getElementById("loader")?.style && (document.getElementById("loader").style.display = "block");

    const data = await analyzeCode(code);

    document.getElementById("loader")?.style && (document.getElementById("loader").style.display = "none");

    // 🔥 Better result formatting
    const summary = {
      issues: data.findings?.length || 0,
      explanation: data.ai?.explanation || "No explanation",
      fixes: data.ai?.fixes || []
    };

    document.getElementById("result").innerText =
      JSON.stringify(summary, null, 2);

    if (data.usage_today !== undefined) {
      document.getElementById("usage").innerText = data.usage_today;
    }

  } catch (err) {
    console.error(err);
    alert("Scan failed: " + err.message);
  }
}

// =========================
// REPO SCAN
// =========================
async function scanRepo() {
  const repoUrl = prompt("Enter GitHub repo URL:");
  if (!repoUrl) return;

  try {
    const data = await scanRepoAPI(repoUrl);

    alert("Scan queued. Task ID: " + data.task_id);

    pollTask(data.task_id);

  } catch (err) {
    console.error(err);
    alert("Repo scan failed: " + err.message);
  }
}

// =========================
// FIXED POLLING (IMPORTANT)
// =========================
async function pollTask(taskId) {
  const interval = setInterval(async () => {
    try {
      const data = await getTaskStatus(taskId);

      // 🔥 show live status in UI
      document.getElementById("status") &&
        (document.getElementById("status").innerText = "Status: " + data.state);

      // show raw debug result
      document.getElementById("result").innerText =
        JSON.stringify(data, null, 2);

      if (data.state === "DONE") {
        clearInterval(interval);
        alert("Repo scan complete!");
        console.log("FINAL RESULT:", data.result);
      }

      if (data.state === "FAILED") {
        clearInterval(interval);
        alert("Scan failed!");
      }

    } catch (err) {
      console.error("Polling error:", err);
      clearInterval(interval);
    }
  }, 2000);
}

// =========================
// UI LOADERS
// =========================
async function loadUsage() {
  try {
    const data = await getUsage();
    const latest = data[data.length - 1];

    document.getElementById("usage").innerText =
      latest?.request_count || 0;

  } catch {
    document.getElementById("usage").innerText = "Error";
  }
}

async function loadHistory() {
  try {
    const data = await getHistory();

    const list = document.getElementById("history");
    list.innerHTML = "";

    data.forEach(item => {
      const li = document.createElement("li");

      // 🔥 SaaS-style badge UI
      li.innerHTML = `
        <span class="badge bg-danger">${item.risk}</span>
        Score: ${item.score}
      `;

      list.appendChild(li);
    });

  } catch (err) {
    console.error(err);
  }
}

async function loadPlan() {
  try {
    const data = await getMe();
    document.getElementById("plan").innerText = data.plan;
  } catch {
    document.getElementById("plan").innerText = "Free";
  }
}

// =========================
// UTIL
// =========================
function copyKey() {
  const key = localStorage.getItem("api_key");

  if (!key) return alert("No API key");

  navigator.clipboard.writeText(key);
  alert("Copied!");
}

function logout() {
  localStorage.clear();
  window.location.replace("login.html");
}

// =========================
// INIT
// =========================
async function init() {
  document.getElementById("apiKey").innerText =
    localStorage.getItem("api_key") || "Not available";

  await loadUsage();
  await loadHistory();
  await loadPlan();
}

init();

// expose
window.scan = scan;
window.copyKey = copyKey;
window.logout = logout;