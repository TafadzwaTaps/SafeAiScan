// =========================
// UI ACTIONS
// =========================

async function scan() {
  const code = document.getElementById("code").value;

  try {
    const data = await analyzeCode(code);

    document.getElementById("result").innerText =
      JSON.stringify(data, null, 2);

  } catch (err) {
    console.error(err);
    alert("Scan failed");
  }
}

async function loadUsage() {
  try {
    const data = await getUsage();

    if (!data || data.length === 0) {
      document.getElementById("usage").innerText = 0;
      return;
    }

    const latest = data[data.length - 1];
    document.getElementById("usage").innerText = latest.request_count;

  } catch {
    document.getElementById("usage").innerText = "Error";
  }
}

async function loadHistory() {
  try {
    const data = await getHistory();

    const historyList = document.getElementById("history");
    historyList.innerHTML = "";

    data.forEach(item => {
      const li = document.createElement("li");
      li.innerText = item.risk + " (" + item.score + ")";
      historyList.appendChild(li);
    });

  } catch (err) {
    console.error("History failed", err);
  }
}

function copyKey() {
  const key = localStorage.getItem("api_key");

  if (!key) {
    alert("No API key found");
    return;
  }

  navigator.clipboard.writeText(key);
  alert("API key copied!");
}

function logout() {
  localStorage.clear();
  window.location.replace("login.html");
}

// =========================
// INIT
// =========================
async function init() {
  // Show API key
  const apiKey = localStorage.getItem("api_key");
  document.getElementById("apiKey").innerText =
    apiKey || "Not available";

  await loadUsage();
  await loadHistory();
}

init();

// =========================
// MAKE FUNCTIONS GLOBAL (IMPORTANT)
// =========================
window.scan = scan;
window.copyKey = copyKey;
window.logout = logout;