async function scan() {
  const code = document.getElementById("code").value;

  try {
    const data = await analyzeCode(code);

    document.getElementById("result").innerText =
      JSON.stringify(data, null, 2);

    // ✅ LIVE USAGE UPDATE
    if (data.usage_today !== undefined) {
      document.getElementById("usage").innerText = data.usage_today;
    }

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

    const list = document.getElementById("history");
    list.innerHTML = "";

    data.forEach(item => {
      const li = document.createElement("li");
      li.innerText = item.risk + " (" + item.score + ")";
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

function copyKey() {
  const key = localStorage.getItem("api_key");

  if (!key) {
    alert("No API key");
    return;
  }

  navigator.clipboard.writeText(key);
  alert("Copied!");
}

function logout() {
  localStorage.clear();
  window.location.replace("login.html");
}

// INIT
async function init() {
  document.getElementById("apiKey").innerText =
    localStorage.getItem("api_key") || "Not available";

  await loadUsage();
  await loadHistory();
  await loadPlan();
}

init();

// 🔥 REQUIRED FOR BUTTONS
window.scan = scan;
window.copyKey = copyKey;
window.logout = logout;