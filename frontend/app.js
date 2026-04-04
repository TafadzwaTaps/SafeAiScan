// =========================
// CONFIG
// =========================
const token = localStorage.getItem("access_token");
const apiKey = localStorage.getItem("api_key");

// Redirect if not logged in
if (!token) {
  window.location.replace("login.html");
}

// =========================
// SCAN CODE
// =========================
async function scan() {
  const code = document.getElementById("code").value;

  try {
    const res = await fetch(`${BASE_URL}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token,
        ...(apiKey && apiKey !== "undefined" && { "x-api-key": apiKey })
      },
      body: JSON.stringify({ text: code })
    });

    if (!res.ok) {
      const errorText = await res.text();
      document.getElementById("result").innerText =
        "❌ Error: " + errorText;

      console.error("SCAN ERROR:", errorText);
      return;
    }

    const data = await res.json();

    document.getElementById("result").innerText =
      JSON.stringify(data, null, 2);

    console.log("SCAN RESPONSE:", data);

  } catch (err) {
    console.error("NETWORK ERROR:", err);
    document.getElementById("result").innerText =
      "❌ Network error while scanning";
  }
}

// =========================
// USAGE
// =========================
async function loadUsage() {
  try {
    const data = await getUsage();

    document.getElementById("usage").innerText =
      data?.length
        ? data[data.length - 1].request_count
        : 0;

  } catch (err) {
    console.error("Usage error:", err);
    document.getElementById("usage").innerText = "Error";
  }
}

// =========================
// HISTORY
// =========================
async function loadHistory() {
  try {
    const res = await fetch(`${BASE_URL}/api/history`, {
      headers: {
        "Authorization": "Bearer " + token,
        ...(apiKey && apiKey !== "undefined" && { "x-api-key": apiKey })
      }
    });

    if (!res.ok) throw new Error("Failed to fetch history");

    const data = await res.json();

    const historyList = document.getElementById("history");
    historyList.innerHTML = "";

    if (!Array.isArray(data) || data.length === 0) {
      historyList.innerHTML = "<li>No history found</li>";
      return;
    }

    data.forEach(item => {
      const li = document.createElement("li");
      li.innerText = `${item.risk} - ${item.score}`;
      historyList.appendChild(li);
    });

  } catch (err) {
    console.error("History error:", err);
    document.getElementById("history").innerHTML =
      "<li>Error loading history</li>";
  }
}

// =========================
// UPGRADE PLAN
// =========================
async function upgrade(plan) {
  try {
    const res = await createCheckout(plan);

    if (!res || !res.checkout_url) {
      throw new Error("Invalid checkout response");
    }

    window.location.href = res.checkout_url;

  } catch (err) {
    console.error("Upgrade failed:", err);
    alert("Upgrade failed");
  }
}

// =========================
// COPY API KEY
// =========================
function copyKey() {
  const key = localStorage.getItem("api_key");

  if (!key) {
    alert("No API key found");
    return;
  }

  navigator.clipboard.writeText(key);
  alert("API key copied!");
}

// =========================
// LOGOUT
// =========================
function logout() {
  localStorage.clear();
  window.location.replace("login.html");
}

// =========================
// CHART
// =========================
async function loadChart() {
  try {
    const data = await getUsage();

    if (!data || data.length === 0) return;

    const labels = data.map(d => d.date);
    const values = data.map(d => d.request_count);

    const ctx = document.getElementById("usageChart");

    new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "API Usage",
          data: values,
          tension: 0.4
        }]
      }
    });

  } catch (err) {
    console.error("Chart failed:", err);
  }
}

// =========================
// INIT DASHBOARD
// =========================
async function init() {
  const apiKeyDisplay = document.getElementById("apiKey");

  if (apiKeyDisplay) {
    apiKeyDisplay.innerText = apiKey || "Not set";
  }

  await loadUsage();
  await loadHistory();
  await loadChart();
}

// Run dashboard
init();