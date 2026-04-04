async function scan() {
  const code = document.getElementById("code").value;

  const res = await fetch(`${BASE_URL}/api/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + localStorage.getItem("access_token"),
      "x-api-key": localStorage.getItem("api_key")
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
}

async function loadUsage() {
  try {
    const data = await getUsage();

    document.getElementById("usage").innerText =
      data.length ? data[data.length - 1].request_count : 0;

  } catch {
    document.getElementById("usage").innerText = "Error";
  }
}

async function loadHistory() {
  try {
    const res = await fetch(`${BASE_URL}/api/history`, {
      headers: {
        "Authorization": "Bearer " + localStorage.getItem("access_token"),
        "x-api-key": localStorage.getItem("api_key")
      }
    });

    if (!res.ok) throw new Error("Failed");

    const data = await res.json();

    const historyList = document.getElementById("history");
    historyList.innerHTML = "";

    if (!Array.isArray(data)) {
      historyList.innerHTML = "<li>No data</li>";
      return;
    }

    data.forEach(item => {
      const li = document.createElement("li");
      li.innerText = item.risk + " - " + item.score;
      historyList.appendChild(li);
    });

  } catch {
    document.getElementById("history").innerHTML =
      "<li>Error loading history</li>";
  }
}

async function upgrade(plan) {
  try {
    const res = await createCheckout(plan);
    window.location.href = res.checkout_url;
  } catch {
    alert("Upgrade failed");
  }
}

function copyKey() {
  navigator.clipboard.writeText(localStorage.getItem("api_key"));
}

function logout() {
  localStorage.clear();
  window.location.replace("login.html");
}

async function init() {
  document.getElementById("apiKey").innerText =
    localStorage.getItem("api_key") || "Not set";

  await loadUsage();
  await loadHistory();
  await loadChart();
}

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
        labels: labels,
        datasets: [{
          label: "API Usage",
          data: values,
          tension: 0.4
        }]
      }
    });

  } catch {
    console.log("Chart failed");
  }
}


init();