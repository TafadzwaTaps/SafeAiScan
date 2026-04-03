async function scan() {
  const resultBox = document.getElementById("result");

  resultBox.innerText = "⏳ Analyzing...";

  try {
    const res = await analyzeCode(
      document.getElementById("code").value
    );

    resultBox.innerText = JSON.stringify(res, null, 2);
  } catch (e) {
    resultBox.innerText = "❌ Scan failed";
  }

  await loadUsage();
  await loadHistory();
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
    const data = await getHistory();

    const list = document.getElementById("history");
    list.innerHTML = "";

    if (!data || !Array.isArray(data)) {
      list.innerHTML = "<li>No data</li>";
      return;
    }

    data.slice(0, 5).forEach(item => {
      const li = document.createElement("li");
      li.innerText = `${item.risk} - ${item.score}`;
      list.appendChild(li);
    });

  } catch (err) {
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
  window.location.href = "login.html";
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