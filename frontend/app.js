// =========================
// CODE SCAN
// =========================
async function scan() {
  const code = document.getElementById("code").value;

  try {
    document.getElementById("loader")?.style &&
      (document.getElementById("loader").style.display = "block");

    startLiveProgress();

    const data = await analyzeCode(code);

    stopLiveProgress();

    document.getElementById("loader")?.style &&
      (document.getElementById("loader").style.display = "none");

    const summary = {
      issues: data.findings?.length || 0,
      explanation: data.ai?.explanation || "No explanation",
      fixes: data.ai?.fixes || []
    };

    renderVulnerabilities(data);
    renderMiniskyPanel(data);

    if (data.findings?.length > 0) {
      enrichCVE(data.findings);
    }

    if (data.usage_today !== undefined) {
      document.getElementById("usage").innerText = data.usage_today;
    }

  } catch (err) {
    console.error(err);
    stopLiveProgress();
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
      renderMinisky(data);

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

function renderVulnerabilities(data) {
  const container = document.getElementById("vulnCards");
  if (!container) return;

  container.innerHTML = "";

  const findings = data.findings || [];

  findings.forEach((vuln, index) => {
    const severityColor =
      vuln.severity === "HIGH" ? "danger" :
      vuln.severity === "MEDIUM" ? "warning" :
      "success";

    const card = document.createElement("div");
    card.className = "card mb-3 shadow-sm fade-in";

    card.onclick = () => openSnyk(vuln); // ✅ FIXED HOOK

    card.innerHTML = `
      <div class="card-header bg-${severityColor} text-white">
        ${vuln.title || "Vulnerability"} (${vuln.severity})
      </div>

      <div class="card-body">
        <p><strong>File:</strong> ${vuln.file || "N/A"}</p>
        <p><strong>Line:</strong> ${vuln.line || "N/A"}</p>

        <button class="btn btn-sm btn-primary"
          onclick="event.stopPropagation(); toggleDetails(${index})">
          View Details
        </button>

        <div id="details-${index}" class="mt-2 d-none">
          <hr/>
          <p><strong>Description:</strong> ${vuln.description || "No description"}</p>
          <p><strong>Fix:</strong> ${vuln.fix || "No fix provided"}</p>

          <div id="cve-${index}" class="mt-2 text-muted">
            Loading CVE enrichment...
          </div>
        </div>
      </div>
    `;

    container.appendChild(card);
  });
}

function toggleDetails(index) {
  const el = document.getElementById(`details-${index}`);
  if (!el) return;

  el.classList.toggle("d-none");
}

// =========================
// MINISKY PANEL (ADD HERE)
// =========================



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

let scanProgressInterval = null;

function startLiveProgress() {
  let progress = 0;

  const bar = document.getElementById("scanProgressBar");
  const text = document.getElementById("scanProgressText");

  if (!bar || !text) return;

  clearInterval(scanProgressInterval);

  scanProgressInterval = setInterval(() => {
    if (progress >= 100) {
      stopLiveProgress();
      return;
    }

    progress += Math.random() * 8;

    bar.style.width = `${progress}%`;
    text.innerText = `Scanning... ${Math.floor(progress)}%`;
  }, 300);
}

function stopLiveProgress() {
  clearInterval(scanProgressInterval);

  const bar = document.getElementById("scanProgressBar");
  const text = document.getElementById("scanProgressText");

  if (bar) bar.style.width = "100%";
  if (text) text.innerText = "Scan Complete";
}

function openSnyk(vuln) {
  const panel = document.getElementById("snykPanel");
  const content = document.getElementById("snykContent");

  if (!panel || !content) return;

  panel.classList.add("open");

  content.innerHTML = `
    <h6>${vuln.title}</h6>

    <p><strong>Severity:</strong> ${vuln.severity}</p>
    <p><strong>File:</strong> ${vuln.file || "N/A"}</p>

    <hr/>

    <p>${vuln.description || ""}</p>

    <hr/>

    <p><strong>AI Fix:</strong></p>
    <pre>${vuln.fix || "No fix available"}</pre>
  `;
}

function closeSnyk() {
  document.getElementById("snykPanel")?.classList.remove("open");
}

async function enrichCVE(findings) {
  findings.forEach(async (vuln, i) => {
    try {
      const res = await fetch(`/api/cve/search?query=${encodeURIComponent(vuln.title)}`);
      const data = await res.json();

      const box = document.getElementById(`cve-${i}`);
      if (!box) return;

      if (data?.cves?.length) {
        const top = data.cves[0];

        box.innerHTML = `
          <div class="alert alert-secondary p-2">
            <strong>${top.id}</strong><br/>
            CVSS: ${top.cvss}<br/>
            <small>${top.description}</small>
          </div>
        `;
      } else {
        box.innerText = "No CVE match found";
      }

    } catch (err) {
      console.error(err);
    }
  });
}

function renderTimeline(data) {
  const el = document.getElementById("timeline");
  if (!el) return;

  const steps = data.timeline || [
    "Code received",
    "Scanning syntax",
    "Running AI analysis",
    "Checking CVEs",
    "Finalizing report"
  ];

  el.innerHTML = steps.map(step => `
    <div class="timeline-step">🧠 ${step}</div>
  `).join("");
}

function renderSeverityTabs(data) {
  const el = document.getElementById("severityTabs");
  if (!el) return;

  const findings = data.findings || [];

  const groups = {
    CRITICAL: findings.filter(f => f.severity === "CRITICAL"),
    HIGH: findings.filter(f => f.severity === "HIGH"),
    MEDIUM: findings.filter(f => f.severity === "MEDIUM"),
    LOW: findings.filter(f => f.severity === "LOW")
  };

  el.innerHTML = `
    <div class="d-flex gap-2 flex-wrap">
      <span class="badge sev-critical">CRITICAL ${groups.CRITICAL.length}</span>
      <span class="badge sev-high">HIGH ${groups.HIGH.length}</span>
      <span class="badge sev-medium">MEDIUM ${groups.MEDIUM.length}</span>
      <span class="badge sev-low">LOW ${groups.LOW.length}</span>
    </div>
  `;
}

function renderCVEPanel(data) {
  const el = document.getElementById("cvePanel");
  if (!el) return;

  const cves = data.cves || data.findings?.map(f => f.cve).filter(Boolean) || [];

  el.innerHTML = `
    <div class="card glass p-3">
      <h6>🧬 CVE Enrichment</h6>

      ${cves.length === 0 ? `
        <p class="text-muted">No CVEs detected</p>
      ` : cves.map(cve => `
        <div class="fix-box">
          <strong>${cve.id}</strong><br/>
          CVSS: ${cve.cvss || "N/A"}<br/>
          ${cve.description || ""}
        </div>
      `).join("")}
    </div>
  `;
}

function renderFixDiff(data) {
  const el = document.getElementById("fixDiff");
  if (!el) return;

  const fixes = data.ai?.fixes || [];

  el.innerHTML = fixes.map(fix => `
    <div class="fix-box">
      <div><strong>❌ Before</strong></div>
      <pre>${fix.before || ""}</pre>

      <div><strong>✅ After</strong></div>
      <pre>${fix.after || ""}</pre>
    </div>
  `).join("");
}

function renderMinisky(data) {
  renderTimeline(data);
  renderSeverityTabs(data);
  renderMiniskyPanel(data);
  renderCVEPanel(data);
  renderFixDiff(data);
}
