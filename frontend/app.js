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
    console.log("🔥 SCAN RESULT:", data); // ADD THIS
    renderAIInsights(data);

    stopLiveProgress();

    document.getElementById("loader")?.style &&
      (document.getElementById("loader").style.display = "none");

    const summary = {
      issues: data.findings?.length || 0,
      explanation: data.ai?.explanation || "No explanation",
      fixes: data.ai?.fixes || [],

    };

    renderVulnerabilities(data);
    renderMiniskyPanel(data);
    updateStatus(data.findings);

    if (data.findings?.length > 0) {
      enrichCVE(data.findings);
    }

    if (data.usage_today !== undefined) {
      const el = document.getElementById("usage");
      if (el) el.innerText = data.usage_today;
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
    loadRepoTree(repoUrl); // ✅ correct variable

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

      // show status
      const statusEl = document.getElementById("status");
      if (statusEl) {
        statusEl.innerText = "Status: " + data.state;
      }

      // 🔥 DEBUG (you NEED this)
      console.log("POLL DATA:", data);

      // =========================
      // ✅ FIX: HANDLE RESULT
      // =========================
      if (data.state === "DONE") {
        clearInterval(interval);

        console.log("FINAL RESULT:", data.result);

        if (!data.result) {
          alert("Scan finished but no results returned");
          return;
        }

        // 🔥 THIS IS THE FIX
        findings = data.result.findings || data.result;

        // render everywhere
        render();
        renderMinisky(data.result);

        alert("Repo scan complete!");
      }

      if (data.state === "FAILED") {
        clearInterval(interval);
        alert("Scan failed: " + data.result);
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

    const el = document.getElementById("usage");
    if (el && latest) el.innerText = latest.request_count;
    
  } catch {
    const el = document.getElementById("usage");
    if (el) el.innerText = "Error";
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

${data.ai?.explanation ? `
  <div class="mt-2 p-2" style="background:#0b1220;border-radius:8px;">
    <small class="text-info">AI Insight:</small>
    <div style="font-size:12px;">${data.ai.explanation}</div>
  </div>
` : ""}

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
  const apiKeyEl = document.getElementById("apiKey");
  if (apiKeyEl) {
    apiKeyEl.innerText = localStorage.getItem("api_key") || "Not available";
  }

  if (document.getElementById("usage")) await loadUsage();
  if (document.getElementById("history")) await loadHistory();
  if (document.getElementById("plan")) await loadPlan();
  if (document.getElementById("teamList")) await loadTeam();
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

async function loadRepoTree(url) {
    const res = await apiRequest(`/api/repo/tree?repo_url=${encodeURIComponent(url)}`);
    const data = await res.json();

    const container = document.getElementById("fileTree");
    container.innerHTML = renderTree(data);
}

function renderTree(nodes) {
    return nodes.map(n => `
        <div style="margin-left:10px">
            ${n.type === "dir" ? "📁" : "📄"} ${n.name}
            ${n.children ? renderTree(n.children) : ""}
        </div>
    `).join("");
}

let currentContext = "";

function openSide(v){
    currentContext = JSON.stringify(v);

    document.getElementById("side").classList.add("open");
    document.getElementById("title").innerText = v.match || v.title;

    document.getElementById("desc").innerHTML = `
        <p>${v.description || ""}</p>
        <pre>${v.fix || ""}</pre>
    `;
}

async function askAI(){
    const q = document.getElementById("aiInput").value;

    const res = await apiRequest("/api/ai/explain", {
        method: "POST",
        body: JSON.stringify({
            question: q,
            context: currentContext
        })
    });

    const data = await res.json();

    const chat = document.getElementById("aiChat");

    chat.innerHTML += `
        <div><b>You:</b> ${q}</div>
        <div class="text-success"><b>AI:</b> ${data.explanation}</div>
        <hr/>
    `;
}

async function exportPDF(){
    const res = await apiRequest("/api/report/pdf", {
        method: "POST",
        body: JSON.stringify({ findings })
    });

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "report.pdf";
    a.click();
}

async function loadTeam(){
    const list = document.getElementById("teamList");
    if (!list) return;

    list.innerHTML = "<li>Loading...</li>";

    try {
        const res = await apiRequest("/api/org/users");
        const data = await res.json();

        list.innerHTML = "";

        data.forEach(u=>{
            const li = document.createElement("li");
            li.innerText = u.email;
            list.appendChild(li);
        });

    } catch (e) {
        list.innerHTML = "<li class='text-danger'>Failed to load team</li>";
    }
}

function renderAIInsights(data) {
  const container = document.getElementById("aiInsights");

  if (!container) return;

  const ai = data.ai || {};

  // 🔥 FALLBACK SYSTEM (VERY IMPORTANT)
  let explanation = ai.explanation || "No AI explanation available.";
  let fixes = ai.fixes || [];

  if (!fixes.length) {
    fixes = [
      "Validate and sanitize all inputs",
      "Use parameterized queries to prevent SQL injection",
      "Store secrets in environment variables",
      "Apply authentication & authorization",
      "Keep dependencies updated"
    ];
  }

  container.innerHTML = `
    <div class="glass p-3 mt-3">
      <h6>🧠 AI Security Insights</h6>

      <div class="mb-2 text-muted small">
        AI-powered explanation of detected risks
      </div>

      <div class="mb-3">
        <strong>Explanation:</strong>
        <div class="mt-1">${explanation}</div>
      </div>

      <div>
        <strong>Recommended Fixes:</strong>
        <ul class="mt-2">
          ${fixes.map(f => `<li>✅ ${f}</li>`).join("")}
        </ul>
      </div>
    </div>
  `;
}

function updateStatus(findings) {
  const statusEl = document.getElementById("statusText");
  if (!statusEl) return;

  const hasCritical = findings.some(f => f.severity === "HIGH" || f.severity === "CRITICAL");

  statusEl.innerText = hasCritical ? "Vulnerable" : "Secure";
  statusEl.className = hasCritical ? "status-risk" : "status-safe";
}

function renderMiniskyPanel(data) {
  renderTimeline(data);
  renderSeverityTabs(data);
  renderCVEPanel(data);
  renderFixDiff(data);
}

function exportReport() {
  exportPDF();
}