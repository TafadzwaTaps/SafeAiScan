// ============================================================
//  SafeAIScan — Dashboard App Logic
// ============================================================

let scanProgressInterval = null;
let findings = [];
let currentContext = "";
let usageChart = null;
let riskChart = null;

// ============================================================
//  CODE SCAN
// ============================================================
async function scan() {
  const code = document.getElementById("code")?.value?.trim();
  if (!code) { showToast("Paste some code to analyze", "warning"); return; }

  setLoader(true);
  startLiveProgress();

  try {
    const data = await analyzeCode(code);
    findings = data.findings || [];

    renderAIInsights(data);
    renderVulnerabilities(data);
    updateStatus(findings);
    renderSeverityTabs(data);
    loadUsageChart();

    if (findings.length > 0) enrichCVE(findings);

    if (data.usage_today !== undefined) {
      const el = document.getElementById("usage");
      if (el) el.innerText = data.usage_today;
    }

    stopLiveProgress();
    showToast(`Scan complete — ${findings.length} issue(s) found`, findings.length > 0 ? "warning" : "success");

  } catch (err) {
    console.error(err);
    stopLiveProgress();
    showToast("Scan failed: " + err.message, "error");
  } finally {
    setLoader(false);
  }
}

// ============================================================
//  REPO SCAN
// ============================================================
async function scanRepo() {
  const repoUrl = prompt("Enter GitHub repo URL (https://github.com/...):");
  if (!repoUrl?.trim()) return;

  if (!repoUrl.startsWith("https://github.com/")) {
    showToast("Only GitHub HTTPS URLs supported", "warning");
    return;
  }

  setLoader(true);
  showToast("Queuing repo scan...", "info");

  try {
    const data = await scanRepoAPI(repoUrl);
    showToast("Scan queued · Task: " + data.task_id, "success");
    pollTask(data.task_id);
  } catch (err) {
    console.error(err);
    showToast("Repo scan failed: " + err.message, "error");
  } finally {
    setLoader(false);
  }
}

// ============================================================
//  TASK POLLING
// ============================================================
async function pollTask(taskId) {
  const states = {
    CLONING: 15, VALIDATING: 35, SCANNING: 65, FINALIZING: 88, DONE: 100, FAILED: 0
  };

  const bar  = document.getElementById("scanProgressBar");
  const text = document.getElementById("scanProgressText");

  const interval = setInterval(async () => {
    try {
      const data = await getTaskStatus(taskId);

      const pct = states[data.state] ?? 50;
      if (bar)  bar.style.width  = pct + "%";
      if (text) text.innerText   = data.message || data.state;

      if (data.state === "DONE") {
        clearInterval(interval);
        findings = data.result?.findings || data.result || [];
        renderVulnerabilities({ findings });
        updateStatus(findings);
        showToast("Repo scan complete!", "success");
      }

      if (data.state === "FAILED") {
        clearInterval(interval);
        if (text) text.innerText = "Scan failed";
        showToast("Scan failed: " + (data.result?.error || "Unknown error"), "error");
      }

    } catch (err) {
      console.error("Polling error:", err);
      clearInterval(interval);
    }
  }, 2500);
}

// ============================================================
//  LOADERS / PROGRESS
// ============================================================
function setLoader(active) {
  const el = document.getElementById("loader");
  if (!el) return;
  el.classList.toggle("active", active);
}

function startLiveProgress() {
  let progress = 2;
  const bar  = document.getElementById("scanProgressBar");
  const text = document.getElementById("scanProgressText");

  const steps = [
    "Parsing code…", "Running static analysis…", "Checking patterns…",
    "AI risk modeling…", "Mapping CVEs…", "Finalizing report…"
  ];
  let stepIdx = 0;

  clearInterval(scanProgressInterval);
  scanProgressInterval = setInterval(() => {
    if (progress >= 95) { stopLiveProgress(); return; }
    progress += Math.random() * 6 + 1;
    if (bar)  bar.style.width = Math.min(95, progress) + "%";
    if (text && stepIdx < steps.length) {
      text.innerText = steps[Math.floor(stepIdx)];
      stepIdx += 0.4;
    }
  }, 350);
}

function stopLiveProgress() {
  clearInterval(scanProgressInterval);
  const bar  = document.getElementById("scanProgressBar");
  const text = document.getElementById("scanProgressText");
  if (bar)  { bar.style.width = "100%"; }
  if (text) text.innerText = "Complete";
  setTimeout(() => { if (bar) bar.style.width = "0%"; if (text) text.innerText = ""; }, 2000);
}

// ============================================================
//  DATA LOADERS
// ============================================================
async function loadUsage() {
  const el = document.getElementById("usage");
  if (!el) return;

  try {
    const data = await getUsage();
    const latest = Array.isArray(data) ? data[data.length - 1] : data;
    el.innerText = latest?.request_count ?? (latest?.count ?? 0);
  } catch {
    el.innerText = "—";
  }
}

async function loadHistory() {
  const list = document.getElementById("history");
  if (!list) return;

  // Show skeletons
  list.innerHTML = [1,2,3].map(() => `
    <div class="skeleton mb-2" style="height:40px; border-radius:8px;"></div>
  `).join("");

  try {
    const data = await getHistory();
    if (!Array.isArray(data) || data.length === 0) {
      list.innerHTML = `<div style="color:var(--text-faint);font-size:12px;padding:8px 0;">No history yet</div>`;
      return;
    }

    list.innerHTML = data.slice(0, 8).map(item => {
      const risk  = item.risk  || "LOW";
      const score = item.score ?? "—";
      const time  = item.created_at ? new Date(item.created_at).toLocaleDateString() : "";
      const sevClass = risk === "HIGH" || risk === "CRITICAL" ? "sev-high" : risk === "MEDIUM" ? "sev-medium" : "sev-low";
      return `
        <div class="history-item pop-in">
          <span class="badge-pill ${sevClass}">${risk}</span>
          <span style="color:var(--text-muted);font-size:11px;">Score: ${score}</span>
          <span style="color:var(--text-faint);font-size:10px;">${time}</span>
        </div>
      `;
    }).join("");

  } catch (err) {
    console.error(err);
    list.innerHTML = `<div style="color:var(--text-faint);font-size:12px;">Failed to load history</div>`;
  }
}

async function loadPlan() {
  const el = document.getElementById("plan");
  if (!el) return;
  try {
    const data = await getMe();
    const plan = data.plan || "Free";
    el.innerHTML = `
      <div style="display:flex;align-items:center;gap:6px;">
        <span class="badge-pill ${plan === 'pro' ? 'sev-high' : plan === 'enterprise' ? 'sev-critical' : 'sev-low'}">${plan.toUpperCase()}</span>
        <span style="font-size:12px;color:var(--text-muted);">${data.email || ""}</span>
      </div>
    `;
  } catch {
    if (el) el.innerHTML = `<span class="badge-pill sev-low">FREE</span>`;
  }
}

async function loadTeam() {
  const list = document.getElementById("teamList");
  if (!list) return;
  try {
    const res  = await apiRequest("/api/org/users");
    const data = await safeJson(res);
    list.innerHTML = (data || []).map(u => `
      <li style="font-size:12px;color:var(--text-muted);padding:4px 0;">
        <i class="bi bi-person-circle me-2" style="color:var(--accent);"></i>${u.email}
      </li>
    `).join("") || `<li style="color:var(--text-faint);font-size:12px;">No team members</li>`;
  } catch {
    if (list) list.innerHTML = `<li style="color:var(--text-faint);font-size:12px;">Team unavailable</li>`;
  }
}

// ============================================================
//  RENDER VULNERABILITIES
// ============================================================
function renderVulnerabilities(data) {
  const container = document.getElementById("vulnCards");
  if (!container) return;

  const list = data.findings || [];

  if (list.length === 0) {
    container.innerHTML = `
      <div style="text-align:center;padding:28px;color:var(--text-muted);">
        <i class="bi bi-shield-check" style="font-size:28px;color:var(--success);display:block;margin-bottom:8px;"></i>
        No issues detected
      </div>`;
    return;
  }

  const sevOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const sorted   = [...list].sort((a, b) => (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0));

  container.innerHTML = sorted.map((vuln, i) => {
    const sev      = (vuln.severity || "LOW").toUpperCase();
    const sevClass = sev === "CRITICAL" ? "sev-crit-card" : sev === "HIGH" ? "sev-high-card" : sev === "MEDIUM" ? "sev-med-card" : "sev-low-card";
    const badgeClass = sev === "CRITICAL" ? "sev-critical" : sev === "HIGH" ? "sev-high" : sev === "MEDIUM" ? "sev-medium" : "sev-low";

    return `
      <div class="vuln-card ${sevClass} pop-in" onclick="toggleVuln(this, ${i})" data-idx="${i}">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;">
          <div style="flex:1;min-width:0;">
            <div class="vuln-title">${escHtml(vuln.title || "Issue")}</div>
            <div class="vuln-meta">
              ${vuln.file  ? `<i class="bi bi-file-code me-1"></i>${escHtml(vuln.file)}` : ""}
              ${vuln.line  ? ` · line ${vuln.line}` : ""}
              ${vuln.source ? ` · <span style="color:var(--accent);">${vuln.source}</span>` : ""}
            </div>
          </div>
          <span class="badge-pill ${badgeClass}" style="margin-left:10px;flex-shrink:0;">${sev}</span>
        </div>

        <div class="vuln-details" id="vd-${i}">
          <div style="color:var(--text-muted);margin-bottom:8px;">${escHtml(vuln.description || "No description provided")}</div>

          ${vuln.fix && vuln.fix !== "No auto-fix available" ? `
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;color:var(--accent);margin-bottom:4px;">Recommended Fix</div>
            <div class="fix-box">${escHtml(vuln.fix)}</div>
          ` : ""}

          ${vuln.cve && vuln.cve !== "N/A" ? `
            <div style="margin-top:8px;display:flex;align-items:center;gap:6px;">
              <span class="badge-pill sev-${cvssSev(vuln.cvss)}">
                <i class="bi bi-bug"></i> ${escHtml(vuln.cve)}
              </span>
              ${vuln.cvss ? `<span style="font-size:11px;color:var(--text-muted);">CVSS ${vuln.cvss}</span>` : ""}
            </div>
          ` : ""}

          <div id="cve-${i}" style="margin-top:6px;"></div>
        </div>
      </div>
    `;
  }).join("");
}

function toggleVuln(card, idx) {
  const wasActive = card.classList.contains("active");
  document.querySelectorAll(".vuln-card.active").forEach(c => c.classList.remove("active"));
  if (!wasActive) card.classList.add("active");
}

// ============================================================
//  AI INSIGHTS
// ============================================================
function renderAIInsights(data) {
  const container = document.getElementById("aiInsights");
  if (!container) return;

  const ai      = data.ai || {};
  const explain = ai.explanation || "";
  const fixes   = Array.isArray(ai.fixes) ? ai.fixes : [];

  if (!explain && fixes.length === 0) {
    container.innerHTML = "";
    return;
  }

  container.innerHTML = `
    <div class="ai-box pop-in">
      <div class="ai-label"><i class="bi bi-cpu me-1"></i> AI Security Insights</div>
      ${explain ? `<p style="font-size:13px;color:var(--text-muted);margin-bottom:8px;">${escHtml(explain)}</p>` : ""}
      ${fixes.length > 0 ? `
        <div style="font-size:11px;color:var(--text-faint);text-transform:uppercase;letter-spacing:0.8px;margin-bottom:6px;">Recommended Actions</div>
        <div style="display:flex;flex-direction:column;gap:4px;">
          ${fixes.map(f => `
            <div style="display:flex;gap:8px;font-size:12px;color:var(--text-muted);">
              <i class="bi bi-check-circle-fill" style="color:var(--success);flex-shrink:0;margin-top:2px;"></i>
              ${escHtml(f)}
            </div>
          `).join("")}
        </div>
      ` : ""}
    </div>
  `;
}

// ============================================================
//  STATUS + SEVERITY TABS
// ============================================================
function updateStatus(findings) {
  const statusEl = document.getElementById("statusText");
  if (!statusEl) return;
  const hasCritical = findings.some(f => ["HIGH","CRITICAL"].includes(f.severity));
  statusEl.innerHTML = hasCritical
    ? `<span class="status-dot online" style="background:var(--danger);box-shadow:0 0 6px var(--danger);"></span>Vulnerable`
    : `<span class="status-dot online"></span>Secure`;
  statusEl.className = hasCritical ? "status-risk" : "status-safe";
}

function renderSeverityTabs(data) {
  const el = document.getElementById("severityTabs");
  if (!el) return;
  const f = data.findings || [];
  const counts = {
    CRITICAL: f.filter(x => x.severity === "CRITICAL").length,
    HIGH:     f.filter(x => x.severity === "HIGH").length,
    MEDIUM:   f.filter(x => x.severity === "MEDIUM").length,
    LOW:      f.filter(x => x.severity === "LOW").length
  };
  el.innerHTML = Object.entries(counts).map(([sev, cnt]) => `
    <span class="badge-pill sev-${sev.toLowerCase()}">${sev} ${cnt}</span>
  `).join("");
}

// ============================================================
//  CVE ENRICHMENT
// ============================================================
async function enrichCVE(findings) {
  findings.forEach(async (vuln, i) => {
    const box = document.getElementById(`cve-${i}`);
    if (!box || !vuln.title) return;
    try {
      const res  = await apiRequest(`/api/cve/search?query=${encodeURIComponent(vuln.title)}`);
      const data = await safeJson(res);
      if (data?.cves?.length) {
        const top = data.cves[0];
        box.innerHTML = `
          <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">
            <i class="bi bi-shield-exclamation me-1" style="color:var(--warning);"></i>
            ${escHtml(top.id)} · CVSS ${top.cvss || "N/A"} · <span style="color:var(--text-faint);">${escHtml((top.description || "").substring(0,120))}…</span>
          </div>`;
      }
    } catch { /* silent */ }
  });
}

// ============================================================
//  CHARTS
// ============================================================
async function loadUsageChart() {
  const ctx = document.getElementById("usageChart");
  if (!ctx) return;

  let labels = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
  let values = [0,0,0,0,0,0,0];

  try {
    const data = await getUsage();
    if (Array.isArray(data) && data.length) {
      labels = data.map(d => d.date || d.day || "—");
      values = data.map(d => d.request_count || d.count || 0);
    }
  } catch { /* use defaults */ }

  if (usageChart) usageChart.destroy();

  const gradient = ctx.getContext("2d").createLinearGradient(0, 0, 0, 200);
  gradient.addColorStop(0, "rgba(91,123,254,0.45)");
  gradient.addColorStop(1, "rgba(91,123,254,0)");

  usageChart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Scans",
        data: values,
        borderColor: "#5b7bfe",
        borderWidth: 2.5,
        backgroundColor: gradient,
        fill: true,
        tension: 0.45,
        pointBackgroundColor: "#5b7bfe",
        pointRadius: 4,
        pointHoverRadius: 7
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false }, tooltip: { backgroundColor: "#0f1a2e", titleColor: "#e8edf8", bodyColor: "#8296b3", borderColor: "#1e3a5f", borderWidth: 1 } },
      scales: {
        x: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#8296b3", font: { size: 11 } } },
        y: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#8296b3", font: { size: 11 } }, beginAtZero: true }
      }
    }
  });
}

function loadRiskChart(findings) {
  const ctx = document.getElementById("riskChart");
  if (!ctx || !findings?.length) return;

  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  findings.forEach(f => {
    const s = (f.severity || "LOW");
    if (s === "CRITICAL") counts.Critical++;
    else if (s === "HIGH") counts.High++;
    else if (s === "MEDIUM") counts.Medium++;
    else counts.Low++;
  });

  if (riskChart) riskChart.destroy();

  riskChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: Object.keys(counts),
      datasets: [{
        data: Object.values(counts),
        backgroundColor: ["#c026d3","#f43f5e","#fb923c","#34d399"],
        borderWidth: 0,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      cutout: "68%",
      plugins: {
        legend: { position: "right", labels: { color: "#8296b3", font: { size: 11 }, padding: 12 } },
        tooltip: { backgroundColor: "#0f1a2e", titleColor: "#e8edf8", bodyColor: "#8296b3" }
      }
    }
  });
}

// ============================================================
//  API KEY UI
// ============================================================
function initApiKey() {
  const el = document.getElementById("apiKeyDisplay");
  if (!el) return;

  const key = localStorage.getItem("api_key") || "";
  el.innerText = key ? maskKey(key) : "Not available";
  el.dataset.full  = key;
  el.dataset.masked = key ? maskKey(key) : "";
  el.dataset.shown  = "false";
}

function maskKey(key) {
  if (!key || key.length < 10) return "••••••••";
  return key.substring(0, 6) + "••••••••" + key.substring(key.length - 4);
}

function toggleApiKey() {
  const el   = document.getElementById("apiKeyDisplay");
  const icon = document.getElementById("toggleKeyIcon");
  if (!el) return;

  const shown = el.dataset.shown === "true";
  el.innerText = shown ? el.dataset.masked : el.dataset.full;
  el.dataset.shown = String(!shown);
  if (icon) icon.className = shown ? "bi bi-eye" : "bi bi-eye-slash";
}

function copyKey() {
  const key = localStorage.getItem("api_key");
  if (!key) { showToast("No API key available", "warning"); return; }

  navigator.clipboard.writeText(key).then(() => {
    showToast("API key copied to clipboard", "success");
    const confirm = document.getElementById("copyConfirm");
    if (confirm) { confirm.classList.add("show"); setTimeout(() => confirm.classList.remove("show"), 1800); }
  }).catch(() => showToast("Copy failed", "error"));
}

// ============================================================
//  UTILITY
// ============================================================
function logout() {
  localStorage.clear();
  window.location.replace("login.html");
}

function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function cvssSev(score) {
  if (!score) return "low";
  if (score >= 9)  return "critical";
  if (score >= 7)  return "high";
  if (score >= 4)  return "medium";
  return "low";
}

async function exportPDF() {
  try {
    const res  = await apiRequest("/api/report/pdf", { method: "POST", body: JSON.stringify({ findings }) });
    const blob = await res.blob();
    const url  = window.URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = "safeaiscan-report.pdf"; a.click();
    showToast("PDF exported", "success");
  } catch (err) {
    showToast("Export failed: " + err.message, "error");
  }
}

// Side panel (shared)
function openSide(v) {
  currentContext = JSON.stringify(v);
  const side  = document.getElementById("side");
  const title = document.getElementById("sideTitle");
  const desc  = document.getElementById("sideDesc");
  if (!side) return;
  if (title) title.innerText = v.title || v.match || "Finding";
  if (desc) desc.innerHTML = `
    <p style="color:var(--text-muted);">${v.description || ""}</p>
    ${v.fix ? `<div class="fix-box mt-2">${escHtml(v.fix)}</div>` : ""}
  `;
  side.classList.add("open");
}

function closeSide() {
  document.getElementById("side")?.classList.remove("open");
}

// Render timeline
function renderTimeline(data) {
  const el = document.getElementById("timeline");
  if (!el) return;
  const steps = data.timeline || ["Code received","Parsing syntax","AI analysis","CVE lookup","Report ready"];
  el.innerHTML = steps.map(s => `<div class="timeline-item">${escHtml(s)}</div>`).join("");
}

function renderTree(nodes) {
  if (!Array.isArray(nodes)) return "";
  return nodes.map(n => `
    <div style="margin-left:12px;padding:2px 0;font-size:11px;color:var(--text-muted);">
      ${n.type === "dir" ? "📁" : "📄"} ${escHtml(n.name)}
      ${n.children ? renderTree(n.children) : ""}
    </div>
  `).join("");
}

async function loadRepoTree(url) {
  const container = document.getElementById("fileTree");
  if (!container) return;
  try {
    const res  = await apiRequest(`/api/repo/tree?repo_url=${encodeURIComponent(url)}`);
    const data = await safeJson(res);
    container.innerHTML = renderTree(data);
  } catch { /* optional feature */ }
}

async function askAI() {
  const q    = document.getElementById("aiInput")?.value?.trim();
  const chat = document.getElementById("aiChat");
  if (!q || !chat) return;

  chat.innerHTML += `<div style="color:var(--accent);font-size:12px;margin-bottom:4px;"><b>You:</b> ${escHtml(q)}</div>`;

  try {
    const res  = await apiRequest("/api/ai/explain", {
      method: "POST",
      body: JSON.stringify({ question: q, context: currentContext })
    });
    const data = await safeJson(res);
    chat.innerHTML += `
      <div style="color:var(--text-muted);font-size:12px;margin-bottom:8px;padding-left:8px;border-left:2px solid var(--accent);">
        ${escHtml(data.explanation || "")}
      </div>
    `;
    chat.scrollTop = chat.scrollHeight;
  } catch (err) {
    chat.innerHTML += `<div style="color:var(--danger);font-size:11px;">Error: ${err.message}</div>`;
  }

  document.getElementById("aiInput").value = "";
}

// ============================================================
//  SCROLL FADE-IN
// ============================================================
function initScrollFade() {
  const observer = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) e.target.classList.add("show"); });
  }, { threshold: 0.12 });
  document.querySelectorAll(".fade-in").forEach(el => observer.observe(el));
}

// ============================================================
//  INIT
// ============================================================
async function init() {
  initApiKey();
  initScrollFade();

  const p = (id) => !!document.getElementById(id);

  if (p("usage"))   await loadUsage();
  if (p("history")) await loadHistory();
  if (p("plan"))    await loadPlan();
  if (p("teamList")) await loadTeam();
  if (p("usageChart")) await loadUsageChart();
}

document.addEventListener("DOMContentLoaded", init);

// expose globals
window.scan = scan;
window.scanRepo = scanRepo;
window.copyKey = copyKey;
window.toggleApiKey = toggleApiKey;
window.logout = logout;
window.exportPDF = exportPDF;
window.openSide = openSide;
window.closeSide = closeSide;
window.askAI = askAI;
window.fetchCVE = fetchCVE;
window.toggleVuln = toggleVuln;
