// ============================================================
//  SafeAIScan Pro — Minisky Scanner Engine
//  Full pipeline: scan → render → enrich → visualize
// ============================================================

window.aiResult = null;
// Global namespace (prevents redeclare + conflicts)
window.SafeAIScan = window.SafeAIScan || {};
const S = window.SafeAIScan;

// ============================================================
// STATE (SAFE SINGLE SOURCE OF TRUTH)
// ============================================================
S.findings = S.findings || [];
S.aiResult = S.aiResult || null;
S.currentContext = S.currentContext || "";
S.scanProgressInterval = S.scanProgressInterval || null;

// ============================================================
//  TIMELINE LOG
// ============================================================
function log(msg, type = "info") {
  const el = document.getElementById("timeline");
  if (!el) return;

  const colors = {
    info:    "var(--accent)",
    success: "var(--success)",
    warning: "var(--warning)",
    error:   "var(--danger)"
  };

  const item = document.createElement("div");
  item.className = "tl-item";
  item.innerHTML = `
    <div class="tl-dot" style="background:${colors[type] || colors.info};"></div>
    <div class="tl-text">${escHtml(msg)}</div>
  `;

  // Prepend so newest is on top
  el.insertBefore(item, el.firstChild);

  // Keep timeline clean (max 30 entries)
  const items = el.querySelectorAll(".tl-item");
  if (items.length > 30) items[items.length - 1].remove();
}

// ============================================================
//  PIPELINE PROGRESS
// ============================================================
const STAGES = [
  { id: "ps-parse",  label: "Parsing code…",           pct: 15 },
  { id: "ps-static", label: "Running static analysis…", pct: 35 },
  { id: "ps-ai",     label: "AI risk modeling…",        pct: 60 },
  { id: "ps-cve",    label: "Mapping CVEs…",             pct: 82 },
  { id: "ps-report", label: "Generating report…",        pct: 96 }
];

// ============================================================
// REPORT BUILDER (NEW CORE FIX)
// ============================================================
function buildReport(findings, aiResult, meta = {}) {
  const severityCount = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };

  findings.forEach(f => {
    const s = (f.severity || "LOW").toUpperCase();
    severityCount[s] = (severityCount[s] || 0) + 1;
  });

  const riskScore = Math.max(
    0,
    100 -
      severityCount.CRITICAL * 25 -
      severityCount.HIGH * 12 -
      severityCount.MEDIUM * 5
  );

  return {
    meta: {
      timestamp: new Date().toISOString(),
      source: meta.source || "code_scan",
      repo: meta.repo || null
    },
    summary: {
      total: findings.length,
      severityCount,
      riskScore,
      status:
        severityCount.CRITICAL > 0
          ? "CRITICAL"
          : severityCount.HIGH > 0
          ? "HIGH_RISK"
          : findings.length > 0
          ? "MODERATE"
          : "CLEAN"
    },
    ai: aiResult || {
      explanation: "No AI analysis available",
      fixes: []
    },
    findings:
      findings.length > 0
        ? findings
        : [
            {
              title: "No Issues Detected",
              description: "Static + AI scan found no vulnerabilities.",
              severity: "LOW",
              fix: "No action required"
            }
          ]
  };
}


function showProgress() {
  const wrap = document.getElementById("scanProgressWrap");
  if (wrap) wrap.style.display = "block";
}

function hideProgress() {
  const wrap = document.getElementById("scanProgressWrap");
  const bar  = document.getElementById("scanProgressBar");
  const text = document.getElementById("scanProgressText");
  const pct  = document.getElementById("scanPct");
  if (bar)  bar.style.width  = "100%";
  if (text) text.innerText   = "Complete";
  if (pct)  pct.innerText    = "100%";
  setTimeout(() => {
    if (wrap) wrap.style.display = "none";
    if (bar)  bar.style.width    = "0%";
    // reset stages
    STAGES.forEach(s => {
      const el = document.getElementById(s.id);
      if (el) { el.classList.remove("active", "done"); }
    });
  }, 1500);
}

function startPipeline() {
  showProgress();

  const bar = document.getElementById("scanProgressBar");
  const text = document.getElementById("scanProgressText");
  const pct = document.getElementById("scanPct");

  let stage = 0;
  let progress = 0;

  clearInterval(S.scanProgressInterval);

  S.scanProgressInterval = setInterval(() => {
    if (stage >= STAGES.length) return;

    const target = STAGES[stage].pct;
    progress += (target - progress) * 0.2;

    if (bar) bar.style.width = progress + "%";
    if (pct) pct.innerText = Math.round(progress) + "%";
    if (text) text.innerText = STAGES[stage].label;

    if (Math.abs(progress - target) < 1.5) stage++;

  }, 250);
}

function stopPipeline() {
  clearInterval(S.scanProgressInterval);
  hideProgress();
}

// ============================================================
// MAIN SCAN (FIXED)
// ============================================================
S.runScan = async function () {
  const code = document.getElementById("code")?.value?.trim();

  if (!code) {
    showToast("Paste some code to scan", "warning");
    return;
  }

  log("Starting scan...");
  startPipeline();
  clearResults();

  try {
    const data = await analyzeCode(code);

    S.aiResult = data.ai || null;
    S.findings = data.findings || [];

    // fallback AI
    if (!S.findings.length && S.aiResult?.explanation) {
      S.findings = [{
        title: "AI Detected Issue",
        description: S.aiResult.explanation,
        severity: "HIGH",
        fix: (S.aiResult.fixes || []).join("\n"),
        source: "ai"
      }];
    }

    if (!S.findings.length) {
      S.findings = [{
        title: "No Issues Detected",
        description: "Clean scan result",
        severity: "LOW",
        fix: "N/A",
        source: "ai"
      }];
    }

    const report = buildReport(S.findings, S.aiResult);

    window.findings = report.findings;
    window.aiResult = report.ai;
    window.scanReport = report;

    renderResults();
    renderOverview();
    renderSeverityBars();
    renderHeatmap();
    renderAIPanel();
    enrichCVEPro(S.findings);

    stopPipeline();
    log(`Scan complete — ${S.findings.length} finding(s)`, S.findings.length > 0 ? "warning" : "success");
    showToast(`${S.findings.length} finding(s) — scan complete`, S.findings.length > 0 ? "warning" : "success");
    
    // SAFE FAILURE REPORT (IMPORTANT FIX)
    window.scanReport = buildReport([], null, {
      source: "failed_scan"
    });

    window.findings = window.scanReport.findings;

  } catch (err) {
    stopPipeline();
    log(err.message, "error");
    showToast("Scan failed: " + err.message, "error");
  }
};


// ============================================================
//  REPO SCAN
// ============================================================
async function scanRepo() {
  const repoUrl = document.getElementById("repoUrl")?.value?.trim();
  if (!repoUrl) { showToast("Enter a GitHub repo URL", "warning"); return; }

  if (!repoUrl.startsWith("https://github.com/")) {
    showToast("Only https://github.com/ URLs supported", "warning");
    return;
  }

  log("Queuing repo scan: " + repoUrl);
  startPipeline();

  try {
    const data = await scanRepoAPI(repoUrl);
    log("Task queued: " + data.task_id, "success");
    showToast("Repo scan queued · " + data.task_id, "success");
    pollTaskPro(data.task_id);
    loadRepoTreePro(repoUrl);
  } catch (err) {
    stopPipeline();
    window.scanReport = buildReport([], null, {
      source: "repo_scan_failed",
      repo: repoUrl
    });

    window.findings = window.scanReport.findings;
    log("Repo scan failed: " + err.message, "error");
    showToast("Failed: " + err.message, "error");
  }
}

// ============================================================
//  TASK POLLING (Pro version with stage mapping)
// ============================================================
async function pollTaskPro(taskId) {
  const stateMap = { CLONING: 15, VALIDATING: 35, SCANNING: 65, FINALIZING: 90, DONE: 100, FAILED: 0 };
  const bar  = document.getElementById("scanProgressBar");
  const text = document.getElementById("scanProgressText");
  const pct  = document.getElementById("scanPct");

  showProgress();

  const iv = setInterval(async () => {
    try {
      const data = await getTaskStatus(taskId);
      const p = stateMap[data.state] ?? 50;

      if (bar)  bar.style.width = p + "%";
      if (text) text.innerText  = data.message || data.state;
      if (pct)  pct.innerText   = p + "%";

      log(data.state + (data.message ? ": " + data.message : ""));

      if (data.state === "DONE") {
        clearInterval(iv);
        S.findings = data.result?.findings || data.result || [];

        window.scanReport = buildReport(S.findings, null, {
          source: "repo_scan",
          repo: repoUrl
        });
        renderResults();
        renderOverview();
        renderSeverityBars();
        renderHeatmap();
        stopPipeline();
        showToast("Repo scan complete!", "success");
        log("Repo scan complete", "success");
      }

      if (data.state === "FAILED") {
        clearInterval(iv);
        stopPipeline();
        log("Scan failed: " + (data.result?.error || "Unknown"), "error");
        showToast("Scan failed", "error");
      }

    } catch (err) {
      console.error("Poll error:", err);
      clearInterval(iv);
      stopPipeline();
    }
  }, 2500);
}

// ============================================================
// CLEAR
// ============================================================
function clearScan() {
  S.findings = [];
  S.aiResult = null;

  document.getElementById("code").value = "";
  clearResults();

  renderOverview();
  renderSeverityBars();
  renderHeatmap();

  log("Cleared");
}

function clearResults() {
  const r = document.getElementById("results");
  const a = document.getElementById("aiInsights");
  if (r) r.innerHTML = "";
  if (a) a.innerHTML = "";
}

// ============================================================
//  RENDER FINDINGS
// ============================================================
function renderResults() {
  const box = document.getElementById("results");
  if (!box) return;

  if (!findings.length) {
    box.innerHTML = `
      <div style="text-align:center;padding:32px 0;color:var(--text-muted);">
        <i class="bi bi-shield-check" style="font-size:32px;color:var(--success);display:block;margin-bottom:10px;"></i>
        No findings to display
      </div>`;
    return;
  }

  const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const sorted = [...findings].sort((a, b) => (order[b.severity] || 0) - (order[a.severity] || 0));

  box.innerHTML = sorted.map((v, i) => {
    const sev = (v.severity || "LOW").toUpperCase();
    const indClass    = sev === "CRITICAL" ? "ind-critical" : sev === "HIGH" ? "ind-high" : sev === "MEDIUM" ? "ind-medium" : "ind-low";
    const badgeClass  = sev === "CRITICAL" ? "sev-critical" : sev === "HIGH" ? "sev-high" : sev === "MEDIUM" ? "sev-medium" : "sev-low";
    const riskPct     = sev === "CRITICAL" ? 95 : sev === "HIGH" ? 75 : sev === "MEDIUM" ? 45 : 20;
    const riskColor   = sev === "CRITICAL" ? "#e879f9" : sev === "HIGH" ? "var(--danger)" : sev === "MEDIUM" ? "var(--warning)" : "var(--success)";

    return `
      <div class="pro-vuln" onclick="toggleProVuln(this, ${i})" data-idx="${i}">
        <div class="pro-vuln-header">
          <div class="pro-vuln-indicator ${indClass}"></div>
          <div class="pro-vuln-info">
            <div class="pro-vuln-name">${escHtml(v.title || "Issue")}</div>
            <div class="pro-vuln-path">
              ${v.file  ? `<i class="bi bi-file-code me-1"></i>${escHtml(v.file)}` : ""}
              ${v.line  ? `· line ${v.line}` : ""}
              ${v.source ? `· <span style="color:var(--accent-2);">${escHtml(v.source)}</span>` : ""}
            </div>
          </div>
          <span class="badge-pill ${badgeClass}">${sev}</span>
          <i class="bi bi-chevron-down" style="color:var(--text-faint);font-size:11px;margin-left:4px;transition:transform 0.2s;" id="chev-${i}"></i>
        </div>

        <div class="pro-vuln-body">
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:10px;line-height:1.6;">
            ${escHtml(v.description || "No description provided")}
          </div>

          ${v.fix && v.fix !== "No auto-fix available" && v.fix !== "N/A" ? `
            <div style="font-size:9px;text-transform:uppercase;letter-spacing:0.8px;color:var(--accent);margin-bottom:5px;">
              <i class="bi bi-wrench-adjustable me-1"></i>Recommended Fix
            </div>
            <div class="drawer-code">${escHtml(v.fix)}</div>
          ` : ""}

          <div class="risk-bar-wrap">
            <div style="font-size:9px;text-transform:uppercase;letter-spacing:0.8px;color:var(--text-faint);margin-bottom:4px;">Risk Level</div>
            <div class="risk-bar-track">
              <div class="risk-bar-fill" style="width:${riskPct}%;background:${riskColor};"></div>
            </div>
            <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text-faint);margin-top:3px;">
              <span>0</span><span style="color:${riskColor};">${riskPct}%</span><span>100</span>
            </div>
          </div>

          ${v.cve && v.cve !== "N/A" ? `
            <div style="margin-top:8px;display:flex;align-items:center;gap:6px;">
              <span class="badge-pill sev-${cvssSev(v.cvss)}">
                <i class="bi bi-bug me-1"></i>${escHtml(v.cve)}
              </span>
              ${v.cvss ? `<span style="font-size:11px;color:var(--text-muted);">CVSS ${v.cvss}</span>` : ""}
            </div>
          ` : ""}

          <div id="proCVE-${i}" style="margin-top:6px;"></div>

          <button class="btn btn-sm btn-outline-light mt-3"
            onclick="event.stopPropagation(); openSideDetail(${i})"
            style="font-size:11px;">
            <i class="bi bi-arrows-fullscreen me-1"></i>View Full Detail
          </button>
        </div>
      </div>
    `;
  }).join("");
}

function toggleProVuln(card, idx) {
  const isOpen = card.classList.contains("open");
  document.querySelectorAll(".pro-vuln.open").forEach(c => {
    c.classList.remove("open");
    const chev = c.querySelector('[id^="chev-"]');
    if (chev) chev.style.transform = "rotate(0deg)";
  });
  if (!isOpen) {
    card.classList.add("open");
    const chev = document.getElementById(`chev-${idx}`);
    if (chev) chev.style.transform = "rotate(180deg)";
  }
}

// ============================================================
//  OVERVIEW METRICS
// ============================================================
function renderOverview() {
  const crit = findings.filter(f => f.severity === "CRITICAL").length;
  const high = findings.filter(f => f.severity === "HIGH").length;
  const med  = findings.filter(f => f.severity === "MEDIUM").length;

  const score = Math.max(0, 100 - crit * 20 - high * 10 - med * 5);
  const hasCrit = crit > 0 || high > 0;

  setEl("totalIssues",  findings.length || "—");
  setEl("criticalCount", crit || "—");
  setEl("highCount",     high || "—");
  setEl("medCount",      med  || "—");
  setEl("riskScore",     findings.length ? score : "—");

  const statusEl = document.getElementById("statusText");
  if (statusEl) {
    statusEl.textContent = hasCrit ? "Vulnerable" : findings.length ? "At Risk" : "Secure";
    statusEl.className = "tstat-val " + (hasCrit ? "status-risk" : "status-safe");
  }
}

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// ============================================================
//  SEVERITY BARS
// ============================================================
function renderSeverityBars() {
  const total = findings.length || 1;

  const counts = {
    critical: findings.filter(f => f.severity === "CRITICAL").length,
    high:     findings.filter(f => f.severity === "HIGH").length,
    medium:   findings.filter(f => f.severity === "MEDIUM").length,
    low:      findings.filter(f => f.severity === "LOW").length
  };

  Object.entries(counts).forEach(([key, cnt]) => {
    const bar = document.getElementById("bar" + capitalize(key));
    const lbl = document.getElementById("cnt" + capitalize(key));
    if (bar) bar.style.width = (cnt / total * 100) + "%";
    if (lbl) lbl.textContent = cnt;
  });
}

function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

// ============================================================
//  HEATMAP
// ============================================================
function renderHeatmap() {
  const map = document.getElementById("heatmap");
  if (!map) return;

  if (!findings.length) { map.innerHTML = ""; return; }

  map.innerHTML = findings.map(v => {
    const sev = (v.severity || "low").toLowerCase();
    const cls = sev === "critical" ? "critical" : sev === "high" ? "high" : sev === "medium" ? "medium" : "low";
    return `<div class="heat-cell ${cls}" title="${escHtml(v.title || sev)}"></div>`;
  }).join("");
}

// ============================================================
//  AI PANEL (right sidebar chat)
// ============================================================
function renderAIPanel() {
  const chat = document.getElementById("aiChat");
  if (!chat || !window.aiResult) return;

  const ai = window.aiResult;

  // Add AI message to chat
  const msg = document.createElement("div");
  msg.className = "ai-msg-bot";
  msg.innerHTML = `
    <i class="bi bi-robot me-1" style="color:var(--accent);"></i>
    <strong>Analysis:</strong><br>
    ${escHtml(ai.explanation || "Scan complete.")}
    ${ai.fixes?.length ? `
      <div style="margin-top:6px;">
        ${ai.fixes.slice(0, 3).map(f => `<div style="margin-top:3px;">• ${escHtml(f)}</div>`).join("")}
      </div>` : ""}
  `;
  chat.appendChild(msg);
  chat.scrollTop = chat.scrollHeight;
}



// ============================================================
//  CVE ENRICHMENT
// ============================================================
async function enrichCVEPro(findings) {
  findings.forEach(async (v, i) => {
    const box = document.getElementById(`proCVE-${i}`);
    if (!box || !v.title) return;
    try {
      const res  = await apiRequest(`/api/cve/search?query=${encodeURIComponent(v.title)}`);
      const data = await safeJson(res);
      if (data?.cves?.length) {
        const top = data.cves[0];
        box.innerHTML = `
          <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text-muted);margin-top:4px;">
            <i class="bi bi-shield-exclamation" style="color:var(--warning);"></i>
            <span style="color:var(--accent-2);">${escHtml(top.id)}</span>
            · CVSS <strong>${top.cvss || "N/A"}</strong>
            · <span style="color:var(--text-faint);">${escHtml((top.description || "").substring(0,90))}…</span>
          </div>`;
      }
    } catch { /* silent */ }
  });
}

// ============================================================
//  SIDE DRAWER (full detail view)
// ============================================================
function openSideDetail(idx) {
  const v = findings[idx];
  if (!v) return;
  currentContext = JSON.stringify(v);

  const sev = (v.severity || "LOW").toUpperCase();
  const badgeClass = sev === "CRITICAL" ? "sev-critical" : sev === "HIGH" ? "sev-high" : sev === "MEDIUM" ? "sev-medium" : "sev-low";

  const title = document.getElementById("sideTitle");
  const sevEl = document.getElementById("sideSev");
  const desc  = document.getElementById("sideDesc");
  const side  = document.getElementById("side");

  if (title) title.textContent = v.title || "Finding";
  if (sevEl) sevEl.innerHTML = `<span class="badge-pill ${badgeClass}">${sev}</span>`;

  if (desc) desc.innerHTML = `
    <div class="drawer-section">
      <div class="drawer-section-label">Description</div>
      <div style="font-size:13px;color:var(--text-muted);line-height:1.7;">${escHtml(v.description || "No description available")}</div>
    </div>

    ${v.file ? `
    <div class="drawer-section">
      <div class="drawer-section-label">Location</div>
      <div style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--accent-2);">
        <i class="bi bi-file-code"></i>
        ${escHtml(v.file)}${v.line ? ` · line ${v.line}` : ""}
      </div>
    </div>` : ""}

    ${v.fix && v.fix !== "N/A" ? `
    <div class="drawer-section">
      <div class="drawer-section-label"><i class="bi bi-wrench-adjustable me-1"></i>Recommended Fix</div>
      <div class="drawer-code">${escHtml(v.fix)}</div>
    </div>` : ""}

    ${v.cve && v.cve !== "N/A" ? `
    <div class="drawer-section">
      <div class="drawer-section-label">CVE Reference</div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <span class="badge-pill sev-${cvssSev(v.cvss)}">${escHtml(v.cve)}</span>
        ${v.cvss ? `<span style="font-size:12px;color:var(--text-muted);">CVSS Score: <strong>${v.cvss}</strong></span>` : ""}
      </div>
    </div>` : ""}

    <div class="drawer-section">
      <div class="drawer-section-label">Risk Score</div>
      <div class="risk-bar-track" style="height:8px;">
        <div class="risk-bar-fill" style="
          width:${sev === 'CRITICAL' ? 95 : sev === 'HIGH' ? 75 : sev === 'MEDIUM' ? 45 : 20}%;
          background:${sev === 'CRITICAL' ? '#e879f9' : sev === 'HIGH' ? 'var(--danger)' : sev === 'MEDIUM' ? 'var(--warning)' : 'var(--success)'};
        "></div>
      </div>
    </div>

    ${v.source ? `
    <div class="drawer-section">
      <div class="drawer-section-label">Detected By</div>
      <div style="font-size:12px;color:var(--accent-2);font-family:'JetBrains Mono',monospace;">${escHtml(v.source)}</div>
    </div>` : ""}
  `;

  if (side) side.classList.add("open");
}

function openSide(v) {
  const idx = findings.indexOf(v);
  if (idx !== -1) { openSideDetail(idx); return; }
  // fallback
  const side  = document.getElementById("side");
  const title = document.getElementById("sideTitle");
  const desc  = document.getElementById("sideDesc");
  if (title) title.textContent = v.title || "Finding";
  if (desc)  desc.innerHTML = `<p style="color:var(--text-muted);">${escHtml(v.description || "")}</p>`;
  if (side)  side.classList.add("open");
}

function closeSide() {
  document.getElementById("side")?.classList.remove("open");
}

// ============================================================
//  REPO FILE TREE
// ============================================================
async function loadRepoTreePro(url) {
  const container = document.getElementById("fileTree");
  if (!container) return;

  container.innerHTML = `<div class="skeleton" style="height:100px;border-radius:6px;"></div>`;

  try {
    const res  = await apiRequest(`/api/repo/tree?repo_url=${encodeURIComponent(url)}`);
    const data = await safeJson(res);
    container.innerHTML = renderTreePro(data) || `<div style="font-size:11px;color:var(--text-faint);">No files found</div>`;
  } catch {
    container.innerHTML = `<div style="font-size:11px;color:var(--text-faint);">Tree unavailable</div>`;
  }
}

function renderTreePro(nodes) {
  if (!Array.isArray(nodes)) return "";
  return nodes.map(n => `
    <div class="ft-item">
      <i class="bi bi-${n.type === 'dir' ? 'folder2' : 'file-code'}"></i>
      <span>${escHtml(n.name)}</span>
    </div>
    ${n.children ? `<div style="padding-left:10px;">${renderTreePro(n.children)}</div>` : ""}
  `).join("");
}

async function fetchCVE() {
  const input = document.getElementById("cveInput")?.value?.trim();
  if (!input) return showToast("Enter a CVE ID or keyword", "warning");

  const panel = document.getElementById("cvePanel");
  if (!panel) return;

  panel.innerHTML = `<div class="skeleton" style="height:60px; border-radius:8px;"></div>`;

  try {
    const res = await apiRequest(`/api/cve/search?query=${encodeURIComponent(input)}`);
    const data = await safeJson(res);

    if (!data.cves?.length) {
      panel.innerHTML = `<div style="color:var(--text-muted);font-size:12px;padding:8px 0;">No CVEs found for "${input}"</div>`;
      return;
    }

    panel.innerHTML = data.cves.map(cve => `
      <div class="panel mb-2 pop-in">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <strong style="font-size:12px;color:var(--accent-2);">${cve.id}</strong>
          <span class="badge-pill sev-${cvssSev(cve.cvss)}">${cve.cvss || "N/A"}</span>
        </div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:4px;">${cve.description || ""}</div>
      </div>
    `).join("");

  } catch (err) {
    console.error(err);
    panel.innerHTML = `<div style="color:var(--danger);font-size:12px;">Error: ${err.message}</div>`;
  }
}

// ============================================================
//  AI CHAT (right panel)
// ============================================================
async function askAI() {
  const q    = document.getElementById("aiInput")?.value?.trim();
  const chat = document.getElementById("aiChat");
  if (!q || !chat) return;

  // User message
  const userMsg = document.createElement("div");
  userMsg.className = "ai-msg-user";
  userMsg.textContent = q;
  chat.appendChild(userMsg);
  chat.scrollTop = chat.scrollHeight;

  document.getElementById("aiInput").value = "";

  // Loading indicator
  const loading = document.createElement("div");
  loading.className = "ai-msg-bot";
  loading.innerHTML = `<span class="skeleton" style="display:inline-block;width:80px;height:14px;border-radius:4px;"></span>`;
  chat.appendChild(loading);
  chat.scrollTop = chat.scrollHeight;

  try {
    const res  = await apiRequest("/api/ai/explain", {
      method: "POST",
      body: JSON.stringify({ question: q, context: currentContext })
    });
    const data = await safeJson(res);

    loading.innerHTML = `
      <i class="bi bi-robot me-1" style="color:var(--accent);"></i>
      ${escHtml(data.explanation || "No response")}
    `;

  } catch (err) {
    loading.innerHTML = `<span style="color:var(--danger);">Error: ${escHtml(err.message)}</span>`;
  }

  chat.scrollTop = chat.scrollHeight;
}

// ============================================================
//  TEAM LOADER
// ============================================================
async function loadTeam() {
  const list = document.getElementById("teamList");
  if (!list) return;

  try {
    const res  = await apiRequest("/api/org/users");
    const data = await safeJson(res);

    if (!data?.length) {
      list.innerHTML = `<div style="font-size:11px;color:var(--text-faint);">No team members</div>`;
      return;
    }

    list.innerHTML = data.map(u => {
      const initials = (u.email || "?").substring(0, 2).toUpperCase();
      return `
        <div class="team-member">
          <div class="team-avatar">${initials}</div>
          <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escHtml(u.email || "—")}</div>
        </div>
      `;
    }).join("");

  } catch {
    list.innerHTML = `<div style="font-size:11px;color:var(--text-faint);">Team unavailable</div>`;
  }
}

// ============================================================
//  HELPERS
// ============================================================
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

// EXPORT FIX (NO MORE EMPTY REPORTS)
// ============================================================
async function exportPDF() {
  try {
    const report = window.scanReport || buildReport(findings, aiResult);

    const res = await apiRequest("/api/report/pdf", {
      method: "POST",
      body: JSON.stringify({ report })
    });

    const blob = await res.blob();
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "SafeAIScan-Report.pdf";
    a.click();

    showToast("Report exported", "success");
  } catch (err) {
    showToast("Export failed", "error");
  }
}

function logout() {
  localStorage.clear();
  window.location.replace("login.html");
}

// ============================================================
//  INIT
// ============================================================
async function initMinisky() {
  log("SafeAIScan Pro initialized", "success");
  await loadTeam();
  renderOverview();
}

document.addEventListener("DOMContentLoaded", initMinisky);

// Expose globals
window.runScan = S.runScan;
window.scanRepo   = scanRepo;
window.openSide   = openSide;
window.closeSide  = closeSide;
window.openSideDetail = openSideDetail;
window.clearScan  = clearScan;
window.exportPDF  = exportPDF;
window.askAI      = askAI;
window.logout     = logout;
window.fetchCVE   = fetchCVE;
window.toggleProVuln = toggleProVuln;
