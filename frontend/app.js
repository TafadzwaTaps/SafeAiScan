// ============================================================
//  SafeAIScan — Dashboard App Logic v2.0
// ============================================================

let scanProgressInterval = null;
let findings = [];
let currentContext = "";
let usageChart = null;
let riskChart  = null;

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
    updateUsageMeter(data.usage_today, data.usage_limit);
    loadUsageChart();

    if (findings.length > 0) enrichCVE(findings);

    stopLiveProgress();
    showToast(
      `Scan complete — ${findings.length} issue(s) found`,
      findings.length > 0 ? "warning" : "success"
    );

  } catch (err) {
    console.error(err);
    stopLiveProgress();

    if (err instanceof PlanError) {
      showUpgradePrompt(err.message);
    } else if (err instanceof LimitError) {
      showToast(err.message, "warning");
      showLimitBanner();
    } else {
      showToast("Scan failed: " + err.message, "error");
    }
  } finally {
    setLoader(false);
  }
}

// ============================================================
//  REPO SCAN
// ============================================================
async function scanRepo() {
  // Check plan before even prompting
  if (!canAccessFeature("repo_scan")) {
    showUpgradePrompt("Repo scanning requires a Pro or Enterprise plan. Upgrade to unlock full repository analysis.");
    return;
  }

  const repoUrl = prompt("Enter GitHub repo URL (https://github.com/user/repo):");
  if (!repoUrl?.trim()) return;

  if (!repoUrl.startsWith("https://github.com/")) {
    showToast("Only GitHub HTTPS URLs are supported", "warning");
    return;
  }

  setLoader(true);
  showToast("Queuing repo scan…", "info");

  try {
    const data = await scanRepoAPI(repoUrl);
    showToast(`Scan queued · Task: ${data.task_id}`, "success");
    pollTask(data.task_id);
  } catch (err) {
    console.error(err);
    if (err instanceof PlanError) {
      showUpgradePrompt(err.message);
    } else {
      showToast("Repo scan failed: " + err.message, "error");
    }
  } finally {
    setLoader(false);
  }
}

// ============================================================
//  TASK POLLING
// ============================================================
async function pollTask(taskId) {
  const states = { CLONING: 15, VALIDATING: 35, SCANNING: 65, FINALIZING: 88, DONE: 100, FAILED: 0 };
  const bar   = document.getElementById("scanProgressBar");
  const text  = document.getElementById("scanProgressText");
  let attempts = 0;

  const interval = setInterval(async () => {
    attempts++;
    if (attempts > 120) { // 5 min max
      clearInterval(interval);
      showToast("Scan is taking too long — check back later", "warning");
      return;
    }

    try {
      const data = await getTaskStatus(taskId);
      const pct  = states[data.state] ?? 50;
      if (bar)  bar.style.width  = pct + "%";
      if (text) text.innerText   = data.message || data.state || "Processing…";

      if (data.state === "DONE") {
        clearInterval(interval);
        findings = data.result?.findings || data.findings || [];
        renderVulnerabilities({ findings });
        updateStatus(findings);
        renderSeverityTabs({ findings });
        stopLiveProgress();
        showToast("Repo scan complete!", "success");
      }

      if (data.state === "FAILED") {
        clearInterval(interval);
        if (text) text.innerText = "Scan failed";
        stopLiveProgress();
        showToast("Scan failed: " + (data.result?.error || "Unknown error"), "error");
      }

    } catch (err) {
      console.error("Poll error:", err);
      clearInterval(interval);
      if (text) text.innerText = "Poll error";
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

  // Disable scan buttons during scan
  const btns = document.querySelectorAll(".scan-actions .btn");
  btns.forEach(b => {
    if (active) {
      b.disabled = true;
      b.style.opacity = "0.6";
    } else {
      b.disabled = false;
      b.style.opacity = "";
    }
  });
}

function startLiveProgress() {
  let progress = 2;
  const bar  = document.getElementById("scanProgressBar");
  const text = document.getElementById("scanProgressText");
  const steps = [
    "Parsing code…", "Running static analysis…", "Checking vulnerability patterns…",
    "AI risk modeling…", "Mapping CVE database…", "Finalizing report…"
  ];
  let stepIdx = 0;

  clearInterval(scanProgressInterval);
  scanProgressInterval = setInterval(() => {
    if (progress >= 95) { return; }
    progress += Math.random() * 5 + 1.5;
    if (bar)  bar.style.width = Math.min(95, progress) + "%";
    if (text && Math.floor(stepIdx) < steps.length) {
      text.innerText = steps[Math.floor(stepIdx)];
      stepIdx += 0.35;
    }
  }, 340);
}

function stopLiveProgress() {
  clearInterval(scanProgressInterval);
  const bar  = document.getElementById("scanProgressBar");
  const text = document.getElementById("scanProgressText");
  if (bar)  bar.style.width = "100%";
  if (text) text.innerText  = "Complete";
  setTimeout(() => {
    if (bar)  bar.style.width = "0%";
    if (text) text.innerText  = "";
  }, 2200);
}

// ============================================================
//  USAGE METER
// ============================================================
function updateUsageMeter(used, limit) {
  const el = document.getElementById("usage");
  if (!el) return;

  if (limit && limit < 999999) {
    const pct  = Math.round((used / limit) * 100);
    const color = pct >= 90 ? "var(--danger)" : pct >= 70 ? "var(--warning)" : "var(--success)";
    el.innerHTML = `
      <span style="font-family:'Syne',sans-serif;font-size:22px;font-weight:700;">${used}</span>
      <span style="font-size:11px;color:var(--text-muted);">/ ${limit}</span>
      <div style="margin-top:6px;height:4px;background:var(--bg-3);border-radius:99px;overflow:hidden;">
        <div style="height:100%;width:${pct}%;background:${color};border-radius:99px;transition:width 0.4s;"></div>
      </div>
    `;
  } else {
    el.innerText = used;
  }
}

function showLimitBanner() {
  const plan = getUserPlan();
  const existing = document.getElementById("limitBanner");
  if (existing) return;

  const banner = document.createElement("div");
  banner.id = "limitBanner";
  banner.style.cssText = `
    background:rgba(251,146,60,0.08);border:1px solid rgba(251,146,60,0.25);
    border-radius:12px;padding:12px 16px;margin-bottom:14px;
    display:flex;align-items:center;justify-content:space-between;gap:12px;
    animation:popIn 0.3s ease both;
  `;
  banner.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;">
      <i class="bi bi-exclamation-triangle" style="color:var(--warning);font-size:16px;"></i>
      <div>
        <div style="font-size:13px;font-weight:600;color:var(--warning);">Daily scan limit reached</div>
        <div style="font-size:11px;color:var(--text-muted);">
          ${plan === "free" ? "Free plan: 20 scans/day. " : ""}Upgrade for more scans.
        </div>
      </div>
    </div>
    <button onclick="showUpgradePrompt('Upgrade to scan more code every day.')" style="
      background:linear-gradient(135deg,#fb923c,#ea580c);color:#fff;border:none;
      padding:7px 14px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;
      font-family:'DM Sans',sans-serif;white-space:nowrap;">
      Upgrade Now
    </button>
  `;

  const scanPanel = document.querySelector(".scan-panel");
  if (scanPanel) scanPanel.parentNode.insertBefore(banner, scanPanel);
}

// ============================================================
//  DATA LOADERS
// ============================================================
async function loadUsage() {
  const el = document.getElementById("usage");
  if (!el) return;

  try {
    const data   = await getUsage();
    const arr    = Array.isArray(data) ? data : [];
    const today  = new Date().toISOString().slice(0, 10);
    const record = arr.find(d => (d.date || "").startsWith(today));
    const count  = record?.request_count ?? record?.count ?? 0;

    const limits = getUserLimits();
    const limit  = limits?.daily_scans ?? null;
    updateUsageMeter(count, limit);
  } catch {
    el.innerText = "—";
  }
}

async function loadHistory() {
  const list = document.getElementById("history");
  if (!list) return;

  list.innerHTML = [1,2,3].map(() =>
    `<div class="skeleton mb-2" style="height:40px;border-radius:8px;"></div>`
  ).join("");

  try {
    const data = await getHistory();
    const arr  = Array.isArray(data) ? data : [];

    if (!arr.length) {
      list.innerHTML = `
        <div style="text-align:center;padding:16px 8px;color:var(--text-faint);font-size:12px;">
          <i class="bi bi-shield" style="display:block;font-size:20px;margin-bottom:6px;color:var(--border-bright);"></i>
          No scans yet — run your first scan!
        </div>`;
      return;
    }

    list.innerHTML = arr.slice(0, 8).map(item => {
      const risk  = (item.risk || "LOW").toUpperCase();
      const count = item.findings_count ?? item.score ?? "—";
      const time  = item.timestamp ? new Date(item.timestamp).toLocaleDateString() : "";
      const sevClass = risk === "HIGH" || risk === "CRITICAL" ? "sev-high" : risk === "MEDIUM" ? "sev-medium" : "sev-low";
      return `
        <div class="history-item pop-in" style="
          display:flex;align-items:center;justify-content:space-between;gap:8px;
          padding:8px 10px;border-radius:8px;background:var(--bg-2);
          border:1px solid var(--border);margin-bottom:6px;
          transition:border-color 0.15s;cursor:default;">
          <span class="badge-pill ${sevClass}">${risk}</span>
          <span style="color:var(--text-muted);font-size:11px;flex:1;">
            ${typeof count === "number" ? `${count} issue${count !== 1 ? "s" : ""}` : count}
          </span>
          <span style="color:var(--text-faint);font-size:10px;">${time}</span>
        </div>
      `;
    }).join("");

  } catch (err) {
    console.error(err);
    list.innerHTML = `<div style="color:var(--text-faint);font-size:12px;padding:8px 0;">
      <i class="bi bi-exclamation-circle me-1"></i>Failed to load history
    </div>`;
  }
}

async function loadPlan() {
  const el = document.getElementById("plan");
  if (!el) return;

  try {
    const data   = await getMe();
    const plan   = (data.plan || "free").toLowerCase();
    const limits = data.limits || {};

    const planColors = {
      free:       "sev-low",
      pro:        "sev-high",
      enterprise: "sev-critical"
    };
    const planIcons = {
      free:       "bi-person",
      pro:        "bi-lightning-charge",
      enterprise: "bi-building"
    };

    el.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
        <span class="badge-pill ${planColors[plan] || 'sev-low'}" style="padding:4px 10px;font-size:11px;">
          <i class="bi ${planIcons[plan] || 'bi-person'} me-1"></i>${plan.toUpperCase()}
        </span>
        <span style="font-size:11px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:150px;" title="${escHtml(data.email || '')}">
          ${escHtml(data.email || "")}
        </span>
      </div>
      <div style="margin-top:8px;font-size:11px;color:var(--text-faint);">
        <i class="bi bi-bar-chart me-1"></i>${limits.daily_scans < 999999 ? limits.daily_scans + " scans/day" : "Unlimited scans"}
      </div>
    `;

    // Update locked UI based on plan
    applyPlanGating(plan, limits);

  } catch {
    el.innerHTML = `<span class="badge-pill sev-low"><i class="bi bi-person me-1"></i>FREE</span>`;
  }
}

function applyPlanGating(plan, limits) {
  // Repo scan button
  const repoBtn = document.querySelector('[onclick="scanRepo()"]');
  if (repoBtn && !limits?.repo_scan) {
    repoBtn.classList.add("locked-feature");
    repoBtn.title = "Requires Pro plan";
    repoBtn.innerHTML = `<i class="bi bi-lock me-1"></i>Scan Repo`;
    repoBtn.style.opacity = "0.55";
  }

  // Show upgrade sidebar section if free
  const upgradeSection = document.querySelector(".side-label + .scan-panel");
  if (upgradeSection && plan !== "free") {
    upgradeSection.style.display = "none";
  }
}

async function loadTeam() {
  const list = document.getElementById("teamList");
  if (!list) return;

  const plan = getUserPlan();
  if (plan === "free") {
    list.innerHTML = `<li style="color:var(--text-faint);font-size:12px;">
      <i class="bi bi-lock me-1"></i>Team management requires Pro
    </li>`;
    return;
  }

  try {
    const res  = await apiRequest("/api/org/users");
    const data = await safeJson(res);
    list.innerHTML = (data || []).map(u => `
      <li style="font-size:12px;color:var(--text-muted);padding:5px 0;display:flex;align-items:center;gap:8px;">
        <i class="bi bi-person-circle" style="color:var(--accent);"></i>
        <span>${escHtml(u.email)}</span>
        <span class="badge-pill sev-low" style="font-size:9px;">${escHtml(u.plan || "free")}</span>
      </li>
    `).join("") || `<li style="color:var(--text-faint);font-size:12px;">No team members yet</li>`;
  } catch {
    list.innerHTML = `<li style="color:var(--text-faint);font-size:12px;">Team unavailable</li>`;
  }
}

// ============================================================
//  RENDER VULNERABILITIES
// ============================================================
function renderVulnerabilities(data) {
  const container = document.getElementById("vulnCards");
  if (!container) return;

  const list = Array.isArray(data) ? data : (data.findings || []);

  if (!list.length) {
    container.innerHTML = `
      <div class="scan-panel" style="text-align:center;padding:28px;">
        <i class="bi bi-shield-check" style="font-size:32px;color:var(--success);display:block;margin-bottom:10px;"></i>
        <div style="font-family:'Syne',sans-serif;font-size:15px;font-weight:700;color:var(--success);margin-bottom:4px;">
          All Clear!
        </div>
        <div style="font-size:12px;color:var(--text-muted);">No security issues detected in this code.</div>
      </div>`;
    return;
  }

  const sevOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const sorted   = [...list].sort((a, b) => (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0));

  container.innerHTML = sorted.map((vuln, i) => {
    const sev       = (vuln.severity || "LOW").toUpperCase();
    const badgeClass = sev === "CRITICAL" ? "sev-critical" : sev === "HIGH" ? "sev-high" : sev === "MEDIUM" ? "sev-medium" : "sev-low";
    const borderColor = sev === "CRITICAL" ? "rgba(192,38,211,0.3)" : sev === "HIGH" ? "rgba(244,63,94,0.25)" : sev === "MEDIUM" ? "rgba(251,146,60,0.2)" : "var(--border)";

    return `
      <div class="vuln-card pop-in" onclick="toggleVuln(this, ${i})" data-idx="${i}"
           style="border-left:3px solid ${borderColor};">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;">
          <div style="flex:1;min-width:0;">
            <div class="vuln-title">${escHtml(vuln.title || "Security Issue")}</div>
            <div class="vuln-meta">
              ${vuln.file   ? `<span><i class="bi bi-file-code me-1"></i>${escHtml(vuln.file)}</span>` : ""}
              ${vuln.line   ? `<span>· line ${vuln.line}</span>` : ""}
              ${vuln.source ? `<span style="color:var(--accent);">· ${escHtml(vuln.source)}</span>` : ""}
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;margin-left:10px;">
            <span class="badge-pill ${badgeClass}">${sev}</span>
            <i class="bi bi-chevron-down" style="color:var(--text-faint);font-size:11px;transition:transform 0.2s;" id="chevron-${i}"></i>
          </div>
        </div>

        <div class="vuln-details" id="vd-${i}">
          <div style="color:var(--text-muted);margin-bottom:8px;font-size:13px;line-height:1.5;">
            ${escHtml(vuln.description || "No description provided.")}
          </div>

          ${vuln.fix && vuln.fix !== "No auto-fix available" ? `
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;color:var(--accent);margin-bottom:5px;">
              <i class="bi bi-wrench me-1"></i>Recommended Fix
            </div>
            <div class="fix-box">${escHtml(vuln.fix)}</div>
          ` : ""}

          ${vuln.cve && vuln.cve !== "N/A" ? `
            <div style="margin-top:8px;display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
              <span class="badge-pill sev-${cvssSev(vuln.cvss)}">
                <i class="bi bi-bug me-1"></i>${escHtml(vuln.cve)}
              </span>
              ${vuln.cvss != null ? `<span style="font-size:11px;color:var(--text-muted);">CVSS ${vuln.cvss}</span>` : ""}
            </div>
          ` : ""}
          <div id="cve-${i}"></div>
        </div>
      </div>
    `;
  }).join("");
}

function toggleVuln(card, idx) {
  const wasActive = card.classList.contains("active");
  document.querySelectorAll(".vuln-card.active").forEach(c => {
    c.classList.remove("active");
    const ch = c.querySelector('[id^="chevron-"]');
    if (ch) ch.style.transform = "";
  });
  if (!wasActive) {
    card.classList.add("active");
    const chevron = document.getElementById(`chevron-${idx}`);
    if (chevron) chevron.style.transform = "rotate(180deg)";
  }
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
  const plan    = getUserPlan();
  const isBasic = plan === "free";

  if (!explain && !fixes.length) { container.innerHTML = ""; return; }

  container.innerHTML = `
    <div class="ai-box pop-in">
      <div class="ai-label">
        <i class="bi bi-cpu me-1"></i>AI Security Insights
        ${isBasic ? `<span class="badge-pill sev-low" style="font-size:9px;margin-left:6px;">Basic</span>` : ""}
      </div>

      ${explain ? `<p style="font-size:13px;color:var(--text-muted);margin-bottom:${fixes.length ? "10px" : "0"};line-height:1.55;">${escHtml(explain)}</p>` : ""}

      ${fixes.length > 0 ? `
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;color:var(--text-faint);margin-bottom:6px;">Recommended Actions</div>
        <div style="display:flex;flex-direction:column;gap:5px;">
          ${fixes.map(f => `
            <div style="display:flex;gap:8px;font-size:12px;color:var(--text-muted);">
              <i class="bi bi-check-circle-fill" style="color:var(--success);flex-shrink:0;margin-top:2px;"></i>
              <span>${escHtml(f)}</span>
            </div>
          `).join("")}
        </div>
      ` : ""}

      ${isBasic ? `
        <div style="margin-top:12px;padding-top:10px;border-top:1px solid var(--border);">
          <a href="#" onclick="showUpgradePrompt('Get full AI-powered vulnerability analysis, actionable code fixes, and CVE mapping with Pro.')" style="
            font-size:11px;color:var(--accent);text-decoration:none;display:flex;align-items:center;gap:5px;">
            <i class="bi bi-lightning-charge"></i>
            Upgrade to Pro for full AI analysis & fixes
          </a>
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
  const hasMedium   = findings.some(f => f.severity === "MEDIUM");
  statusEl.innerHTML = hasCritical
    ? `<span class="status-dot" style="background:var(--danger);box-shadow:0 0 6px var(--danger);"></span>Vulnerable`
    : hasMedium
    ? `<span class="status-dot" style="background:var(--warning);box-shadow:0 0 6px var(--warning);"></span>Caution`
    : `<span class="status-dot online"></span>Secure`;
  statusEl.className = hasCritical ? "status-risk" : hasMedium ? "" : "status-safe";
}

function renderSeverityTabs(data) {
  const el = document.getElementById("severityTabs");
  if (!el) return;
  const f = data.findings || [];
  if (!f.length) { el.innerHTML = ""; return; }

  const counts = {
    CRITICAL: f.filter(x => x.severity === "CRITICAL").length,
    HIGH:     f.filter(x => x.severity === "HIGH").length,
    MEDIUM:   f.filter(x => x.severity === "MEDIUM").length,
    LOW:      f.filter(x => x.severity === "LOW").length
  };
  el.innerHTML = Object.entries(counts)
    .filter(([, v]) => v > 0)
    .map(([sev, cnt]) => `
      <span class="badge-pill sev-${sev.toLowerCase()}">${sev} ${cnt}</span>
    `).join("");
}

// ============================================================
//  CVE ENRICHMENT (background, non-blocking)
// ============================================================
async function enrichCVE(findingsList) {
  for (let i = 0; i < findingsList.length && i < 5; i++) {
    const vuln = findingsList[i];
    const box  = document.getElementById(`cve-${i}`);
    if (!box || !vuln.title || (vuln.cve && vuln.cve !== "N/A")) continue;

    try {
      const res  = await apiRequest(`/api/cve/search?query=${encodeURIComponent(vuln.title)}`);
      const data = await safeJson(res);
      const cves = data?.cves || [];

      if (cves.length) {
        const top = cves[0];
        box.innerHTML = `
          <div style="font-size:11px;color:var(--text-muted);margin-top:6px;
                      padding:6px 8px;background:rgba(56,189,248,0.06);border-radius:6px;
                      border:1px solid rgba(56,189,248,0.12);">
            <i class="bi bi-shield-exclamation me-1" style="color:var(--warning);"></i>
            <strong style="color:var(--accent-2);">${escHtml(top.id || "")}</strong>
            ${top.cvss != null ? `· CVSS <strong>${top.cvss}</strong>` : ""}
            ${top.description ? ` · <span style="color:var(--text-faint);">${escHtml(top.description.substring(0, 100))}…</span>` : ""}
          </div>`;
      }
    } catch { /* silent — CVE enrichment is optional */ }
  }
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
    const arr  = Array.isArray(data) ? data : [];
    if (arr.length) {
      labels = arr.map(d => {
        const date = d.date ? new Date(d.date) : null;
        return date ? date.toLocaleDateString("en", { weekday: "short" }) : "—";
      });
      values = arr.map(d => d.request_count || d.count || 0);
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
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#0f1a2e",
          titleColor: "#e8edf8",
          bodyColor: "#8296b3",
          borderColor: "#1e3a5f",
          borderWidth: 1
        }
      },
      scales: {
        x: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#8296b3", font: { size: 11 } } },
        y: { grid: { color: "rgba(255,255,255,0.04)" }, ticks: { color: "#8296b3", font: { size: 11 } }, beginAtZero: true }
      }
    }
  });
}

function loadRiskChart(findingsList) {
  const ctx = document.getElementById("riskChart");
  if (!ctx) return;

  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  (findingsList || []).forEach(f => {
    const s = (f.severity || "low").toUpperCase();
    if (s === "CRITICAL")    counts.Critical++;
    else if (s === "HIGH")   counts.High++;
    else if (s === "MEDIUM") counts.Medium++;
    else                     counts.Low++;
  });

  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (!total) return;

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
        legend: {
          position: "right",
          labels: { color: "#8296b3", font: { size: 11 }, padding: 12 }
        },
        tooltip: {
          backgroundColor: "#0f1a2e",
          titleColor: "#e8edf8",
          bodyColor: "#8296b3"
        }
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
  el.innerText        = key ? maskKey(key) : "Not available";
  el.dataset.full     = key;
  el.dataset.masked   = key ? maskKey(key) : "";
  el.dataset.shown    = "false";
}

function maskKey(key) {
  if (!key || key.length < 10) return "••••••••••••";
  return key.substring(0, 8) + "••••••••" + key.substring(key.length - 4);
}

function toggleApiKey() {
  const el   = document.getElementById("apiKeyDisplay");
  const icon = document.getElementById("toggleKeyIcon");
  if (!el) return;
  const shown = el.dataset.shown === "true";
  el.innerText     = shown ? el.dataset.masked : el.dataset.full;
  el.dataset.shown = String(!shown);
  if (icon) icon.className = shown ? "bi bi-eye" : "bi bi-eye-slash";
}

function copyKey() {
  const key = localStorage.getItem("api_key");
  if (!key || key === "undefined") { showToast("No API key available", "warning"); return; }

  navigator.clipboard.writeText(key).then(() => {
    showToast("API key copied to clipboard!", "success");
    const confirm = document.getElementById("copyConfirm");
    if (confirm) { confirm.classList.add("show"); setTimeout(() => confirm.classList.remove("show"), 1800); }
  }).catch(() => {
    // Fallback for older browsers
    const el = document.createElement("textarea");
    el.value = key; el.style.position = "fixed"; el.style.opacity = "0";
    document.body.appendChild(el); el.select();
    document.execCommand("copy");
    document.body.removeChild(el);
    showToast("API key copied!", "success");
  });
}

// ============================================================
//  UTILITY
//  FIX: guarded to avoid duplicate declarations with api.js
// ============================================================
function logout() {
  localStorage.clear();
  window.location.replace("login.html");
}

// Use window.escHtml if already defined by api.js (loaded first), else define it
function escHtml(str) {
  if (window.escHtml && window.escHtml !== escHtml) return window.escHtml(str);
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function cvssSev(score) {
  if (window.cvssSev && window.cvssSev !== cvssSev) return window.cvssSev(score);
  if (score == null) return "low";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

async function exportPDF() {
  if (!findings.length) { showToast("Run a scan first to export results", "warning"); return; }

  showToast("Generating PDF report…", "info");
  try {
    const res  = await apiRequest("/api/report/pdf", {
      method: "POST",
      body: JSON.stringify({ findings })
    });
    const blob = await res.blob();
    const url  = window.URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = "safeaiscan-report.pdf"; a.click();
    window.URL.revokeObjectURL(url);
    showToast("PDF report downloaded!", "success");
  } catch (err) {
    showToast("PDF export failed: " + err.message, "error");
  }
}

function openSide(v) {
  currentContext = JSON.stringify(v);
  const side  = document.getElementById("side");
  const title = document.getElementById("sideTitle");
  const desc  = document.getElementById("sideDesc");
  if (!side) return;
  if (title) title.innerText = v.title || v.match || "Finding";
  if (desc) desc.innerHTML = `
    <p style="color:var(--text-muted);font-size:13px;line-height:1.55;">${escHtml(v.description || "No description available.")}</p>
    ${v.fix && v.fix !== "No auto-fix available" ? `
      <div class="ai-label mt-3 mb-2"><i class="bi bi-wrench me-1"></i>Recommended Fix</div>
      <div class="fix-box">${escHtml(v.fix)}</div>
    ` : ""}
    ${v.cve && v.cve !== "N/A" ? `
      <div style="margin-top:12px;">
        <span class="badge-pill sev-${cvssSev(v.cvss)}">
          <i class="bi bi-bug me-1"></i>${escHtml(v.cve)}
        </span>
        ${v.cvss != null ? `<span style="margin-left:8px;font-size:11px;color:var(--text-muted);">CVSS ${v.cvss}</span>` : ""}
      </div>
    ` : ""}
  `;
  side.classList.add("open");
}

function closeSide() {
  document.getElementById("side")?.classList.remove("open");
}

async function askAI() {
  const q    = document.getElementById("aiInput")?.value?.trim();
  const chat = document.getElementById("aiChat");
  if (!q || !chat) return;

  chat.innerHTML += `
    <div style="color:var(--accent);font-size:12px;margin-bottom:4px;">
      <strong>You:</strong> ${escHtml(q)}
    </div>`;

  document.getElementById("aiInput").value = "";

  try {
    const res  = await apiRequest("/api/ai/explain", {
      method: "POST",
      body: JSON.stringify({ question: q, context: currentContext })
    });
    const data = await safeJson(res);
    const text = data.explanation || data.data?.explanation || "";
    chat.innerHTML += `
      <div style="color:var(--text-muted);font-size:12px;margin-bottom:8px;
                  padding-left:10px;border-left:2px solid var(--accent);">
        ${escHtml(text)}
      </div>`;
    chat.scrollTop = chat.scrollHeight;
  } catch (err) {
    chat.innerHTML += `<div style="color:var(--danger);font-size:11px;margin-bottom:6px;">
      <i class="bi bi-x-circle me-1"></i>${escHtml(err.message)}
    </div>`;
  }
}

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

// ============================================================
//  SCROLL FADE-IN
// ============================================================
function initScrollFade() {
  const observer = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) e.target.classList.add("show"); });
  }, { threshold: 0.1 });
  document.querySelectorAll(".fade-in").forEach(el => observer.observe(el));
}

// ============================================================
//  PLAN EVENT LISTENER
// ============================================================
document.addEventListener("planUpdated", (e) => {
  const d = e.detail;
  if (d.usage_today != null) updateUsageMeter(d.usage_today, d.usage_limit);
});

// ============================================================
//  INIT
// ============================================================
async function init() {
  initApiKey();
  initScrollFade();

  const has = (id) => !!document.getElementById(id);

  // Load all data in parallel for speed
  const tasks = [];
  if (has("plan"))       tasks.push(loadPlan());
  if (has("usage"))      tasks.push(loadUsage());
  if (has("history"))    tasks.push(loadHistory());
  if (has("usageChart")) tasks.push(loadUsageChart());
  if (has("teamList"))   tasks.push(loadTeam());

  await Promise.allSettled(tasks);
}

document.addEventListener("DOMContentLoaded", init);

// ---- GLOBAL EXPORTS ----
window.scan             = scan;
window.scanRepo         = scanRepo;
window.copyKey          = copyKey;
window.toggleApiKey     = toggleApiKey;
window.initApiKey       = initApiKey;   // FIX: expose so api.js rotateApiKey can call it
window.logout           = logout;
window.exportPDF        = exportPDF;
window.openSide         = openSide;
window.closeSide        = closeSide;
window.askAI            = askAI;
// FIX: fetchCVE is defined in api.js — don't re-export an undefined ref here
// window.fetchCVE      = fetchCVE;  ← removed
window.toggleVuln       = toggleVuln;
window.renderVulnerabilities = renderVulnerabilities;
window.loadRiskChart    = loadRiskChart;
window.escHtml          = escHtml;
window.cvssSev          = cvssSev;
window.rotateApiKey     = rotateApiKey;
