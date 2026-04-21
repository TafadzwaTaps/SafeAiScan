// ============================================================
//  SafeAIScan Pro — Minisky Scanner Engine v2.1
//  FIXED: plan gating, findings reference, repo scan task_id,
//         upgrade modal, auth flow, renderResults scope
// ============================================================
if (!window.PlanError) {
  class PlanError extends Error {
    constructor(message = "Plan upgrade required") {
      super(message);
      this.name = "PlanError";
    }
  }
  window.PlanError = PlanError;
}

if (!window.LimitError) {
  class LimitError extends Error {
    constructor(message = "Usage limit exceeded") {
      super(message);
      this.name = "LimitError";
    }
  }
  window.LimitError = LimitError;
}

window.aiResult = null;
window.SafeAIScan = window.SafeAIScan || {};
const S = window.SafeAIScan;

// STATE
S.findings = S.findings || [];
S.aiResult = S.aiResult || null;
S.currentContext = S.currentContext || "";
S.scanProgressInterval = S.scanProgressInterval || null;
S.userPlan = localStorage.getItem("user_plan") || "free";
S.userEmail = localStorage.getItem("user_email") || "";

// ============================================================
//  PLAN DETECTION — runs on load, syncs from backend
// ============================================================
async function loadAndApplyPlan() {
  try {
    const res  = await apiRequest("/api/me");
    const data = await safeJson(res);

    const plan  = data?.plan || data?.data?.plan || "free";
    const email = data?.email || data?.data?.email || "";
    const limits = data?.limits || data?.data?.limits || {};

    S.userPlan   = plan;
    S.userEmail  = email;
    S.userLimits = limits;

    localStorage.setItem("user_plan",   plan);
    localStorage.setItem("user_email",  email);
    localStorage.setItem("user_limits", JSON.stringify(limits));

    // Update plan badge in topbar
    const planBadge = document.getElementById("planBadge");
    if (planBadge) {
      const labels = { free: "FREE", pro: "PRO", enterprise: "ENTERPRISE" };
      const colors = {
        free:       "background:rgba(52,211,153,0.15);color:#6ee7b7;border:1px solid rgba(52,211,153,0.3);",
        pro:        "background:linear-gradient(135deg,rgba(91,123,254,0.25),rgba(192,38,211,0.2));color:#a5b4fc;border:1px solid rgba(91,123,254,0.35);",
        enterprise: "background:linear-gradient(135deg,rgba(192,38,211,0.25),rgba(244,63,94,0.2));color:#e879f9;border:1px solid rgba(192,38,211,0.4);"
      };
      planBadge.textContent  = labels[plan] || plan.toUpperCase();
      planBadge.style.cssText += colors[plan] || colors.free;
    }

    // Apply plan gating to UI
    applyPlanGating(plan);

    return { plan, email, limits };
  } catch (err) {
    console.warn("Plan load failed, using cached:", S.userPlan);
    applyPlanGating(S.userPlan);
    return { plan: S.userPlan };
  }
}

function canProAccess() {
  return ["pro", "enterprise"].includes((S.userPlan || "free").toLowerCase());
}

function applyPlanGating(plan) {
  const isPro = ["pro", "enterprise"].includes(plan.toLowerCase());

  const repoBtn = document.getElementById("repoScanBtn");

if (repoBtn) {
  repoBtn.dataset.originalHtml = repoBtn.dataset.originalHtml || repoBtn.innerHTML;

  if (!isPro) {
    repoBtn.innerHTML = `<i class="bi bi-lock me-1"></i>Scan <span style="font-size:9px;opacity:0.7;">(Pro)</span>`;
    repoBtn.onclick = (e) => {
      e.preventDefault();
      showUpgradeModal("Repo scanning");
    };
  } else {
    repoBtn.innerHTML = repoBtn.dataset.originalHtml;
    repoBtn.onclick = null;
  }
}
}

// ============================================================
//  UPGRADE MODAL
// ============================================================
function showUpgradeModal(featureName = "this feature") {
  // Remove existing modal
  document.getElementById("upgradeModal")?.remove();

  const modal = document.createElement("div");
  modal.id = "upgradeModal";
  modal.style.cssText = `
    position:fixed;inset:0;z-index:99999;display:flex;align-items:center;justify-content:center;
    background:rgba(0,0,0,0.7);backdrop-filter:blur(8px);padding:16px;
  `;

  modal.innerHTML = `
    <div style="
      background:var(--bg-2);border:1px solid var(--border-bright);
      border-radius:20px;max-width:480px;width:100%;
      box-shadow:0 32px 80px rgba(0,0,0,0.7);
      animation:popIn 0.25s cubic-bezier(0.34,1.56,0.64,1) both;
      overflow:hidden;
    ">
      <!-- Header -->
      <div style="
        background:linear-gradient(135deg,rgba(91,123,254,0.15),rgba(192,38,211,0.1));
        border-bottom:1px solid var(--border);padding:24px 28px 20px;
      ">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
          <div style="font-family:'Syne',sans-serif;font-size:20px;font-weight:800;letter-spacing:-0.03em;">
            <i class="bi bi-lightning-charge" style="color:var(--warning);margin-right:8px;"></i>Upgrade Required
          </div>
          <button onclick="document.getElementById('upgradeModal').remove()" style="
            background:var(--bg-3);border:1px solid var(--border);color:var(--text-muted);
            border-radius:8px;width:30px;height:30px;cursor:pointer;font-size:16px;
            display:flex;align-items:center;justify-content:center;
          "><i class="bi bi-x"></i></button>
        </div>
        <p style="font-size:13px;color:var(--text-muted);margin:0;">
          <strong style="color:var(--text-primary);">${escHtml(featureName)}</strong>
          requires a Pro or Enterprise plan.
        </p>
      </div>

      <!-- Plan comparison -->
      <div style="padding:20px 28px;">
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:20px;">

          <!-- Free -->
          <div style="background:var(--bg-1);border:1px solid var(--border);border-radius:12px;padding:14px;text-align:center;">
            <div style="font-size:11px;font-weight:700;color:var(--text-faint);text-transform:uppercase;letter-spacing:0.8px;margin-bottom:8px;">Free</div>
            <div style="font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:var(--text-primary);">$0</div>
            <div style="font-size:10px;color:var(--text-faint);margin-bottom:12px;">/month</div>
            <div style="font-size:11px;color:var(--text-muted);text-align:left;display:flex;flex-direction:column;gap:5px;">
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>20 scans/day</div>
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>Code scanning</div>
              <div><i class="bi bi-x me-1" style="color:var(--danger);"></i>Repo scanning</div>
              <div><i class="bi bi-x me-1" style="color:var(--danger);"></i>Full AI analysis</div>
              <div><i class="bi bi-x me-1" style="color:var(--danger);"></i>CVE enrichment</div>
            </div>
          </div>

          <!-- Pro -->
          <div style="
            background:linear-gradient(145deg,var(--bg-1),rgba(91,123,254,0.08));
            border:1px solid rgba(91,123,254,0.4);border-radius:12px;padding:14px;text-align:center;
            box-shadow:0 0 0 1px rgba(91,123,254,0.2),0 8px 32px rgba(91,123,254,0.12);
            position:relative;
          ">
            <div style="
              position:absolute;top:-10px;left:50%;transform:translateX(-50%);
              background:linear-gradient(135deg,#5b7bfe,#4361ee);color:#fff;
              font-size:9px;font-weight:700;padding:2px 10px;border-radius:99px;
              letter-spacing:0.8px;text-transform:uppercase;
            ">Popular</div>
            <div style="font-size:11px;font-weight:700;color:#93aaff;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:8px;">Pro</div>
            <div style="font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:var(--text-primary);">$29</div>
            <div style="font-size:10px;color:var(--text-faint);margin-bottom:12px;">/month</div>
            <div style="font-size:11px;color:var(--text-muted);text-align:left;display:flex;flex-direction:column;gap:5px;">
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>200 scans/day</div>
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>Repo scanning</div>
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>Full AI analysis</div>
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>CVE enrichment</div>
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>5 team members</div>
            </div>
          </div>

          <!-- Enterprise -->
          <div style="background:var(--bg-1);border:1px solid rgba(192,38,211,0.3);border-radius:12px;padding:14px;text-align:center;">
            <div style="font-size:11px;font-weight:700;color:#e879f9;text-transform:uppercase;letter-spacing:0.8px;margin-bottom:8px;">Enterprise</div>
            <div style="font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:var(--text-primary);">Custom</div>
            <div style="font-size:10px;color:var(--text-faint);margin-bottom:12px;">/month</div>
            <div style="font-size:11px;color:var(--text-muted);text-align:left;display:flex;flex-direction:column;gap:5px;">
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>Unlimited scans</div>
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>All Pro features</div>
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>Unlimited team</div>
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>Audit logs</div>
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>API access</div>
            </div>
          </div>
        </div>

        <!-- CTA buttons -->
        <div style="display:flex;gap:10px;">
          <button onclick="window.location.href='index.html#pricing'" style="
            flex:1;background:linear-gradient(135deg,#5b7bfe,#4361ee);color:#fff;border:none;
            padding:12px;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;
            font-family:'DM Sans',sans-serif;
          ">
            <i class="bi bi-lightning-charge me-1"></i>Upgrade to Pro
          </button>
          <button onclick="window.location.href='enterprise.html'" style="
            flex:1;background:transparent;color:var(--text-muted);border:1px solid var(--border);
            padding:12px;border-radius:10px;font-size:13px;cursor:pointer;
            font-family:'DM Sans',sans-serif;
          ">
            <i class="bi bi-building me-1"></i>Enterprise Demo
          </button>
        </div>

        <div style="text-align:center;margin-top:12px;">
          <button onclick="document.getElementById('upgradeModal').remove()" style="
            background:none;border:none;color:var(--text-faint);font-size:12px;
            cursor:pointer;font-family:'DM Sans',sans-serif;
          ">Maybe later</button>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  modal.addEventListener("click", e => { if (e.target === modal) modal.remove(); });
}

// ============================================================
//  TIMELINE LOG
// ============================================================
function log(msg, type = "info") {
  const el = document.getElementById("timeline");
  if (!el) return;
  const colors = { info: "var(--accent)", success: "var(--success)", warning: "var(--warning)", error: "var(--danger)" };
  const item = document.createElement("div");
  item.className = "tl-item";
  item.innerHTML = `
    <div class="tl-dot" style="background:${colors[type] || colors.info};"></div>
    <div class="tl-text">${escHtml(msg)}</div>
  `;
  el.insertBefore(item, el.firstChild);
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

function showProgress() {
  const wrap = document.getElementById("scanProgressWrap");
  if (wrap) wrap.style.display = "block";
}

function hideProgress() {
  const wrap = document.getElementById("scanProgressWrap");
  const bar  = document.getElementById("scanProgressBar");
  const text = document.getElementById("scanProgressText");
  const pct  = document.getElementById("scanPct");
  if (bar)  bar.style.width = "100%";
  if (text) text.innerText  = "Complete";
  if (pct)  pct.innerText   = "100%";
  setTimeout(() => {
    if (wrap) wrap.style.display = "none";
    if (bar)  bar.style.width    = "0%";
    STAGES.forEach(s => {
      const el = document.getElementById(s.id);
      if (el) el.classList.remove("active", "done");
    });
  }, 1500);
}

function startPipeline() {
  showProgress();
  const bar  = document.getElementById("scanProgressBar");
  const text = document.getElementById("scanProgressText");
  const pct  = document.getElementById("scanPct");

  let stage = 0;
  let progress = 0;

  clearInterval(S.scanProgressInterval);
  S.scanProgressInterval = setInterval(() => {
    if (stage >= STAGES.length) return;
    const target = STAGES[stage].pct;
    progress += (target - progress) * 0.2;
    if (bar)  bar.style.width = progress + "%";
    if (pct)  pct.innerText   = Math.round(progress) + "%";
    if (text) text.innerText  = STAGES[stage].label;

    // Mark stage as active
    STAGES.forEach((s, i) => {
      const el = document.getElementById(s.id);
      if (!el) return;
      if (i < stage) { el.classList.remove("active"); el.classList.add("done"); }
      else if (i === stage) { el.classList.add("active"); el.classList.remove("done"); }
      else { el.classList.remove("active", "done"); }
    });

    if (Math.abs(progress - target) < 1.5) stage++;
  }, 250);
}

function stopPipeline() {
  clearInterval(S.scanProgressInterval);
  hideProgress();
}

// ============================================================
//  REPORT BUILDER
// ============================================================
function buildReport(findings, aiResult, meta = {}) {
  const severityCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach(f => {
    const s = (f.severity || "LOW").toUpperCase();
    severityCount[s] = (severityCount[s] || 0) + 1;
  });

  const riskScore = Math.max(0,
    100 - severityCount.CRITICAL * 25 - severityCount.HIGH * 12 - severityCount.MEDIUM * 5
  );

  return {
    meta: { timestamp: new Date().toISOString(), source: meta.source || "code_scan", repo: meta.repo || null },
    summary: {
      total: findings.length,
      severityCount,
      riskScore,
      status: severityCount.CRITICAL > 0 ? "CRITICAL"
             : severityCount.HIGH > 0 ? "HIGH_RISK"
             : findings.length > 0 ? "MODERATE" : "CLEAN"
    },
    ai: aiResult || { explanation: "No AI analysis available", fixes: [] },
    findings: findings.length > 0 ? findings : [{
      title: "No Issues Detected",
      description: "Static + AI scan found no vulnerabilities.",
      severity: "LOW",
      fix: "No action required"
    }]
  };
}

// ============================================================
//  MAIN SCAN — uses S.findings as the source of truth
// ============================================================
S.runScan = async function () {
  const code = document.getElementById("code")?.value?.trim();
  if (!code) { showToast("Paste some code to scan", "warning"); return; }

  log("Starting scan…");
  startPipeline();
  clearResults();

  try {
    const data = await analyzeCode(code);

    S.aiResult  = data.ai || null;
    S.findings  = data.findings || [];

    // AI-only fallback
    if (!S.findings.length && S.aiResult?.explanation) {
      S.findings = [{
        title:       "AI Detected Issue",
        description: S.aiResult.explanation,
        severity:    "HIGH",
        fix:         (S.aiResult.fixes || []).join("\n"),
        source:      "ai"
      }];
    }

    const report = buildReport(S.findings, S.aiResult);
    window.findings   = S.findings; // keep window.findings in sync
    window.aiResult   = S.aiResult;
    window.scanReport = report;

    renderResults(S.findings);
    renderOverview(S.findings);
    renderSeverityBars(S.findings);
    renderHeatmap(S.findings);
    renderAIPanel();
    enrichCVEPro(S.findings);

    // Update usage counter
    if (data.usage_today !== undefined) {
      const el = document.getElementById("usageCount");
      if (el) el.textContent = `${data.usage_today}/${data.usage_limit || "∞"}`;
    }

    stopPipeline();
    log(`Scan complete — ${S.findings.length} finding(s)`, S.findings.length > 0 ? "warning" : "success");
    showToast(`${S.findings.length} finding(s) — scan complete`, S.findings.length > 0 ? "warning" : "success");

  } catch (err) {
    stopPipeline();
    log(err.message, "error");
    if (err instanceof PlanError) {
      showUpgradeModal("Full AI analysis");
    } else if (err instanceof LimitError) {
      showToast(err.message, "warning");
    } else {
      showToast("Scan failed: " + err.message, "error");
    }
    // Set safe empty report so no stale state
    window.scanReport = buildReport([], null, { source: "failed_scan" });
    window.findings   = window.scanReport.findings;
    S.findings        = [];
  }
};

// Quick AI-only scan alias
window.scan = S.runScan;

// ============================================================
//  REPO SCAN — FIXED: repoUrl scope, plan gate, task polling
// ============================================================
async function scanRepo() {
  if (!canProAccess()) {
    showUpgradeModal("Repo scanning");
    return;
  }

  const repoInput = document.getElementById("repoUrl");
  const repoUrl   = repoInput?.value?.trim();
  if (!repoUrl) { showToast("Enter a GitHub repo URL", "warning"); return; }

  if (!repoUrl.startsWith("https://github.com/")) {
    showToast("Only https://github.com/ URLs supported", "warning");
    return;
  }

  log("Queuing repo scan: " + repoUrl);
  startPipeline();

  // Disable button while scanning
  const repoBtn = document.getElementById("repoScanBtn");
  if (repoBtn) { repoBtn.disabled = true; repoBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Scanning`; }

  try {
    const data = await scanRepoAPI(repoUrl);
    const taskId = data?.task_id || data?.data?.task_id;

    if (!taskId) throw new Error("No task ID returned from server");

    log("Task queued: " + taskId, "success");
    showToast("Repo scan queued · " + taskId, "success");
    pollTaskPro(taskId, repoUrl);          // ← pass repoUrl explicitly
    loadRepoTreePro(repoUrl);

  } catch (err) {
    stopPipeline();
    log("Repo scan failed: " + err.message, "error");
    if (err instanceof PlanError) showUpgradeModal("Repo scanning");
    else showToast("Failed: " + err.message, "error");
  } finally {
    if (repoBtn) {
      repoBtn.disabled = false;
      repoBtn.innerHTML = "Scan";
    }
  }
}

// ============================================================
//  TASK POLLING — FIXED: taskId and repoUrl passed explicitly
// ============================================================
async function pollTaskPro(taskId, repoUrl) {
  const stateMap = { CLONING: 15, VALIDATING: 35, SCANNING: 65, FINALIZING: 90, DONE: 100, FAILED: 0 };
  const bar  = document.getElementById("scanProgressBar");
  const text = document.getElementById("scanProgressText");
  const pct  = document.getElementById("scanPct");

  showProgress();
  let attempts = 0;

  const iv = setInterval(async () => {
    attempts++;
    if (attempts > 120) { // 5-min timeout
      clearInterval(iv);
      stopPipeline();
      showToast("Scan timed out — check back later", "warning");
      return;
    }

    try {
      const data = await getTaskStatus(taskId);
      const p = stateMap[data.state] ?? 50;

      if (bar)  bar.style.width = p + "%";
      if (text) text.innerText  = data.message || data.state || "Processing…";
      if (pct)  pct.innerText   = p + "%";

      log((data.message || data.state) + "");

      if (data.state === "DONE") {
        clearInterval(iv);
        S.findings = data.result?.findings || data.findings || [];
        window.findings = S.findings;
        window.scanReport = buildReport(S.findings, null, { source: "repo_scan", repo: repoUrl });

        renderResults(S.findings);
        renderOverview(S.findings);
        renderSeverityBars(S.findings);
        renderHeatmap(S.findings);
        stopPipeline();
        showToast("Repo scan complete!", "success");
        log("Repo scan complete", "success");
      }

      if (data.state === "FAILED") {
        clearInterval(iv);
        stopPipeline();
        log("Scan failed: " + (data.result?.error || "Unknown"), "error");
        showToast("Scan failed: " + (data.result?.error || "Unknown error"), "error");
      }

    } catch (err) {
      console.error("Poll error:", err);
      clearInterval(iv);
      stopPipeline();
      log("Poll error: " + err.message, "error");
    }
  }, 2500);
}

// ============================================================
//  CLEAR
// ============================================================
function clearScan() {
  S.findings = [];
  S.aiResult = null;
  window.findings = [];
  window.aiResult = null;

  const codeEl = document.getElementById("code");
  if (codeEl) codeEl.value = "";

  clearResults();
  renderOverview([]);
  renderSeverityBars([]);
  renderHeatmap([]);
  log("Cleared");
}

function clearResults() {
  const r = document.getElementById("results");
  const a = document.getElementById("aiInsights");
  if (r) r.innerHTML = "";
  if (a) a.innerHTML = "";
}

// ============================================================
//  RENDER FINDINGS — FIXED: takes findings as param
// ============================================================
function renderResults(findings) {
  // Normalize — accept undefined/null/array
  if (!Array.isArray(findings)) findings = S.findings || [];

  const box = document.getElementById("results");
  if (!box) return;

  if (!findings.length) {
    box.innerHTML = `
      <div style="text-align:center;padding:32px 0;color:var(--text-muted);">
        <i class="bi bi-shield-check" style="font-size:32px;color:var(--success);display:block;margin-bottom:10px;"></i>
        <div style="font-family:'Syne',sans-serif;font-size:15px;font-weight:700;color:var(--success);margin-bottom:4px;">All Clear</div>
        <div style="font-size:12px;">No findings to display</div>
      </div>`;
    return;
  }

  const order  = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const sorted = [...findings].sort((a, b) => (order[b.severity] || 0) - (order[a.severity] || 0));

  box.innerHTML = sorted.map((v, i) => {
    const sev        = (v.severity || "LOW").toUpperCase();
    const indClass   = sev === "CRITICAL" ? "ind-critical" : sev === "HIGH" ? "ind-high" : sev === "MEDIUM" ? "ind-medium" : "ind-low";
    const badgeClass = sev === "CRITICAL" ? "sev-critical" : sev === "HIGH" ? "sev-high" : sev === "MEDIUM" ? "sev-medium" : "sev-low";
    const riskPct    = sev === "CRITICAL" ? 95 : sev === "HIGH" ? 75 : sev === "MEDIUM" ? 45 : 20;
    const riskColor  = sev === "CRITICAL" ? "#e879f9" : sev === "HIGH" ? "var(--danger)" : sev === "MEDIUM" ? "var(--warning)" : "var(--success)";

    return `
      <div class="pro-vuln" onclick="toggleProVuln(this,${i})" data-idx="${i}">
        <div class="pro-vuln-header">
          <div class="pro-vuln-indicator ${indClass}"></div>
          <div class="pro-vuln-info">
            <div class="pro-vuln-name">${escHtml(v.title || "Issue")}</div>
            <div class="pro-vuln-path">
              ${v.file   ? `<i class="bi bi-file-code me-1"></i>${escHtml(v.file)}` : ""}
              ${v.line   ? `· line ${v.line}` : ""}
              ${v.source ? `· <span style="color:var(--accent-2);">${escHtml(v.source)}</span>` : ""}
            </div>
          </div>
          <span class="badge-pill ${badgeClass}">${sev}</span>
          <i class="bi bi-chevron-down" style="color:var(--text-faint);font-size:11px;margin-left:4px;transition:transform 0.2s;" id="chev-${i}"></i>
        </div>

        <div class="pro-vuln-body">
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:10px;line-height:1.6;">
            ${escHtml(v.description || "No description provided.")}
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
              ${v.cvss != null ? `<span style="font-size:11px;color:var(--text-muted);">CVSS ${v.cvss}</span>` : ""}
            </div>
          ` : ""}

          <div id="proCVE-${i}" style="margin-top:6px;"></div>

          <button class="btn btn-sm btn-outline-light mt-3"
            onclick="event.stopPropagation();openSideDetail(${i})"
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
//  OVERVIEW METRICS — FIXED: takes findings as param
// ============================================================
function renderOverview(findings) {
  if (!Array.isArray(findings)) findings = S.findings || [];

  const crit  = findings.filter(f => f.severity === "CRITICAL").length;
  const high  = findings.filter(f => f.severity === "HIGH").length;
  const med   = findings.filter(f => f.severity === "MEDIUM").length;
  const score = Math.max(0, 100 - crit * 20 - high * 10 - med * 5);
  const hasCrit = crit > 0 || high > 0;

  setEl("totalIssues",   findings.length || "—");
  setEl("criticalCount", crit || "—");
  setEl("highCount",     high || "—");
  setEl("medCount",      med  || "—");
  setEl("riskScore",     findings.length ? score : "—");

  const statusEl = document.getElementById("statusText");
  if (statusEl) {
    statusEl.textContent = hasCrit ? "Vulnerable" : findings.length ? "At Risk" : "Secure";
    statusEl.className   = "tstat-val " + (hasCrit ? "danger" : findings.length ? "warning" : "success");
  }
}

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// ============================================================
//  SEVERITY BARS — FIXED: takes findings as param
// ============================================================
function renderSeverityBars(findings) {
  if (!Array.isArray(findings)) findings = S.findings || [];

  const total  = findings.length || 1;
  const counts = {
    critical: findings.filter(f => (f.severity || "").toUpperCase() === "CRITICAL").length,
    high:     findings.filter(f => (f.severity || "").toUpperCase() === "HIGH").length,
    medium:   findings.filter(f => (f.severity || "").toUpperCase() === "MEDIUM").length,
    low:      findings.filter(f => (f.severity || "").toUpperCase() === "LOW").length,
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
//  HEATMAP — FIXED: takes findings as param
// ============================================================
function renderHeatmap(findings) {
  if (!Array.isArray(findings)) findings = S.findings || [];

  const map = document.getElementById("heatmap");
  if (!map) return;

  if (!findings.length) { map.innerHTML = ""; return; }

  map.innerHTML = findings.map(v => {
    const sev = (v.severity || "low").toLowerCase();
    return `<div class="heat-cell ${sev}" title="${escHtml(v.title || sev)}"></div>`;
  }).join("");
}

// ============================================================
//  AI PANEL
// ============================================================
function renderAIPanel() {
  const chat = document.getElementById("aiChat");
  if (!chat || !S.aiResult) return;

  const ai  = S.aiResult;
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
  if (!Array.isArray(findings)) return;
  for (let i = 0; i < Math.min(findings.length, 5); i++) {
    const v   = findings[i];
    const box = document.getElementById(`proCVE-${i}`);
    if (!box || !v.title || (v.cve && v.cve !== "N/A")) continue;
    try {
      const res  = await apiRequest(`/api/cve/search?query=${encodeURIComponent(v.title)}`);
      const data = await safeJson(res);
      const cves = data?.cves || [];
      if (cves.length) {
        const top = cves[0];
        box.innerHTML = `
          <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text-muted);margin-top:4px;
                      padding:5px 8px;background:rgba(56,189,248,0.05);border-radius:6px;border:1px solid rgba(56,189,248,0.12);">
            <i class="bi bi-shield-exclamation" style="color:var(--warning);"></i>
            <span style="color:var(--accent-2);">${escHtml(top.id || "")}</span>
            ${top.cvss != null ? `· CVSS <strong>${top.cvss}</strong>` : ""}
            ${top.description ? `· <span style="color:var(--text-faint);">${escHtml(top.description.substring(0, 90))}…</span>` : ""}
          </div>`;
      }
    } catch { /* silent */ }
  }
}

// ============================================================
//  CVE LOOKUP (panel)
// ============================================================
async function fetchCVE() {
  const input = document.getElementById("cveInput")?.value?.trim();
  if (!input) return showToast("Enter a CVE ID or keyword", "warning");

  const panel = document.getElementById("cvePanel");
  if (!panel) return;

  panel.innerHTML = `<div class="skeleton" style="height:60px;border-radius:8px;"></div>`;

  try {
    const res  = await apiRequest(`/api/cve/search?query=${encodeURIComponent(input)}`);
    const data = await safeJson(res);
    const cves = data?.cves || [];

    if (!cves.length) {
      panel.innerHTML = `<div style="color:var(--text-muted);font-size:12px;padding:8px 0;">No CVEs found for "${escHtml(input)}"</div>`;
      return;
    }

    panel.innerHTML = cves.map(cve => `
      <div class="cve-entry">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <strong style="font-size:12px;color:var(--accent-2);">${escHtml(cve.id || "")}</strong>
          <span class="badge-pill sev-${cvssSev(cve.cvss)}">${cve.cvss ?? "N/A"}</span>
        </div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:4px;line-height:1.4;">
          ${escHtml((cve.description || "").substring(0, 200))}
        </div>
      </div>
    `).join("");
  } catch (err) {
    panel.innerHTML = `<div style="color:var(--danger);font-size:12px;">
      <i class="bi bi-exclamation-triangle me-1"></i>${escHtml(err.message)}
    </div>`;
  }
}

// ============================================================
//  AI CHAT
// ============================================================
async function askAI() {
  const q    = document.getElementById("aiInput")?.value?.trim();
  const chat = document.getElementById("aiChat");
  if (!q || !chat) return;

  const userMsg = document.createElement("div");
  userMsg.className = "ai-msg-user";
  userMsg.textContent = q;
  chat.appendChild(userMsg);
  chat.scrollTop = chat.scrollHeight;
  document.getElementById("aiInput").value = "";

  const loading = document.createElement("div");
  loading.className = "ai-msg-bot";
  loading.innerHTML = `<span class="skeleton" style="display:inline-block;width:80px;height:14px;border-radius:4px;"></span>`;
  chat.appendChild(loading);
  chat.scrollTop = chat.scrollHeight;

  try {
    const context = S.currentContext || JSON.stringify(S.findings.slice(0, 3));
    const res  = await apiRequest("/api/ai/explain", {
      method: "POST",
      body: JSON.stringify({ question: q, context })
    });
    const data = await safeJson(res);
    const text = data?.explanation || data?.data?.explanation || "No response";
    loading.innerHTML = `<i class="bi bi-robot me-1" style="color:var(--accent);"></i>${escHtml(text)}`;
  } catch (err) {
    loading.innerHTML = `<span style="color:var(--danger);"><i class="bi bi-exclamation-circle me-1"></i>${escHtml(err.message)}</span>`;
  }
  chat.scrollTop = chat.scrollHeight;
}

// ============================================================
//  TEAM LOADER
// ============================================================
async function loadTeam() {
  const list = document.getElementById("teamList");
  if (!list) return;

  if (!canProAccess()) {
    list.innerHTML = `
      <div style="font-size:11px;color:var(--text-faint);text-align:center;padding:8px 0;">
        <i class="bi bi-lock me-1"></i>Team management requires Pro
      </div>`;
    return;
  }

  try {
    const res  = await apiRequest("/api/org/users");
    const data = await safeJson(res);
    const arr  = Array.isArray(data) ? data : (data?.data || []);

    if (!arr.length) {
      list.innerHTML = `<div style="font-size:11px;color:var(--text-faint);">No team members</div>`;
      return;
    }

    list.innerHTML = arr.map(u => {
      const initials = (u.email || "?").substring(0, 2).toUpperCase();
      return `
        <div class="team-member">
          <div class="team-avatar">${initials}</div>
          <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;">${escHtml(u.email || "—")}</div>
          ${u.role ? `<span class="badge-pill sev-low" style="font-size:9px;">${escHtml(u.role)}</span>` : ""}
        </div>`;
    }).join("");
  } catch {
    list.innerHTML = `<div style="font-size:11px;color:var(--text-faint);">Team unavailable</div>`;
  }
}

// ============================================================
//  REPO FILE TREE
// ============================================================
async function loadRepoTreePro(url) {
  const container = document.getElementById("fileTree");
  if (!container) return;

  container.innerHTML = `<div class="skeleton" style="height:80px;border-radius:6px;"></div>`;

  try {
    const res  = await apiRequest(`/api/repo/tree?repo_url=${encodeURIComponent(url)}`);
    const data = await safeJson(res);
    const nodes = Array.isArray(data) ? data : (data?.data || []);
    container.innerHTML = renderTreePro(nodes) || `<div style="font-size:11px;color:var(--text-faint);">No files found</div>`;
  } catch {
    container.innerHTML = `<div style="font-size:11px;color:var(--text-faint);">Tree unavailable</div>`;
  }
}

function renderTreePro(nodes) {
  if (!Array.isArray(nodes)) return "";
  return nodes.map(n => `
    <div class="ft-item">
      <i class="bi bi-${n.type === "dir" ? "folder2" : "file-code"}"></i>
      <span>${escHtml(n.name)}</span>
    </div>
    ${n.children ? `<div style="padding-left:10px;">${renderTreePro(n.children)}</div>` : ""}
  `).join("");
}

// ============================================================
//  SIDE DRAWER
// ============================================================
function openSideDetail(idx) {
  const list = S.findings.length ? S.findings : (window.findings || []);
  const v    = list[idx];
  if (!v) return;
  S.currentContext = JSON.stringify({
  title: v.title,
  severity: v.severity,
  file: v.file,
  line: v.line
});

  const sev        = (v.severity || "LOW").toUpperCase();
  const badgeClass = sev === "CRITICAL" ? "sev-critical" : sev === "HIGH" ? "sev-high" : sev === "MEDIUM" ? "sev-medium" : "sev-low";

  const title = document.getElementById("sideTitle");
  const sevEl = document.getElementById("sideSev");
  const desc  = document.getElementById("sideDesc");
  const side  = document.getElementById("side");

  if (title) title.textContent = v.title || "Finding";
  if (sevEl) sevEl.innerHTML   = `<span class="badge-pill ${badgeClass}">${sev}</span>`;
  if (desc)  desc.innerHTML = `
    <div class="drawer-section">
      <div class="drawer-section-label">Description</div>
      <div style="font-size:13px;color:var(--text-muted);line-height:1.7;">${escHtml(v.description || "No description.")}</div>
    </div>
    ${v.file ? `
    <div class="drawer-section">
      <div class="drawer-section-label">Location</div>
      <div style="font-size:12px;color:var(--accent-2);">
        <i class="bi bi-file-code me-1"></i>${escHtml(v.file)}${v.line ? ` · line ${v.line}` : ""}
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
        ${v.cvss != null ? `<span style="font-size:12px;color:var(--text-muted);">CVSS: <strong>${v.cvss}</strong></span>` : ""}
      </div>
    </div>` : ""}
    <div class="drawer-section">
      <div class="drawer-section-label">Risk Score</div>
      <div class="risk-bar-track" style="height:8px;">
        <div class="risk-bar-fill" style="
          width:${sev === "CRITICAL" ? 95 : sev === "HIGH" ? 75 : sev === "MEDIUM" ? 45 : 20}%;
          background:${sev === "CRITICAL" ? "#e879f9" : sev === "HIGH" ? "var(--danger)" : sev === "MEDIUM" ? "var(--warning)" : "var(--success)"};
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
  const list = S.findings.length ? S.findings : (window.findings || []);
  const idx  = list.indexOf(v);
  if (idx !== -1) { openSideDetail(idx); return; }
  const side  = document.getElementById("side");
  const title = document.getElementById("sideTitle");
  const desc  = document.getElementById("sideDesc");
  if (title) title.textContent = v.title || "Finding";
  if (desc)  desc.innerHTML    = `<p style="color:var(--text-muted);">${escHtml(v.description || "")}</p>`;
  if (side)  side.classList.add("open");
}

function closeSide() {
  document.getElementById("side")?.classList.remove("open");
}

// ============================================================
//  EXPORT PDF
// ============================================================
async function exportPDF() {
  const report = window.scanReport || buildReport(S.findings, S.aiResult);
  if (!S.findings.length) { showToast("Run a scan first", "warning"); return; }

  try {
    const res  = await apiRequest("/api/report/pdf", {
      method: "POST",
      body: JSON.stringify({ findings: S.findings })
    });
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = "SafeAIScan-Report.pdf"; a.click();
    URL.revokeObjectURL(url);
    showToast("Report exported", "success");
  } catch (err) {
    showToast("Export failed: " + err.message, "error");
  }
}

// ============================================================
//  HELPERS
// ============================================================
function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function cvssSev(score) {
  if (score == null) return "low";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function logout() {
  localStorage.clear();
  window.location.replace("login.html");
}

// ============================================================
//  INIT
// ============================================================
async function initMinisky() {
  log("SafeAIScan Pro initializing…", "info");

  await loadAndApplyPlan();

  await loadTeam();
  renderOverview([]);
  renderSeverityBars([]);

  log("Ready", "success");
}

document.addEventListener("DOMContentLoaded", initMinisky);

// ---- GLOBALS ----
window.runScan        = S.runScan;
window.scan           = S.runScan;
window.scanRepo       = scanRepo;
window.openSide       = openSide;
window.closeSide      = closeSide;
window.openSideDetail = openSideDetail;
window.clearScan      = clearScan;
window.exportPDF      = exportPDF;
window.askAI          = askAI;
window.logout         = logout;
window.fetchCVE       = fetchCVE;
window.toggleProVuln  = toggleProVuln;
window.showUpgradeModal = showUpgradeModal;
