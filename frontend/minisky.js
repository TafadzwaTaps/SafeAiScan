// ============================================================
//  SafeAIScan Pro — Minisky Scanner Engine v3.0
//
//  FIXES APPLIED:
//  [1] PlanError/LimitError declared ONCE — guard prevents re-declaration
//  [2] runScan bound to window AFTER definition — no more "not defined"
//  [3] All functions scoped inside SafeAIScan namespace (S.*) or hoisted
//       before use — no more undefined renderResults / clearResults
//  [4] DEV_MODE global toggle — true = full enterprise access,
//       false = dashboard + basic scan only, upgrade modal on blocked features
//  [5] getUserPlan() is the SOLE authority on plan — decoupled from UI
//  [6] Initialization guard — initMinisky() runs exactly once
//  [7] All async calls wrapped in try/catch — app never crashes
//  [8] onclick attributes replaced with addEventListener bindings
//  [9] canProAccess() / canEnterpriseAccess() use getUserPlan() exclusively
//  [10] applyPlanGating() rebuilt around DEV_MODE-aware getUserPlan()
// ============================================================

// ============================================================
//  DEV MODE — false in production; set window.DEV_MODE = true BEFORE
//  loading this script to unlock all features during testing.
// ============================================================
window.DEV_MODE = window.DEV_MODE !== undefined ? window.DEV_MODE : false;

// ============================================================
//  ERROR CLASSES — declared exactly once, guarded
// ============================================================
(function defineErrors() {
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
})();

// ============================================================
//  NAMESPACE — single global object, safe to re-include
// ============================================================
window.SafeAIScan = window.SafeAIScan || {};
const S = window.SafeAIScan;

// ---- STATE (initialize only if not already set) ----
S.findings            = S.findings            || [];
S.aiResult            = S.aiResult            || null;
S.currentContext      = S.currentContext      || "";
S.scanProgressInterval= S.scanProgressInterval|| null;
S.userPlan            = S.userPlan            || localStorage.getItem("user_plan") || "free";
S.userEmail           = S.userEmail           || localStorage.getItem("user_email") || "";
S.userLimits          = S.userLimits          || null;

// ============================================================
//  PLAN — single source of truth
// ============================================================
S.getUserPlan = function () {
  if (window.DEV_MODE) return "enterprise";
  return (S.userPlan || localStorage.getItem("user_plan") || "free").toLowerCase();
};

function canProAccess() {
  return ["pro", "enterprise"].includes(S.getUserPlan());
}

function canEnterpriseAccess() {
  return S.getUserPlan() === "enterprise";
}

function canAccessFeature(feature) {
  if (window.DEV_MODE) return true;
  const plan = S.getUserPlan();
  const featureMap = {
    repo_scan:       ["pro", "enterprise"],
    advanced_ai:     ["pro", "enterprise"],
    cve_enrichment:  ["pro", "enterprise"],
    team:            ["enterprise"],
    audit_logs:      ["enterprise"],
    api_access:      ["enterprise"],
  };
  return (featureMap[feature] || []).includes(plan);
}

// ============================================================
//  PLAN LOAD — syncs from /api/me on init
// ============================================================
async function loadAndApplyPlan() {
  try {
    const res   = await apiRequest("/api/me");
    const data  = await safeJson(res);
    const plan   = (data?.plan || data?.data?.plan || "free").toLowerCase();
    const email  = data?.email  || data?.data?.email  || "";
    const limits = data?.limits || data?.data?.limits || {};

    S.userPlan   = plan;
    S.userEmail  = email;
    S.userLimits = limits;

    localStorage.setItem("user_plan",   plan);
    localStorage.setItem("user_email",  email);
    localStorage.setItem("user_limits", JSON.stringify(limits));

  } catch (err) {
    console.warn("[SafeAIScan] Plan load failed, using cached:", S.userPlan);
  }

  // Always apply gating regardless of fetch outcome
  applyPlanGating();
  updatePlanBadge();
}

function updatePlanBadge() {
  const planBadge = document.getElementById("planBadge");
  if (!planBadge) return;

  const plan = S.getUserPlan();
  const labels = { free: "FREE", pro: "PRO", enterprise: "ENTERPRISE" };
  const colors  = {
    free:       "background:rgba(52,211,153,0.15);color:#6ee7b7;border:1px solid rgba(52,211,153,0.3);",
    pro:        "background:linear-gradient(135deg,rgba(91,123,254,0.25),rgba(192,38,211,0.2));color:#a5b4fc;border:1px solid rgba(91,123,254,0.35);",
    enterprise: "background:linear-gradient(135deg,rgba(192,38,211,0.25),rgba(244,63,94,0.2));color:#e879f9;border:1px solid rgba(192,38,211,0.4);"
  };
  planBadge.textContent   = labels[plan] || plan.toUpperCase();
  planBadge.style.cssText += colors[plan] || colors.free;
}

function applyPlanGating() {
  const isPro = canProAccess();
  const repoBtn = document.getElementById("repoScanBtn");

  if (repoBtn) {
    // Store original HTML once
    if (!repoBtn.dataset.originalHtml) {
      repoBtn.dataset.originalHtml = repoBtn.innerHTML;
    }

    // Remove any previously attached clone (avoid stacking listeners)
    const oldClone = document.getElementById("repoScanBtnGated");
    if (oldClone) oldClone.remove();

    if (!isPro) {
      repoBtn.innerHTML = `<i class="bi bi-lock me-1"></i>Scan <span style="font-size:9px;opacity:0.7;">(Pro)</span>`;
      // Replace with a clone to strip existing event listeners, then re-add
      const gated = repoBtn.cloneNode(true);
      gated.id = "repoScanBtnGated";
      repoBtn.replaceWith(gated);
      gated.addEventListener("click", (e) => {
        e.preventDefault();
        showUpgradeModal("Repo scanning");
      });
    } else {
      repoBtn.innerHTML = repoBtn.dataset.originalHtml;
      const unlocked = repoBtn.cloneNode(true);
      repoBtn.replaceWith(unlocked);
      unlocked.addEventListener("click", scanRepo);
    }
  }

  // Hide upgrade banner for paid plans
  const upgradeBanner = document.getElementById("upgradeBanner");
  if (upgradeBanner) {
    upgradeBanner.style.display = isPro ? "none" : "";
  }

  // Gate feature sections that should be hidden for free users
  const gatedSections = document.querySelectorAll("[data-feature-gate]");
  gatedSections.forEach(section => {
    const feature = section.dataset.featureGate;
    section.style.display = canAccessFeature(feature) ? "" : "none";
  });
}

// ============================================================
//  UPGRADE MODAL
// ============================================================
function showUpgradeModal(featureName = "this feature") {
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
      <div style="
        background:linear-gradient(135deg,rgba(91,123,254,0.15),rgba(192,38,211,0.1));
        border-bottom:1px solid var(--border);padding:24px 28px 20px;
      ">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
          <div style="font-family:'Syne',sans-serif;font-size:20px;font-weight:800;letter-spacing:-0.03em;">
            <i class="bi bi-lightning-charge" style="color:var(--warning);margin-right:8px;"></i>Upgrade Required
          </div>
          <button id="upgradeModalClose" style="
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

      <div style="padding:20px 28px;">
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:20px;">

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
            <div style="font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:var(--text-primary);">$8.99</div>
            <div style="font-size:10px;color:var(--text-faint);margin-bottom:12px;">/month</div>
            <div style="font-size:11px;color:var(--text-muted);text-align:left;display:flex;flex-direction:column;gap:5px;">
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>100 scans/day</div>
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>Repo scanning</div>
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>Deep AI analysis</div>
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>CVE enrichment</div>
              <div><i class="bi bi-check2 me-1" style="color:var(--success);"></i>REST API access</div>
            </div>
          </div>

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

        <div style="display:flex;gap:10px;">
          <button id="upgradeModalPro" style="
            flex:1;background:linear-gradient(135deg,#5b7bfe,#4361ee);color:#fff;border:none;
            padding:12px;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;
            font-family:'DM Sans',sans-serif;">
            <i class="bi bi-lightning-charge me-1"></i>Upgrade to Pro
          </button>
          <button id="upgradeModalEnt" style="
            flex:1;background:transparent;color:var(--text-muted);border:1px solid var(--border);
            padding:12px;border-radius:10px;font-size:13px;cursor:pointer;
            font-family:'DM Sans',sans-serif;">
            <i class="bi bi-building me-1"></i>Enterprise Demo
          </button>
        </div>

        <div style="text-align:center;margin-top:12px;">
          <button id="upgradeModalLater" style="
            background:none;border:none;color:var(--text-faint);font-size:12px;
            cursor:pointer;font-family:'DM Sans',sans-serif;">
            Maybe later
          </button>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  // Bind close buttons via addEventListener — no inline onclick
  modal.addEventListener("click", e => { if (e.target === modal) modal.remove(); });
  document.getElementById("upgradeModalClose")?.addEventListener("click", () => modal.remove());
  document.getElementById("upgradeModalLater")?.addEventListener("click", () => modal.remove());
  document.getElementById("upgradeModalPro")?.addEventListener("click", () => { window.location.href = "pricing.html"; });
  document.getElementById("upgradeModalEnt")?.addEventListener("click", () => { window.location.href = "enterprise.html"; });
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

  let stage    = 0;
  let progress = 0;

  clearInterval(S.scanProgressInterval);
  S.scanProgressInterval = setInterval(() => {
    if (stage >= STAGES.length) return;
    const target = STAGES[stage].pct;
    progress += (target - progress) * 0.2;
    if (bar)  bar.style.width = progress + "%";
    if (pct)  pct.innerText   = Math.round(progress) + "%";
    if (text) text.innerText  = STAGES[stage].label;

    STAGES.forEach((s, i) => {
      const el = document.getElementById(s.id);
      if (!el) return;
      if (i < stage)      { el.classList.remove("active"); el.classList.add("done"); }
      else if (i === stage){ el.classList.add("active"); el.classList.remove("done"); }
      else                 { el.classList.remove("active", "done"); }
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
  (findings || []).forEach(f => {
    const s = (f.severity || "LOW").toUpperCase();
    severityCount[s] = (severityCount[s] || 0) + 1;
  });

  const riskScore = Math.max(0,
    100 - severityCount.CRITICAL * 25 - severityCount.HIGH * 12 - severityCount.MEDIUM * 5
  );

  return {
    meta: { timestamp: new Date().toISOString(), source: meta.source || "code_scan", repo: meta.repo || null },
    summary: {
      total: (findings || []).length,
      severityCount,
      riskScore,
      status: severityCount.CRITICAL > 0 ? "CRITICAL"
             : severityCount.HIGH > 0 ? "HIGH_RISK"
             : (findings || []).length > 0 ? "MODERATE" : "CLEAN"
    },
    ai: aiResult || { explanation: "No AI analysis available", fixes: [] },
    findings: (findings || []).length > 0 ? findings : [{
      title: "No Issues Detected",
      description: "Static + AI scan found no vulnerabilities.",
      severity: "LOW",
      fix: "No action required"
    }]
  };
}

// ============================================================
//  CLEAR HELPERS — defined before runScan uses them
// ============================================================
function clearResults() {
  const r = document.getElementById("results");
  const a = document.getElementById("aiInsights");
  if (r) r.innerHTML = "";
  if (a) a.innerHTML = "";
}

function clearScan() {
  S.findings      = [];
  S.aiResult      = null;
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

// ============================================================
//  MAIN SCAN — Full static + AI pipeline (Pro)
// ============================================================
async function runScan() {
  const code = document.getElementById("code")?.value?.trim();
  if (!code) { showToast("Paste some code to scan", "warning"); return; }

  log("Starting full scan…");
  startPipeline();
  clearResults();

  // Mark AI Only button as inactive
  const aiOnlyBtn = document.getElementById("aiOnlyBtn");
  const scanBtn   = document.getElementById("scanBtn");
  if (scanBtn)   { scanBtn.disabled = true;   scanBtn.innerHTML   = `<span class="spinner-border spinner-border-sm me-1"></span>Scanning…`; }
  if (aiOnlyBtn) { aiOnlyBtn.disabled = true; }

  try {
    const data = await analyzeCode(code);

    S.aiResult = data.ai || null;
    S.findings = data.findings || [];

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
    window.findings   = S.findings;
    window.aiResult   = S.aiResult;
    window.scanReport = report;

    renderResults(S.findings);
    renderOverview(S.findings);
    renderSeverityBars(S.findings);
    renderHeatmap(S.findings);
    renderAIPanel();

    // CVE enrichment — gated to pro/enterprise
    if (canAccessFeature("cve_enrichment")) {
      enrichCVEPro(S.findings);
    }

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
    if (err instanceof window.PlanError) {
      showUpgradeModal("Full scan");
    } else if (err instanceof window.LimitError) {
      showToast(err.message, "warning");
    } else {
      showToast("Scan failed: " + err.message, "error");
    }
    window.scanReport = buildReport([], null, { source: "failed_scan" });
    window.findings   = [];
    S.findings        = [];
  } finally {
    if (scanBtn)   { scanBtn.disabled   = false; scanBtn.innerHTML   = `<i class="bi bi-play-circle-fill me-2"></i>Run Full Scan`; }
    if (aiOnlyBtn) { aiOnlyBtn.disabled = false; }
  }
}

// Alias on S for internal use
S.runScan = runScan;

// ============================================================
//  AI-ONLY SCAN — Pro deep analysis mode, richer output
// ============================================================
async function runAIScan() {
  const code = document.getElementById("code")?.value?.trim();
  if (!code) { showToast("Paste some code for AI analysis", "warning"); return; }

  // AI-only is a Pro feature
  if (!canAccessFeature("advanced_ai")) {
    showUpgradeModal("AI-Only deep analysis");
    return;
  }

  log("Starting AI-only deep analysis…", "info");
  startPipeline();
  clearResults();

  const aiOnlyBtn = document.getElementById("aiOnlyBtn");
  const scanBtn   = document.getElementById("scanBtn");
  if (aiOnlyBtn) { aiOnlyBtn.disabled = true;  aiOnlyBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Analyzing…`; }
  if (scanBtn)   { scanBtn.disabled   = true; }

  try {
    // Use the analyze endpoint but signal AI-only mode for deeper output
    const res = await apiRequest("/api/analyze", {
      method: "POST",
      body: JSON.stringify({ text: code, mode: "ai_only", depth: "full" })
    });
    const data = await safeJson(res);

    S.aiResult = data.ai || null;
    // In AI-only mode we trust the AI findings exclusively
    S.findings = data.findings || [];

    // Build rich AI findings from explanation if no structured findings returned
    if (!S.findings.length && S.aiResult) {
      const ai = S.aiResult;
      // Parse fixes array into individual findings for richer display
      const fixes = ai.fixes || [];
      if (fixes.length > 0) {
        S.findings = fixes.map((fix, i) => ({
          title:       `AI Finding #${i + 1}`,
          description: fix,
          severity:    i === 0 ? "HIGH" : "MEDIUM",
          fix:         "See AI recommendation above",
          source:      "ai_deep"
        }));
      } else if (ai.explanation) {
        S.findings = [{
          title:       "AI Security Analysis",
          description: ai.explanation,
          severity:    "HIGH",
          fix:         "Review the AI analysis for remediation guidance",
          source:      "ai_deep"
        }];
      }
    }

    const report = buildReport(S.findings, S.aiResult, { source: "ai_only" });
    window.findings   = S.findings;
    window.aiResult   = S.aiResult;
    window.scanReport = report;

    renderResults(S.findings);
    renderOverview(S.findings);
    renderSeverityBars(S.findings);
    renderHeatmap(S.findings);
    renderAIPanelDeep(data); // Richer AI panel for Pro users

    // CVE enrichment on AI findings — also gated
    if (canAccessFeature("cve_enrichment")) {
      enrichCVEPro(S.findings);
    }

    stopPipeline();
    log(`AI analysis complete — ${S.findings.length} finding(s)`, S.findings.length > 0 ? "warning" : "success");
    showToast(`AI deep analysis done — ${S.findings.length} issue(s)`, S.findings.length > 0 ? "warning" : "success");

  } catch (err) {
    stopPipeline();
    log(err.message, "error");
    if (err instanceof window.PlanError) {
      showUpgradeModal("AI-Only deep analysis");
    } else if (err instanceof window.LimitError) {
      showToast(err.message, "warning");
    } else {
      showToast("AI analysis failed: " + err.message, "error");
    }
    S.findings = [];
    window.findings = [];
  } finally {
    if (aiOnlyBtn) { aiOnlyBtn.disabled = false; aiOnlyBtn.innerHTML = `<i class="bi bi-cpu me-1"></i>AI Only`; }
    if (scanBtn)   { scanBtn.disabled   = false; }
  }
}

// ============================================================
//  RICH AI PANEL — Pro mode with full detail breakdown
// ============================================================
function renderAIPanelDeep(data) {
  const chat = document.getElementById("aiChat");
  if (!chat) return;

  const ai = data.ai || S.aiResult;
  if (!ai) return;

  // Clear previous
  chat.innerHTML = "";

  // Header message
  const header = document.createElement("div");
  header.className = "ai-msg-bot";
  header.innerHTML = `
    <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px;">
      <i class="bi bi-cpu-fill" style="color:var(--accent);font-size:16px;"></i>
      <strong style="font-size:13px;color:var(--text-primary);">Deep AI Security Analysis</strong>
      <span style="font-size:9px;padding:2px 7px;border-radius:99px;background:linear-gradient(135deg,rgba(91,123,254,0.25),rgba(192,38,211,0.2));color:#a5b4fc;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;">Pro</span>
    </div>
    <div style="font-size:13px;color:var(--text-muted);line-height:1.7;margin-bottom:10px;">
      ${escHtml(ai.explanation || "Analysis complete.")}
    </div>
    ${ai.risk_summary ? `
      <div style="background:rgba(244,63,94,0.08);border:1px solid rgba(244,63,94,0.2);border-radius:8px;padding:10px 12px;margin-bottom:10px;">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;color:var(--danger);margin-bottom:4px;font-weight:700;">Risk Summary</div>
        <div style="font-size:12px;color:var(--text-muted);line-height:1.6;">${escHtml(ai.risk_summary)}</div>
      </div>` : ""}
    ${ai.fixes && ai.fixes.length ? `
      <div style="margin-top:10px;">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;color:var(--accent);margin-bottom:8px;font-weight:700;">
          <i class="bi bi-wrench-adjustable me-1"></i>Recommended Fixes
        </div>
        ${ai.fixes.map((fix, i) => `
          <div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:8px;padding:8px 10px;
                      background:rgba(91,123,254,0.06);border-radius:8px;border-left:3px solid var(--accent);">
            <span style="background:var(--accent);color:#fff;font-size:10px;font-weight:700;border-radius:50%;
                         width:18px;height:18px;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px;">${i+1}</span>
            <span style="font-size:12px;color:var(--text-muted);line-height:1.6;">${escHtml(fix)}</span>
          </div>`).join("")}
      </div>` : ""}
    ${ai.severity_prediction ? `
      <div style="margin-top:8px;display:flex;align-items:center;gap:8px;font-size:11px;color:var(--text-muted);">
        <i class="bi bi-shield-exclamation" style="color:var(--warning);"></i>
        Predicted severity: <strong style="color:var(--warning);">${escHtml(ai.severity_prediction)}</strong>
      </div>` : ""}
  `;
  chat.appendChild(header);

  // Compliance note if available
  if (data.compliance || ai.compliance) {
    const comp = data.compliance || ai.compliance;
    const compMsg = document.createElement("div");
    compMsg.className = "ai-msg-bot";
    compMsg.innerHTML = `
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.8px;color:#e879f9;margin-bottom:6px;font-weight:700;">
        <i class="bi bi-clipboard-check me-1"></i>Compliance Impact
      </div>
      <div style="font-size:12px;color:var(--text-muted);line-height:1.6;">${escHtml(typeof comp === "string" ? comp : JSON.stringify(comp))}</div>
    `;
    chat.appendChild(compMsg);
  }

  // Prompt to ask follow-up
  const hint = document.createElement("div");
  hint.className = "ai-msg-bot";
  hint.style.cssText = "color:var(--text-faint);font-size:11px;border:1px dashed var(--border);background:transparent;";
  hint.innerHTML = `<i class="bi bi-chat-dots me-1" style="color:var(--accent);"></i>Ask me anything about these findings below…`;
  chat.appendChild(hint);

  chat.scrollTop = chat.scrollHeight;
}

// ============================================================
//  REPO SCAN — plan-gated
// ============================================================
async function scanRepo() {
  if (!canAccessFeature("repo_scan")) {
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

  const repoBtn = document.getElementById("repoScanBtn") || document.getElementById("repoScanBtnGated");
  if (repoBtn) {
    repoBtn.disabled = true;
    repoBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Scanning`;
  }

  try {
    const data   = await scanRepoAPI(repoUrl);
    const taskId = data?.task_id || data?.data?.task_id;

    if (!taskId) throw new Error("No task ID returned from server");

    log("Task queued: " + taskId, "success");
    showToast("Repo scan queued · " + taskId, "success");
    pollTaskPro(taskId, repoUrl);
    loadRepoTreePro(repoUrl);

  } catch (err) {
    stopPipeline();
    log("Repo scan failed: " + err.message, "error");
    if (err instanceof window.PlanError) showUpgradeModal("Repo scanning");
    else showToast("Failed: " + err.message, "error");
  } finally {
    if (repoBtn) {
      repoBtn.disabled = false;
      repoBtn.innerHTML = "Scan";
    }
  }
}

// ============================================================
//  TASK POLLING
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
    if (attempts > 120) {
      clearInterval(iv);
      stopPipeline();
      showToast("Scan timed out — check back later", "warning");
      return;
    }

    try {
      const data = await getTaskStatus(taskId);
      const p    = stateMap[data.state] ?? 50;

      if (bar)  bar.style.width = p + "%";
      if (text) text.innerText  = data.message || data.state || "Processing…";
      if (pct)  pct.innerText   = p + "%";

      log((data.message || data.state) + "");

      if (data.state === "DONE") {
        clearInterval(iv);
        S.findings      = data.result?.findings || data.findings || [];
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
      console.error("[SafeAIScan] Poll error:", err);
      clearInterval(iv);
      stopPipeline();
      log("Poll error: " + err.message, "error");
    }
  }, 2500);
}

// ============================================================
//  RENDER FINDINGS
// ============================================================
function renderResults(findings) {
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
      <div class="pro-vuln" data-idx="${i}">
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

          <button class="btn btn-sm btn-outline-light mt-3 view-detail-btn" data-idx="${i}"
            style="font-size:11px;">
            <i class="bi bi-arrows-fullscreen me-1"></i>View Full Detail
          </button>
        </div>
      </div>
    `;
  }).join("");

  // Attach event listeners after render — no inline onclick
  box.querySelectorAll(".pro-vuln").forEach(card => {
    card.addEventListener("click", function (e) {
      if (e.target.closest(".view-detail-btn")) return; // handled separately
      toggleProVuln(this, parseInt(this.dataset.idx, 10));
    });
  });
  box.querySelectorAll(".view-detail-btn").forEach(btn => {
    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      openSideDetail(parseInt(this.dataset.idx, 10));
    });
  });
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
//  SEVERITY BARS
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
//  HEATMAP
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
//  CVE ENRICHMENT — plan gated
// ============================================================
async function enrichCVEPro(findings) {
  if (!Array.isArray(findings)) return;
  if (!canAccessFeature("cve_enrichment")) return;

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
    } catch { /* silent fail — never crash */ }
  }
}

// ============================================================
//  CVE LOOKUP (panel)
// ============================================================
async function fetchCVE() {
  if (!canAccessFeature("cve_enrichment")) {
    showUpgradeModal("CVE enrichment");
    return;
  }

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
  if (!canAccessFeature("advanced_ai")) {
    showUpgradeModal("Full AI chat");
    return;
  }

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
//  TEAM LOADER — plan gated
// ============================================================
async function loadTeam() {
  const list = document.getElementById("teamList");
  if (!list) return;

  if (!canAccessFeature("team")) {
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
    const res   = await apiRequest(`/api/repo/tree?repo_url=${encodeURIComponent(url)}`);
    const data  = await safeJson(res);
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
//  TOAST NOTIFICATIONS
// ============================================================
function showToast(message, type = "info") {
  const colors = {
    info:    "rgba(91,123,254,0.15)",
    success: "rgba(52,211,153,0.12)",
    warning: "rgba(251,146,60,0.12)",
    error:   "rgba(244,63,94,0.12)"
  };
  const textColors = { info: "#93aaff", success: "#6ee7b7", warning: "#fdba74", error: "#fb7185" };
  const icons      = { info: "bi-info-circle", success: "bi-check-circle", warning: "bi-exclamation-triangle", error: "bi-x-circle" };

  if (!document.querySelector("#toastStyle")) {
    const s = document.createElement("style");
    s.id = "toastStyle";
    s.textContent = `
      @keyframes toastIn  { from { opacity:0;transform:translateY(12px) scale(0.95); } to { opacity:1;transform:translateY(0) scale(1); } }
      @keyframes toastOut { from { opacity:1;transform:scale(1); } to { opacity:0;transform:translateY(6px) scale(0.95); } }
      .toast-container { position:fixed;bottom:20px;right:20px;z-index:99999;display:flex;flex-direction:column;gap:8px;align-items:flex-end; }
    `;
    document.head.appendChild(s);
  }

  let container = document.querySelector(".toast-container");
  if (!container) {
    container = document.createElement("div");
    container.className = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.style.cssText = `
    background:${colors[type] || colors.info};
    color:${textColors[type] || textColors.info};
    border:1px solid ${textColors[type] || textColors.info}33;
    border-radius:10px;padding:11px 16px;font-size:13px;
    font-family:'DM Sans',sans-serif;font-weight:500;
    backdrop-filter:blur(12px);
    box-shadow:0 8px 32px rgba(0,0,0,0.4);
    animation:toastIn 0.25s ease both;
    max-width:320px;display:flex;align-items:center;gap:8px;cursor:pointer;
  `;
  toast.innerHTML = `<i class="bi ${icons[type] || icons.info}" style="flex-shrink:0;font-size:14px;"></i><span>${escHtml(message)}</span>`;

  const dismiss = () => {
    toast.style.animation = "toastOut 0.22s ease forwards";
    setTimeout(() => toast.remove(), 230);
  };
  toast.addEventListener("click", dismiss);
  container.appendChild(toast);
  setTimeout(dismiss, 3800);
}

// ============================================================
//  UNHANDLED REJECTION HANDLER
// ============================================================
window.addEventListener("unhandledrejection", e => {
  if (e.reason instanceof window.PlanError) {
    showUpgradeModal(e.reason.message);
    e.preventDefault();
  } else if (e.reason instanceof window.LimitError) {
    showToast(e.reason.message, "warning");
    e.preventDefault();
  } else {
    console.error("[SafeAIScan] Unhandled rejection:", e.reason);
  }
});

// ============================================================
//  INIT — runs ONCE, guarded
// ============================================================
async function initMinisky() {
  if (window.SafeAIScanInitialized) return;
  window.SafeAIScanInitialized = true;

  log("SafeAIScan Pro initializing…", "info");

  if (window.DEV_MODE) {
    log("⚠ DEV MODE — enterprise access unlocked", "warning");
  }

  await loadAndApplyPlan();
  await loadTeam();
  renderOverview([]);
  renderSeverityBars([]);

  // Bind scan button via addEventListener — not inline onclick
  const scanBtn = document.getElementById("scanBtn");
  if (scanBtn) scanBtn.addEventListener("click", runScan);

  // AI Only button triggers dedicated deep-AI scan (Pro)
  const aiOnlyBtn = document.getElementById("aiOnlyBtn");
  if (aiOnlyBtn) aiOnlyBtn.addEventListener("click", runAIScan);

  // Bind clear button
  const clearBtn = document.getElementById("clearBtn");
  if (clearBtn) clearBtn.addEventListener("click", clearScan);

  // Export PDF
  const exportPdfBtn = document.getElementById("exportPdfBtn");
  if (exportPdfBtn) exportPdfBtn.addEventListener("click", exportPDF);

  // Logout
  const logoutBtn = document.getElementById("logoutBtn");
  if (logoutBtn) logoutBtn.addEventListener("click", logout);

  // Upgrade banner button
  const upgradeBannerBtn = document.getElementById("upgradeBannerBtn");
  if (upgradeBannerBtn) upgradeBannerBtn.addEventListener("click", () => showUpgradeModal("Pro features"));

  // CVE search button
  const cveSearchBtn = document.getElementById("cveSearchBtn");
  if (cveSearchBtn) cveSearchBtn.addEventListener("click", fetchCVE);

  // AI send button
  const aiSendBtn = document.getElementById("aiSendBtn");
  if (aiSendBtn) aiSendBtn.addEventListener("click", askAI);

  // Bind AI input Enter key
  const aiInput = document.getElementById("aiInput");
  if (aiInput) aiInput.addEventListener("keydown", e => { if (e.key === "Enter") askAI(); });

  // Bind CVE search Enter key
  const cveInput = document.getElementById("cveInput");
  if (cveInput) cveInput.addEventListener("keydown", e => { if (e.key === "Enter") fetchCVE(); });

  // Bind side drawer close
  const sideClose = document.getElementById("sideClose");
  if (sideClose) sideClose.addEventListener("click", closeSide);

  log("Ready", "success");
}

// ============================================================
//  GLOBAL BINDINGS — defined AFTER all functions, bound once
// ============================================================
window.runScan          = runScan;
window.runAIScan        = runAIScan;         // AI-only deep scan
window.scan             = runScan;           // alias
window.scanRepo         = scanRepo;
window.clearScan        = clearScan;
window.openSide         = openSide;
window.closeSide        = closeSide;
window.openSideDetail   = openSideDetail;
window.exportPDF        = exportPDF;
window.askAI            = askAI;
window.logout           = logout;
window.fetchCVE         = fetchCVE;
window.toggleProVuln    = toggleProVuln;
window.showUpgradeModal = showUpgradeModal;
window.showToast        = showToast;

// Expose S.runScan as well (for backwards compat)
S.runScan = runScan;

// ============================================================
//  BOOT
// ============================================================
document.addEventListener("DOMContentLoaded", initMinisky);
