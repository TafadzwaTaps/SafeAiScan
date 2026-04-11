let findings = [];
window.aiResult = null;

// =========================
// LOG TIMELINE
// =========================
function log(msg){
    const el = document.getElementById("timeline");
    if(!el) return;
    const d = document.createElement("div");
    d.className="timeline-item";
    d.innerText=msg;
    el.prepend(d);
}

// =========================
// 🚀 PIPELINE PROGRESS
// =========================
function startPipeline(){
    const steps = [
        "Parsing code...",
        "Running static analysis...",
        "Checking vulnerabilities...",
        "AI risk modeling...",
        "Mapping CVEs...",
        "Finalizing report..."
    ];

    const text = document.getElementById("scanProgressText");
    const bar = document.getElementById("scanProgressBar");

    let i = 0;

    clearInterval(scanProgressInterval);

    scanProgressInterval = setInterval(()=>{
        if(i >= steps.length){
            clearInterval(scanProgressInterval);
            return;
        }

        const percent = ((i+1)/steps.length)*100;

        text.innerText = steps[i];
        bar.style.width = percent + "%";

        i++;
    }, 700);
}

function stopProgress(){
    clearInterval(scanProgressInterval);
    document.getElementById("scanProgressBar").style.width = "100%";
    document.getElementById("scanProgressText").innerText = "Scan Complete";
}

// =========================
// 🔥 MAIN SCAN (FIXED)
// =========================
async function runScan(){
    console.log("🔥 RUN_SCAN STARTED");
    log("Scanning...");
    startPipeline();

    try{
        const data = await analyzeCode(
            document.getElementById("code").value
        );

        console.log("🔥 SCAN RESULT:", data);

        window.aiResult = data.ai || null;

        findings = data.findings || [];

        // ✅ FALLBACK SYSTEM
        if(findings.length === 0){
            if(window.aiResult?.explanation){
                findings = [{
                    title: "AI Detected Issues",
                    description: window.aiResult.explanation,
                    severity: "HIGH",
                    fix: (window.aiResult.fixes || []).join("\n")
                }];
            } else {
                findings = [{
                    title: "No Issues Detected",
                    description: "Scanner found nothing.",
                    severity: "LOW",
                    fix: "N/A"
                }];
            }
        }

        renderOverview(data);
        render();
        renderAI();
        renderHeatmap();

        stopProgress();
        log("Scan complete");

    }catch(e){
        stopProgress();
        log("Error: "+e.message);
    }
}

// =========================
// 📊 OVERVIEW PANEL
// =========================
function renderOverview(data){
    const el = document.getElementById("totalIssues");

    const score = Math.max(0, 100 - findings.length * 10);

    document.getElementById("totalIssues").innerText = findings.length;
    document.getElementById("riskScore").innerText = score;
    document.getElementById("criticalCount").innerText =
        findings.filter(f=>f.severity==="HIGH").length;
}

// =========================
// 🧬 RENDER VULNS
// =========================
function render(){
    const box = document.getElementById("results");
    box.innerHTML="";

    const order = {CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1};

    findings.sort((a,b)=>(order[b.severity]||0)-(order[a.severity]||0));

    findings.forEach(v=>{
        const color =
            v.severity==="HIGH" ? "danger" :
            v.severity==="MEDIUM" ? "warning" :
            "success";

        const div=document.createElement("div");
        div.className="vuln";

        div.innerHTML = `
<div class="d-flex justify-content-between">
    <div>
        <b>${v.title}</b>
        <div class="text-muted small">${v.description}</div>

        ${renderCVEBadges(v)}
    </div>

    <span class="badge bg-${color}">
        ${v.severity}
    </span>
</div>

${renderRiskBar(v)}
`;

        div.onclick=()=>openSide(v);
        box.appendChild(div);
    });
}

// =========================
// 🤖 AI PANEL
// =========================
function renderAI(){
    const box = document.getElementById("aiChat");
    if(!box) return;

    if(!window.aiResult){
        box.innerHTML = "No AI response";
        return;
    }

    box.innerHTML = `
        <div><b>AI Analysis:</b></div>
        <div class="small mb-2">
            ${window.aiResult.explanation}
        </div>

        <ul class="small">
            ${(window.aiResult.fixes||[])
                .map(f=>`<li>${f}</li>`).join("")}
        </ul>
    `;
}

// =========================
// 🔥 HEATMAP
// =========================
function renderHeatmap(){
    const map=document.getElementById("heatmap");
    map.innerHTML="";

    findings.forEach(v=>{
        const c=document.createElement("div");
        c.className="heat-cell " + (v.severity?.toLowerCase() || "low");
        map.appendChild(c);
    });
}

// =========================
// SIDE PANEL
// =========================
function openSide(v){
    document.getElementById("side").classList.add("open");

    document.getElementById("title").innerText=v.title;

    document.getElementById("desc").innerHTML=`
        <p>${v.description}</p>
        <pre>${v.fix}</pre>
    `;
}

function closeSide(){
    document.getElementById("side").classList.remove("open");
}

function renderCVEBadges(v){
    if(!v.cves || v.cves.length === 0){
        return `<div class="text-muted small">No CVEs</div>`;
    }

    return `
        <div class="mt-2 d-flex flex-wrap gap-1">
            ${v.cves.map(cve => `
                <span class="badge ${getCVSSColor(cve.cvss)} border"
                      style="cursor:pointer"
                      onclick="openCVE('${cve.id}')">
                    🧬 ${cve.id}
                </span>
            `).join("")}
        </div>
    `;
}

function openCVE(id){
    const vuln = findings.find(f =>
        f.cves?.some(c => c.id === id)
    );

    const cve = vuln?.cves.find(c => c.id === id);

    if(!cve) return;

    document.getElementById("side").classList.add("open");

    document.getElementById("title").innerText = id;

    document.getElementById("desc").innerHTML = `
        <p><b>CVSS:</b> ${cve.cvss || "N/A"}</p>
        <p>${cve.description}</p>
    `;
}

function renderRiskBar(v){
    const max = Math.max(...(v.cves || []).map(c=>c.score || 0), 0);

    if(max === 0){
        return `<div class="small text-muted">Low risk</div>`;
    }

    const percent = Math.min(100, max);

    const color =
        percent > 70 ? "#ef4444" :
        percent > 40 ? "#f59e0b" :
        "#22c55e";

    return `
        <div class="mt-2">
            <div style="
                height:6px;
                background:#1f2937;
                border-radius:6px;
                overflow:hidden;">
                
                <div style="
                    width:${percent}%;
                    height:100%;
                    background:${color};
                    transition:0.3s;">
                </div>
            </div>

            <div class="small text-muted">
                Exploit Risk: ${Math.round(percent)}%
            </div>
        </div>
    `;
}

function getCVSSColor(score){
    if(!score) return "bg-secondary";
    if(score >= 9) return "bg-danger";
    if(score >= 7) return "bg-warning";
    if(score >= 4) return "bg-info";
    return "bg-success";
}

window.runScan = runScan;
window.openSide = openSide;
window.closeSide = closeSide;