import os
import uuid
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
from fastapi import FastAPI, Depends, HTTPException, Header, Request, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, validator
from passlib.context import CryptContext
from auth import create_access_token, verify_token
from supabase import create_client
from scanner import safe_clone, validate_repo, full_scan
from github import Github
from fastapi import WebSocket, WebSocketDisconnect
from tasks import run_scan
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
import time

# =========================================================
# LOGGING
# =========================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("safeaiscan")

# =========================================================
# APP
# =========================================================
app = FastAPI(title="SafeAIScan Enterprise SaaS Layer", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://localhost:3000",
        "https://rathious-safeaiscan.hf.space"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# ENV
# =========================================================
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
HF_API_KEY = os.getenv("HF_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
security = HTTPBearer()

# =========================================================
# TIER SYSTEM
# =========================================================
PLAN_LIMITS = {
    "free": {
        "daily_scans": 20,
        "history_limit": 5,
        "repo_scan": False,
        "ai_depth": "basic",
        "api_access": False,
        "team_members": 1,
    },
    "pro": {
        "daily_scans": 200,
        "history_limit": 100,
        "repo_scan": True,
        "ai_depth": "full",
        "api_access": True,
        "team_members": 5,
    },
    "enterprise": {
        "daily_scans": 999999,
        "history_limit": 999999,
        "repo_scan": True,
        "ai_depth": "full",
        "api_access": True,
        "team_members": 999999,
    },
}

def get_plan_limits(plan: str) -> dict:
    return PLAN_LIMITS.get(plan.lower(), PLAN_LIMITS["free"])

def check_plan_access(plan: str, feature: str) -> bool:
    limits = get_plan_limits(plan)
    return bool(limits.get(feature, False))

# =========================================================
# STANDARD RESPONSE HELPERS
# =========================================================
def ok(data=None, **kwargs):
    return {"success": True, "data": data, **kwargs}

def err(message: str, code: int = 400):
    raise HTTPException(status_code=code, detail={"success": False, "error": message})

# =========================================================
# PASSWORD + HASH
# =========================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password[:72])

def verify_password(plain, hashed):
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False

def hash_key(key: str):
    return hashlib.sha256(key.encode()).hexdigest()

# =========================================================
# REQUEST MODELS
# =========================================================
class RegisterRequest(BaseModel):
    email: str
    password: str
    org_name: str

    @validator("email")
    def email_valid(cls, v):
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email address")
        return v.lower().strip()

    @validator("password")
    def password_strong(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @validator("org_name")
    def org_not_empty(cls, v):
        if not v.strip():
            raise ValueError("Organization name is required")
        return v.strip()

class LoginRequest(BaseModel):
    email: str
    password: str

    @validator("email")
    def normalize(cls, v):
        return v.lower().strip()

class AnalyzeRequest(BaseModel):
    text: str

    @validator("text")
    def not_empty(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Code text is required")
        if len(v) > 50000:
            raise ValueError("Input too large (max 50,000 characters)")
        return v

class RepoRequest(BaseModel):
    repo_url: str

    @validator("repo_url")
    def valid_github(cls, v):
        v = v.strip()
        if not v.startswith("https://github.com/"):
            raise ValueError("Only GitHub HTTPS URLs are supported")
        return v

class AIExplainRequest(BaseModel):
    question: str
    context: str

# =========================================================
# REGISTER
# =========================================================
@app.post("/auth/register")
def register(req: RegisterRequest):
    try:
        # Check duplicate email
        existing = supabase.table("users").select("id").eq("email", req.email).execute()
        if existing.data:
            err("Email already registered", 409)

        user_id = str(uuid.uuid4())
        org_id = str(uuid.uuid4())

        logger.info(f"Registering user {req.email}")

        supabase.table("organizations").insert({
            "id": org_id,
            "name": req.org_name
        }).execute()

        password_hash = hash_password(req.password)
        raw_key = f"saas_{uuid.uuid4().hex}"
        api_hash = hash_key(raw_key)

        user_row = {
            "id": user_id,
            "email": req.email,
            "password_hash": password_hash,
            "org_id": org_id,
            "api_key_hash": api_hash,
        }
        try:
            supabase.table("users").insert({
                **user_row,
                "plan": "free",
                "created_at": datetime.now(timezone.utc).isoformat()
            }).execute()
        except Exception:
            supabase.table("users").insert(user_row).execute()

        token = create_access_token({"sub": user_id})

        logger.info(f"Registered: {req.email}")
        return ok({
            "access_token": token,
            "api_key": raw_key,
            "plan": "free"
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Register error: {e}")
        raise HTTPException(500, detail={"success": False, "error": "Registration failed. Please try again."})

# =========================================================
# LOGIN
# =========================================================
@app.post("/auth/login")
def login(req: LoginRequest):
    try:
        user_res = supabase.table("users").select("*").eq("email", req.email).execute()

        if not user_res.data:
            raise HTTPException(401, detail={"success": False, "error": "Invalid credentials"})

        user = user_res.data[0]

        if not verify_password(req.password, user["password_hash"]):
            raise HTTPException(401, detail={"success": False, "error": "Invalid credentials"})

        token = create_access_token({"sub": user["id"]})

        # Regenerate API key if missing
        raw_key = None
        if not user.get("api_key_hash"):
            raw_key = f"saas_{uuid.uuid4().hex}"
            supabase.table("users").update({
                "api_key_hash": hash_key(raw_key)
            }).eq("id", user["id"]).execute()

        logger.info(f"Login: {req.email}")
        return ok({
            "access_token": token,
            "user_id": user["id"],
            "org_id": user.get("org_id"),
            "plan": user.get("plan", "free"),
            "api_key": raw_key  # only on first issue; None otherwise
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(500, detail={"success": False, "error": "Login failed"})

# =========================================================
# AUTH DEPENDENCY
# =========================================================
def get_user(
    authorization: str = Header(None),
    x_api_key: str = Header(None)
):
    if not authorization:
        raise HTTPException(401, detail={"success": False, "error": "Missing authorization"})

    token = authorization.replace("Bearer ", "").strip()
    payload = verify_token(token)

    if not payload:
        raise HTTPException(401, detail={"success": False, "error": "Invalid or expired token"})

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(401, detail={"success": False, "error": "Malformed token"})

    user_res = supabase.table("users").select("*").eq("id", user_id).execute()
    if not user_res.data:
        raise HTTPException(403, detail={"success": False, "error": "User not found"})

    user = user_res.data[0]

    if x_api_key and x_api_key not in ("undefined", "null", ""):
        if user.get("api_key_hash") != hash_key(x_api_key):
            raise HTTPException(403, detail={"success": False, "error": "Invalid API key"})

    org = None
    if user.get("org_id"):
        org_res = supabase.table("organizations").select("*").eq("id", user["org_id"]).execute()
        org = org_res.data[0] if org_res.data else None

    return {"user": user, "org": org}

# =========================================================
# USAGE TRACKING
# =========================================================
def track_usage(user_id: str, org_id: str) -> int:
    today = str(datetime.utcnow().date())
    try:
        record = supabase.table("usage_metrics") \
            .select("*") \
            .eq("user_id", user_id) \
            .eq("date", today) \
            .execute()

        if record.data:
            count = record.data[0]["request_count"] + 1
            supabase.table("usage_metrics").update({
                "request_count": count
            }).eq("id", record.data[0]["id"]).execute()
            return count

        supabase.table("usage_metrics").insert({
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "org_id": org_id,
            "date": today,
            "request_count": 1
        }).execute()
        return 1
    except Exception as e:
        logger.error(f"Usage tracking error: {e}")
        return 1

def check_limit(count: int, plan: str) -> bool:
    limit = get_plan_limits(plan)["daily_scans"]
    return count <= limit

# =========================================================
# VULNERABILITY SCANNER
# =========================================================
def scan_vulnerabilities(text: str) -> list:
    patterns = [
        ("eval(",          "HIGH",     "eval() executes arbitrary code and is highly dangerous with user input."),
        ("exec(",          "HIGH",     "exec() runs dynamic code; avoid with untrusted input."),
        ("os.system(",     "HIGH",     "os.system() can execute shell commands; use subprocess with args instead."),
        ("subprocess.call","MEDIUM",   "subprocess.call with shell=True can lead to shell injection."),
        ("pickle.loads(",  "CRITICAL", "pickle.loads() deserializes untrusted data and can execute arbitrary code."),
        ("__import__(",    "HIGH",     "Dynamic import with __import__ can load malicious modules."),
        ("open(",          "LOW",      "File operations should validate paths to prevent path traversal."),
        ("SELECT *",       "MEDIUM",   "Wildcard SELECT queries may expose sensitive columns; be explicit."),
        ("f\"SELECT",      "HIGH",     "f-string SQL construction is vulnerable to SQL injection; use parameterized queries."),
        ("f'SELECT",       "HIGH",     "f-string SQL construction is vulnerable to SQL injection; use parameterized queries."),
        (".format(request","HIGH",     "String-formatted queries with request data risk SQL injection."),
        ("SECRET",         "MEDIUM",   "Hardcoded secret detected; use environment variables instead."),
        ("PASSWORD",       "MEDIUM",   "Hardcoded password detected; use environment variables instead."),
        ("curl ",          "LOW",      "Direct curl usage in code may allow SSRF; validate URLs."),
        ("wget ",          "LOW",      "wget in code may allow SSRF; validate URLs."),
        ("document.write(","MEDIUM",   "document.write() with user data can lead to XSS."),
        ("innerHTML",      "MEDIUM",   "Setting innerHTML with unsanitized data can lead to XSS."),
        ("dangerouslySetInnerHTML", "HIGH", "React dangerouslySetInnerHTML bypasses XSS protection."),
    ]

    findings = []
    seen = set()

    for pattern, severity, description in patterns:
        if pattern.lower() in text.lower() and pattern not in seen:
            seen.add(pattern)
            findings.append({
                "title": f"Insecure use of `{pattern.strip()}`",
                "match": pattern,
                "severity": severity,
                "description": description,
                "fix": "Review and sanitize input. Consult OWASP guidelines for secure alternatives.",
                "cve": "N/A",
                "cvss": 5.0
            })

    return findings

# =========================================================
# AI ENGINE
# =========================================================
async def ai_enrich(text: str, findings: list, depth: str = "full") -> dict:
    if not HF_API_KEY:
        return {"explanation": "AI analysis unavailable (no API key configured).", "fixes": []}

    if depth == "basic":
        # Free plan: summarize findings without deep analysis
        if findings:
            return {
                "explanation": f"Detected {len(findings)} potential security issue(s). Upgrade to Pro for detailed AI-powered analysis and remediation steps.",
                "fixes": ["Upgrade to Pro for actionable AI fixes"]
            }
        return {"explanation": "No critical issues detected in the submitted code.", "fixes": []}

    def parse_ai_output(content: str):
        issues, fixes = [], []
        try:
            if "FIXES:" in content:
                parts = content.split("FIXES:")
                for line in parts[0].split("\n"):
                    line = line.strip()
                    if line.startswith("-") and len(line) > 2:
                        issues.append(line.lstrip("- ").strip())
                for line in parts[1].split("\n"):
                    line = line.strip()
                    if line.startswith("-") and len(line) > 2:
                        fixes.append(line.lstrip("- ").strip())
                return "\n".join(issues), fixes
            return content.strip(), []
        except Exception as e:
            logger.error(f"AI parse error: {e}")
            return content, []

    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=35) as client:
                res = await client.post(
                    "https://router.huggingface.co/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {HF_API_KEY}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "meta-llama/Meta-Llama-3-8B-Instruct",
                        "messages": [{
                            "role": "user",
                            "content": f"""You are a senior cybersecurity engineer. Analyze the code below for security vulnerabilities.

Known detected issues: {findings}

Respond ONLY with this format:
SECURITY_ISSUES:
- brief issue description (one per line)

FIXES:
- actionable fix (one per line)

If no vulnerabilities: say "No critical vulnerabilities found." under SECURITY_ISSUES and nothing under FIXES.

Code (max 1500 chars):
{text[:1500]}"""
                        }],
                        "temperature": 0.2,
                        "max_tokens": 512
                    }
                )

            if res.status_code != 200:
                logger.warning(f"HF API HTTP {res.status_code}: {res.text[:200]}")
                if attempt == 0:
                    await asyncio.sleep(1)
                    continue
                return {"explanation": "AI service temporarily unavailable.", "fixes": []}

            data = res.json()

            if "choices" in data:
                content = data["choices"][0]["message"]["content"]
                explanation, fixes = parse_ai_output(content)
                return {"explanation": explanation, "fixes": fixes}

            if "error" in data:
                return {"explanation": str(data["error"])[:200], "fixes": []}

            return {"explanation": str(data)[:200], "fixes": []}

        except httpx.TimeoutException:
            logger.warning(f"AI timeout attempt {attempt + 1}")
            if attempt == 0:
                import asyncio
                await asyncio.sleep(1.5)
                continue
            return {"explanation": "AI analysis timed out. Static scan results are still accurate.", "fixes": []}
        except Exception as e:
            logger.error(f"AI error: {e}")
            return {"explanation": "AI analysis failed. Static scan results are still accurate.", "fixes": []}

    return {"explanation": "AI unavailable after retries.", "fixes": []}

# =========================================================
# /api/analyze — MAIN SCAN ENDPOINT
# =========================================================
@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, auth=Depends(get_user)):
    try:
        user = auth["user"]
        org = auth.get("org")
        plan = user.get("plan", "free").lower()
        org_id = org["id"] if org else user["id"]

        usage_count = track_usage(user["id"], org_id)

        if not check_limit(usage_count, plan):
            limits = get_plan_limits(plan)
            err(
                f"Daily scan limit reached ({limits['daily_scans']} scans/day on {plan.upper()} plan). Upgrade to continue.",
                429
            )

        findings = scan_vulnerabilities(req.text)
        ai_depth = get_plan_limits(plan)["ai_depth"]
        ai = await ai_enrich(req.text, findings, depth=ai_depth)

        # Risk scoring
        sev_scores = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3}
        score = min(100, sum(sev_scores.get(f.get("severity", "LOW"), 3) for f in findings))

        critical_count = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
        risk = "CRITICAL" if critical_count >= 3 else "HIGH" if critical_count >= 1 else "MEDIUM" if findings else "LOW"

        analysis_id = str(uuid.uuid4())
        try:
            supabase.table("analysis_history").insert({
                "id": analysis_id,
                "user_id": user["id"],
                "org_id": org_id,
                "input_text": req.text[:500],  # truncate for storage
                "risk": risk,
                "score": score,
                "findings_count": len(findings),
                "explanation": ai.get("explanation", "")[:1000],
                "fixes": ai.get("fixes", []),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }).execute()
        except Exception as db_err:
            logger.warning(f"History insert failed (non-fatal): {db_err}")

        limits = get_plan_limits(plan)
        logger.info(f"Scan: user={user['id']} plan={plan} findings={len(findings)} usage={usage_count}")

        return ok({
            "id": analysis_id,
            "usage_today": usage_count,
            "usage_limit": limits["daily_scans"],
            "plan": plan,
            "findings": findings,
            "ai": ai,
            "risk": risk,
            "score": score
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analyze error: {e}")
        raise HTTPException(500, detail={"success": False, "error": "Scan failed. Please try again."})

# =========================================================
# /api/me
# =========================================================
@app.get("/api/me")
def get_me(auth=Depends(get_user)):
    user = auth["user"]
    org = auth.get("org")
    plan = user.get("plan", "free").lower()
    limits = get_plan_limits(plan)

    return ok({
        "user_id": user["id"],
        "email": user.get("email"),
        "plan": plan,
        "org_name": org["name"] if org else None,
        "limits": limits
    })

# =========================================================
# /api/usage
# =========================================================
@app.get("/api/usage")
def usage(auth=Depends(get_user)):
    user = auth["user"]
    try:
        data = supabase.table("usage_metrics") \
            .select("*") \
            .eq("user_id", user["id"]) \
            .order("date", desc=True) \
            .limit(30) \
            .execute()
        return ok(data.data)
    except Exception as e:
        logger.error(f"Usage fetch error: {e}")
        return ok([])

# =========================================================
# /api/history
# =========================================================
@app.get("/api/history")
def history(auth=Depends(get_user)):
    user = auth["user"]
    plan = user.get("plan", "free").lower()
    limit = get_plan_limits(plan)["history_limit"]

    try:
        res = supabase.table("analysis_history") \
            .select("id,risk,score,findings_count,timestamp") \
            .eq("user_id", user["id"]) \
            .order("timestamp", desc=True) \
            .limit(limit) \
            .execute()
        return ok(res.data)
    except Exception as e:
        logger.error(f"History fetch error: {e}")
        return ok([])

# =========================================================
# /api/scan-repo
# =========================================================
@app.post("/api/scan-repo")
def scan_repo(req: RepoRequest, background_tasks: BackgroundTasks, auth=Depends(get_user)):
    user = auth["user"]
    org = auth.get("org")
    plan = user.get("plan", "free").lower()

    if not check_plan_access(plan, "repo_scan"):
        err("Repo scanning requires a Pro or Enterprise plan. Upgrade to unlock this feature.", 403)

    task_id = str(uuid.uuid4())
    org_id = org["id"] if org else user["id"]

    try:
        supabase.table("scan_tasks").insert({
            "id": task_id,
            "user_id": user["id"],
            "org_id": org_id,
            "repo_url": req.repo_url,
            "state": "QUEUED",
            "progress": 0,
            "created_at": datetime.now(timezone.utc).isoformat()
        }).execute()
    except Exception as e:
        logger.error(f"Task insert error: {e}")
        err("Failed to queue task", 500)

    background_tasks.add_task(run_scan, task_id, req.repo_url, user["id"], org_id)

    logger.info(f"Repo scan queued: task={task_id} repo={req.repo_url}")
    return ok({"task_id": task_id, "status": "queued"})

# =========================================================
# /api/task/{task_id}
# =========================================================
@app.get("/api/task/{task_id}")
def get_task(task_id: str, auth=Depends(get_user)):
    try:
        res = supabase.table("scan_tasks") \
            .select("*") \
            .eq("id", task_id) \
            .single() \
            .execute()

        if not res.data:
            err("Task not found", 404)

        return ok(res.data)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get task error: {e}")
        err("Failed to fetch task status", 500)

# =========================================================
# /api/cve/search
# =========================================================
@app.get("/api/cve/search")
async def cve_search(query: str, auth=Depends(get_user)):
    if not query or len(query.strip()) < 2:
        err("Query must be at least 2 characters")

    query = query.strip()[:100]

    try:
        cached = supabase.table("cve_cache").select("*").eq("query", query).execute()
        if cached.data:
            return ok(cached.data[0]["result"])
    except Exception:
        pass  # cache miss is fine

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.get(CVE_API, params={
                "keywordSearch": query,
                "resultsPerPage": 3
            })
        data = res.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cves.append({
                "id": cve.get("id"),
                "description": (cve.get("descriptions", [{}])[0].get("value", ""))[:300],
                "cvss": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0]
                         .get("cvssData", {}).get("baseScore", None)
            })

        result = {"cves": cves}

        try:
            supabase.table("cve_cache").insert({"query": query, "result": result}).execute()
        except Exception:
            pass  # cache write failure is non-fatal

        return ok(result)
    except httpx.TimeoutException:
        err("CVE lookup timed out", 503)
    except Exception as e:
        logger.error(f"CVE search error: {e}")
        err("CVE lookup failed", 500)

# =========================================================
# /api/ai/explain
# =========================================================
@app.post("/api/ai/explain")
async def ai_explain(req: AIExplainRequest, auth=Depends(get_user)):
    user = auth["user"]
    plan = user.get("plan", "free").lower()

    if not check_plan_access(plan, "api_access") and plan != "pro" and plan != "enterprise":
        # Allow explain for all plans but limit depth
        pass

    try:
        result = await ai_enrich(
            req.context[:2000] + "\n\nQuestion: " + req.question[:500],
            [],
            depth=get_plan_limits(plan)["ai_depth"]
        )
        return ok(result)
    except Exception as e:
        logger.error(f"AI explain error: {e}")
        err("AI explanation failed", 500)

# =========================================================
# /api/report/pdf
# =========================================================
@app.post("/api/report/pdf")
def generate_pdf(data: dict, auth=Depends(get_user)):
    user = auth["user"]
    plan = user.get("plan", "free").lower()

    findings = data.get("findings", [])
    file_path = f"/tmp/report_{uuid.uuid4()}.pdf"

    try:
        doc = SimpleDocTemplate(file_path, pagesize=letter)
        styles = getSampleStyleSheet()
        content = []

        content.append(Paragraph("SafeAIScan Security Report", styles["Title"]))
        content.append(Spacer(1, 12))
        content.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
        content.append(Paragraph(f"Plan: {plan.upper()}", styles["Normal"]))
        content.append(Spacer(1, 20))

        if findings:
            content.append(Paragraph(f"Findings ({len(findings)} total)", styles["Heading2"]))
            content.append(Spacer(1, 8))
            for f in findings:
                sev = f.get("severity", "LOW")
                title = f.get("title", "Issue")
                desc = f.get("description", "")
                content.append(Paragraph(f"[{sev}] {title}", styles["Heading3"]))
                if desc:
                    content.append(Paragraph(desc, styles["Normal"]))
                content.append(Spacer(1, 6))
        else:
            content.append(Paragraph("No vulnerabilities detected.", styles["Normal"]))

        doc.build(content)
        return FileResponse(file_path, filename="safeaiscan-report.pdf", media_type="application/pdf")

    except Exception as e:
        logger.error(f"PDF error: {e}")
        err("PDF generation failed", 500)

# =========================================================
# /api/org/users
# =========================================================
@app.get("/api/org/users")
def get_org_users(auth=Depends(get_user)):
    user = auth["user"]
    org = auth.get("org")
    plan = user.get("plan", "free").lower()

    if plan == "free":
        err("Team management requires Pro or Enterprise plan", 403)

    org_id = org["id"] if org else None
    if not org_id:
        return ok([])

    try:
        res = supabase.table("users").select("email,plan,created_at").eq("org_id", org_id).execute()
        return ok(res.data)
    except Exception as e:
        logger.error(f"Org users error: {e}")
        return ok([])

# =========================================================
# /api/repo/tree
# =========================================================
@app.get("/api/repo/tree")
def get_repo_tree(repo_url: str, auth=Depends(get_user)):
    user = auth["user"]
    plan = user.get("plan", "free").lower()

    if not check_plan_access(plan, "repo_scan"):
        err("Repo access requires Pro or Enterprise plan", 403)

    try:
        g = Github(GITHUB_TOKEN) if GITHUB_TOKEN else Github()
        repo_name = repo_url.replace("https://github.com/", "")
        repo = g.get_repo(repo_name)

        def build_tree(contents, depth=0):
            if depth > 3:
                return []
            tree = []
            for file in contents[:50]:  # limit breadth
                node = {"name": file.name, "path": file.path, "type": file.type}
                if file.type == "dir" and depth < 2:
                    try:
                        node["children"] = build_tree(repo.get_contents(file.path), depth + 1)
                    except Exception:
                        node["children"] = []
                tree.append(node)
            return tree

        return ok(build_tree(repo.get_contents("")))
    except Exception as e:
        logger.error(f"Repo tree error: {e}")
        err(f"Could not fetch repo: {str(e)[:100]}", 500)

# =========================================================
# /api/auth/rotate-key
# =========================================================
@app.post("/api/auth/rotate-key")
def rotate_api_key(auth=Depends(get_user)):
    user = auth["user"]
    raw_key = f"saas_{uuid.uuid4().hex}"
    try:
        supabase.table("users").update({
            "api_key_hash": hash_key(raw_key)
        }).eq("id", user["id"]).execute()
        logger.info(f"API key rotated for user {user['id']}")
        return ok({"api_key": raw_key})
    except Exception as e:
        logger.error(f"Key rotation error: {e}")
        err("Key rotation failed", 500)

# =========================================================
# HEALTH CHECK
# =========================================================
@app.get("/")
def home():
    return {"status": "SafeAIScan v2.0 running", "success": True}

@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0", "timestamp": datetime.now(timezone.utc).isoformat()}

# =========================================================
# WEBSOCKET (real-time scan progress)
# =========================================================
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            data = await ws.receive_text()
            await ws.send_json({"type": "ping", "ts": time.time()})
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")

# =========================================================
# GLOBAL EXCEPTION HANDLER
# =========================================================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception {request.url}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": "An unexpected error occurred. Please try again."}
    )
