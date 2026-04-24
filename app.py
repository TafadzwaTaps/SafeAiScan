import os
import uuid
import hashlib
import asyncio
import logging
import time
from datetime import datetime, timezone

# FIX: load .env file automatically if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed — env vars must be set externally

import httpx
from fastapi import (
    FastAPI, Depends, HTTPException, Header,
    Request, BackgroundTasks, WebSocket, WebSocketDisconnect
)
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
# FIX: use field_validator for pydantic v2 compat; removed deprecated @validator
try:
    from pydantic import BaseModel, field_validator as _fv
    _USE_FIELD_VALIDATOR = True
except ImportError:
    from pydantic import BaseModel, validator as _fv
    _USE_FIELD_VALIDATOR = False

from passlib.context import CryptContext
from config import DEV_MODE
from github import Github
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
from auth import create_access_token, verify_token
# FIX: removed duplicate "from fastapi import Request"
from access import enforce_feature, has_feature, get_ai_depth, get_daily_limit, within_limit
from plans import get_plan_limits
from tasks import run_scan
import db as DB

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("safeaiscan")

app = FastAPI(title="SafeAIScan Enterprise", version="2.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5500","http://localhost:3000","https://rathious-safeaiscan.hf.space"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

HF_API_KEY   = os.getenv("HF_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
CVE_API      = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def ok(data=None, **extra):
    return {"success": True, "data": data, **extra}

def fail(message: str, code: int = 400):
    raise HTTPException(status_code=code, detail={"success": False, "error": message})

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(pw: str) -> str:
    return pwd_context.hash(pw[:72])

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False

def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def require_feature(auth, feature: str):
    enforce_feature(auth["user"], feature)

# ---- MODELS ----
class RegisterRequest(BaseModel):
    email: str
    password: str
    org_name: str

    @_fv("email")
    @classmethod
    def valid_email(cls, v):
        v = v.lower().strip()
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email address")
        return v

    @_fv("password")
    @classmethod
    def strong_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @_fv("org_name")
    @classmethod
    def nonempty_org(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Organization name is required")
        return v

class LoginRequest(BaseModel):
    email: str
    password: str

    @_fv("email")
    @classmethod
    def normalize(cls, v):
        return v.lower().strip()

class AnalyzeRequest(BaseModel):
    text: str

    @_fv("text")
    @classmethod
    def not_empty(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Code text cannot be empty")
        if len(v) > 50_000:
            raise ValueError("Input too large (max 50,000 chars)")
        return v

class RepoRequest(BaseModel):
    repo_url: str

    @_fv("repo_url")
    @classmethod
    def github_only(cls, v):
        v = v.strip()
        if not v.startswith("https://github.com/"):
            raise ValueError("Only GitHub HTTPS URLs are supported")
        return v

class AIExplainRequest(BaseModel):
    question: str
    context: str

# FIX: typed model for PDF endpoint — FastAPI cannot parse raw dict body
class PDFReportRequest(BaseModel):
    findings: list = []

# ---- AUTH ----
def get_user(request: Request, authorization: str = Header(None), x_api_key: str = Header(None)):
    if hasattr(request.state, "_auth"):
        return request.state._auth
    if not authorization:
        raise HTTPException(401, detail={"success": False, "error": "Missing authorization header"})
    token = authorization.removeprefix("Bearer ").strip()
    payload = verify_token(token)
    if not payload:
        raise HTTPException(401, detail={"success": False, "error": "Invalid or expired token"})
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(401, detail={"success": False, "error": "Malformed token"})
    user = DB.fetch_user_by_id(user_id)
    if not user:
        raise HTTPException(403, detail={"success": False, "error": "User not found"})
    if not user.get("is_active", True):
        raise HTTPException(403, detail={"success": False, "error": "Account deactivated"})
    if x_api_key and x_api_key not in ("undefined", "null", ""):
        if user.get("api_key_hash") != hash_key(x_api_key):
            raise HTTPException(403, detail={"success": False, "error": "Invalid API key"})
    org = None
    if user.get("org_id"):
        org = DB.fetch_org_by_id(user["org_id"])
    result = {"user": user, "org": org, "request": request}
    request.state._auth = result
    return result

# FIX: replaced deprecated datetime.utcnow() → datetime.now(timezone.utc) throughout
def track_usage(user_id: str, org_id: str) -> int:
    today = str(datetime.now(timezone.utc).date())
    try:
        existing = DB.fetch_usage_today(user_id, today)
        count = (existing["request_count"] + 1) if existing else 1
        DB.upsert_usage(user_id, org_id or user_id, today, count)
        return count
    except Exception as exc:
        logger.error(f"track_usage: {exc}")
        return 1

_PATTERNS = [
    ("eval(",                   "HIGH",     "eval() executes arbitrary code — dangerous with user input."),
    ("exec(",                   "HIGH",     "exec() runs dynamic code — avoid with untrusted input."),
    ("os.system(",              "HIGH",     "os.system() executes shell commands; use subprocess with a list instead."),
    ("subprocess.call",         "MEDIUM",   "subprocess.call with shell=True can lead to shell injection."),
    ("pickle.loads(",           "CRITICAL", "pickle.loads() can execute arbitrary code from untrusted data."),
    ("__import__(",             "HIGH",     "Dynamic __import__ can load malicious modules."),
    ("open(",                   "LOW",      "File operations should validate paths to prevent traversal."),
    ("SELECT *",                "MEDIUM",   "Wildcard SELECT may expose sensitive columns; be explicit."),
    ('f"SELECT',                "HIGH",     "f-string SQL is vulnerable to injection — use parameterized queries."),
    ("f'SELECT",                "HIGH",     "f-string SQL is vulnerable to injection — use parameterized queries."),
    (".format(request",         "HIGH",     "String-formatted queries with request data risk SQL injection."),
    ("SECRET",                  "MEDIUM",   "Possible hardcoded secret — use environment variables."),
    ("PASSWORD",                "MEDIUM",   "Possible hardcoded password — use environment variables."),
    ("curl ",                   "LOW",      "Direct curl usage may allow SSRF — validate URLs."),
    ("wget ",                   "LOW",      "wget in code may allow SSRF — validate URLs."),
    ("document.write(",         "MEDIUM",   "document.write() with user data can cause XSS."),
    ("innerHTML",               "MEDIUM",   "Setting innerHTML with unsanitized data can cause XSS."),
    ("dangerouslySetInnerHTML", "HIGH",     "React dangerouslySetInnerHTML bypasses XSS protection."),
    ("base64.b64decode(",       "LOW",      "Decoding user-supplied base64 without validation can introduce injection."),
    ("yaml.load(",              "HIGH",     "yaml.load() allows arbitrary code execution — use yaml.safe_load()."),
    ("deserialize(",            "HIGH",     "Deserialization of untrusted data is a critical attack vector."),
    ("md5(",                    "LOW",      "MD5 is cryptographically broken — use SHA-256 or better."),
    ("sha1(",                   "LOW",      "SHA-1 is deprecated for security — use SHA-256 or better."),
]

def scan_vulnerabilities(text: str) -> list:
    findings, seen, lower = [], set(), text.lower()
    for pattern, severity, description in _PATTERNS:
        if pattern.lower() in lower and pattern not in seen:
            seen.add(pattern)
            findings.append({"title": f"Insecure use of `{pattern.strip()}`", "match": pattern, "severity": severity, "description": description, "fix": "Review this pattern and sanitize inputs. See OWASP for secure alternatives.", "cve": "N/A", "cvss": 5.0})
    return findings

async def ai_enrich(text: str, findings: list, depth: str = "full") -> dict:
    if not HF_API_KEY:
        return {"explanation": "AI analysis unavailable (no HF_API_KEY configured).", "fixes": []}
    if depth == "basic":
        if findings:
            return {"explanation": f"Detected {len(findings)} potential security issue(s). Upgrade to Pro for detailed AI analysis.", "fixes": ["Upgrade to Pro for actionable AI fixes"]}
        return {"explanation": "No critical issues detected in the submitted code.", "fixes": []}

    def parse_response(content: str):
        issues, fixes = [], []
        try:
            if "FIXES:" in content:
                parts = content.split("FIXES:", 1)
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
        except Exception as exc:
            logger.error(f"AI parse: {exc}")
            return content, []

    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=35) as client:
                res = await client.post("https://router.huggingface.co/v1/chat/completions", headers={"Authorization": f"Bearer {HF_API_KEY}", "Content-Type": "application/json"}, json={"model": "meta-llama/Meta-Llama-3-8B-Instruct", "messages": [{"role": "user", "content": f"You are a senior cybersecurity engineer. Analyze the code below.\n\nKnown issues: {findings}\n\nRespond ONLY in this format:\nSECURITY_ISSUES:\n- one per line\n\nFIXES:\n- one actionable fix per line\n\nIf no issues, write 'No critical vulnerabilities found.' under SECURITY_ISSUES.\n\nCode:\n{text[:1500]}"}], "temperature": 0.2, "max_tokens": 512})
            if res.status_code != 200:
                logger.warning(f"HF API {res.status_code}: {res.text[:200]}")
                if attempt == 0:
                    await asyncio.sleep(1.2)
                    continue
                return {"explanation": "AI service temporarily unavailable.", "fixes": []}
            data = res.json()
            if "choices" in data:
                content = data["choices"][0]["message"]["content"]
                explanation, fixes = parse_response(content)
                return {"explanation": explanation, "fixes": fixes}
            if "error" in data:
                return {"explanation": str(data["error"])[:200], "fixes": []}
            return {"explanation": str(data)[:200], "fixes": []}
        except httpx.TimeoutException:
            logger.warning(f"AI timeout attempt {attempt + 1}")
            if attempt == 0:
                await asyncio.sleep(1.5)
                continue
            return {"explanation": "AI timed out. Static scan results are still accurate.", "fixes": []}
        except Exception as exc:
            logger.error(f"AI error: {exc}")
            return {"explanation": "AI failed. Static scan results are still accurate.", "fixes": []}
    return {"explanation": "AI unavailable after retries.", "fixes": []}

# ---- ROUTES ----
@app.get("/api/dev/mode")
def dev_mode_status():
    return {"dev_mode": DEV_MODE, "status": "ALL FEATURES UNLOCKED" if DEV_MODE else "PRODUCTION MODE"}

@app.post("/auth/register")
def register(req: RegisterRequest, request: Request):
    try:
        if DB.user_email_exists(req.email):
            fail("This email is already registered.", 409)
        user_id = str(uuid.uuid4())
        org_id  = str(uuid.uuid4())
        DB.insert_org({"id": org_id, "name": req.org_name})
        raw_key  = f"saas_{uuid.uuid4().hex}"
        api_hash = hash_key(raw_key)
        base_row = {"id": user_id, "email": req.email, "password_hash": hash_password(req.password), "org_id": org_id, "api_key_hash": api_hash}
        try:
            DB.insert_user({**base_row, "plan": "free", "role": "admin", "created_at": datetime.now(timezone.utc).isoformat()})
        except Exception:
            DB.insert_user(base_row)
        token = create_access_token({"sub": user_id})
        DB.write_audit_log(user_id, "register", org_id=org_id, ip_address=request.client.host)
        return ok({"access_token": token, "api_key": raw_key, "plan": "free"})
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Register error: {exc}")
        raise HTTPException(500, detail={"success": False, "error": "Registration failed. Please try again."})

@app.post("/auth/login")
def login(req: LoginRequest, request: Request):
    try:
        user = DB.fetch_user_by_email(req.email)
        if not user or not verify_password(req.password, user.get("password_hash", "")):
            raise HTTPException(401, detail={"success": False, "error": "Invalid credentials"})
        if not user.get("is_active", True):
            raise HTTPException(403, detail={"success": False, "error": "Account deactivated"})
        token   = create_access_token({"sub": user["id"]})
        raw_key = None
        if not user.get("api_key_hash"):
            raw_key = f"saas_{uuid.uuid4().hex}"
            try:
                DB.update_user(user["id"], {"api_key_hash": hash_key(raw_key)})
            except Exception as exc:
                logger.warning(f"API key auto-issue failed: {exc}")
                raw_key = None
        try:
            DB.update_user(user["id"], {"last_login": datetime.now(timezone.utc).isoformat()})
        except Exception:
            pass
        DB.write_audit_log(user["id"], "login", org_id=user.get("org_id"), ip_address=request.client.host)
        return ok({"access_token": token, "user_id": user["id"], "org_id": user.get("org_id"), "plan": user.get("plan", "free"), "api_key": raw_key})
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Login error: {exc}")
        raise HTTPException(500, detail={"success": False, "error": "Login failed"})

@app.post("/api/auth/rotate-key")
def rotate_api_key(auth=Depends(get_user)):
    user    = auth["user"]
    raw_key = f"saas_{uuid.uuid4().hex}"
    try:
        DB.update_user(user["id"], {"api_key_hash": hash_key(raw_key)})
        DB.cache_invalidate(f"user:{user['id']}")
        DB.write_audit_log(user["id"], "key_rotate", org_id=user.get("org_id"))
        return ok({"api_key": raw_key})
    except Exception as exc:
        logger.error(f"Key rotation: {exc}")
        fail("Key rotation failed", 500)

@app.get("/api/me")
def get_me(auth=Depends(get_user)):
    user   = auth["user"]
    org    = auth.get("org")
    # DEV_MODE: always return enterprise plan so frontend stays unlocked
    if DEV_MODE:
        dev_limits = get_plan_limits("enterprise")
        return ok({
            "user_id":  user["id"],
            "email":    user.get("email"),
            "plan":     "enterprise",
            "role":     user.get("role", "admin"),
            "org_name": org["name"] if org else None,
            "limits":   dev_limits,
            "dev_mode": True
        })
    plan   = user.get("plan", "free").lower()
    limits = get_plan_limits(plan)
    return ok({
        "user_id":  user["id"],
        "email":    user.get("email"),
        "plan":     plan,
        "role":     user.get("role", "member"),
        "org_name": org["name"] if org else None,
        "limits":   limits
    })

@app.get("/api/org/users")
def get_org_users(auth=Depends(get_user)):
    user   = auth["user"]
    org    = auth.get("org")
    plan   = user.get("plan", "free").lower()
    if plan == "free" and not DEV_MODE:
        fail("Team management requires Pro or Enterprise plan", 403)
    org_id = org["id"] if org else None
    if not org_id:
        return ok([])
    return ok(DB.fetch_org_members(org_id))

@app.get("/api/dashboard")
def get_dashboard(auth=Depends(get_user)):
    user   = auth["user"]
    org    = auth.get("org")
    plan   = user.get("plan", "free").lower()
    limits = get_plan_limits(user.get("plan", "free"))
    org_id = org["id"] if org else None
    today  = str(datetime.now(timezone.utc).date())
    today_usage = 0
    try:
        rec = DB.fetch_usage_today(user["id"], today)
        today_usage = rec["request_count"] if rec else 0
    except Exception:
        pass
    batch = DB.fetch_dashboard_data(user["id"], org_id, plan)
    return ok({"user": {"user_id": user["id"], "email": user.get("email"), "plan": plan, "role": user.get("role", "member"), "org_name": org["name"] if org else None, "limits": limits}, "usage_today": today_usage, "usage_limit": limits["daily_scans"], "usage_series": batch["usage"], "history": batch["history"], "team": batch["team"]})

@app.get("/api/usage")
def get_usage(auth=Depends(get_user)):
    return ok(DB.fetch_usage_history(auth["user"]["id"], limit=30))

@app.get("/api/history")
def get_history(auth=Depends(get_user)):
    user  = auth["user"]
    limit = get_plan_limits(user.get("plan", "free"))["history_limit"]
    return ok(DB.fetch_scan_history(user["id"], limit=min(limit, 20)))

@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, request: Request, auth=Depends(get_user)):
    try:
        user   = auth["user"]
        org    = auth.get("org")
        org_id = org["id"] if org else user["id"]

        # DEV_MODE: skip limit tracking, use full depth
        if DEV_MODE:
            findings = scan_vulnerabilities(req.text)
            ai       = await ai_enrich(req.text, findings, depth="full")
            sev_score = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3}
            score     = min(100, sum(sev_score.get(f.get("severity", "LOW"), 3) for f in findings))
            hi_count  = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
            risk      = ("CRITICAL" if hi_count >= 3 else "HIGH" if hi_count >= 1 else "MEDIUM" if findings else "LOW")
            return ok({
                "id": str(uuid.uuid4()), "usage_today": 0, "usage_limit": 999999,
                "plan": "enterprise", "findings": findings, "ai": ai, "risk": risk, "score": score
            })

        plan   = user.get("plan", "free").lower()
        usage_count = track_usage(user["id"], org_id)
        if not within_limit(user, usage_count):
            limits = get_plan_limits(plan)
            fail(f"Daily scan limit reached ({limits['daily_scans']} scans/day)", 429)
        findings = scan_vulnerabilities(req.text)
        ai_depth = get_ai_depth(user)
        ai       = await ai_enrich(req.text, findings, depth=ai_depth)
        sev_score = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3}
        score     = min(100, sum(sev_score.get(f.get("severity", "LOW"), 3) for f in findings))
        hi_count  = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
        risk      = ("CRITICAL" if hi_count >= 3 else "HIGH" if hi_count >= 1 else "MEDIUM" if findings else "LOW")
        analysis_id = str(uuid.uuid4())
        DB.insert_scan_history({"id": analysis_id, "user_id": user["id"], "org_id": org_id, "input_text": req.text[:500], "risk": risk, "score": score, "findings_count": len(findings), "explanation": ai.get("explanation", "")[:1000], "fixes": ai.get("fixes", []), "timestamp": datetime.now(timezone.utc).isoformat()})
        DB.write_audit_log(user["id"], "scan", org_id=org_id, resource="/api/analyze", ip_address=request.client.host, metadata={"findings": len(findings), "risk": risk})
        limits = get_plan_limits(plan)
        logger.info(f"Scan: user={user['id']} plan={plan} findings={len(findings)} usage={usage_count}")
        return ok({"id": analysis_id, "usage_today": usage_count, "usage_limit": limits["daily_scans"], "plan": plan, "findings": findings, "ai": ai, "risk": risk, "score": score})
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Analyze error: {exc}")
        raise HTTPException(500, detail={"success": False, "error": "Scan failed. Please try again."})

@app.post("/api/scan-repo")
def scan_repo_endpoint(req: RepoRequest, background_tasks: BackgroundTasks, auth=Depends(get_user)):
    # FIX: renamed function from scan_repo to scan_repo_endpoint to avoid clash with imported run_scan
    user  = auth["user"]
    org   = auth.get("org")
    require_feature(auth, "repo_scan")
    task_id = str(uuid.uuid4())
    org_id  = org["id"] if org else user["id"]
    if not DB.insert_scan_task({"id": task_id, "user_id": user["id"], "org_id": org_id, "repo_url": req.repo_url, "state": "QUEUED", "progress": 0, "created_at": datetime.now(timezone.utc).isoformat()}):
        fail("Failed to queue scan task", 500)
    background_tasks.add_task(run_scan, task_id, req.repo_url, user["id"], org_id)
    logger.info(f"Repo scan queued: task={task_id}")
    return ok({"task_id": task_id, "status": "queued"})

@app.get("/api/task/{task_id}")
def get_task(task_id: str, auth=Depends(get_user)):
    try:
        data = DB.fetch_scan_task(task_id)
        if not data:
            fail("Task not found", 404)
        return ok(data)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Get task: {exc}")
        fail("Failed to fetch task status", 500)

@app.get("/api/cve/search")
async def cve_search(query: str, auth=Depends(get_user)):
    query = (query or "").strip()[:100]
    if len(query) < 2:
        fail("Query must be at least 2 characters")
    cached = DB.fetch_cve_cache(query)
    if cached:
        return ok(cached)
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.get(CVE_API, params={"keywordSearch": query, "resultsPerPage": 3})
        data = res.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cves.append({"id": cve.get("id"), "description": (cve.get("descriptions", [{}])[0].get("value", ""))[:300], "cvss": (cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore"))})
        result = {"cves": cves}
        DB.store_cve_cache(query, result)
        return ok(result)
    except httpx.TimeoutException:
        fail("CVE lookup timed out", 503)
    except Exception as exc:
        logger.error(f"CVE search: {exc}")
        fail("CVE lookup failed", 500)

@app.post("/api/ai/explain")
async def ai_explain(req: AIExplainRequest, auth=Depends(get_user)):
    user  = auth["user"]
    plan  = user.get("plan", "free").lower()
    depth = get_plan_limits(plan)["ai_depth"]
    try:
        result = await ai_enrich(req.context[:2000] + "\n\nQuestion: " + req.question[:500], [], depth=depth)
        return ok(result)
    except Exception as exc:
        logger.error(f"AI explain: {exc}")
        fail("AI explanation failed", 500)

# FIX: use PDFReportRequest typed model instead of raw dict
@app.post("/api/report/pdf")
def generate_pdf(data: PDFReportRequest, auth=Depends(get_user)):
    user     = auth["user"]
    plan     = user.get("plan", "free").lower()
    findings = data.findings
    filepath = f"/tmp/report_{uuid.uuid4()}.pdf"
    try:
        doc     = SimpleDocTemplate(filepath, pagesize=letter)
        styles  = getSampleStyleSheet()
        content = [Paragraph("SafeAIScan Security Report", styles["Title"]), Spacer(1, 12), Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]), Paragraph(f"Plan: {plan.upper()}", styles["Normal"]), Spacer(1, 20)]
        if findings:
            content.append(Paragraph(f"Findings ({len(findings)} total)", styles["Heading2"]))
            content.append(Spacer(1, 8))
            for f in findings:
                content.append(Paragraph(f"[{f.get('severity','LOW')}] {f.get('title','Issue')}", styles["Heading3"]))
                if f.get("description"):
                    content.append(Paragraph(f["description"], styles["Normal"]))
                content.append(Spacer(1, 6))
        else:
            content.append(Paragraph("No vulnerabilities detected.", styles["Normal"]))
        doc.build(content)
        return FileResponse(filepath, filename="safeaiscan-report.pdf", media_type="application/pdf")
    except Exception as exc:
        logger.error(f"PDF: {exc}")
        fail("PDF generation failed", 500)

@app.get("/api/repo/tree")
def get_repo_tree(repo_url: str, auth=Depends(get_user)):
    require_feature(auth, "repo_scan")
    try:
        g         = Github(GITHUB_TOKEN) if GITHUB_TOKEN else Github()
        repo_name = repo_url.removeprefix("https://github.com/")
        repo      = g.get_repo(repo_name)
        def build_tree(contents, depth=0):
            if depth > 2: return []
            tree = []
            for f in contents[:50]:
                node = {"name": f.name, "path": f.path, "type": f.type}
                if f.type == "dir":
                    try: node["children"] = build_tree(repo.get_contents(f.path), depth + 1)
                    except Exception: node["children"] = []
                tree.append(node)
            return tree
        return ok(build_tree(repo.get_contents("")))
    except Exception as exc:
        logger.error(f"Repo tree: {exc}")
        fail(f"Could not fetch repo: {str(exc)[:120]}", 500)

@app.get("/")
def home():
    return {"status": "SafeAIScan v2.1 running", "success": True}

@app.get("/health")
def health():
    return {"status": "ok", "version": "2.1.0", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            await ws.receive_text()
            await ws.send_json({"type": "ping", "ts": time.time()})
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled {request.method} {request.url.path}: {exc}")
    return JSONResponse(status_code=500, content={"success": False, "error": "An unexpected error occurred. Please try again."})
