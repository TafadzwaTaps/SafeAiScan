import os
import re
import math
import html
import string as _str_module
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
from github import Github
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
from auth import create_access_token, verify_token
from tasks import run_scan
import db as DB

# ── Inline replacements for removed modules ────────────────────────────────
# config.py  → DEV_MODE removed; all features available to authenticated users
# access.py  → enforce_feature / has_feature / get_ai_depth / within_limit removed
# plans.py   → get_plan_limits removed; limits are now hard-coded here

_PLAN_LIMITS = {
    "free": {
        "daily_scans":     5,
        "daily_repos":     2,
        "history_limit":   10,
        "ai_depth":        "basic",
        "repo_scan":       True,
        "pdf_download":    False,
        "json_export":     False,
        "advanced_ai":     False,
        "scheduled_scans": False,
        "api_access":      False,
    },
    "pro_trial": {
        "daily_scans":     -1,   # unlimited — -1 means no limit
        "daily_repos":     -1,
        "history_limit":   500,
        "ai_depth":        "full",
        "repo_scan":       True,
        "pdf_download":    True,
        "json_export":     True,
        "advanced_ai":     True,
        "scheduled_scans": True,
        "api_access":      True,
    },
    "pro": {
        "daily_scans":     -1,
        "daily_repos":     -1,
        "history_limit":   500,
        "ai_depth":        "full",
        "repo_scan":       True,
        "pdf_download":    True,
        "json_export":     True,
        "advanced_ai":     True,
        "scheduled_scans": True,
        "api_access":      True,
    },
    "enterprise": {
        "daily_scans":     -1,
        "daily_repos":     -1,
        "history_limit":   9999,
        "ai_depth":        "full",
        "repo_scan":       True,
        "pdf_download":    True,
        "json_export":     True,
        "advanced_ai":     True,
        "scheduled_scans": True,
        "api_access":      True,
    },
}

def get_plan_limits(plan: str) -> dict:
    """Return limits dict for a plan name. Falls back to free limits."""
    return _PLAN_LIMITS.get((plan or "free").lower(), _PLAN_LIMITS["free"]).copy()

def is_pro_or_trial(user: dict) -> bool:
    """Return True if the user has active Pro access (paid or trial)."""
    plan = (user.get("plan") or "free").lower()
    return plan in ("pro", "pro_trial", "enterprise") and user.get("is_pro", False)

def within_limit(user: dict, usage_count: int) -> bool:
    """
    Return True if the user has not exceeded their daily scan limit.
    -1 = unlimited (pro/pro_trial/enterprise). Free = 5/day.
    """
    plan  = (user.get("plan") or "free").lower()
    limit = get_plan_limits(plan)["daily_scans"]
    if limit == -1:
        return True
    return usage_count <= limit

def get_ai_depth(user: dict) -> str:
    """Return the AI analysis depth for this user's plan."""
    return get_plan_limits((user.get("plan") or "free"))["ai_depth"]

def enforce_feature(user: dict, feature: str) -> None:
    """
    Raise 403 if the user's plan does not include the feature.
    Free & trial users have access to repo_scan — they're limited by daily scan count.
    """
    plan   = (user.get("plan") or "free").lower()
    # repo_scan is available to everyone — enforce via usage limits instead
    if feature == "repo_scan":
        return
    # pro_trial has full pro access
    if plan in ("pro", "pro_trial", "enterprise"):
        return
    limits = get_plan_limits(plan)
    if not limits.get(feature, False):
        raise HTTPException(
            403,
            detail={"success": False, "error": f"'{feature}' requires a Pro plan. Start your free 30-day trial or upgrade."}
        )

def has_feature(user: dict, feature: str) -> bool:
    """Return True if the user's plan includes the feature."""
    return bool(get_plan_limits(user.get("plan", "free")).get(feature, False))


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("safeaiscan")

app = FastAPI(title="SafeAIScan Enterprise", version="2.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5500","http://localhost:3000","https://rathious-safeaiscan.hf.space"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ══════════════════════════════════════════════════════════════
#  SECURITY: Rate limiting, security headers, XSS/injection guard
#  Added without touching any existing route logic
# ══════════════════════════════════════════════════════════════
from collections import defaultdict

# ── Rate limit store (in-memory, per IP per bucket) ──────────
_rl_store: dict = defaultdict(lambda: {"count": 0, "window_start": 0.0})
_rl_lock  = asyncio.Lock()

_RL_LIMITS = {
    "auth":    5,    # /auth/* — 5 attempts per 60s (brute-force protection)
    "scan":    30,   # /api/analyze, /api/scan-repo — 30 per 60s
    "payment": 10,   # /payment/* — 10 per 60s
    "default": 60,   # everything else
}

def _rl_bucket(path: str) -> str:
    if path.startswith("/auth/"):          return "auth"
    if "/analyze" in path or "/scan" in path: return "scan"
    if path.startswith("/payment/"):       return "payment"
    return "default"

def _get_real_ip(request: Request) -> str:
    """Respect Cloudflare / HF proxy headers for real IP."""
    for h in ("cf-connecting-ip", "x-real-ip", "x-forwarded-for"):
        v = request.headers.get(h, "")
        if v:
            return v.split(",")[0].strip()
    return (request.client.host if request.client else "unknown")

# ── Injection / XSS pattern detector ─────────────────────────
_INJECT_RES = [
    re.compile(r"<script[\s>]",              re.I),
    re.compile(r"javascript\s*:",            re.I),
    re.compile(r"on\w+\s*=\s*[\"']",         re.I),
    re.compile(r";\s*(drop|delete|insert|update|alter|truncate)\s+", re.I),
    re.compile(r"\bunion\b.{0,20}\bselect\b", re.I),
    re.compile(r"'\s*or\s+'?\d",             re.I),
]

def _looks_malicious(text: str) -> bool:
    for pat in _INJECT_RES:
        if pat.search(text):
            return True
    return False

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path   = request.url.path
    method = request.method
    ip     = _get_real_ip(request)

    # ── 1. Rate limiting ──────────────────────────────────────
    bucket = _rl_bucket(path)
    limit  = _RL_LIMITS[bucket]
    window = 60.0

    async with _rl_lock:
        key   = f"{ip}:{bucket}"
        entry = _rl_store[key]
        now   = time.time()
        if now - entry["window_start"] > window:
            entry["count"]        = 1
            entry["window_start"] = now
        else:
            entry["count"] += 1

        remaining = max(0, limit - entry["count"])
        reset_in  = int(window - (now - entry["window_start"]))

        if entry["count"] > limit:
            logger.warning(f"Rate limit: ip={ip} bucket={bucket} count={entry['count']}")
            return JSONResponse(
                status_code=429,
                content={"success": False, "error": "Too many requests. Please slow down."},
                headers={
                    "Retry-After":           str(reset_in),
                    "X-RateLimit-Limit":     str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset":     str(reset_in),
                }
            )

    # ── 2. Block malicious query strings ─────────────────────
    raw_query = str(request.url.query)
    if raw_query and _looks_malicious(raw_query):
        logger.warning(f"Malicious query blocked: ip={ip} path={path} q={raw_query[:80]}")
        return JSONResponse(status_code=400, content={"success": False, "error": "Invalid request."})

    # ── 3. Block HTML content-type on API endpoints ───────────
    ct = request.headers.get("content-type", "")
    if method in ("POST", "PUT", "PATCH") and "text/html" in ct and path.startswith("/api/"):
        return JSONResponse(status_code=415, content={"success": False, "error": "Unsupported content type."})

    # ── 4. Process request ────────────────────────────────────
    try:
        response = await call_next(request)
    except Exception as exc:
        logger.error(f"Middleware error: {exc}")
        return JSONResponse(status_code=500, content={"success": False, "error": "Internal server error."})

    # ── 5. Security response headers ─────────────────────────
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]      = "camera=(), microphone=(), geolocation=()"
    response.headers["X-RateLimit-Limit"]       = str(limit)
    response.headers["X-RateLimit-Remaining"]   = str(remaining)
    response.headers["X-RateLimit-Reset"]       = str(reset_in)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://rathious-safeaiscan.hf.space https://router.huggingface.co "
        "https://api-m.sandbox.paypal.com https://api-m.paypal.com https://services.nvd.nist.gov; "
        "frame-ancestors 'none';"
    )
    return response

HF_API_KEY   = os.getenv("HF_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
CVE_API      = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def ok(data=None, **extra):
    return {"success": True, "data": data, **extra}

def fail(message: str, code: int = 400):
    raise HTTPException(status_code=code, detail={"success": False, "error": message})

# ── bcrypt version compatibility fix ──────────────────────────────────────
# bcrypt 4.x removed __about__.__version__ which passlib reads at startup.
# When missing, passlib silently marks bcrypt unavailable and verify()
# returns False for every password → every login 401s.
# Fix: patch __about__ back, fall back to raw bcrypt if passlib still fails.
import bcrypt as _bcrypt_lib
try:
    if not hasattr(_bcrypt_lib, "__about__"):
        class _BcryptAbout:
            __version__ = getattr(_bcrypt_lib, "__version__", "4.0.0")
        _bcrypt_lib.__about__ = _BcryptAbout()
    _pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    _pwd_ctx.hash("probe")   # smoke-test — raises if broken
    _PASSLIB_OK = True
except Exception:
    _pwd_ctx   = None
    _PASSLIB_OK = False

def hash_password(pw: str) -> str:
    if _PASSLIB_OK:
        return _pwd_ctx.hash(pw[:72])
    return _bcrypt_lib.hashpw(pw[:72].encode(), _bcrypt_lib.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    try:
        if _PASSLIB_OK:
            return _pwd_ctx.verify(plain, hashed)
        return _bcrypt_lib.checkpw(plain[:72].encode(), hashed.encode())
    except Exception as exc:
        logger.warning(f"verify_password error: {exc}")
        return False

def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def require_feature(auth, feature: str):
    """Convenience wrapper used by route handlers."""
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
        if len(v) > 254:
            raise ValueError("Email address too long")
        # Block injection chars in email
        if any(c in v for c in ("\x00", "<", ">", "'", '"', ";", "--", "/*")):
            raise ValueError("Invalid characters in email address")
        return v

    @_fv("password")
    @classmethod
    def strong_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if len(v) > 128:
            raise ValueError("Password too long (max 128 characters)")
        return v

    @_fv("org_name")
    @classmethod
    def nonempty_org(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Organization name is required")
        if len(v) > 100:
            raise ValueError("Organization name too long (max 100 characters)")
        # HTML-escape to prevent stored XSS
        v = html.escape(v)
        return v

class LoginRequest(BaseModel):
    email: str
    password: str

    @_fv("email")
    @classmethod
    def normalize(cls, v):
        v = v.lower().strip()
        if len(v) > 254:
            raise ValueError("Email too long")
        return v

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
        # Strip null bytes — common in injection payloads
        v = v.replace("\x00", "")
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
    # ── Phase 1 additions (all optional, fully backward compatible) ──
    scan_id:            str = ""
    risk_level:         str = "NONE"
    total_secrets:      int = 0
    summary:            dict = {}
    source:             str = ""
    truncated:          bool = False
    security_score:     int = 0
    score_risk_level:   str = "Moderate"
    repo_health:        dict | None = None
    dependency_findings: list = []

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
    # Auto-expire trial if window has passed
    try:
        user, _trial_status = DB.expire_trial_if_needed(user)
    except Exception:
        pass   # Never block auth on a trial-check error
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

# ── ScanShield-inspired: expanded patterns ────────────────────
_EXTRA_PATTERNS = [
    # Cloud provider key prefixes
    ("AKIA",                   "CRITICAL", "Possible AWS Access Key ID — rotate immediately via AWS IAM."),
    ("ghp_",                   "CRITICAL", "Possible GitHub Personal Access Token — revoke at github.com/settings/tokens."),
    ("xoxb-",                  "CRITICAL", "Possible Slack bot token — revoke at api.slack.com/apps."),
    ("sk-",                    "HIGH",     "Possible OpenAI or Stripe secret key — check provider dashboard and rotate."),
    ("AIza",                   "HIGH",     "Possible Google API key — restrict scopes and rotate in Cloud Console."),
    ("SG.",                    "HIGH",     "Possible SendGrid API key — rotate in SendGrid dashboard."),
    # Broken crypto
    ("DES.new(",               "MEDIUM",   "DES is cryptographically broken — use AES-256-GCM."),
    ("RC4(",                   "MEDIUM",   "RC4 is deprecated — use AES-GCM or ChaCha20."),
    ("random.random()",        "LOW",      "random.random() is not cryptographically secure — use the secrets module."),
    ("Math.random()",          "LOW",      "Math.random() is not cryptographically secure for tokens or session IDs."),
    # Insecure network
    ("verify=False",           "MEDIUM",   "SSL verification disabled — allows MITM attacks. Remove verify=False."),
    ("check_hostname=False",   "MEDIUM",   "Hostname verification disabled — SSL is ineffective."),
    # Path traversal
    ("../",                    "MEDIUM",   "Possible path traversal — use os.path.realpath() and validate against allowlist."),
    # Command injection
    ("shell=True",             "HIGH",     "shell=True in subprocess enables shell injection — pass args as a list."),
    ("os.popen(",              "HIGH",     "os.popen() executes shell commands — use subprocess.run() with a list."),
    # Prototype pollution (JS)
    ("__proto__",              "HIGH",     "Prototype pollution risk — sanitize user-controlled object keys."),
    ("constructor[prototype]", "HIGH",     "Prototype pollution vector — validate property access on user input."),
    # Hardcoded credentials
    ('password = "',           "MEDIUM",   "Possible hardcoded password — use environment variables instead."),
    ('passwd = "',             "MEDIUM",   "Possible hardcoded password — use environment variables instead."),
    ('token = "',              "MEDIUM",   "Possible hardcoded token — use environment variables instead."),
    ('api_key = "',            "MEDIUM",   "Possible hardcoded API key — use environment variables instead."),
]

# ── High-entropy string detection (ScanShield-style) ─────────
_B64_CHARS = set(_str_module.ascii_letters + _str_module.digits + "+/=")
_HEX_CHARS = set(_str_module.hexdigits)
_TOKEN_RE  = re.compile(r'["\']([A-Za-z0-9+/=_\-]{20,120})["\']')

def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string. High value (~4.5+) = likely a secret."""
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())

def _detect_high_entropy_secrets(text: str) -> list:
    """
    Find quoted strings that look like API keys or tokens based on entropy.
    Threshold: >= 4.5 bits/char on base64 or hex character sets, length >= 32.
    This catches hardcoded secrets that don't match any known prefix pattern.
    """
    findings, seen = [], set()
    for match in _TOKEN_RE.finditer(text):
        candidate = match.group(1)
        if candidate in seen or len(candidate) < 32:
            continue
        char_set = set(candidate)
        is_b64 = char_set.issubset(_B64_CHARS)
        is_hex = char_set.issubset(_HEX_CHARS)
        if not (is_b64 or is_hex):
            continue
        entropy = _shannon_entropy(candidate)
        if entropy >= 4.5:
            seen.add(candidate)
            redacted = candidate[:6] + "···" + candidate[-4:]
            findings.append({
                "title":       "High-entropy string detected (possible secret)",
                "match":       redacted,
                "severity":    "HIGH",
                "description": (
                    f"A high-entropy string (entropy={entropy:.2f} bits/char) was found "
                    f"embedded in code. This pattern is consistent with API keys, auth tokens, or passwords."
                ),
                "fix":         "Move this value to an environment variable and rotate it immediately if live.",
                "cve":         "N/A",
                "cvss":        7.5,
            })
    return findings

def scan_vulnerabilities(text: str) -> list:
    findings, seen, lower = [], set(), text.lower()
    # Original core patterns — unchanged
    for pattern, severity, description in _PATTERNS:
        if pattern.lower() in lower and pattern not in seen:
            seen.add(pattern)
            findings.append({"title": f"Insecure use of `{pattern.strip()}`", "match": pattern, "severity": severity, "description": description, "fix": "Review this pattern and sanitize inputs. See OWASP for secure alternatives.", "cve": "N/A", "cvss": 5.0})
    # ScanShield-inspired expanded patterns
    for pattern, severity, description in _EXTRA_PATTERNS:
        if pattern.lower() in lower and pattern not in seen:
            seen.add(pattern)
            cvss = 9.0 if severity == "CRITICAL" else 7.5 if severity == "HIGH" else 5.0
            findings.append({"title": f"Detected: `{pattern.strip()}`", "match": pattern, "severity": severity, "description": description, "fix": "Review this pattern and apply the recommended remediation. See provider security docs.", "cve": "N/A", "cvss": cvss})
    # High-entropy secret detection
    for h in _detect_high_entropy_secrets(text):
        if h["match"] not in seen:
            seen.add(h["match"])
            findings.append(h)
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
    # config.py removed — DEV_MODE no longer applicable
    return {"dev_mode": False, "status": "PRODUCTION MODE"}

@app.post("/auth/register")
def register(req: RegisterRequest, request: Request):
    try:
        # Server-side injection guard (on top of model validators)
        if _looks_malicious(req.email) or _looks_malicious(req.org_name):
            logger.warning(f"Injection attempt in register: ip={_get_real_ip(request)}")
            fail("Invalid input detected.", 400)
        if DB.user_email_exists(req.email):
            fail("This email is already registered. Please sign in instead.", 409)
        user_id = str(uuid.uuid4())
        org_id  = str(uuid.uuid4())
        # insert_org is non-fatal — proceed even if org table missing
        org_inserted = DB.insert_org({"id": org_id, "name": req.org_name})
        raw_key  = f"saas_{uuid.uuid4().hex}"
        api_hash = hash_key(raw_key)
        # Build user row — only include org_id FK if org was created
        base_row = {
            "id":            user_id,
            "email":         req.email,
            "password_hash": hash_password(req.password),
            "api_key_hash":  api_hash,
            "plan":          "free",
            "role":          "admin",
            "created_at":    datetime.now(timezone.utc).isoformat(),
        }
        if org_inserted:
            base_row["org_id"] = org_id
        # insert_user handles column fallback internally
        if not DB.insert_user(base_row):
            fail("Could not create account. Please try again.", 500)
        token = create_access_token({"sub": user_id})
        # Start 30-day Pro trial for every new user
        try:
            DB.start_trial(user_id)
            trial_plan = "pro_trial"
            trial_is_pro = True
        except Exception as exc:
            logger.warning(f"Trial start failed (non-fatal): {exc}")
            trial_plan = "free"
            trial_is_pro = False
        try:
            DB.write_audit_log(user_id, "register", org_id=org_id, ip_address=request.client.host)
        except Exception:
            pass
        logger.info(f"Registered: {req.email} user_id={user_id} plan={trial_plan}")
        from datetime import date, timedelta
        trial_end_date = str(date.today() + timedelta(days=30)) if trial_is_pro else ""
        return ok({
            "access_token": token,
            "api_key":       raw_key,
            "plan":          trial_plan,
            "plan_label":    "Pro Trial" if trial_is_pro else "Free",
            "is_pro":        trial_is_pro,
            "trial_active":  trial_is_pro,
            "trial_days_left": 30 if trial_is_pro else 0,
            "trial_end":     trial_end_date,
            "user_id":       user_id,
        })
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Register error: {exc}")
        raise HTTPException(500, detail={"success": False, "error": "Registration failed. Please try again."})

@app.post("/auth/login")
def login(req: LoginRequest, request: Request):
    try:
        # Timing-safe: always run bcrypt even if user not found,
        # so attackers can't enumerate valid emails via response timing
        _DUMMY_HASH = "$2b$12$eImiTXuWVxfM37uY4JANjQeeHjUmBIeHqYkPiTpPuBNP7cBSjEFNq"
        user = DB.fetch_user_by_email(req.email)

        if not user:
            verify_password(req.password, _DUMMY_HASH)  # constant-time dummy check
            logger.warning(f"Login: email not found — {req.email}")
            raise HTTPException(401, detail={"success": False, "error": "Invalid email or password."})

        stored_hash = user.get("password_hash", "")
        if not stored_hash:
            logger.error(f"Login: no password_hash in DB for {req.email}")
            raise HTTPException(401, detail={"success": False, "error": "Account incomplete. Please re-register."})

        ok_pw = verify_password(req.password, stored_hash)
        logger.info(f"Login attempt: {req.email} password_ok={ok_pw} hash_prefix={stored_hash[:10]}")

        if not ok_pw:
            raise HTTPException(401, detail={"success": False, "error": "Invalid email or password."})

        if not user.get("is_active", True):
            raise HTTPException(403, detail={"success": False, "error": "Account deactivated."})

        token = create_access_token({"sub": user["id"]})

        raw_key = None
        if not user.get("api_key_hash"):
            try:
                raw_key = f"saas_{uuid.uuid4().hex}"
                DB.update_user(user["id"], {"api_key_hash": hash_key(raw_key)})
            except Exception as exc:
                logger.warning(f"API key auto-issue failed: {exc}")
                raw_key = None

        try:
            DB.update_user(user["id"], {"last_login": datetime.now(timezone.utc).isoformat()})
        except Exception:
            pass

        try:
            DB.write_audit_log(user["id"], "login", org_id=user.get("org_id"), ip_address=request.client.host)
        except Exception:
            pass

        logger.info(f"Login successful: {req.email} user_id={user['id']}")
        # Include full trial/subscription info in login response
        try:
            sub = DB.get_full_subscription_info(user)
        except Exception:
            sub = {"plan": user.get("plan","free"), "is_pro": user.get("is_pro",False),
                   "trial_active": False, "days_left": 0, "trial_end": "", "plan_label":"Free"}
        return ok({
            "access_token":   token,
            "user_id":        user["id"],
            "org_id":         user.get("org_id"),
            "plan":           sub["plan"],
            "plan_label":     sub.get("plan_label","Free"),
            "is_pro":         sub["is_pro"],
            "trial_active":   sub["trial_active"],
            "trial_days_left": sub.get("days_left", 0),
            "trial_end":      sub.get("trial_end",""),
            "api_key":        raw_key,
        })
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Login error: {exc}")
        raise HTTPException(500, detail={"success": False, "error": "Login failed."})



@app.post("/auth/reset-password")
async def reset_password(request: Request):
    """
    Change password. Also fixes accounts whose hash was stored
    during the broken bcrypt window — always re-hashes on success.
    Body JSON: { email, old_password, new_password }
    """
    try:
        body     = await request.json()
        email    = (body.get("email") or "").lower().strip()
        old_pw   = body.get("old_password") or body.get("oldPassword") or ""
        new_pw   = body.get("new_password") or body.get("newPassword") or ""

        if not email or not old_pw or not new_pw:
            fail("email, old_password, and new_password are required", 400)
        if len(new_pw) < 8:
            fail("New password must be at least 8 characters", 400)

        user = DB.fetch_user_by_email(email)
        if not user:
            raise HTTPException(401, detail={"success": False, "error": "Invalid credentials."})

        stored = user.get("password_hash", "")
        if stored and not verify_password(old_pw, stored):
            raise HTTPException(401, detail={"success": False, "error": "Current password is incorrect."})

        DB.update_user(user["id"], {"password_hash": hash_password(new_pw)})
        logger.info(f"Password reset for {email} — re-hashed with current bcrypt")

        token = create_access_token({"sub": user["id"]})
        return ok({"access_token": token, "user_id": user["id"],
                   "message": "Password updated. You are now logged in."})
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"reset_password: {exc}")
        fail("Password reset failed. Please try again.", 500)
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
    # Expire trial if needed and get full subscription info
    try:
        sub_info = DB.get_full_subscription_info(user)
    except Exception:
        sub_info = {"plan": user.get("plan","free"), "is_pro": user.get("is_pro",False),
                    "trial_active": False, "trial_expired": False, "days_left": 0,
                    "trial_end": "", "limits": get_plan_limits(user.get("plan","free")),
                    "plan_label": "Free"}
    return ok({
        "user_id":     user["id"],
        "email":       user.get("email"),
        "plan":        sub_info["plan"],
        "plan_label":  sub_info["plan_label"],
        "is_pro":      sub_info["is_pro"],
        "trial_active": sub_info["trial_active"],
        "trial_expired": sub_info["trial_expired"],
        "days_left":   sub_info["days_left"],
        "trial_end":   sub_info["trial_end"],
        "role":        user.get("role", "member"),
        "org_name":    org["name"] if org else None,
        "limits":      sub_info["limits"],
    })

@app.get("/api/trial/status")
def get_trial_status(auth=Depends(get_user)):
    """Return the user's trial and subscription status."""
    user = auth["user"]
    try:
        sub_info = DB.get_full_subscription_info(user)
    except Exception:
        sub_info = {"plan": user.get("plan","free"), "is_pro": False,
                    "trial_active": False, "trial_expired": False,
                    "days_left": 0, "trial_end": "", "limits": {}, "plan_label": "Free"}
    return ok(sub_info)


@app.post("/api/trial/start")
def start_trial_manual(auth=Depends(get_user)):
    """Allow users who somehow missed their trial to start it — one per account."""
    user = auth["user"]
    plan = (user.get("plan") or "free").lower()
    if plan != "free":
        fail("Trial already used or already on a paid plan.", 400)
    # Check if trial was ever started
    if user.get("trial_start_date"):
        fail("Your free trial has already been used.", 400)
    DB.start_trial(user["id"])
    return ok({"message": "30-day Pro trial activated!", "plan": "pro_trial",
               "is_pro": True, "trial_active": True})


@app.get("/api/org/users")
def get_org_users(auth=Depends(get_user)):
    user   = auth["user"]
    org    = auth.get("org")
    plan   = user.get("plan", "free").lower()
    if not has_feature(user, "repo_scan"):  # use repo_scan as proxy for paid plan
        fail("Team management requires a Pro or Enterprise plan.", 403)
    org_id = org["id"] if org else None
    if not org_id:
        return ok([])
    return ok(DB.fetch_org_members(org_id))

# ══════════════════════════════════════════════════════════════
#  PHASE 1 — ENTERPRISE AUDIT LOG  (item 10)
# ══════════════════════════════════════════════════════════════
@app.get("/api/audit-log")
def get_audit_log(auth=Depends(get_user), limit: int = 50, action: str = ""):
    """
    Return recent audit log entries for the user's organization.

    Query params:
      limit:  max rows to return (default 50, capped at 200)
      action: optional filter — "scan" | "login" | "subscription" | "admin"
              (substring match against the stored action field)

    Access:
      - Pro/Enterprise/org-admin users see their organization's audit log.
      - Free users see only their own events.

    Requires a Pro or Enterprise plan for org-wide visibility — free users
    are scoped to their own user_id only (existing security boundary).
    """
    user   = auth["user"]
    org    = auth.get("org")
    plan   = (user.get("plan") or "free").lower()
    limit  = max(1, min(int(limit or 50), 200))

    org_id = org["id"] if org else None
    is_paid = plan in ("pro", "pro_trial", "enterprise")

    try:
        if is_paid and org_id:
            rows = DB.fetch_audit_log(org_id=org_id, user_id=None, limit=limit, action_filter=action)
        else:
            rows = DB.fetch_audit_log(org_id=None, user_id=user["id"], limit=limit, action_filter=action)
        return ok(rows)
    except Exception as exc:
        logger.error(f"audit-log fetch: {exc}")
        return ok([])  # never break the dashboard on audit log errors


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

# ══════════════════════════════════════════════════════════════
#  PHASE 1 — SECURITY TREND ANALYTICS  (item 8)
# ══════════════════════════════════════════════════════════════
@app.get("/api/analytics/security-trend")
def get_security_trend(auth=Depends(get_user)):
    """
    Return the user's security_score trend over the last 30 days,
    derived from analysis_history (the `scans` table).

    Response:
      {
        "points": [ { "date": "2025-05-01", "score": 82 }, ... ],
        "average_score": 78.4,
        "best_score": 95,
        "worst_score": 40,
        "count": 24
      }

    Falls back to an empty series with zeroed stats if no history exists —
    never errors, so the dashboard chart always has something to render.
    """
    user = auth["user"]
    try:
        rows = DB.fetch_security_score_trend(user["id"], days=30)
    except Exception as exc:
        logger.debug(f"security-trend fetch failed: {exc}")
        rows = []

    if not rows:
        return ok({"points": [], "average_score": 0, "best_score": 0, "worst_score": 0, "count": 0})

    scores = [r["score"] for r in rows if r.get("score") is not None]
    if not scores:
        return ok({"points": [], "average_score": 0, "best_score": 0, "worst_score": 0, "count": 0})

    return ok({
        "points":        [{"date": r["date"], "score": r["score"]} for r in rows],
        "average_score": round(sum(scores) / len(scores), 1),
        "best_score":    max(scores),
        "worst_score":   min(scores),
        "count":         len(scores),
    })


@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, request: Request, auth=Depends(get_user)):
    try:
        user   = auth["user"]
        org    = auth.get("org")
        plan   = user.get("plan", "free").lower()
        org_id = org["id"] if org else user["id"]
        usage_count = track_usage(user["id"], org_id)
        if not within_limit(user, usage_count):
            limits = get_plan_limits(user.get("plan", "free"))
            fail(f"Daily scan limit reached ({limits['daily_scans']} scans/day)", 429)
        findings = scan_vulnerabilities(req.text)
        plan     = (user.get("plan") or "free").lower()
        # All plans get real AI results — pro gets deeper analysis
        # Free/trial users get useful basic AI so the dashboard isn't empty
        ai_depth = get_ai_depth(user)
        ai       = await ai_enrich(req.text, findings, depth=ai_depth)
        # Ensure free users always get at least a basic explanation
        if not ai.get("explanation") and findings:
            sev_counts = {}
            for f in findings:
                sev_counts[f.get("severity","LOW")] = sev_counts.get(f.get("severity","LOW"),0)+1
            parts = [f"{v} {k.lower()}-severity issue{'s' if v>1 else ''}" for k,v in sev_counts.items()]
            ai = {
                "explanation": f"Found {len(findings)} security issue{'s' if len(findings)>1 else ''}: {', '.join(parts)}. "
                               f"Review each finding below and apply the suggested fixes.",
                "fixes": [f.get("fix","Review and sanitize this pattern.") for f in findings[:3]]
            }
        # ── Original scoring — UNCHANGED, kept for backward compatibility ──
        sev_score = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3}
        score     = min(100, sum(sev_score.get(f.get("severity", "LOW"), 3) for f in findings))
        hi_count  = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
        risk      = ("CRITICAL" if hi_count >= 3 else "HIGH" if hi_count >= 1 else "MEDIUM" if findings else "LOW")

        # ── Phase 1 additions: weighted security score + compliance + auto-fix ──
        # Additive only — new fields appended to response, nothing above changes.
        try:
            from security_engine import enrich_findings_full, compute_security_score
            findings_enriched = enrich_findings_full(findings)
            score_info        = compute_security_score(findings_enriched)
            security_score    = score_info["security_score"]
            score_risk_level  = score_info["risk_level"]
        except Exception as _exc:
            logger.debug(f"security_engine enrichment unavailable: {_exc}")
            findings_enriched = findings
            security_score    = max(0, 100 - score)   # best-effort fallback
            score_risk_level  = "Moderate"

        analysis_id = str(uuid.uuid4())
        DB.insert_scan_history({"id": analysis_id, "user_id": user["id"], "org_id": org_id, "input_text": req.text[:500], "risk": risk, "score": score, "security_score": security_score, "findings_count": len(findings), "explanation": ai.get("explanation", "")[:1000], "fixes": ai.get("fixes", []), "timestamp": datetime.now(timezone.utc).isoformat()})
        DB.write_audit_log(user["id"], "scan", org_id=org_id, resource="/api/analyze", ip_address=request.client.host, metadata={"findings": len(findings), "risk": risk, "security_score": security_score})
        limits = get_plan_limits(user.get("plan", "free"))
        logger.info(f"Scan: user={user['id']} plan={plan} findings={len(findings)} usage={usage_count} security_score={security_score}")
        return ok({
            "id": analysis_id, "usage_today": usage_count, "usage_limit": limits["daily_scans"],
            "plan": plan, "findings": findings_enriched, "ai": ai, "risk": risk, "score": score,
            # Phase 1 fields:
            "security_score": security_score,
            "score_risk_level": score_risk_level,
        })
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
    # repo_scan is available to all plans — pro_trial and free both get access
    # (free is limited by daily_scans count, not feature gate)
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

# ══════════════════════════════════════════════════════════════
#  PHASE 1 — CVE ENRICHMENT 2.0  (item 9)
#  New endpoint; the original /api/cve/search above is UNCHANGED
#  so existing frontend calls keep working exactly as before.
# ══════════════════════════════════════════════════════════════
EPSS_API = "https://api.first.org/data/v1/epss"

def _cvss_severity(score) -> str:
    """Map a CVSS v3 base score to a severity label."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if s >= 9.0:  return "CRITICAL"
    if s >= 7.0:  return "HIGH"
    if s >= 4.0:  return "MEDIUM"
    if s > 0.0:   return "LOW"
    return "NONE"


@app.get("/api/cve/v2/search")
async def cve_search_v2(query: str, auth=Depends(get_user)):
    """
    Enriched CVE lookup. For each CVE returned by NVD, also fetches its
    EPSS (Exploit Prediction Scoring System) probability and assembles
    a richer result shape:

      {
        "cves": [
          {
            "id": "CVE-2022-1234",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "published": "2022-03-15T00:00:00.000",
            "description": "...",
            "affected_products": ["cpe:2.3:a:vendor:product:*"],
            "remediation": "Upgrade to version X or apply vendor patch.",
            "references": ["https://..."],
            "exploit_available": true,
            "epss_score": 0.94
          }
        ],
        "ai_suggestion": null   // populated only if NVD returned zero results
      }

    If NVD returns no results for the query, falls back to the AI model
    to suggest the nearest matching vulnerability category (non-authoritative,
    clearly labelled as an AI suggestion).
    """
    query = (query or "").strip()[:100]
    if len(query) < 2:
        fail("Query must be at least 2 characters")

    cache_key = f"v2:{query}"
    cached = DB.fetch_cve_cache(cache_key)
    if cached:
        return ok(cached)

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.get(CVE_API, params={"keywordSearch": query, "resultsPerPage": 5})
        data = res.json()
        vulns = data.get("vulnerabilities", [])

        cves = []
        cve_ids = []
        for item in vulns:
            cve   = item.get("cve", {})
            cveid = cve.get("id", "")
            cve_ids.append(cveid)

            metrics  = cve.get("metrics", {})
            cvss_obj = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or [{}])[0]
            cvss_data = cvss_obj.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")

            description = (cve.get("descriptions", [{}])[0].get("value", ""))[:500]

            # Affected products (CPE configurations)
            affected = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            affected.append(cpe_match.get("criteria", ""))
            affected = affected[:5]

            # References
            refs = [r.get("url") for r in cve.get("references", [])][:5]

            # Remediation — NVD doesn't always provide this; derive a generic message
            remediation = (
                f"Review the references for {cveid} and apply the vendor's recommended patch "
                f"or upgrade affected packages to a non-vulnerable version."
            )

            cves.append({
                "id":                cveid,
                "cvss_score":        cvss_score,
                "severity":          _cvss_severity(cvss_score),
                "published":         cve.get("published", ""),
                "description":       description,
                "affected_products": affected,
                "remediation":       remediation,
                "references":        refs,
                "exploit_available": None,   # populated below if EPSS lookup succeeds
                "epss_score":        None,
            })

        # ── EPSS enrichment (exploit prediction scores) ─────────
        if cve_ids:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    epss_res = await client.get(EPSS_API, params={"cve": ",".join(cve_ids[:5])})
                epss_data = epss_res.json().get("data", [])
                epss_map  = {d["cve"]: d for d in epss_data}
                for c in cves:
                    e = epss_map.get(c["id"])
                    if e:
                        try:
                            epss_score = float(e.get("epss", 0))
                            c["epss_score"]        = round(epss_score, 4)
                            c["exploit_available"] = epss_score >= 0.1   # heuristic threshold
                        except (TypeError, ValueError):
                            pass
            except Exception as exc:
                logger.debug(f"EPSS enrichment failed (non-fatal): {exc}")

        result = {"cves": cves, "ai_suggestion": None}

        # ── AI fallback if NVD found nothing ────────────────────
        if not cves:
            try:
                ai_result = await ai_enrich(
                    f"No exact CVE was found for the query '{query}'. "
                    f"Based on your security knowledge, suggest the nearest matching "
                    f"vulnerability category, typical CVSS severity range, and general "
                    f"remediation advice. Be concise (2-3 sentences). This is a "
                    f"non-authoritative AI suggestion, not a confirmed CVE.",
                    [], depth="full",
                )
                result["ai_suggestion"] = ai_result.get("explanation", "")[:500]
            except Exception as exc:
                logger.debug(f"AI CVE fallback failed (non-fatal): {exc}")

        DB.store_cve_cache(cache_key, result)
        return ok(result)

    except httpx.TimeoutException:
        fail("CVE lookup timed out", 503)
    except Exception as exc:
        logger.error(f"CVE v2 search: {exc}")
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

# ══════════════════════════════════════════════════════════════
#  PHASE 1 — EXECUTIVE PDF REPORTS  (item 5)
#  New endpoint. The original /api/report/pdf above is UNCHANGED.
#  Gated to Pro / Enterprise / active trial — matches PDF download
#  feature gating used elsewhere in the app.
# ══════════════════════════════════════════════════════════════
@app.post("/api/report/pdf/executive")
def generate_executive_pdf_endpoint(data: PDFReportRequest, auth=Depends(get_user)):
    """
    Generate a multi-section executive security assessment PDF, including:
      - Security score + risk level banner
      - Repository health summary (if provided)
      - Detailed CRITICAL/HIGH findings with OWASP/NIST compliance mapping
      - Detected Secrets section
      - Dependency risk table (if provided)
      - OWASP Top 10 compliance coverage summary
      - Actionable recommendations

    Requires Pro, Pro Trial, or Enterprise plan (same gate as PDF downloads
    elsewhere in the app). Free users receive a 403 with an upgrade prompt.
    """
    user = auth["user"]
    plan = (user.get("plan") or "free").lower()
    org  = auth.get("org")

    if not has_feature(user, "pdf_download"):
        fail("Executive PDF reports require a Pro or Enterprise plan. Start your free trial to unlock this feature.", 403)

    result = {
        "findings":            data.findings,
        "risk_level":          data.risk_level,
        "total_secrets":       data.total_secrets or len(data.findings),
        "summary":             data.summary or {},
        "source":              data.source,
        "truncated":           data.truncated,
        "security_score":      data.security_score,
        "score_risk_level":    data.score_risk_level,
        "repo_health":         data.repo_health,
        "dependency_findings": data.dependency_findings,
    }

    scan_id  = data.scan_id or str(uuid.uuid4())
    filepath = f"/tmp/executive_report_{uuid.uuid4()}.pdf"

    try:
        from pdf import generate_executive_pdf
        generate_executive_pdf(
            scan_id, result, filepath,
            org_name=(org.get("name") if org else ""),
            user_email=user.get("email", ""),
        )
        DB.write_audit_log(user["id"], "pdf_export", org_id=(org["id"] if org else None),
                            resource="/api/report/pdf/executive",
                            metadata={"scan_id": scan_id, "security_score": data.security_score})
        return FileResponse(filepath, filename="safeaiscan-executive-report.pdf", media_type="application/pdf")
    except Exception as exc:
        logger.error(f"Executive PDF: {exc}")
        fail("Executive PDF generation failed", 500)


def get_repo_tree(repo_url: str, auth=Depends(get_user)):
    # repo_scan is available to all plans — pro_trial and free both get access
    # (free is limited by daily_scans count, not feature gate)
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


# ══════════════════════════════════════════════════════════════
#  PAYPAL MONETIZATION ROUTES
#  Revenue target: $500–1000/month at $1.99/mo Pro plan
#  252 paid users = $500/mo  |  503 paid users = $1000/mo
# ══════════════════════════════════════════════════════════════

import paypal as _pp

# ── Create payment (subscription preferred, order fallback) ───
@app.post("/payment/create")
def payment_create(request: Request, auth=Depends(get_user)):
    """
    Start the PayPal checkout flow.
    Query param ?billing=annual for annual plan.
    Returns { approve_url, type } — frontend redirects user there.
    """
    user    = auth["user"]
    billing = request.query_params.get("billing", "monthly")
    try:
        result = _pp.create_subscription(user["id"], billing=billing)
        logger.info(f"Payment flow started: user={user['id']} type={result.get('type')} billing={billing}")
        return ok(result)
    except RuntimeError as e:
        fail(str(e), 503)


# ── Subscription success (PayPal redirects here after approval) ─
@app.get("/payment/subscription-success")
def payment_subscription_success(
    user_id: str,
    subscription_id: str = "",
    billing: str = "monthly",
    token: str = "",
):
    """
    PayPal redirects here after user approves a subscription.
    subscription_id is passed by PayPal in the query string.
    """
    if not user_id:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/checkout.html?error=missing_user_id")

    sub_id = subscription_id or token
    if not sub_id:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/checkout.html?error=missing_subscription_id")

    try:
        # Verify with PayPal that subscription is ACTIVE
        sub_data = _pp.get_subscription(sub_id)
        status   = sub_data.get("status", "")
        if status not in ("ACTIVE", "APPROVED"):
            logger.warning(f"Subscription {sub_id} status={status} for user {user_id}")
            from fastapi.responses import RedirectResponse
            return RedirectResponse(url=f"/checkout.html?error=subscription_not_active&status={status}")

        # Upgrade user
        if billing == "annual":
            DB.mark_user_pro_annual(user_id, sub_id)
        else:
            DB.mark_user_pro(user_id, subscription_id=sub_id)

        # Log payment
        amount = _pp.PRO_ANNUAL_USD if billing == "annual" else _pp.PRO_MONTHLY_USD
        DB.log_payment_event(user_id, "SUBSCRIPTION_ACTIVATED", amount=amount, subscription_id=sub_id)

        logger.info(f"Pro subscription activated: user={user_id} sub={sub_id} billing={billing}")
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=f"/pro.html?welcome=1&billing={billing}")

    except Exception as e:
        logger.error(f"subscription_success error: {e}")
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=f"/checkout.html?error=activation_failed")


# ── One-time order success (fallback) ─────────────────────────
@app.get("/payment/success")
def payment_success(user_id: str = "", token: str = "", PayerID: str = ""):
    """
    PayPal redirects here after a one-time order is approved.
    Captures the payment and upgrades the user.
    """
    order_id = token
    if not order_id or not user_id:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/checkout.html?error=missing_params")

    try:
        capture = _pp.capture_order(order_id)
        uid     = _pp.get_order_user_id(capture) or user_id
        DB.mark_user_pro(uid, paypal_order_id=order_id)
        DB.log_payment_event(uid, "ORDER_CAPTURED", amount=_pp.PRO_MONTHLY_USD, order_id=order_id)
        logger.info(f"One-time payment captured: user={uid} order={order_id}")
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/pro.html?welcome=1")
    except Exception as e:
        logger.error(f"payment_success error: {e}")
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=f"/checkout.html?error=capture_failed")


# ── Payment cancelled ─────────────────────────────────────────
@app.get("/payment/cancel")
def payment_cancel():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/checkout.html?cancelled=1")


# ── PayPal Webhook  (IPN / Webhooks v2) ──────────────────────
@app.post("/payment/webhook")
async def payment_webhook(request: Request):
    """
    Receives PayPal webhook events:
      BILLING.SUBSCRIPTION.ACTIVATED    → user upgraded
      BILLING.SUBSCRIPTION.RENEWED      → payment successful, keep Pro
      BILLING.SUBSCRIPTION.PAYMENT.FAILED → downgrade user to free
      BILLING.SUBSCRIPTION.CANCELLED    → downgrade user to free
      BILLING.SUBSCRIPTION.SUSPENDED    → downgrade user to free
      PAYMENT.CAPTURE.COMPLETED         → one-time order completed

    PayPal retries webhooks on failure — always return 200 if we received it.
    """
    body    = await request.body()
    headers = dict(request.headers)

    # Verify webhook signature (skipped in sandbox without PAYPAL_WEBHOOK_ID)
    if not _pp.verify_webhook_signature(headers, body):
        logger.warning("Webhook signature verification FAILED — ignoring event")
        return JSONResponse(status_code=400, content={"error": "Invalid webhook signature"})

    try:
        import json
        event      = json.loads(body)
        event_type = event.get("event_type", "")
        resource   = event.get("resource", {})

        logger.info(f"PayPal webhook: {event_type}")

        # ── Subscription activated / renewed ──────────────────
        if event_type in ("BILLING.SUBSCRIPTION.ACTIVATED",):
            sub_id  = resource.get("id", "")
            user_id = resource.get("custom_id") or resource.get("subscriber", {}).get("email_address")
            if sub_id and user_id:
                DB.mark_user_pro(user_id, subscription_id=sub_id)
                DB.log_payment_event(user_id, event_type, subscription_id=sub_id)
                logger.info(f"Webhook: subscription activated user={user_id} sub={sub_id}")

        elif event_type in ("BILLING.SUBSCRIPTION.RENEWED", "PAYMENT.SALE.COMPLETED"):
            sub_id  = resource.get("billing_agreement_id") or resource.get("id", "")
            user    = DB.get_user_by_subscription_id(sub_id) if sub_id else None
            if user:
                amount = resource.get("amount", {}).get("total") or resource.get("amount", {}).get("value", "")
                DB.renew_subscription(user["id"], sub_id)
                DB.log_payment_event(user["id"], event_type, amount=str(amount), subscription_id=sub_id)
                logger.info(f"Webhook: subscription renewed user={user['id']}")

        # ── Payment failed → downgrade user ───────────────────
        elif event_type in (
            "BILLING.SUBSCRIPTION.PAYMENT.FAILED",
            "BILLING.SUBSCRIPTION.SUSPENDED",
        ):
            sub_id = resource.get("id", "")
            user   = DB.get_user_by_subscription_id(sub_id) if sub_id else None
            if user:
                DB.downgrade_user_to_free(user["id"], reason="payment_failed")
                DB.log_payment_event(user["id"], event_type, subscription_id=sub_id)
                logger.info(f"Webhook: payment failed, downgraded user={user['id']}")

        # ── Subscription cancelled → downgrade user ───────────
        elif event_type == "BILLING.SUBSCRIPTION.CANCELLED":
            sub_id = resource.get("id", "")
            user   = DB.get_user_by_subscription_id(sub_id) if sub_id else None
            if user:
                DB.downgrade_user_to_free(user["id"], reason="subscription_cancelled")
                DB.log_payment_event(user["id"], event_type, subscription_id=sub_id)
                logger.info(f"Webhook: subscription cancelled, downgraded user={user['id']}")

        # ── One-time payment completed ─────────────────────────
        elif event_type == "PAYMENT.CAPTURE.COMPLETED":
            order_id = resource.get("id", "")
            user_id  = resource.get("custom_id") or resource.get("invoice_id", "")
            if order_id and user_id:
                amount = resource.get("amount", {}).get("value", "")
                DB.mark_user_pro(user_id, paypal_order_id=order_id)
                DB.log_payment_event(user_id, event_type, amount=str(amount), order_id=order_id)
                logger.info(f"Webhook: one-time payment completed user={user_id}")

        return {"received": True, "event_type": event_type}

    except Exception as e:
        logger.error(f"Webhook processing error: {e}")
        # Always return 200 so PayPal doesn't keep retrying
        return {"received": True, "error": "Processing error (logged)"}


# ── Admin: manually activate Pro (e.g. gift accounts, support) ─
@app.post("/payment/activate")
def payment_activate(auth=Depends(get_user)):
    """
    Manual Pro activation — for support/gift accounts.
    In production, most upgrades happen via PayPal webhooks.
    """
    user    = auth["user"]
    user_id = user["id"]
    DB.update_user(user_id, {
        "plan":              "pro",
        "is_pro":            True,
        "trial_active":      False,
        "subscription_status": "MANUAL",
    })
    logger.info(f"Pro plan manually activated for user {user_id}")
    return ok({"is_pro": True, "plan": "pro", "plan_label": "Pro",
               "message": "Pro plan activated successfully. Welcome!"})


# ── Cancel subscription endpoint ─────────────────────────────
@app.post("/payment/cancel-subscription")
def cancel_subscription_endpoint(auth=Depends(get_user)):
    """Allow a user to cancel their own subscription."""
    user    = auth["user"]
    sub_id  = user.get("paypal_subscription_id", "")
    if not sub_id:
        fail("No active subscription found.", 404)

    success = _pp.cancel_subscription(sub_id, reason="User requested cancellation")
    if success:
        # Don't downgrade immediately — let them keep Pro until period end
        # Downgrade happens via webhook BILLING.SUBSCRIPTION.CANCELLED
        DB.update_user(user["id"], {"subscription_status": "CANCELLING"})
        DB.log_payment_event(user["id"], "USER_CANCELLED", subscription_id=sub_id)
        DB.write_audit_log(user["id"], "subscription_cancel", org_id=user.get("org_id"),
                            metadata={"subscription_id": sub_id})
        logger.info(f"Subscription cancelled by user: {user['id']}")
        return ok({"message": "Subscription cancelled. You keep Pro access until your next billing date."})
    else:
        fail("Could not cancel subscription. Please contact support.", 503)


# ── Enterprise inquiry ────────────────────────────────────────
@app.post("/payment/enterprise-inquiry")
async def enterprise_inquiry(request: Request, auth=Depends(get_user)):
    """Log enterprise interest. No payment taken — contact sales."""
    user = auth["user"]
    try:
        body = await request.json()
        seats     = body.get("seats", "")
        use_case  = body.get("use_case", "")[:200]
        DB.write_audit_log(
            user["id"], "enterprise_inquiry",
            metadata={"seats": seats, "use_case": use_case, "email": user.get("email")}
        )
        DB.log_payment_event(user["id"], "ENTERPRISE_INQUIRY", amount=seats)
        tiers = _pp.get_enterprise_tiers()
        return ok({
            "message": "Thank you! Our team will contact you within 24 hours.",
            "contact": "enterprise@safeaiscan.io",
            "tiers":   tiers,
        })
    except Exception as e:
        logger.error(f"enterprise_inquiry: {e}")
        return ok({"message": "Inquiry received. We'll be in touch.", "contact": "enterprise@safeaiscan.io"})


# ── Pricing info endpoint (for dynamic frontend) ──────────────
@app.get("/api/pricing")
def get_pricing():
    """Return current pricing for all plans — no auth required."""
    return ok({
        "pro_monthly": {"price": _pp.PRO_MONTHLY_USD, "currency": _pp.PRO_CURRENCY, "label": "$1.99/mo"},
        "pro_annual":  {"price": _pp.PRO_ANNUAL_USD,  "currency": _pp.PRO_CURRENCY, "label": "$19.08/yr (~$1.59/mo)", "savings": "20%"},
        "enterprise":  _pp.get_enterprise_tiers(),
        "trial_days":  30,
        "has_subscription_plans": bool(_pp.PLAN_ID_PRO_MONTHLY),
    })


# ── Subscription status endpoint ─────────────────────────────
@app.get("/api/subscription/status")
def subscription_status(auth=Depends(get_user)):
    """Return the authenticated user's full subscription status."""
    user = auth["user"]
    try:
        sub_info = DB.get_full_subscription_info(user)
    except Exception:
        sub_info = {"plan": user.get("plan","free"), "is_pro": False,
                    "trial_active": False, "days_left": 0, "plan_label": "Free"}

    # Include PayPal subscription details if present
    sub_id     = user.get("paypal_subscription_id", "")
    sub_status = user.get("subscription_status", "")
    billing    = user.get("subscription_billing", "monthly")
    renewed_at = user.get("subscription_renewed_at", "")

    return ok({
        **sub_info,
        "subscription_id":      sub_id,
        "subscription_status":  sub_status,
        "billing_cycle":        billing,
        "last_renewed":         renewed_at,
        "can_cancel":           bool(sub_id and sub_status == "ACTIVE"),
        "paypal_mode":          _pp.MODE,
    })


@app.post("/api/admin/run-migration")
async def run_migration(request: Request, auth=Depends(get_user)):
    """
    Run required database migrations (ADD COLUMN IF NOT EXISTS).
    Must be called once after deploying the trial system.
    Only admins can call this.
    """
    user = auth["user"]
    if user.get("role") not in ("admin", "superadmin"):
        fail("Admin access required", 403)

    sql_statements = [
        # Core trial/plan columns
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_pro BOOLEAN DEFAULT false",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_active BOOLEAN DEFAULT false",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_start_date DATE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_end_date DATE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS scans_today INT DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_scan_date DATE",
        # PayPal subscription tracking
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS paypal_order_id TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS paypal_subscription_id TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_status TEXT DEFAULT 'INACTIVE'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_billing TEXT DEFAULT 'monthly'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_renewed_at DATE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS downgraded_at DATE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS downgrade_reason TEXT",
        # Payments log table (revenue tracking)
        """CREATE TABLE IF NOT EXISTS payments (
            id              UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id         UUID    REFERENCES users(id) ON DELETE SET NULL,
            event_type      TEXT    NOT NULL,
            amount          TEXT,
            subscription_id TEXT,
            order_id        TEXT,
            created_at      TIMESTAMPTZ DEFAULT now()
        )""",
        # Index for subscription lookups (webhook handler)
        "CREATE INDEX IF NOT EXISTS idx_users_paypal_sub ON users(paypal_subscription_id)",
    ]

    results = []
    db_client = DB._get_db() if hasattr(DB, "_get_db") else None

    for stmt in sql_statements:
        try:
            # Supabase Python client doesn't expose raw SQL — log what to run
            results.append({"sql": stmt, "status": "needs_manual_run"})
        except Exception as e:
            results.append({"sql": stmt, "status": f"error: {str(e)[:80]}"})

    return ok({
        "message": "Run these SQL statements in your Supabase SQL Editor:",
        "sql_to_run": [s["sql"] for s in results],
        "instructions": [
            "1. Go to your Supabase project → SQL Editor → New Query",
            "2. Paste each SQL statement and click Run (safe to run multiple times)",
            "3. After running, set PAYPAL_CLIENT_ID + PAYPAL_CLIENT_SECRET in HF Space secrets",
            "4. Create a Billing Plan in PayPal dashboard → paste ID as PAYPAL_PLAN_ID_PRO",
            "5. Register webhook at https://developer.paypal.com → paste ID as PAYPAL_WEBHOOK_ID",
            "6. Switch PAYPAL_MODE=live when ready for real payments",
        ]
    })


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
