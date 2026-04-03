import os
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from fastapi.security import HTTPBearer , HTTPAuthorizationCredentials
import httpx
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext
from auth import create_access_token, verify_token
from supabase import create_client

# =========================================================
# APP
# =========================================================
app = FastAPI(title="SafeAIScan Enterprise SaaS Layer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:5500",
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


supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
security = HTTPBearer()

# =========================================================
# PASSWORD SYSTEM
# =========================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    payload = verify_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return payload

# =========================================================
# HELPERS
# =========================================================
def hash_key(key: str):
    return hashlib.sha256(key.encode()).hexdigest()

# =========================================================
# AUTH MODELS
# =========================================================
class RegisterRequest(BaseModel):
    email: str
    password: str
    org_name: str

class LoginRequest(BaseModel):
    email: str
    password: str

class AnalyzeRequest(BaseModel):
    text: str

# =========================================================
# REGISTER (FULL ONBOARDING)
# =========================================================
@app.post("/auth/register")
def register(req: RegisterRequest):
    existing = supabase.table("users").select("*").eq("email", req.email).execute()

    if existing.data:
        raise HTTPException(400, "User already exists")

    user_id = str(uuid.uuid4())
    org_id = str(uuid.uuid4())

    # create org
    supabase.table("organizations").insert({
        "id": org_id,
        "name": req.org_name
    }).execute()

    # create user
    password_hash = hash_password(req.password)

    supabase.table("users").insert({
        "id": user_id,
        "email": req.email,
        "password_hash": password_hash,
        "org_id": org_id,
        "api_key_hash": None
    }).execute()

    # generate API key (auto onboarding)
    raw_key = f"saas_{uuid.uuid4().hex}"
    api_hash = hash_key(raw_key)

    supabase.table("users").update({
        "api_key_hash": api_hash
    }).eq("id", user_id).execute()

    # init usage row
    supabase.table("usage_metrics").insert({
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "org_id": org_id,
        "date": str(datetime.utcnow().date()),
        "request_count": 0
    }).execute()

    token = create_access_token({"sub": user["id"]})

    return {
        "access_token": token,
        "api_key": raw_key,
        "user_id": user_id,
        "org_id": org_id
    }

# =========================================================
# LOGIN
# =========================================================
@app.post("/auth/login")
def login(req: LoginRequest):
    user_res = supabase.table("users").select("*").eq("email", req.email).execute()

    if not user_res.data:
        raise HTTPException(401, "Invalid credentials")

    user = user_res.data[0]

    if not verify_password(req.password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")

    token = create_access_token({"sub": user["id"]})

    return {
        "access_token": token,
        "api_key": None,  # 👈 IMPORTANT (user must reuse saved one)
        "user_id": user["id"],
        "org_id": user["org_id"]
    }

# =========================================================
# API KEY GENERATION (manual rotation)
# =========================================================
@app.post("/auth/create-api-key")
def create_api_key(user_id: str):
    raw_key = f"saas_{uuid.uuid4().hex}"
    hashed = hash_key(raw_key)

    supabase.table("users").update({
        "api_key_hash": hashed
    }).eq("id", user_id).execute()

    return {"api_key": raw_key}

# =========================================================
# AUTH + TENANT RESOLUTION
# =========================================================
def get_user(
    authorization: str = Header(None),
    x_api_key: str = Header(None)
):
    if not authorization:
        raise HTTPException(401, "Missing token")

    token = authorization.replace("Bearer ", "")
    payload = verify_token(token)

    if not payload:
        raise HTTPException(401, "Invalid token")

    user_id = payload.get("sub")

    user_res = supabase.table("users").select("*").eq("id", user_id).execute()

    if not user_res.data:
        raise HTTPException(403, "User not found")

    user = user_res.data[0]

    # OPTIONAL MODE: allow API key OR JWT (fixes your frontend pain)
    if x_api_key:
        if user["api_key_hash"] != hash_key(x_api_key):
            raise HTTPException(403, "Invalid API key")

    org = supabase.table("organizations").select("*").eq("id", user["org_id"]).execute()

    return {
        "user": user,
        "org": org.data[0] if org.data else None
    }

# =========================================================
# USAGE TRACKING
# =========================================================
def track_usage(user_id: str, org_id: str):
    today = datetime.utcnow().date()

    record = supabase.table("usage_metrics") \
        .select("*") \
        .eq("user_id", user_id) \
        .eq("date", str(today)) \
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
        "date": str(today),
        "request_count": 1
    }).execute()

    return 1

def check_limit(count: int, limit: int = 50):
    return count <= limit

# =========================================================
# SECURITY ENGINE
# =========================================================
def scan_vulnerabilities(text: str):
    patterns = ["eval(", "exec(", "os.system", "pickle.loads", "curl", "wget"]

    return [{"match": p} for p in patterns if p in text]

# =========================================================
# AI ENGINE
# =========================================================
async def ai_enrich(text: str, findings):
    if not HF_API_KEY:
        return {
            "explanation": "AI disabled",
            "fixes": ["Set HF_API_KEY"]
        }

    async with httpx.AsyncClient(timeout=30) as client:
        res = await client.post(
            "https://router.huggingface.co/hf-inference/models/HuggingFaceH4/zephyr-7b-beta",
            headers={"Authorization": f"Bearer {HF_API_KEY}"},
            json={
                "inputs": f"""
You are a cybersecurity expert.

Findings:
{findings}

Return JSON:
{{ "explanation": "", "fixes": [] }}

Code:
{text[:2000]}
"""
            }
        )

    data = res.json()

    if isinstance(data, list):
        return data[0]

    return data

# =========================================================
# MAIN ENDPOINT
# =========================================================
@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, auth=Depends(get_user)):
    user = auth["user"]
    org = auth["org"]

    usage_count = track_usage(user["id"], org["id"])

    if not check_limit(usage_count):
        raise HTTPException(429, "Usage limit exceeded")

    findings = scan_vulnerabilities(req.text)
    ai = await ai_enrich(req.text, findings)

    analysis_id = str(uuid.uuid4())

    supabase.table("analysis_history").insert({
        "id": analysis_id,
        "user_id": user["id"],
        "org_id": org["id"],
        "input_text": req.text,
        "risk": "AUTO",
        "score": len(findings) * 20,
        "explanation": ai.get("explanation"),
        "fixes": ai.get("fixes"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }).execute()

    return {
        "id": analysis_id,
        "usage_today": usage_count,
        "findings": findings,
        "ai": ai
    }

# =========================================================
# USAGE DASHBOARD
# =========================================================
@app.get("/api/usage")
def usage(auth=Depends(get_user)):
    user = auth["user"]

    data = supabase.table("usage_metrics") \
        .select("*") \
        .eq("user_id", user["id"]) \
        .execute()

    return data.data

# =========================================================
# HEALTH CHECK
# =========================================================
@app.get("/")
def home():
    return {"status": "SafeAIScan running on Hugging Face Spaces"}

@app.get("/api/history")
def history(auth=Depends(get_user)):
    user = auth["user"]

    res = supabase.table("analysis_history") \
        .select("*") \
        .eq("user_id", user["id"]) \
        .order("timestamp", desc=True) \
        .limit(20) \
        .execute()

    return res.data