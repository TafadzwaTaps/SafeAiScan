import os
import uuid
import hashlib
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import jwt, JWTError
from supabase import create_client

# =========================================================
# APP
# =========================================================
app = FastAPI(title="SafeAIScan Enterprise SaaS Layer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
ALGORITHM = "HS256"

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# =========================================================
# AI MODEL
# =========================================================
HF_MODEL_URL = "https://router.huggingface.co/hf-inference/models/HuggingFaceH4/zephyr-7b-beta"


# =========================================================
# AUTH
# =========================================================
def verify_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except JWTError:
        return None


def hash_key(key: str):
    return hashlib.sha256(key.encode()).hexdigest()


# =========================================================
# API KEY GENERATION (ENTERPRISE FEATURE)
# =========================================================
@app.post("/auth/create-api-key")
def create_api_key(user_id: str):
    raw_key = f"saas_{uuid.uuid4().hex}"
    hashed = hash_key(raw_key)

    supabase.table("users").update({
        "api_key_hash": hashed
    }).eq("id", user_id).execute()

    return {
        "api_key": raw_key
    }


# =========================================================
# USER AUTH + TENANT RESOLUTION
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

    user_id = payload["sub"]

    user_res = supabase.table("users").select("*").eq("id", user_id).execute()

    if not user_res.data:
        raise HTTPException(403, "User not found")

    user = user_res.data[0]

    if not x_api_key:
        raise HTTPException(403, "Missing API key")

    if user["api_key_hash"] != hash_key(x_api_key):
        raise HTTPException(403, "Invalid API key")

    org = supabase.table("organizations").select("*").eq("id", user["org_id"]).execute()

    return {
        "user": user,
        "org": org.data[0] if org.data else None
    }


# =========================================================
# USAGE TRACKING (REAL SAAS LIMITS)
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


# =========================================================
# RATE LIMIT (ENTERPRISE DB VERSION)
# =========================================================
def check_limit(count: int, limit: int = 50):
    return count <= limit


# =========================================================
# MODELS
# =========================================================
class AnalyzeRequest(BaseModel):
    text: str


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
            HF_MODEL_URL,
            headers={"Authorization": f"Bearer {HF_API_KEY}"},
            json={
                "inputs": f"""
You are a cybersecurity expert.

Findings:
{findings}

Return JSON:
{{
  "explanation": "",
  "fixes": []
}}

Code:
{text[:2000]}
"""
            }
        )

    data = res.json()

    try:
        if isinstance(data, list):
            return data[0]
        return data
    except:
        return {
            "explanation": "AI parsing failed",
            "fixes": ["Manual review required"]
        }


# =========================================================
# SECURITY ENGINE
# =========================================================
def scan_vulnerabilities(text: str):
    patterns = ["eval(", "exec(", "os.system", "pickle.loads", "curl", "wget"]

    return [
        {"match": p}
        for p in patterns if p in text
    ]


# =========================================================
# MAIN ENTERPRISE ENDPOINT
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
# USAGE DASHBOARD API
# =========================================================
@app.get("/api/usage")
def usage(auth=Depends(get_user)):
    user = auth["user"]

    data = supabase.table("usage_metrics") \
        .select("*") \
        .eq("user_id", user["id"]) \
        .execute()

    return data.data

@app.get("/")
def home():
    return {"status": "SafeAIScan running on Hugging Face Spaces"}

# IMPORTANT: HF uses port 7860 internally