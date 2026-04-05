import os
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from fastapi.security import HTTPBearer , HTTPAuthorizationCredentials
import httpx
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from auth import create_access_token, verify_token
from supabase import create_client
from scanner import safe_clone, validate_repo, full_scan
from fastapi import BackgroundTasks
from github import Github
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from tasks import run_scan
from store import tasks_store
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

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
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
security = HTTPBearer()

# =========================================================
# PASSWORD SYSTEM
# =========================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password[:72])

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

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

class RepoRequest(BaseModel):
    repo_url: str

class AIExplainRequest(BaseModel):
    question: str
    context: str

# =========================================================
# REGISTER (FULL ONBOARDING)
# =========================================================
@app.post("/auth/register")
def register(req: RegisterRequest):
    try:
        print("Incoming request:", req)

        user_id = str(uuid.uuid4())
        org_id = str(uuid.uuid4())

        print("Creating org...")

        org_res = supabase.table("organizations").insert({
            "id": org_id,
            "name": req.org_name
        }).execute()

        print("ORG RESULT:", org_res)

        print("Creating user...")

        password_hash = hash_password(req.password)

        user_res = supabase.table("users").insert({
            "id": user_id,
            "email": req.email,
            "password_hash": password_hash,
            "org_id": org_id,
            "api_key_hash": None
        }).execute()

        print("USER RESULT:", user_res)

        raw_key = f"saas_{uuid.uuid4().hex}"
        api_hash = hash_key(raw_key)

        supabase.table("users").update({
            "api_key_hash": api_hash
        }).eq("id", user_id).execute()

        token = create_access_token({"sub": user_id})

        return {
            "access_token": token,
            "api_key": raw_key
        }

    except Exception as e:
        print("🔥 REGISTER ERROR:", str(e))
        raise HTTPException(500, str(e))

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
    if x_api_key and x_api_key != "undefined":
        if user["api_key_hash"] != hash_key(x_api_key):
            raise HTTPException(403, "Invalid API key")

    org = supabase.table("organizations").select("*").eq("id", user["org_id"]).execute()
    print("AUTH HEADER:", authorization)
    print("TOKEN:", token)
    print("PAYLOAD:", payload)

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

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            res = await client.post(
    "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2",
    headers={
        "Authorization": f"Bearer {HF_API_KEY}",
        "Content-Type": "application/json"
    },
    json={
        "inputs": f"""
Return ONLY JSON.

Format:
{{ "explanation": "string", "fixes": ["string"] }}

Code:
{text[:1500]}
"""
    }
            )

        # SAFE PARSE
        try:
            data = res.json()
        except Exception as e:
            print("🔥 AI JSON PARSE ERROR:", str(e))
            print("RAW RESPONSE:", res.text)

            return {
                "explanation": res.text[:500],
                "fixes": []
            }

        # HANDLE HF FORMAT
        if isinstance(data, list):
            data = data[0]

        # HANDLE GENERATED TEXT
        if isinstance(data, dict) and "generated_text" in data:
            text_output = data["generated_text"]

            try:
                import json
                parsed = json.loads(text_output)
                return parsed
            except:
                return {
                    "explanation": text_output[:500],
                    "fixes": []
                }

        if isinstance(data, dict):
            return data

        return {
            "explanation": str(data),
            "fixes": []
        }

    except Exception as e:
        print("🔥 AI REQUEST ERROR:", str(e))
        return {
            "explanation": "AI request failed",
            "fixes": []
        }

# =========================================================
# MAIN ENDPOINT
# =========================================================
@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, auth=Depends(get_user)):
    try:
        user = auth["user"]
        org = auth.get("org")

        if not org:
            raise HTTPException(500, "Organization not found")

        usage_count = track_usage(user["id"], org["id"])

        if not check_limit(usage_count):
            raise HTTPException(429, "Usage limit exceeded")

        findings = scan_vulnerabilities(req.text)

        ai = await ai_enrich(req.text, findings)

        analysis_id = str(uuid.uuid4())

        result = supabase.table("analysis_history").insert({
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

        print("INSERT RESULT:", result)

        return {
            "id": analysis_id,
            "usage_today": usage_count,
            "findings": findings,
            "ai": ai
        }

    except Exception as e:
        print("🔥 ANALYZE ERROR:", str(e))
        raise HTTPException(500, str(e))

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

@app.get("/api/me")
def get_me(auth=Depends(get_user)):
    user = auth["user"]

    return {
        "plan": user.get("plan", "free")
    }

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

@app.post("/api/scan-repo")
def scan_repo(req: RepoRequest, background_tasks: BackgroundTasks, auth=Depends(get_user)):
    user = auth["user"]
    org = auth["org"]

    task_id = str(uuid.uuid4())

    tasks_store[task_id] = {
        "state": "QUEUED",
        "result": None
    }

    background_tasks.add_task(
        run_scan,
        task_id,
        req.repo_url,
        user["id"],
        org["id"]
    )

    return {
        "status": "queued",
        "task_id": task_id
    }


@app.get("/api/task/{task_id}")
def get_task(task_id: str):
    return tasks_store.get(task_id, {"state": "NOT_FOUND"})

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()

    try:
        while True:
            await ws.send_json({
                "type": "progress",
                "value": 50,
                "message": "Scanning..."
            })
    except WebSocketDisconnect:
        print("Client disconnected")


@app.get("/api/repo/tree")
def get_repo_tree(repo_url: str, auth=Depends(get_user)):
    try:
        g = Github(GITHUB_TOKEN)

        repo_name = repo_url.replace("https://github.com/", "")
        repo = g.get_repo(repo_name)

        contents = repo.get_contents("")

        def build_tree(contents):
            tree = []
            for file in contents:
                node = {
                    "name": file.name,
                    "path": file.path,
                    "type": file.type
                }

                if file.type == "dir":
                    node["children"] = build_tree(repo.get_contents(file.path))

                tree.append(node)
            return tree

        return build_tree(contents)

    except Exception as e:
        raise HTTPException(500, str(e))
    
@app.post("/api/ai/explain")
async def ai_explain(req: AIExplainRequest, auth=Depends(get_user)):
    result = await ai_enrich(req.context + "\n\nQuestion: " + req.question, [])
    return result

@app.post("/api/report/pdf")
def generate_pdf(data: dict, auth=Depends(get_user)):
    file_path = f"/tmp/report_{uuid.uuid4()}.pdf"

    doc = SimpleDocTemplate(file_path)
    styles = getSampleStyleSheet()

    content = []

    content.append(Paragraph("SafeAIScan Report", styles["Title"]))

    for f in data.get("findings", []):
        content.append(Paragraph(f"{f.get('match')} - {f.get('severity','HIGH')}", styles["Normal"]))

    doc.build(content)

    return FileResponse(file_path, filename="report.pdf")

@app.get("/api/org/users")
def get_org_users(auth=Depends(get_user)):
    org_id = auth["org"]["id"]

    res = supabase.table("users").select("email").eq("org_id", org_id).execute()

    return res.data