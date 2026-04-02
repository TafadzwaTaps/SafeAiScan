# ========================= IMPORTS (UNCHANGED + ADDED) =========================
from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from typing import List, Dict
import git, os, re, json, uuid, sqlite3, logging, hashlib
from datetime import datetime, timezone, timedelta
import httpx
import jwt  # ✅ NEW

# ========================= INIT (UNCHANGED) =========================
templates = Jinja2Templates(directory="templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

USERS = {
    "master": "Matrix123!"
}

DB_PATH = "security_analysis.db"
HF_API_KEY = os.environ.get("HF_API_KEY")
HF_MODEL_URL = "https://router.huggingface.co/hf-inference/models/HuggingFaceH4/zephyr-7b-beta"

SECRET_KEY = "#SafeAiScan@2026" # ✅ NEW
ALGORITHM = "HS256"

# ========================= APP =========================
app = FastAPI(title="SafeAIScan Enterprise Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========================= DATABASE =========================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ORIGINAL TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_history (
            id TEXT PRIMARY KEY,
            input_text TEXT,
            risk TEXT,
            score REAL,
            explanation TEXT,
            fixes TEXT,
            timestamp TEXT
        )
    """)

    # ✅ NEW USERS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            api_key TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ========================= AUTH =========================
def create_token(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=10)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    return payload["sub"]

# ========================= MODEL =========================
class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=5, max_length=20000)

# ========================= SIGNATURE ENGINE (UNCHANGED) =========================
SIGNATURES = {
    "SQL Injection": (r"(SELECT .* FROM .* WHERE .*['\"]?\s*\+|\bOR\b\s+1=1|DROP TABLE)", 9),
    "XSS": (r"(<script>|javascript:|onerror=|onload=|alert\()", 8),
    "Command Injection": (r"(;|\|\||&&)\s*(rm|ls|cat|whoami|bash|sh)", 10),
    "Path Traversal": (r"(\.\./|\.\.\\)", 7),
    "Hardcoded Secrets": (r"(api_key|password|secret|token)\s*=\s*['\"]", 8),
    "Insecure Deserialization": (r"(pickle\.loads|yaml\.load\(|marshal\.loads)", 9),
}

def scan_vulnerabilities(text: str) -> List[Dict]:
    findings = []
    for name, (pattern, weight) in SIGNATURES.items():
        if re.search(pattern, text, re.IGNORECASE):
            findings.append({"type": name, "weight": weight})
    return findings

# ========================= RISK ENGINE =========================
def calculate_risk(findings: List[Dict]) -> Dict:
    if not findings:
        return {"risk": "Low", "score": 0}

    total = sum(f["weight"] for f in findings)
    score = min(total, 10)

    if total >= 18:
        level = "Critical"
    elif total >= 12:
        level = "High"
    elif total >= 6:
        level = "Medium"
    else:
        level = "Low"

    return {"risk": level, "score": score}

# ========================= EXPLANATION =========================
def build_explanation(findings: List[Dict]) -> str:
    if not findings:
        return "No vulnerabilities detected in static analysis."
    return "Detected vulnerabilities: " + ", ".join([f["type"] for f in findings])

# ========================= AI =========================
async def ai_enrich(text: str, findings: List[Dict]):
    if not HF_API_KEY:
        return {"explanation": "AI disabled", "fixes": []}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                HF_MODEL_URL,
                headers={"Authorization": f"Bearer {HF_API_KEY}"},
                json={"inputs": f"Explain vulnerabilities: {findings}"}
            )

        data = response.json()
        output = data[0].get("generated_text", "") if isinstance(data, list) else str(data)

        return {
            "explanation": output,
            "fixes": ["Validate input", "Use secure coding practices"]
        }

    except:
        return {"explanation": "AI unavailable", "fixes": []}

# ========================= MAIN ENGINE (FIXED) =========================
async def analyze_engine(text: str):

    findings = scan_vulnerabilities(text)
    risk_data = calculate_risk(findings)
    ai_data = await ai_enrich(text, findings)

    fixes = ai_data.get("fixes")

    if not isinstance(fixes, list):
        fixes = ["Sanitize inputs", "Validate input data"]

    confidence = min(100, len(findings) * 20)  # ✅ NEW

    return {
        "risk": risk_data["risk"],
        "score": risk_data["score"],
        "confidence": confidence,
        "findings": findings,
        "explanation": build_explanation(findings) + ". " + ai_data.get("explanation", ""),
        "fixes": fixes
    }

# ========================= ROUTES =========================
@app.get("/")
def root():
    return {"status": "SafeAIScan Enterprise Running"}

@app.get("/debug")
def debug():
    return {"ok": True}

# ---------------- AUTH ----------------
@app.post("/login")
def login(username: str, password: str):
    if USERS.get(username) != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token({"sub": username})
    return {"access_token": token}

# ---------------- ANALYZE ----------------
@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, user=Depends(get_current_user)):

    result = await analyze_engine(req.text)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO analysis_history
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        str(uuid.uuid4()),
        req.text,
        result["risk"],
        result["score"],
        result["explanation"],
        json.dumps(result["fixes"]),
        datetime.now(timezone.utc).isoformat()
    ))

    conn.commit()
    conn.close()

    return result

# ---------------- FILE SCAN ----------------
@app.post("/api/scan-file")
async def scan_file(file: UploadFile = File(...), user=Depends(get_current_user)):

    content = await file.read()
    text = content.decode(errors="ignore")

    result = await analyze_engine(text)

    file_hash = hashlib.sha256(content).hexdigest()

    return {
        "filename": file.filename,
        "hash": file_hash,
        **result
    }

# ---------------- REPO SCAN (UNCHANGED) ----------------
@app.post("/api/scan-repo")
async def scan_repo(repo_url: str, user=Depends(get_current_user)):

    path = "/tmp/repo"
    if os.path.exists(path):
        os.system(f"rm -rf {path}")

    git.Repo.clone_from(repo_url, path)

    results = []

    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith((".py", ".js", ".java", ".txt")):
                with open(os.path.join(root, f), "r", errors="ignore") as file:
                    text = file.read()

                result = await analyze_engine(text)

                results.append({
                    "file": f,
                    "risk": result["risk"],
                    "score": result["score"]
                })

    return {"results": results}

# ---------------- CVE ----------------
@app.get("/api/cve")
async def get_cve(query: str):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
    async with httpx.AsyncClient() as client:
        res = await client.get(url)
    return res.json()

# ---------------- HASH LOOKUP ----------------
@app.get("/api/hash/{file_hash}")
def hash_lookup(file_hash: str):
    return {
        "hash": file_hash,
        "status": "No malware DB connected yet"
    }