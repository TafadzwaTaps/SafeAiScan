from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from typing import List, Dict
import git
import os, re, json, uuid, sqlite3, logging, hashlib
from datetime import datetime, timedelta, timezone
import httpx
import jwt

# =========================================================
# CONFIG
# =========================================================
DB_PATH = "security_analysis.db"
SECRET_KEY = "#SafeAiScan@2026"
ALGORITHM = "HS256"

HF_API_KEY = os.environ.get("HF_API_KEY")
HF_MODEL_URL = "https://router.huggingface.co/hf-inference/models/HuggingFaceH4/zephyr-7b-beta"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# =========================================================
# APP INIT
# =========================================================
app = FastAPI(title="SafeAIScan Enterprise Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# DATABASE
# =========================================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            api_key TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_history (
            id TEXT PRIMARY KEY,
            username TEXT,
            input_text TEXT,
            risk TEXT,
            score REAL,
            explanation TEXT,
            fixes TEXT,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# =========================================================
# AUTH
# =========================================================
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

# =========================================================
# MODELS
# =========================================================
class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=5, max_length=20000)

# =========================================================
# SIGNATURE ENGINE
# =========================================================
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

# =========================================================
# RISK ENGINE
# =========================================================
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

# =========================================================
# AI ENRICHMENT
# =========================================================
async def ai_enrich(text: str, findings: List[Dict]):
    if not HF_API_KEY:
        return {"explanation": "AI disabled", "fixes": []}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            res = await client.post(
                HF_MODEL_URL,
                headers={"Authorization": f"Bearer {HF_API_KEY}"},
                json={"inputs": f"Explain vulnerabilities: {findings}"}
            )

        data = res.json()
        output = data[0].get("generated_text", "") if isinstance(data, list) else str(data)

        return {
            "explanation": output,
            "fixes": ["Validate input", "Use secure coding practices"]
        }

    except:
        return {"explanation": "AI unavailable", "fixes": []}

# =========================================================
# MAIN ENGINE
# =========================================================
async def analyze_engine(text: str):
    findings = scan_vulnerabilities(text)
    risk_data = calculate_risk(findings)
    ai_data = await ai_enrich(text, findings)

    confidence = min(100, len(findings) * 20)

    return {
        "risk": risk_data["risk"],
        "score": risk_data["score"],
        "confidence": confidence,
        "findings": findings,
        "explanation": ai_data.get("explanation", ""),
        "fixes": ai_data.get("fixes", [])
    }

# =========================================================
# ROUTES
# =========================================================
@app.post("/login")
def login(username: str, password: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()

    if not user or user[1] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token({"sub": username})
    return {"access_token": token}

@app.post("/register")
def register(username: str, password: str):
    api_key = str(uuid.uuid4())

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users VALUES (?, ?, ?)", (username, password, api_key))
        conn.commit()
    except:
        raise HTTPException(status_code=400, detail="User exists")

    return {"api_key": api_key}

# ---------------- ANALYZE ----------------
@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, user=Depends(get_current_user)):
    result = await analyze_engine(req.text)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO analysis_history VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        str(uuid.uuid4()),
        user,
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

# ---------------- HASH LOOKUP ----------------
@app.get("/api/hash/{file_hash}")
def hash_lookup(file_hash: str):
    return {
        "hash": file_hash,
        "status": "Unknown file (no malware DB yet)"
    }

# ---------------- HISTORY ----------------
@app.get("/api/history")
def history(user=Depends(get_current_user)):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT risk, score, timestamp FROM analysis_history
        WHERE username=?
        ORDER BY timestamp DESC
        LIMIT 20
    """, (user,))

    rows = cursor.fetchall()
    conn.close()

    return rows

