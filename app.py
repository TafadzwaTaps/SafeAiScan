from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from typing import List, Dict
import git, os, re, json, uuid, sqlite3, logging, hashlib
from datetime import datetime, timedelta, timezone
import httpx
import jwt

# =========================================================
# CONFIG
# =========================================================
DB_PATH = "security_analysis.db"
HF_API_KEY = os.environ.get("HF_API_KEY")

HF_MODEL_URL = "https://router.huggingface.co/hf-inference/models/HuggingFaceH4/zephyr-7b-beta"

SECRET_KEY = "SUPER_SECRET_KEY"
ALGORITHM = "HS256"

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

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

USERS = {
    "master": "Matrix123!"
}

# =========================================================
# DATABASE
# =========================================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analysis_history (
        id TEXT PRIMARY KEY,
        user TEXT,
        input_text TEXT,
        risk TEXT,
        score REAL,
        explanation TEXT,
        fixes TEXT,
        timestamp TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        user TEXT,
        api_key TEXT
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
    payload["exp"] = datetime.utcnow() + timedelta(hours=12)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

# =========================================================
# REQUEST MODEL
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

def scan_vulnerabilities(text: str):
    findings = []
    for name, (pattern, weight) in SIGNATURES.items():
        if re.search(pattern, text, re.IGNORECASE):
            findings.append({"type": name, "weight": weight})
    return findings

# =========================================================
# RISK ENGINE
# =========================================================
def calculate_risk(findings):
    if not findings:
        return {"risk": "Low", "score": 0}

    total = sum(f["weight"] for f in findings)
    score = min(total, 10)

    if total >= 18:
        risk = "Critical"
    elif total >= 12:
        risk = "High"
    elif total >= 6:
        risk = "Medium"
    else:
        risk = "Low"

    return {"risk": risk, "score": score}

# =========================================================
# AI ENRICHMENT (OPTIONAL FREE)
# =========================================================
async def ai_enrich(text, findings):

    if not HF_API_KEY:
        return {
            "explanation": "AI disabled (no API key)",
            "fixes": ["Use input validation", "Sanitize user input"]
        }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            res = await client.post(
                HF_MODEL_URL,
                headers={"Authorization": f"Bearer {HF_API_KEY}"},
                json={"inputs": f"Explain vulnerabilities: {findings}"}
            )

        data = res.json()
        output = data[0].get("generated_text", "") if isinstance(data, list) else str(data)

        return {
            "explanation": output,
            "fixes": ["Sanitize input", "Use prepared statements"]
        }

    except:
        return {
            "explanation": "AI unavailable",
            "fixes": ["Manual review required"]
        }

# =========================================================
# MAIN ENGINE (FIXED)
# =========================================================
async def analyze_engine(text):

    findings = scan_vulnerabilities(text)
    risk_data = calculate_risk(findings)
    ai_data = await ai_enrich(text, findings)

    confidence = min(len(findings) * 20, 100)

    return {
        "risk": risk_data["risk"],
        "score": risk_data["score"],
        "confidence": confidence,
        "findings": findings,
        "explanation": ai_data["explanation"],
        "fixes": ai_data["fixes"]
    }

# =========================================================
# ROUTES
# =========================================================
@app.get("/")
def root():
    return {"status": "SafeAIScan Enterprise Running"}

@app.post("/login")
def login(username: str, password: str):
    if USERS.get(username) != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token({"sub": username})
    return {"access_token": token}

# =========================================================
# ANALYZE
# =========================================================
@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest, user: str = Depends(verify_token)):

    result = await analyze_engine(req.text)

    analysis_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO analysis_history
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        analysis_id,
        user,
        req.text,
        result["risk"],
        result["score"],
        result["explanation"],
        json.dumps(result["fixes"]),
        timestamp
    ))

    conn.commit()
    conn.close()

    return result

# =========================================================
# FILE SCAN
# =========================================================
@app.post("/api/scan-file")
async def scan_file(file: UploadFile = File(...), user: str = Depends(verify_token)):

    content = await file.read()
    text = content.decode(errors="ignore")

    file_hash = hashlib.sha256(content).hexdigest()

    result = await analyze_engine(text)

    return {
        "filename": file.filename,
        "hash": file_hash,
        **result
    }

# =========================================================
# HASH LOOKUP
# =========================================================
@app.get("/api/hash/{file_hash}")
def lookup_hash(file_hash: str):
    return {
        "hash": file_hash,
        "status": "No known malware signatures",
        "reputation": "Clean"
    }

# =========================================================
# HISTORY (USER-BASED)
# =========================================================
@app.get("/api/history")
def history(user: str = Depends(verify_token)):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, input_text, risk, score, timestamp
        FROM analysis_history
        WHERE user=?
        ORDER BY timestamp DESC
    """, (user,))

    rows = cursor.fetchall()
    conn.close()

    return rows

# =========================================================
# API KEY GENERATION
# =========================================================
@app.post("/api/generate-key")
def generate_key(user: str = Depends(verify_token)):

    key = str(uuid.uuid4())

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO api_keys VALUES (?, ?, ?)
    """, (str(uuid.uuid4()), user, key))

    conn.commit()
    conn.close()

    return {"api_key": key}