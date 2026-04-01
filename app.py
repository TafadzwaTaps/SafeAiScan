from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi import UploadFile, File
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
from pydantic import BaseModel, Field
from typing import List, Dict
import git
import os
import os
import re
import json
import uuid
import sqlite3
import logging
from datetime import datetime, timezone
import httpx

templates = Jinja2Templates(directory="templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

USERS = {
    "master": "Matrix123!"
}


# =========================================================
# CONFIG
# =========================================================
DB_PATH = "security_analysis.db"

HF_API_KEY = os.environ.get("HF_API_KEY")

HF_MODEL_URL = "https://router.huggingface.co/hf-inference/models/HuggingFaceH4/zephyr-7b-beta"

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
    conn.commit()
    conn.close()

init_db()

# =========================================================
# REQUEST MODEL
# =========================================================
class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=5, max_length=20000)

# =========================================================
# SECURITY SIGNATURE ENGINE
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
            findings.append({
                "type": name,
                "weight": weight
            })

    return findings

# =========================================================
# RISK ENGINE (CVSS STYLE)
# =========================================================
def calculate_risk(findings: List[Dict]) -> Dict:
    if not findings:
        return {
            "risk": "Low",
            "score": 0,
            "level": "Safe"
        }

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

    return {
        "risk": level,
        "score": score
    }

# =========================================================
# EXPLANATION BUILDER
# =========================================================
def build_explanation(findings: List[Dict]) -> str:
    if not findings:
        return "No vulnerabilities detected in static analysis."

    return "Detected vulnerabilities: " + ", ".join([f["type"] for f in findings])

# =========================================================
# AI ENRICHMENT LAYER
# =========================================================
async def ai_enrich(text: str, findings: List[Dict]):

    if not HF_API_KEY:
        return {
            "explanation": "AI disabled (missing HF_API_KEY)",
            "fixes": ["Set HF_API_KEY in environment variables"]
        }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                HF_MODEL_URL,
                headers={
                    "Authorization": f"Bearer {HF_API_KEY}"
                },
                json={
                    "inputs": f"""
You are a cybersecurity expert.

Detected issues:
{findings}

Return ONLY JSON:
{{
  "explanation": "",
  "fixes": []
}}

Input:
{text[:2000]}
"""
                }
            )

        data = response.json()

        if isinstance(data, list):
            output = data[0].get("generated_text", "")
        else:
            output = str(data)

        try:
            return json.loads(output)
        except:
            return {
                "explanation": output,
                "fixes": ["Validate input", "Use secure coding practices"]
            }

    except Exception as e:
        logging.error(f"HF ERROR: {repr(e)}")
        return {
            "explanation": "AI enrichment unavailable",
            "fixes": ["Check HF API token or model availability"]
        }

# =========================================================
# MAIN ENGINE
# =========================================================
async def analyze_engine(text: str):

    findings = scan_vulnerabilities(text)
    risk_data = calculate_risk(findings)
    ai_data = await ai_enrich(text, findings)

    return {
        "risk": risk_data["risk"],
        "score": risk_data["score"],
        "findings": findings,
        "explanation": build_explanation(findings) + ". " + ai_data.get("explanation", ""),
        "fixes": ai_data.get("fixes", ["Sanitize inputs", "Validate input data"])
    }

# =========================================================
# API ENDPOINTS
# =========================================================
@app.get("/")
def root():
    return {"status": "SafeAIScan Enterprise Running"}

@app.get("/debug")
def debug():
    return {"ok": True}

@app.post("/api/analyze")
async def analyze(req: AnalyzeRequest):

    result = await analyze_engine(req.text)

    analysis_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO analysis_history
        (id, input_text, risk, score, explanation, fixes, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        analysis_id,
        req.text,
        result["risk"],
        result["score"],
        result["explanation"],
        json.dumps(result["fixes"]),
        timestamp
    ))

    conn.commit()
    conn.close()

    return {
        "id": analysis_id,
        "risk": result["risk"],
        "score": result["score"],
        "findings": result["findings"],
        "explanation": result["explanation"],
        "fixes": result["fixes"],
        "timestamp": timestamp
    }

@app.get("/api/history")
def history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, input_text, risk, score, explanation, fixes, timestamp
        FROM analysis_history
        ORDER BY timestamp DESC
        LIMIT 50
    """)

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "input": r[1],
            "risk": r[2],
            "score": r[3],
            "explanation": r[4],
            "fixes": json.loads(r[5]),
            "timestamp": r[6]
        }
        for r in rows
    ]

@app.delete("/api/history")
def clear_history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM analysis_history")
    conn.commit()
    conn.close()
    return {"message": "History cleared"}

@app.get("/api/cve")
async def get_cve(query: str):

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"

    async with httpx.AsyncClient() as client:
        res = await client.get(url)

    return res.json()

@app.post("/login")
def login(username: str, password: str):
    if USERS.get(username) != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token({"sub": username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/api/scan-file")
async def scan_file(file: UploadFile = File(...), token: str = Depends(oauth2_scheme)):

    content = await file.read()
    text = content.decode(errors="ignore")

    result = await analyze_engine(text)

    return {
        "filename": file.filename,
        "result": result
    }

@app.post("/api/scan-repo")
async def scan_repo(repo_url: str, token: str = Depends(oauth2_scheme)):

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