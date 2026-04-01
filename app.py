from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List
import os, json, uuid, sqlite3, logging, re
from datetime import datetime, timezone
import httpx

# ------------------------
# CONFIG
# ------------------------
DB_PATH = "security_analysis.db"
HF_API_KEY = os.environ.get("HF_API_KEY")  # optional
if not HF_API_KEY:
    print("WARNING: HF_API_KEY not set — AI disabled")

# ------------------------
# DATABASE INIT
# ------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_history (
            id TEXT PRIMARY KEY,
            input_text TEXT NOT NULL,
            input_preview TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            explanation TEXT NOT NULL,
            fixes TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ------------------------
# MODELS
# ------------------------
class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=10, max_length=50000)

class AnalyzeResponse(BaseModel):
    id: str
    risk: str
    explanation: str
    fixes: List[str]
    timestamp: str

# ------------------------
# FASTAPI APP
# ------------------------
app = FastAPI(title="SafeScan AI API (Free Engine)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ------------------------
# RULE-BASED DETECTION
# ------------------------
def detect_vulnerabilities(text: str):
    findings = []

    patterns = {
        "SQL Injection": r"(SELECT .* FROM .* WHERE .*['\"]?\s*\+|\bOR\b\s+1=1)",
        "XSS": r"(<script>|javascript:|onerror=|onload=)",
        "Command Injection": r"(;|\|\||&&)\s*(rm|ls|cat|whoami)",
        "Hardcoded Secrets": r"(api_key|password|secret)\s*=\s*['\"]",
        "Path Traversal": r"(\.\./|\.\.\\)",
    }

    for name, pattern in patterns.items():
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(name)

    return findings

# ------------------------
# AI + HYBRID ENGINE
# ------------------------
async def analyze_with_ai(text: str) -> dict:
    findings = detect_vulnerabilities(text)

    ai_result = {
        "risk": "Low",
        "explanation": "",
        "fixes": []
    }

    # ------------------------
    # TRY AI (HF FREE MODEL)
    # ------------------------
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                "https://router.huggingface.co/hf-inference/models/HuggingFaceH4/zephyr-7b-beta",
                headers={
                    "Authorization": f"Bearer {HF_API_KEY}" if HF_API_KEY else ""
                },
                json={
                    "inputs": f"""
You are a cybersecurity expert.

Detected issues: {findings}

Analyze the security risk and respond ONLY in JSON:
{{
  "risk": "Low | Medium | High",
  "explanation": "",
  "fixes": []
}}

Text:
{text[:2000]}
"""
                }
            )

        data = response.json()

        output = data[0]["generated_text"] if isinstance(data, list) else str(data)

        try:
            ai_result = json.loads(output)
        except:
            ai_result = {
                "risk": "Medium",
                "explanation": output,
                "fixes": []
            }

    except Exception as e:
        logging.error(f"HF ERROR: {repr(e)}")
        ai_result = {
            "risk": "Medium",
            "explanation": "AI unavailable, fallback used",
            "fixes": []
        }

    # ------------------------
    # FINAL DECISION ENGINE
    # ------------------------
    if findings:
        risk = "High" if len(findings) > 1 else "Medium"
        explanation = f"Detected vulnerabilities: {', '.join(findings)}. {ai_result.get('explanation','')}"
        fixes = list(set(ai_result.get("fixes", []) + [
            "Sanitize inputs",
            "Use parameterized queries",
            "Validate user input"
        ]))
    else:
        risk = ai_result.get("risk", "Low")
        explanation = ai_result.get("explanation", "No major issues detected")
        fixes = ai_result.get("fixes", ["Follow secure coding practices"])

    return {
        "risk": risk,
        "explanation": explanation,
        "fixes": fixes
    }

# ------------------------
# ROUTES
# ------------------------
@app.get("/")
async def root():
    return {"message": "SafeScan AI API is running (Free Mode)"}

@app.get("/debug")
async def debug():
    return {"status": "API is reachable"}

@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(body: AnalyzeRequest):
    text = body.text.strip()

    if len(text) < 10:
        raise HTTPException(status_code=400, detail="Input too short")

    result = await analyze_with_ai(text)

    # Save to DB
    analysis_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    preview = text[:100] + "..." if len(text) > 100 else text

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO analysis_history 
        (id, input_text, input_preview, risk_level, explanation, fixes, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        analysis_id,
        text,
        preview,
        result["risk"],
        result["explanation"],
        json.dumps(result["fixes"]),
        timestamp
    ))
    conn.commit()
    conn.close()

    return AnalyzeResponse(
        id=analysis_id,
        risk=result["risk"],
        explanation=result["explanation"],
        fixes=result["fixes"],
        timestamp=timestamp
    )

@app.get("/api/history")
async def history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, input_preview, risk_level, explanation, fixes, timestamp 
        FROM analysis_history 
        ORDER BY timestamp DESC 
        LIMIT 50
    ''')
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "input_preview": r[1],
            "risk_level": r[2],
            "explanation": r[3],
            "fixes": json.loads(r[4]),
            "timestamp": r[5]
        }
        for r in rows
    ]

@app.delete("/api/history")
async def clear_history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM analysis_history")
    conn.commit()
    conn.close()
    return {"message": "History cleared"}