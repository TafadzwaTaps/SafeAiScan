# app.py

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List
import os, json, uuid, sqlite3, logging
from datetime import datetime, timezone
from openai import OpenAI

# ------------------------
# CONFIG
# ------------------------
DB_PATH = "security_analysis.db"

EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY")
if not EMERGENT_LLM_KEY:
    raise RuntimeError("EMERGENT_LLM_KEY not set in environment variables")

# ✅ Correct Emergent endpoint (OpenAI-compatible)
client = OpenAI(
    api_key=EMERGENT_LLM_KEY,
    base_url="https://api.emergent.run/v1"
)

# ------------------------
# DATABASE
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
# APP
# ------------------------
app = FastAPI(title="SafeScan AI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ------------------------
# AI ANALYSIS FUNCTION
# ------------------------
async def analyze_with_ai(text: str) -> dict:
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": """You are a cybersecurity expert.

Return ONLY valid JSON:
{
  "risk": "Low | Medium | High",
  "explanation": "",
  "fixes": []
}

Keep it short."""
                },
                {
                    "role": "user",
                    "content": text[:4000]
                }
            ],
            temperature=0.2,
            max_tokens=150
        )

        content = response.choices[0].message.content.strip()

        # Clean markdown JSON blocks
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        content = content.strip()

        try:
            result = json.loads(content)
        except json.JSONDecodeError:
            logging.warning("Invalid JSON from model, using fallback")
            result = {
                "risk": "Medium",
                "explanation": content,
                "fixes": ["Check input"]
            }

        return {
            "risk": result.get("risk", "Medium"),
            "explanation": result.get("explanation", ""),
            "fixes": result.get("fixes", [])
        }

    except Exception as e:
        logging.error(f"AI error: {e}")
        return {
            "risk": "Medium",
            "explanation": str(e),
            "fixes": ["Retry analysis"]
        }

# ------------------------
# ROUTES
# ------------------------
@app.get("/")
async def root():
    return {"message": "SafeScan AI API is running"}

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