# api/analyze.py
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse
import os
import json
import uuid
from datetime import datetime, timezone
import httpx

# Create FastAPI instance
app = FastAPI()

# Pydantic model for input
class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=10, max_length=50000, description="Text to analyze")

# Pydantic model for output
class AnalyzeResponse(BaseModel):
    id: str
    risk: str
    explanation: str
    fixes: list
    timestamp: str

# AI analysis function
async def analyze_with_ai(text: str) -> dict:
    api_key = os.environ.get("EMERGENT_LLM_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="AI API key not configured")

    system_prompt = """You are a cybersecurity analysis assistant. Analyze this text (logs, code, or email) and respond ONLY with valid JSON:
{"risk":"Low|Medium|High","explanation":"Brief explanation under 150 words","fixes":["fix1","fix2","fix3"]}
Keep it short and concise. Max 3-5 fixes."""

    truncated_text = text[:4000] if len(text) > 4000 else text

    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": truncated_text}
        ],
        "max_tokens": 150,
        "temperature": 0.2
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json=payload
        )

    data = response.json()
    result_text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    
    # Clean JSON if AI adds code blocks
    clean_response = result_text.strip()
    if clean_response.startswith("```"):
        clean_response = clean_response.split("```")[1]
        if clean_response.startswith("json"):
            clean_response = clean_response[4:]
    clean_response = clean_response.strip()

    try:
        result = json.loads(clean_response)
        risk = result.get("risk", "Medium").capitalize()
        if risk not in ["Low", "Medium", "High"]:
            risk = "Medium"
        return {
            "risk": risk,
            "explanation": result.get("explanation", "")[:500],
            "fixes": result.get("fixes", [])[:5] if isinstance(result.get("fixes", []), list) else [str(result.get("fixes", []))]
        }
    except json.JSONDecodeError:
        return {
            "risk": "Medium",
            "explanation": clean_response[:500],
            "fixes": ["Review manually", "Consult security docs"]
        }

# API route
@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_text(body: AnalyzeRequest):
    text = body.text.strip()
    if len(text) < 10:
        raise HTTPException(status_code=400, detail="Input too short")

    result = await analyze_with_ai(text)

    # Create ID and timestamp
    analysis_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    return AnalyzeResponse(
        id=analysis_id,
        risk=result["risk"],
        explanation=result["explanation"],
        fixes=result["fixes"],
        timestamp=timestamp
    )