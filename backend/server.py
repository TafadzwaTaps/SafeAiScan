from fastapi import FastAPI, APIRouter, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime, timezone
import sqlite3
import json
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from emergentintegrations.llm.chat import LlmChat, UserMessage
import asyncio

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# SQLite setup
DB_PATH = ROOT_DIR / "security_analysis.db"

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

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Create the main app
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Pydantic models
class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=10, max_length=50000, description="Text to analyze (logs, code, or email)")

class AnalyzeResponse(BaseModel):
    id: str
    risk: str
    explanation: str
    fixes: List[str]
    timestamp: str

class HistoryItem(BaseModel):
    id: str
    input_preview: str
    risk_level: str
    explanation: str
    fixes: List[str]
    timestamp: str

# AI Analysis function
async def analyze_with_ai(text: str) -> dict:
    api_key = os.environ.get('EMERGENT_LLM_KEY')
    if not api_key:
        raise HTTPException(status_code=500, detail="AI API key not configured")
    
    system_prompt = """You are a cybersecurity analysis assistant. Analyze the provided text (which could be logs, code, or email) for security issues.

RESPOND ONLY WITH VALID JSON in this exact format:
{"risk":"Low|Medium|High","explanation":"Brief explanation under 150 words","fixes":["fix1","fix2","fix3"]}

Risk Levels:
- Low: No immediate threats, minor improvements possible
- Medium: Potential vulnerabilities, should be addressed
- High: Critical security issues requiring immediate action

Keep responses concise. Focus on the most important findings. Maximum 3-5 fixes."""

    try:
        chat = LlmChat(
            api_key=api_key,
            session_id=f"security-{uuid.uuid4()}",
            system_message=system_prompt
        ).with_model("openai", "gpt-4o-mini")
        
        # Truncate input to minimize tokens
        truncated_text = text[:4000] if len(text) > 4000 else text
        
        user_message = UserMessage(
            text=f"Analyze this for security issues:\n\n{truncated_text}"
        )
        
        response = await chat.send_message(user_message)
        
        # Parse JSON response
        try:
            # Clean response - sometimes AI adds markdown code blocks
            clean_response = response.strip()
            if clean_response.startswith("```"):
                clean_response = clean_response.split("```")[1]
                if clean_response.startswith("json"):
                    clean_response = clean_response[4:]
            clean_response = clean_response.strip()
            
            result = json.loads(clean_response)
            
            # Validate structure
            if "risk" not in result or "explanation" not in result or "fixes" not in result:
                raise ValueError("Invalid response structure")
            
            # Normalize risk level
            risk = result["risk"].capitalize()
            if risk not in ["Low", "Medium", "High"]:
                risk = "Medium"
            
            return {
                "risk": risk,
                "explanation": result["explanation"][:500],
                "fixes": result["fixes"][:5] if isinstance(result["fixes"], list) else [str(result["fixes"])]
            }
        except json.JSONDecodeError:
            # Fallback if AI doesn't return valid JSON
            return {
                "risk": "Medium",
                "explanation": response[:500],
                "fixes": ["Review the content manually", "Consult security documentation"]
            }
    except Exception as e:
        logging.error(f"AI analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# API Routes
@api_router.get("/")
async def root():
    return {"message": "SafeScan AI - Cybersecurity Analysis API"}

@api_router.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit("10/minute")
async def analyze_text(request: Request, body: AnalyzeRequest):
    """Analyze text for security issues"""
    text = body.text.strip()
    
    if len(text) < 10:
        raise HTTPException(status_code=400, detail="Input too short. Provide at least 10 characters.")
    
    # Perform AI analysis
    result = await analyze_with_ai(text)
    
    # Save to history
    analysis_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    input_preview = text[:100] + "..." if len(text) > 100 else text
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO analysis_history (id, input_text, input_preview, risk_level, explanation, fixes, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (analysis_id, text, input_preview, result["risk"], result["explanation"], json.dumps(result["fixes"]), timestamp))
    conn.commit()
    conn.close()
    
    return AnalyzeResponse(
        id=analysis_id,
        risk=result["risk"],
        explanation=result["explanation"],
        fixes=result["fixes"],
        timestamp=timestamp
    )

@api_router.get("/history", response_model=List[HistoryItem])
async def get_history():
    """Get analysis history"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, input_preview, risk_level, explanation, fixes, timestamp FROM analysis_history ORDER BY timestamp DESC LIMIT 50')
    rows = cursor.fetchall()
    conn.close()
    
    return [
        HistoryItem(
            id=row[0],
            input_preview=row[1],
            risk_level=row[2],
            explanation=row[3],
            fixes=json.loads(row[4]),
            timestamp=row[5]
        )
        for row in rows
    ]

@api_router.delete("/history/{analysis_id}")
async def delete_history_item(analysis_id: str):
    """Delete a history item"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM analysis_history WHERE id = ?', (analysis_id,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    
    if deleted == 0:
        raise HTTPException(status_code=404, detail="History item not found")
    
    return {"message": "Deleted successfully"}

@api_router.delete("/history")
async def clear_history():
    """Clear all history"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM analysis_history')
    conn.commit()
    conn.close()
    
    return {"message": "History cleared"}

@api_router.get("/examples")
async def get_examples():
    """Get example test cases"""
    return {
        "examples": [
            {
                "name": "Suspicious Log Entry",
                "type": "log",
                "content": """2024-01-15 14:32:11 - WARNING - Failed login attempt for user 'admin' from IP 192.168.1.105
2024-01-15 14:32:15 - WARNING - Failed login attempt for user 'admin' from IP 192.168.1.105
2024-01-15 14:32:18 - WARNING - Failed login attempt for user 'admin' from IP 192.168.1.105
2024-01-15 14:32:22 - CRITICAL - Account 'admin' locked after 3 failed attempts
2024-01-15 14:33:01 - WARNING - SSH connection attempt from 192.168.1.105 blocked"""
            },
            {
                "name": "SQL Injection Vulnerable Code",
                "type": "code",
                "content": """def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def login(request):
    user = request.POST['username']
    password = request.POST['password']
    result = get_user(user)
    if result and result['password'] == password:
        return True"""
            },
            {
                "name": "Phishing Email",
                "type": "email",
                "content": """From: security@amaz0n-verify.com
Subject: URGENT: Your account has been compromised!

Dear Valued Customer,

We have detected suspicious activity on your account. Your account will be suspended within 24 hours unless you verify your identity.

Click here immediately to verify: http://amaz0n-security-verify.suspicious-link.com/verify

Please enter your:
- Full name
- Credit card number
- CVV
- Social Security Number

This is an automated message. Do not reply."""
            }
        ]
    }

# Include the API router
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files
static_path = ROOT_DIR / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=static_path), name="static")

# Serve index.html for root
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    index_path = static_path / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return HTMLResponse("<h1>SafeScan AI</h1><p>Frontend not found</p>")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
