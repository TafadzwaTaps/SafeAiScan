from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from server import app


app = FastAPI(title="SafeScan AI API")

# Allow CORS for your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or restrict to your frontend URL
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.get("/")
async def root():
    return {"message": "SafeScan AI FastAPI running"}
