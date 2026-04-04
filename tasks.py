from celery_worker import celery
from datetime import datetime, timezone
import uuid

@celery.task
def scan_repo_task(repo_url, user_id, org_id):
    import requests

    # ⚠️ SAFE IMPORT INSIDE TASK (prevents circular imports)
    from your_scanner import scan_vulnerabilities
    from your_ai import ai_enrich
    from your_db import supabase

    code = f"Repo scan placeholder: {repo_url}"

    findings = scan_vulnerabilities(code)

    ai = None
    try:
        ai = ai_enrich(code, findings)
    except Exception as e:
        ai = {"explanation": str(e), "fixes": []}

    result_id = str(uuid.uuid4())

    supabase.table("analysis_history").insert({
        "id": result_id,
        "user_id": user_id,
        "org_id": org_id,
        "input_text": repo_url,
        "risk": "REPO_SCAN",
        "score": len(findings) * 25,
        "explanation": ai.get("explanation"),
        "fixes": ai.get("fixes"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }).execute()

    return {"id": result_id}