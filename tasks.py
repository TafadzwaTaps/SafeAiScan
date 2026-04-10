import os
import shutil
import traceback
from scanner import safe_clone, validate_repo, full_scan
from supabase import create_client

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise Exception("Missing Supabase credentials")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

TABLE = "scan_tasks"


# =========================
# SAFE UPDATE (CRITICAL FIX)
# =========================
def update_task(task_id: str, payload: dict):
    try:
        supabase.table(TABLE).update(payload).eq("id", task_id).execute()
    except Exception as e:
        print("🔥 SUPABASE UPDATE FAILED:", str(e))
        traceback.print_exc()


# =========================
# SCAN WORKER
# =========================
def run_scan(task_id, repo_url, user_id, org_id):
    path = None

    try:
        update_task(task_id, {
            "state": "CLONING",
            "message": "Cloning repository...",
            "progress": 10
        })

        path = safe_clone(repo_url)

        update_task(task_id, {
            "state": "VALIDATING",
            "message": "Validating repository...",
            "progress": 30
        })

        validate_repo(path)

        update_task(task_id, {
            "state": "SCANNING",
            "message": "Running security scan...",
            "progress": 60
        })

        results = full_scan(path)

        update_task(task_id, {
            "state": "FINALIZING",
            "message": "Preparing results...",
            "progress": 90
        })

        # ✅ FORCE NORMALIZED FORMAT (IMPORTANT FIX)
        findings = []

        if isinstance(results, dict):
            findings = results.get("findings", [])
        elif isinstance(results, list):
            findings = results
        else:
            findings = []

        update_task(task_id, {
            "state": "DONE",
            "message": "Scan complete",
            "progress": 100,
            "result": {
                "findings": findings
            }
        })

        print(f"✅ SCAN DONE: {task_id}")

    except Exception as e:
        error = str(e)

        print("🔥 SCAN ERROR:", error)
        traceback.print_exc()

        update_task(task_id, {
            "state": "FAILED",
            "message": "Scan failed",
            "result": {
                "error": error
            }
        })

    finally:
        if path and os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)