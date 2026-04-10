import os
import shutil
from scanner import safe_clone, validate_repo, full_scan
from supabase import create_client

# =========================================================
# SUPABASE SETUP
# =========================================================
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

TABLE = "scan_tasks"   # 🔥 SINGLE SOURCE OF TRUTH


# =========================================================
# UPDATE TASK (CLEAN VERSION)
# =========================================================
def update_task(task_id, **kwargs):
    supabase.table(TABLE).update(kwargs).eq("id", task_id).execute()


# =========================================================
# MAIN SCAN WORKER (SUPABASE-BASED)
# =========================================================
def run_scan(task_id, repo_url, user_id, org_id):
    path = None

    try:
        # 🔹 Step 1: Clone
        update_task(
            task_id,
            state="CLONING",
            message="Cloning repository...",
            progress=10
        )

        path = safe_clone(repo_url)

        # 🔹 Step 2: Validate
        update_task(
            task_id,
            state="VALIDATING",
            message="Validating repository...",
            progress=30
        )

        validate_repo(path)

        # 🔹 Step 3: Scan
        update_task(
            task_id,
            state="SCANNING",
            message="Running security scanners...",
            progress=60
        )

        results = full_scan(path)

        # 🔹 Step 4: Finalize
        update_task(
            task_id,
            state="FINALIZING",
            message="Saving results...",
            progress=90
        )

        # 🔥 IMPORTANT: normalize result
        findings = results.get("findings", []) if isinstance(results, dict) else results

        # 🔹 Final state (ONLY ONCE — no duplicate updates)
        update_task(
            task_id,
            state="DONE",
            message="Scan complete",
            progress=100,
            result={"findings": findings}
        )

    except Exception as e:
        # 🔥 Proper error structure
        update_task(
            task_id,
            state="FAILED",
            message="Scan failed",
            result={"error": str(e)}
        )

    finally:
        if path and os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)