from scanner import safe_clone, validate_repo, full_scan
from app import tasks_store
import shutil

def run_scan(task_id, repo_url, user_id, org_id):
    path = None
    try:
        tasks_store[task_id]["state"] = "CLONING"
        path = safe_clone(repo_url)

        tasks_store[task_id]["state"] = "VALIDATING"
        validate_repo(path)

        tasks_store[task_id]["state"] = "SCANNING"
        results = full_scan(path)

        tasks_store[task_id]["state"] = "DONE"
        tasks_store[task_id]["result"] = results

    except Exception as e:
        tasks_store[task_id]["state"] = "FAILED"
        tasks_store[task_id]["result"] = str(e)

    finally:
        if path and os.path.exists(path):
            shutil.rmtree(path)