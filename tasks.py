import os
import shutil
from scanner import safe_clone, validate_repo, full_scan
from store import tasks_store


def run_scan(task_id, repo_url, user_id, org_id, ws=None):
    path = None

    def push(state, msg=None, progress=None):
        tasks_store[task_id]["state"] = state
        if msg:
            tasks_store[task_id]["message"] = msg

        # websocket push (if available)
        if ws:
            try:
                ws.send_json({
                    "type": "progress",
                    "value": progress or 0,
                    "message": msg or state
                })
            except:
                pass

    try:
        push("CLONING", "Cloning repository...", 10)
        path = safe_clone(repo_url)

        push("VALIDATING", "Validating repository...", 30)
        validate_repo(path)

        push("SCANNING", "Running security scanners...", 60)
        results = full_scan(path)

        push("ENRICHING", "Adding CVE intelligence...", 80)

        tasks_store[task_id]["state"] = "DONE"
        tasks_store[task_id]["result"] = {
             "findings": results if isinstance(results, list) else results.get("findings", [])
             }

        push("DONE", "Scan complete", 100)

    except Exception as e:
        tasks_store[task_id]["state"] = "FAILED"
        tasks_store[task_id]["result"] = str(e)

    finally:
        if path and os.path.exists(path):
            shutil.rmtree(path)