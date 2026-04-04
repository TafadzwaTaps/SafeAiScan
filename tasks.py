from celery import Celery
from scanner import safe_clone, validate_repo, full_scan

celery = Celery(
    "scanner",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)


# =========================================================
# MAIN SCAN TASK
# =========================================================
@celery.task(bind=True)
def scan_repo_task(self, repo_url, user_id, org_id):

    try:
        self.update_state(state="CLONING")
        path = safe_clone(repo_url)

        self.update_state(state="VALIDATING")
        validate_repo(path)

        self.update_state(state="SCANNING")
        results = full_scan(path)

        return {
            "status": "done",
            "results": results
        }

    except Exception as e:
        return {
            "status": "failed",
            "error": str(e)
        }