"""
tasks.py — Background Scan Worker
===================================
Runs async repo scans as FastAPI BackgroundTasks.
No plan gating, no org logic — just clone → validate → scan → save.

State machine:  QUEUED → CLONING → VALIDATING → SCANNING → DONE
                                                          ↘ FAILED
"""

import logging
import traceback
from datetime import datetime, timezone

import db
from scanner import safe_clone, validate_repo_size, scan_directory, build_result

logger = logging.getLogger("secretscan.tasks")


def run_repo_scan(task_id: str, repo_url: str, user_id: str, is_pro: bool) -> None:
    """
    Full async pipeline for scanning a GitHub repository.

    Called by FastAPI's BackgroundTasks — runs in a thread after the
    HTTP response has already been sent to the client.

    The client polls GET /scan/status/{task_id} for progress.
    """
    import shutil
    clone_dir = None

    def _update(state: str, message: str, progress: int, result_json=None):
        """Helper: persist task state to the DB."""
        fields = {
            "state":      state,
            "message":    message,
            "progress":   progress,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        if result_json is not None:
            fields["result_json"] = result_json
        db.update_scan_task(task_id, fields)

    try:
        # ── 1. Clone ──────────────────────────────────────────
        logger.info(f"[{task_id}] Starting repo scan: {repo_url}")
        _update("CLONING", "Cloning repository…", 10)

        clone_dir = safe_clone(repo_url)

        # ── 2. Validate size ──────────────────────────────────
        _update("VALIDATING", "Checking repository size…", 30)
        validate_repo_size(clone_dir)

        # ── 3. Scan for secrets ───────────────────────────────
        _update("SCANNING", "Scanning for hardcoded secrets…", 60)
        findings = scan_directory(clone_dir)

        # ── 4. Build result and save ──────────────────────────
        _update("SCANNING", "Preparing report…", 90)
        result = build_result(findings, source=repo_url, is_pro=is_pro)

        # Persist to scans table so GET /report/{id} works
        scan_id = db.save_scan(user_id, repo_url, result)

        _update("DONE", "Scan complete", 100, result_json={
            **result,
            "scan_id": scan_id,
        })

        logger.info(
            f"[{task_id}] Done — {result['total_secrets']} secret(s), "
            f"risk={result['risk_level']}"
        )

    except (ValueError, RuntimeError) as exc:
        # Expected failures: bad URL, repo too large, clone failed
        logger.warning(f"[{task_id}] Scan error: {exc}")
        _update("FAILED", str(exc), 0, result_json={"error": str(exc)})

    except Exception as exc:
        # Unexpected failures — log full traceback for debugging
        logger.error(f"[{task_id}] Unexpected error: {exc}")
        traceback.print_exc()
        _update("FAILED", "An unexpected error occurred.", 0,
                result_json={"error": "Scan failed unexpectedly."})

    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)


# ── Backwards-compatibility alias ─────────────────────────────────────────────
# app.py imports `run_scan` (old name). The function was renamed to
# run_repo_scan but the alias keeps the import working without touching app.py.
run_scan = run_repo_scan
