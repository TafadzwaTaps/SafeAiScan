"""
tasks.py — Background Scan Worker
===================================
Runs async repo scans as FastAPI BackgroundTasks.
No plan gating, no org logic — just clone → validate → scan → save.

State machine:  QUEUED → CLONING → VALIDATING → SCANNING → DONE
                                                          ↘ FAILED

Phase 1 additions (additive, non-breaking):
  - Dependency vulnerability scan runs alongside the secret scan
  - build_result() now returns security_score / repo_health / dependency data
  - The security_score is logged to analysis_history (scans table) so the
    Security Trend Analytics endpoint (/api/analytics/security-trend) has data
"""

import logging
import traceback
from datetime import datetime, timezone

import db
from scanner import safe_clone, validate_repo_size, scan_directory, build_result

logger = logging.getLogger("secretscan.tasks")

# Phase 1: dependency scanner — optional import, degrades gracefully
try:
    from dependency_scanner import scan_dependencies, count_dependencies
    _DEP_SCAN_AVAILABLE = True
except Exception as _exc:  # pragma: no cover
    logger.debug(f"dependency_scanner unavailable in tasks.py: {_exc}")
    _DEP_SCAN_AVAILABLE = False


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

        # ── 3b. Dependency vulnerability scan (Phase 1) ────────
        dependency_findings = None
        dependency_count    = 0
        if _DEP_SCAN_AVAILABLE:
            _update("SCANNING", "Checking dependencies for known vulnerabilities…", 75)
            try:
                dependency_findings = scan_dependencies(clone_dir)
                dependency_count    = count_dependencies(clone_dir)
            except Exception as exc:
                logger.warning(f"[{task_id}] Dependency scan failed (non-fatal): {exc}")

        # ── 4. Build result and save ──────────────────────────
        _update("SCANNING", "Preparing report…", 90)
        result = build_result(
            findings, source=repo_url, is_pro=is_pro,
            dependency_findings=dependency_findings,
            dependency_count=dependency_count,
        )

        # Persist to scans table so GET /report/{id} works
        scan_id = db.save_scan(user_id, repo_url, result)

        # ── 4b. Log security score to analysis_history (Phase 1) ──
        # Powers /api/analytics/security-trend. Non-fatal on failure.
        try:
            db.insert_scan_history({
                "id":              scan_id or task_id,
                "user_id":         user_id,
                "input_text":      f"repo_scan:{repo_url}"[:120],
                "risk":            result.get("risk_level", "LOW"),
                "score":           result.get("security_score", 0),
                "security_score":  result.get("security_score", 0),
                "findings_count":  result.get("total_secrets", 0),
                "explanation":     f"Repository scan of {repo_url}",
                "fixes":           [],
                "timestamp":       datetime.now(timezone.utc).isoformat(),
            })
        except Exception as exc:
            logger.debug(f"[{task_id}] security score history log failed (non-fatal): {exc}")

        _update("DONE", "Scan complete", 100, result_json={
            **result,
            "scan_id": scan_id,
        })

        logger.info(
            f"[{task_id}] Done — {result['total_secrets']} secret(s), "
            f"risk={result['risk_level']}, security_score={result.get('security_score')}"
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
