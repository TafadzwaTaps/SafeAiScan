"""
db.py — Resilient Supabase service layer
- Retry with exponential backoff on network errors
- Per-request in-memory cache (no Redis required)
- Batched dashboard query to minimize round-trips
- Never crashes the request — always returns safe fallbacks
"""

import os
import time
import logging
import functools
from typing import Any, Optional
from supabase import create_client, Client

logger = logging.getLogger("safeaiscan.db")

# ============================================================
# CLIENT
# ============================================================
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set")

_client: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

def get_client() -> Client:
    return _client

# ============================================================
# RETRY DECORATOR
# ============================================================
def _is_retryable(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(k in msg for k in (
        "server disconnected", "connection", "timeout",
        "remotedisconnected", "remote protocol", "eof",
        "connectionreset", "broken pipe"
    ))

def with_retry(max_attempts: int = 3, base_delay: float = 0.4):
    """Exponential backoff retry for Supabase calls."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_attempts):
                try:
                    return fn(*args, **kwargs)
                except Exception as exc:
                    last_exc = exc
                    if not _is_retryable(exc) or attempt == max_attempts - 1:
                        raise
                    delay = base_delay * (2 ** attempt)
                    logger.warning(
                        f"[retry] {fn.__name__} attempt {attempt+1}/{max_attempts} "
                        f"failed: {exc}. Retrying in {delay:.1f}s"
                    )
                    time.sleep(delay)
            raise last_exc
        return wrapper
    return decorator

# ============================================================
# IN-MEMORY SHORT-TTL CACHE (replaces Redis for single-process)
# ============================================================
_cache: dict[str, tuple[float, Any]] = {}
_CACHE_TTL = 8.0  # seconds — dashboard data freshness window

def _cache_get(key: str) -> Optional[Any]:
    if key in _cache:
        ts, val = _cache[key]
        if time.monotonic() - ts < _CACHE_TTL:
            return val
        del _cache[key]
    return None

def _cache_set(key: str, val: Any):
    _cache[key] = (time.monotonic(), val)

def cache_invalidate(prefix: str):
    """Invalidate all cache keys starting with prefix."""
    keys = [k for k in _cache if k.startswith(prefix)]
    for k in keys:
        del _cache[k]

# ============================================================
# USER QUERIES
# ============================================================
@with_retry()
def fetch_user_by_id(user_id: str) -> Optional[dict]:
    cache_key = f"user:{user_id}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    res = _client.table("users").select("*").eq("id", user_id).execute()
    user = res.data[0] if res.data else None
    if user:
        _cache_set(cache_key, user)
    return user

@with_retry()
def fetch_user_by_email(email: str) -> Optional[dict]:
    res = _client.table("users").select("*").eq("email", email).execute()
    return res.data[0] if res.data else None

@with_retry()
def update_user(user_id: str, payload: dict) -> bool:
    _client.table("users").update(payload).eq("id", user_id).execute()
    cache_invalidate(f"user:{user_id}")
    return True

@with_retry()
def insert_user(row: dict) -> bool:
    _client.table("users").insert(row).execute()
    return True

@with_retry()
def user_email_exists(email: str) -> bool:
    res = _client.table("users").select("id").eq("email", email).execute()
    return bool(res.data)

# ============================================================
# ORG QUERIES
# ============================================================
@with_retry()
def fetch_org_by_id(org_id: str) -> Optional[dict]:
    if not org_id:
        return None

    cache_key = f"org:{org_id}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        res = _client.table("organizations").select("*").eq("id", org_id).execute()
        org = res.data[0] if res.data else None
        _cache_set(cache_key, org)
        return org
    except Exception as exc:
        logger.warning(f"fetch_org_by_id({org_id}) failed: {exc} — returning None")
        return None

@with_retry()
def insert_org(row: dict) -> bool:
    _client.table("organizations").insert(row).execute()
    return True

@with_retry()
def fetch_org_members(org_id: str) -> list:
    try:
        res = _client.table("users") \
            .select("id,email,plan,role,created_at,last_login") \
            .eq("org_id", org_id) \
            .execute()
        return res.data or []
    except Exception as exc:
        logger.error(f"fetch_org_members({org_id}): {exc}")
        return []

# ============================================================
# USAGE QUERIES
# ============================================================
@with_retry()
def fetch_usage_today(user_id: str, date_str: str) -> Optional[dict]:
    res = _client.table("usage_metrics") \
        .select("*") \
        .eq("user_id", user_id) \
        .eq("date", date_str) \
        .execute()
    return res.data[0] if res.data else None

@with_retry()
def upsert_usage(user_id: str, org_id: str, date_str: str, count: int) -> bool:
    existing = fetch_usage_today(user_id, date_str)
    if existing:
        _client.table("usage_metrics") \
            .update({"request_count": count}) \
            .eq("id", existing["id"]) \
            .execute()
    else:
        import uuid
        _client.table("usage_metrics").insert({
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "org_id": org_id,
            "date": date_str,
            "request_count": count
        }).execute()
    return True

@with_retry()
def fetch_usage_history(user_id: str, limit: int = 30) -> list:
    try:
        res = _client.table("usage_metrics") \
            .select("date,request_count") \
            .eq("user_id", user_id) \
            .order("date", desc=True) \
            .limit(limit) \
            .execute()
        return res.data or []
    except Exception as exc:
        logger.error(f"fetch_usage_history: {exc}")
        return []

# ============================================================
# HISTORY QUERIES
# ============================================================

# Columns that definitely exist — safe subset used everywhere
_HISTORY_SAFE_COLS = "id,risk,score,timestamp"

# Extended columns — used when migration has been applied
_HISTORY_FULL_COLS = "id,risk,score,findings_count,timestamp"

@with_retry()
def fetch_scan_history(user_id: str, limit: int = 20) -> list:
    """
    Tries full columns first; falls back to safe subset if
    findings_count column doesn't exist yet (pre-migration).
    """
    for cols in (_HISTORY_FULL_COLS, _HISTORY_SAFE_COLS):
        try:
            res = _client.table("analysis_history") \
                .select(cols) \
                .eq("user_id", user_id) \
                .order("timestamp", desc=True) \
                .limit(limit) \
                .execute()
            return res.data or []
        except Exception as exc:
            err_str = str(exc)
            if "findings_count" in err_str or "PGRST204" in err_str or "column" in err_str.lower():
                logger.warning(f"findings_count column missing, falling back to safe cols: {exc}")
                continue
            logger.error(f"fetch_scan_history: {exc}")
            return []
    return []

@with_retry()
def insert_scan_history(row: dict) -> bool:
    """
    Tries inserting full row; if findings_count column missing,
    retries without it. Scan never fails because of a missing column.
    """
    try:
        _client.table("analysis_history").insert(row).execute()
        return True
    except Exception as exc:
        err_str = str(exc)
        if "findings_count" in err_str or "PGRST204" in err_str:
            logger.warning("findings_count missing — inserting without it")
            fallback = {k: v for k, v in row.items() if k != "findings_count"}
            try:
                _client.table("analysis_history").insert(fallback).execute()
                return True
            except Exception as exc2:
                logger.error(f"History insert fallback failed: {exc2}")
                return False
        logger.error(f"History insert failed: {exc}")
        return False

# ============================================================
# SCAN TASKS
# ============================================================
@with_retry()
def insert_scan_task(row: dict) -> bool:
    _client.table("scan_tasks").insert(row).execute()
    return True

@with_retry()
def fetch_scan_task(task_id: str) -> Optional[dict]:
    res = _client.table("scan_tasks") \
        .select("*") \
        .eq("id", task_id) \
        .single() \
        .execute()
    return res.data

# ============================================================
# CVE CACHE
# ============================================================
@with_retry()
def fetch_cve_cache(query: str) -> Optional[dict]:
    try:
        res = _client.table("cve_cache").select("result").eq("query", query).execute()
        return res.data[0]["result"] if res.data else None
    except Exception:
        return None

@with_retry()
def store_cve_cache(query: str, result: dict) -> bool:
    try:
        _client.table("cve_cache").insert({"query": query, "result": result}).execute()
        return True
    except Exception:
        return False

# ============================================================
# AUDIT LOGS
# ============================================================
def write_audit_log(
    user_id: str,
    action: str,
    org_id: Optional[str] = None,
    resource: Optional[str] = None,
    ip_address: Optional[str] = None,
    status: str = "success",
    metadata: Optional[dict] = None
):
    """Fire-and-forget audit log. Never raises."""
    import uuid
    try:
        _client.table("audit_logs").insert({
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "org_id": org_id,
            "action": action,
            "resource": resource,
            "ip_address": ip_address,
            "status": status,
            "metadata": metadata or {}
        }).execute()
    except Exception as exc:
        logger.warning(f"Audit log write failed (non-fatal): {exc}")

# ============================================================
# DASHBOARD — BATCHED QUERY (single function, minimum round-trips)
# ============================================================
def fetch_dashboard_data(user_id: str, org_id: Optional[str], plan: str) -> dict:
    """
    Gathers everything the dashboard needs in 3 parallel-safe calls:
      1. usage_metrics  (last 30 days)
      2. analysis_history (last N based on plan)
      3. org members if applicable

    Returns a safe dict — never raises.
    """
    from plans import get_plan_limits
    limits = get_plan_limits(plan)
    history_limit = limits["history_limit"]

    usage_data   = []
    history_data = []
    org_members  = []

    # Usage
    try:
        usage_data = fetch_usage_history(user_id, limit=30)
    except Exception as exc:
        logger.error(f"Dashboard usage fetch: {exc}")

    # History
    try:
        history_data = fetch_scan_history(user_id, limit=min(history_limit, 20))
    except Exception as exc:
        logger.error(f"Dashboard history fetch: {exc}")

    # Team members (only for paid plans)
    if org_id and plan in ("pro", "enterprise"):
        try:
            org_members = fetch_org_members(org_id)
        except Exception as exc:
            logger.error(f"Dashboard org members fetch: {exc}")

    return {
        "usage":   usage_data,
        "history": history_data,
        "team":    org_members,
    }
