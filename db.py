"""
db.py — Database Layer
=======================
All database operations for SecretScan in one place.
Backed by Supabase (Postgres under the hood).

Required Supabase tables:

  users
  ─────
  id            UUID  PRIMARY KEY  DEFAULT gen_random_uuid()
  email         TEXT  UNIQUE NOT NULL
  password_hash TEXT  NOT NULL
  is_pro        BOOL  NOT NULL DEFAULT false
  scans_today   INT   NOT NULL DEFAULT 0
  last_scan_date DATE
  paypal_order_id TEXT             -- set after successful PayPal payment
  created_at    TIMESTAMPTZ DEFAULT now()

  scans
  ─────
  id            UUID  PRIMARY KEY  DEFAULT gen_random_uuid()
  user_id       UUID  REFERENCES users(id) ON DELETE CASCADE
  source        TEXT                        -- "zip_upload" or repo URL
  risk_level    TEXT                        -- HIGH | MEDIUM | LOW | NONE
  total_secrets INT   NOT NULL DEFAULT 0
  result_json   JSONB NOT NULL              -- full build_result() dict
  created_at    TIMESTAMPTZ DEFAULT now()

  scan_tasks                                -- for async repo scans
  ──────────
  id            UUID  PRIMARY KEY
  user_id       UUID  REFERENCES users(id)
  repo_url      TEXT
  state         TEXT  DEFAULT 'QUEUED'      -- QUEUED|CLONING|SCANNING|DONE|FAILED
  progress      INT   DEFAULT 0
  message       TEXT
  result_json   JSONB
  created_at    TIMESTAMPTZ DEFAULT now()
  updated_at    TIMESTAMPTZ

Every function returns data or None — never raises to the caller.
Errors are logged so the endpoint can still return a graceful response.
"""

import os
import logging
from datetime import date
from supabase import create_client, Client

logger = logging.getLogger("secretscan.db")

# ──────────────────────────────────────────────────────────────
#  CLIENT — initialised once at module load
# ──────────────────────────────────────────────────────────────

_URL = os.getenv("SUPABASE_URL")
_KEY = os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not _URL or not _KEY:
    raise EnvironmentError(
        "SUPABASE_URL and SUPABASE_KEY must be set as environment variables."
    )

_db: Client = create_client(_URL, _KEY)


def _one(response) -> dict | None:
    """Return first row from a Supabase response, or None."""
    data = response.data
    return data[0] if data else None


# ──────────────────────────────────────────────────────────────
#  USERS
# ──────────────────────────────────────────────────────────────

def get_user_by_id(user_id: str) -> dict | None:
    try:
        return _one(_db.table("users").select("*").eq("id", user_id).limit(1).execute())
    except Exception as e:
        logger.error(f"get_user_by_id({user_id}): {e}")
        return None


def get_user_by_email(email: str) -> dict | None:
    try:
        return _one(_db.table("users").select("*").eq("email", email).limit(1).execute())
    except Exception as e:
        logger.error(f"get_user_by_email: {e}")
        return None


def email_exists(email: str) -> bool:
    return get_user_by_email(email) is not None


def create_user(email: str, password_hash: str) -> dict | None:
    """Insert a new user row and return it."""
    try:
        return _one(
            _db.table("users").insert({
                "email":         email,
                "password_hash": password_hash,
                "is_pro":        False,
            }).execute()
        )
    except Exception as e:
        logger.error(f"create_user({email}): {e}")
        return None


def update_user(user_id: str, fields: dict) -> bool:
    """Partial update on any user fields. Returns True on success."""
    try:
        _db.table("users").update(fields).eq("id", user_id).execute()
        return True
    except Exception as e:
        logger.error(f"update_user({user_id}): {e}")
        return False


def mark_user_pro(user_id: str, paypal_order_id: str = "") -> bool:
    """Flip is_pro=True and record the PayPal order ID."""
    return update_user(user_id, {
        "is_pro":          True,
        "paypal_order_id": paypal_order_id,
    })


def check_and_increment_scan(user_id: str) -> tuple[bool, str]:
    """
    Rate-limit free users to 1 scan per day.
    Pro users are always allowed.

    Returns:
        (allowed: bool, reason: str)
    """
    user = get_user_by_id(user_id)
    if not user:
        return False, "User not found."

    if user.get("is_pro"):
        return True, "ok"   # pro users have unlimited scans

    today = str(date.today())
    last  = user.get("last_scan_date", "")
    count = user.get("scans_today", 0)

    if last != today:
        # New day — reset counter
        update_user(user_id, {"scans_today": 1, "last_scan_date": today})
        return True, "ok"

    if count >= 1:
        return False, "Free plan allows 1 scan per day. Upgrade to Pro for unlimited scans."

    update_user(user_id, {"scans_today": count + 1})
    return True, "ok"


# ──────────────────────────────────────────────────────────────
#  SCANS
# ──────────────────────────────────────────────────────────────

def save_scan(user_id: str, source: str, result: dict) -> str | None:
    """
    Persist a completed scan result.

    Returns the new scan UUID, or None on failure.
    """
    try:
        row = _one(
            _db.table("scans").insert({
                "user_id":       user_id,
                "source":        source,
                "risk_level":    result.get("risk_level", "NONE"),
                "total_secrets": result.get("total_secrets", 0),
                "result_json":   result,
            }).execute()
        )
        return row["id"] if row else None
    except Exception as e:
        logger.error(f"save_scan({user_id}): {e}")
        return None


def get_scan(scan_id: str, user_id: str) -> dict | None:
    """Fetch a scan by ID, scoped to the requesting user."""
    try:
        return _one(
            _db.table("scans")
            .select("*")
            .eq("id", scan_id)
            .eq("user_id", user_id)
            .limit(1)
            .execute()
        )
    except Exception as e:
        logger.error(f"get_scan({scan_id}): {e}")
        return None


def list_scans(user_id: str, limit: int = 20) -> list:
    """Return the most recent scans for a user, newest first."""
    try:
        res = (
            _db.table("scans")
            .select("id, source, risk_level, total_secrets, created_at")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return res.data or []
    except Exception as e:
        logger.error(f"list_scans({user_id}): {e}")
        return []


# ──────────────────────────────────────────────────────────────
#  SCAN TASKS (async repo scans)
# ──────────────────────────────────────────────────────────────

def create_scan_task(task_id: str, user_id: str, repo_url: str) -> bool:
    try:
        _db.table("scan_tasks").insert({
            "id":       task_id,
            "user_id":  user_id,
            "repo_url": repo_url,
            "state":    "QUEUED",
            "progress": 0,
            "message":  "Queued for scanning…",
        }).execute()
        return True
    except Exception as e:
        logger.error(f"create_scan_task({task_id}): {e}")
        return False


def update_scan_task(task_id: str, fields: dict) -> None:
    """Best-effort update — logs failure but never raises."""
    try:
        _db.table("scan_tasks").update(fields).eq("id", task_id).execute()
    except Exception as e:
        logger.error(f"update_scan_task({task_id}): {e}")


def get_scan_task(task_id: str, user_id: str) -> dict | None:
    try:
        return _one(
            _db.table("scan_tasks")
            .select("*")
            .eq("id", task_id)
            .eq("user_id", user_id)
            .limit(1)
            .execute()
        )
    except Exception as e:
        logger.error(f"get_scan_task({task_id}): {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  BACKWARDS-COMPATIBILITY LAYER
#  app.py was written against the old DB module which had different function
#  names and additional helpers.  All aliases and stubs live here so neither
#  app.py nor the new db.py needs to change structure.
# ══════════════════════════════════════════════════════════════════════════════

# ── Name aliases (old name → new function) ────────────────────────────────────
def fetch_user_by_id(user_id: str) -> dict | None:
    return get_user_by_id(user_id)

def fetch_user_by_email(email: str) -> dict | None:
    return get_user_by_email(email)

def user_email_exists(email: str) -> bool:
    return email_exists(email)

def insert_user(data: dict) -> bool:
    """Insert a user row from a raw dict (old-style call)."""
    try:
        # Prefer explicit fields; fall back gracefully if columns differ
        _db.table("users").insert(data).execute()
        return True
    except Exception as e:
        logger.error(f"insert_user: {e}")
        return False

def fetch_scan_task(task_id: str, user_id: str | None = None) -> dict | None:
    """Fetch a scan task.  user_id is optional for backwards compat."""
    try:
        q = _db.table("scan_tasks").select("*").eq("id", task_id)
        if user_id:
            q = q.eq("user_id", user_id)
        return _one(q.limit(1).execute())
    except Exception as e:
        logger.error(f"fetch_scan_task({task_id}): {e}")
        return None

def insert_scan_task(data: dict) -> bool:
    """Insert a scan task row from a raw dict (old-style call)."""
    try:
        _db.table("scan_tasks").insert(data).execute()
        return True
    except Exception as e:
        logger.error(f"insert_scan_task: {e}")
        return False

# ── Org helpers ───────────────────────────────────────────────────────────────

def insert_org(data: dict) -> bool:
    """Insert an organisation row. No-op if organisations table doesn't exist."""
    try:
        _db.table("organisations").insert(data).execute()
        return True
    except Exception as e:
        logger.warning(f"insert_org (non-fatal): {e}")
        return False  # non-fatal — org_id still stored on user row

def fetch_org_by_id(org_id: str) -> dict | None:
    try:
        return _one(_db.table("organisations").select("*").eq("id", org_id).limit(1).execute())
    except Exception as e:
        logger.warning(f"fetch_org_by_id({org_id}): {e}")
        return None

def fetch_org_members(org_id: str) -> list:
    try:
        res = _db.table("users").select("id, email, is_pro, created_at").eq("org_id", org_id).execute()
        return res.data or []
    except Exception as e:
        logger.error(f"fetch_org_members({org_id}): {e}")
        return []

# ── Scan history helpers ──────────────────────────────────────────────────────

def insert_scan_history(data: dict) -> bool:
    """Persist a scan result into the scans table using old field names."""
    try:
        # Map old field names to new schema
        row = {
            "user_id":       data.get("user_id"),
            "source":        data.get("input_text", "")[:120] or "code_paste",
            "risk_level":    data.get("risk", "LOW"),
            "total_secrets": data.get("findings_count", 0),
            "result_json":   {
                "explanation":    data.get("explanation", ""),
                "fixes":          data.get("fixes", []),
                "score":          data.get("score", 0),
                "findings_count": data.get("findings_count", 0),
            },
        }
        # Include id if provided
        if data.get("id"):
            row["id"] = data["id"]
        _db.table("scans").insert(row).execute()
        return True
    except Exception as e:
        logger.error(f"insert_scan_history: {e}")
        return False

def fetch_scan_history(user_id: str, limit: int = 20) -> list:
    return list_scans(user_id, limit=limit)

# ── Usage tracking (best-effort — graceful if table absent) ──────────────────

def fetch_usage_today(user_id: str, today: str) -> dict | None:
    """Fetch today's usage record.  Returns None if table not present."""
    try:
        return _one(
            _db.table("usage_tracking")
            .select("*")
            .eq("user_id", user_id)
            .eq("date", today)
            .limit(1)
            .execute()
        )
    except Exception:
        return None  # table may not exist — caller handles None

def upsert_usage(user_id: str, org_id: str, today: str, count: int) -> None:
    """Update daily usage counter.  Best-effort — never raises."""
    try:
        existing = fetch_usage_today(user_id, today)
        if existing:
            _db.table("usage_tracking").update({"request_count": count}).eq("user_id", user_id).eq("date", today).execute()
        else:
            _db.table("usage_tracking").insert({"user_id": user_id, "org_id": org_id, "date": today, "request_count": count}).execute()
    except Exception as e:
        logger.debug(f"upsert_usage (non-fatal): {e}")

def fetch_usage_history(user_id: str, limit: int = 30) -> list:
    try:
        res = (
            _db.table("usage_tracking")
            .select("date, request_count")
            .eq("user_id", user_id)
            .order("date", desc=True)
            .limit(limit)
            .execute()
        )
        return res.data or []
    except Exception:
        return []

# ── Dashboard aggregation ─────────────────────────────────────────────────────

def fetch_dashboard_data(user_id: str, org_id: str | None, plan: str) -> dict:
    """Return usage series, history, and team for the dashboard endpoint."""
    usage   = fetch_usage_history(user_id, limit=30)
    history = fetch_scan_history(user_id, limit=10)
    team    = fetch_org_members(org_id) if org_id else []
    return {"usage": usage, "history": history, "team": team}

# ── CVE cache (in-memory — no DB table needed) ────────────────────────────────

_cve_cache: dict = {}

def fetch_cve_cache(query: str) -> dict | None:
    return _cve_cache.get(query.lower())

def store_cve_cache(query: str, data: dict) -> None:
    # Keep cache bounded — evict oldest entry when over 200 items
    if len(_cve_cache) >= 200:
        oldest = next(iter(_cve_cache))
        del _cve_cache[oldest]
    _cve_cache[query.lower()] = data

# ── Audit log (best-effort — graceful if table absent) ───────────────────────

def write_audit_log(user_id: str, action: str, **kwargs) -> None:
    """Write an audit log entry.  Completely non-fatal — never raises."""
    try:
        row = {
            "user_id":    user_id,
            "action":     action,
            "created_at": __import__("datetime").datetime.utcnow().isoformat(),
        }
        row.update({k: str(v)[:500] if v else None for k, v in kwargs.items()})
        _db.table("audit_logs").insert(row).execute()
    except Exception as e:
        logger.debug(f"write_audit_log (non-fatal): {e}")

# ── Cache invalidation stub ───────────────────────────────────────────────────

def cache_invalidate(key: str) -> None:
    """No-op stub — in-memory caches invalidate themselves via TTL."""
    pass
