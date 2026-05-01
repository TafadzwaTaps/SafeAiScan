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
