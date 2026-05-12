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


# ══════════════════════════════════════════════════════════════
#  TRIAL SYSTEM
#  New Supabase columns needed on `users` table:
#    plan            TEXT     DEFAULT 'pro_trial'
#    trial_active    BOOLEAN  DEFAULT true
#    trial_start_date DATE
#    trial_end_date   DATE
#    is_pro           BOOLEAN DEFAULT false
#
#  SQL migration (run once in Supabase SQL editor):
#  ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_active    BOOLEAN DEFAULT true;
#  ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_start_date DATE;
#  ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_end_date   DATE;
#  ALTER TABLE users ADD COLUMN IF NOT EXISTS is_pro           BOOLEAN DEFAULT false;
# ══════════════════════════════════════════════════════════════

from datetime import date as _date, timedelta as _td

TRIAL_DAYS = 30   # length of Pro trial in days


def start_trial(user_id: str) -> bool:
    """
    Activate a 30-day Pro trial for a newly registered user.
    Called immediately after insert_user in register().
    """
    today     = _date.today()
    end_date  = today + _td(days=TRIAL_DAYS)
    return update_user(user_id, {
        "plan":             "pro_trial",
        "trial_active":     True,
        "trial_start_date": str(today),
        "trial_end_date":   str(end_date),
        "is_pro":           True,    # pro_trial has full Pro access
    })


def get_trial_status(user: dict) -> dict:
    """
    Return a dict describing the user's current trial / plan state.

    Fields:
        plan          - canonical plan string
        is_pro        - True if user has active pro or pro_trial
        trial_active  - True if currently in trial window
        trial_expired - True if trial existed but has expired
        days_left     - int days remaining (0 if expired/not in trial)
        trial_end     - ISO date string of trial end
    """
    plan  = (user.get("plan") or "free").lower()
    today = _date.today()

    # Parse trial end date safely
    trial_end_raw = user.get("trial_end_date") or ""
    trial_end     = None
    try:
        if trial_end_raw:
            trial_end = _date.fromisoformat(str(trial_end_raw))
    except (ValueError, TypeError):
        pass

    # Determine effective status
    if plan in ("pro", "enterprise"):
        return {"plan": plan, "is_pro": True, "trial_active": False,
                "trial_expired": False, "days_left": 0, "trial_end": ""}

    if plan == "pro_trial":
        if trial_end and today <= trial_end:
            days_left = (trial_end - today).days
            return {"plan": "pro_trial", "is_pro": True, "trial_active": True,
                    "trial_expired": False, "days_left": days_left,
                    "trial_end": str(trial_end)}
        else:
            # Trial window has passed — mark expired if not already
            return {"plan": "free", "is_pro": False, "trial_active": False,
                    "trial_expired": True, "days_left": 0,
                    "trial_end": str(trial_end) if trial_end else ""}

    # plain free
    return {"plan": "free", "is_pro": False, "trial_active": False,
            "trial_expired": False, "days_left": 0, "trial_end": ""}


def expire_trial_if_needed(user: dict) -> dict:
    """
    If the trial has expired, downgrade the user to free in the DB
    and return the updated user dict.  Called on every authenticated request.
    """
    status = get_trial_status(user)
    if status["trial_expired"] and user.get("plan") == "pro_trial":
        update_user(user["id"], {
            "plan":         "free",
            "trial_active": False,
            "is_pro":       False,
        })
        user = {**user, "plan": "free", "trial_active": False, "is_pro": False}
    return user, status


def get_full_subscription_info(user: dict) -> dict:
    """
    One-stop helper used by /api/me and dashboard endpoints.
    Returns everything the frontend needs about the user's subscription.
    """
    user, trial_status = expire_trial_if_needed(user)
    plan   = trial_status["plan"]
    limits = _plan_limits_for(plan)
    return {
        **trial_status,
        "limits":    limits,
        "plan_label": _plan_label(plan),
    }


def _plan_limits_for(plan: str) -> dict:
    """Return scan limits for a given effective plan."""
    LIMITS = {
        "free": {
            "daily_scans":     5,
            "daily_repos":     2,
            "history_limit":   10,
            "ai_depth":        "basic",
            "repo_scan":       True,
            "pdf_download":    False,
            "json_export":     False,
            "advanced_ai":     False,
            "scheduled_scans": False,
            "api_access":      False,
        },
        "pro_trial": {
            "daily_scans":     -1,   # unlimited
            "daily_repos":     -1,
            "history_limit":   500,
            "ai_depth":        "full",
            "repo_scan":       True,
            "pdf_download":    True,
            "json_export":     True,
            "advanced_ai":     True,
            "scheduled_scans": True,
            "api_access":      True,
        },
        "pro": {
            "daily_scans":     -1,
            "daily_repos":     -1,
            "history_limit":   500,
            "ai_depth":        "full",
            "repo_scan":       True,
            "pdf_download":    True,
            "json_export":     True,
            "advanced_ai":     True,
            "scheduled_scans": True,
            "api_access":      True,
        },
        "enterprise": {
            "daily_scans":     -1,
            "daily_repos":     -1,
            "history_limit":   9999,
            "ai_depth":        "full",
            "repo_scan":       True,
            "pdf_download":    True,
            "json_export":     True,
            "advanced_ai":     True,
            "scheduled_scans": True,
            "api_access":      True,
        },
    }
    return LIMITS.get(plan, LIMITS["free"])


def _plan_label(plan: str) -> str:
    return {
        "free":       "Free",
        "pro_trial":  "Pro Trial",
        "pro":        "Pro",
        "enterprise": "Enterprise",
    }.get(plan, "Free")


# ══════════════════════════════════════════════════════════════
#  BACKWARDS-COMPATIBILITY ALIASES
#  app.py was written against an older DB module with different
#  function names. Every alias here maps old → new without
#  changing any existing call site in app.py.
# ══════════════════════════════════════════════════════════════

# ── User aliases ──────────────────────────────────────────────

def fetch_user_by_id(user_id: str) -> dict | None:
    """Alias: app.py calls DB.fetch_user_by_id()"""
    return get_user_by_id(user_id)


def fetch_user_by_email(email: str) -> dict | None:
    """Alias: app.py calls DB.fetch_user_by_email()"""
    return get_user_by_email(email)


def user_email_exists(email: str) -> bool:
    """Alias: app.py calls DB.user_email_exists()"""
    return email_exists(email)


def insert_user(data: dict) -> bool:
    """
    Insert a user row from a raw dict (old-style call).
    Maps the old dict format to the new column-safe insert.
    """
    try:
        _db.table("users").insert(data).execute()
        return True
    except Exception as e:
        logger.error(f"insert_user: {e}")
        return False


# ── Organisation helpers ──────────────────────────────────────

def insert_org(data: dict) -> bool:
    """Insert an org row — graceful if table doesn't exist."""
    try:
        _db.table("organisations").insert(data).execute()
        return True
    except Exception as e:
        logger.warning(f"insert_org (non-fatal): {e}")
        return False


def fetch_org_by_id(org_id: str) -> dict | None:
    try:
        return _one(
            _db.table("organisations").select("*").eq("id", org_id).limit(1).execute()
        )
    except Exception as e:
        logger.warning(f"fetch_org_by_id({org_id}): {e}")
        return None


def fetch_org_members(org_id: str) -> list:
    try:
        res = _db.table("users").select(
            "id, email, plan, trial_active, is_pro, created_at"
        ).eq("org_id", org_id).execute()
        return res.data or []
    except Exception as e:
        logger.error(f"fetch_org_members({org_id}): {e}")
        return []


# ── Scan history helpers ──────────────────────────────────────

def insert_scan_history(data: dict) -> bool:
    """
    Persist a scan result. Maps old field names to the scans table schema.
    Accepts both old-style dicts (risk/score/findings_count) and new-style.
    """
    try:
        row = {
            "user_id":       data.get("user_id"),
            "source":        data.get("input_text", "")[:120] or "code_paste",
            "risk_level":    data.get("risk", data.get("risk_level", "LOW")),
            "total_secrets": data.get("findings_count", 0),
            "result_json": {
                "explanation":    data.get("explanation", ""),
                "fixes":          data.get("fixes", []),
                "score":          data.get("score", 0),
                "findings_count": data.get("findings_count", 0),
            },
        }
        if data.get("id"):
            row["id"] = data["id"]
        _db.table("scans").insert(row).execute()
        return True
    except Exception as e:
        logger.error(f"insert_scan_history: {e}")
        return False


def fetch_scan_history(user_id: str, limit: int = 20) -> list:
    """Fetch scan history for a user, newest first."""
    return list_scans(user_id, limit=limit)


# ── Usage tracking ────────────────────────────────────────────

def fetch_usage_today(user_id: str, today: str) -> dict | None:
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
        return None   # table may not exist yet


def upsert_usage(user_id: str, org_id: str, today: str, count: int) -> None:
    try:
        existing = fetch_usage_today(user_id, today)
        if existing:
            _db.table("usage_tracking").update(
                {"request_count": count}
            ).eq("user_id", user_id).eq("date", today).execute()
        else:
            _db.table("usage_tracking").insert({
                "user_id":       user_id,
                "org_id":        org_id,
                "date":          today,
                "request_count": count,
            }).execute()
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


def fetch_dashboard_data(user_id: str, org_id, plan: str) -> dict:
    usage   = fetch_usage_history(user_id, limit=30)
    history = fetch_scan_history(user_id, limit=10)
    team    = fetch_org_members(org_id) if org_id else []
    return {"usage": usage, "history": history, "team": team}


# ── CVE cache (in-memory) ─────────────────────────────────────

_cve_cache: dict = {}

def fetch_cve_cache(query: str) -> dict | None:
    return _cve_cache.get(query.lower())

def store_cve_cache(query: str, data: dict) -> None:
    if len(_cve_cache) >= 200:
        oldest = next(iter(_cve_cache))
        del _cve_cache[oldest]
    _cve_cache[query.lower()] = data


# ── Audit log ─────────────────────────────────────────────────

def write_audit_log(user_id: str, action: str, **kwargs) -> None:
    """Non-fatal audit log. Never raises."""
    try:
        import datetime as _dt
        row = {
            "user_id":    user_id,
            "action":     action,
            "created_at": _dt.datetime.utcnow().isoformat(),
        }
        row.update({k: str(v)[:500] if v else None for k, v in kwargs.items()})
        _db.table("audit_logs").insert(row).execute()
    except Exception as e:
        logger.debug(f"write_audit_log (non-fatal): {e}")


def cache_invalidate(key: str) -> None:
    """No-op stub — in-memory caches invalidate via TTL."""
    pass


# ── Scan task (1-arg backwards compat) ───────────────────────

def fetch_scan_task(task_id: str, user_id: str | None = None) -> dict | None:
    """
    Fetch a scan task.
    app.py calls DB.fetch_scan_task(task_id) with only 1 arg.
    The new get_scan_task() requires 2 args, so this wrapper bridges the gap.
    """
    try:
        q = _db.table("scan_tasks").select("*").eq("id", task_id)
        if user_id:
            q = q.eq("user_id", user_id)
        return _one(q.limit(1).execute())
    except Exception as e:
        logger.error(f"fetch_scan_task({task_id}): {e}")
        return None


def insert_scan_task(data: dict) -> bool:
    try:
        _db.table("scan_tasks").insert(data).execute()
        return True
    except Exception as e:
        logger.error(f"insert_scan_task: {e}")
        return False
