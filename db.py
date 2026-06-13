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

# Accept all common Supabase env var naming conventions:
# HuggingFace Spaces, Vercel, Next.js, plain Docker, etc.
_URL = (
    os.getenv("SUPABASE_URL") or
    os.getenv("NEXT_PUBLIC_SUPABASE_URL") or
    os.getenv("SUPABASE_HOST") or ""
)
_KEY = (
    os.getenv("SUPABASE_KEY") or
    os.getenv("SUPABASE_SERVICE_ROLE_KEY") or
    os.getenv("SUPABASE_SECRET_KEY") or
    os.getenv("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY") or
    os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY") or
    os.getenv("SUPABASE_ANON_KEY") or ""
)

if not _URL or not _KEY:
    import warnings
    warnings.warn(
        "SUPABASE_URL and SUPABASE_KEY not found in environment. "
        "Set them in HuggingFace Space secrets or your .env file.",
        stacklevel=1
    )
    _db = None
else:
    _db: Client = create_client(_URL, _KEY)
    logger.info(f"Supabase connected: {_URL[:40]}…")


def _get_db() -> Client:
    """Return the DB client, raising a clear error if not configured."""
    if _db is None:
        raise RuntimeError(
            "Supabase is not configured. Set SUPABASE_URL and SUPABASE_KEY "
            "environment variables in your HuggingFace Space secrets."
        )
    return _db


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
            _get_db().table("users").insert({
                "email":         email,
                "password_hash": password_hash,
                "is_pro":        False,
            }).execute()
        )
    except Exception as e:
        logger.error(f"create_user({email}): {e}")
        return None


# Columns that always exist in the base users table
_BASE_USER_COLS = {"id","email","password_hash","plan","org_id","api_key_hash",
                   "role","last_login","is_active","created_at"}
# Extended columns (require ALTER TABLE migration)
_EXTENDED_USER_COLS = {"is_pro","trial_active","trial_start_date","trial_end_date",
                       "scans_today","last_scan_date","paypal_order_id"}


def update_user(user_id: str, fields: dict) -> bool:
    """
    Partial update. If update fails because a column doesn't exist yet
    (missing migration), retries with only base columns so the app never
    crashes on schema gaps.
    """
    try:
        _get_db().table("users").update(fields).eq("id", user_id).execute()
        return True
    except Exception as e:
        err = str(e).lower()
        if "column" in err or "does not exist" in err or "schema" in err:
            safe = {k: v for k, v in fields.items() if k in _BASE_USER_COLS}
            if safe:
                try:
                    _get_db().table("users").update(safe).eq("id", user_id).execute()
                    logger.warning(f"update_user({user_id}): stripped missing cols, saved {list(safe)}")
                    return True
                except Exception as e2:
                    logger.error(f"update_user({user_id}) retry: {e2}")
        logger.error(f"update_user({user_id}): {e}")
        return False


def mark_user_pro(user_id: str, paypal_order_id: str = "", subscription_id: str = "") -> bool:
    """Upgrade user to paid Pro — clears trial, sets subscription fields."""
    fields = {
        "is_pro":           True,
        "plan":             "pro",
        "trial_active":     False,
        "paypal_order_id":  paypal_order_id,
    }
    if subscription_id:
        fields["paypal_subscription_id"] = subscription_id
        fields["subscription_status"]    = "ACTIVE"
        fields["subscription_billing"]   = "monthly"
    return update_user(user_id, fields)


def mark_user_pro_annual(user_id: str, subscription_id: str) -> bool:
    """Upgrade user to annual Pro subscription."""
    return update_user(user_id, {
        "is_pro":                    True,
        "plan":                      "pro",
        "trial_active":              False,
        "paypal_subscription_id":    subscription_id,
        "subscription_status":       "ACTIVE",
        "subscription_billing":      "annual",
        "subscription_renewed_at":   str(_date.today()),
    })


def downgrade_user_to_free(user_id: str, reason: str = "payment_failed") -> bool:
    """
    Downgrade a user from Pro → Free.
    Called when:
      - PayPal payment fails (webhook BILLING.SUBSCRIPTION.PAYMENT.FAILED)
      - Subscription cancelled (webhook BILLING.SUBSCRIPTION.CANCELLED)
      - Trial expires (expire_trial_if_needed)
    Never raises — graceful failure.
    """
    try:
        success = update_user(user_id, {
            "is_pro":                 False,
            "plan":                   "free",
            "trial_active":           False,
            "subscription_status":    "INACTIVE",
            "downgraded_at":          str(_date.today()),
            "downgrade_reason":       reason,
        })
        if success:
            logger.info(f"User {user_id} downgraded to free — reason: {reason}")
        return success
    except Exception as e:
        logger.error(f"downgrade_user_to_free({user_id}): {e}")
        return False


def get_user_by_subscription_id(subscription_id: str) -> dict | None:
    """Find a user by their PayPal subscription ID."""
    try:
        return _one(
            _get_db().table("users")
            .select("*")
            .eq("paypal_subscription_id", subscription_id)
            .limit(1)
            .execute()
        )
    except Exception as e:
        logger.error(f"get_user_by_subscription_id({subscription_id}): {e}")
        return None


def renew_subscription(user_id: str, subscription_id: str) -> bool:
    """Mark a successful subscription renewal payment."""
    return update_user(user_id, {
        "is_pro":                   True,
        "plan":                     "pro",
        "subscription_status":      "ACTIVE",
        "subscription_renewed_at":  str(_date.today()),
    })


def log_payment_event(user_id: str, event_type: str, amount: str = "", subscription_id: str = "", order_id: str = "") -> None:
    """Log a PayPal payment event to the payments table (non-fatal)."""
    try:
        import datetime as _dt
        _get_db().table("payments").insert({
            "user_id":         user_id,
            "event_type":      event_type,
            "amount":          amount,
            "subscription_id": subscription_id,
            "order_id":        order_id,
            "created_at":      _dt.datetime.utcnow().isoformat(),
        }).execute()
    except Exception as e:
        logger.debug(f"log_payment_event (non-fatal): {e}")


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
            _get_db().table("scans").insert({
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
            _get_db().table("scans")
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
            _get_db().table("scans")
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
        _get_db().table("scan_tasks").insert({
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
        _get_db().table("scan_tasks").update(fields).eq("id", task_id).execute()
    except Exception as e:
        logger.error(f"update_scan_task({task_id}): {e}")


def get_scan_task(task_id: str, user_id: str) -> dict | None:
    try:
        return _one(
            _get_db().table("scan_tasks")
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
    Tries to write all trial columns; if extended columns don't exist yet,
    falls back to just setting plan='pro_trial' (minimum viable trial).
    """
    today    = _date.today()
    end_date = today + _td(days=TRIAL_DAYS)

    # Full trial fields (requires migration)
    full_fields = {
        "plan":             "pro_trial",
        "trial_active":     True,
        "trial_start_date": str(today),
        "trial_end_date":   str(end_date),
        "is_pro":           True,
    }
    # Minimum viable fields (always works, plan col always exists)
    min_fields = {"plan": "pro_trial"}

    try:
        _get_db().table("users").update(full_fields).eq("id", user_id).execute()
        logger.info(f"Trial started for {user_id} → ends {end_date}")
        return True
    except Exception as e:
        logger.warning(f"start_trial full fields failed ({e}), trying minimum fields")
        try:
            _get_db().table("users").update(min_fields).eq("id", user_id).execute()
            logger.info(f"Trial started (plan only) for {user_id}")
            return True
        except Exception as e2:
            logger.error(f"start_trial failed entirely: {e2}")
            return False


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

    # Parse trial end date safely — column may not exist yet
    trial_end_raw = user.get("trial_end_date") or ""
    trial_end     = None
    try:
        if trial_end_raw:
            trial_end = _date.fromisoformat(str(trial_end_raw))
    except (ValueError, TypeError):
        pass

    # When trial columns don't exist yet, treat pro_trial plan as 30 days from created_at
    if plan == "pro_trial" and not trial_end:
        created_raw = user.get("created_at") or ""
        try:
            if created_raw:
                from datetime import datetime as _dt
                created = _dt.fromisoformat(str(created_raw)[:10])
                trial_end = created.date() + _td(days=TRIAL_DAYS)
        except Exception:
            trial_end = today + _td(days=TRIAL_DAYS)  # assume fresh trial

    # Determine effective status
    if plan in ("pro", "enterprise"):
        return {"plan": plan, "is_pro": True, "trial_active": False,
                "trial_expired": False, "days_left": 0, "trial_end": ""}

    if plan == "pro_trial":
        # Check trial_active column if it exists, otherwise infer from dates
        col_active = user.get("trial_active")
        if col_active is False:
            # Explicitly deactivated
            return {"plan": "free", "is_pro": False, "trial_active": False,
                    "trial_expired": True, "days_left": 0, "trial_end": ""}
        if trial_end and today <= trial_end:
            days_left = (trial_end - today).days
            return {"plan": "pro_trial", "is_pro": True, "trial_active": True,
                    "trial_expired": False, "days_left": days_left,
                    "trial_end": str(trial_end)}
        else:
            # Window passed
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
    Insert a user row. Strips problematic columns on failure and retries,
    so missing migrations and FK errors never block registration.
    """
    try:
        _get_db().table("users").insert(data).execute()
        return True
    except Exception as e:
        err = str(e).lower()
        # FK failure (org_id) or column doesn't exist → strip and retry
        if "foreign" in err or "org_id" in err or "column" in err or "does not exist" in err:
            safe = {k: v for k, v in data.items()
                    if k in {"id","email","password_hash","plan","role","api_key_hash","created_at"}}
            try:
                _get_db().table("users").insert(safe).execute()
                logger.warning(f"insert_user: stripped FK/cols, inserted with {list(safe)}")
                return True
            except Exception as e2:
                logger.error(f"insert_user retry: {e2}")
        logger.error(f"insert_user: {e}")
        return False


# ── Organisation helpers ──────────────────────────────────────

def insert_org(data: dict) -> bool:
    """Insert an org row — graceful if table doesn't exist."""
    try:
        _get_db().table("organizations").insert(data).execute()
        return True
    except Exception as e:
        logger.warning(f"insert_org (non-fatal): {e}")
        return False


def fetch_org_by_id(org_id: str) -> dict | None:
    try:
        return _one(
            _get_db().table("organizations").select("*").eq("id", org_id).limit(1).execute()
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

    Phase 1: also stores `security_score` (weighted 0-100 score) inside
    result_json so /api/analytics/security-trend can chart it over time.
    Backward compatible — defaults to the legacy `score` if not provided.
    """
    try:
        security_score = data.get("security_score", data.get("score", 0))
        row = {
            "user_id":       data.get("user_id"),
            "source":        data.get("input_text", "")[:120] or "code_paste",
            "risk_level":    data.get("risk", data.get("risk_level", "LOW")),
            "total_secrets": data.get("findings_count", 0),
            "result_json": {
                "explanation":     data.get("explanation", ""),
                "fixes":           data.get("fixes", []),
                "score":           data.get("score", 0),
                "security_score":  security_score,
                "findings_count":  data.get("findings_count", 0),
            },
        }
        if data.get("id"):
            row["id"] = data["id"]
        if data.get("timestamp"):
            row["created_at"] = data["timestamp"]
        _get_db().table("scans").insert(row).execute()
        return True
    except Exception as e:
        logger.error(f"insert_scan_history: {e}")
        return False


def fetch_scan_history(user_id: str, limit: int = 20) -> list:
    """Fetch scan history for a user, newest first."""
    return list_scans(user_id, limit=limit)


# ══════════════════════════════════════════════════════════════
#  PHASE 1 — SECURITY TREND ANALYTICS
# ══════════════════════════════════════════════════════════════

def fetch_security_score_trend(user_id: str, days: int = 30) -> list:
    """
    Return the security_score for each scan in the last `days` days,
    newest last (chronological order — good for line charts).

    Returns:
        [ { "date": "2025-05-01", "score": 82 }, ... ]

    Reads from the `scans` table's result_json.security_score field.
    Falls back to result_json.score (legacy) if security_score is absent.
    Never raises — returns [] on any error so the dashboard chart
    always has *something* to render (an empty state).
    """
    try:
        from datetime import datetime, timezone, timedelta
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        res = (
            _get_db().table("scans")
            .select("created_at, result_json")
            .eq("user_id", user_id)
            .gte("created_at", since)
            .order("created_at", desc=False)
            .limit(500)
            .execute()
        )
        rows = res.data or []

        points = []
        for r in rows:
            rj = r.get("result_json") or {}
            score = rj.get("security_score", rj.get("score"))
            if score is None:
                continue
            created = r.get("created_at", "")
            date_str = created[:10] if created else ""
            points.append({"date": date_str, "score": int(score)})

        return points
    except Exception as e:
        logger.debug(f"fetch_security_score_trend (non-fatal): {e}")
        return []


# ══════════════════════════════════════════════════════════════
#  PHASE 1 — ENTERPRISE AUDIT LOG QUERIES
# ══════════════════════════════════════════════════════════════

def fetch_audit_log(org_id: str | None = None, user_id: str | None = None,
                     limit: int = 50, action_filter: str = "") -> list:
    """
    Fetch audit log entries, newest first.

    At least one of org_id / user_id should be provided to scope results.
    If both are None, returns [] (avoids accidentally returning all rows).

    action_filter: optional substring match against the `action` column
    (e.g. "scan", "login", "subscription", "admin").

    Returns a list of dicts with at least: id, user_id, action, created_at,
    plus any of org_id/resource/ip_address/metadata that exist on the row.
    Never raises — returns [] on any error.
    """
    if not org_id and not user_id:
        return []

    try:
        q = _get_db().table("audit_logs").select("*")
        if org_id:
            q = q.eq("org_id", org_id)
        elif user_id:
            q = q.eq("user_id", user_id)

        if action_filter:
            # Supabase PostgREST 'ilike' for case-insensitive substring match
            q = q.ilike("action", f"%{action_filter}%")

        res = q.order("created_at", desc=True).limit(limit).execute()
        return res.data or []
    except Exception as e:
        logger.debug(f"fetch_audit_log (non-fatal): {e}")
        return []


# ── Usage tracking ────────────────────────────────────────────

def fetch_usage_today(user_id: str, today: str) -> dict | None:
    try:
        return _one(
            _get_db().table("usage_tracking")
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
            _get_db().table("usage_tracking").update(
                {"request_count": count}
            ).eq("user_id", user_id).eq("date", today).execute()
        else:
            _get_db().table("usage_tracking").insert({
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
            _get_db().table("usage_tracking")
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
        _get_db().table("audit_logs").insert(row).execute()
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
        _get_db().table("scan_tasks").insert(data).execute()
        return True
    except Exception as e:
        logger.error(f"insert_scan_task: {e}")
        return False
