from config import DEV_MODE

# Single source of truth for all plan limits
_PLAN_LIMITS = {
    "free": {
        "daily_scans":      10,
        "history_limit":    10,
        "ai_depth":         "basic",
        "repo_scan":        False,
        "team_management":  False,
    },
    "pro": {
        "daily_scans":      100,
        "history_limit":    100,
        "ai_depth":         "full",
        "repo_scan":        True,
        "team_management":  False,
    },
    "enterprise": {
        "daily_scans":      1000,
        "history_limit":    1000,
        "ai_depth":         "full",
        "repo_scan":        True,
        "team_management":  True,
    },
}

_DEV_LIMITS = {
    "daily_scans":      999999,
    "history_limit":    999999,
    "ai_depth":         "full",
    "repo_scan":        True,
    "team_management":  True,
}

def get_plan_limits(plan: str) -> dict:
    """
    Central limits system.
    DEV_MODE unlocks everything for testing.
    FIX: always returns a complete dict — never returns {} which causes KeyError
         when callers access limits["daily_scans"] etc.
    """
    if DEV_MODE:
        return _DEV_LIMITS.copy()

    plan = (plan or "free").lower()
    # FIX: fall back to free limits for any unrecognised plan string
    return _PLAN_LIMITS.get(plan, _PLAN_LIMITS["free"]).copy()
