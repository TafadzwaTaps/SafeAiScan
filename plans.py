"""
plans.py — SaaS tier definitions
Single source of truth for plan limits and feature access.
Import this everywhere instead of duplicating PLAN_LIMITS dicts.
"""

PLAN_LIMITS: dict[str, dict] = {
    "free": {
        "daily_scans":   20,
        "history_limit": 5,
        "repo_scan":     False,
        "ai_depth":      "basic",
        "api_access":    False,
        "team_members":  1,
        "pdf_export":    True,
        "cve_lookup":    True,
        "audit_logs":    False,
        "webhooks":      False,
    },
    "pro": {
        "daily_scans":   200,
        "history_limit": 100,
        "repo_scan":     True,
        "ai_depth":      "full",
        "api_access":    True,
        "team_members":  5,
        "pdf_export":    True,
        "cve_lookup":    True,
        "audit_logs":    True,
        "webhooks":      False,
    },
    "enterprise": {
        "daily_scans":   999_999,
        "history_limit": 999_999,
        "repo_scan":     True,
        "ai_depth":      "full",
        "api_access":    True,
        "team_members":  999_999,
        "pdf_export":    True,
        "cve_lookup":    True,
        "audit_logs":    True,
        "webhooks":      True,
    },
}

# Role hierarchy: higher index = more permissions
ROLE_HIERARCHY = ["viewer", "member", "admin"]

def get_plan_limits(plan: str) -> dict:
    return PLAN_LIMITS.get((plan or "free").lower(), PLAN_LIMITS["free"])

def check_plan_access(plan: str, feature: str) -> bool:
    return bool(get_plan_limits(plan).get(feature, False))

def check_role(user_role: str, required_role: str) -> bool:
    """Returns True if user_role is at least as permissive as required_role."""
    try:
        return ROLE_HIERARCHY.index(user_role) >= ROLE_HIERARCHY.index(required_role)
    except ValueError:
        return False

def within_limit(count: int, plan: str) -> bool:
    return count <= get_plan_limits(plan)["daily_scans"]
