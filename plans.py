"""
plans.py — SINGLE SOURCE OF TRUTH (FIXED)
"""

PLAN_LIMITS = {
    "free": {
        "daily_scans": 20,
        "history_limit": 5,
        "ai_depth": "basic",
        "features": {
            "repo_scan": False,
            "api_access": False,
            "audit_logs": False,
            "pdf_export": True,
            "cve_lookup": True,
            "webhooks": False,
            "team_members": False,
        }
    },
    "pro": {
        "daily_scans": 200,
        "history_limit": 100,
        "ai_depth": "full",
        "features": {
            "repo_scan": True,
            "api_access": True,
            "audit_logs": True,
            "pdf_export": True,
            "cve_lookup": True,
            "webhooks": False,
            "team_members": True,
        }
    },
    "enterprise": {
        "daily_scans": 999999,
        "history_limit": 999999,
        "ai_depth": "full",
        "features": {
            "repo_scan": True,
            "api_access": True,
            "audit_logs": True,
            "pdf_export": True,
            "cve_lookup": True,
            "webhooks": True,
            "team_members": True,
        }
    }
}


# -----------------------------
# SAFE ACCESS HELPERS (FIXED)
# -----------------------------

def get_plan_limits(plan: str):
    return PLAN_LIMITS.get((plan or "free").lower(), PLAN_LIMITS["free"])


def get_feature(plan: str, feature: str) -> bool:
    return get_plan_limits(plan)["features"].get(feature, False)


def get_ai_depth(plan: str) -> str:
    return get_plan_limits(plan)["ai_depth"]


def get_daily_limit(plan: str) -> int:
    return get_plan_limits(plan)["daily_scans"]


def get_history_limit(plan: str) -> int:
    return get_plan_limits(plan)["history_limit"]


def within_limit(plan: str, count: int) -> bool:
    return count <= get_daily_limit(plan)