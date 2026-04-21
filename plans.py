from config import DEV_MODE

def get_plan_limits(plan: str):
    """
    Central limits system.
    DEV_MODE unlocks everything for testing.
    """

    if DEV_MODE:
        return {
            "daily_scans": 999999,
            "history_limit": 999999,
            "ai_depth": "full",
            "repo_scan": True,
            "team_management": True,
        }

    plan = (plan or "free").lower()

    return {
        "free": {
            "daily_scans": 10,
            "history_limit": 10,
            "ai_depth": "basic",
            "repo_scan": False,
            "team_management": False,
        },
        "pro": {
            "daily_scans": 100,
            "history_limit": 100,
            "ai_depth": "full",
            "repo_scan": True,
            "team_management": False,
        },
        "enterprise": {
            "daily_scans": 1000,
            "history_limit": 1000,
            "ai_depth": "full",
            "repo_scan": True,
            "team_management": True,
        },
    }.get(plan, {})