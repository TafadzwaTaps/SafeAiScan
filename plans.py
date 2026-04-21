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