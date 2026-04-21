from plans import PLAN_LIMITS

def get_limits(plan: str):
    return PLAN_LIMITS.get(plan.lower(), PLAN_LIMITS["free"])


def has_feature(user, feature: str) -> bool:
    plan = user.get("plan", "free").lower()
    return get_limits(plan)["features"].get(feature, False)


def enforce_feature(user, feature: str):
    if not has_feature(user, feature):
        from fastapi import HTTPException
        raise HTTPException(
            status_code=403,
            detail={
                "success": False,
                "error": f"{feature} requires Pro or higher plan"
            }
        )


def get_ai_depth(user):
    plan = user.get("plan", "free").lower()
    return get_limits(plan)["ai_depth"]


def get_daily_limit(user):
    plan = user.get("plan", "free").lower()
    return get_limits(plan)["daily_scans"]


def within_limit(count: int, user) -> bool:
    return count < get_daily_limit(user)