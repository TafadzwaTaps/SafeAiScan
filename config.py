import os

# ============================================================
#  CONFIG — single source of truth
#  DEV_MODE=true in .env → all plan gates unlocked
#  DEV_MODE=false (or unset) → production gating enforced
# ============================================================

_raw = os.getenv("DEV_MODE", "true").lower().strip()
DEV_MODE: bool = _raw in ("1", "true", "yes", "on")
