"""
auth.py — JWT Authentication
==============================
Stateless JWT-based auth. No roles, no enterprise tiers.
Tokens carry only the user's ID (sub claim).

Kept intentionally minimal — bcrypt hashing lives in app.py
so this module has zero FastAPI imports and is easy to unit-test.
"""

import os
import logging
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError

logger = logging.getLogger("secretscan.auth")

# Read from env; fall back to a dev-only default (override in production!)
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production-use-a-long-random-string")
ALGORITHM  = "HS256"
TOKEN_TTL_MINUTES = 60 * 24   # 24 hours — long enough to avoid friction


def create_access_token(user_id) -> str:
    """
    Create a signed JWT for the given user ID.

    Accepts either:
      - a plain string user UUID  (new style: create_access_token(user_id))
      - a dict with a "sub" key   (old style: create_access_token({"sub": user_id}))

    The token contains:
      sub  — user UUID (primary claim, used by get_current_user)
      iat  — issued-at timestamp
      exp  — expiry timestamp
    """
    # Support both calling conventions without breaking either
    if isinstance(user_id, dict):
        sub = str(user_id.get("sub", ""))
    else:
        sub = str(user_id)

    now    = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=TOKEN_TTL_MINUTES)

    payload = {
        "sub": sub,
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict | None:
    """
    Decode and validate a JWT.

    Returns the full payload dict on success, or None if the token is
    missing, expired, or tampered with.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        if not payload.get("sub"):
            logger.warning("Token missing 'sub' claim")
            return None

        return payload

    except JWTError as e:
        logger.debug(f"JWT verification failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected token error: {e}")
        return None
