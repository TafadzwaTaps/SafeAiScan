import os
import logging
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("safeaiscan.auth")

SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_THIS_IN_PRODUCTION_MUST_BE_LONG_AND_RANDOM")
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 90  # 1.5 hours


def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    to_encode = data.copy()
    expire    = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Validate required fields
        if not payload.get("sub"):
            logger.warning("Token missing 'sub' claim")
            return None
        return payload
    except JWTError as e:
        logger.debug(f"JWT verification failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Token error: {e}")
        return None
