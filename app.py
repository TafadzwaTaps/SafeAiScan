"""
app.py — SecretScan API
========================
Lean FastAPI backend. One product, one purpose: detect hardcoded secrets.

Endpoints
─────────
POST /auth/register            Create account
POST /auth/login               Login → JWT
GET  /auth/me                  Current user profile

POST /scan/file                Upload ZIP → synchronous scan → result
POST /scan/repo                GitHub URL → async background scan → task_id
GET  /scan/status/{task_id}    Poll async scan progress
GET  /scan/history             List user's past scans

GET  /report/{scan_id}         Fetch full scan result JSON
GET  /report/{scan_id}/pdf     Download PDF report (Pro only)

POST /payment/create           Create PayPal order → return approval URL
GET  /payment/success          Capture PayPal payment → upgrade user to Pro
GET  /payment/cancel           Handle cancelled payment

GET  /health                   Liveness probe

Design decisions
────────────────
- No plans.py / access.py — replaced by a single `is_pro` boolean on the user.
- Free tier:  1 scan/day, first 5 findings shown, no PDF download.
- Pro tier:   unlimited scans, all findings, PDF download.
- PayPal upgrade flow is 3 endpoints (create → PayPal redirect → capture).
- All responses use ok() / fail() envelope for consistent frontend parsing.
"""

import os
import uuid
import logging
import tempfile
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from fastapi import (
    FastAPI, Depends, HTTPException, Header,
    Request, BackgroundTasks, UploadFile, File,
)
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from passlib.context import CryptContext

import db
import paypal
from auth import create_access_token, verify_token
from scanner import scan_zip, validate_repo_url
from tasks import run_repo_scan
from pdf import generate_pdf

# ──────────────────────────────────────────────────────────────
#  LOGGING
# ──────────────────────────────────────────────────────────────

logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("secretscan")

# ──────────────────────────────────────────────────────────────
#  APP + CORS
# ──────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "SecretScan API",
    description = "Upload code → detect exposed secrets → upsell Pro.",
    version     = "1.0.0",
    docs_url    = "/docs",
)

_origins = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5500,https://rathious-safeaiscan.hf.space",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins     = [o.strip() for o in _origins],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ──────────────────────────────────────────────────────────────
#  CRYPTO
# ──────────────────────────────────────────────────────────────

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _hash(plain: str) -> str:
    return _pwd.hash(plain[:72])


def _check(plain: str, hashed: str) -> bool:
    try:
        return _pwd.verify(plain, hashed)
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────
#  RESPONSE HELPERS
# ──────────────────────────────────────────────────────────────

def ok(data=None, **kw) -> dict:
    """Standard success envelope."""
    return {"success": True, "data": data, **kw}


def fail(msg: str, code: int = 400):
    """Raise a structured HTTP error."""
    raise HTTPException(status_code=code, detail={"success": False, "error": msg})


# ──────────────────────────────────────────────────────────────
#  REQUEST MODELS
# ──────────────────────────────────────────────────────────────

class RegisterBody(BaseModel):
    email:    str
    password: str

    @field_validator("email")
    @classmethod
    def valid_email(cls, v: str) -> str:
        v = v.lower().strip()
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Enter a valid email address.")
        return v

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters.")
        return v


class LoginBody(BaseModel):
    email:    str
    password: str

    @field_validator("email")
    @classmethod
    def norm(cls, v: str) -> str:
        return v.lower().strip()


class RepoBody(BaseModel):
    repo_url: str

    @field_validator("repo_url")
    @classmethod
    def valid_url(cls, v: str) -> str:
        v = v.strip()
        try:
            validate_repo_url(v)
        except ValueError as exc:
            raise ValueError(str(exc))
        return v


# ──────────────────────────────────────────────────────────────
#  AUTH DEPENDENCY
# ──────────────────────────────────────────────────────────────

def get_current_user(
    request:       Request,
    authorization: str = Header(None),
) -> dict:
    """
    Validate the Bearer JWT and return the user dict from the DB.
    Result is cached on request.state so multiple dependencies
    in the same request don't hit the DB more than once.
    """
    if hasattr(request.state, "_user"):
        return request.state._user

    if not authorization:
        raise HTTPException(401, detail={"success": False, "error": "Authorization header required."})

    token   = authorization.removeprefix("Bearer ").strip()
    payload = verify_token(token)

    if not payload:
        raise HTTPException(401, detail={"success": False, "error": "Invalid or expired token."})

    user = db.get_user_by_id(payload["sub"])
    if not user:
        raise HTTPException(401, detail={"success": False, "error": "User not found."})

    request.state._user = user
    return user


# ──────────────────────────────────────────────────────────────
#  AUTH ENDPOINTS
# ──────────────────────────────────────────────────────────────

@app.post("/auth/register", summary="Create a new account")
def register(body: RegisterBody):
    """
    Creates a user account and returns a JWT.
    New users start on the Free tier (is_pro=False).
    """
    if db.email_exists(body.email):
        fail("This email is already registered.", 409)

    user = db.create_user(body.email, _hash(body.password))
    if not user:
        fail("Registration failed. Please try again.", 500)

    token = create_access_token(user["id"])
    logger.info(f"Registered: {body.email} ({user['id']})")
    return ok({"access_token": token, "user_id": user["id"], "is_pro": False})


@app.post("/auth/login", summary="Login and receive a JWT")
def login(body: LoginBody):
    """Returns a JWT on valid credentials."""
    user = db.get_user_by_email(body.email)

    if not user or not _check(body.password, user.get("password_hash", "")):
        raise HTTPException(
            401, detail={"success": False, "error": "Invalid email or password."}
        )

    token = create_access_token(user["id"])
    logger.info(f"Login: {body.email}")
    return ok({
        "access_token": token,
        "user_id":      user["id"],
        "is_pro":       user.get("is_pro", False),
    })


@app.get("/auth/me", summary="Current user profile")
def get_me(user: dict = Depends(get_current_user)):
    return ok({
        "user_id":    user["id"],
        "email":      user.get("email"),
        "is_pro":     user.get("is_pro", False),
        "scans_today": user.get("scans_today", 0),
    })


# ──────────────────────────────────────────────────────────────
#  SCAN ENDPOINTS
# ──────────────────────────────────────────────────────────────

@app.post("/scan/file", summary="Upload a ZIP file and scan for secrets")
async def scan_file(
    file: UploadFile = File(..., description="ZIP archive of your project"),
    user: dict       = Depends(get_current_user),
):
    """
    Accepts a .zip archive, extracts it, scans every eligible file,
    and returns the full result synchronously.

    Free users: limited to 1 scan/day and first 5 findings.
    Pro users:  unlimited scans, all findings.
    """
    # ── Rate-limit check ──────────────────────────────────────
    allowed, reason = db.check_and_increment_scan(user["id"])
    if not allowed:
        fail(reason, 429)

    # ── File validation ───────────────────────────────────────
    if not (file.filename or "").lower().endswith(".zip"):
        fail("Only .zip files are accepted.", 422)

    # ── Write upload to temp file ─────────────────────────────
    fd, tmp_path = tempfile.mkstemp(suffix=".zip")
    try:
        import os as _os
        _os.close(fd)
        content = await file.read()

        with open(tmp_path, "wb") as fh:
            fh.write(content)

        logger.info(
            f"ZIP scan: user={user['id']} file={file.filename} "
            f"size={len(content):,}B is_pro={user.get('is_pro')}"
        )

        is_pro  = user.get("is_pro", False)
        result  = scan_zip(tmp_path, is_pro=is_pro)
        scan_id = db.save_scan(user["id"], "zip_upload", result)

        logger.info(
            f"ZIP scan done: scan_id={scan_id} "
            f"secrets={result['total_secrets']} risk={result['risk_level']}"
        )
        return ok({**result, "scan_id": scan_id})

    except (ValueError, RuntimeError) as exc:
        fail(str(exc), 422)
    except Exception as exc:
        logger.error(f"ZIP scan error ({user['id']}): {exc}")
        fail("Scan failed. Please try again.", 500)
    finally:
        try:
            import os as _os
            _os.unlink(tmp_path)
        except OSError:
            pass


@app.post("/scan/repo", summary="Queue a GitHub repository scan")
def scan_repo_endpoint(
    body:             RepoBody,
    background_tasks: BackgroundTasks,
    user:             dict = Depends(get_current_user),
):
    """
    Accepts a GitHub URL, queues a background scan, returns a task_id immediately.
    Poll GET /scan/status/{task_id} for progress updates.
    When state == DONE the full result is included in the response.
    """
    # ── Rate-limit check ──────────────────────────────────────
    allowed, reason = db.check_and_increment_scan(user["id"])
    if not allowed:
        fail(reason, 429)

    task_id = str(uuid.uuid4())
    is_pro  = user.get("is_pro", False)

    ok_flag = db.create_scan_task(task_id, user["id"], body.repo_url)
    if not ok_flag:
        fail("Failed to queue scan. Please try again.", 500)

    # Pass is_pro so the background worker applies the right result filter
    background_tasks.add_task(run_repo_scan, task_id, body.repo_url, user["id"], is_pro)

    logger.info(f"Repo scan queued: task={task_id} repo={body.repo_url} user={user['id']}")
    return ok({
        "task_id":  task_id,
        "status":   "queued",
        "poll_url": f"/scan/status/{task_id}",
    })


@app.get("/scan/status/{task_id}", summary="Poll async repo scan progress")
def scan_status(task_id: str, user: dict = Depends(get_current_user)):
    """
    Returns the current state of a background repo scan.

    Recommend polling every 3 seconds until state is DONE or FAILED.
    When state == DONE, result_json contains the full findings.
    """
    task = db.get_scan_task(task_id, user["id"])
    if not task:
        fail("Task not found.", 404)
    return ok(task)


@app.get("/scan/history", summary="List past scans")
def scan_history(user: dict = Depends(get_current_user)):
    """Returns the 20 most recent scans for the current user."""
    scans = db.list_scans(user["id"])
    return ok(scans)


# ──────────────────────────────────────────────────────────────
#  REPORT ENDPOINTS
# ──────────────────────────────────────────────────────────────

@app.get("/report/{scan_id}", summary="Fetch a stored scan result")
def get_report(scan_id: str, user: dict = Depends(get_current_user)):
    """Returns the full JSON result for a past scan."""
    record = db.get_scan(scan_id, user["id"])
    if not record:
        fail("Report not found.", 404)
    return ok(record)


@app.get("/report/{scan_id}/pdf", summary="Download PDF report (Pro only)")
def download_pdf(scan_id: str, user: dict = Depends(get_current_user)):
    """
    Generates and streams a PDF report.
    Requires a Pro account — free users see an upgrade prompt.
    """
    if not user.get("is_pro"):
        fail(
            "PDF reports are a Pro feature. "
            "Upgrade at /payment/create to unlock unlimited scans and PDF downloads.",
            403,
        )

    record = db.get_scan(scan_id, user["id"])
    if not record:
        fail("Scan not found.", 404)

    # result_json may be on the record directly or nested
    result   = record.get("result_json") or record
    out_path = f"/tmp/ss_{scan_id}.pdf"

    try:
        generate_pdf(scan_id, result, out_path)
    except Exception as exc:
        logger.error(f"PDF generation failed for {scan_id}: {exc}")
        fail("PDF generation failed.", 500)

    return FileResponse(
        path       = out_path,
        filename   = f"secretscan-{scan_id[:8]}.pdf",
        media_type = "application/pdf",
    )


# ──────────────────────────────────────────────────────────────
#  PAYPAL PAYMENT ENDPOINTS
# ──────────────────────────────────────────────────────────────

@app.post("/payment/create", summary="Initiate PayPal Pro upgrade payment")
def create_payment(user: dict = Depends(get_current_user)):
    """
    Creates a PayPal order for the Pro plan.

    Returns:
        {
          "order_id":    "5O190127TN364715T",
          "approve_url": "https://www.paypal.com/checkoutnow?token=..."
        }

    The frontend should redirect the user to approve_url.
    PayPal will redirect back to /payment/success on completion.
    """
    if user.get("is_pro"):
        fail("You already have a Pro account.", 400)

    try:
        result = paypal.create_order(user["id"])
    except RuntimeError as exc:
        logger.error(f"PayPal create_order failed for {user['id']}: {exc}")
        fail(str(exc), 502)

    logger.info(f"PayPal order created: {result['order_id']} for user {user['id']}")
    return ok(result)


@app.get("/payment/success", summary="PayPal payment success callback")
def payment_success(token: str, PayerID: str = ""):  # noqa: N803 — PayPal uses PascalCase
    """
    PayPal redirects the user here after they approve the payment.

    Query params provided by PayPal:
      token    — the PayPal order ID (confusingly called "token" in the redirect)
      PayerID  — the payer's PayPal account ID

    Steps:
      1. Capture the order (charge the card)
      2. Extract the user_id we embedded in custom_id
      3. Mark the user as Pro in the DB
      4. Redirect the user to the dashboard

    NOTE: In production, also implement PayPal webhooks for reliable
    payment confirmation (covers edge cases like browser crashes).
    """
    order_id = token   # PayPal sends the order ID as "token" in the redirect URL

    try:
        capture_data = paypal.capture_order(order_id)
    except RuntimeError as exc:
        logger.error(f"PayPal capture failed for order {order_id}: {exc}")
        # Redirect to a friendly error page rather than showing a JSON error
        return RedirectResponse(
            url    = f"{paypal.APP_BASE_URL}/payment/error?reason={str(exc)[:100]}",
            status_code = 302,
        )

    # Extract the user_id we stored in custom_id when creating the order
    user_id = paypal.get_order_user_id(capture_data)

    if not user_id:
        logger.error(f"No user_id in capture data for order {order_id}: {capture_data}")
        return RedirectResponse(
            url = f"{paypal.APP_BASE_URL}/payment/error?reason=missing_user",
            status_code = 302,
        )

    # Mark the user as Pro
    upgraded = db.mark_user_pro(user_id, paypal_order_id=order_id)
    if upgraded:
        logger.info(f"User {user_id} upgraded to Pro (order: {order_id})")
    else:
        # Non-fatal: the payment succeeded but the DB update failed.
        # Log for manual follow-up; don't punish the user.
        logger.error(f"Failed to mark user {user_id} as Pro after successful payment {order_id}")

    # Redirect to the dashboard with a success flag so the UI can show a congrats message
    return RedirectResponse(
        url         = f"{paypal.APP_BASE_URL}/dashboard?upgraded=1",
        status_code = 302,
    )


@app.get("/payment/cancel", summary="PayPal payment cancelled callback")
def payment_cancel():
    """
    PayPal redirects here if the user clicks 'Cancel' on the PayPal page.
    No charge has been made — just redirect back to the pricing page.
    """
    logger.info("PayPal payment cancelled by user.")
    return RedirectResponse(
        url         = f"{paypal.APP_BASE_URL}/pricing?cancelled=1",
        status_code = 302,
    )


# ──────────────────────────────────────────────────────────────
#  HOUSEKEEPING
# ──────────────────────────────────────────────────────────────

@app.get("/health", summary="Liveness probe")
def health():
    return {"status": "ok", "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/", include_in_schema=False)
def root():
    return {"service": "SecretScan API", "docs": "/docs"}


@app.exception_handler(Exception)
async def _global_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code = 500,
        content     = {"success": False, "error": "An unexpected error occurred."},
    )
