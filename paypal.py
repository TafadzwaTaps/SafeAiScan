"""
paypal.py — PayPal Checkout Integration
=========================================
Handles the full PayPal Orders API v2 flow:

  1. POST /payment/create   → create a PayPal order, return approval URL
  2. GET  /payment/success  → capture the approved order, mark user Pro
  3. GET  /payment/cancel   → handle cancelled payment

Uses PayPal Orders API v2 (REST) with client_credentials auth.
No SDK required — just httpx.

Environment variables required:
  PAYPAL_CLIENT_ID      — from developer.paypal.com
  PAYPAL_CLIENT_SECRET  — from developer.paypal.com
  PAYPAL_MODE           — "sandbox" (default) or "live"
  APP_BASE_URL          — your deployed frontend URL (for redirect_url links)
                          e.g. https://yourdomain.com

PayPal Sandbox testing:
  Use https://developer.paypal.com/tools/sandbox/ buyer accounts.
  Switch PAYPAL_MODE=live for production.
"""

import os
import logging
import httpx

logger = logging.getLogger("secretscan.paypal")

# ──────────────────────────────────────────────────────────────
#  CONFIG
# ──────────────────────────────────────────────────────────────

CLIENT_ID     = os.getenv("PAYPAL_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")
MODE          = os.getenv("PAYPAL_MODE", "sandbox").lower()   # "sandbox" | "live"
APP_BASE_URL  = os.getenv("APP_BASE_URL", "http://localhost:3000")

# Pro plan pricing — change here to update everywhere
PRO_PRICE_USD = "9.99"
PRO_CURRENCY  = "USD"
PRO_PLAN_NAME = "SecretScan Pro — Unlimited Scans + PDF Reports"

_BASE = {
    "sandbox": "https://api-m.sandbox.paypal.com",
    "live":    "https://api-m.paypal.com",
}.get(MODE, "https://api-m.sandbox.paypal.com")

if not CLIENT_ID or not CLIENT_SECRET:
    logger.warning(
        "PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET not set. "
        "PayPal endpoints will return errors until configured."
    )


# ──────────────────────────────────────────────────────────────
#  LOW-LEVEL HELPERS
# ──────────────────────────────────────────────────────────────

def _get_access_token() -> str:
    """
    Fetch a short-lived PayPal OAuth2 bearer token.
    Called before every API request (tokens expire in ~9 hours,
    but fetching fresh each time keeps things simple for an MVP).

    Raises:
        RuntimeError: if credentials are wrong or PayPal is unreachable.
    """
    if not CLIENT_ID or not CLIENT_SECRET:
        raise RuntimeError(
            "PayPal credentials not configured. Set PAYPAL_CLIENT_ID and "
            "PAYPAL_CLIENT_SECRET environment variables."
        )

    try:
        resp = httpx.post(
            f"{_BASE}/v1/oauth2/token",
            data={"grant_type": "client_credentials"},
            auth=(CLIENT_ID, CLIENT_SECRET),
            timeout=15,
        )
        resp.raise_for_status()
        token = resp.json().get("access_token")
        if not token:
            raise RuntimeError("PayPal returned no access_token.")
        return token

    except httpx.HTTPStatusError as e:
        logger.error(f"PayPal auth failed ({e.response.status_code}): {e.response.text[:200]}")
        raise RuntimeError(f"PayPal authentication failed: {e.response.status_code}")
    except httpx.RequestError as e:
        logger.error(f"PayPal unreachable: {e}")
        raise RuntimeError("Could not reach PayPal. Please try again.")


def _paypal_headers() -> dict:
    return {
        "Authorization": f"Bearer {_get_access_token()}",
        "Content-Type":  "application/json",
    }


# ──────────────────────────────────────────────────────────────
#  PUBLIC API
# ──────────────────────────────────────────────────────────────

def create_order(user_id: str) -> dict:
    """
    Create a PayPal Order for the Pro plan upgrade.

    Returns:
        {
          "order_id":    "5O190127TN364715T",
          "approve_url": "https://www.paypal.com/checkoutnow?token=..."
        }

    Raises:
        RuntimeError: if the PayPal API call fails.
    """
    # Build return URLs — PayPal redirects the browser here after payment
    success_url = f"{APP_BASE_URL}/payment/success?user_id={user_id}"
    cancel_url  = f"{APP_BASE_URL}/payment/cancel"

    order_payload = {
        "intent": "CAPTURE",
        "purchase_units": [{
            "amount": {
                "currency_code": PRO_CURRENCY,
                "value":         PRO_PRICE_USD,
            },
            "description": PRO_PLAN_NAME,
            # Custom ID lets us match the order to a user on the success callback
            "custom_id": user_id,
        }],
        "application_context": {
            "brand_name":          "SecretScan",
            "landing_page":        "BILLING",
            "user_action":         "PAY_NOW",
            "return_url":          success_url,
            "cancel_url":          cancel_url,
            "shipping_preference": "NO_SHIPPING",
        },
    }

    try:
        resp = httpx.post(
            f"{_BASE}/v2/checkout/orders",
            json=order_payload,
            headers=_paypal_headers(),
            timeout=20,
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        logger.error(f"create_order failed ({e.response.status_code}): {e.response.text[:300]}")
        raise RuntimeError(f"PayPal order creation failed: {e.response.status_code}")
    except httpx.RequestError as e:
        logger.error(f"PayPal unreachable during create_order: {e}")
        raise RuntimeError("Could not reach PayPal. Please try again.")

    data = resp.json()
    order_id = data.get("id")

    # Find the "approve" link in the HATEOAS links array
    approve_url = next(
        (link["href"] for link in data.get("links", []) if link["rel"] == "approve"),
        None,
    )

    if not order_id or not approve_url:
        logger.error(f"Unexpected PayPal response: {data}")
        raise RuntimeError("PayPal returned an unexpected response. Please try again.")

    logger.info(f"PayPal order created: {order_id} for user {user_id}")
    return {"order_id": order_id, "approve_url": approve_url}


def capture_order(order_id: str) -> dict:
    """
    Capture (finalise) an approved PayPal order.

    Call this from GET /payment/success after PayPal redirects back.

    Returns:
        The full PayPal capture response dict.

    Raises:
        RuntimeError: if capture fails (payment not approved, already captured, etc.).
    """
    try:
        resp = httpx.post(
            f"{_BASE}/v2/checkout/orders/{order_id}/capture",
            headers=_paypal_headers(),
            json={},   # empty body required by PayPal
            timeout=20,
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        logger.error(f"capture_order({order_id}) failed ({e.response.status_code}): {e.response.text[:300]}")
        raise RuntimeError(f"Payment capture failed: {e.response.status_code}")
    except httpx.RequestError as e:
        logger.error(f"PayPal unreachable during capture: {e}")
        raise RuntimeError("Could not reach PayPal. Please try again.")

    data   = resp.json()
    status = data.get("status")

    if status != "COMPLETED":
        logger.warning(f"Capture status for {order_id}: {status}")
        raise RuntimeError(f"Payment not completed (status: {status}). Please try again.")

    logger.info(f"PayPal order captured: {order_id} status={status}")
    return data


def get_order_user_id(capture_data: dict) -> str | None:
    """
    Extract the user_id from the custom_id field we embedded when creating the order.
    This is how we know which user to upgrade after payment.
    """
    try:
        units = capture_data.get("purchase_units", [])
        if units:
            return units[0].get("custom_id")
    except Exception:
        pass
    return None
