"""
paypal.py — PayPal Subscription + One-Time Payment Integration
================================================================
Handles the complete PayPal monetization flow for SafeAIScan:

  SUBSCRIPTIONS (preferred — recurring revenue):
    POST /payment/create-subscription  → create PayPal subscription, return approval URL
    GET  /payment/subscription-success → capture subscription ID, upgrade user
    POST /payment/webhook              → IPN/webhook: handle renewals, failures, cancellations

  ONE-TIME ORDERS (fallback if subscriptions unavailable):
    POST /payment/create              → create PayPal order, return approval URL
    GET  /payment/success             → capture order, upgrade user to Pro
    GET  /payment/cancel              → handle cancelled payment

  ENTERPRISE:
    POST /payment/enterprise-inquiry  → log inquiry, return contact info

Environment variables required:
  PAYPAL_CLIENT_ID      — from developer.paypal.com
  PAYPAL_CLIENT_SECRET  — from developer.paypal.com
  PAYPAL_MODE           — "sandbox" (default) or "live"
  PAYPAL_PLAN_ID_PRO    — PayPal Billing Plan ID for Pro Monthly (create in PayPal dashboard)
  PAYPAL_PLAN_ID_ANNUAL — PayPal Billing Plan ID for Pro Annual (optional)
  APP_BASE_URL          — deployed frontend URL, e.g. https://rathious-safeaiscan.hf.space

Revenue targets:
  $1.99/month × 252 users = ~$500/month
  $1.99/month × 503 users = ~$1000/month
  Conversion target: 5-8% of free users → paid (industry average for B2B SaaS)
"""

import os
import logging
import hmac
import hashlib
import httpx

logger = logging.getLogger("safeaiscan.paypal")

# ──────────────────────────────────────────────────────────────
#  CONFIG
# ──────────────────────────────────────────────────────────────

CLIENT_ID     = os.getenv("PAYPAL_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")
MODE          = os.getenv("PAYPAL_MODE", "sandbox").lower()
APP_BASE_URL  = os.getenv("APP_BASE_URL", "http://localhost:3000")
WEBHOOK_ID    = os.getenv("PAYPAL_WEBHOOK_ID", "")  # set after creating webhook in PayPal dashboard

# PayPal Billing Plan IDs — create once in PayPal dashboard, paste here
PLAN_ID_PRO_MONTHLY = os.getenv("PAYPAL_PLAN_ID_PRO", "")
PLAN_ID_PRO_ANNUAL  = os.getenv("PAYPAL_PLAN_ID_ANNUAL", "")

# Pricing
PRO_MONTHLY_USD = "1.99"
PRO_ANNUAL_USD  = "19.08"   # $1.59/mo × 12 = 20% discount
ENTERPRISE_USD  = "49.00"   # custom — contact sales

PRO_CURRENCY    = "USD"
PRO_PLAN_NAME   = "SafeAIScan Pro — Unlimited Scans + PDF Reports"

_BASE = {
    "sandbox": "https://api-m.sandbox.paypal.com",
    "live":    "https://api-m.paypal.com",
}.get(MODE, "https://api-m.sandbox.paypal.com")

if not CLIENT_ID or not CLIENT_SECRET:
    logger.warning(
        "PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET not set. "
        "Set them in HuggingFace Space secrets. PayPal endpoints will error until configured."
    )


# ──────────────────────────────────────────────────────────────
#  LOW-LEVEL HELPERS
# ──────────────────────────────────────────────────────────────

def _get_access_token() -> str:
    """
    Fetch a short-lived PayPal OAuth2 bearer token.
    Called before every API request.
    Raises RuntimeError on failure.
    """
    if not CLIENT_ID or not CLIENT_SECRET:
        raise RuntimeError(
            "PayPal credentials not configured. Set PAYPAL_CLIENT_ID and "
            "PAYPAL_CLIENT_SECRET in your HuggingFace Space secrets."
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
#  SUBSCRIPTIONS  (recurring revenue — preferred path)
# ──────────────────────────────────────────────────────────────

def create_subscription(user_id: str, billing: str = "monthly") -> dict:
    """
    Create a PayPal subscription for Pro plan.

    billing: "monthly" ($1.99) or "annual" ($19.08)

    Returns:
        { "subscription_id": "...", "approve_url": "https://paypal.com/..." }

    NOTE: Requires PAYPAL_PLAN_ID_PRO to be set.
    If no plan ID configured, falls back to one-time order.
    """
    plan_id = PLAN_ID_PRO_ANNUAL if billing == "annual" else PLAN_ID_PRO_MONTHLY

    if not plan_id:
        logger.warning("No PayPal plan ID configured — falling back to one-time order")
        return create_order(user_id)

    return_url = f"{APP_BASE_URL}/payment/subscription-success?user_id={user_id}&billing={billing}"
    cancel_url = f"{APP_BASE_URL}/payment/cancel"

    payload = {
        "plan_id":    plan_id,
        "quantity":   "1",
        "subscriber": {
            "name": {"given_name": "SafeAIScan", "surname": "User"},
        },
        "application_context": {
            "brand_name":          "SafeAIScan",
            "locale":              "en-US",
            "shipping_preference": "NO_SHIPPING",
            "user_action":         "SUBSCRIBE_NOW",
            "payment_method": {
                "payer_selected":   "PAYPAL",
                "payee_preferred":  "IMMEDIATE_PAYMENT_REQUIRED",
            },
            "return_url": return_url,
            "cancel_url": cancel_url,
        },
        "custom_id": user_id,
    }

    try:
        resp = httpx.post(
            f"{_BASE}/v1/billing/subscriptions",
            json=payload,
            headers=_paypal_headers(),
            timeout=20,
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        logger.error(f"create_subscription failed ({e.response.status_code}): {e.response.text[:300]}")
        raise RuntimeError(f"PayPal subscription creation failed: {e.response.status_code}")
    except httpx.RequestError as e:
        logger.error(f"PayPal unreachable during create_subscription: {e}")
        raise RuntimeError("Could not reach PayPal. Please try again.")

    data = resp.json()
    sub_id = data.get("id")
    approve_url = next(
        (link["href"] for link in data.get("links", []) if link["rel"] == "approve"),
        None,
    )

    if not sub_id or not approve_url:
        logger.error(f"Unexpected PayPal subscription response: {data}")
        raise RuntimeError("PayPal returned an unexpected response. Please try again.")

    logger.info(f"PayPal subscription created: {sub_id} for user {user_id} ({billing})")
    return {"subscription_id": sub_id, "approve_url": approve_url, "type": "subscription"}


def get_subscription(subscription_id: str) -> dict:
    """Fetch subscription details from PayPal."""
    try:
        resp = httpx.get(
            f"{_BASE}/v1/billing/subscriptions/{subscription_id}",
            headers=_paypal_headers(),
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.error(f"get_subscription({subscription_id}): {e}")
        raise RuntimeError(f"Could not fetch subscription: {e}")


def cancel_subscription(subscription_id: str, reason: str = "User requested cancellation") -> bool:
    """Cancel a PayPal subscription."""
    try:
        resp = httpx.post(
            f"{_BASE}/v1/billing/subscriptions/{subscription_id}/cancel",
            json={"reason": reason},
            headers=_paypal_headers(),
            timeout=15,
        )
        # 204 = success, 422 = already cancelled
        return resp.status_code in (204, 422)
    except Exception as e:
        logger.error(f"cancel_subscription({subscription_id}): {e}")
        return False


def suspend_subscription(subscription_id: str) -> bool:
    """Suspend (pause) a subscription — used when payment fails."""
    try:
        resp = httpx.post(
            f"{_BASE}/v1/billing/subscriptions/{subscription_id}/suspend",
            json={"reason": "Payment failed — subscription suspended"},
            headers=_paypal_headers(),
            timeout=15,
        )
        return resp.status_code in (204, 422)
    except Exception as e:
        logger.error(f"suspend_subscription({subscription_id}): {e}")
        return False


# ──────────────────────────────────────────────────────────────
#  ONE-TIME ORDERS  (fallback / legacy)
# ──────────────────────────────────────────────────────────────

def create_order(user_id: str, amount: str = PRO_MONTHLY_USD) -> dict:
    """
    Create a one-time PayPal order (fallback when no subscription plan is configured).

    Returns:
        { "order_id": "...", "approve_url": "https://...", "type": "order" }
    """
    success_url = f"{APP_BASE_URL}/payment/success?user_id={user_id}"
    cancel_url  = f"{APP_BASE_URL}/payment/cancel"

    order_payload = {
        "intent": "CAPTURE",
        "purchase_units": [{
            "amount": {
                "currency_code": PRO_CURRENCY,
                "value":         amount,
            },
            "description": PRO_PLAN_NAME,
            "custom_id":   user_id,
        }],
        "application_context": {
            "brand_name":          "SafeAIScan",
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
        raise RuntimeError("Could not reach PayPal. Please try again.")

    data       = resp.json()
    order_id   = data.get("id")
    approve_url = next(
        (link["href"] for link in data.get("links", []) if link["rel"] == "approve"),
        None,
    )

    if not order_id or not approve_url:
        raise RuntimeError("PayPal returned an unexpected response. Please try again.")

    logger.info(f"PayPal order created: {order_id} for user {user_id}")
    return {"order_id": order_id, "approve_url": approve_url, "type": "order"}


def capture_order(order_id: str) -> dict:
    """Capture (finalise) an approved PayPal order."""
    try:
        resp = httpx.post(
            f"{_BASE}/v2/checkout/orders/{order_id}/capture",
            headers=_paypal_headers(),
            json={},
            timeout=20,
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        logger.error(f"capture_order({order_id}) failed ({e.response.status_code}): {e.response.text[:300]}")
        raise RuntimeError(f"Payment capture failed: {e.response.status_code}")
    except httpx.RequestError as e:
        raise RuntimeError("Could not reach PayPal. Please try again.")

    data   = resp.json()
    status = data.get("status")

    if status != "COMPLETED":
        raise RuntimeError(f"Payment not completed (status: {status}). Please try again.")

    logger.info(f"PayPal order captured: {order_id} status={status}")
    return data


def get_order_user_id(capture_data: dict) -> str | None:
    """Extract user_id from the custom_id field embedded when creating the order."""
    try:
        units = capture_data.get("purchase_units", [])
        if units:
            return units[0].get("custom_id")
    except Exception:
        pass
    return None


# ──────────────────────────────────────────────────────────────
#  WEBHOOK VERIFICATION  (security — verify PayPal sent this)
# ──────────────────────────────────────────────────────────────

def verify_webhook_signature(
    headers: dict,
    body: bytes,
    webhook_id: str = "",
) -> bool:
    """
    Verify a PayPal webhook using the PayPal SDK verification API.
    Falls back to True in sandbox mode (for testing without webhook ID).

    headers: dict of request headers (case-insensitive)
    body:    raw request bytes
    webhook_id: PAYPAL_WEBHOOK_ID from dashboard
    """
    wh_id = webhook_id or WEBHOOK_ID

    # In sandbox without webhook ID — skip verification for dev/testing
    if MODE == "sandbox" and not wh_id:
        logger.warning("Webhook signature verification skipped (sandbox + no PAYPAL_WEBHOOK_ID)")
        return True

    try:
        # Normalise header keys to lowercase
        h = {k.lower(): v for k, v in headers.items()}
        payload = {
            "auth_algo":         h.get("paypal-auth-algo", ""),
            "cert_url":          h.get("paypal-cert-url", ""),
            "transmission_id":   h.get("paypal-transmission-id", ""),
            "transmission_sig":  h.get("paypal-transmission-sig", ""),
            "transmission_time": h.get("paypal-transmission-time", ""),
            "webhook_id":        wh_id,
            "webhook_event":     body.decode("utf-8"),
        }
        resp = httpx.post(
            f"{_BASE}/v1/notifications/verify-webhook-signature",
            json=payload,
            headers=_paypal_headers(),
            timeout=10,
        )
        result = resp.json().get("verification_status", "FAILURE")
        return result == "SUCCESS"
    except Exception as e:
        logger.error(f"Webhook verification error: {e}")
        return False


# ──────────────────────────────────────────────────────────────
#  ENTERPRISE PLAN PRICING HELPER
# ──────────────────────────────────────────────────────────────

ENTERPRISE_TIERS = [
    {"seats": "Up to 5",   "monthly": "29.00",  "annual": "278.40",  "label": "Team"},
    {"seats": "Up to 20",  "monthly": "79.00",  "annual": "758.40",  "label": "Business"},
    {"seats": "Unlimited", "monthly": "199.00", "annual": "1910.40", "label": "Enterprise"},
]

def get_enterprise_tiers() -> list:
    return ENTERPRISE_TIERS
