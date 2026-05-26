# SafeAIScan — Monetization Setup Guide
**Goal: $500–1000/month at $1.99/mo Pro plan**

---

## 1. Run the Database Migration

Go to your Supabase project → **SQL Editor → New Query**  
Paste the entire contents of `migration.sql` and click **Run**.

This adds:
- Subscription tracking columns on `users`
- `payments` table (revenue log + audit trail)
- `usage_tracking` table
- `revenue_summary` view (check your MRR instantly)

---

## 2. Set Up PayPal Developer Account

1. Go to [developer.paypal.com](https://developer.paypal.com)
2. Log in with your business PayPal account
3. Go to **My Apps & Credentials**
4. Create a **Live** app (or Sandbox for testing)
5. Copy your **Client ID** and **Secret**

---

## 3. Create a PayPal Billing Plan (for recurring subscriptions)

This is the key step for recurring revenue. Without it, payments are one-time only.

1. In PayPal Developer dashboard → **Subscriptions → Plans → Create Plan**
2. Fill in:
   - **Product**: Create new → "SafeAIScan Pro"
   - **Plan name**: SafeAIScan Pro Monthly
   - **Billing cycle**: Monthly, $1.99 USD
   - **Trial period**: None (you handle trials in-app)
3. Click **Create Plan**
4. Copy the **Plan ID** (starts with `P-`)
5. Repeat for Annual plan: $19.08/year, billing cycle = 12 months

---

## 4. Set Up PayPal Webhook

1. In PayPal Developer → **Webhooks → Add Webhook**
2. Webhook URL: `https://rathious-safeaiscan.hf.space/payment/webhook`
3. Select these events:
   - `BILLING.SUBSCRIPTION.ACTIVATED`
   - `BILLING.SUBSCRIPTION.RENEWED`
   - `BILLING.SUBSCRIPTION.PAYMENT.FAILED`
   - `BILLING.SUBSCRIPTION.CANCELLED`
   - `BILLING.SUBSCRIPTION.SUSPENDED`
   - `PAYMENT.CAPTURE.COMPLETED`
   - `PAYMENT.SALE.COMPLETED`
4. Save and copy the **Webhook ID**

---

## 5. Add Secrets to HuggingFace Space

Go to your HF Space → **Settings → Repository secrets** → Add:

| Secret Name | Value |
|---|---|
| `PAYPAL_CLIENT_ID` | Your PayPal app Client ID |
| `PAYPAL_CLIENT_SECRET` | Your PayPal app Secret |
| `PAYPAL_MODE` | `live` (use `sandbox` for testing) |
| `PAYPAL_PLAN_ID_PRO` | The Monthly plan ID (P-...) |
| `PAYPAL_PLAN_ID_ANNUAL` | The Annual plan ID (P-...) |
| `PAYPAL_WEBHOOK_ID` | Your webhook ID from step 4 |
| `APP_BASE_URL` | `https://rathious-safeaiscan.hf.space` |
| `SUPABASE_URL` | Already set |
| `SUPABASE_SERVICE_ROLE_KEY` | Already set |

---

## 6. Test the Full Flow (Sandbox First)

1. Set `PAYPAL_MODE=sandbox`
2. Create a sandbox buyer account at [developer.paypal.com/tools/sandbox](https://developer.paypal.com/tools/sandbox)
3. Register a new user on SafeAIScan
4. Go to checkout → click Subscribe → use sandbox buyer account
5. Confirm webhook fires: check HF Space logs for `PayPal webhook: BILLING.SUBSCRIPTION.ACTIVATED`
6. Confirm user upgraded: check Supabase → `users` table → `plan = 'pro'`
7. Simulate payment failure: PayPal sandbox → Billing → trigger failed payment
8. Confirm downgrade: user should revert to `plan = 'free'`

Once all tests pass → set `PAYPAL_MODE=live` and restart the Space.

---

## 7. Revenue Path to $500–1000/month

| Target | Paid Users Needed |
|---|---|
| $500/month | 252 users × $1.99 |
| $750/month | 377 users × $1.99 |
| $1000/month | 503 users × $1.99 |

**Conversion funnel:**
- Every new user gets a **30-day free Pro trial** automatically
- At trial end → automatic downgrade → upgrade prompt shown
- Industry benchmark: 5–8% of trial users convert to paid
- To hit $500/mo: need ~3,000–5,000 trial starts (252 ÷ 6%)

**Growth levers (no cost):**
1. Post on r/netsec, r/devops, r/programming with a real scan demo
2. Submit to ProductHunt, BetaList, HackerNews Show HN
3. Add a "Powered by SafeAIScan" badge to generated PDFs (free ads)
4. GitHub README scan results → share button → viral loop
5. Offer a free "1 scan report" shareable link (no account needed)

---

## 8. Monitor Revenue

Run this query in Supabase SQL Editor anytime:

```sql
SELECT * FROM revenue_summary;
```

Also check the `payments` table for all transactions:

```sql
SELECT event_type, amount, created_at
FROM payments
ORDER BY created_at DESC
LIMIT 50;
```

---

## API Endpoints Reference

| Endpoint | Method | Description |
|---|---|---|
| `/payment/create?billing=monthly` | POST | Start PayPal checkout |
| `/payment/subscription-success` | GET | PayPal return URL after approval |
| `/payment/success` | GET | One-time order fallback return URL |
| `/payment/cancel` | GET | PayPal cancel return URL |
| `/payment/webhook` | POST | PayPal webhook receiver |
| `/payment/cancel-subscription` | POST | User cancels own subscription |
| `/payment/activate` | POST | Manual Pro activation (support) |
| `/api/pricing` | GET | Current pricing (no auth) |
| `/api/subscription/status` | GET | User's subscription details |
| `/api/admin/run-migration` | POST | DB migration helper (admin only) |

