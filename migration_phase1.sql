-- ============================================================
--  SafeAIScan — Phase 1 Enterprise Upgrade Migration
--  Run once in Supabase SQL Editor. All statements are
--  idempotent (IF NOT EXISTS) — safe to re-run.
-- ============================================================

-- ── 1. Audit log table (item 10: Enterprise Readiness) ─────
-- Stores: scan events, login events, subscription events, admin actions
CREATE TABLE IF NOT EXISTS audit_logs (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        REFERENCES users(id) ON DELETE SET NULL,
  org_id      UUID,
  action      TEXT        NOT NULL,    -- e.g. "scan", "login", "register",
                                        -- "key_rotate", "subscription_cancel",
                                        -- "enterprise_inquiry", "pdf_export"
  resource    TEXT,                    -- e.g. "/api/analyze"
  ip_address  TEXT,
  metadata    JSONB,
  created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_org_created
  ON audit_logs(org_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created
  ON audit_logs(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_action
  ON audit_logs(action);

-- RLS: users can see their own audit rows; service role bypasses for org queries
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_logs_own_rows ON audit_logs;
CREATE POLICY audit_logs_own_rows ON audit_logs
  FOR SELECT USING (auth.uid()::text = user_id::text);


-- ── 2. scans table: security_score trend support ───────────
-- result_json already exists and is JSONB — security_score is stored
-- inside it (no new column needed). Add created_at index for trend queries.
CREATE INDEX IF NOT EXISTS idx_scans_user_created
  ON scans(user_id, created_at DESC);


-- ── 3. scan_tasks: ensure result_json can hold repo_health /
--      dependency_findings (already JSONB — no schema change needed,
--      this is a no-op safety check) ──────────────────────────
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'scan_tasks' AND column_name = 'result_json'
  ) THEN
    ALTER TABLE scan_tasks ADD COLUMN result_json JSONB;
  END IF;
END $$;


-- ── 4. Verification ──────────────────────────────────────────
SELECT table_name, column_name, data_type
FROM information_schema.columns
WHERE table_name IN ('audit_logs', 'scans', 'scan_tasks')
  AND column_name IN ('id','user_id','org_id','action','metadata','result_json','created_at')
ORDER BY table_name, column_name;
