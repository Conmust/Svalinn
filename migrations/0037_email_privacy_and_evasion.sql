-- Email privacy + ban-evasion support.
--
-- Emails are no longer stored in plaintext going forward. `email_encrypted`
-- holds an AES-256-GCM ciphertext (nonce + tag included, base64), and
-- `email_hash` is a keyed HMAC-SHA256 blind index -- deterministic, so it
-- can still be looked up/compared for uniqueness and login, but doesn't
-- reveal the real address even if the database leaks (see
-- crate::email_privacy for both). The legacy plaintext `email` column is
-- backfilled into the new columns and then cleared by a one-time startup
-- routine (see `backfill_email_privacy` in main.rs) rather than kept
-- around indefinitely; it's left nullable here so that backfill can clear
-- it without violating NOT NULL.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_encrypted TEXT,
    ADD COLUMN IF NOT EXISTS email_hash TEXT,
    ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;

ALTER TABLE users ALTER COLUMN email DROP NOT NULL;

-- Partial (not plain UNIQUE) so a brief in-flight row with email_hash still
-- NULL (mid-backfill) can never collide with itself or anyone else.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_hash ON users(email_hash) WHERE email_hash IS NOT NULL;

-- One-time email verification links. Only a hash of the token is stored,
-- same pattern as refresh_tokens.
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user ON email_verification_tokens(user_id);

-- Durable record of banned emails (by blind-index hash), independent of
-- whether the original account still exists -- so a re-registration (or a
-- rejoin, for a per-server ban) is caught even if the banned account is
-- later deleted. server_id NULL = platform-wide ban (mirrors
-- users.banned_at); non-NULL = scoped to one server's ban list (mirrors
-- server_bans).
CREATE TABLE IF NOT EXISTS banned_emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_hash TEXT NOT NULL,
    server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Two partial unique indexes instead of one UNIQUE(email_hash, server_id):
-- Postgres treats NULL as distinct from NULL in a plain unique constraint,
-- which would let the same email be recorded as platform-banned twice.
CREATE UNIQUE INDEX IF NOT EXISTS idx_banned_emails_global ON banned_emails(email_hash) WHERE server_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_banned_emails_server ON banned_emails(email_hash, server_id) WHERE server_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_banned_emails_lookup ON banned_emails(email_hash, server_id);

-- A global account ban (users.banned_at) should also close the email
-- re-registration loophole; mirror it into banned_emails automatically.
CREATE OR REPLACE FUNCTION svalinn_on_user_banned_record_email() RETURNS trigger AS $$
BEGIN
    IF NEW.banned_at IS NOT NULL AND OLD.banned_at IS NULL AND NEW.email_hash IS NOT NULL THEN
        INSERT INTO banned_emails (email_hash, server_id, reason)
        VALUES (NEW.email_hash, NULL, NEW.ban_reason)
        ON CONFLICT (email_hash) WHERE server_id IS NULL DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_banned_record_email ON users;
CREATE TRIGGER users_banned_record_email
    AFTER UPDATE OF banned_at ON users
    FOR EACH ROW EXECUTE FUNCTION svalinn_on_user_banned_record_email();
