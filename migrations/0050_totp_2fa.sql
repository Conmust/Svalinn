-- TOTP-based two-factor authentication.
--
-- totp_secrets: one row per user, created the moment setup starts.
-- `enabled_at` is NULL until the user proves they actually scanned it (by
-- submitting a valid code to `/auth/2fa/enable`) -- so an abandoned setup
-- never silently turns 2FA on. `secret_encrypted` uses the same
-- AES-256-GCM key as email_privacy (there's no reason to manage a second
-- encryption key for one more small secret that needs the same property:
-- recoverable by the server to verify codes, but not stored in plaintext).
-- `last_used_step` blocks replay: once a code for a given 30s step has been
-- accepted, that same step is refused even if it's still inside the
-- verification window (e.g. someone who shoulder-surfed or intercepted a
-- code in transit can't reuse it a few seconds later).
CREATE TABLE IF NOT EXISTS totp_secrets (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_encrypted TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    enabled_at TIMESTAMPTZ,
    last_used_step BIGINT
);

-- One-time recovery codes, issued (all at once) the moment 2FA is enabled
-- and again on request. Hashed, not stored in plaintext, same reasoning as
-- every other token table here -- these are themselves a password-
-- equivalent credential.
CREATE TABLE IF NOT EXISTS totp_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_totp_backup_codes_user ON totp_backup_codes(user_id);

-- Bridges login's two steps for a 2FA-enabled account: issued once the
-- password is confirmed correct, redeemed by a correct TOTP/backup code at
-- `/auth/2fa/login`. Short-lived (see PENDING_LOGIN_TTL_MINUTES in
-- routes::auth) and, like every other token here, stored only as a hash.
CREATE TABLE IF NOT EXISTS totp_pending_logins (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);
