-- Immediate revocation. The server LISTENs on the "svalinn_access" channel and
-- closes live connections when it's notified, so access ends at once however
-- a ban or revocation is made (admin tool, app, or a direct SQL update).

ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason TEXT;

-- Banning a user ends all of their sessions.
CREATE OR REPLACE FUNCTION svalinn_on_user_banned() RETURNS trigger AS $$
BEGIN
    IF NEW.banned_at IS NOT NULL AND OLD.banned_at IS NULL THEN
        UPDATE refresh_tokens SET revoked_at = NOW()
        WHERE user_id = NEW.id AND revoked_at IS NULL;

        PERFORM pg_notify('svalinn_access',
            json_build_object('kind', 'user_banned', 'user_id', NEW.id)::text);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_banned ON users;
CREATE TRIGGER users_banned
    AFTER UPDATE OF banned_at ON users
    FOR EACH ROW EXECUTE FUNCTION svalinn_on_user_banned();

-- A revoked session (logout, theft detection, ban). Routine rotation also sets
-- revoked_at, but together with replaced_at, so it doesn't notify.
CREATE OR REPLACE FUNCTION svalinn_on_session_revoked() RETURNS trigger AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL AND NEW.replaced_at IS NULL THEN
        PERFORM pg_notify('svalinn_access',
            json_build_object('kind', 'session_revoked',
                              'user_id', NEW.user_id,
                              'session_id', NEW.family_id)::text);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS refresh_tokens_revoked ON refresh_tokens;
CREATE TRIGGER refresh_tokens_revoked
    AFTER UPDATE OF revoked_at ON refresh_tokens
    FOR EACH ROW EXECUTE FUNCTION svalinn_on_session_revoked();
