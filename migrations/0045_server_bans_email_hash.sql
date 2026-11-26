-- Fixes a ban-evasion-protection bug found in a fresh adversarial audit:
-- `unban_member` used to clear the matching `banned_emails` row by looking
-- up the target's CURRENT `users.email_hash` -- but `ban_member` recorded
-- the email hash as it was AT BAN TIME. If the banned user changed their
-- email in between (still possible: a per-server ban doesn't lock the
-- account itself), those two hashes diverge, and the unban's DELETE on
-- `banned_emails` silently matches zero rows: the OLD hash stays blocked
-- forever, with no way for a moderator to clear it, even though they just
-- explicitly lifted the ban. Not a way to bypass a ban (it fails toward
-- over-restrictive, not under), but a real "unban doesn't fully unban" bug.
--
-- Fix: store the email hash actually used for the `banned_emails` write
-- directly on the `server_bans` row itself, so `unban_member` can delete
-- the matching `banned_emails` row by the hash that's actually there,
-- rather than re-deriving a (possibly different) one from the user's
-- current record.
ALTER TABLE server_bans ADD COLUMN IF NOT EXISTS email_hash TEXT;

-- Best-effort backfill for existing bans: the user's current hash is the
-- closest approximation available for a ban that predates this column (if
-- they've since changed email, this still won't be exactly right for
-- those rows, but it's strictly no worse than today's behavior, and exact
-- for every row where it hasn't changed since).
UPDATE server_bans sb
SET email_hash = u.email_hash
FROM users u
WHERE sb.user_id = u.id AND sb.email_hash IS NULL;
