-- Per-server nicknames.
--
-- A member can set a different display name for themselves within one
-- server, without touching their global `username`. Server admins/owners
-- can also set or clear another member's nickname (e.g. to enforce a
-- naming policy), same rank rule as other moderation actions.
--
-- NULL means "no nickname set here, show the username" -- this is the
-- common case, so it's nullable rather than defaulting to the username
-- (which would need to be kept in sync on every username change).
ALTER TABLE server_members ADD COLUMN IF NOT EXISTS nickname VARCHAR(100);

-- Note: `users.avatar_url` (profile picture) already exists as of
-- migration 0002 -- it was added for a profile feature that was never
-- finished, so the column has sat unused ever since. This change is what
-- finally wires it up (see users.rs); no new column needed for it.
