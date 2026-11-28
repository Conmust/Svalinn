-- A durable record of moderation actions within a server: kicks, bans,
-- unbans, built-in and custom role changes, and a moderator deleting
-- someone else's message. Written by crates/svalinn-server/src/audit_log.rs,
-- read via GET /api/v1/servers/:server_id/audit-log (moderator rank or
-- above, same gate as the existing bans list).
--
-- actor_id/target_user_id/target_channel_id are ON DELETE SET NULL rather
-- than CASCADE: an account or channel being deleted later shouldn't erase
-- the historical record that an action happened, only the ability to
-- resolve who/what it was (the UI falls back to "a deleted user"/"a
-- deleted channel"). The server itself is the one thing this can't outlive
-- -- CASCADE there matches how every other per-server table already behaves
-- (servers, server_members, server_bans, roles, ...).
CREATE TABLE moderation_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    target_channel_id UUID REFERENCES channels(id) ON DELETE SET NULL,
    reason TEXT,
    -- Action-specific extra detail (e.g. {"old_role": "member", "new_role":
    -- "moderator"} for a role change, {"message_id": "..."} for a deleted
    -- message). Never used to decide access -- it's display-only context.
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The log is read almost exclusively as "the last N entries for this
-- server", newest first.
CREATE INDEX idx_moderation_audit_log_server_created ON moderation_audit_log (server_id, created_at DESC, id DESC);
