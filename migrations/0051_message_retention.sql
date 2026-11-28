-- Server-wide message retention: a periodic sweep (see
-- crates/svalinn-server/src/retention.rs) keeps at most 500 non-pinned
-- messages per server, exempting a message that's still unread by some
-- current member for up to 30 days or until the server's unread backlog
-- passes 1250 messages (2.5x the cap), whichever comes first. Pinned
-- messages are capped separately at 200 per server, enforced at pin time
-- in routes::messages::set_pinned.
--
-- No new columns or tables: everything the sweep and the pin cap need
-- (messages.is_pinned, messages.created_at, channel_reads.last_read_message_id,
-- server_members) already exists. This migration only adds the index the
-- pin-cap check needs to stay cheap as a server's message history grows --
-- the sweep's own per-channel "most recent N" ranking already has
-- idx_messages_channel_history (channel_id, created_at DESC, id DESC) from
-- migration 0027.

-- Speeds "how many messages is this server's pin count already at" (the
-- 200-per-server cap, checked on every pin) without scanning the whole
-- channel's history for the rare pinned rows.
CREATE INDEX IF NOT EXISTS idx_messages_pinned_channel ON messages(channel_id) WHERE is_pinned = true;
