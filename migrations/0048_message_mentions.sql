-- @mentions. Channel message content is never seen by the server (it's
-- per-device fan-out encrypted -- see `create_message`'s doc comment), so
-- mention detection has to happen client-side: the client parses its own
-- plaintext for "@username" before encrypting it, resolves those against
-- the channel's member list, and sends the resulting user ids alongside
-- the ciphertext as plain (unencrypted) metadata, the same way a pin's
-- revealed plaintext is sent deliberately unencrypted. This table just
-- records that metadata so every read path can report who was mentioned
-- without re-deriving it, and so a future "my mentions" view has an
-- index-friendly way to ask "what has mentioned me".
CREATE TABLE IF NOT EXISTS message_mentions (
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    mentioned_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (message_id, mentioned_user_id)
);

CREATE INDEX IF NOT EXISTS idx_message_mentions_user ON message_mentions (mentioned_user_id);
