-- Lets a moderator optionally store a readable copy of an encrypted
-- channel message while (and only while) it's pinned, so a member who
-- joins the server after it was sent -- and therefore never received a
-- `message_recipients` row for it, by design (see
-- `routes::messages::create_message`'s doc comment) -- isn't locked out
-- of a pinned announcement/rule just because they weren't there when it
-- was encrypted.
--
-- This is a deliberate, explicit, per-message weakening of end-to-end
-- encryption: the server can read `pin_plaintext_content`. It is never
-- set automatically. See `routes::messages::set_pin_visibility`.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS pin_plaintext_content TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS pin_plaintext_revealed_by UUID REFERENCES users(id);
ALTER TABLE messages ADD COLUMN IF NOT EXISTS pin_plaintext_revealed_at TIMESTAMPTZ;
