-- Per-device end-to-end encryption, replacing the single-device model from
-- 0029_dm_e2e_encryption.sql. Each device a user logs in on now generates
-- and keeps its own X25519 keypair forever -- private keys never move
-- between devices, so a message to a user with N devices must be encrypted
-- once per device.
--
-- This migration does NOT touch `users.public_key` or the existing
-- `messages.is_encrypted` / `messages.nonce` / `messages.content` columns,
-- and does NOT migrate any data out of `users.public_key` into the new
-- `device_keys` table. Pre-existing plaintext history and pre-existing
-- single-device-era encrypted history are left exactly as they are and
-- keep rendering via the old columns; `users.public_key` is simply orphaned
-- going forward. New encrypted messages use the tables below instead.

-- A fan-out message's ciphertext lives entirely in `message_recipients`
-- (one row per recipient device) rather than on the `messages` row itself,
-- so `content`/`nonce` are left NULL for such messages. `content` was
-- NOT NULL (set for every channel message and every pre-fan-out DM), so
-- that constraint has to be relaxed here; it stays required in practice
-- for every row that doesn't go through the new per-device path.
ALTER TABLE messages ALTER COLUMN content DROP NOT NULL;

-- One row per device a user has registered a keypair from. A device never
-- uploads its private key -- only `public_key`.
CREATE TABLE IF NOT EXISTS device_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    device_label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Hot lookup path: "all of this user's devices" (fetched when composing a
-- send, and when listing a user's own devices for management).
CREATE INDEX IF NOT EXISTS idx_device_keys_user_id ON device_keys(user_id);

-- The per-device cap (10 devices/user) is enforced at the application layer,
-- not here -- see routes::devices::MAX_DEVICES_PER_USER.

-- One row per (encrypted message, recipient device) pair. For a message
-- encrypted under the new per-device model, this table is the source of
-- truth for ciphertext -- `messages.content`/`messages.nonce` are left NULL
-- for such messages; the old columns remain in use only for legacy
-- single-device-era rows that predate this migration.
CREATE TABLE IF NOT EXISTS message_recipients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES device_keys(id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL,
    nonce TEXT NOT NULL,
    -- Base64 X25519 public key of the DEVICE THAT SENT this message (i.e.
    -- the device that encrypted it), denormalized onto every recipient row.
    -- X25519/crypto_box key agreement is symmetric: a recipient device
    -- decrypts with (its own private key, the *other* device's public
    -- key) -- so recipients need to know which public key the sender used,
    -- not just their own. Storing it here means decrypting only ever needs
    -- this one row, with no second lookup, and still works even if the
    -- sending device is later removed from `device_keys`.
    sender_public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Hot lookup path: "every message_recipients row addressed to MY device".
CREATE INDEX IF NOT EXISTS idx_message_recipients_device_id ON message_recipients(device_id);
-- Used when loading a page of conversation history (join message_recipients
-- for the fetched messages) and by the message-delete cascade.
CREATE INDEX IF NOT EXISTS idx_message_recipients_message_id ON message_recipients(message_id);
