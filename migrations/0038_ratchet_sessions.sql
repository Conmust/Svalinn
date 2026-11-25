-- Double Ratchet (X3DH-style bootstrap + per-message-key ratchet) support,
-- additive alongside the stateless per-device crypto_box model from
-- 0030_device_keys_and_fanout.sql. Nothing here touches `device_keys`,
-- `message_recipients`'s existing `ciphertext`/`nonce`/`sender_public_key`
-- columns, or any pre-existing row -- a fan-out message keeps working
-- exactly as it does today unless it opts into the new path via
-- `message_recipients.ratchet_version`. See crypto.ts / ratchet.ts for the
-- client side and routes/devices.rs for prekey upload/consumption.
--
-- Rollout model: existing conversations keep using the stateless path
-- forever (there is no attempt to migrate live key-agreement state into a
-- ratchet session after the fact -- that's a correctness risk for no real
-- benefit). Only a session bootstrapped fresh via a consumed prekey bundle
-- uses a `ratchet_sessions` row.

-- A device's prekey bundle: one signed prekey (rotated periodically, the
-- active one has `consumed_at IS NULL` and `key_type = 'signed'` -- it is
-- reused across many session bootstraps, never consumed) plus a pool of
-- one-time prekeys (each consumed by exactly one session bootstrap, then
-- never reused -- this is what gives a fresh session forward secrecy even
-- when the recipient device is offline at send time).
CREATE TABLE IF NOT EXISTS device_prekeys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES device_keys(id) ON DELETE CASCADE,
    key_type TEXT NOT NULL CHECK (key_type IN ('signed', 'one_time')),
    public_key TEXT NOT NULL,
    -- Present only for key_type = 'signed': an Ed25519 signature (by the
    -- device's identity key, which must therefore also carry an Ed25519
    -- signing key alongside its X25519 agreement key -- see ratchet.ts's
    -- identity keypair, which is a second keypair from the device's
    -- existing long-term key material, not a replacement for it) over this
    -- prekey's public key bytes, letting a sender verify the bundle came
    -- from the device it claims to, not a server-substituted key.
    signature TEXT,
    -- NULL until a one-time prekey is handed out to a session-bootstrap
    -- request; NULL forever for the signed prekey, which is reusable.
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (key_type <> 'signed' OR signature IS NOT NULL)
);

-- Hot lookup path: "this device's active signed prekey" and "an unconsumed
-- one-time prekey to hand out next" both filter on (device_id, key_type,
-- consumed_at).
CREATE INDEX IF NOT EXISTS idx_device_prekeys_device_lookup
    ON device_prekeys(device_id, key_type, consumed_at);

-- One row per *directed* (owning device, peer device) pair -- NOT one row
-- per undirected device pair. This matters: a Double Ratchet session isn't
-- shared mutable state both sides read and write to a common copy of --
-- each side independently tracks its OWN view of the session (its own
-- current ratchet keypair, its own send/receive chain keys and counters),
-- which happens to stay in sync with the other side's view via the DH
-- outputs they exchange in-band, not via any shared storage. So "Alice's
-- laptop talking to Bob's phone" and "Bob's phone talking to Alice's
-- laptop" are two SEPARATE rows here, each encrypted under a key that
-- never leaves the device that wrote it (see ratchet.ts's
-- `derivePickleKey`, deterministically derived from that device's own
-- long-term identity key, so the device can recover its OWN backed-up
-- state later even after clearing its local ratchet cache -- this table
-- exists purely as that one device's own encrypted backup of a session it
-- already has locally, not as a channel for moving state between
-- different devices or different users). A row here is never readable by
-- anyone except the device that wrote it (see routes::ratchet's ownership
-- check, which requires owning `device_id`, not `peer_device_id`).
CREATE TABLE IF NOT EXISTS ratchet_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES device_keys(id) ON DELETE CASCADE,
    peer_device_id UUID NOT NULL REFERENCES device_keys(id) ON DELETE CASCADE,
    pickle_ciphertext TEXT NOT NULL,
    pickle_nonce TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ratchet_sessions_unique_pair UNIQUE (device_id, peer_device_id)
);

-- Hot lookup path: "my own backup of my session with this specific peer
-- device" -- the unique constraint above already covers this exact shape,
-- so no separate index is needed for it; this one instead supports
-- cascading/auditing by peer (e.g. "every session backup that involves
-- peer device X", relevant if X is later removed).
CREATE INDEX IF NOT EXISTS idx_ratchet_sessions_peer_device ON ratchet_sessions(peer_device_id);

-- Additive marker on message_recipients: NULL (the default) means "this row
-- uses the existing stateless crypto_box scheme, decrypt it exactly as
-- today." A ratcheted message instead stores Double-Ratchet-style wire
-- format (DH ratchet public key + chain counters + ciphertext, all
-- serialized together) in the EXISTING `ciphertext` column -- a ratchet
-- message envelope carries its own per-message key material, so it needs
-- neither a separate nonce nor a denormalized sender key. Both columns are
-- therefore relaxed to nullable here (used by every pre-existing row;
-- simply left NULL by a ratcheted one).
ALTER TABLE message_recipients
    ADD COLUMN IF NOT EXISTS ratchet_version SMALLINT,
    ALTER COLUMN nonce DROP NOT NULL,
    ALTER COLUMN sender_public_key DROP NOT NULL;

COMMENT ON COLUMN message_recipients.ratchet_version IS
    'NULL = legacy stateless crypto_box row (nonce/sender_public_key are meaningful). 1 = Double Ratchet row (ciphertext is a full ratchet message envelope; nonce/sender_public_key are NULL and unused).';

ALTER TABLE message_recipients
    ADD CONSTRAINT message_recipients_legacy_fields_present CHECK (
        ratchet_version IS NOT NULL OR (nonce IS NOT NULL AND sender_public_key IS NOT NULL)
    );
