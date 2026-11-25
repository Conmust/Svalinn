-- Adds an optional Ed25519 signing public key to a device's identity,
-- alongside its existing X25519 agreement key (`device_keys.public_key`,
-- used for crypto_box key agreement and, with the Double Ratchet, as one
-- of the X3DH-style DH inputs). This is deliberately a SEPARATE keypair
-- from the agreement key, not a single key doing double duty -- X25519 and
-- Ed25519 keys aren't safely interchangeable without specialized handling
-- (XEdDSA) that this project doesn't implement, so a ratchet-capable
-- device just generates and manages two identity keypairs instead: one for
-- DH, one for signing its own signed prekey. See ratchet.ts.
--
-- Nullable and backfilled as NULL for every pre-existing device: a device
-- that never registers a signing key simply can't have its prekey bundle's
-- signature verified, and `fetch_prekey_bundle` treats "no signing key on
-- file" as "this device hasn't opted into the ratchet yet" (see
-- routes::ratchet), not as an error -- nothing about existing per-device
-- crypto_box messaging depends on this column at all.
ALTER TABLE device_keys
    ADD COLUMN IF NOT EXISTS signing_public_key TEXT;
