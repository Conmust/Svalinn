-- Optional, opt-in passphrase-based recovery backup for a user's E2EE
-- device private key (see routes::users::{get,put,delete}_key_backup and
-- apps/desktop/src/lib/recovery.ts).
--
-- The server never sees the user's passphrase or the derived symmetric key
-- used to encrypt this blob, and therefore can never decrypt it -- it only
-- stores and relays opaque ciphertext the owning client already produced
-- and already owns.
--
-- Single-backup-slot-per-user design: `user_id` is the PRIMARY KEY, so a
-- user has at most one backup row at a time, and uploading a new one
-- (`PUT`) overwrites/replaces whatever was there before. This is a known,
-- accepted limitation: this table backs up ONE device's private key at a
-- time, not "all of a user's devices' keys" -- there's no support here for
-- backing up multiple devices' keys in a single blob, or keeping a history
-- of older backups. A user who wants to change which device's key is
-- backed up (or rotate their passphrase) just re-encrypts and re-uploads,
-- replacing the old backup outright.
CREATE TABLE IF NOT EXISTS key_backups (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- Base64 ciphertext (nonce prepended, then crypto_secretbox_easy output)
    -- of the JSON payload { privateKey, publicKey, deviceId } for the one
    -- device whose key this backs up. Opaque to the server.
    encrypted_blob TEXT NOT NULL,
    -- Base64 crypto_pwhash salt used to derive the symmetric key from the
    -- user's passphrase. Not secret on its own -- a salt only needs to be
    -- unique, not hidden -- but kept alongside the blob since it's required
    -- to re-derive the same key later.
    salt TEXT NOT NULL,
    -- KDF tier/algorithm used to derive the symmetric key, e.g.
    -- {"algorithm": "argon2id13", "opslimit": ..., "memlimit": ..., "version": 1}.
    -- Stored explicitly (rather than assumed from current client defaults)
    -- so a future client version can still reproduce the exact derivation
    -- used for an older backup even if its own defaults change later.
    kdf_params JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
