-- End-to-end encryption for 1-on-1 direct messages. The server never sees
-- plaintext content or private keys for an encrypted message; it only
-- stores/relays ciphertext and public keys.
--
-- `users.public_key`: base64-encoded X25519 public key for the user's
-- (single) device. NULL until that user has logged in on an E2EE-aware
-- client, which is the normal state for most existing accounts today.
ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key TEXT;

-- `messages.is_encrypted`: true when `content` holds base64 ciphertext
-- (NaCl `crypto_box`) rather than plaintext. Existing/old messages default
-- to false and are left exactly as they are -- there's no retroactive
-- encryption of history the server never had the keys to encrypt anyway.
-- `messages.nonce`: base64-encoded nonce used for that ciphertext; only
-- present (NOT NULL) when `is_encrypted` is true.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_encrypted BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS nonce TEXT;
