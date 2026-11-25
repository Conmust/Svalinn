-- Cryptographic blind tokens for anonymous patron-tier redemption.
--
-- The point of this scheme: a payment can happen through any channel you
-- like (card, cash, a voucher) without this database ever recording which
-- account that payment was for. Blind RSA signatures (RFC 9474) let the
-- server certify "this token is a legitimate patron-tier grant" without
-- ever seeing the token's contents at signing time -- so even a full
-- database leak can't tell you which redemption came from which payment.
--
-- blind_token_skus: one RSA keypair per tier. The secret key signs blinded
-- requests; the public key lets anyone verify a finished token. Generated
-- once and reused, since rotating it would invalidate every token already
-- in someone's pocket.
CREATE TABLE IF NOT EXISTS blind_token_skus (
    tier TEXT PRIMARY KEY,
    secret_key_der BYTEA NOT NULL,
    public_key_der BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- blind_token_receipts: a one-time-use ticket that authorizes exactly one
-- blind-signing request for a given tier. This is the (necessarily
-- non-anonymous-to-someone) hook where a completed payment turns into
-- permission to mint a token -- today that's the site owner minting one by
-- hand after a cash/voucher payment; later it could just as well be a
-- payment-processor webhook. Only the token's hash is stored, same as
-- refresh tokens, so a database leak doesn't hand out usable receipts.
CREATE TABLE IF NOT EXISTS blind_token_receipts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tier TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at TIMESTAMPTZ
);

-- blind_token_redemptions: blocks a finished (serial, signature) pair from
-- being redeemed twice. `redeemed_by` has to exist -- the tier has to land
-- on *some* account -- but nothing here points back to the receipt or
-- payment that produced the token, because that link was never recorded.
CREATE TABLE IF NOT EXISTS blind_token_redemptions (
    serial_hash TEXT PRIMARY KEY,
    tier TEXT NOT NULL,
    redeemed_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redeemed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_blind_token_redemptions_redeemed_by ON blind_token_redemptions(redeemed_by);
