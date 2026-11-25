-- A lightweight, append-only ledger of skipped message keys this device
-- has ever consumed, kept INDEPENDENTLY of `ratchet_sessions`'s
-- whole-session backup blob (migration 0038). This closes most of the
-- remaining gap in that backup's own eager-write mitigation (see
-- `ratchet.ts`'s `saveSessionEagerly`): a skipped message key is deleted
-- from local state the moment it's used to decrypt an out-of-order
-- message, since it's single-use by the Double Ratchet's design, but the
-- whole-session backup can still -- in principle -- lag behind that one
-- consumption (network hiccup, a crash mid-write). If this device's local
-- storage were then lost, recovering from that stale backup would restore
-- a session whose `skippedKeys` map still lists the key as available,
-- letting a captured-and-replayed copy of the original ciphertext decrypt
-- a second time.
--
-- This table is the fix for that: every time a skipped key is consumed,
-- the client also (best-effort, fired alongside the eager session backup,
-- not waiting on it) records that fact here, in a row that is NEVER
-- rewritten or deleted afterward -- unlike the session backup, there is no
-- "latest version" to race against, just an accumulating set of
-- known-consumed slots. On recovery, after restoring a session backup, the
-- client fetches every row here for the (device, peer device) pair and
-- strips any matching entry from the restored `skippedKeys` map before
-- trusting it, regardless of how stale the backup blob itself turns out to
-- be. See `routes::ratchet`'s new endpoints and `ratchet.ts`'s
-- `reportSkippedKeyConsumed`/`fetchConsumedSkippedKeys`.
--
-- This narrows the window further but does not close it to zero: if BOTH
-- this write and the session backup are lost before either lands (e.g.
-- local storage is wiped while fully offline, before either request ever
-- leaves the device), recovery still has nothing to cross-check against.
-- Closing that residual case would require the server to be consulted
-- synchronously as part of every decrypt, which isn't compatible with
-- offline-first E2EE messaging -- so, same as the eager-backup mitigation
-- it complements, this is a meaningful narrowing, not a complete fix.
CREATE TABLE IF NOT EXISTS ratchet_consumed_skipped_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES device_keys(id) ON DELETE CASCADE,
    peer_device_id UUID NOT NULL REFERENCES device_keys(id) ON DELETE CASCADE,
    -- Together these identify exactly one skipped-key "slot", the same way
    -- `ratchet.ts`'s local `skippedKeys` map keys itself
    -- (`${dhPublicKeyB64}:${messageNumber}`) -- kept as two columns here
    -- rather than one concatenated string so the uniqueness constraint
    -- below can't be fooled by a value that happens to contain the
    -- separator (base64 can't, but there's no reason to rely on that).
    dh_public_key TEXT NOT NULL,
    message_number INTEGER NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Reporting the same consumption twice (e.g. a retried request after a
    -- dropped response) is a no-op, not a new row -- see
    -- `report_consumed_skipped_key`'s `ON CONFLICT DO NOTHING`.
    CONSTRAINT ratchet_consumed_skipped_keys_unique UNIQUE (device_id, peer_device_id, dh_public_key, message_number)
);

-- Hot lookup path: "every skipped key I (device_id) have ever consumed
-- from this peer", fetched in full on recovery (see above). The unique
-- constraint already indexes this exact prefix, so no separate index is
-- needed.
