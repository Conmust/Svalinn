-- Daily snapshots of the total signed-up user count, for public growth
-- charts (e.g. a community "X users and counting" page).
--
-- This intentionally stores nothing about *who* signed up -- just a single
-- aggregate number per day. There is no way to recover which accounts
-- existed on a given date from this table, only how many did.
CREATE TABLE IF NOT EXISTS user_count_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_date DATE NOT NULL UNIQUE,
    total_users BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
