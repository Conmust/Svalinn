-- Invite codes for joining a server.
CREATE TABLE IF NOT EXISTS server_invites (
    code TEXT PRIMARY KEY,
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,                -- NULL = never expires
    max_uses INTEGER CHECK (max_uses IS NULL OR max_uses > 0),  -- NULL = unlimited
    uses INTEGER NOT NULL DEFAULT 0,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_server_invites_server ON server_invites(server_id);

-- Per-server bans: the user is removed and can't rejoin with an invite.
-- (Separate from users.banned_at, which bans an account from the whole app.)
CREATE TABLE IF NOT EXISTS server_bans (
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    banned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (server_id, user_id)
);
