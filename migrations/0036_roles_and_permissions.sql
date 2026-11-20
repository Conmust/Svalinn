-- Discord-style granular permissions: server-defined roles carrying a
-- bitflag permission set, assigned to members many-to-many, plus
-- per-channel overwrites (by role and by individual member) that take
-- precedence over a member's role permissions in that one channel.
--
-- This sits ALONGSIDE the existing server_members.role column, which is
-- left untouched and keeps governing the simple owner > admin > moderator
-- > member rank used for kicking, banning and transferring ownership --
-- that hierarchy is orthogonal to "what can you do in this channel" and
-- rewriting it isn't needed to add real per-channel permissions.
--
-- Permission bits (see permissions.rs for the authoritative list):
--   1<<0  VIEW_CHANNEL
--   1<<1  SEND_MESSAGES
--   1<<2  MANAGE_MESSAGES   (delete/pin/lock/hide others' messages)
--   1<<3  MANAGE_CHANNELS
--   1<<4  MANAGE_ROLES
--   1<<5  MANAGE_SERVER     (rename, icon, server settings)
--   1<<6  KICK_MEMBERS
--   1<<7  BAN_MEMBERS
--   1<<8  MANAGE_EMOJIS
--   1<<9  CREATE_INVITE
--   1<<10 MENTION_EVERYONE
--   1<<11 ATTACH_FILES
--   1<<12 ADD_REACTIONS
--   1<<13 ADMINISTRATOR     (bypasses every check and every overwrite)

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    color VARCHAR(7),
    permissions BIGINT NOT NULL DEFAULT 0,
    -- Higher sorts first in the role list/picker; purely cosmetic
    -- ordering today, not a permission-hierarchy rank.
    position INT NOT NULL DEFAULT 0,
    -- The implicit base role every member has, whether or not they're
    -- assigned any other role (Discord's "@everyone"). Exactly one per
    -- server; created automatically and can't be deleted.
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_one_default_per_server
    ON roles(server_id) WHERE is_default;
CREATE INDEX IF NOT EXISTS idx_roles_server_id ON roles(server_id);

CREATE TABLE IF NOT EXISTS member_roles (
    server_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (server_id, user_id, role_id),
    FOREIGN KEY (server_id, user_id) REFERENCES server_members(server_id, user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_member_roles_role_id ON member_roles(role_id);

CREATE TABLE IF NOT EXISTS channel_role_overwrites (
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    allow BIGINT NOT NULL DEFAULT 0,
    deny BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (channel_id, role_id)
);

CREATE TABLE IF NOT EXISTS channel_member_overwrites (
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    allow BIGINT NOT NULL DEFAULT 0,
    deny BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (channel_id, user_id)
);

-- Seed every existing server with its default (@everyone) role, plus
-- Moderator and Admin roles, and carry each current member's existing
-- server_members.role text value over into an explicit member_roles
-- assignment -- so permission-wise nothing changes the moment this ships.
-- 'owner' isn't translated into a role row: ownership already bypasses
-- every permission check via servers.owner_id, independent of roles.
DO $$
DECLARE
    srv RECORD;
    default_role_id UUID;
    moderator_role_id UUID;
    admin_role_id UUID;
BEGIN
    -- Re-run safety: a dev reset or a migration-table rollback can run
    -- this file again against servers that already have roles (from a
    -- previous run of this same migration, since create_server does its
    -- own seeding going forward and wouldn't be reflected in a replay of
    -- this backfill anyway). Skip any server that already has a default
    -- role rather than hard-failing on the one-default-per-server index
    -- or duplicating Moderator/Admin.
    FOR srv IN SELECT id FROM servers WHERE NOT EXISTS (
        SELECT 1 FROM roles WHERE roles.server_id = servers.id AND roles.is_default
    ) LOOP
        INSERT INTO roles (server_id, name, color, permissions, position, is_default)
        -- VIEW_CHANNEL | SEND_MESSAGES | CREATE_INVITE | ATTACH_FILES | ADD_REACTIONS
        VALUES (srv.id, 'Member', '#99aab5', (1|2|512|2048|4096), 0, true)
        RETURNING id INTO default_role_id;

        INSERT INTO roles (server_id, name, color, permissions, position, is_default)
        -- default perms | MANAGE_MESSAGES
        VALUES (srv.id, 'Moderator', '#3ba55d', (1|2|512|2048|4096|4), 1, false)
        RETURNING id INTO moderator_role_id;

        INSERT INTO roles (server_id, name, color, permissions, position, is_default)
        -- ADMINISTRATOR (bypasses everything else)
        VALUES (srv.id, 'Admin', '#ed4245', (1<<13), 2, false)
        RETURNING id INTO admin_role_id;

        INSERT INTO member_roles (server_id, user_id, role_id)
        SELECT server_id, user_id, moderator_role_id FROM server_members
        WHERE server_id = srv.id AND role = 'moderator';

        INSERT INTO member_roles (server_id, user_id, role_id)
        SELECT server_id, user_id, admin_role_id FROM server_members
        WHERE server_id = srv.id AND role = 'admin';
    END LOOP;
END $$;
