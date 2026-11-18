-- Create servers table
CREATE TABLE IF NOT EXISTS servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    icon TEXT,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create server_members table (tracks which users are in which servers)
CREATE TABLE IF NOT EXISTS server_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(20) DEFAULT 'member', -- 'owner', 'admin', 'member'
    joined_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(server_id, user_id)
);

-- Add server_id to channels table
ALTER TABLE channels ADD COLUMN IF NOT EXISTS server_id UUID REFERENCES servers(id) ON DELETE CASCADE;

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_server_members_user_id ON server_members(user_id);
CREATE INDEX IF NOT EXISTS idx_server_members_server_id ON server_members(server_id);
CREATE INDEX IF NOT EXISTS idx_channels_server_id ON channels(server_id);

-- Create a default server and add the first user to it (only if a user exists)
DO $$
DECLARE
    first_user_id UUID;
BEGIN
    SELECT id INTO first_user_id FROM users LIMIT 1;
    
    IF first_user_id IS NOT NULL THEN
        INSERT INTO servers (id, name, owner_id) 
        VALUES ('00000000-0000-0000-0000-000000000010', 'Svalinn HQ', first_user_id)
        ON CONFLICT DO NOTHING;

        INSERT INTO server_members (server_id, user_id, role)
        VALUES ('00000000-0000-0000-0000-000000000010', first_user_id, 'owner')
        ON CONFLICT DO NOTHING;

        UPDATE channels SET server_id = '00000000-0000-0000-0000-000000000010' WHERE server_id IS NULL;
    END IF;
END $$;