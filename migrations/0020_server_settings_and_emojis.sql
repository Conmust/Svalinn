-- Add settings columns to servers
ALTER TABLE servers ADD COLUMN IF NOT EXISTS icon_url TEXT;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS description TEXT;

-- Create custom emojis table
CREATE TABLE IF NOT EXISTS custom_emojis (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(server_id, name)
);

CREATE INDEX IF NOT EXISTS idx_custom_emojis_server ON custom_emojis(server_id);