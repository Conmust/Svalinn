-- Add a lock flag to messages
ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_locked BOOLEAN DEFAULT FALSE;

-- Index for faster lookups if needed
CREATE INDEX IF NOT EXISTS idx_messages_is_locked ON messages(is_locked);