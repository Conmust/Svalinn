-- Add editing tracking to messages
ALTER TABLE messages 
ADD COLUMN IF NOT EXISTS is_edited BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

-- Update existing messages to have updated_at = created_at
UPDATE messages SET updated_at = created_at WHERE updated_at IS NULL;