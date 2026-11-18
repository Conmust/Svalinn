-- 1. Ensure the conversations table exists
CREATE TABLE IF NOT EXISTS conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Ensure the conversation_participants table exists
CREATE TABLE IF NOT EXISTS conversation_participants (
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (conversation_id, user_id)
);

-- 3. Ensure the conversation_id column exists on messages
ALTER TABLE messages ADD COLUMN IF NOT EXISTS conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE;

-- 4. CRITICAL: Make channel_id nullable so DMs (which don't belong to a channel) can be saved
ALTER TABLE messages ALTER COLUMN channel_id DROP NOT NULL;