-- Add user status column with default 'offline'
ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'offline';

-- Create index for faster status lookups
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

-- Update existing users: if they were online, set status to 'online', otherwise 'offline'
UPDATE users SET status = CASE 
    WHEN is_online THEN 'online'
    ELSE 'offline'
END;