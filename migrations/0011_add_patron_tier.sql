-- Add patron tier tracking to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS patron_tier VARCHAR(20) DEFAULT 'free';

-- Add index for faster patron lookups
CREATE INDEX IF NOT EXISTS idx_users_patron_tier ON users(patron_tier);

-- Optional: Add a bio field for patrons to show off
ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT DEFAULT '';