-- Add is_online column to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_online BOOLEAN DEFAULT false;