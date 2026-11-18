ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment_url TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment_filename TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment_size BIGINT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment_mime_type TEXT;