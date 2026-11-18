-- Uploaded files are served only to members of the server they belong to.
-- These indexes keep that per-request lookup fast.
CREATE INDEX IF NOT EXISTS idx_messages_attachment_url ON messages(attachment_url) WHERE attachment_url IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_custom_emojis_url ON custom_emojis(url);
CREATE INDEX IF NOT EXISTS idx_servers_icon_url ON servers(icon_url) WHERE icon_url IS NOT NULL;
