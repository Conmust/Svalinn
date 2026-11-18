-- custom_emojis.created_by was declared NOT NULL together with ON DELETE SET NULL,
-- so deleting a user who had uploaded an emoji failed. Allow NULL instead.
ALTER TABLE custom_emojis ALTER COLUMN created_by DROP NOT NULL;
