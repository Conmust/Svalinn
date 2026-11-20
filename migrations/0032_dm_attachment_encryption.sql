-- Extends the per-device DM fan-out model (0030_device_keys_and_fanout.sql)
-- to file attachments. Until now, a DM's `attachment_url` (and the file
-- bytes it points at) was always plaintext, even for an otherwise fully
-- encrypted fan-out message -- only the message TEXT was end-to-end
-- encrypted.
--
-- Re-encrypting the whole file once per recipient device (the way text
-- content is encrypted today) would mean uploading/storing N copies of a
-- potentially large file. Instead, this uses hybrid encryption: the client
-- generates ONE random symmetric key per attachment, encrypts the file
-- bytes with it ONCE (`crypto_secretbox_easy`, stored as today's single
-- shared blob at `attachment_url`), then wraps that small key once per
-- recipient device with the existing per-device `crypto_box_easy`
-- mechanism already used for text. Only the small wrapped key is
-- duplicated per device, not the file itself.
--
-- `messages.attachment_nonce` is the secretbox nonce for the shared
-- encrypted file blob -- one value per message, since the blob itself is
-- shared across every recipient. `message_recipients.attachment_key_*` is
-- each device's own wrapped copy of the symmetric file key: reuses that
-- row's existing `sender_public_key` column to unwrap it, exactly like it
-- already does for the per-device message ciphertext.
--
-- All three new columns are nullable: most messages have no attachment,
-- the legacy single-device send path never populates them, and even a
-- fan-out message with an attachment only sets `attachment_key_*` on
-- recipient rows (never on rows for a message with no attachment).
ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment_nonce TEXT;
ALTER TABLE message_recipients ADD COLUMN IF NOT EXISTS attachment_key_ciphertext TEXT;
ALTER TABLE message_recipients ADD COLUMN IF NOT EXISTS attachment_key_nonce TEXT;
