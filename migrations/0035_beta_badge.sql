-- An owner-granted badge, independent of the patron tier system: the site
-- owner can mark any account with it (and unmark it) from that user's
-- profile. Shown alongside the tier badge (`PatronBadge.svelte`), never in
-- place of it, and visible regardless of patron_tier/site ownership.
ALTER TABLE users ADD COLUMN IF NOT EXISTS has_beta_badge BOOLEAN NOT NULL DEFAULT false;
