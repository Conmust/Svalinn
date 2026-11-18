-- App-wide role. A site owner outranks everyone in every server they belong
-- to (they can manage, moderate, kick and ban anyone there, and can't be
-- kicked or banned by server staff). Set with: svalinn-admin set-site-owner
ALTER TABLE users ADD COLUMN IF NOT EXISTS site_role TEXT CHECK (site_role IN ('owner'));
