-- Add all existing users to the default server
INSERT INTO server_members (server_id, user_id, role)
SELECT '00000000-0000-0000-0000-000000000010', id, 'owner'
FROM users
ON CONFLICT DO NOTHING;
