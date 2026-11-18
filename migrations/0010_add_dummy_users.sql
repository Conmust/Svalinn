-- Seed dummy users for testing (safe to run multiple times)
INSERT INTO users (username, email, password_hash, is_online)
SELECT v.username, v.email, v.password_hash, v.is_online
FROM (VALUES
    ('alice_hacker',  'alice@test.com',   '$argon2id$v=19$m=16,t=2,p=1$dummy123', true),
    ('bob_coder',     'bob@test.com',     '$argon2id$v=19$m=16,t=2,p=1$dummy123', true),
    ('charlie_dev',   'charlie@test.com', '$argon2id$v=19$m=16,t=2,p=1$dummy123', false),
    ('diana_sys',     'diana@test.com',   '$argon2id$v=19$m=16,t=2,p=1$dummy123', true),
    ('eve_admin',     'eve@test.com',     '$argon2id$v=19$m=16,t=2,p=1$dummy123', false)
) AS v(username, email, password_hash, is_online)
WHERE NOT EXISTS (
    SELECT 1 FROM users u WHERE u.email = v.email
);

-- Add them to your first server (only if a server exists)
DO $$
DECLARE
    first_server_id UUID;
BEGIN
    SELECT id INTO first_server_id FROM servers ORDER BY created_at ASC LIMIT 1;
    
    IF first_server_id IS NOT NULL THEN
        INSERT INTO server_members (server_id, user_id, role)
        SELECT
            first_server_id,
            u.id,
            CASE
                WHEN u.username = 'eve_admin' THEN 'admin'
                WHEN u.username IN ('alice_hacker', 'bob_coder') THEN 'moderator'
                ELSE 'member'
            END
        FROM users u
        WHERE u.email IN ('alice@test.com', 'bob@test.com', 'charlie@test.com', 'diana@test.com', 'eve@test.com')
        ON CONFLICT DO NOTHING;
    END IF;
END $$;