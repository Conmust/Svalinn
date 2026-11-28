-- Enforces, at the database level, the invariant `pin_plaintext_content`
-- is supposed to uphold: a readable copy of a message only ever exists
-- while that message is pinned (see `routes::messages::reveal_pin_plaintext`
-- and `routes::messages::unpin_message`'s doc comments). The application
-- already closes the one concurrency race that could violate this (a
-- reveal landing between an unpin's read and write), and already masks the
-- column at read time as a second line of defense -- this constraint is
-- the third: it makes any future write path that forgets either of those
-- fail loudly at the database, rather than silently leaving a message's
-- content server-readable after it's no longer pinned.
ALTER TABLE messages ADD CONSTRAINT pin_plaintext_only_while_pinned
    CHECK (pin_plaintext_content IS NULL OR COALESCE(is_pinned, false));
