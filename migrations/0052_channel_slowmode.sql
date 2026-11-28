-- Per-channel slowmode: the minimum number of seconds an ordinary member
-- must wait between messages they send in this channel. 0 (the default)
-- means no slowmode. Enforced in routes::messages::create_message; set via
-- routes::channels::set_channel_slowmode, which requires admin rank or the
-- manage_channels permission (the same gate rename/delete already use).
--
-- Members holding manage_messages on the channel (moderators) are exempt --
-- see create_message's doc comment on the enforcement itself.
ALTER TABLE channels
    ADD COLUMN slowmode_seconds INTEGER NOT NULL DEFAULT 0
    CONSTRAINT channels_slowmode_seconds_range CHECK (slowmode_seconds BETWEEN 0 AND 21600);
