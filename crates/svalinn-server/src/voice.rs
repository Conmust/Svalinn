//! In-memory roster of who's currently in each voice channel.
//!
//! Deliberately not persisted: like `presence::Presence`'s open-connection
//! count, "who's in a voice channel" is only ever true of a live process.
//! A restart (or a crash) should come back with every voice channel empty,
//! not with stale occupants nobody can clear -- the client that reconnects
//! will `join` again if it's still actually in the call.
//!
//! One registry is shared by every voice channel on the server; membership
//! is checked by the route handlers (`routes/voice.rs`) before `join` is
//! ever called, so this module itself doesn't need to know about servers,
//! channel types, or permissions at all.

use std::collections::HashMap;

use serde::Serialize;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct VoiceParticipant {
    pub user_id: Uuid,
    pub username: String,
    pub muted: bool,
}

#[derive(Default)]
pub struct VoiceChannels {
    // channel_id -> (user_id -> participant). A `Vec` would also work at
    // this scale, but keying by user_id makes `leave`/`set_muted`/rejoin
    // (e.g. a reconnect that races the old connection's cleanup) O(1)
    // instead of a linear scan, and naturally dedupes a double-join.
    rooms: Mutex<HashMap<Uuid, HashMap<Uuid, VoiceParticipant>>>,
}

impl VoiceChannels {
    /// Adds the user to the channel's roster and returns who was already
    /// there (i.e. the peers the joining client needs to WebRTC-connect
    /// to) -- not including the user themselves, whether or not this is a
    /// rejoin.
    pub async fn join(&self, channel_id: Uuid, user_id: Uuid, username: String) -> Vec<VoiceParticipant> {
        let mut rooms = self.rooms.lock().await;
        let room = rooms.entry(channel_id).or_default();
        let existing: Vec<VoiceParticipant> = room.values().filter(|p| p.user_id != user_id).cloned().collect();
        room.insert(user_id, VoiceParticipant { user_id, username, muted: false });
        existing
    }

    /// Removes the user from one channel. Returns whether they were in it.
    pub async fn leave(&self, channel_id: Uuid, user_id: Uuid) -> bool {
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&channel_id) else { return false };
        let was_present = room.remove(&user_id).is_some();
        if room.is_empty() {
            rooms.remove(&channel_id);
        }
        was_present
    }

    /// Removes the user from every channel they're in (e.g. on disconnect,
    /// where the client never got a chance to call `leave` itself).
    /// Returns the channels they were removed from.
    pub async fn leave_all(&self, user_id: Uuid) -> Vec<Uuid> {
        let mut rooms = self.rooms.lock().await;
        let mut left = Vec::new();
        rooms.retain(|channel_id, room| {
            if room.remove(&user_id).is_some() {
                left.push(*channel_id);
            }
            !room.is_empty()
        });
        left
    }

    /// Updates the user's mute flag. Returns whether they were in the
    /// channel (a no-op client-side race -- e.g. toggling mute right as a
    /// leave is in flight -- shouldn't resurrect a room entry for them).
    pub async fn set_muted(&self, channel_id: Uuid, user_id: Uuid, muted: bool) -> bool {
        let mut rooms = self.rooms.lock().await;
        let Some(room) = rooms.get_mut(&channel_id) else { return false };
        let Some(participant) = room.get_mut(&user_id) else { return false };
        participant.muted = muted;
        true
    }

    /// Is this user currently in this channel? Used to authorize relaying
    /// WebRTC signaling between two users -- both sides must actually be
    /// joined to the same voice channel.
    pub async fn contains(&self, channel_id: Uuid, user_id: Uuid) -> bool {
        let rooms = self.rooms.lock().await;
        rooms.get(&channel_id).is_some_and(|room| room.contains_key(&user_id))
    }

    /// The current roster of one channel.
    pub async fn roster(&self, channel_id: Uuid) -> Vec<VoiceParticipant> {
        let rooms = self.rooms.lock().await;
        rooms.get(&channel_id).map(|room| room.values().cloned().collect()).unwrap_or_default()
    }

    /// Rosters of several channels at once (e.g. every voice channel in a
    /// server), keyed by channel id. Channels with nobody in them are
    /// simply absent from the map.
    pub async fn rosters(&self, channel_ids: &[Uuid]) -> HashMap<Uuid, Vec<VoiceParticipant>> {
        let rooms = self.rooms.lock().await;
        channel_ids
            .iter()
            .filter_map(|id| rooms.get(id).map(|room| (*id, room.values().cloned().collect())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(n: &str) -> String {
        n.to_string()
    }

    #[tokio::test]
    async fn join_returns_existing_but_not_self() {
        let voice = VoiceChannels::default();
        let channel = Uuid::new_v4();
        let (alice, bob) = (Uuid::new_v4(), Uuid::new_v4());

        assert_eq!(voice.join(channel, alice, name("alice")).await.len(), 0);
        let seen_by_bob = voice.join(channel, bob, name("bob")).await;
        assert_eq!(seen_by_bob.len(), 1);
        assert_eq!(seen_by_bob[0].user_id, alice);

        // A rejoin doesn't see yourself either.
        let rejoined = voice.join(channel, alice, name("alice")).await;
        assert_eq!(rejoined.len(), 1);
        assert_eq!(rejoined[0].user_id, bob);
    }

    #[tokio::test]
    async fn leave_empties_the_room() {
        let voice = VoiceChannels::default();
        let channel = Uuid::new_v4();
        let alice = Uuid::new_v4();

        voice.join(channel, alice, name("alice")).await;
        assert!(voice.leave(channel, alice).await);
        assert!(!voice.leave(channel, alice).await); // already gone
        assert_eq!(voice.roster(channel).await.len(), 0);
    }

    #[tokio::test]
    async fn leave_all_covers_every_channel_the_user_is_in() {
        let voice = VoiceChannels::default();
        let (c1, c2) = (Uuid::new_v4(), Uuid::new_v4());
        let alice = Uuid::new_v4();

        voice.join(c1, alice, name("alice")).await;
        voice.join(c2, alice, name("alice")).await;

        let mut left = voice.leave_all(alice).await;
        left.sort();
        let mut expected = vec![c1, c2];
        expected.sort();
        assert_eq!(left, expected);
        assert!(voice.roster(c1).await.is_empty());
        assert!(voice.roster(c2).await.is_empty());
    }

    #[tokio::test]
    async fn contains_checks_the_specific_channel() {
        let voice = VoiceChannels::default();
        let (c1, c2) = (Uuid::new_v4(), Uuid::new_v4());
        let alice = Uuid::new_v4();

        voice.join(c1, alice, name("alice")).await;
        assert!(voice.contains(c1, alice).await);
        assert!(!voice.contains(c2, alice).await);
    }

    #[tokio::test]
    async fn set_muted_updates_the_roster() {
        let voice = VoiceChannels::default();
        let channel = Uuid::new_v4();
        let alice = Uuid::new_v4();

        voice.join(channel, alice, name("alice")).await;
        assert!(voice.set_muted(channel, alice, true).await);
        assert!(voice.roster(channel).await[0].muted);

        // No room / not in it: reports false instead of creating one.
        assert!(!voice.set_muted(Uuid::new_v4(), alice, true).await);
    }
}
