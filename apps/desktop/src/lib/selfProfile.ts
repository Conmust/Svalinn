import { writable } from 'svelte/store';

/**
 * The logged-in user's own signed avatar URL, kept separately from
 * `lib/auth.ts`'s `localStorage`-backed `User` so a changed avatar shows
 * up immediately in every mounted component (the channel/DM list
 * footers) without a reload or re-login. `AccountSettings.svelte` sets
 * this after a successful upload/clear; `ChannelList.svelte` and
 * `DMList.svelte` seed it on mount via `fetchMyProfile()`, since the
 * signed link in `localStorage`'s cached user (if any) expires.
 */
export const selfAvatarUrl = writable<string | null>(null);
