// Tests for the pure helpers pulled out of ChannelList.svelte/
// ServerSettings.svelte so they could be tested without a Svelte
// component-testing setup (see those components for where each is used).
import { describe, expect, it } from 'vitest';
import {
  MAX_SLOWMODE_SECONDS,
  formatBytes,
  mergeChannelUpdate,
  usageColor,
  validateSlowmodeSeconds,
} from './servers';

describe('validateSlowmodeSeconds', () => {
  it('accepts 0 (off) and the maximum', () => {
    expect(validateSlowmodeSeconds(0)).toBeNull();
    expect(validateSlowmodeSeconds(MAX_SLOWMODE_SECONDS)).toBeNull();
  });

  it('accepts an ordinary in-range value', () => {
    expect(validateSlowmodeSeconds(15)).toBeNull();
    expect(validateSlowmodeSeconds(30)).toBeNull();
  });

  it('rejects a negative value', () => {
    expect(validateSlowmodeSeconds(-1)).toMatch(/between 0 and/);
  });

  it('rejects anything past the server-side cap', () => {
    expect(validateSlowmodeSeconds(MAX_SLOWMODE_SECONDS + 1)).toMatch(/between 0 and/);
  });

  it('rejects a non-integer value', () => {
    expect(validateSlowmodeSeconds(15.5)).toMatch(/between 0 and/);
    expect(validateSlowmodeSeconds(NaN)).toMatch(/between 0 and/);
  });
});

describe('mergeChannelUpdate', () => {
  interface TestChannel {
    id: string;
    name: string;
    slowmode_seconds: number;
  }

  const channels: TestChannel[] = [
    { id: 'a', name: 'general', slowmode_seconds: 0 },
    { id: 'b', name: 'random', slowmode_seconds: 0 },
  ];

  it('merges only the named fields into the matching channel, leaving the rest untouched', () => {
    const result = mergeChannelUpdate(channels, { id: 'a', slowmode_seconds: 30 });
    expect(result.find(c => c.id === 'a')).toEqual({ id: 'a', name: 'general', slowmode_seconds: 30 });
    // Untouched channel, and untouched fields on the touched one.
    expect(result.find(c => c.id === 'b')).toEqual(channels[1]);
  });

  // Regression test for the bug this replaced: `onChannelUpdated` used to
  // apply only a hardcoded `name` field (`{ ...c, name: data.name }`), so
  // an update that didn't carry `name` -- like the slowmode broadcast,
  // which only ever sends `{ id, server_id, slowmode_seconds }` -- would
  // blank the channel's name to `undefined` instead of leaving it alone.
  it('does not blank out a field the update never mentions (the slowmode-broadcast case)', () => {
    const result = mergeChannelUpdate(channels, { id: 'a', slowmode_seconds: 15 });
    expect(result.find(c => c.id === 'a')?.name).toBe('general');
  });

  it('leaves the array as-is if no channel matches the update\'s id', () => {
    const result = mergeChannelUpdate(channels, { id: 'nonexistent', name: 'x' });
    expect(result).toEqual(channels);
  });

  it('does not mutate the original array', () => {
    const original = [...channels];
    mergeChannelUpdate(channels, { id: 'a', name: 'renamed' });
    expect(channels).toEqual(original);
  });
});

describe('formatBytes', () => {
  it('formats a sub-1024 value in bytes with no decimal', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1023)).toBe('1023 B');
  });

  it('formats exactly 1024 as 1.0 KB, not 1024 B', () => {
    expect(formatBytes(1024)).toBe('1.0 KB');
  });

  it('formats a value in the KB range to one decimal place', () => {
    expect(formatBytes(1536)).toBe('1.5 KB');
  });

  it('rolls over into MB at exactly 1024 KB', () => {
    expect(formatBytes(1024 * 1024)).toBe('1.0 MB');
  });

  it('rolls over into GB at exactly 1024 MB', () => {
    expect(formatBytes(1024 * 1024 * 1024)).toBe('1.0 GB');
  });

  it('stops at TB rather than rolling over again', () => {
    // Comfortably past the PB boundary -- should still read as some
    // number of TB, not roll into a unit past the end of the table.
    const hugeValue = 1024 * 1024 * 1024 * 1024 * 1024;
    expect(formatBytes(hugeValue)).toMatch(/ TB$/);
  });
});

describe('usageColor', () => {
  it('is green well under the cap', () => {
    expect(usageColor(10, 100)).toBe('#00ff00');
  });

  it('is green just under the 75% warning line', () => {
    expect(usageColor(74, 100)).toBe('#00ff00');
  });

  it('is amber at and past the 75% warning line but under the cap', () => {
    expect(usageColor(75, 100)).toBe('#ffaa00');
    expect(usageColor(99, 100)).toBe('#ffaa00');
  });

  it('is red at exactly the cap', () => {
    expect(usageColor(100, 100)).toBe('#ff0000');
  });

  it('is red past the cap', () => {
    expect(usageColor(150, 100)).toBe('#ff0000');
  });

  it('is green (not a divide-by-zero crash) for a non-positive cap', () => {
    expect(usageColor(5, 0)).toBe('#00ff00');
    expect(usageColor(5, -1)).toBe('#00ff00');
  });
});
