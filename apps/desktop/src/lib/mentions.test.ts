import { describe, expect, it } from 'vitest';
import { extractMentionedUsernames, splitMentionSegments } from './mentions';

describe('extractMentionedUsernames', () => {
  it('matches a known username case-insensitively and returns its real casing', () => {
    expect(extractMentionedUsernames('hey @Alice how are you', ['alice', 'bob'])).toEqual(['alice']);
  });

  it('ignores a word that looks like a mention but matches no known member', () => {
    expect(extractMentionedUsernames('email me at @nobody', ['alice'])).toEqual([]);
  });

  it('returns each distinct mentioned username once, even if typed twice', () => {
    expect(extractMentionedUsernames('@alice and @alice again', ['alice'])).toEqual(['alice']);
  });

  it('finds multiple distinct mentions in one message', () => {
    const found = extractMentionedUsernames('@alice can you loop in @bob', ['alice', 'bob', 'carol']);
    expect(found.sort()).toEqual(['alice', 'bob']);
  });

  it('does not match a bare "@" with nothing after it, or an email-like address', () => {
    expect(extractMentionedUsernames('reach me @ noon, or at alice@example.com', ['alice', 'example'])).toEqual([]);
  });
});

describe('splitMentionSegments', () => {
  it('returns the whole content as one non-mention segment when nobody is mentioned', () => {
    expect(splitMentionSegments('just a plain message', [])).toEqual([{ text: 'just a plain message', isMention: false }]);
  });

  it('splits out a matched mention from surrounding text', () => {
    expect(splitMentionSegments('hey @alice welcome', ['alice'])).toEqual([
      { text: 'hey ', isMention: false },
      { text: '@alice', isMention: true },
      { text: ' welcome', isMention: false },
    ]);
  });

  it('matches case-insensitively but preserves the text as typed', () => {
    expect(splitMentionSegments('hey @ALICE', ['alice'])).toEqual([
      { text: 'hey ', isMention: false },
      { text: '@ALICE', isMention: true },
    ]);
  });

  it('does not highlight a "@word" that is not in mentionUsernames, even though something else matched', () => {
    expect(splitMentionSegments('@alice and @nobody', ['alice'])).toEqual([
      { text: '@alice', isMention: true },
      { text: ' and @nobody', isMention: false },
    ]);
  });

  it('does not treat the "@" in an email address as a mention', () => {
    expect(splitMentionSegments('reach me at alice@example.com', ['example'])).toEqual([
      { text: 'reach me at alice@example.com', isMention: false },
    ]);
  });

  it('rejoining every segment reproduces the original content exactly', () => {
    const content = 'start @alice middle @bob end with trailing text';
    const segments = splitMentionSegments(content, ['alice', 'bob']);
    expect(segments.map(s => s.text).join('')).toBe(content);
  });
});
