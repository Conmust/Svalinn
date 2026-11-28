/** `@username` parsing and rendering, shared by the composer (resolving
 * what the sender typed into user ids to send) and message display
 * (splitting a sent message's text into plain/highlighted segments).
 *
 * Kept deliberately simple for v1: an exact, case-insensitive match on a
 * member's `username` only (not `display_name`, which can contain spaces
 * and punctuation that would make "where does the mention end" ambiguous).
 * No autocomplete UI -- you type the real username and it resolves. */

const USERNAME_CHARS = /[a-zA-Z0-9_]/;

/** Finds every `@word` token in `text` and returns the distinct usernames
 * (case preserved as typed) of ones that match a known member -- for the
 * composer to resolve into user ids before sending. Matching is
 * case-insensitive; `knownUsernames` should be every member's `username`
 * for the channel being sent to. */
export function extractMentionedUsernames(text: string, knownUsernames: readonly string[]): string[] {
  const known = new Map(knownUsernames.map(u => [u.toLowerCase(), u]));
  const found = new Set<string>();
  // The negative lookbehind keeps this from treating the "@" in an email
  // address (alice@example.com) as a mention of a member named "example".
  const re = /(?<![a-zA-Z0-9_])@([a-zA-Z0-9_]+)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    const real = known.get(match[1].toLowerCase());
    if (real) found.add(real);
  }
  return [...found];
}

export interface MentionSegment {
  text: string;
  /** True for a `@username` segment (including the `@`) that matched one
   * of `mentionUsernames` -- the ones to render highlighted. */
  isMention: boolean;
}

/** Splits `content` into segments for rendering, marking `@username`
 * occurrences that match one of `mentionUsernames` (case-insensitive) so
 * the caller can highlight exactly those -- never an arbitrary "@word"
 * that merely looks like a mention but wasn't one the server recorded for
 * this message. Plain text segments are rendered as-is (the caller is
 * expected to use Svelte's normal text interpolation, not `{@html}`, so
 * there's no HTML-escaping to do here). */
export function splitMentionSegments(content: string, mentionUsernames: readonly string[]): MentionSegment[] {
  if (mentionUsernames.length === 0 || !content) {
    return [{ text: content, isMention: false }];
  }
  const mentionSet = new Set(mentionUsernames.map(u => u.toLowerCase()));
  const segments: MentionSegment[] = [];
  let buffer = '';
  let i = 0;
  while (i < content.length) {
    // The `i === 0 || !USERNAME_CHARS.test(...)` check mirrors
    // `extractMentionedUsernames`'s negative lookbehind: without it, the
    // "@" in an email address (alice@example.com) would be treated as a
    // mention of a member named "example".
    if (content[i] === '@' && (i === 0 || !USERNAME_CHARS.test(content[i - 1]))) {
      let j = i + 1;
      while (j < content.length && USERNAME_CHARS.test(content[j])) j++;
      const candidate = content.slice(i + 1, j);
      if (candidate && mentionSet.has(candidate.toLowerCase())) {
        if (buffer) {
          segments.push({ text: buffer, isMention: false });
          buffer = '';
        }
        segments.push({ text: content.slice(i, j), isMention: true });
        i = j;
        continue;
      }
    }
    buffer += content[i];
    i++;
  }
  if (buffer) segments.push({ text: buffer, isMention: false });
  return segments;
}
