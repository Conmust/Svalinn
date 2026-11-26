// Regression test for `fileUrl`'s scheme allow-list -- part of the fix for
// a stored-XSS vector: an attachment/avatar/server-icon URL is rendered
// directly into an `<a href>`/`<img src>`/`<source src>` across the
// desktop client (MessageItem.svelte, DMChatArea.svelte, ServerRail.svelte,
// ...) with no further check, so `fileUrl` itself has to be the one place
// that refuses to hand back a dangerous scheme like `javascript:` verbatim.
// The server now also rejects these outright before they're ever stored
// (see `files::is_safe_external_url` and its call sites in
// `routes/{users,servers,messages,conversations}.rs`), but this is the
// client-side half of the same fix, covering any such value regardless of
// how it got here.
import { describe, expect, it } from 'vitest';
import { fileUrl } from './api';

describe('fileUrl', () => {
  it('returns an empty string for nothing', () => {
    expect(fileUrl(null)).toBe('');
    expect(fileUrl(undefined)).toBe('');
    expect(fileUrl('')).toBe('');
  });

  it('passes an http(s) URL through unchanged', () => {
    expect(fileUrl('https://example.com/pic.png')).toBe('https://example.com/pic.png');
    expect(fileUrl('http://example.com/pic.png')).toBe('http://example.com/pic.png');
  });

  it('passes a locally-created blob: object URL through unchanged', () => {
    expect(fileUrl('blob:http://localhost/some-uuid')).toBe('blob:http://localhost/some-uuid');
  });

  it('prepends apiBase to a bare /uploads/... path', () => {
    const result = fileUrl('/uploads/abc.png');
    // Not returned bare -- some origin is prefixed -- but the path itself
    // is preserved at the end.
    expect(result).not.toBe('/uploads/abc.png');
    expect(result.endsWith('/uploads/abc.png')).toBe(true);
  });

  it('never returns a javascript: URL verbatim', () => {
    const result = fileUrl('javascript:alert(document.cookie)');
    expect(result.toLowerCase().startsWith('javascript:')).toBe(false);
  });

  it('never returns a data: or vbscript: URL verbatim either', () => {
    expect(fileUrl('data:text/html,<script>alert(1)</script>').toLowerCase().startsWith('data:')).toBe(false);
    expect(fileUrl('vbscript:msgbox(1)').toLowerCase().startsWith('vbscript:')).toBe(false);
  });
});
