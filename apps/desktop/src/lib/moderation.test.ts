// Tests for `describeAuditAction`, the pure label-builder used by the
// Audit Log tab in ServerSettings.svelte -- see that component for where
// it's rendered, and crates/svalinn-server/src/audit_log.rs for the
// action strings and metadata shapes it has to handle.
import { describe, expect, it } from 'vitest';
import { describeAuditAction, type AuditLogEntry } from './moderation';

function entry(overrides: Partial<AuditLogEntry> = {}): AuditLogEntry {
  return {
    id: 'entry-1',
    action: 'member_kicked',
    actor_id: 'actor-1',
    actor_username: 'Mod',
    target_user_id: 'target-1',
    target_username: 'Troll',
    target_channel_id: null,
    target_channel_name: null,
    reason: null,
    metadata: {},
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('describeAuditAction', () => {
  it('describes a kick', () => {
    expect(describeAuditAction(entry({ action: 'member_kicked' }))).toBe('Mod kicked Troll');
  });

  it('describes a ban and an unban', () => {
    expect(describeAuditAction(entry({ action: 'member_banned' }))).toBe('Mod banned Troll');
    expect(describeAuditAction(entry({ action: 'member_unbanned' }))).toBe('Mod unbanned Troll');
  });

  it('describes a role change using the old and new role from metadata', () => {
    const result = describeAuditAction(
      entry({ action: 'role_changed', metadata: { old_role: 'member', new_role: 'moderator' } }),
    );
    expect(result).toBe("Mod changed Troll's role from member to moderator");
  });

  it('falls back to a question mark for a role change missing metadata', () => {
    expect(describeAuditAction(entry({ action: 'role_changed', metadata: {} }))).toBe(
      "Mod changed Troll's role from ? to ?",
    );
  });

  it('describes a moderator-deleted message, naming the channel when known', () => {
    const withChannel = entry({ action: 'message_deleted', target_channel_name: 'general' });
    expect(describeAuditAction(withChannel)).toBe('Mod deleted a message from Troll in #general');

    const withoutChannel = entry({ action: 'message_deleted', target_channel_name: null });
    expect(describeAuditAction(withoutChannel)).toBe('Mod deleted a message from Troll');
  });

  it('falls back gracefully when the actor or target account has since been deleted', () => {
    const result = describeAuditAction(
      entry({ action: 'member_kicked', actor_username: null, target_username: null }),
    );
    expect(result).toBe('A deleted user kicked a deleted user');
  });
});
