// The moderation audit log: a durable record of kicks, bans, unbans, role
// changes and moderator-deleted messages for a server. Thin wrapper around
// crates/svalinn-server/src/routes/moderation.rs -- see
// crates/svalinn-server/src/audit_log.rs for what each `action` string
// means and what `metadata` carries for it.

import { apiFetch, apiBase } from './api';

export interface AuditLogEntry {
  id: string;
  action: string;
  actor_id: string | null;
  /** `null` if the acting moderator's account has since been deleted. */
  actor_username: string | null;
  target_user_id: string | null;
  /** `null` either because this action had no target user, or that
   * account has since been deleted. */
  target_username: string | null;
  target_channel_id: string | null;
  target_channel_name: string | null;
  reason: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

async function errorFrom(res: Response, fallback: string): Promise<string> {
  const err = await res.json().catch(() => ({}));
  return err.error || fallback;
}

/**
 * A page of audit log entries, newest first. Pass `before` (an entry id
 * from a previous page) to load older entries. Fewer than `limit` entries
 * back means there's no more history.
 */
export async function fetchAuditLog(
  serverId: string,
  options: { before?: string; limit?: number } = {},
): Promise<AuditLogEntry[]> {
  const params = new URLSearchParams();
  if (options.before) params.set('before', options.before);
  if (options.limit) params.set('limit', String(options.limit));
  const qs = params.toString();
  const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/audit-log${qs ? `?${qs}` : ''}`);
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to load the audit log'));
  return res.json();
}

/** A short, human-readable label for an audit log entry's `action`. */
export function describeAuditAction(entry: AuditLogEntry): string {
  const actor = entry.actor_username ?? 'A deleted user';
  const target = entry.target_username ?? 'a deleted user';
  switch (entry.action) {
    case 'member_kicked':
      return `${actor} kicked ${target}`;
    case 'member_banned':
      return `${actor} banned ${target}`;
    case 'member_unbanned':
      return `${actor} unbanned ${target}`;
    case 'role_changed': {
      const oldRole = entry.metadata?.old_role;
      const newRole = entry.metadata?.new_role;
      return `${actor} changed ${target}'s role from ${oldRole ?? '?'} to ${newRole ?? '?'}`;
    }
    case 'custom_role_assigned':
      return `${actor} assigned a role to ${target}`;
    case 'custom_role_unassigned':
      return `${actor} removed a role from ${target}`;
    case 'message_deleted':
      return `${actor} deleted a message from ${target}${entry.target_channel_name ? ` in #${entry.target_channel_name}` : ''}`;
    default:
      return `${actor} performed ${entry.action} on ${target}`;
  }
}
