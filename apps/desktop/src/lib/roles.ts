// Server roles, member role assignment, and per-channel permission
// overwrites. Thin wrapper around crates/svalinn-server/src/routes/roles.rs
// -- see permissions.rs there for the bitflag names and how they resolve.

import { apiFetch, apiBase } from './api';

export interface Role {
  id: string;
  server_id: string;
  name: string;
  color: string | null;
  permissions: string[];
  position: number;
  is_default: boolean;
}

export interface RoleOverwrite {
  role_id: string;
  allow: string[];
  deny: string[];
}

export interface MemberOverwrite {
  user_id: string;
  allow: string[];
  deny: string[];
}

export interface ChannelOverwrites {
  roles: RoleOverwrite[];
  members: MemberOverwrite[];
}

/**
 * Every permission bit the server knows about, in the same order as
 * `Permission::ALL_NAMED`, each with a short label and description for the
 * permission-picker checkbox grid. `administrator` is called out specially
 * in the UI (it bypasses every other bit) rather than shown as just another
 * checkbox in the grid.
 */
export const PERMISSION_INFO: { name: string; label: string; description: string }[] = [
  { name: 'view_channel', label: 'View Channel', description: 'See this channel and read its messages' },
  { name: 'send_messages', label: 'Send Messages', description: 'Post messages in text channels' },
  { name: 'manage_messages', label: 'Manage Messages', description: "Delete, pin, lock or hide others' messages" },
  { name: 'manage_channels', label: 'Manage Channels', description: 'Create, rename, delete and reorder channels' },
  { name: 'manage_roles', label: 'Manage Roles', description: 'Create, edit and assign roles ranked below your own' },
  { name: 'manage_server', label: 'Manage Server', description: 'Rename the server, change its icon and settings' },
  { name: 'kick_members', label: 'Kick Members', description: 'Remove members ranked below your own' },
  { name: 'ban_members', label: 'Ban Members', description: 'Ban members ranked below your own' },
  { name: 'manage_emojis', label: 'Manage Emojis', description: 'Upload and delete custom emojis' },
  { name: 'create_invite', label: 'Create Invite', description: 'Generate invite links to the server' },
  { name: 'mention_everyone', label: 'Mention Everyone', description: 'Use @everyone and @here' },
  { name: 'attach_files', label: 'Attach Files', description: 'Upload attachments to messages' },
  { name: 'add_reactions', label: 'Add Reactions', description: 'React to messages with emoji' },
  { name: 'administrator', label: 'Administrator', description: 'Bypasses every permission check and overwrite' },
];

function jsonHeaders() {
  return { 'Content-Type': 'application/json' };
}

async function errorFrom(res: Response, fallback: string): Promise<string> {
  const err = await res.json().catch(() => ({}));
  return err.error || fallback;
}

// --- Roles ---

export async function listRoles(serverId: string): Promise<Role[]> {
  const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/roles`);
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to load roles'));
  return res.json();
}

export async function createRole(
  serverId: string,
  payload: { name: string; color?: string | null; permissions: string[] },
): Promise<Role> {
  const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/roles`, {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to create role'));
  return res.json();
}

export async function updateRole(
  serverId: string,
  roleId: string,
  payload: { name?: string; color?: string | null; permissions?: string[]; position?: number },
): Promise<Role> {
  const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/roles/${roleId}`, {
    method: 'PATCH',
    headers: jsonHeaders(),
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to update role'));
  return res.json();
}

export async function deleteRole(serverId: string, roleId: string): Promise<void> {
  const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/roles/${roleId}`, { method: 'DELETE' });
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to delete role'));
}

// --- Member role assignment ---

export async function assignRole(serverId: string, userId: string, roleId: string): Promise<void> {
  const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/members/${userId}/roles/${roleId}`, {
    method: 'PUT',
  });
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to assign role'));
}

export async function unassignRole(serverId: string, userId: string, roleId: string): Promise<void> {
  const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/members/${userId}/roles/${roleId}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to unassign role'));
}

// --- Resolved permissions ---

export async function myServerPermissions(serverId: string): Promise<string[]> {
  const res = await apiFetch(`${apiBase()}/api/v1/servers/${serverId}/permissions/me`);
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to load permissions'));
  return (await res.json()).permissions;
}

export async function myChannelPermissions(channelId: string): Promise<string[]> {
  const res = await apiFetch(`${apiBase()}/api/v1/channels/${channelId}/permissions/me`);
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to load permissions'));
  return (await res.json()).permissions;
}

// --- Channel overwrites ---

export async function listChannelOverwrites(channelId: string): Promise<ChannelOverwrites> {
  const res = await apiFetch(`${apiBase()}/api/v1/channels/${channelId}/overwrites`);
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to load channel overwrites'));
  return res.json();
}

export async function setRoleOverwrite(
  channelId: string,
  roleId: string,
  payload: { allow: string[]; deny: string[] },
): Promise<void> {
  const res = await apiFetch(`${apiBase()}/api/v1/channels/${channelId}/overwrites/role/${roleId}`, {
    method: 'PUT',
    headers: jsonHeaders(),
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to set role overwrite'));
}

export async function deleteRoleOverwrite(channelId: string, roleId: string): Promise<void> {
  const res = await apiFetch(`${apiBase()}/api/v1/channels/${channelId}/overwrites/role/${roleId}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to remove role overwrite'));
}

export async function setMemberOverwrite(
  channelId: string,
  userId: string,
  payload: { allow: string[]; deny: string[] },
): Promise<void> {
  const res = await apiFetch(`${apiBase()}/api/v1/channels/${channelId}/overwrites/member/${userId}`, {
    method: 'PUT',
    headers: jsonHeaders(),
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to set member overwrite'));
}

export async function deleteMemberOverwrite(channelId: string, userId: string): Promise<void> {
  const res = await apiFetch(`${apiBase()}/api/v1/channels/${channelId}/overwrites/member/${userId}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error(await errorFrom(res, 'Failed to remove member overwrite'));
}
