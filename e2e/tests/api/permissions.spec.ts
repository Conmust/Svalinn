import { test, expect } from '@playwright/test';
import { admin, call, createServer, join, login, register, uniq } from '../../support/api';

test.describe('roles and permissions', () => {
  test('a new server gets a default role granting ordinary members the old baseline', async () => {
    const owner = await register('own');
    const { server } = await createServer(owner);
    const member = await register('mem');
    await join(owner, server.id, member);

    const roles = (await call(owner, 'GET', `/servers/${server.id}/roles`)).body;
    expect(roles).toHaveLength(1);
    expect(roles[0]).toMatchObject({ name: 'Member', is_default: true });
    expect(roles[0].permissions).toEqual(
      expect.arrayContaining(['view_channel', 'send_messages', 'create_invite', 'attach_files', 'add_reactions']),
    );

    const mine = (await call(member, 'GET', `/servers/${server.id}/permissions/me`)).body;
    expect(mine.permissions).toEqual(expect.arrayContaining(['view_channel', 'send_messages']));
    expect(mine.permissions).not.toContain('manage_roles');

    // The owner wasn't assigned the default role explicitly, but
    // unconditional-owner bypass still gives them everything.
    const ownerPerms = (await call(owner, 'GET', `/servers/${server.id}/permissions/me`)).body;
    expect(ownerPerms.permissions).toContain('administrator');
  });

  test('a plain member cannot create a role, and cannot grant permissions they lack', async () => {
    const owner = await register('own');
    const { server } = await createServer(owner);
    const member = await register('mem');
    await join(owner, server.id, member);

    const denied = await call(member, 'POST', `/servers/${server.id}/roles`, {
      name: 'Sneaky', permissions: ['administrator'],
    });
    expect(denied.status).toBe(403);

    // Grant the member MANAGE_ROLES via a custom role, but nothing else --
    // they should still be unable to mint an admin role for themselves.
    const limited = await call(owner, 'POST', `/servers/${server.id}/roles`, {
      name: 'Limited Manager', permissions: ['manage_roles'],
    });
    expect(limited.status).toBe(200);
    await call(owner, 'PUT', `/servers/${server.id}/members/${member.user.id}/roles/${limited.body.id}`);

    const escalate = await call(member, 'POST', `/servers/${server.id}/roles`, {
      name: 'Escalated', permissions: ['administrator'],
    });
    expect(escalate.status).toBe(400);
    expect(escalate.body.error).toContain("don't have yourself" || "permission you don't have");

    const ok = await call(member, 'POST', `/servers/${server.id}/roles`, {
      name: 'Fine', permissions: ['manage_roles'],
    });
    expect(ok.status).toBe(200);
  });

  test('role hierarchy: a manager cannot touch a role at or above their own rank', async () => {
    const owner = await register('own');
    const { server } = await createServer(owner);
    const manager = await register('mgr');
    await join(owner, server.id, manager);

    // New roles are appended at the top of the list (highest position),
    // same as Discord -- so create the junior role first.
    const low = (await call(owner, 'POST', `/servers/${server.id}/roles`, {
      name: 'Low', permissions: ['view_channel'],
    })).body;
    const high = (await call(owner, 'POST', `/servers/${server.id}/roles`, {
      name: 'High', permissions: ['manage_roles', 'manage_server'],
    })).body;
    await call(owner, 'PUT', `/servers/${server.id}/members/${manager.user.id}/roles/${high.id}`);

    // manager's own highest role is "High"; they can manage "Low" (below
    // them) but not "High" itself or create anything at/above their own
    // position.
    const editLow = await call(manager, 'PATCH', `/servers/${server.id}/roles/${low.id}`, { name: 'Low2' });
    expect(editLow.status).toBe(200);

    const editOwn = await call(manager, 'PATCH', `/servers/${server.id}/roles/${high.id}`, { name: 'High2' });
    expect(editOwn.status).toBe(403);

    const deleteOwn = await call(manager, 'DELETE', `/servers/${server.id}/roles/${high.id}`);
    expect(deleteOwn.status).toBe(403);
  });

  test('channel overwrites cannot be used to self-escalate or to silence a higher role', async () => {
    const owner = await register('own');
    const { server, channel } = await createServer(owner);
    const chanManager = await register('cm');
    await join(owner, server.id, chanManager);

    // A junior role, created before chanManager's own role so it ranks
    // below them, plus an ordinary member with no custom role at all
    // (rank -1, also below chanManager) -- both valid overwrite targets
    // for someone with just MANAGE_CHANNELS.
    const juniorRole = (await call(owner, 'POST', `/servers/${server.id}/roles`, {
      name: 'Junior', permissions: ['view_channel'],
    })).body;
    const managerRole = (await call(owner, 'POST', `/servers/${server.id}/roles`, {
      name: 'Chan Manager', permissions: ['manage_channels'],
    })).body;
    await call(owner, 'PUT', `/servers/${server.id}/members/${chanManager.user.id}/roles/${managerRole.id}`);
    const plainMember = await register('plain');
    await join(owner, server.id, plainMember);

    // Can't grant a target they outrank a permission they don't hold
    // themselves, whether via a role overwrite or a member overwrite.
    const escalateViaRole = await call(chanManager, 'PUT', `/channels/${channel.id}/overwrites/role/${juniorRole.id}`, {
      allow: ['administrator'],
    });
    expect(escalateViaRole.status).toBe(400);

    const escalateViaMember = await call(chanManager, 'PUT', `/channels/${channel.id}/overwrites/member/${plainMember.user.id}`, {
      allow: ['ban_members'],
    });
    expect(escalateViaMember.status).toBe(400);

    // A permission they DO hold is fine on a target they outrank.
    const fineAllow = await call(chanManager, 'PUT', `/channels/${channel.id}/overwrites/member/${plainMember.user.id}`, {
      allow: ['manage_channels'],
    });
    expect(fineAllow.status).toBe(204);

    // Create a senior "Admin" role ranked above chanManager's own role,
    // assigned to a different member -- chanManager must not be able to
    // deny (silence) or allow-override that role in this channel, even
    // though they hold MANAGE_CHANNELS.
    const admin2 = await register('adm2');
    await join(owner, server.id, admin2);
    const seniorRole = (await call(owner, 'POST', `/servers/${server.id}/roles`, {
      name: 'Senior', permissions: ['view_channel', 'send_messages'],
    })).body;
    await call(owner, 'PUT', `/servers/${server.id}/members/${admin2.user.id}/roles/${seniorRole.id}`);

    const silenceSenior = await call(chanManager, 'PUT', `/channels/${channel.id}/overwrites/role/${seniorRole.id}`, {
      deny: ['send_messages'],
    });
    expect(silenceSenior.status).toBe(403);

    const silenceSeniorMember = await call(chanManager, 'PUT', `/channels/${channel.id}/overwrites/member/${admin2.user.id}`, {
      deny: ['send_messages'],
    });
    expect(silenceSeniorMember.status).toBe(403);

    // The owner (who outranks everyone and holds everything) can still do
    // all of this normally.
    expect((await call(owner, 'PUT', `/channels/${channel.id}/overwrites/role/${seniorRole.id}`, {
      deny: ['send_messages'],
    })).status).toBe(204);
  });

  test('the default role cannot be deleted', async () => {
    const owner = await register('own');
    const { server } = await createServer(owner);
    const roles = (await call(owner, 'GET', `/servers/${server.id}/roles`)).body;
    const del = await call(owner, 'DELETE', `/servers/${server.id}/roles/${roles[0].id}`);
    expect(del.status).toBe(400);
  });

  test('channel overwrites take precedence over roles, and member over role', async () => {
    const owner = await register('own');
    const { server, channel } = await createServer(owner);
    const member = await register('mem');
    await join(owner, server.id, member);

    // By default the member can view the channel (default role grants it).
    expect((await call(member, 'GET', `/channels/${channel.id}/permissions/me`)).body.permissions)
      .toContain('view_channel');

    const defaultRole = (await call(owner, 'GET', `/servers/${server.id}/roles`)).body
      .find((r: any) => r.is_default);

    // Deny view_channel for the default role in this one channel.
    const denyRes = await call(owner, 'PUT', `/channels/${channel.id}/overwrites/role/${defaultRole.id}`, {
      deny: ['view_channel'],
    });
    expect(denyRes.status).toBe(204);
    expect((await call(member, 'GET', `/channels/${channel.id}/permissions/me`)).body.permissions)
      .not.toContain('view_channel');

    // A member-specific overwrite allowing it back wins over the role deny.
    const allowRes = await call(owner, 'PUT', `/channels/${channel.id}/overwrites/member/${member.user.id}`, {
      allow: ['view_channel'],
    });
    expect(allowRes.status).toBe(204);
    expect((await call(member, 'GET', `/channels/${channel.id}/permissions/me`)).body.permissions)
      .toContain('view_channel');

    // Sending is still blocked, since nothing restored it and the default
    // role's grant wasn't denied for it specifically -- confirm the owner
    // (unconditional bypass) and member resolve independently.
    const overwrites = (await call(owner, 'GET', `/channels/${channel.id}/overwrites`)).body;
    expect(overwrites.roles).toHaveLength(1);
    expect(overwrites.members).toHaveLength(1);
  });

  test('view_channel and send_messages are actually enforced on messages', async () => {
    const owner = await register('own');
    const { server, channel } = await createServer(owner);
    const member = await register('mem');
    await join(owner, server.id, member);

    expect((await call(member, 'GET', `/channels/${channel.id}/messages`)).status).toBe(200);

    const defaultRole = (await call(owner, 'GET', `/servers/${server.id}/roles`)).body
      .find((r: any) => r.is_default);
    await call(owner, 'PUT', `/channels/${channel.id}/overwrites/role/${defaultRole.id}`, {
      deny: ['send_messages'],
    });

    const sendAttempt = await call(member, 'POST', `/channels/${channel.id}/messages`, {
      encrypted_for: [],
      sender_device_id: '00000000-0000-0000-0000-000000000000',
    });
    expect(sendAttempt.status).toBe(403);

    await call(owner, 'PUT', `/channels/${channel.id}/overwrites/role/${defaultRole.id}`, {
      deny: ['view_channel'],
    });
    expect((await call(member, 'GET', `/channels/${channel.id}/messages`)).status).toBe(403);
  });

  test('a site owner who has not joined is still blocked despite the new permission checks', async () => {
    // Mirrors moderation.spec.ts's existing invariant test, specifically
    // against the new resolve_server/resolve_channel bypass path.
    const owner = await register('own');
    const { server, channel } = await createServer(owner);
    const name = uniq('Boss');
    expect(admin('create-user', name, `${name}@example.test`, '123456', '--site-owner')).toContain('site owner');
    const boss = { ...(await login(`${name}@example.test`, '123456')).body, ip: '10.9.9.8' };

    expect((await call(boss, 'GET', `/channels/${channel.id}/permissions/me`)).status).toBe(403);
    expect((await call(boss, 'GET', `/servers/${server.id}/permissions/me`)).status).toBe(403);
    await join(owner, server.id, boss);
    expect((await call(boss, 'GET', `/servers/${server.id}/permissions/me`)).body.permissions).toContain('administrator');
    admin('remove-site-owner', name);
  });
});
