<script lang="ts">
  import { createEventDispatcher, onMount } from 'svelte';
  import { apiFetch, apiBase } from '../lib/api';
  import { getCurrentUser, updateUserInStorage } from '../lib/auth';

  const dispatch = createEventDispatcher();

  let username = '';
  let email = '';
  let isSiteOwner = false;

  // Change email
  let newEmail = '';
  let emailPassword = '';
  let emailMessage = '';
  let emailError = '';
  let emailBusy = false;

  // Change password
  let currentPassword = '';
  let newPassword = '';
  let confirmPassword = '';
  let passwordMessage = '';
  let passwordError = '';
  let passwordBusy = false;

  onMount(async () => {
    const res = await apiFetch(`${apiBase()}/api/v1/users/me/account`);
    if (res.ok) {
      const account = await res.json();
      username = account.username;
      email = account.email;
      isSiteOwner = account.is_site_owner;
    }
  });

  async function errorFrom(res: Response, fallback: string): Promise<string> {
    const err = await res.json().catch(() => ({}));
    return err.error || fallback;
  }

  async function changeEmail(e: Event) {
    e.preventDefault();
    emailMessage = emailError = '';
    emailBusy = true;
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/users/me/email`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: newEmail, current_password: emailPassword }),
      });
      if (res.ok) {
        email = (await res.json()).email;
        const user = getCurrentUser();
        if (user) updateUserInStorage({ ...user, email });
        newEmail = emailPassword = '';
        emailMessage = 'Email updated. Use it the next time you log in.';
      } else {
        emailError = await errorFrom(res, 'Could not change email');
      }
    } catch (err: any) {
      emailError = err.message || 'Network error';
    } finally {
      emailBusy = false;
    }
  }

  async function changePassword(e: Event) {
    e.preventDefault();
    passwordMessage = passwordError = '';
    if (newPassword !== confirmPassword) {
      passwordError = "The new passwords don't match";
      return;
    }
    passwordBusy = true;
    try {
      const res = await apiFetch(`${apiBase()}/api/v1/users/me/password`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      });
      if (res.ok) {
        const { other_sessions_ended } = await res.json();
        currentPassword = newPassword = confirmPassword = '';
        passwordMessage = other_sessions_ended > 0
          ? `Password changed. You were logged out on ${other_sessions_ended} other device${other_sessions_ended === 1 ? '' : 's'}.`
          : 'Password changed.';
      } else {
        passwordError = await errorFrom(res, 'Could not change password');
      }
    } catch (err: any) {
      passwordError = err.message || 'Network error';
    } finally {
      passwordBusy = false;
    }
  }

  const input = 'w-full bg-[#0a0e0a] border border-[#00ff00] px-3 py-2 text-[#00ff00] text-sm focus:outline-none focus:shadow-[0_0_10px_rgba(0,255,0,0.3)]';
  const label = 'block text-xs text-[#00aa00] uppercase tracking-wider mb-1';
  const submit = 'w-full py-2 bg-black border-2 border-[#00ff00] text-[#00ff00] font-semibold uppercase tracking-wider text-sm hover:bg-[#00ff00] hover:text-black transition-all disabled:opacity-50';
</script>

<svelte:window on:keydown={(e) => e.key === 'Escape' && dispatch('close')} />

<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="account-title">
  <div class="relative w-[520px] max-w-[92vw] max-h-[88vh] overflow-y-auto bg-black border-2 border-[#00ff00] shadow-[0_0_30px_rgba(0,255,0,0.4)]">
    <div class="p-4 border-b border-[#00ff00] flex items-center justify-between">
      <h3 id="account-title" class="font-bold uppercase tracking-widest text-sm text-[#00ff00]">{'>'} Account Settings</h3>
      <button class="text-[#00ff00] hover:text-red-500" on:click={() => dispatch('close')} aria-label="Close account settings">✕</button>
    </div>

    <div class="p-6 space-y-8">
      <section>
        <div class="text-lg font-bold text-[#00ff00]">{username}</div>
        <div class="text-xs text-[#00aa00]">{email}</div>
        {#if isSiteOwner}
          <div class="inline-block mt-2 px-2 py-0.5 text-[10px] uppercase tracking-widest border border-[#ffaa00] text-[#ffaa00]">Site owner</div>
        {/if}
      </section>

      <form on:submit={changeEmail} class="space-y-3">
        <h4 class="text-sm font-bold text-[#00ff00] uppercase tracking-wider">Change email</h4>
        <div>
          <label for="account-new-email" class={label}>New email</label>
          <input id="account-new-email" type="email" bind:value={newEmail} class={input} required autocomplete="email" />
        </div>
        <div>
          <label for="account-email-password" class={label}>Current password</label>
          <input id="account-email-password" type="password" bind:value={emailPassword} class={input} required autocomplete="current-password" />
        </div>
        {#if emailError}<div class="text-xs text-red-500">{'>'} {emailError}</div>{/if}
        {#if emailMessage}<div class="text-xs text-[#00ff00]">{'>'} {emailMessage}</div>{/if}
        <button type="submit" class={submit} disabled={emailBusy}>{emailBusy ? 'Saving...' : 'Change email'}</button>
      </form>

      <form on:submit={changePassword} class="space-y-3">
        <h4 class="text-sm font-bold text-[#00ff00] uppercase tracking-wider">Change password</h4>
        <div>
          <label for="account-current-password" class={label}>Current password</label>
          <input id="account-current-password" type="password" bind:value={currentPassword} class={input} required autocomplete="current-password" />
        </div>
        <div>
          <label for="account-new-password" class={label}>New password</label>
          <input id="account-new-password" type="password" bind:value={newPassword} class={input} required minlength="6" autocomplete="new-password" />
        </div>
        <div>
          <label for="account-confirm-password" class={label}>Confirm new password</label>
          <input id="account-confirm-password" type="password" bind:value={confirmPassword} class={input} required minlength="6" autocomplete="new-password" />
        </div>
        <p class="text-[11px] text-[#00aa00]">Changing your password logs you out on every other device.</p>
        {#if passwordError}<div class="text-xs text-red-500">{'>'} {passwordError}</div>{/if}
        {#if passwordMessage}<div class="text-xs text-[#00ff00]">{'>'} {passwordMessage}</div>{/if}
        <button type="submit" class={submit} disabled={passwordBusy}>{passwordBusy ? 'Saving...' : 'Change password'}</button>
      </form>
    </div>
  </div>
</div>
