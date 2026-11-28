// @vitest-environment happy-dom
//
// ConfirmModal.svelte is the shared confirmation dialog used by the
// unpin-confirmation flow in ChatArea.svelte (show the server's
// requires_confirmation warning, confirm to retry with ?confirm=true)
// and by the pin-visibility-reveal flow -- both pass it a message and
// react to its confirm/cancel events rather than doing their own dialog
// logic. This tests the modal itself: that it shows what it's given and
// fires the right event for each action.
//
// It deliberately does NOT test ChatArea.svelte's own wiring (that
// clicking "Unpin" on an old pin actually opens this with the server's
// warning text, or that confirming calls unpinMessage(id, true)) --
// ChatArea.svelte fans out to ~10 modules on mount (websocket, crypto,
// ratchet, device recovery, server members, ...), so exercising that
// specific interaction via a real mount isn't attempted here. That
// wiring is covered today by: manual testing, the plain `handlePin`/
// `confirmUnpin` code review, and messages.test.ts's coverage of
// unpinMessage's request/response shapes (the server contract this
// wiring depends on).
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import { tick } from 'svelte';
import ConfirmModal from './ConfirmModal.svelte';

afterEach(() => cleanup());

describe('ConfirmModal', () => {
  it('shows the given title, message and confirm button text', () => {
    render(ConfirmModal, {
      props: {
        title: 'Unpin message',
        message: 'This message is old enough that unpinning it will delete it immediately.',
        confirmText: 'Unpin and delete',
        variant: 'danger',
      },
    });

    expect(screen.getByText(/Unpin message/)).toBeTruthy();
    expect(screen.getByText(/This message is old enough/)).toBeTruthy();
    expect(screen.getByText('[Unpin and delete]')).toBeTruthy();
  });

  it('dispatches confirm when the confirm button is clicked', async () => {
    const onConfirm = vi.fn();
    const { component } = render(ConfirmModal, { props: { message: 'Sure?' } });
    component.$on('confirm', onConfirm);

    await fireEvent.click(screen.getByText('[CONFIRM]'));

    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('dispatches cancel when the cancel button is clicked', async () => {
    const onCancel = vi.fn();
    const { component } = render(ConfirmModal, { props: { message: 'Sure?' } });
    component.$on('cancel', onCancel);

    await fireEvent.click(screen.getByText('[CANCEL]'));

    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('dispatches cancel on Escape and confirm on Enter', async () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    const { component } = render(ConfirmModal, { props: { message: 'Sure?' } });
    component.$on('confirm', onConfirm);
    component.$on('cancel', onCancel);
    // ConfirmModal registers its keydown listener in onMount, which Svelte
    // 4 flushes on the next microtask rather than synchronously at render.
    await tick();

    await fireEvent.keyDown(window, { key: 'Escape' });
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(onConfirm).not.toHaveBeenCalled();

    await fireEvent.keyDown(window, { key: 'Enter' });
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('dispatches cancel when the backdrop is clicked', async () => {
    const onCancel = vi.fn();
    const { component, container } = render(ConfirmModal, { props: { message: 'Sure?' } });
    component.$on('cancel', onCancel);

    const backdrop = container.querySelector('[role="button"]');
    expect(backdrop).toBeTruthy();
    await fireEvent.click(backdrop!);

    expect(onCancel).toHaveBeenCalledTimes(1);
  });
});
