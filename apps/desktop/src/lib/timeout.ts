// Small shared helper so no part of the E2EE subsystem (sodium's WASM
// init, device registration, key-backup lookups, ...) can hang the UI
// indefinitely. Nothing here is crypto-specific -- it just bounds how long
// we're willing to wait on a promise before treating it as failed, so a
// stuck webview, a dead network call, or a WASM module that never calls
// back resolves to a clear error instead of a spinner that never ends.

/** Thrown by `withTimeout` when `promise` didn't settle within `ms`. The
 * underlying operation may still complete later (this doesn't cancel
 * anything) -- it's just that nothing is still waiting on it. */
export class TimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TimeoutError';
  }
}

/**
 * Resolves/rejects with whatever `promise` settles with, UNLESS `ms`
 * milliseconds pass first, in which case it rejects with a `TimeoutError`
 * instead. `promise` itself is never cancelled (most of what we wrap here
 * -- `fetch`, libsodium's WASM init -- has no cancellation hook anyway);
 * this only stops making the caller wait on it.
 */
export function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new TimeoutError(message)), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}
