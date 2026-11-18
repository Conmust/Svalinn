import { defineConfig } from '@playwright/test';
import { API_PORT, API_URL, APP_PORT, APP_URL, DATABASE_URL, ROOT, SERVER_ENV } from './support/config';

const CI = !!process.env.CI;

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  workers: CI ? 2 : 3,
  retries: CI ? 1 : 0,
  forbidOnly: CI,
  reporter: CI ? [['github'], ['html', { open: 'never' }]] : [['list']],
  use: {
    baseURL: APP_URL,
    // Traces cost time; record one only when a failing test is retried.
    trace: 'on-first-retry',
  },
  projects: [
    { name: 'api', testDir: './tests/api' },
    { name: 'ui', testDir: './tests/ui', use: { viewport: { width: 1300, height: 760 } } },
  ],
  webServer: [
    {
      // Build everything (the tests also run svalinn-admin), apply
      // migrations to the test database, then start the server.
      command:
        'node e2e/scripts/prepare-db.mjs && cargo build -q -p svalinn-server --bins && ' +
        'cargo run -q -p svalinn-server --bin run-migrations && cargo run -q -p svalinn-server --bin svalinn-server',
      cwd: ROOT,
      url: `${API_URL}/health`,
      env: { ...SERVER_ENV, E2E_DATABASE_URL: DATABASE_URL },
      timeout: 10 * 60_000,
      reuseExistingServer: !CI,
      stdout: 'ignore',
      stderr: 'pipe',
    },
    {
      command: `pnpm --filter desktop exec vite --port ${APP_PORT} --strictPort`,
      cwd: ROOT,
      url: APP_URL,
      env: { VITE_API_URL: `http://localhost:${API_PORT}` },
      timeout: 2 * 60_000,
      reuseExistingServer: !CI,
    },
  ],
});
