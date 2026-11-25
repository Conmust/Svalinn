// Settings for the test environment. Tests run their own server and app on
// separate ports and a separate database, so they don't touch your dev setup.
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

export const API_PORT = Number(process.env.E2E_API_PORT ?? 3101);
export const APP_PORT = Number(process.env.E2E_APP_PORT ?? 1421);
export const API_URL = `http://localhost:${API_PORT}`;
export const APP_URL = `http://localhost:${APP_PORT}`;

export const DATABASE_URL =
  process.env.E2E_DATABASE_URL ?? 'postgres://svalinn:svalinn_dev@localhost:5432/svalinn_test';

/** Known to the tests so they can forge tokens and signed links. Test-only. */
export const JWT_SECRET = 'e2e-test-secret-not-for-production-0123456789';

/**
 * email_privacy::init_keys refuses to start the server without these.
 * Test-only, fixed so a run's encrypted-email fixtures stay readable across
 * processes in the same run; not used anywhere outside this test database.
 */
export const EMAIL_ENCRYPTION_KEY =
  process.env.E2E_EMAIL_ENCRYPTION_KEY ?? 'sjaP9fNPQiOdj5s23kGjy6bCtQj3tcO+DQfxmcuAuWo=';
export const EMAIL_BLIND_INDEX_PEPPER =
  process.env.E2E_EMAIL_BLIND_INDEX_PEPPER ?? 'e2e-test-pepper-not-a-real-secret-0123456789';

/** Environment for the server under test. */
export const SERVER_ENV: Record<string, string> = {
  DATABASE_URL,
  JWT_SECRET,
  EMAIL_ENCRYPTION_KEY,
  EMAIL_BLIND_INDEX_PEPPER,
  APP_ENV: 'test',
  HOST: '127.0.0.1',
  PORT: String(API_PORT),
  CORS_ALLOWED_ORIGINS: `${APP_URL},http://127.0.0.1:${APP_PORT}`,
  // Each test user sends its own X-Forwarded-For address, so per-IP rate
  // limits stay switched on without the suite tripping over them.
  TRUST_PROXY: 'true',
  RUST_LOG: 'warn',
};

export const exe = (name: string) =>
  path.join(ROOT, 'target', 'debug', process.platform === 'win32' ? `${name}.exe` : name);
