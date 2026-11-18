// Creates the test database if it doesn't exist yet. Run before migrations.
import pg from 'pg';

const url = new URL(process.env.E2E_DATABASE_URL ?? 'postgres://svalinn:svalinn_dev@localhost:5432/svalinn_test');
const dbName = url.pathname.slice(1);
const admin = new URL(url);
admin.pathname = '/postgres';

const client = new pg.Client({ connectionString: admin.toString() });
try {
  await client.connect();
} catch (e) {
  console.error(`Can't reach Postgres at ${url.host}: ${e.message}`);
  console.error('Start it (for example: docker compose up -d postgres) or set E2E_DATABASE_URL.');
  process.exit(1);
}
const { rowCount } = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [dbName]);
if (rowCount === 0) {
  await client.query(`CREATE DATABASE "${dbName.replace(/"/g, '""')}"`);
  console.log(`Created test database ${dbName}`);
}
await client.end();
