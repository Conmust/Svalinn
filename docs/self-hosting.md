# Self-Hosting Svalinn

This is the guide referenced from the README's [Self-Hosting](../README.md#self-hosting)
section: running `svalinn-server` for a community you host yourself, backed
by Docker Compose, with a reverse proxy in front of it for TLS.

If you just want to point the desktop app at a server for local development,
see [Run the Backend](../README.md#run-the-backend) instead — this guide is
for a server other people will actually connect to.

- [Quick start with Docker Compose](#quick-start-with-docker-compose)
- [Reverse proxy](#reverse-proxy)
- [Backups](#backups)
- [Upgrading](#upgrading)
- [Security hardening checklist](#security-hardening-checklist)

---

## Quick start with Docker Compose

This brings up Postgres, Redis, coturn (TURN/STUN for voice/video), applies
migrations, and starts the server, all in one stack.

1. **Clone the repo and create your `.env`:**

   ```bash
   git clone https://github.com/Conmust/Svalinn.git
   cd Svalinn
   cp .env.example .env
   ```

2. **Fill in `.env`.** At minimum, for a real deployment, set:

   | Variable | Why |
   |---|---|
   | `JWT_SECRET` | Signs login tokens. `openssl rand -hex 32` |
   | `EMAIL_ENCRYPTION_KEY` | Encrypts stored emails. `openssl rand -base64 32`. **Back this up** — losing it makes every stored email permanently unrecoverable. |
   | `EMAIL_BLIND_INDEX_PEPPER` | Lets the server look up emails without storing them in a searchable plaintext form. `openssl rand -hex 32`. Treat as permanent once set — changing it later locks every existing account out by email lookup. |
   | `RESEND_API_KEY` / `EMAIL_FROM` | Sends real verification/password-reset emails (see [email_delivery.rs](../crates/svalinn-server/src/email_delivery.rs)). Without these, those flows fail and get logged, not sent — users can't verify their email or reset a forgotten password. |
   | `POSTGRES_PASSWORD` | Only read by the compose file below, to set Postgres's own password. `openssl rand -hex 20` |
   | `TURN_SECRET` | Shared secret for minting TURN credentials. `openssl rand -hex 32`. Only needed if you want the coturn fallback for calls between peers that can't connect directly. |
   | `CORS_ALLOWED_ORIGINS` | If you build the desktop app to point at your server, or host a web build later, list its origin(s) here. |

   Leave `APP_ENV` as-is — the compose file below force-sets it to
   `production` regardless of what's in `.env`, since `.env.example`'s
   `development` default is for running the server directly with `cargo run`
   on your own machine.

3. **Bring up the stack:**

   ```bash
   docker compose -f deploy/docker-compose.prod.yml up -d --build
   ```

   This builds the server image from the repository's [`Dockerfile`](../Dockerfile),
   runs migrations once (the `migrate` service), then starts `server`, which
   waits for that to finish successfully before it starts. Postgres and Redis
   data live in named Docker volumes (`postgres_data`, `redis_data`); uploaded
   files (avatars, server icons, message attachments) live in `uploads_data`.

4. **Check it's up:**

   ```bash
   docker compose -f deploy/docker-compose.prod.yml logs -f server
   curl http://localhost:3001/health   # from inside the host, before you've set up a reverse proxy
   ```

   The server itself isn't published to the host on purpose (see the
   hardening checklist) — put a reverse proxy in front of it next.

5. **Point the desktop app at your server.** Users enter your server's URL on
   the login screen (see [Run a Server for Other People](../README.md#run-a-server-for-other-people)
   in the README for the app-side details).

`deploy/docker-compose.prod.yml` is a separate file from the repository
root's `docker-compose.yml`, which only brings up Postgres/Redis/coturn for
someone running the server with `cargo run` during development — that
file's `DATABASE_URL` (`localhost`) is correct for that case and wrong
inside a container, so don't run the server service from it.

---

## Reverse proxy

Terminate TLS at the proxy and forward to the server on the internal Docker
network (port 3001, as `expose`d by the `server` service — not published to
the host). Two things matter beyond a normal reverse-proxy config:

- **WebSocket upgrade** on `/api/v1/ws` — the server's real-time fan-out
  (messages, presence, typing indicators) is a single long-lived WebSocket
  connection per client.
- **Forwarded client address** — the server's rate limiting
  (`TRUST_PROXY=true`, already set by the compose file) reads
  `X-Forwarded-For` to see the real client IP instead of the proxy's.

### Caddy

Caddy handles WebSocket upgrades and gets a certificate automatically with
no extra config:

```caddyfile
chat.example.com {
    reverse_proxy localhost:3001
}
```

(Use `svalinn-server:3001` instead of `localhost:3001` if Caddy itself runs
as another service on the same Docker network as `deploy/docker-compose.prod.yml`,
rather than directly on the host.)

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name chat.example.com;

    ssl_certificate     /etc/letsencrypt/live/chat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Needed for /api/v1/ws specifically, but harmless to apply to the
        # whole location block.
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # The WebSocket connection is long-lived; nginx's default 60s
        # timeout would silently kill idle connections.
        proxy_read_timeout 1d;
        proxy_send_timeout 1d;
    }
}

server {
    listen 80;
    server_name chat.example.com;
    return 301 https://$host$request_uri;
}
```

### TURN (coturn)

coturn doesn't sit behind your reverse proxy — its ports (3478, 5349,
49160-49200/udp) need to reach the internet directly, since it's relaying
raw media, not HTTP. The compose file already publishes those. If you're
behind NAT yourself, forward those ports at your router/firewall, and set
`TURN_URIS` in `.env` to your public hostname or IP so clients know where to
reach it.

---

## Backups

Three things need backing up; losing any one has a different (and
permanent) consequence.

### Database

```bash
docker compose -f deploy/docker-compose.prod.yml exec -T postgres \
  pg_dump -U svalinn svalinn | gzip > svalinn-$(date +%F).sql.gz
```

Restore into a fresh stack (run this *before* starting `server`, right after
`postgres` is up and `migrate` has run against an empty database):

```bash
gunzip -c svalinn-2026-01-15.sql.gz | docker compose -f deploy/docker-compose.prod.yml exec -T postgres \
  psql -U svalinn svalinn
```

### Uploaded files

The `uploads_data` volume holds avatars, server icons, and message
attachments:

```bash
docker run --rm -v svalinn_uploads_data:/data -v "$PWD":/backup alpine \
  tar czf /backup/svalinn-uploads-$(date +%F).tar.gz -C /data .
```

(Docker Compose prefixes volume names with the project name, usually the
parent directory name — run `docker volume ls` to confirm the exact name on
your host before scripting this.)

### `.env` — especially `EMAIL_ENCRYPTION_KEY`

Back up `.env` itself, somewhere separate from the database backup (it's
secrets, the database backup is data). `EMAIL_ENCRYPTION_KEY` is the one
that matters most: every stored email address is encrypted with it, and
there is no recovery path if it's lost — not even from a database backup,
since the database only ever holds ciphertext. `EMAIL_BLIND_INDEX_PEPPER` is
the other one worth being deliberate about, though its failure mode is
different: it doesn't make data unrecoverable, but changing it after the
fact makes every existing account's email permanently unmatchable by
lookup (login-by-email, duplicate-signup checks, ban checks all break for
pre-existing accounts).

A reasonable cadence: nightly database dump, nightly (or on-change) uploads
archive, and `.env` backed up once whenever it changes rather than on a
schedule — and all three stored somewhere other than the host itself.

---

## Upgrading

```bash
git pull
docker compose -f deploy/docker-compose.prod.yml up -d --build
```

This rebuilds the image from the new source, re-runs `migrate` against the
(now possibly newer) migration set, and only then recreates `server` — same
ordering as a fresh deploy, so a partially-migrated schema is never served.

Two things worth knowing before you upgrade:

- **This isn't a zero-downtime deploy.** `server` stops before the new
  container starts. Presence, voice-channel rosters, and in-flight
  WebSocket connections are kept in-process (see the Architecture Overview
  in the README) rather than in Postgres/Redis, so a restart drops them —
  clients reconnect automatically, but expect a brief blip for anyone
  online during the upgrade.
- **Check the changelog/commit history for breaking `.env` changes** before
  upgrading across a large version gap — a new required variable will show
  up as a clear startup error (`init_keys`/`email_delivery::init`'s
  fail-fast checks print exactly what's missing and why), but it's still
  worth reading what changed first.

If an upgrade goes badly, roll back the code (`git checkout <previous-tag>`)
and rebuild the same way — migrations in this project are additive and
designed not to need a down-migration path, but restoring the database
backup taken right before the upgrade is the reliable fallback if a
migration itself is the problem.

---

## Security hardening checklist

- [ ] **Changed every default secret.** `JWT_SECRET`, `EMAIL_ENCRYPTION_KEY`,
      `EMAIL_BLIND_INDEX_PEPPER`, `POSTGRES_PASSWORD`, `TURN_SECRET` are all
      placeholders in `.env.example` — the server refuses to start with
      several of them unset outside development, but it can't tell a
      real secret from a weak one you typed in.
- [ ] **Postgres and Redis are not published to the host.** The compose
      file already omits `ports:` for both (unlike the local-dev
      `docker-compose.yml`, which does publish them, deliberately, for
      `cargo run` to reach) — don't add them back on a public host.
- [ ] **The server itself is only reachable through your reverse proxy.**
      The compose file `expose`s port 3001 to other containers on the same
      Docker network but doesn't publish it to the host; your reverse proxy
      is the only path in from outside.
- [ ] **TLS terminates at the reverse proxy**, not at the server — the
      examples above assume this.
- [ ] **`TRUST_PROXY=true`** (already set by the compose file) — without
      it, rate limiting sees your reverse proxy's IP for every request
      instead of each client's, effectively rate-limiting the whole proxy
      together, not each user individually.
- [ ] **`CORS_ALLOWED_ORIGINS`** lists only origins you actually serve a
      client from. The default allows only the Tauri app and the dev
      server — tighten or extend it deliberately, don't widen it broadly.
- [ ] **Back up `EMAIL_ENCRYPTION_KEY` before you have real users on the
      server**, not after (see [Backups](#backups)) — there's no recovery
      path once it's lost.
- [ ] **Keep the host OS and Docker itself patched.** This guide covers the
      application; it's not a substitute for normal host hardening
      (firewall rules for anything other than 443/80/the TURN ports, SSH
      key auth, automatic security updates).
- [ ] **Independently audited cryptography is not yet a claim this project
      makes** (see the README's [Security Model](../README.md#security-model))
      — self-hosting doesn't change what's and isn't audited; it only
      changes who operates the server.
