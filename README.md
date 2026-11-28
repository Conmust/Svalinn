# Svalinn

> **Your voice. Your data. Zero bloat.**

Svalinn is a desktop-first, privacy-focused communication app inspired by the best parts of community chat platforms — without the resource bloat, invasive data collection, or predatory feature gating.

Built with **Rust**, **Tauri**, and **Svelte**, Svalinn delivers real-time text chat, voice and video calls, and end-to-end encrypted direct and channel messages while staying lightweight on system resources.

---

## Status

**Alpha / active development**

The core of Svalinn works today: accounts, servers, roles and permissions, text channels, voice channels, 1:1 voice/video calls, end-to-end encrypted messaging (DMs and channels), moderation tooling, and a self-serve patron tier. It is still pre-release — expect breaking changes, rough edges, and features that are deliberately unfinished (see [Not Yet Implemented](#not-yet-implemented) below).

Every push and pull request runs the full CI suite: the server's unit tests, a desktop type-check and build, and an end-to-end Playwright suite covering the API and the UI (including the crypto/recovery paths) — see [Tests](#tests).

---

## Why Svalinn?

Modern chat platforms have become powerful, but they often come with serious tradeoffs:

- High RAM and CPU usage
- Heavy desktop clients built on bundled browser runtimes
- Opaque data collection practices
- Core communication features locked behind subscriptions
- Increasing dependence on phone numbers, identity checks, or invasive verification flows
- Community tools that depend on fragile third-party bots

Svalinn exists to prove that a modern community chat app can be:

- **Fast**
- **Private**
- **Lightweight**
- **Auditable**
- **Sustainable**
- **Familiar enough to use immediately**

The goal was never to clone every feature of existing platforms on day one. The goal was to build a sharp, reliable wedge — private communication that respects your hardware — and then grow outward from there without losing that discipline.

---

## Core Principles

### 1. Performance is a feature

Svalinn is designed to use as little memory and CPU as possible.

Instead of bundling a full Chromium runtime like Electron apps do, Svalinn uses **Tauri** and the operating system's native webview.

This buys very different results depending on platform. macOS (WKWebView) and Linux (WebKitGTK) are genuinely lightweight, OS-shared frameworks. Windows has no equivalent: Tauri's only supported webview there is **WebView2**, which is Chromium itself, running its own multi-process architecture (browser, GPU, renderer, network processes). There is no official lighter alternative today — Tauri's Servo-based experiment to replace system webviews (Verso) has stalled and isn't production-ready.

Target memory footprint:

```text
Idle desktop client (macOS/Linux): <35 MB RAM
Idle desktop client (Windows): Svalinn's own processes stay under 35 MB RAM, but total
  Task-Manager-visible usage will be substantially higher (hundreds of MB) due to
  WebView2's own Chromium process tree. This is WebView2 overhead, not Svalinn's
  footprint — see "Important measurement note" below.
```

This is a target, not a marketing guarantee. Formal benchmark methodology and published numbers are still outstanding.

A built-in performance indicator, the **Svalinn Gauge**, already ships in the client (`apps/desktop/src/components/SvalinnGauge.svelte`, backed by a Tauri command in `src-tauri/src/gauge.rs`) and shows live memory/CPU usage so the app can be held to its own claim. It hides itself gracefully if its backend command isn't available on a given platform/build.

---

### 2. Privacy by default

Implemented today:

- No phone number required to sign up
- No biometric verification
- No ad tracking
- Email addresses are never shown to other users; disposable/throwaway email domains are blocked at signup, and a dedicated ban-evasion defense (see `email_privacy.rs`, `disposable_email.rs`) stops banned users from simply re-registering with a new address
- End-to-end encrypted direct messages **and** channel messages (Double Ratchet + X3DH, detailed below), including encrypted file attachments
- Passphrase-based end-to-end encrypted key recovery backup, so losing a device doesn't have to mean losing your encrypted history
- Open-source desktop client
- A public signup-count dashboard (`community-stats.html`) that publishes aggregate growth stats without exposing any individual user's data
- Anonymous patron-tier payments via RFC 9474 blind RSA tokens, so supporting the project doesn't require linking a payment to an identity server-side

Not yet implemented — see [Not Yet Implemented](#not-yet-implemented):

- Local-first message caching (the client currently relies on the server for message history; there is no local SQLite cache yet)
- Full metadata privacy and protection against global network observers

---

### 3. Familiar, not foreign

Svalinn already has the structure people expect coming from Discord, Guilded, Slack, or Matrix clients:

- Servers, with ownership and transfer
- Text channels and voice channels
- Direct messages
- A member list with avatars, per-server nicknames, and profile pictures
- A full role system: custom roles, a role hierarchy, and per-channel permission overwrites for both roles and individual members
- Invites (optionally expiring, optionally limited-use)

---

### 4. No artificial degradation

Core communication — messaging, channels, voice, DMs, E2EE — is not paywalled.

The only thing gated by tier today is **server creation**, which requires at least the Guild tier; the Patron tier (and a site-owner-grantable Beta badge) are self-service/cosmetic and do not affect the ability to communicate.

Paid plans, going forward, will continue to focus on:

- Community administration tools
- Creator/community monetization
- Hosted convenience
- Advanced organization features
- Optional supporter cosmetics (e.g. badge emblems)

Not basic dignity.

---

## What's Implemented

| Area | Status |
|---|---|
| Desktop app (Tauri + Svelte + Rust) | ✅ Working |
| Email/password auth, refresh tokens, sessions | ✅ Working |
| Server creation, ownership transfer, deletion | ✅ Working |
| Text channels (create/rename/delete), message history, edit | ✅ Working |
| Real-time messaging over WebSockets | ✅ Working |
| Roles, role hierarchy, per-channel role + member permission overwrites | ✅ Working |
| Invites (expiring / limited-use) | ✅ Working |
| Moderation: kick, ban, unban, site-owner override | ✅ Working |
| 1-on-1 and channel E2EE messaging (Double Ratchet / X3DH) | ✅ Working |
| E2EE file attachments in DMs | ✅ Working |
| E2EE key recovery via passphrase-encrypted backup | ✅ Working |
| Voice channels (multi-person) | ✅ Working |
| 1:1 voice/video calls over P2P WebRTC | ✅ Working |
| Profile pictures, per-server nicknames, badge emblems | ✅ Working |
| Email privacy, disposable-domain blocking, ban-evasion defense | ✅ Working |
| Anonymous signup-count public dashboard | ✅ Working |
| Anonymous patron-tier payments (RFC 9474 blind RSA tokens) | ✅ Working |
| Svalinn Gauge (RAM/CPU indicator) | ✅ Working |
| Tauri mobile scaffolding + responsive layout | 🟡 Scaffolded, not a shipping mobile app |
| Windows/macOS/Linux desktop builds | 🟡 Buildable; no published release artifacts yet |

## Not Yet Implemented

These are deliberately out of scope for now, to keep the core tight:

- Mobile apps (desktop-responsive layout exists; native mobile packaging does not)
- Web app
- Screen sharing
- Group video calls beyond 1:1 (voice channels support many people; video calling is currently 1:1)
- Local SQLite message cache
- Bot ecosystem / webhooks
- Animated stickers
- Public server discovery
- Message marketplace
- Algorithmic feeds
- Activities/games
- Full federation
- Server-level SFU voice E2EE (see Security Model)
- Independently audited cryptography

These may be considered later, but the project has deliberately kept them out while proving out the core: **private, lightweight, real-time communication that already works end-to-end.**

---

## Architecture Overview

```text
┌─────────────────────────────────────┐
│           Svalinn Desktop           │
│        Tauri + Svelte + Rust        │
└─────────────────────────────────────┘
                  │
                  │ WSS / HTTPS
                  ▼
┌─────────────────────────────────────┐
│             Rust Backend            │
│         svalinn-server (Axum)       │
└─────────────────────────────────────┘
          │                    │
          │                    │
          ▼                    ▼
┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL     │    │  In-process     │
│ Persistent data  │    │  pub/sub +      │
│                  │    │  presence       │
└──────────────────┘    └─────────────────┘

Voice/Video:
┌─────────────────────────────────────┐
│       WebRTC Audio/Video Pipeline    │
│          P2P, STUN/TURN assisted     │
└─────────────────────────────────────┘

E2EE:
┌─────────────────────────────────────┐
│   Double Ratchet + X3DH (client)     │
│   Server stores ciphertext only      │
└─────────────────────────────────────┘
```

---

## Tech Stack (as built)

### Desktop Client

- **Tauri** — native desktop shell using system webviews
- **Rust** — native backend logic, commands, and the Svalinn Gauge
- **Svelte** — lightweight compiled frontend
- **TypeScript** — frontend type safety, including the ratchet/recovery crypto code in `apps/desktop/src/lib`
- **Tailwind CSS** — styling

### Server (`crates/svalinn-server`)

- **Rust**
- **Axum**
- **PostgreSQL** (42 migrations and counting — see `migrations/`)
- **WebSockets** for real-time fan-out
- A dedicated `svalinn-admin` CLI binary for bans, session revocation and site-owner management (see Getting Started)

### Voice/Video

- **WebRTC**, peer-to-peer, for 1:1 calls and multi-person voice channels

### Cryptography

- Audited primitives only — no custom cryptographic primitives
- 1-on-1 **and** channel DM encryption using a Double Ratchet / X3DH-style design (`apps/desktop/src/lib/ratchet.ts`)
- Local, per-device identity, signing, and prekey material, generated client-side and never sent to the server in plaintext
- Server-side ciphertext storage only for E2EE messages
- Passphrase-based (Argon2id) recovery backup that can carry ratchet identity material across a device recovery, so a lost device doesn't silently break decryption of messages addressed to its old prekeys

---

## Security Model

Svalinn is privacy-focused, but security claims must be precise.

### What's actually in place

- E2EE for direct messages **and** channel messages
- E2EE file attachments
- Encrypted transport for all client-server communication
- Local generation of identity keys; private keys that never leave the user's device in plaintext
- Server inability to read E2EE message plaintext
- A deterministic tie-break for the X3DH mutual-initiation race (two devices initiating a session toward each other at the same moment), so both sides reliably converge on one session
- A passphrase recovery flow that restores ratchet identity/prekey material, not just the core identity keypair, so recovered devices can actually decrypt messages sent against their pre-recovery prekeys
- CI runs CodeQL on every push/PR, and the project has already had, and fixed, findings from a live pentest of its newer features

### Not yet claimed

- Independently audited cryptography
- Full metadata privacy
- Production-grade secure multi-device sync (recovery restores one device from a backup; it is not live multi-device sync)
- E2EE for multi-person voice/video (SFU-style group calls, if added later, should not be described as end-to-end encrypted unless a verified media-layer E2EE mechanism backs it)
- Protection against compromised endpoints
- Anonymity against global network observers

### Voice/video encryption note

WebRTC media is encrypted in transit using standard WebRTC security mechanisms (DTLS-SRTP). 1:1 calls are peer-to-peer. If a future group-voice mode routes media through an SFU, that mode should not be described as fully end-to-end encrypted unless an additional media-layer E2EE mechanism is implemented and verified.

---

## Threat Model

Svalinn is designed to reduce exposure from:

- Unnecessary personal data collection
- Server-side reading of private messages (DMs and channels)
- Invasive account verification requirements
- Bloated clients consuming excessive system resources
- Casual metadata leakage through excessive telemetry
- Ban evasion via throwaway/disposable email re-registration

Svalinn does not currently claim to protect users from:

- Malware on their own device
- Compromised operating systems
- Malicious recipients taking screenshots
- Traffic analysis by powerful network adversaries
- All forms of metadata correlation

Security is a process. Reports, audits, and criticism are welcome.

---

## Reporting Security Issues

Please do **not** open public GitHub issues for sensitive vulnerabilities.

Instead, use:

```text
security@svalinn.app
```

If that address is not yet active, replace this section with your preferred private disclosure method before launch.

Please include:

- affected version/commit
- operating system
- reproduction steps
- impact assessment
- proof of concept if available

We will aim to acknowledge security reports promptly and publish fixes transparently when appropriate.

---

## Getting Started

### Prerequisites

Install:

- Rust stable toolchain
- Node.js LTS
- pnpm
- Docker
- Tauri system dependencies for your OS

Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

pnpm:

```bash
npm install -g pnpm
```

Check versions:

```bash
rustc --version
cargo --version
node --version
pnpm --version
docker --version
```

---

## Clone the Repository

```bash
git clone https://github.com/Conmust/Svalinn.git
cd Svalinn
```

---

## Install Dependencies

```bash
pnpm install
```

---

## Start Local Services

```bash
docker compose up -d
```

Expected local service:

```text
PostgreSQL
```

---

## Environment Variables

Create a `.env` file from the example:

```bash
cp .env.example .env
```

The defaults in `.env.example` match the database in `docker-compose.yml`.

`JWT_SECRET` signs login tokens, and the server won't start without it. A short value is accepted only when `APP_ENV=development`; anywhere else, use at least 32 random characters, for example the output of:

```bash
openssl rand -base64 48
```

---

## Use Supabase as the Database

Svalinn only needs Postgres, so a Supabase project works. Its server talks to the database directly and doesn't use Supabase's Data API, Auth or Storage.

1. **Connection string:** in the Supabase dashboard, click **Connect** and copy the **Session pooler** string (port 5432). It looks like `postgresql://postgres.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres`. Add `?sslmode=require` to the end and put it in `.env` as `DATABASE_URL`. If the password has characters like `@`, `:`, `/` or `#`, URL-encode them or choose a password without them.
   - Don't use the **Transaction pooler** (port 6543). It breaks the prepared statements the server uses and the notifications that close a banned user's connection straight away.
   - The **Direct connection** (`db.<project-ref>.supabase.co`) also works, but only if your network supports IPv6.
2. **Turn off the Data API:** in **Project Settings → Data API**, disable it, or remove `public` from the exposed schemas. Supabase otherwise offers every table in `public`, including `users`, through a web API whose key is public. Migration `0028` also locks those tables down, as a second layer.
3. **Run the migrations and start the server** as below.

Keep the tests on a separate database (local Docker, or a second Supabase project via `E2E_DATABASE_URL`): they create many throwaway accounts.

---

## Run Database Migrations

Run this from the repository root:

```bash
cargo run -p svalinn-server --bin run-migrations
```

Applied migrations are recorded in the `_svalinn_migrations` table, so running it again only applies new files. There are 42 migrations as of this writing, covering everything from the original schema through roles/permissions, E2EE DM and channel sessions, key recovery, email privacy, and anonymous blind-token payments.

---

## Run the Backend

```bash
cargo run -p svalinn-server --bin svalinn-server
```

The server listens on `http://127.0.0.1:3001`.

---

## Run a Server for Other People

- **Listen address:** set `HOST=0.0.0.0` (and `PORT` if needed) so other machines can connect. Put the server behind a reverse proxy that provides HTTPS, and set `TRUST_PROXY=true` so rate limits see real client addresses.
- **Desktop app server address:** the app connects to `VITE_API_URL` (set when building; see `apps/desktop/.env.example`) and users can change the server on the login screen.
- **CORS:** only the desktop app and the dev server may call the API by default. Use `CORS_ALLOWED_ORIGINS` to change the list.
- **Rate limits:** logins are limited to 20 attempts per IP address per 5 minutes and 5 failed attempts per account per 15 minutes. Registration is limited to 5 new accounts per IP per hour, and invite lookups to 20 per user per 10 minutes. Limits are kept in memory and reset when the server restarts.

## Manage a Server

- **Roles:** Server Settings → Roles lets admins and above create custom roles, order the role hierarchy, and assign roles below their own rank. Owners can grant anything; admins can grant moderator and below.
- **Channel permissions:** each channel has a permissions panel for both role-based and per-member overwrites (view, send, manage, etc.), gated to admins and above.
- **Channels:** admins and above can rename or delete a channel from its hover buttons in the channel list. Deleting a channel deletes its messages and files.
- **Ownership:** the owner can transfer the server to another member from **Manage** (asks for your password); they stay on as an admin.
- **Delete server:** owner only, in **Server Settings → Overview**. Asks for your password and the server name.
- **History and editing:** scroll to the top of a channel to load older messages, 50 at a time. Use **Edit** on your own messages; edited messages are marked "(edited)".

## Account Settings

The person icon at the bottom of the server list opens **Account Settings**, where you can change your email or password, upload a profile picture, pick a badge emblem (if eligible), and run or restore an E2EE key recovery backup. Changing your email or password needs your current password, and changing your password logs you out on every other device.

## Invite People

Owners, admins and moderators create invites in **Server Settings → Invites**, optionally expiring and limited to a number of uses, and share the code. Others join from the **+** button in the server list (**Join** tab). Moderators and above can kick or ban members ranked below them from the member list, and lift bans in **Server Settings → Bans**. Anyone but the owner can leave a server from **Server Settings → Overview**.

---

## Ban Accounts and End Sessions

Run these from the repository root with the same `.env` as the server:

```bash
cargo run -p svalinn-server --bin svalinn-admin -- ban <email-or-username> [reason]
cargo run -p svalinn-server --bin svalinn-admin -- unban <email-or-username>
cargo run -p svalinn-server --bin svalinn-admin -- revoke-sessions <email-or-username>
cargo run -p svalinn-server --bin svalinn-admin -- list-banned
cargo run -p svalinn-server --bin svalinn-admin -- create-user <username> <email> <password> [--site-owner]
cargo run -p svalinn-server --bin svalinn-admin -- set-site-owner <email-or-username>
cargo run -p svalinn-server --bin svalinn-admin -- remove-site-owner <email-or-username>
```

A **site owner** outranks everyone, including each server's owner, in every server they belong to: they can manage settings, invites, emojis and messages, and kick or ban anyone, and nobody can kick or ban them. They don't get access to servers they haven't joined.

A ban takes effect immediately: the user's sessions are revoked, open connections are closed, the app returns to the login screen showing the reason, and every request and login is refused until the ban is lifted. This also applies if `users.banned_at` is set directly in the database. After an unban, the user logs in again. Banning is also defended against simple evasion: disposable/throwaway email domains are blocked at signup, so a banned user can't just register a fresh account with a burner address to get back in.

Uploaded files (attachments, emojis, server icons) are never served publicly. The API hands out signed links tied to the viewer's login session, and every download re-checks that the account isn't banned, the session is active and the viewer belongs to the file's server. Saved links therefore stop working as soon as access is revoked. Links expire after 6 hours; the app gets fresh ones whenever it loads messages.

---

## Run the Desktop App

```bash
pnpm --filter desktop tauri dev
```

To run only the web frontend in a browser: `pnpm dev`.

---

## Repository Structure

```text
svalinn/
├── apps/
│   └── desktop/
│       ├── src/            # Svelte UI + TS client-side crypto (ratchet.ts, recovery.ts)
│       ├── src-tauri/       # Rust Tauri shell, incl. the Svalinn Gauge
│       └── package.json
│
├── crates/
│   └── svalinn-server/      # Axum backend: auth, servers, channels, roles, voice
│       ├── src/              #   signaling, blind-token payments, email privacy, admin CLI
│       └── Cargo.toml
│
├── migrations/               # 42 sequential Postgres migrations
│
├── e2e/                      # Playwright API + UI/browser test suites
│   ├── tests/api/
│   └── tests/ui/
│
├── community-stats.html      # Public, anonymous signup-count dashboard
├── docker-compose.yml
├── Cargo.toml
├── package.json
├── pnpm-workspace.yaml
└── README.md
```

This reflects the repository as it stands today, not an aspirational layout — the `svalinn-core`/`svalinn-crypto`/`svalinn-protocol`/`svalinn-media` crate split and the `packages/ui` workspace mentioned in earlier drafts of this document haven't been built; the server is currently one crate and the crypto lives client-side in TypeScript.

---

## Tests

The `e2e/` folder holds API and browser tests (Playwright). They start their own server on port 3101 and app on port 1421, using a separate `svalinn_test` database, so they don't touch your dev setup and can run while it's running.

```bash
docker compose up -d postgres
```

```bash
pnpm install
```

```bash
pnpm --filter e2e exec playwright install chromium
```

```bash
pnpm test:e2e
```

Use `pnpm --filter e2e test:api` or `pnpm --filter e2e test:ui` to run one half, and `pnpm --filter e2e report` to open the last report. The test database is created on first run; set `E2E_DATABASE_URL` to use a different one. The server's unit tests run with `cargo test -p svalinn-server`.

The UI suite includes dedicated coverage for the trickiest parts of the crypto stack: simultaneous-initiation races between two devices (`dm-race-retest.spec.ts`) and end-to-end key recovery from a passphrase backup, including resuming a conversation on a recovered device (`recovery-open-conversation.spec.ts`), alongside the rest of the recovery, ratchet, and resilience suites.

GitHub Actions (`.github/workflows/ci.yml`) runs the server build and unit tests, the desktop type check and build, the full API and browser suite, and CodeQL on every push and pull request.

---

## Development Scripts

```bash
pnpm --filter desktop tauri dev  # Run desktop app in development
pnpm dev                         # Run just the web frontend in a browser
pnpm build                       # Build the desktop app
pnpm check                       # Type-check the desktop frontend
pnpm test:e2e                    # Run the full e2e suite
cargo check                      # Check the Rust workspace
cargo test -p svalinn-server      # Run server unit tests
cargo fmt                        # Format Rust code
docker compose up -d             # Start local services (Postgres)
```

---

## Performance Goals

| Scenario | Target |
|---|---|
| Idle app | <35 MB RAM |
| Basic text chat | <75 MB RAM |
| Small voice room | TBD |
| Startup time | <2 seconds on typical modern hardware |
| Message send latency | <100 ms server round-trip under normal conditions |

These are engineering targets, not guaranteed claims, and formal published benchmarks (hardware, OS, build type, measurement method) are still outstanding.

### Important measurement note

Because Tauri uses system webviews, memory reporting must account for the relevant app process tree, not just the Rust process. See the Svalinn Gauge section above for the built-in indicator that already surfaces this.

---

## Design Language

Svalinn's UI aims to feel:

- calm
- compact
- fast
- familiar
- dark by default
- keyboard-friendly
- low-noise

Visual direction:

```text
Background: Obsidian / near-black
Primary accent: Frost blue
Text: Soft white / muted grey
Font: Inter, Geist, or similar
Monospace: JetBrains Mono
```

Color is used sparingly. Frost blue is reserved for active states, unread indicators, focus rings, secure indicators, and primary actions.

---

## Roadmap

### Done (and still hardening)

- Tauri desktop shell, Svelte UI, Rust backend
- Auth, servers, channels, real-time text
- Roles, permissions, invites, moderation
- E2EE DMs and channel messages (Double Ratchet/X3DH), E2EE attachments, E2EE recovery backup
- Voice channels and 1:1 voice/video calls
- Svalinn Gauge
- Self-service patron tier, badge emblems, beta badges
- Email privacy, disposable-domain blocking, ban-evasion defense
- Anonymous signup stats dashboard
- Anonymous patron payments via blind RSA tokens
- CI: unit tests, type-check/build, full e2e suite, CodeQL
- Self-hosting documentation (Docker Compose stack, reverse proxy, backups, upgrades, hardening — see [docs/self-hosting.md](docs/self-hosting.md))

### Next — Community Foundations

- Local message cache for offline/fast-start
- Better moderation tooling (audit logs)
- Screen sharing
- Desktop packaging and published release builds for Windows/macOS/Linux
- Published, methodologically documented performance benchmarks

### Later — Sustainability

- Hosted community plans
- Creator/community monetization tools
- Organization features
- Long-term infrastructure funding

### Later — Expansion

- Native mobile clients (beyond the current responsive-layout scaffolding)
- Web client
- Federation/bridging research
- Group video / larger voice rooms with verified media-layer E2EE
- Advanced accessibility support

---

## Monetization Philosophy

Svalinn will not sell user data.

Svalinn will not intentionally degrade basic communication to force subscriptions.

Revenue sources today and under consideration:

- Self-service patron-tier subscriptions, paid anonymously via blind RSA tokens
- Paid hosted community tools (planned)
- Advanced organization features (planned)
- Creator monetization tools (planned)
- Managed hosting (planned)
- Enterprise support (planned)

The core promise remains:

> Your voice. Your data. Zero bloat.

---

## Self-Hosting

The server is a normal Rust/Postgres service with a documented `.env` and migration flow (see "Run a Server for Other People" above). For running it for a community, with a full Docker Compose stack, a reverse proxy in front of it, and backup/upgrade/hardening guidance, see **[docs/self-hosting.md](docs/self-hosting.md)**:

- Docker Compose deployment guide
- Reverse proxy examples (Caddy, nginx)
- Backup/restore guide
- Upgrade guide
- Security hardening checklist

---

## Contributing

Contributions are welcome.

Good first contribution areas:

- Local message caching
- Screen sharing
- Svelte UI components and accessibility improvements
- Rust backend endpoints
- WebSocket handling
- Linux/Windows/macOS packaging
- Benchmark tooling and published numbers
- Documentation (including self-hosting docs)
- Threat model review

Before contributing, please read:

```text
CONTRIBUTING.md
```

If that file does not exist yet, open an issue or discussion first so we can coordinate.

---

## Development Rules

To keep Svalinn focused:

1. Do not add features that significantly increase memory usage without discussion.
2. Do not add telemetry without explicit review.
3. Do not implement custom cryptography.
4. Do not add auto-playing media by default.
5. Do not add growth hacks, ads, or engagement loops.
6. Prefer boring, auditable technology over clever complexity.
7. Measure before claiming performance improvements.
8. A failing test gets fixed or explicitly, visibly marked as a known issue with a root-cause note — never silently routed around.

---

## License

License not finalized.

Recommended options:

- **AGPL-3.0-or-later** for strong open-source protection, especially for hosted/server deployments
- **MIT/Apache-2.0** for maximum permissive adoption
- split licensing if SDKs/protocol libraries need broader integration

Until a license is chosen, this project should be treated as:

```text
All rights reserved.
```

Replace this section before public launch.

---

## Name

Svalinn is named after the mythological shield that stands before the sun.

The name reflects the purpose of the project:

> A shield against overwhelming heat — against bloat, extraction, and unnecessary surveillance.

---

## Links

Replace these before launch:

```text
Website:      https://svalinn.app
Docs:         https://docs.svalinn.app
Security:     security@svalinn.app
Community:    TBD
GitHub:       https://github.com/Conmust/Svalinn
```

---

## Summary

Svalinn is no longer just a thesis — most of the hard parts (E2EE messaging with real recovery, roles and permissions, voice and video, anonymous payments, ban-evasion-resistant moderation) are built, tested, and running in CI today.

Modern community chat does not need to be heavy, invasive, or extractive. Svalinn is the proof that a better tool is possible, one working feature at a time.

**Your voice. Your data. Zero bloat.**
