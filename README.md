# Svalinn

> **Your voice. Your data. Zero bloat.**

Svalinn is a desktop-first, privacy-focused communication app inspired by the best parts of community chat platforms — without the resource bloat, invasive data collection, or predatory feature gating.

Built with **Rust**, **Tauri**, and **Svelte**, Svalinn aims to deliver fast text chat, low-latency voice, and end-to-end encrypted direct messages while staying lightweight on system resources.

---

## Status

**Pre-alpha / active design and development**

Svalinn is not yet production-ready.

This repository currently represents the foundation of the project: architecture, MVP scope, client shell, backend experiments, and early implementation work.

Expect breaking changes, incomplete features, and rough edges.

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

The goal is not to clone every feature of existing platforms on day one.

The goal is to build a sharp, reliable wedge:  
**private communication that respects your hardware.**

---

## Core Principles

### 1. Performance is a feature

Svalinn is designed to use as little memory and CPU as possible.

Instead of bundling a full Chromium runtime like Electron apps do, Svalinn uses **Tauri** and the operating system’s native webview.

Target MVP memory footprint:

```text
Idle desktop client: <35 MB RAM
```

This is a target, not a marketing guarantee. Benchmark methodology will be published as the app matures.

---

### 2. Privacy by default

Svalinn is being designed around data minimization.

Planned MVP privacy properties:

- No phone number required
- No biometric verification
- No ad tracking
- No selling user data
- End-to-end encrypted 1-on-1 direct messages
- Open-source desktop client
- Local-first message caching

---

### 3. Familiar, not foreign

Svalinn uses a familiar structure:

- Servers
- Text channels
- Voice channels
- Direct messages
- Member lists
- Roles

The experience should feel immediately understandable to users coming from Discord, Guilded, Slack, or Matrix clients.

---

### 4. No artificial degradation

Svalinn should not cripple basic communication to force upgrades.

Core communication features should not be paywalled just because they are expensive for users to live without.

Paid plans, when introduced, will focus on:

- Community administration tools
- Creator/community monetization
- Hosted convenience
- Advanced organization features
- Optional supporter cosmetics

Not basic dignity.

---

## MVP Scope

The first version of Svalinn is intentionally narrow.

| Feature | MVP Status |
|---|---|
| Desktop app using Tauri | Planned |
| Svelte frontend | Planned |
| Rust backend | Planned |
| Email/password or magic-link auth | Planned |
| Server creation | Planned |
| Text channels | Planned |
| Real-time messaging over WebSockets | Planned |
| Local SQLite cache | Planned |
| 1-on-1 E2EE direct messages | Planned |
| Voice channels | Planned |
| WebRTC voice | Planned |
| Opus audio | Planned |
| RNNoise noise suppression | Planned |
| Svalinn Gauge RAM/CPU monitor | Planned |
| Windows/macOS/Linux builds | Planned |

---

## Not in the MVP

To avoid feature creep, the following are intentionally out of scope for the first release:

- Mobile apps
- Web app
- Screen sharing
- Video calls
- Bot ecosystem
- Webhooks
- Animated stickers
- Complex permission systems
- Public server discovery
- Message marketplace
- Algorithmic feeds
- Activities/games
- Full federation
- Server-level E2EE

These may be considered later, but the MVP must first prove the core value:

> **Private, lightweight, real-time communication.**

---

## The Svalinn Gauge

Svalinn includes a planned built-in performance indicator called the **Svalinn Gauge**.

Example:

```text
[ 24 MB RAM | 1.2% CPU ]
```

The goal is simple:

If Svalinn claims to be lightweight, it should be willing to show its work.

The Gauge is intended to display:

- Current memory usage
- Current CPU usage
- Optional recent usage graph
- Measurement details in development/debug mode

### Important measurement note

Because Tauri uses system webviews, memory reporting must account for the relevant app process tree, not just the Rust process.

Future benchmark reports should include:

- Operating system
- Hardware
- App version
- Idle vs active chat vs active voice usage
- WebView process memory
- GPU process memory where applicable
- Measurement tool used

---

## Architecture Overview

High-level architecture:

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
│          Axum / Actix Web           │
└─────────────────────────────────────┘
          │                    │
          │                    │
          ▼                    ▼
┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │      Redis      │
│ Persistent Data │    │ Pub/Sub/Presence│
└─────────────────┘    └─────────────────┘

Voice:
┌─────────────────────────────────────┐
│       WebRTC Audio Pipeline         │
│     Opus + RNNoise + P2P/TURN       │
└─────────────────────────────────────┘
```

---

## Planned Tech Stack

### Desktop Client

- **Tauri** — native desktop shell using system webviews
- **Rust** — native backend logic, commands, telemetry, crypto integration
- **Svelte** — lightweight compiled frontend
- **TypeScript** — frontend type safety
- **Tailwind CSS** — design system styling
- **SQLite** — local cache

### Server

- **Rust**
- **Axum** or **Actix Web**
- **PostgreSQL**
- **Redis**
- **WebSockets**

### Voice

- **WebRTC**
- **Opus**
- **RNNoise**
- **coturn** for TURN fallback
- Possible future SFU support for larger voice rooms

### Cryptography

- audited libraries only
- no custom cryptographic primitives
- planned 1-on-1 DM encryption using established Double Ratchet / X3DH-style design
- local private key storage
- server-side ciphertext storage only for E2EE DMs

---

## Security Model

Svalinn is privacy-focused, but security claims must be precise.

### MVP target

The MVP aims to support:

- E2EE for 1-on-1 direct messages
- encrypted transport for all client-server communication
- local generation of identity keys
- private keys that never leave the user’s device
- server inability to read E2EE DM plaintext

### Not yet claimed

The MVP does **not** yet claim:

- independently audited cryptography
- full metadata privacy
- production-grade secure multi-device sync
- E2EE server channels
- E2EE large group voice
- protection against compromised endpoints
- anonymity against global network observers

### Voice encryption note

WebRTC media is encrypted in transit using standard WebRTC security mechanisms.

However, if future voice rooms use an SFU, Svalinn should not describe that mode as fully end-to-end encrypted unless an additional media-layer E2EE mechanism is implemented and verified.

---

## Threat Model

Svalinn is being designed to reduce exposure from:

- unnecessary personal data collection
- server-side reading of private DMs
- invasive account verification requirements
- bloated clients consuming excessive system resources
- casual metadata leakage through excessive telemetry

Svalinn does not currently claim to protect users from:

- malware on their own device
- compromised operating systems
- malicious recipients taking screenshots
- traffic analysis by powerful network adversaries
- all forms of metadata correlation

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

> These instructions are provisional and may change as the repository structure solidifies.

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
git clone https://github.com/Conmust/svalinn.git
cd svalinn
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

Expected local services:

```text
PostgreSQL
Redis
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

## Run Database Migrations

Run this from the repository root:

```bash
cargo run -p svalinn-server --bin run-migrations
```

Applied migrations are recorded in the `_svalinn_migrations` table, so running it again only applies new files.

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

## Account Settings

The person icon at the bottom of the server list opens **Account Settings**, where you can change your email or password. Both need your current password. Changing your password logs you out on every other device.

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

A ban takes effect immediately: the user's sessions are revoked, open connections are closed, the app returns to the login screen showing the reason, and every request and login is refused until the ban is lifted. This also applies if `users.banned_at` is set directly in the database. After an unban, the user logs in again.

Uploaded files (attachments, emojis, server icons) are never served publicly. The API hands out signed links tied to the viewer's login session, and every download re-checks that the account isn't banned, the session is active and the viewer belongs to the file's server. Saved links therefore stop working as soon as access is revoked. Links expire after 6 hours; the app gets fresh ones whenever it loads messages.

---

## Run the Desktop App

```bash
pnpm --filter desktop tauri dev
```

To run only the web frontend in a browser: `pnpm dev`.

---

## Repository Structure

Planned structure:

```text
svalinn/
├── apps/
│   └── desktop/
│       ├── src/
│       ├── src-tauri/
│       └── package.json
│
├── crates/
│   ├── svalinn-server/
│   ├── svalinn-core/
│   ├── svalinn-crypto/
│   ├── svalinn-protocol/
│   └── svalinn-media/
│
├── packages/
│   ├── ui/
│   ├── config/
│   └── types/
│
├── docs/
│   ├── WHITEPAPER.md
│   ├── THREAT_MODEL.md
│   ├── PERFORMANCE.md
│   └── SELF_HOSTING.md
│
├── docker-compose.yml
├── Cargo.toml
├── package.json
├── pnpm-workspace.yaml
├── README.md
└── LICENSE
```

---

## Development Scripts

Planned scripts:

```bash
pnpm --filter desktop tauri dev  # Run desktop app in development
pnpm build           # Build frontend
pnpm check           # Type-check frontend
pnpm lint            # Lint frontend
cargo check          # Check Rust workspace
cargo test           # Run Rust tests
cargo fmt            # Format Rust code
docker compose up -d # Start local services
```

---

## Performance Goals

Svalinn’s early performance goals are:

| Scenario | Target |
|---|---|
| Idle app | <35 MB RAM |
| Basic text chat | <75 MB RAM |
| Small voice room | TBD |
| Startup time | <2 seconds on typical modern hardware |
| Message send latency | <100 ms server round-trip under normal conditions |

These are engineering targets, not guaranteed claims.

Published benchmarks should include hardware, OS, build type, and measurement method.

---

## Design Language

Svalinn’s UI should feel:

- calm
- compact
- fast
- familiar
- dark by default
- keyboard-friendly
- low-noise

Planned visual direction:

```text
Background: Obsidian / near-black
Primary accent: Frost blue
Text: Soft white / muted grey
Font: Inter, Geist, or similar
Monospace: JetBrains Mono
```

Color should be used sparingly.

Frost blue is reserved for:

- active states
- unread indicators
- focus rings
- secure indicators
- primary actions

---

## Roadmap

### Phase 1 — Desktop MVP

- Tauri desktop shell
- Svelte UI
- Rust backend
- Auth
- Servers and channels
- Real-time text
- Local cache
- E2EE DMs
- WebRTC voice
- Svalinn Gauge
- Desktop packaging

### Phase 2 — Community Foundations

- Better moderation tools
- Role hierarchy
- Invite management
- Audit logs
- Screen sharing
- Self-hosting documentation
- Public beta builds

### Phase 3 — Sustainability

- Optional supporter tier
- Hosted community plans
- Creator/community tools
- Organization features
- Long-term infrastructure funding

### Phase 4 — Expansion

- Mobile clients
- Web client
- Federation/bridging research
- Larger voice rooms
- Advanced accessibility support

---

## Monetization Philosophy

Svalinn will not sell user data.

Svalinn will not intentionally degrade basic communication to force subscriptions.

Possible future revenue sources:

- voluntary supporter subscriptions
- paid hosted community tools
- advanced organization features
- creator monetization tools
- managed hosting
- enterprise support

The core promise remains:

> Your voice. Your data. Zero bloat.

---

## Self-Hosting

Self-hosting is a long-term goal.

The project should eventually allow communities to run their own Svalinn infrastructure.

Planned self-hosting support:

- Docker Compose deployment
- PostgreSQL/Redis setup
- TURN server setup
- reverse proxy examples
- backup/restore guide
- upgrade guide
- security hardening checklist

Self-hosting documentation will live at:

```text
docs/SELF_HOSTING.md
```

---

## Contributing

Contributions are welcome.

Good first contribution areas:

- Tauri setup
- Svelte UI components
- Rust backend endpoints
- WebSocket handling
- SQLite caching
- accessibility improvements
- Linux packaging
- benchmark tooling
- documentation
- threat model review

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
Whitepaper:   ./docs/WHITEPAPER.md
Security:     security@svalinn.app
Community:   TBD
GitHub:       https://github.com/YOUR_ORG/svalinn
```

---

## Summary

Svalinn is an experiment with a simple thesis:

Modern community chat does not need to be heavy, invasive, or extractive.

A better tool is possible.

**Your voice. Your data. Zero bloat.**
