# Vuln Intel Platform

Vulnerability intelligence platform: ingest CVE + enrich with EPSS/KEV + AI context, provide a fast UI for triage, and keep the pipeline observable.

This repo is a **pnpm + turbo monorepo** with:
- **API** (NestJS): auth + CVE search + stats endpoints
- **Ingest** (NestJS): NVD/KEV/EPSS + vendor advisory RSS/Atom ingestion
- **AI** (NestJS): background workers for scoring + LLM enrichment (Ollama/OpenAI-compatible)
- **Web** (Next.js App Router): UI + BFF routes (proxy to API + extra integrations like ФСТЭК feed)

---

## Modules (what you get)

### Web UI (`apps/web`)
- **Dashboard / Overview**: platform summary, freshness watermarks, “hot” CVEs, vendor landscape.
- **Vulnerabilities**: list, filters, CVE card (with optional on-demand enrich).
- **Patch management**: vendor advisory feed (RSS/Atom → normalized table).
- **ФСТЭК module**: Telegram-based BDU feed parser (`/api/fstec/feed`) with optional local linking.
- **Health page**: `/health` UI, backed by `/api/health` checks.

### API (`apps/api`)
- **Auth**: JWT + optional TOTP (2FA). Bootstrap first user via env on empty DB.
- **CVE**: search/list/details, lookup helpers, optional manual enrich endpoint.
- **Stats**: summary/vendors/queue health + DLQ tools.
- **Health**: lightweight API health endpoint.

### Ingest (`apps/ingest`)
- **NVD**: incremental polling and DB ingestion.
- **KEV**: CISA Known Exploited Vulnerabilities catalog → DB upsert.
- **EPSS**: daily feed import (CSV.gz) → DB upsert + deterministic rescoring queue fanout.
- **Patch advisories**: vendor RSS/Atom ingestion → `vendor_advisory` table.

### AI (`apps/ai`)
- **Queue workers**: consume from RabbitMQ (`ai.enrich`, scoring queues).
- **LLM integration**: OpenAI-compatible `chat/completions` (or LAN Ollama) with retries/timeouts.
- **Redis**: optional enrich cache to avoid repeated LLM calls.

---

## Integrations & external data sources

- **NVD (NIST)**: CVE data (uses `NVD_API_KEY` when set).
- **CISA KEV**: `known_exploited_vulnerabilities.json`.
- **EPSS**: `epss_scores-current.csv.gz`.
- **Vendor advisories (RSS/Atom)**: configurable list; includes international + RU sources.
- **ФСТЭК BDU Telegram feed**: parses `https://t.me/s/<channel>` by default (no RSSHub dependency).
- **RabbitMQ**: event bus / queues / DLQ.
- **Postgres**: primary storage.
- **Redis**: enrich cache + some invalidation helpers.

---

## Repo layout

- `apps/api` — NestJS HTTP API (port is `PORT`, default in dev orchestrator: 4001)
- `apps/ingest` — NestJS ingest runner (no public port)
- `apps/ai` — NestJS worker runner (no public port)
- `apps/web` — Next.js UI + BFF routes (port: `WEB_PORT`, default: 3001)
- `packages/shared` — shared types/schemas/utilities (used by all apps)
- `infra` — local dev infra (Docker compose + Postgres init SQL)
- `scripts` — dev orchestrator + ops helpers

---

## Quickstart (local dev)

### Prerequisites
- **Node.js**: >= 20
- **pnpm**: repo pins `pnpm@10`
- **Docker**: for Postgres/Redis/RabbitMQ

### 1) Start infra (DB/Redis/RabbitMQ)

```bash
pnpm infra:up
```

This starts:
- Postgres `localhost:5432`
- Redis `localhost:6379`
- RabbitMQ `localhost:5672` + management UI `http://localhost:15672` (user/pass: `vuln`/`vuln`)

### 2) Configure env

Create local secrets file:

```bash
cp .env.example .env
```

Minimum required for API auth:
- `JWT_SECRET` (**>= 32 chars**)

Optional but recommended:
- `AUTH_BOOTSTRAP_EMAIL` / `AUTH_BOOTSTRAP_PASSWORD` to auto-create the first user (only when `auth_user` table is empty)
- `NVD_API_KEY` for higher NVD throughput
- `LLM_ENDPOINT` / `LLM_API_KEY` / `LLM_MODEL` for AI enrichment

### 3) Install deps

```bash
pnpm install
```

### 4) Run everything

```bash
pnpm dev
```

The dev orchestrator (`scripts/dev.mjs`) selects free ports and prints them, typically:
- Web: `http://127.0.0.1:3001`
- API: `http://127.0.0.1:4001/api`

If you want a faster restart without wiping Next cache:

```bash
pnpm dev:fast
```

---

## Health / observability

### Health page (UI)
- `GET /health` — authenticated UI page with a live view of checks.

### Health API (BFF)
- `GET /api/health` — performs parallel checks against upstream API and local integrations.
  - If you are logged in, it forwards your `Authorization` header.
  - `401` is treated as “service reachable” (auth required), not a failure.

---

## Running with Docker (all-in-one)

This is useful for a quick demo environment.

```bash
cp .env.example .env
docker compose -f infra/docker-compose.full.yml up --build
```

Services:
- Web: `http://localhost:3000`
- API: `http://localhost:4000/api`

---

## Hardware requirements (rule-of-thumb)

These are pragmatic starting points. Your real needs depend on ingest cadence, CVE backlog size, and LLM setup.

### Dev / single-user demo (laptop)
- **CPU**: 4–8 cores
- **RAM**: 8–16 GB (16 GB recommended if running Docker + Next + Nest workers)
- **Disk**: 10–30 GB free (Postgres volume grows with CVE history; lockfile/node_modules also large)
- **Network**: outbound access to NVD/CISA/EPSS/Telegram if you want live feeds

### Small team / continuous ingest (single VM)
- **CPU**: 8–16 cores
- **RAM**: 16–32 GB
- **Disk**: 50–200+ GB depending on retention / indexing
- **DB**: use managed Postgres if possible

### AI enrichment (Ollama on LAN / GPU)
- If using **Ollama**: a GPU box is recommended.
- Control concurrency via `LLM_MAX_PARALLEL` and queue prefetch via `AI_ENRICH_PREFETCH`.

---

## Common troubleshooting

### “Dev already running … .dev.lock”
`scripts/dev.mjs` writes `.dev.lock`. If your last run crashed and left a stale pid, stop it or delete the lock:

```bash
rm -f .dev.lock
```

### RabbitMQ `PRECONDITION_FAILED` on `ai.enrich`
Queue parameters may have changed (e.g., priority). Delete the queue in RabbitMQ UI and restart the apps.

### ФСТЭК feed errors
By default it parses Telegram HTML:
- Source: `https://t.me/s/<channel>`
- Configure channel via `FSTEC_TG_CHANNEL`

If your network blocks Telegram, switch to RSS mode:
- `FSTEC_FEED_SOURCE=rss`
- `FSTEC_TG_RSS_URL=...` (ideally your own RSSHub instance)

### EPSS/KEV/NVD not updating
Check `stats/summary` freshness watermarks and make sure outbound network is available.

---

## Security notes

- Do **not** commit `.env` (repo ignores it).
- If you accidentally posted a token anywhere, **revoke it immediately**.
- For production, set a strong `JWT_SECRET` and disable any dev-only registration flow.

