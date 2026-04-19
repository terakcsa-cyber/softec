# Vuln Intel Platform (next-gen)

Production-grade vulnerability intelligence platform with AI context engine, event-driven ingestion, and attack-path visualization.

## Monorepo layout

- `apps/api`: Public API (NestJS)
- `apps/ai`: AI enrichment + risk scoring workers (NestJS)
- `apps/web`: Next.js frontend (dark-mode first)
- `packages/shared`: Shared types/schemas/utilities
- `infra`: Local dev infrastructure (docker-compose, init scripts)

## Local development (first run)

1. Install Node.js 20+.
2. Start infra:

```bash
docker compose -f infra/docker-compose.yml up -d
```

3. Install deps and run:

```bash
npm install
npm run dev
```

## Run everything with Docker

```bash
cp .env.example .env
docker compose -f infra/docker-compose.full.yml up --build
```

## Notes

- This repo is a starting point with production-minded structure: queues, idempotency hooks, audit logging scaffolding, rate limiting, and an AI service boundary.

