# TLS reverse proxy (Caddy)

Terminates HTTPS for the `web` service using certificates from the shared `tls_certs` volume.
Also serves Let's Encrypt HTTP-01 challenges from the shared ACME webroot on port 80.

## Paths

| File / path | Purpose |
|------|---------|
| `/certs/cert.pem` | Public certificate / fullchain (PEM) |
| `/certs/key.pem` | Private key (PEM, mode 600) |
| `/var/www/certbot/.well-known/acme-challenge/` | ACME HTTP-01 tokens (written by API/certbot) |

Certificates are issued or generated from **Settings → Веб / TLS** (admin-only): Let's Encrypt via certbot, or self-signed for labs. The entrypoint bootstraps a short-lived placeholder if files are missing, then polls for changes and runs `caddy reload`.

## Ports

| Port | Use |
|------|-----|
| 443 | HTTPS → `web:3000` |
| 80 | `/.well-known/acme-challenge/` from webroot, else redirect to HTTPS |
| 2019 | Caddy admin API (Docker network only; not published) |

## Compose

Enabled in `docker-compose.prod.yml` and `docker-compose.staging.yml` via `WEB_TLS_PUBLISHED_PORT` (default `443` / `8443`).
Shared volumes: `tls_certs` + `acme_webroot` (prod) or `tls_staging_certs` + `acme_staging_webroot` (staging).
