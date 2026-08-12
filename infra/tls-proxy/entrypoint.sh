#!/bin/sh
set -eu

CERT_DIR="${TLS_CERTS_DIR:-/certs}"
CADDYFILE="${CADDYFILE_PATH:-/etc/caddy/Caddyfile}"
ACME_ROOT="${TLS_ACME_WEBROOT:-/var/www/certbot}"

mkdir -p "$CERT_DIR"
mkdir -p "$ACME_ROOT/.well-known/acme-challenge"

if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
  echo "[tls-proxy] bootstrap placeholder self-signed cert (replace via Settings → Веб / TLS)"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
    -keyout "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
  chmod 600 "$CERT_DIR/key.pem"
  chmod 644 "$CERT_DIR/cert.pem"
fi

caddy run --config "$CADDYFILE" --adapter caddyfile &
CADDY_PID=$!

mtime_of() {
  if [ -f "$1" ]; then
    stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

last_cert="$(mtime_of "$CERT_DIR/cert.pem")"
last_key="$(mtime_of "$CERT_DIR/key.pem")"

cleanup() {
  kill "$CADDY_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

while kill -0 "$CADDY_PID" 2>/dev/null; do
  sleep 2
  now_cert="$(mtime_of "$CERT_DIR/cert.pem")"
  now_key="$(mtime_of "$CERT_DIR/key.pem")"
  if [ "$now_cert" != "$last_cert" ] || [ "$now_key" != "$last_key" ]; then
    last_cert="$now_cert"
    last_key="$now_key"
    echo "[tls-proxy] cert files changed — reloading Caddy"
    caddy reload --config "$CADDYFILE" --adapter caddyfile || echo "[tls-proxy] reload failed (will retry on next change)"
  fi
done

wait "$CADDY_PID"
