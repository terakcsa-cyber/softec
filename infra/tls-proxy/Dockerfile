FROM caddy:2.8-alpine

RUN apk add --no-cache openssl

COPY Caddyfile /etc/caddy/Caddyfile
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 443 2019
VOLUME ["/certs"]

ENTRYPOINT ["/entrypoint.sh"]
