FROM node:20-alpine AS deps
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable && corepack prepare pnpm@10.0.0 --activate
WORKDIR /repo
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json ./
COPY apps/api/package.json apps/api/package.json
COPY apps/ai/package.json apps/ai/package.json
COPY apps/ingest/package.json apps/ingest/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/shared/package.json packages/shared/package.json
RUN pnpm install --frozen-lockfile

FROM deps AS build
COPY . .
RUN pnpm --filter @vuln-intel/shared build && pnpm --filter @vuln-intel/api build

FROM node:20-alpine AS runtime
ARG PLATFORM_GIT_SHA=
ARG PLATFORM_GIT_BRANCH=
ARG PLATFORM_GIT_TAG=
ENV NODE_ENV=production
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
ENV PLATFORM_GIT_SHA=$PLATFORM_GIT_SHA
ENV PLATFORM_GIT_BRANCH=$PLATFORM_GIT_BRANCH
ENV PLATFORM_GIT_TAG=$PLATFORM_GIT_TAG
RUN apk add --no-cache openssl git docker-cli py3-pip \
  && pip3 install --no-cache-dir --break-system-packages 'certbot>=5.4' \
  && corepack enable && corepack prepare pnpm@10.0.0 --activate
WORKDIR /repo
COPY --from=build /repo/package.json /repo/pnpm-lock.yaml /repo/pnpm-workspace.yaml ./
COPY --from=build /repo/node_modules ./node_modules
COPY --from=build /repo/packages/shared ./packages/shared
COPY --from=build /repo/apps/api ./apps/api
COPY --from=build /repo/infra/postgres/migrations ./infra/postgres/migrations
EXPOSE 4001
CMD ["pnpm", "--filter", "@vuln-intel/api", "start"]

