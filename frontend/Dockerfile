FROM node:22-bookworm-slim AS deps
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@11.22.0 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY frontend/package.json frontend/package.json
COPY typescript/agentguard/package.json typescript/agentguard/package.json
RUN pnpm install --frozen-lockfile

FROM deps AS builder
COPY . .
RUN pnpm --filter frontend build

FROM node:22-bookworm-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN groupadd --system --gid 10001 agentguard \
  && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin agentguard
COPY --from=builder --chown=agentguard:agentguard /app/frontend/.next/standalone ./
COPY --from=builder --chown=agentguard:agentguard /app/frontend/.next/static ./frontend/.next/static
COPY --from=builder --chown=agentguard:agentguard /app/frontend/public ./frontend/public
USER agentguard
EXPOSE 3000
STOPSIGNAL SIGTERM
CMD ["node", "frontend/server.js"]
