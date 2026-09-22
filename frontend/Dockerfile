FROM rust:1.89-bookworm AS cli-builder
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p agentguard

FROM node:22.19.0-bookworm-slim AS deps
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@11.22.0 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY frontend/package.json frontend/package.json
COPY typescript/agentguard/package.json typescript/agentguard/package.json
RUN pnpm install --frozen-lockfile

FROM deps AS builder
COPY . .
# The console's CLI-backed routes import the workspace SDK. Build it in the
# image so a clean Docker context never depends on a developer's dist/ folder.
RUN pnpm --filter agentguard build
RUN pnpm --filter frontend build

FROM node:22.19.0-bookworm-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN apt-get update \
  && apt-get upgrade --yes --no-install-recommends \
  && rm -rf /var/lib/apt/lists/* \
  && rm -rf /usr/local/lib/node_modules/npm \
    /usr/local/lib/node_modules/corepack \
    /opt/yarn-v1.22.22 \
  && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
    /usr/local/bin/yarn /usr/local/bin/yarnpkg /usr/local/bin/pnpm \
  && groupadd --system --gid 10001 agentguard \
  && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin agentguard
COPY --from=builder --chown=agentguard:agentguard /app/frontend/.next/standalone ./
COPY --from=builder --chown=agentguard:agentguard /app/frontend/.next/static ./frontend/.next/static
COPY --from=builder --chown=agentguard:agentguard /app/frontend/public ./frontend/public
COPY --from=cli-builder --chown=agentguard:agentguard /src/target/release/agentguard /usr/local/bin/agentguard
USER 10001:10001
ENV AGENTGUARD_BIN=/usr/local/bin/agentguard
EXPOSE 3000
STOPSIGNAL SIGTERM
CMD ["node", "frontend/server.js"]
