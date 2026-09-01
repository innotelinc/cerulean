# ── Build the dashboard ───────────────────────────────────────────────────
FROM node:24-alpine AS web-build
WORKDIR /app
COPY package.json package-lock.json* ./
COPY web/package.json web/package.json
RUN npm install --workspaces --include-workspace-root
COPY web web
RUN npm run build -w web

# ── Build the server ──────────────────────────────────────────────────────
FROM node:24-alpine AS server-build
WORKDIR /app
COPY package.json package-lock.json* ./
COPY server/package.json server/package.json
COPY web/package.json web/package.json
RUN npm install --workspaces --include-workspace-root --omit=dev
COPY server server
RUN npm run build -w server

# ── Runtime ───────────────────────────────────────────────────────────────
FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=server-build /app/node_modules node_modules
COPY --from=server-build /app/server/dist server/dist
COPY --from=server-build /app/server/package.json server/package.json
COPY --from=web-build /app/web/dist web/dist
EXPOSE 3000
CMD ["node", "server/dist/index.js"]
