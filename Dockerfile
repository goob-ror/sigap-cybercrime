# Build the app and the offline kit, then serve them with SIGAP's small Node server.
# Without an API key the container makes no outbound connections. With one, only server/api.mjs does,
# and only after an operator allows it. The key is given when it starts, never at build time:
# .dockerignore keeps .env out of every layer.

# --- Build stage ---
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# The offline kit is built too and served at /unduh/sigap-kit.zip. It does not contain server/.
RUN npm run build:kit

# --- Serve stage ---
FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY server/api.mjs server/sigap-server.mjs ./server/
ENV NODE_ENV=production
ENV PORT=8080
USER node
EXPOSE 8080
CMD ["node", "server/sigap-server.mjs"]
# Build:  docker build -t sigap .
# Run:    docker run --rm -p 8080:8080 sigap                    fully offline
#         docker run --rm -p 8080:8080 --env-file .env sigap    with Google Safe Browsing
# Browsers disable hashing, and so importing, except over HTTPS or localhost: see docs/DEPLOYMENT.md.
