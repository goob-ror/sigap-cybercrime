# Build the static app, then serve it with nginx. The result is fully offline:
# the container makes no outbound connections and needs no backend.

# --- Build stage ---
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# --- Serve stage ---
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
# Build:  docker build -t sigap .
# Run:    docker run --rm -p 8080:80 sigap   ->  http://localhost:8080
