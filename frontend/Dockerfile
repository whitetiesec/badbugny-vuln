# syntax=docker/dockerfile:1
FROM node:18-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install --legacy-peer-deps --no-audit --no-fund
COPY . .
RUN npm run build

FROM node:18-alpine
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/vite.config.js ./
COPY --from=build /app/package.json ./
EXPOSE 3000
# vite preview keeps the /api → backend proxy from vite.config.js so the
# browser never has to think about CORS. (The CORS misconfig is still
# exploitable by hitting :8080 directly.)
CMD ["npx", "vite", "preview", "--host", "0.0.0.0", "--port", "3000"]
