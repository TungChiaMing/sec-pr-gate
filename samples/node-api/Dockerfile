# Intentionally misconfigured: ':latest' tag (DS-0001) and no USER (DS-0002) -> Trivy misconfig scanner
FROM node:latest
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js .
EXPOSE 3000
CMD ["node", "server.js"]
