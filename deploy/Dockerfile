# ASI image (architecture §10): web build → Go build → runtime with nmap,
# httpx and nuclei (pinned releases) and nuclei-templates (pinned tag, baked in).
# Build from the repo root: docker compose build asi

# ── 1. web ──
FROM node:22-alpine3.24 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ── 2. go ──
FROM golang:1.27.4-alpine3.24 AS go
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY signatures/ signatures/
COPY web/embed.go web/
COPY --from=web /src/web/dist web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/asi ./cmd/asi

# ── 3. httpx + nuclei + templates ──
FROM alpine:3.24.4 AS scanners
ARG TARGETARCH=amd64
ARG HTTPX_VERSION=1.12.0
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_TEMPLATES_VERSION=v10.5.2
RUN apk add --no-cache curl unzip
WORKDIR /tmp/n
RUN curl -fsSLO "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${TARGETARCH}.zip" \
 && curl -fsSLO "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_checksums.txt" \
 && grep " httpx_${HTTPX_VERSION}_linux_${TARGETARCH}.zip\$" "httpx_${HTTPX_VERSION}_checksums.txt" | sha256sum -c - \
 && unzip -o "httpx_${HTTPX_VERSION}_linux_${TARGETARCH}.zip" httpx \
 && install -m 0755 httpx /usr/local/bin/httpx
RUN curl -fsSLO "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
 && curl -fsSLO "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_checksums.txt" \
 && grep " nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip\$" "nuclei_${NUCLEI_VERSION}_checksums.txt" | sha256sum -c - \
 && unzip -o "nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" nuclei \
 && install -m 0755 nuclei /usr/local/bin/nuclei
RUN mkdir -p /opt/nuclei-templates \
 && curl -fsSL "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${NUCLEI_TEMPLATES_VERSION}.tar.gz" \
    | tar -xz -C /opt/nuclei-templates --strip-components=1

# ── 4. runtime ──
FROM alpine:3.24.4
RUN apk add --no-cache ca-certificates tzdata nmap nmap-scripts
COPY --from=scanners /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=scanners /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=scanners /opt/nuclei-templates /opt/nuclei-templates
COPY --from=go /out/asi /usr/local/bin/asi
# Templates are baked into the image; nuclei must never update itself or the
# templates at runtime (the scanner also passes -duc / -disable-update-check).
ENV ASI_NUCLEI_TEMPLATES=/opt/nuclei-templates \
    DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true \
    HOME=/var/lib/asi
RUN mkdir -p /var/lib/asi
WORKDIR /var/lib/asi
# Runs as root inside the container: nmap -sS needs raw sockets (cap NET_RAW/NET_ADMIN in compose.yml).
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/asi"]
