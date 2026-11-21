# RAVEN image (architecture §10): web build → Go build → runtime with nmap,
# httpx, nuclei, wpscan and nikto (pinned releases) and nuclei-templates (pinned tag, baked in).
# Build from the repo root: docker compose build raven

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
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/raven ./cmd/raven

# ── 3. httpx + nuclei + templates ──
FROM alpine:3.24.4 AS scanners
ARG TARGETARCH=amd64
ARG HTTPX_VERSION=1.12.0
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_TEMPLATES_VERSION=v10.5.2
ARG NUCLEI_TEMPLATES_SHA256=016b7abbf931d4d1a851a5a568e44510dc61691dc8a5202e3b24e701515ec574
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
 && curl -fsSL "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${NUCLEI_TEMPLATES_VERSION}.tar.gz" -o nuclei-templates.tar.gz \
 && echo "${NUCLEI_TEMPLATES_SHA256}  nuclei-templates.tar.gz" | sha256sum -c - \
 && tar -xzf nuclei-templates.tar.gz -C /opt/nuclei-templates --strip-components=1 \
 && rm -f nuclei-templates.tar.gz

# ── 3b. wpscan (pinned gem + build-time metadata DB, offline at runtime) ──
FROM alpine:3.24.4 AS wpscan
ARG WPSCAN_VERSION=4.2.1
ARG WPSCAN_SHA256=ae2133545bb1b9fae78cc16b0326f6dc550ac69801e8d90b10242f2c475006a4
RUN apk add --no-cache ruby ruby-dev build-base libcurl curl-dev libffi-dev zlib-dev sqlite-dev curl
WORKDIR /tmp/wpscan
RUN curl -fsSLO "https://rubygems.org/gems/wpscan-${WPSCAN_VERSION}.gem" \
 && echo "${WPSCAN_SHA256}  wpscan-${WPSCAN_VERSION}.gem" | sha256sum -c - \
 && gem install --no-document --install-dir /opt/wpscan-gems --bindir /opt/wpscan-gems/bin "wpscan-${WPSCAN_VERSION}.gem" \
 && rm -rf /opt/wpscan-gems/cache /opt/wpscan-gems/doc \
 && find /opt/wpscan-gems/extensions -name '*.o' -o -name '*.c' -o -name 'mkmf.log' -o -name 'gem_make.out' | xargs -r rm -f
# Download the local WPScan metadata DB at build time (verified against upstream
# .sha512 by wpscan --update) and record its date + SHA-256 manifest. Runtime
# runs strictly with --no-update and no API token.
RUN mkdir -p /opt/wpscan-db /tmp/wpscan-home \
 && GEM_HOME=/opt/wpscan-gems GEM_PATH=/opt/wpscan-gems XDG_CACHE_HOME=/opt/wpscan-db HOME=/tmp/wpscan-home \
    /opt/wpscan-gems/bin/wpscan --update --verbose \
 && date -u +%Y-%m-%dT%H:%M:%SZ > /opt/wpscan-db/wpscan/db/DB_DATE \
 && (cd /opt/wpscan-db/wpscan/db && sha256sum metadata.json wp_fingerprints.json timthumbs-v3.txt config_backups.txt db_exports.txt backup_folders.txt dynamic_finders.yml LICENSE sponsor.txt > CHECKSUMS.sha256)

# ── 3c. nikto (pinned release, checksum-verified, offline config) ──
FROM alpine:3.24.4 AS nikto
ARG NIKTO_VERSION=2.6.1
ARG NIKTO_SHA256=d1ca1acb05d81a5a6f374c0afdd76b33afa0089278631a20673c0210a71d992f
RUN apk add --no-cache curl \
 && curl -fsSL -o /tmp/nikto.tar.gz "https://github.com/sullo/nikto/archive/refs/tags/${NIKTO_VERSION}.tar.gz" \
 && echo "${NIKTO_SHA256}  /tmp/nikto.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/nikto \
 && tar -xzf /tmp/nikto.tar.gz -C /tmp \
 && cp -a "/tmp/nikto-${NIKTO_VERSION}/program/." /opt/nikto/ \
 && cp /opt/nikto/nikto.conf.default /opt/nikto/nikto.conf \
 && sed -i \
    -e 's|^UPDATES=.*|UPDATES=no|' \
    -e 's|^#PROMPTS=.*|PROMPTS=no|' \
    -e 's|^CIRT=.*|CIRT=|' \
    -e 's|^VERSION_API=.*|VERSION_API=|' \
    -e 's|^CHECK6HOST=.*|CHECK6HOST=|' \
    -e 's|^# EXECDIR=.*|EXECDIR=/opt/nikto|' \
    -e 's|^@@EXTRAS=.*|@@EXTRAS=dictionary;siebel;auth;put_del_test;shellshock;ms10_070;apacheusers;optionsbleed|' \
    /opt/nikto/nikto.conf \
 && chmod 0755 /opt/nikto/nikto.pl \
 && rm -rf /tmp/nikto.tar.gz "/tmp/nikto-${NIKTO_VERSION}"

# ── 4. runtime ──
FROM alpine:3.24.4
RUN apk add --no-cache ca-certificates tzdata nmap nmap-scripts ruby libcurl sqlite-libs procps \
    perl perl-net-ssleay perl-io-socket-ssl perl-xml-writer
COPY --from=scanners /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=scanners /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=scanners /opt/nuclei-templates /opt/nuclei-templates
COPY --from=wpscan /opt/wpscan-gems /opt/wpscan-gems
COPY --from=wpscan /opt/wpscan-db /opt/wpscan-db
COPY --from=nikto /opt/nikto /opt/nikto
RUN ln -s /opt/nikto/nikto.pl /usr/local/bin/nikto
RUN printf '#!/bin/sh\nunset WPSCAN_API_TOKEN WPSCAN_ENTERPRISE_DB_TOKEN\nexport GEM_HOME=/opt/wpscan-gems\nexport GEM_PATH=/opt/wpscan-gems\nexec /opt/wpscan-gems/bin/wpscan "$@"\n' > /usr/local/bin/wpscan \
 && chmod 0755 /usr/local/bin/wpscan
COPY --from=go /out/raven /usr/local/bin/raven
# Templates and WPScan metadata DB are baked into the image; scanners must never
# update themselves or call external APIs at runtime.
ENV RAVEN_NUCLEI_TEMPLATES=/opt/nuclei-templates \
    RAVEN_WPSCAN_DB=/opt/wpscan-db \
    DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true \
    HOME=/var/lib/raven
RUN mkdir -p /var/lib/raven
WORKDIR /var/lib/raven
# Runs as root inside the container: nmap -sS needs raw sockets (cap NET_RAW/NET_ADMIN in compose.yml).
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/raven"]
