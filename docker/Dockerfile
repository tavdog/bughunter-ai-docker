FROM ubuntu:24.04

ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive

# --- Layer 1: System packages (rarely changes) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    curl \
    unzip \
    ca-certificates \
    python3 \
    python3-pip \
    sqlmap \
    ffuf \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# --- Layer 2: Node.js ---
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# --- Layer 3: Go ---
RUN curl -fsSL "https://go.dev/dl/go1.23.5.linux-${TARGETARCH}.tar.gz" -o /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH=/root/go

# --- Layer 4: Security tools (rarely changes) ---
RUN mkdir -p /tmp/tools && \
    TOOL_VERSIONS="subfinder:2.14.0 httpx:1.9.0 nuclei:3.9.0 naabu:2.6.1" && \
    for entry in $TOOL_VERSIONS; do \
        tool="${entry%%:*}"; \
        version="${entry##*:}"; \
        url="https://github.com/projectdiscovery/${tool}/releases/download/v${version}/${tool}_${version}_linux_${TARGETARCH}.zip"; \
        echo "Downloading $tool v${version} for linux/${TARGETARCH}..."; \
        if curl -fsSL "$url" -o "/tmp/tools/${tool}.zip"; then \
            unzip -o "/tmp/tools/${tool}.zip" -d /usr/local/bin/ && \
            chmod +x "/usr/local/bin/${tool}" && \
            echo "  -> installed"; \
        else \
            echo "  -> download failed, will install via go"; \
            GOOS=linux GOARCH=${TARGETARCH} go install "github.com/projectdiscovery/${tool}/v2/cmd/${tool}@latest" 2>/dev/null || \
            GOOS=linux GOARCH=${TARGETARCH} go install "github.com/projectdiscovery/${tool}/cmd/${tool}@latest" 2>/dev/null || \
            echo "  -> go install also failed for $tool"; \
        fi; \
    done && \
    rm -rf /tmp/tools

# --- Layer 5: Claude Code ---
RUN npm install -g @anthropic-ai/claude-code 2>&1 || echo "Claude Code not installed"

# --- Layer 6: App dirs + Apache modules (cached after first build) ---
WORKDIR /var/www/bughunter.clodhost.com
RUN mkdir -p /data /var/www/bughunter.clodhost.com/public/reports && \
    chown -R www-data:www-data /var/www/bughunter.clodhost.com/public
RUN a2enmod ssl headers proxy proxy_http proxy_wstunnel rewrite

# --- Layer 7: App dependencies (cached unless package.json changes) ---
COPY package.json ./
RUN npm install --omit=dev 2>&1 || npm install 2>&1

# --- Layer 8: Application source (changes frequently) ---
COPY db.js server.js ./
COPY public/ ./public/
COPY skills/ ./skills/

# --- Layer 9: Apache config + entrypoint ---
COPY docker/apache-site.conf /etc/apache2/sites-available/bughunter.conf
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && \
    a2dissite 000-default.conf default-ssl.conf 2>/dev/null || true && \
    a2ensite bughunter.conf

EXPOSE 443
ENTRYPOINT ["/entrypoint.sh"]
