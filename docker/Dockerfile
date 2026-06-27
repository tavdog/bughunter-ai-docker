FROM ubuntu:24.04

ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive

# Install system packages
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

# Install Node.js 22 (ARM64 + amd64)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.23
RUN curl -fsSL "https://go.dev/dl/go1.23.5.linux-${TARGETARCH}.tar.gz" -o /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH=/root/go

# Download pre-built security tool binaries for the target architecture
# All four ProjectDiscovery tools publish ARM64 + amd64 releases
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

# Install Claude Code CLI
RUN npm install -g @anthropic-ai/claude-code 2>&1 || echo "Claude Code not installed — mount binary or set API key at runtime"

# Set up app directory
WORKDIR /var/www/bughunter.clodhost.com

# Install Node.js app dependencies
COPY package.json ./
RUN npm install --omit=dev 2>&1 || npm install 2>&1

# Copy application code
COPY db.js server.js ./
COPY public/ ./public/
COPY skills/ ./skills/

# Create data and reports directories
RUN mkdir -p /data /var/www/bughunter.clodhost.com/public/reports && \
    chown -R www-data:www-data /var/www/bughunter.clodhost.com/public

# Configure Apache
RUN a2enmod ssl headers proxy proxy_http proxy_wstunnel rewrite

COPY apache-site.conf /etc/apache2/sites-available/bughunter.conf
RUN a2dissite 000-default.conf default-ssl.conf 2>/dev/null || true && \
    a2ensite bughunter.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 443

ENTRYPOINT ["/entrypoint.sh"]
