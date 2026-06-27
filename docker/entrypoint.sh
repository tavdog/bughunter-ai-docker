#!/bin/bash
set -e

# Generate self-signed SSL cert
if [ ! -f /etc/ssl/certs/bughunter.crt ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/bughunter.key \
        -out /etc/ssl/certs/bughunter.crt \
        -subj "/C=US/ST=State/L=City/O=BugHunter/CN=localhost"
    echo "SSL certificate generated"
fi

# Optional: set up basic auth
if [ -n "$BUGHUNTER_USER" ] && [ -n "$BUGHUNTER_PASS" ]; then
    htpasswd -cb /etc/apache2/.htpasswd "$BUGHUNTER_USER" "$BUGHUNTER_PASS"
    export APACHE_ARGUMENTS="-D AUTH_ENABLED"
    echo "Basic auth enabled (user: $BUGHUNTER_USER)"
fi

# Start Apache
echo "Starting Apache..."
apache2ctl -D FOREGROUND &

# Wait for Apache to be ready
sleep 2

# Ensure data directory exists
mkdir -p /data

# Start Node.js server
echo "Starting BugHunter AI..."
cd /var/www/bughunter.clodhost.com
exec node server.js
