#!/bin/sh
set -e

SSL_DIR="/etc/nginx/ssl"
SSL_CERT="$SSL_DIR/server.crt"
SSL_KEY="$SSL_DIR/server.key"

# Generate self-signed certificate if it doesn't exist
# Users can mount their own certificates to override
if [ ! -f "$SSL_CERT" ] || [ ! -f "$SSL_KEY" ]; then
    echo "Generating self-signed SSL certificate..."

    # Get hostname for certificate CN, default to 'localhost'
    SSL_CN="${SSL_COMMON_NAME:-localhost}"
    SSL_ORG="${SSL_ORGANIZATION:-Forms WAF}"
    SSL_DAYS="${SSL_VALIDITY_DAYS:-365}"

    # Generate certificate with SAN (Subject Alternative Name) for modern browsers
    openssl req -x509 -nodes -days "$SSL_DAYS" -newkey rsa:2048 \
        -keyout "$SSL_KEY" \
        -out "$SSL_CERT" \
        -subj "/C=US/ST=State/L=City/O=$SSL_ORG/CN=$SSL_CN" \
        -addext "subjectAltName=DNS:$SSL_CN,DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

    chmod 600 "$SSL_KEY"
    chmod 644 "$SSL_CERT"

    echo "Self-signed SSL certificate generated:"
    echo "  Certificate: $SSL_CERT"
    echo "  Key: $SSL_KEY"
    echo "  CN: $SSL_CN"
    echo "  Valid for: $SSL_DAYS days"
    echo ""
    echo "To use your own certificate, mount files to:"
    echo "  - $SSL_CERT"
    echo "  - $SSL_KEY"
else
    echo "Using existing SSL certificate from $SSL_DIR"
fi

# Execute the main command
exec "$@"
