FROM openresty/openresty:1.27.1.2-alpine
USER root

# Install dependencies and Lua modules in a single layer:
# - curl: for health checks
# - perl: required by some OpenResty tools
# - openssl: for generating self-signed SSL certificates
# - libmaxminddb: MaxMind GeoIP2 database library
# - libmaxminddb-dev: headers for lua-resty-maxminddb
# - lua-resty-http: HTTP client for CAPTCHA verification and webhooks
# - lua-resty-maxminddb: MaxMind GeoIP2/GeoLite2 database reader
# - lua-resty-openidc: OpenID Connect relying party for SSO
# - lua-resty-jwt: JWT parsing and validation (dependency of openidc)
# - lua-resty-session: Session management (dependency of openidc)
# Note: LDAP support uses pure Lua implementation via cosocket (no external deps)
RUN apk add --no-cache curl perl openssl libmaxminddb libmaxminddb-dev && \
    opm get ledgetech/lua-resty-http && \
    opm get anjia0532/lua-resty-maxminddb && \
    opm get zmartzone/lua-resty-openidc && \
    mkdir -p /usr/share/GeoIP /var/log/nginx /etc/nginx/ssl \
             /usr/local/openresty/nginx/client_body_temp \
             /usr/local/openresty/nginx/proxy_temp \
             /usr/local/openresty/nginx/fastcgi_temp \
             /usr/local/openresty/nginx/uwsgi_temp \
             /usr/local/openresty/nginx/scgi_temp \
             /var/run && \
    ln -s /dev/stdout /var/log/nginx/access.log && \
    ln -s /dev/stderr /var/log/nginx/error.log && \
    chown -R nobody:nobody /etc/nginx/ssl /var/log/nginx \
           /usr/local/openresty/nginx/client_body_temp \
           /usr/local/openresty/nginx/proxy_temp \
           /usr/local/openresty/nginx/fastcgi_temp \
           /usr/local/openresty/nginx/uwsgi_temp \
           /usr/local/openresty/nginx/scgi_temp \
           /var/run

# Copy configuration
COPY conf/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /etc/nginx/lua/

# Copy entrypoint script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

# Run as non-root user (nobody = 65534 on Alpine)
USER nobody

EXPOSE 8080 8081 8082 8443

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/local/openresty/bin/openresty", "-c", "/usr/local/openresty/nginx/conf/nginx.conf", "-g", "daemon off;"]
