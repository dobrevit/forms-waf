FROM openresty/openresty:1.27.1.2-alpine
USER root
# Install additional Lua modules and dependencies
RUN apk add --no-cache curl perl

# Install lua-resty-http for CAPTCHA provider verification
RUN opm get ledgetech/lua-resty-http

# Copy configuration
COPY conf/nginx.conf /etc/nginx/nginx.conf
COPY lua/ /etc/nginx/lua/

# Create log directory
RUN mkdir -p /var/log/nginx && \
    ln -s /dev/stdout /var/log/nginx/access.log && \
    ln -s /dev/stderr /var/log/nginx/error.log

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

EXPOSE 8080 8081

CMD ["/usr/local/openresty/bin/openresty", "-c", "/usr/local/openresty/nginx/conf/nginx.conf", "-g", "daemon off;"]
