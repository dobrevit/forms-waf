FROM haproxy:2.8-alpine
USER root
# Install additional tools
RUN apk add --no-cache curl bind-tools bash

# Copy configuration
COPY --chown=haproxy:root haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg
COPY --chown=haproxy:root haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg.tmpl
COPY --chown=haproxy:root docker-entrypoint.sh /docker-entrypoint.sh

RUN chmod +x /docker-entrypoint.sh && \
    # Create socket directory
    mkdir -p /var/run /usr/local/etc/haproxy && \
    chown -R haproxy:root /var/run /usr/local/etc/haproxy

USER haproxy

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8405/health || exit 1

# Expose ports
# 8080 - Main HTTP traffic
# 8404 - Stats/metrics
# 8405 - Health check
# 10000 - Peer synchronization
EXPOSE 8080 8404 8405 10000

ENTRYPOINT ["/docker-entrypoint.sh"]
