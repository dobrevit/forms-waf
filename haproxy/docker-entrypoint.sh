#!/bin/sh
set -e

# Use /tmp for writable config when running in Kubernetes with ConfigMap
CONFIG_SOURCE="/usr/local/etc/haproxy/haproxy.cfg"
CONFIG_FILE="/tmp/haproxy.cfg"
CONFIG_TEMPLATE="/usr/local/etc/haproxy/haproxy.cfg.tmpl"

# Copy config to writable location
cp "$CONFIG_SOURCE" "$CONFIG_FILE"

# Function to get the local hostname/pod name
get_local_peer_name() {
    if [ -n "$HOSTNAME" ]; then
        echo "$HOSTNAME"
    else
        hostname
    fi
}

# Function to generate peers configuration (used in Docker Compose mode only)
generate_peers_config() {
    local local_peer=$(get_local_peer_name)
    local peer_port=${HAPROXY_PEER_PORT:-10000}
    local headless_svc=${HAPROXY_HEADLESS_SERVICE:-haproxy-headless}
    local replica_count=${HAPROXY_REPLICAS:-1}

    echo "peers haproxy_peers"

    # Generate peer entries for StatefulSet
    for i in $(seq 0 $((replica_count - 1))); do
        peer_name="haproxy-${i}"
        if [ "$peer_name" = "$local_peer" ]; then
            # Local peer binds to all interfaces
            echo "    peer ${peer_name} 0.0.0.0:${peer_port}"
        else
            # Remote peers use headless service DNS
            echo "    peer ${peer_name} ${peer_name}.${headless_svc}:${peer_port}"
        fi
    done
}

# Function to update local peer binding in Kubernetes mode
# Helm generates the correct peers section with full pod names,
# but each pod needs to bind its own peer entry to 0.0.0.0
update_local_peer_binding() {
    local local_peer=$(get_local_peer_name)
    local peer_port=${HAPROXY_PEER_PORT:-10000}

    # Find the peer line matching local hostname and replace its address with 0.0.0.0
    # This allows the local peer to bind to all interfaces while keeping the correct peer name
    # Pattern: "    peer <local_peer> <anything>:<port>" -> "    peer <local_peer> 0.0.0.0:<port>"
    if grep -q "peer ${local_peer} " "$CONFIG_FILE"; then
        sed -i "s|^\([[:space:]]*peer ${local_peer}\) [^:]*:${peer_port}|\1 0.0.0.0:${peer_port}|" "$CONFIG_FILE"
        echo "Updated local peer ${local_peer} to bind on 0.0.0.0:${peer_port}"
    else
        echo "Warning: Local peer ${local_peer} not found in config"
    fi
}

# Function to configure backend servers
configure_backends() {
    local backend_host=${BACKEND_HOST:-backend}
    local backend_port=${BACKEND_PORT:-8080}

    # For Kubernetes, this might be a service name
    # For docker-compose, this might be a container name
    echo "    server app1 ${backend_host}:${backend_port} check inter 5s fall 3 rise 2"
}

# Process configuration template
process_config() {
    local local_peer=$(get_local_peer_name)

    # Replace placeholder with actual peer name (for Docker Compose mode)
    sed -i "s/LOCAL_PEER_PLACEHOLDER/${local_peer}/g" "$CONFIG_FILE"

    # In Kubernetes StatefulSet mode, update local peer binding
    # Helm already generates the correct peers section with full pod names (e.g., forms-waf-haproxy-0)
    # We just need to update the local peer's address to 0.0.0.0 so it can bind properly
    if [ "${KUBERNETES_MODE:-false}" = "true" ]; then
        update_local_peer_binding
    fi

    # Replace backend placeholder if set
    if [ -n "$BACKEND_HOST" ]; then
        sed -i "s/backend:8080/${BACKEND_HOST}:${BACKEND_PORT:-8080}/g" "$CONFIG_FILE"
    fi
}

# Validate configuration
validate_config() {
    echo "Validating HAProxy configuration..."
    haproxy -c -f "$CONFIG_FILE"
}

# Main
echo "HAProxy Forms WAF starting..."
echo "Local peer name: $(get_local_peer_name)"

# Process configuration
process_config

# Validate
validate_config

# Start HAProxy
echo "Starting HAProxy..."
exec haproxy -f "$CONFIG_FILE" "$@"
