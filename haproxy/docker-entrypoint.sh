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

# Function to generate peers configuration
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
    # if [ -f "$CONFIG_TEMPLATE" ]; then
    #     cp --force "$CONFIG_TEMPLATE" "$CONFIG_FILE"
    # fi

    local local_peer=$(get_local_peer_name)

    # Replace placeholder with actual peer name
    sed -i "s/LOCAL_PEER_PLACEHOLDER/${local_peer}/g" "$CONFIG_FILE"

    # In Kubernetes StatefulSet mode, rebuild peers section
    if [ "${KUBERNETES_MODE:-false}" = "true" ]; then
        # Generate new peers config
        peers_config=$(generate_peers_config)

        # Replace peers section in config
        # This is a simplified approach - in production, use confd or similar
        sed -i '/^peers haproxy_peers/,/^[^[:space:]]/{/^peers/!{/^[^[:space:]]/!d}}' "$CONFIG_FILE"
        sed -i '/^peers haproxy_peers/d' "$CONFIG_FILE"

        # Insert new peers config after global section
        echo "$peers_config" | sed -i '/^defaults/r /dev/stdin' "$CONFIG_FILE"
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
