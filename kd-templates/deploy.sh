#!/bin/bash
# kd deployment script for Forms WAF
# Usage: ./deploy.sh [environment-file]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${1:-$SCRIPT_DIR/env.default}"

# Load environment variables
if [ -f "$ENV_FILE" ]; then
    echo "Loading environment from: $ENV_FILE"
    set -a
    source "$ENV_FILE"
    set +a
else
    echo "Warning: Environment file not found: $ENV_FILE"
    echo "Using default values..."
fi

# Default values
export NAMESPACE="${NAMESPACE:-forms-waf}"
export RELEASE_NAME="${RELEASE_NAME:-forms-waf}"
export OPENRESTY_IMAGE="${OPENRESTY_IMAGE:-forms-waf/openresty}"
export OPENRESTY_TAG="${OPENRESTY_TAG:-latest}"
export HAPROXY_IMAGE="${HAPROXY_IMAGE:-forms-waf/haproxy}"
export HAPROXY_TAG="${HAPROXY_TAG:-latest}"
export OPENRESTY_REPLICAS="${OPENRESTY_REPLICAS:-2}"
export HAPROXY_REPLICAS="${HAPROXY_REPLICAS:-3}"
export REDIS_HOST="${REDIS_HOST:-${RELEASE_NAME}-redis}"
export BACKEND_HOST="${BACKEND_HOST:-${RELEASE_NAME}-backend}"

echo "=== Forms WAF Deployment ==="
echo "Namespace: $NAMESPACE"
echo "Release Name: $RELEASE_NAME"
echo "OpenResty Image: $OPENRESTY_IMAGE:$OPENRESTY_TAG"
echo "HAProxy Image: $HAPROXY_IMAGE:$HAPROXY_TAG"
echo ""

# Function to apply templates with variable substitution
apply_template() {
    local template="$1"
    echo "Applying: $template"
    envsubst < "$template" | kubectl apply -f -
}

# Create namespace
apply_template "$SCRIPT_DIR/namespace.yaml"

# Apply configurations
apply_template "$SCRIPT_DIR/openresty-configmap.yaml"
apply_template "$SCRIPT_DIR/haproxy-configmap.yaml"

# Deploy Redis
apply_template "$SCRIPT_DIR/redis.yaml"

# Wait for Redis
echo "Waiting for Redis to be ready..."
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=redis -n "$NAMESPACE" --timeout=120s

# Initialize Redis
apply_template "$SCRIPT_DIR/redis-init-job.yaml"

# Deploy OpenResty
apply_template "$SCRIPT_DIR/openresty-deployment.yaml"

# Deploy HAProxy StatefulSet
apply_template "$SCRIPT_DIR/haproxy-statefulset.yaml"

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Wait for all pods to be ready:"
echo "  kubectl get pods -n $NAMESPACE -w"
echo ""
echo "Test the WAF:"
echo "  kubectl port-forward svc/${RELEASE_NAME}-openresty -n $NAMESPACE 8080:8080"
echo "  curl -X POST http://localhost:8080/submit -d 'name=test&message=hello'"
