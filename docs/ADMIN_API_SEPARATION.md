# Admin API Separation - Options Analysis

> **Implementation Status: Complete** - Option 1 (Dedicated Admin Port on 8082) has been implemented. This document is retained as historical design documentation. See [ARCHITECTURE.md](ARCHITECTURE.md) for the current system architecture.

## Current State (Historical)

The WAF admin API is currently exposed on the **same server block as production traffic** (port 8080), protected only by IP-based access control:

```nginx
# Current: nginx.conf (port 8080)
server {
    listen 8080;

    location / {
        # Production WAF traffic
    }

    location /waf-admin/ {
        allow 127.0.0.1;
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
        # Admin API handler
    }
}
```

### Current Port Layout

| Port | Purpose | Exposed |
|------|---------|---------|
| 8080 | WAF traffic + Admin API | External |
| 8081 | Health checks + Metrics | Internal |

### Problems with Current Approach

1. **Security Risk**: Admin API shares port with production traffic
2. **Network Policy Complexity**: Cannot easily block admin at network level
3. **Accidental Exposure**: Misconfigured proxy could expose `/waf-admin/`
4. **Audit Difficulty**: Admin and traffic logs intermingled
5. **Rate Limiting Conflict**: Production rate limits apply to admin calls

---

## Options Analysis

### Option 1: Dedicated Admin Port (Recommended)

Add a third server block on a dedicated port (e.g., 8082) exclusively for admin API.

```nginx
# Port 8080 - Production WAF traffic only
server {
    listen 8080;
    server_name _;

    location / {
        # WAF processing + proxy to HAProxy
    }

    # No /waf-admin/ here
}

# Port 8081 - Health/Metrics (unchanged)
server {
    listen 8081;
    # Health checks and Prometheus metrics
}

# Port 8082 - Admin API only (NEW)
server {
    listen 8082;
    server_name _;

    # Optional: Bind to localhost only for extra security
    # listen 127.0.0.1:8082;

    location / {
        return 404;
    }

    location /waf-admin/ {
        content_by_lua_block {
            local admin = require "admin_api"
            admin.handle_request()
        }
    }

    # Can add authentication here
    location = /waf-admin/auth {
        # API key validation endpoint
    }
}
```

**Pros:**
- Clean separation of concerns
- Easy to apply network policies (block 8082 from external)
- Separate access logs for auditing
- Can bind to localhost only if needed
- No risk of accidental exposure through path confusion
- Independent rate limiting possible

**Cons:**
- Additional port to manage
- Slightly more complex configuration
- Need to update Kubernetes services/Docker ports

**Kubernetes Service Changes:**
```yaml
# Separate service for admin (optional - or add port to existing service)
apiVersion: v1
kind: Service
metadata:
  name: forms-waf-openresty-admin
spec:
  type: ClusterIP  # Internal only
  ports:
    - port: 8082
      targetPort: admin
      name: admin
  selector:
    app: openresty
```

**Docker Compose Changes:**
```yaml
openresty:
  ports:
    - "8080:8080"      # WAF traffic
    - "8081:8081"      # Health/metrics
    # Admin port NOT exposed externally by default
    # - "8082:8082"    # Uncomment for local development only
```

---

### Option 2: Merge Admin with Metrics Port (8081)

Move admin API to the existing internal port (8081) alongside health/metrics.

```nginx
# Port 8081 - Internal services (health, metrics, admin)
server {
    listen 8081;

    location /health {
        return 200 "OK\n";
    }

    location /metrics {
        content_by_lua_block {
            local metrics = require "metrics"
            ngx.say(metrics.get_prometheus())
        }
    }

    location /waf-admin/ {
        content_by_lua_block {
            local admin = require "admin_api"
            admin.handle_request()
        }
    }
}
```

**Pros:**
- No new ports required
- Already an "internal" port in most setups
- Simple change

**Cons:**
- Mixes operational (health/metrics) with management (admin)
- Prometheus scraping could accidentally hit admin endpoints
- Health checks and admin share fate (if admin crashes health check, pod restarts)
- Harder to apply different access policies

---

### Option 3: Unix Socket for Admin

Expose admin API only via Unix socket, not TCP.

```nginx
# Unix socket for admin (local access only)
server {
    listen unix:/var/run/waf-admin.sock;

    location /waf-admin/ {
        content_by_lua_block {
            local admin = require "admin_api"
            admin.handle_request()
        }
    }
}
```

**Access via kubectl exec or docker exec:**
```bash
# Kubernetes
kubectl exec -it openresty-pod -- curl --unix-socket /var/run/waf-admin.sock http://localhost/waf-admin/status

# Docker
docker exec waf-openresty curl --unix-socket /var/run/waf-admin.sock http://localhost/waf-admin/status
```

**Pros:**
- Maximum security - no network exposure at all
- Cannot be accessed remotely without shell access
- Zero attack surface from network

**Cons:**
- Requires shell access for every admin operation
- Cannot use standard HTTP tools without proxy
- Harder to integrate with CI/CD, monitoring dashboards
- No remote management capability
- Complex setup for Kubernetes (need sidecar or shared volume)

---

### Option 4: Sidecar Container for Admin

Run admin API in a separate container, communicating with main OpenResty via shared memory or Redis.

```yaml
# Kubernetes pod with sidecar
spec:
  containers:
    - name: openresty
      # Main WAF container - no admin API
      ports:
        - containerPort: 8080
        - containerPort: 8081

    - name: admin
      # Separate admin container
      image: openresty-admin:latest
      ports:
        - containerPort: 8082
      volumeMounts:
        - name: shared-lua
          mountPath: /etc/nginx/lua
```

**Pros:**
- Complete isolation
- Can have different resource limits
- Independent scaling (though usually not needed)
- Different security contexts possible

**Cons:**
- Significant complexity increase
- Shared state challenges (need Redis or shared dict workarounds)
- More container images to maintain
- Overkill for most deployments

---

### Option 5: API Gateway / Ingress Level Separation

Use Kubernetes Ingress or API Gateway to route admin traffic separately.

```yaml
# Ingress for admin (internal only)
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: waf-admin-internal
  annotations:
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8"
spec:
  ingressClassName: nginx-internal  # Internal ingress class
  rules:
    - host: waf-admin.internal
      http:
        paths:
          - path: /waf-admin
            pathType: Prefix
            backend:
              service:
                name: forms-waf-openresty
                port:
                  number: 8082
```

**Pros:**
- Centralized access control
- Can add authentication at ingress level
- Works with existing tooling (cert-manager, etc.)

**Cons:**
- Still need separate port in OpenResty
- Adds dependency on ingress controller
- More moving parts

---

## Recommendation

### Primary: Option 1 - Dedicated Admin Port

**Recommended port assignment:**

| Port | Purpose | Binding | Exposure |
|------|---------|---------|----------|
| 8080 | WAF Traffic | 0.0.0.0 | External (via LB/Ingress) |
| 8081 | Health + Metrics | 0.0.0.0 | Internal (Prometheus, k8s probes) |
| 8082 | Admin API | 0.0.0.0 or 127.0.0.1 | Internal only (never expose) |

### Implementation Summary

```
┌─────────────────────────────────────────────────────────────┐
│                      OpenResty Container                    │
├─────────────────────────────────────────────────────────────┤
│  Port 8080 (0.0.0.0)     │  Production WAF traffic         │
│  ──────────────────────  │  ─────────────────────────────  │
│  • WAF processing        │  • Exposed via LoadBalancer     │
│  • Proxy to HAProxy      │  • Public facing                │
├─────────────────────────────────────────────────────────────┤
│  Port 8081 (0.0.0.0)     │  Operational endpoints          │
│  ──────────────────────  │  ─────────────────────────────  │
│  • /health               │  • Kubernetes probes            │
│  • /metrics              │  • Prometheus scraping          │
├─────────────────────────────────────────────────────────────┤
│  Port 8082 (0.0.0.0)     │  Admin API (NEW)                │
│  ──────────────────────  │  ─────────────────────────────  │
│  • /waf-admin/*          │  • ClusterIP service only       │
│  • Optional auth         │  • Network policy restricted    │
│  • Audit logging         │  • Never exposed externally     │
└─────────────────────────────────────────────────────────────┘
```

### Security Layers (Defense in Depth)

1. **Network Level**: Kubernetes NetworkPolicy or Docker network isolation
2. **Service Level**: ClusterIP (not LoadBalancer/NodePort)
3. **Nginx Level**: Optional `listen 127.0.0.1:8082` for localhost-only
4. **Application Level**: API key authentication (future enhancement)
5. **Audit Level**: Separate access log for admin operations

---

## Implementation Checklist

### Files to Modify

| File | Changes |
|------|---------|
| `openresty/conf/nginx.conf` | Add server block for port 8082, remove `/waf-admin/` from 8080 |
| `docker-compose.yml` | Add port 8082 (comment out for production) |
| `helm/forms-waf/values.yaml` | Add `adminPort` configuration |
| `helm/forms-waf/templates/openresty-deployment.yaml` | Add containerPort 8082 |
| `helm/forms-waf/templates/openresty-service.yaml` | Add admin port (or create separate service) |
| `kd-templates/openresty-deployment.yaml` | Add containerPort 8082 |

### Optional Enhancements

| Enhancement | Priority | Effort |
|-------------|----------|--------|
| Separate Kubernetes Service for admin | Medium | Low |
| NetworkPolicy to restrict admin access | High | Low |
| API key authentication | High | Medium |
| Audit logging to separate file | Medium | Low |
| Rate limiting for admin API | Low | Low |

---

## Quick Implementation

### Minimal nginx.conf Change

```nginx
# Add this new server block
server {
    listen 8082;
    server_name _;

    access_log /var/log/nginx/admin-access.log json_combined;

    location / {
        return 404 '{"error": "Not found"}\n';
        default_type application/json;
    }

    location /waf-admin/ {
        content_by_lua_block {
            local admin = require "admin_api"
            admin.handle_request()
        }
    }
}
```

### Remove from Main Server (port 8080)

```nginx
# DELETE this entire block from the port 8080 server
# location /waf-admin/ {
#     allow 127.0.0.1;
#     ...
# }
```

---

## Alternative: Hybrid Approach

If you want to support both local development (easy access) and production (locked down), use environment variable:

```nginx
# In nginx.conf, using env variable
server {
    listen 8080;

    location / {
        # WAF traffic
    }

    # Only enable on main port if explicitly allowed (dev mode)
    # set_by_lua $admin_on_main 'return os.getenv("WAF_ADMIN_ON_MAIN_PORT") or "false"';
    # if ($admin_on_main = "true") {
    #     location /waf-admin/ { ... }
    # }
}

# Always available on dedicated port
server {
    listen 8082;
    location /waf-admin/ { ... }
}
```

However, this adds complexity. The cleaner approach is:
- **Development**: Expose port 8082 in docker-compose
- **Production**: Never expose port 8082 externally

---

## Conclusion

**Recommended approach**: Dedicated admin port (Option 1) with:
- Port 8082 for admin API
- Removed from main traffic port (8080)
- ClusterIP service in Kubernetes (internal only)
- Not exposed in Docker Compose by default

This provides clean separation with minimal complexity and follows security best practices for management interfaces.
