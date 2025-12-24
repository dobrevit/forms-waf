# API Handlers Architecture

This guide documents the modular API handler structure for the Forms WAF Admin API.

## Overview

The Admin API uses a modular handler architecture where each domain area is handled by a dedicated Lua module in `openresty/lua/api_handlers/`. This provides:

- **Separation of concerns** - Each handler manages one resource type
- **Maintainability** - Easy to add new endpoints without touching core code
- **Testability** - Handlers can be tested in isolation
- **RBAC integration** - Consistent permission checking across all handlers

## Handler Structure

Each handler module follows a consistent pattern:

```lua
-- api_handlers/example.lua
local _M = {}

local utils = require "api_handlers.utils"

_M.handlers = {}

-- GET /example - List all
_M.handlers["GET:/example"] = function()
    -- Implementation
    return utils.json_response({...})
end

-- POST /example - Create new
_M.handlers["POST:/example"] = function()
    local data, err = utils.get_json_body()
    if not data then
        return utils.error_response(err, 400)
    end
    -- Implementation
    return utils.json_response({...}, 201)
end

-- GET /example/{id} - Get one
_M.handlers["GET:/example/:id"] = function(id)
    -- Implementation
end

return _M
```

## Handler Index

| Handler | File | Endpoints | Resource Type |
|---------|------|-----------|---------------|
| system | system.lua | /status, /metrics, /sync, /learning/stats | System operations |
| users | users.lua | /users/* | User management |
| providers | providers.lua | /auth/providers/* | SSO provider configuration |
| config | config.lua | /config/* | Global configuration |
| vhosts | vhosts.lua | /vhosts/* | Virtual hosts |
| endpoints | endpoints.lua | /endpoints/* | Protected endpoints |
| defense_profiles | defense_profiles.lua | /defense-profiles/* | DAG-based defense profiles |
| attack_signatures | attack_signatures.lua | /attack-signatures/* | Attack signature patterns |
| keywords | keywords.lua | /keywords/* | Blocked/flagged keywords |
| hashes | hashes.lua | /hashes/* | Content hashes |
| whitelist | whitelist.lua | /whitelist/* | IP allowlist |
| timing | timing.lua | /timing/* | Form timing configuration |
| captcha | captcha.lua | /captcha/* | CAPTCHA providers/settings |
| behavioral | behavioral.lua | /behavioral/* | ML tracking |
| webhooks | webhooks.lua | /webhooks/* | Event notifications |
| geoip | geoip.lua | /geoip/* | Geographic restrictions |
| reputation | reputation.lua | /reputation/* | IP reputation |
| bulk | bulk.lua | /bulk/* | Import/export operations |
| cluster | cluster.lua | /cluster/* | Cluster status |
| utils | utils.lua | - | Shared utilities |

---

## Handler Details

### system.lua

System status and metrics.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /status | WAF status and configuration |
| GET | /metrics | Metrics summary (local + global) |
| POST | /metrics/reset | Reset all metrics (testing) |
| POST | /sync | Force Redis sync |
| GET | /learning/stats | Field learning statistics |

### users.lua

User management (admin role required).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /users | List all users |
| POST | /users | Create new user |
| GET | /users/:id | Get user details |
| PUT | /users/:id | Update user |
| DELETE | /users/:id | Delete user |
| POST | /users/:id/password | Reset password |

### providers.lua

SSO provider configuration.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /auth/providers | List configured providers |
| POST | /auth/providers | Add new provider |
| GET | /auth/providers/:type | Get provider config |
| PUT | /auth/providers/:type | Update provider |
| DELETE | /auth/providers/:type | Remove provider |

Provider types: `ldap`, `oidc`, `saml`

### config.lua

Global configuration management.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /config/thresholds | Get global thresholds |
| PUT | /config/thresholds | Update thresholds |
| GET | /config/routing | Get routing configuration |
| PUT | /config/routing | Update routing |

### vhosts.lua

Virtual host management.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /vhosts | List all vhosts |
| POST | /vhosts | Create vhost |
| GET | /vhosts/:id | Get vhost details |
| PUT | /vhosts/:id | Update vhost |
| DELETE | /vhosts/:id | Delete vhost |
| POST | /vhosts/:id/enable | Enable vhost |
| POST | /vhosts/:id/disable | Disable vhost |
| GET | /vhosts/:id/fields | Get learned fields |

### endpoints.lua

Endpoint configuration.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /endpoints | List all endpoints |
| POST | /endpoints | Create endpoint |
| GET | /endpoints/:id | Get endpoint details |
| PUT | /endpoints/:id | Update endpoint |
| DELETE | /endpoints/:id | Delete endpoint |
| POST | /endpoints/:id/enable | Enable endpoint |
| POST | /endpoints/:id/disable | Disable endpoint |
| GET | /endpoints/:id/fields | Get learned fields |

### keywords.lua

Keyword list management.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /keywords/blocked | List blocked keywords |
| POST | /keywords/blocked | Add blocked keywords |
| DELETE | /keywords/blocked | Remove blocked keywords |
| GET | /keywords/flagged | List flagged keywords |
| POST | /keywords/flagged | Add flagged keywords |
| PUT | /keywords/flagged | Update keyword score |
| DELETE | /keywords/flagged | Remove flagged keywords |

### hashes.lua

Content hash management.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /hashes/blocked | List blocked hashes |
| POST | /hashes/blocked | Add blocked hashes |
| DELETE | /hashes/blocked | Remove blocked hashes |

### whitelist.lua

IP allowlist management.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /whitelist/ips | List whitelisted IPs |
| POST | /whitelist/ips | Add IPs to whitelist |
| DELETE | /whitelist/ips | Remove IPs from whitelist |

Supports both exact IPs and CIDR notation.

### timing.lua

Form timing token configuration.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /timing/config | Get timing configuration |
| PUT | /timing/config | Update timing configuration |

### captcha.lua

CAPTCHA provider and settings management.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /captcha/providers | List CAPTCHA providers |
| POST | /captcha/providers | Add CAPTCHA provider |
| GET | /captcha/providers/:id | Get provider details |
| PUT | /captcha/providers/:id | Update provider |
| DELETE | /captcha/providers/:id | Delete provider |
| GET | /captcha/config | Get global CAPTCHA settings |
| PUT | /captcha/config | Update CAPTCHA settings |

Provider types: `recaptcha_v2`, `recaptcha_v3`, `hcaptcha`, `turnstile`

### behavioral.lua

Behavioral tracking and anomaly detection.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /behavioral/summary | Overview of all tracking |
| GET | /behavioral/stats | Historical statistics |
| GET | /behavioral/baseline | Get baseline data |
| POST | /behavioral/recalculate | Force baseline recalculation |
| GET | /behavioral/flows | List flows for vhost |
| GET | /behavioral/vhosts | List vhosts with tracking |

See [Behavioral Tracking Guide](BEHAVIORAL_TRACKING.md) for details.

### webhooks.lua

Webhook configuration.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /webhooks/config | Get webhook configuration |
| PUT | /webhooks/config | Update webhook configuration |
| POST | /webhooks/test | Send test webhook |

### geoip.lua

Geographic restriction configuration.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /geoip/config | Get GeoIP configuration |
| PUT | /geoip/config | Update GeoIP configuration |
| GET | /geoip/lookup | Lookup IP location |

### reputation.lua

IP reputation configuration.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /reputation/config | Get reputation configuration |
| PUT | /reputation/config | Update reputation configuration |
| GET | /reputation/check | Check IP reputation |
| GET | /reputation/blocklist | List local blocklist |
| POST | /reputation/blocklist | Add to blocklist |
| DELETE | /reputation/blocklist | Remove from blocklist |

### bulk.lua

Bulk import/export operations.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /bulk/export/keywords | Export all keywords |
| POST | /bulk/import/keywords | Import keywords |
| GET | /bulk/export/hashes | Export blocked hashes |
| POST | /bulk/import/hashes | Import hashes |
| GET | /bulk/export/whitelist | Export IP whitelist |
| POST | /bulk/import/whitelist | Import whitelist |
| DELETE | /bulk/clear/:type | Clear all of type |

### cluster.lua

Cluster status and coordination.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /cluster/status | Cluster health status |
| GET | /cluster/instances | List all instances |
| GET | /cluster/leader | Get current leader |
| GET | /cluster/config | Get coordinator config |
| GET | /cluster/this | Get this instance info |

See [Cluster Coordination Guide](CLUSTER_COORDINATION.md) for details.

---

## Shared Utilities (utils.lua)

Common utilities used by all handlers:

```lua
local utils = require "api_handlers.utils"

-- Redis connection
local red, err = utils.get_redis()
utils.close_redis(red)

-- Response helpers
utils.json_response(data, status)      -- Send JSON response
utils.error_response(message, status)   -- Send error response

-- Request parsing
local data, err = utils.get_json_body() -- Parse JSON body

-- Validation
local ok, err = utils.validate_required(data, {"field1", "field2"})
```

---

## RBAC Permission Mapping

Each endpoint requires specific permissions. See [RBAC Guide](RBAC.md) for full details.

| Resource | Permissions |
|----------|-------------|
| users | create, read, update, delete |
| providers | create, read, update, delete |
| vhosts | create, read, update, delete, enable, disable |
| endpoints | create, read, update, delete, enable, disable |
| keywords | create, read, update, delete |
| config | read, update |
| logs | read |
| metrics | read, reset |
| bulk | import, export, clear |
| captcha | read, update |
| security | read, update |

---

## Adding New Handlers

1. Create new file `api_handlers/myresource.lua`:

```lua
local _M = {}
local utils = require "api_handlers.utils"

_M.handlers = {}

_M.handlers["GET:/myresource"] = function()
    -- List all
    return utils.json_response({items = {}})
end

_M.handlers["POST:/myresource"] = function()
    local data, err = utils.get_json_body()
    if not data then
        return utils.error_response(err, 400)
    end
    -- Create
    return utils.json_response({id = "new-id"}, 201)
end

_M.handlers["GET:/myresource/:id"] = function(id)
    -- Get one
    return utils.json_response({id = id})
end

return _M
```

2. Register in `admin_api.lua`:

```lua
local myresource = require "api_handlers.myresource"

-- Add to handler loading
for key, handler in pairs(myresource.handlers) do
    handlers[key] = handler
end
```

3. Add RBAC permissions in `rbac.lua`:

```lua
-- Add to role definitions
myresource = {"create", "read", "update", "delete"}
```

4. Update documentation (this file and README.md)

---

## Request/Response Examples

### List Resources

```bash
curl -X GET http://localhost:8082/api/vhosts \
  -H "Authorization: Bearer {token}"
```

```json
{
  "vhosts": [
    {
      "id": "example-com",
      "name": "Example Website",
      "hostnames": ["example.com", "*.example.com"],
      "enabled": true
    }
  ],
  "total": 1
}
```

### Create Resource

```bash
curl -X POST http://localhost:8082/api/vhosts \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "New Website",
    "hostnames": ["newsite.com"]
  }'
```

```json
{
  "id": "new-website",
  "name": "New Website",
  "hostnames": ["newsite.com"],
  "enabled": false
}
```

### Error Response

```json
{
  "error": "Missing required field: name"
}
```

---

## Testing Handlers

Run individual handler tests:

```bash
# Test system endpoints
curl http://localhost:8082/api/status
curl http://localhost:8082/api/metrics

# Test with authentication
TOKEN=$(curl -s -X POST http://localhost:8082/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}' | jq -r .token)

curl http://localhost:8082/api/vhosts -H "Authorization: Bearer $TOKEN"
```
