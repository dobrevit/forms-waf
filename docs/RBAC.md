# Role-Based Access Control (RBAC)

This guide explains the Role-Based Access Control system in the Forms WAF Admin UI.

## Overview

RBAC provides:
- **Role-based permissions** - Define what actions each role can perform
- **Multi-tenancy** - Scope access to specific virtual hosts
- **Consistent enforcement** - Permissions checked on every API request
- **UI integration** - Hide/disable features based on permissions

## Roles

### Built-in Roles

| Role | Description | Scope |
|------|-------------|-------|
| `admin` | Full access to all features | Global |
| `operator` | Manage configurations within assigned vhosts | Per-vhost |
| `viewer` | Read-only access | Per-vhost |

### Role Hierarchy

```
admin     - Full control, including user management
  ↓
operator  - Create/modify configurations
  ↓
viewer    - Read-only access
```

---

## Permissions

### Permission Structure

Each role has permissions defined as:

```json
{
  "id": "operator",
  "name": "Operator",
  "permissions": {
    "vhosts": ["read", "update", "enable", "disable"],
    "endpoints": ["create", "read", "update", "delete"],
    "keywords": ["create", "read", "update", "delete"],
    "config": ["read", "update"],
    "users": [],
    "providers": [],
    "logs": ["read"],
    "metrics": ["read"],
    "bulk": ["import", "export"],
    "captcha": ["read", "update"],
    "security": ["read", "update"]
  },
  "scope": "vhost"
}
```

### Resource Permissions

| Resource | Actions | Description |
|----------|---------|-------------|
| `vhosts` | create, read, update, delete, enable, disable | Virtual host management |
| `endpoints` | create, read, update, delete, enable, disable | Protected endpoint configuration |
| `keywords` | create, read, update, delete | Blocked/flagged keywords |
| `config` | read, update | System configuration (thresholds, allowlists) |
| `users` | create, read, update, delete | User management |
| `providers` | create, read, update, delete | SSO provider management |
| `logs` | read | View logs and activity |
| `metrics` | read, reset | View and reset metrics |
| `bulk` | import, export, clear | Bulk operations |
| `captcha` | read, update | CAPTCHA provider settings |
| `security` | read, update | Security settings (timing, GeoIP, reputation) |

### Default Role Permissions

#### Admin
```yaml
vhosts: [create, read, update, delete, enable, disable]
endpoints: [create, read, update, delete, enable, disable]
keywords: [create, read, update, delete]
config: [read, update]
users: [create, read, update, delete]
providers: [create, read, update, delete]
logs: [read]
metrics: [read, reset]
bulk: [import, export, clear]
captcha: [read, update]
security: [read, update]
```

#### Operator
```yaml
vhosts: [read, update, enable, disable]  # No create/delete
endpoints: [create, read, update, delete, enable, disable]
keywords: [create, read, update, delete]
config: [read, update]
users: []  # No user management
providers: []  # No provider management
logs: [read]
metrics: [read]  # No reset
bulk: [import, export]  # No clear
captcha: [read, update]
security: [read, update]
```

#### Viewer
```yaml
vhosts: [read]
endpoints: [read]
keywords: [read]
config: [read]
users: []
providers: []
logs: [read]
metrics: [read]
bulk: [export]  # Export only
captcha: [read]
security: [read]
```

---

## Vhost Scoping

### Overview

Users can be scoped to specific virtual hosts, limiting their access to only those vhosts.

### Scope Types

| Scope | Description | Example |
|-------|-------------|---------|
| `["*"]` | Global access - all vhosts | Admin users |
| `["vhost-1", "vhost-2"]` | Limited to specific vhosts | Team-specific operators |

### How Scoping Works

1. **User assigned vhost scope** during SSO login (from role mapping) or manual assignment
2. **API requests checked** against user's vhost scope
3. **Scoped resources filtered** - Users only see/modify their vhosts

### Example: Team-Based Access

```yaml
# SSO Role Mapping
role_mapping:
  mappings:
    # DevOps team - all vhosts
    - group: "DevOps"
      role: admin
      vhosts: ["*"]

    # Team Alpha - only their vhosts
    - group: "Team-Alpha"
      role: operator
      vhosts: ["alpha-prod", "alpha-staging"]

    # Support team - read-only, all vhosts
    - group: "Support"
      role: viewer
      vhosts: ["*"]
```

---

## API Permission Checks

### RBAC Middleware

Every API request is checked by the RBAC middleware:

```lua
-- rbac.lua middleware flow
1. Extract session from cookie
2. Load user's role and vhost scope
3. Determine required permission for endpoint
4. Check if user's role has required permission
5. If scoped resource, check vhost access
6. Allow or deny request
```

### Endpoint Permission Map

All 89 API endpoints have defined permission requirements:

| Method | Path | Resource | Action | Scoped |
|--------|------|----------|--------|--------|
| GET | /vhosts | vhosts | read | no |
| POST | /vhosts | vhosts | create | no |
| GET | /vhosts/:id | vhosts | read | yes |
| PUT | /vhosts/:id | vhosts | update | yes |
| DELETE | /vhosts/:id | vhosts | delete | yes |
| POST | /endpoints | endpoints | create | yes |
| ... | ... | ... | ... | ... |

### Scoped Resources

These resources are checked against user's vhost scope:

- Virtual host operations (when accessing specific vhost)
- Endpoint operations (endpoints belong to vhosts)
- Vhost-specific keywords
- Vhost-specific configuration

---

## Frontend Permission Checking

### usePermissions Hook

```typescript
import { usePermissions } from '@/hooks/usePermissions'

function MyComponent() {
  const {
    canCreateVhosts,
    canDeleteVhosts,
    canManageUsers,
    canManageProviders,
    hasVhostAccess,
    hasPermission,
  } = usePermissions()

  // Check specific permission
  if (!hasPermission('endpoints', 'delete')) {
    return <p>No delete permission</p>
  }

  // Check vhost access
  if (!hasVhostAccess('alpha-prod')) {
    return <p>No access to this vhost</p>
  }

  return <MyFeature />
}
```

### Conditional Rendering

```tsx
// Hide buttons based on permissions
{canManageUsers && (
  <Button onClick={handleDelete}>Delete User</Button>
)}

// Disable inputs based on permissions
<Input
  disabled={!hasPermission('config', 'update')}
  value={threshold}
  onChange={handleChange}
/>

// Filter data based on vhost scope
const accessibleVhosts = vhosts.filter(v =>
  hasVhostAccess(v.id)
)
```

---

## User Management

### Creating Users

Admins can create local users with specific roles and vhost scopes:

```bash
# Create operator with limited vhost access
curl -X POST https://waf-admin.example.com/api/users \
  -H "Content-Type: application/json" \
  -H "Cookie: waf_admin_session=<admin-session>" \
  -d '{
    "username": "team-alpha-op",
    "password": "secure-password",
    "email": "alpha@example.com",
    "display_name": "Team Alpha Operator",
    "role": "operator",
    "vhost_scope": ["alpha-prod", "alpha-staging"]
  }'
```

### Modifying User Access

```bash
# Update user's role and scope
curl -X PUT https://waf-admin.example.com/api/users/team-alpha-op \
  -H "Content-Type: application/json" \
  -H "Cookie: waf_admin_session=<admin-session>" \
  -d '{
    "role": "admin",
    "vhost_scope": ["*"]
  }'
```

### SSO User Provisioning

When users login via SSO:

1. **First login** - User created with mapped role and vhost scope
2. **Subsequent logins** - If `sync_on_login` enabled, role/scope updated
3. **No matching groups** - User gets `default_role` and `default_vhosts`

---

## Helm Configuration

### Enable RBAC

```yaml
# values.yaml
adminUI:
  auth:
    rbac:
      enabled: true
      # Default roles are created by redis-init job
```

### Role Initialization

The redis-init job creates default roles:

```bash
# During helm install/upgrade
echo "Creating RBAC role definitions..."
redis-cli SET "waf:auth:roles:config:admin" '<admin-role-json>'
redis-cli SET "waf:auth:roles:config:operator" '<operator-role-json>'
redis-cli SET "waf:auth:roles:config:viewer" '<viewer-role-json>'
```

---

## Redis Schema

### User Record

```json
{
  "username": "jsmith",
  "password_hash": "...",
  "salt": "...",
  "role": "operator",
  "vhost_scope": ["alpha-prod", "alpha-staging"],
  "auth_provider": "oidc",
  "provider_id": "corporate-sso",
  "external_id": "12345",
  "email": "jsmith@example.com",
  "display_name": "John Smith",
  "must_change_password": false,
  "created_at": "2025-01-15T10:00:00Z",
  "last_login": "2025-01-16T08:30:00Z"
}
```

### Role Definition

```json
{
  "id": "admin",
  "name": "Administrator",
  "description": "Full administrative access",
  "permissions": {
    "vhosts": ["create", "read", "update", "delete", "enable", "disable"],
    "users": ["create", "read", "update", "delete"],
    // ... other permissions
  },
  "scope": "global"
}
```

### Session Record

```json
{
  "username": "jsmith",
  "role": "operator",
  "vhost_scope": ["alpha-prod", "alpha-staging"],
  "auth_provider": "oidc",
  "created_at": 1705312200,
  "expires_at": 1705398600,
  "must_change_password": false
}
```

---

## Security Considerations

1. **Deny by default** - Requests without valid session are rejected
2. **Check every request** - RBAC middleware on all API endpoints
3. **Principle of least privilege** - Start with viewer, escalate as needed
4. **Audit logging** - Log all permission denials
5. **Session expiration** - Sessions expire after configured timeout
6. **Scope validation** - Always verify vhost access for scoped operations

---

## Troubleshooting

### "Permission denied" errors

1. Check user's role in session: `GET /api/auth/verify`
2. Verify role has required permission
3. For scoped resources, check vhost_scope includes target

### User can't see vhost

1. Check user's vhost_scope
2. Verify scope is `["*"]` or includes the vhost ID
3. If SSO user, check role mapping configuration

### SSO user gets wrong role

1. Enable debug logging to see claims
2. Verify group names match exactly (case-sensitive)
3. Check claim_name matches IdP claim
4. Verify sync_on_login is enabled

### New user can't login

1. Verify user was created successfully
2. Check password meets requirements
3. If SSO, verify provider is enabled
4. Check for account lockout

---

## Related Documentation

- [OIDC Provider Configuration](./SSO_OIDC_SETUP.md)
- [LDAP Provider Configuration](./SSO_LDAP_SETUP.md)
- [SAML Provider Configuration](./SSO_SAML_SETUP.md)
