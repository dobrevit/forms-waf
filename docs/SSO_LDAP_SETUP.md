# LDAP/Active Directory Integration Guide

This guide explains how to configure LDAP and Active Directory authentication for the Forms WAF Admin UI.

## Overview

LDAP authentication provides:
- Integration with existing corporate directories
- Username/password authentication against directory server
- Group-based role mapping from LDAP groups
- Support for both Active Directory and OpenLDAP

## Supported LDAP Servers

- **Microsoft Active Directory** - Windows domain services
- **OpenLDAP** - Open-source LDAP server
- **389 Directory Server** - Red Hat/Fedora LDAP
- **FreeIPA** - Identity management solution
- **ApacheDS** - Apache Directory Server

---

## Configuration via Helm

### Active Directory Example

```yaml
# values.yaml
adminUI:
  auth:
    providers:
      - id: corp-ldap
        name: "Corporate Directory"
        type: ldap
        enabled: true
        priority: 100
        ldap:
          host: "ldap.example.com"
          port: 636
          useSsl: true
          sslVerify: true
          timeout: 5000
          baseDn: "dc=example,dc=com"
          # Service account for user search (search+bind mode)
          bindDn: "cn=service-account,ou=service-accounts,dc=example,dc=com"
          bindPassword: ""  # Use existingSecret
          existingSecret:
            name: "waf-ldap-secrets"
            key: "corp-ldap-bind-password"
          # User search settings
          userBaseDn: "ou=users,dc=example,dc=com"
          userFilter: "(sAMAccountName={username})"  # AD style
          # Group search settings
          groupBaseDn: "ou=groups,dc=example,dc=com"
          groupFilter: "(member={user_dn})"
          groupAttribute: "cn"
        roleMapping:
          defaultRole: viewer
          defaultVhosts: ["*"]
          syncOnLogin: true
          mappings:
            - group: "WAF-Admins"
              role: admin
              vhosts: ["*"]
            - group: "WAF-Operators"
              role: operator
              vhosts: ["*"]
```

### OpenLDAP Example

```yaml
adminUI:
  auth:
    providers:
      - id: openldap
        name: "OpenLDAP"
        type: ldap
        enabled: true
        ldap:
          host: "ldap.example.com"
          port: 389
          useSsl: false  # Use STARTTLS or plain (not recommended)
          baseDn: "dc=example,dc=com"
          # Direct bind mode (no service account)
          userDnTemplate: "uid={username},ou=people,dc=example,dc=com"
          # Group settings
          groupBaseDn: "ou=groups,dc=example,dc=com"
          groupFilter: "(memberUid={username})"
          groupAttribute: "cn"
        roleMapping:
          defaultRole: viewer
          mappings:
            - group: "waf-admins"
              role: admin
              vhosts: ["*"]
```

### Creating Secrets for Bind Credentials

```bash
# Create secret with LDAP bind passwords
kubectl create secret generic waf-ldap-secrets \
  --from-literal=corp-ldap-bind-password="service-account-password" \
  -n forms-waf
```

---

## Authentication Modes

### Mode 1: Search and Bind (Recommended)

Uses a service account to search for users, then binds with user credentials.

```
1. Connect to LDAP with service account (bindDn/bindPassword)
2. Search for user using userFilter
3. If user found, bind with user's DN and password
4. If bind succeeds, search for user's groups
5. Map groups to WAF role
```

**Advantages:**
- Users can log in with username (not full DN)
- More flexible user search criteria
- Better error messages (user not found vs wrong password)

**Configuration:**
```yaml
ldap:
  bindDn: "cn=service,ou=accounts,dc=example,dc=com"
  bindPassword: "service-password"
  userFilter: "(sAMAccountName={username})"  # Search by username
```

### Mode 2: Direct Bind

Constructs user DN from template and binds directly.

```
1. Construct user DN from template: uid={username},ou=users,dc=example,dc=com
2. Bind with constructed DN and provided password
3. If bind succeeds, search for user's groups
4. Map groups to WAF role
```

**Advantages:**
- No service account required
- Simpler configuration

**Configuration:**
```yaml
ldap:
  userDnTemplate: "uid={username},ou=people,dc=example,dc=com"
  # No bindDn/bindPassword needed
```

---

## Configuration Options

### Connection Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `host` | LDAP server hostname | Required |
| `port` | LDAP port | 389 (LDAP) or 636 (LDAPS) |
| `useSsl` | Use LDAPS (SSL/TLS) | `true` |
| `sslVerify` | Verify server certificate | `true` |
| `timeout` | Connection timeout (ms) | `5000` |

### Bind Settings

| Setting | Description | Example |
|---------|-------------|---------|
| `baseDn` | Base DN for all searches | `dc=example,dc=com` |
| `bindDn` | Service account DN | `cn=service,ou=accounts,dc=example,dc=com` |
| `bindPassword` | Service account password | Use `existingSecret` |

### User Search Settings

| Setting | Description | Example |
|---------|-------------|---------|
| `userBaseDn` | Base DN for user search | `ou=users,dc=example,dc=com` |
| `userFilter` | LDAP filter for user search | `(sAMAccountName={username})` |
| `userDnTemplate` | DN template for direct bind | `uid={username},ou=people,dc=example,dc=com` |

### Group Search Settings

| Setting | Description | Example |
|---------|-------------|---------|
| `groupBaseDn` | Base DN for group search | `ou=groups,dc=example,dc=com` |
| `groupFilter` | LDAP filter for group search | `(member={user_dn})` |
| `groupAttribute` | Attribute containing group name | `cn` |

---

## Directory-Specific Configuration

### Active Directory

```yaml
ldap:
  host: "dc1.example.com"
  port: 636
  useSsl: true
  baseDn: "dc=example,dc=com"
  bindDn: "cn=WAF Service Account,ou=Service Accounts,dc=example,dc=com"
  userBaseDn: "ou=Users,dc=example,dc=com"
  # sAMAccountName is the Windows logon name
  userFilter: "(sAMAccountName={username})"
  # Or use userPrincipalName for email-style login
  # userFilter: "(userPrincipalName={username})"
  groupBaseDn: "ou=Groups,dc=example,dc=com"
  # AD uses member attribute with full user DN
  groupFilter: "(member={user_dn})"
  groupAttribute: "cn"
```

**Active Directory Notes:**
- Port 636 uses LDAPS (recommended)
- Port 389 with STARTTLS is also supported
- `sAMAccountName` is the pre-Windows 2000 logon name
- `userPrincipalName` is the UPN (user@domain.com)
- Groups use `member` attribute with full DNs

### OpenLDAP

```yaml
ldap:
  host: "ldap.example.com"
  port: 636
  useSsl: true
  baseDn: "dc=example,dc=com"
  # Direct bind with DN template
  userDnTemplate: "uid={username},ou=people,dc=example,dc=com"
  # Or use search+bind with service account
  # bindDn: "cn=admin,dc=example,dc=com"
  # userFilter: "(uid={username})"
  groupBaseDn: "ou=groups,dc=example,dc=com"
  # POSIX groups use memberUid with just username
  groupFilter: "(memberUid={username})"
  # Or groupOfNames uses member with full DN
  # groupFilter: "(member={user_dn})"
  groupAttribute: "cn"
```

**OpenLDAP Notes:**
- POSIX groups use `memberUid` with plain usernames
- `groupOfNames` uses `member` with full DNs
- UID is typically the login attribute

### FreeIPA

```yaml
ldap:
  host: "ipa.example.com"
  port: 636
  useSsl: true
  baseDn: "dc=example,dc=com"
  bindDn: "uid=service,cn=users,cn=accounts,dc=example,dc=com"
  userBaseDn: "cn=users,cn=accounts,dc=example,dc=com"
  userFilter: "(uid={username})"
  groupBaseDn: "cn=groups,cn=accounts,dc=example,dc=com"
  groupFilter: "(member={user_dn})"
  groupAttribute: "cn"
```

---

## Configuration via Admin UI

1. Navigate to **Admin** → **Auth Providers**
2. Click **Add Provider**
3. Select Type: **LDAP**
4. Configure:

### General Tab

| Setting | Description |
|---------|-------------|
| Provider ID | Unique identifier (e.g., `corp-ldap`) |
| Provider Name | Display name for login page |
| Enabled | Toggle provider on/off |
| Priority | Order on login page |

### Config Tab

| Setting | Description |
|---------|-------------|
| Host | LDAP server hostname |
| Port | Server port (636 for LDAPS) |
| Use SSL | Enable SSL/TLS connection |
| Verify SSL | Verify server certificate |
| Timeout | Connection timeout (ms) |
| Base DN | Root DN for searches |
| Bind DN | Service account DN |
| Bind Password | Service account password |

### Advanced Settings (Accordion)

| Setting | Description |
|---------|-------------|
| User Base DN | DN for user searches |
| User DN Template | Template for direct bind |
| User Filter | LDAP filter for user search |
| Group Base DN | DN for group searches |
| Group Filter | LDAP filter for group search |
| Group Attribute | Attribute with group name |

### Role Mapping Tab

| Setting | Description |
|---------|-------------|
| Default Role | Role for unmatched users |
| Sync on Login | Update role on each login |
| Group Mappings | Map LDAP groups to WAF roles |

---

## Configuration via API

```bash
# Create LDAP provider
curl -X POST https://waf-admin.example.com/api/auth/providers/config \
  -H "Content-Type: application/json" \
  -H "Cookie: waf_admin_session=<session>" \
  -d '{
    "id": "corp-ldap",
    "name": "Corporate LDAP",
    "type": "ldap",
    "enabled": true,
    "priority": 100,
    "ldap": {
      "host": "ldap.example.com",
      "port": 636,
      "use_ssl": true,
      "ssl_verify": true,
      "timeout": 5000,
      "base_dn": "dc=example,dc=com",
      "bind_dn": "cn=service,ou=accounts,dc=example,dc=com",
      "bind_password": "service-password",
      "user_base_dn": "ou=users,dc=example,dc=com",
      "user_filter": "(sAMAccountName={username})",
      "group_base_dn": "ou=groups,dc=example,dc=com",
      "group_filter": "(member={user_dn})",
      "group_attribute": "cn"
    },
    "role_mapping": {
      "default_role": "viewer",
      "default_vhosts": ["*"],
      "sync_on_login": true,
      "mappings": [
        {"group": "WAF-Admins", "role": "admin", "vhosts": ["*"]},
        {"group": "WAF-Operators", "role": "operator", "vhosts": ["*"]}
      ]
    }
  }'

# Test LDAP connection
curl -X POST https://waf-admin.example.com/api/auth/providers/config/corp-ldap/test \
  -H "Cookie: waf_admin_session=<session>"
```

---

## Authentication Flow

```
LDAP Login Flow (Search + Bind Mode):

1. User enters username/password on login page
2. POST to /api/auth/sso/ldap with credentials
3. OpenResty connects to LDAP with service account
4. Search for user: (&(objectClass=user)(sAMAccountName=jsmith))
5. If user found, extract user DN
6. Bind with user DN and provided password
7. If bind succeeds, search for user's groups
8. Map LDAP groups to WAF role using mappings
9. Create/update user in Redis
10. Create session and set cookie
11. Return success response to frontend
```

---

## Troubleshooting

### "Connection refused" or "Connection timed out"
- Check firewall allows connection to LDAP port
- Verify hostname resolves correctly
- Try telnet/nc to test connectivity: `nc -zv ldap.example.com 636`

### "SSL handshake failed"
- Check if server uses self-signed certificate
- If testing, set `sslVerify: false` (not for production)
- Verify certificate chain is complete

### "Invalid credentials" for service account
- Verify bind DN is correct (full DN, not username)
- Check password hasn't expired
- Ensure service account has read permissions

### "User not found"
- Check user filter syntax is correct
- Verify user exists in specified base DN
- Test filter in LDAP browser (ldapsearch, Apache Directory Studio)
- Check for typos in attribute names (case-sensitive)

### "Groups not found" or wrong role
- Verify group filter syntax
- Check group base DN is correct
- Confirm group membership (some are nested)
- Match group names exactly (case-sensitive)

### Testing LDAP Filters

Use `ldapsearch` to test your filters:

```bash
# Test user search
ldapsearch -H ldaps://ldap.example.com:636 \
  -D "cn=service,ou=accounts,dc=example,dc=com" \
  -w "password" \
  -b "ou=users,dc=example,dc=com" \
  "(sAMAccountName=jsmith)"

# Test group search
ldapsearch -H ldaps://ldap.example.com:636 \
  -D "cn=service,ou=accounts,dc=example,dc=com" \
  -w "password" \
  -b "ou=groups,dc=example,dc=com" \
  "(member=cn=John Smith,ou=users,dc=example,dc=com)"
```

---

## Security Best Practices

1. **Always use LDAPS (port 636)** - Never use plain LDAP in production
2. **Use service accounts** - Don't use admin credentials
3. **Limit service account permissions** - Read-only access to user/group OUs
4. **Verify SSL certificates** - Don't disable in production
5. **Use secrets management** - Never store passwords in values.yaml
6. **Enable account lockout** - Protect against brute force
7. **Audit authentication** - Log all login attempts
8. **Regular password rotation** - Rotate service account password

---

## Related Documentation

- [OIDC Provider Configuration](./SSO_OIDC_SETUP.md)
- [SAML Provider Configuration](./SSO_SAML_SETUP.md)
- [Role-Based Access Control](./RBAC.md)
