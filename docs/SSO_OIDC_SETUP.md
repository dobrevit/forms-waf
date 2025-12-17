# OIDC SSO Integration Guide

This guide explains how to configure OpenID Connect (OIDC) identity providers for the Forms WAF Admin UI.

## Overview

OIDC is the recommended authentication protocol for SSO integration. It provides:
- Secure token-based authentication
- Standard JWT claims for user identity
- Group-based role mapping
- Just-in-time user provisioning

## Supported OIDC Providers

The Forms WAF Admin supports any OIDC-compliant identity provider, including:

- **Keycloak** - Open-source identity management
- **Okta** - Enterprise identity provider
- **Azure AD / Entra ID** - Microsoft cloud identity
- **Auth0** - Developer-friendly identity platform
- **Google Workspace** - Google Cloud Identity
- **AWS Cognito** - AWS managed identity
- **GitLab** - Self-hosted or cloud
- **GitHub** - OAuth2/OIDC support

---

## Configuration via Helm

### Basic OIDC Provider

```yaml
# values.yaml
adminUI:
  auth:
    providers:
      - id: corporate-sso
        name: "Corporate SSO"
        type: oidc
        enabled: true
        priority: 100
        oidc:
          # Use discovery URL (recommended)
          discovery: "https://idp.example.com/.well-known/openid-configuration"
          # Or specify issuer directly
          # issuer: "https://idp.example.com"
          clientId: "waf-admin"
          # For production, use existingSecret instead
          clientSecret: ""
          existingSecret:
            name: "waf-oidc-secrets"
            key: "corporate-sso-client-secret"
          scopes:
            - openid
            - profile
            - email
            - groups
          sslVerify: true
          usePkce: true
        roleMapping:
          defaultRole: viewer
          defaultVhosts:
            - "*"
          claimName: groups
          syncOnLogin: true
          mappings:
            - group: "WAF-Admins"
              role: admin
              vhosts: ["*"]
            - group: "WAF-Operators"
              role: operator
              vhosts: ["*"]
            - group: "Team-Alpha"
              role: operator
              vhosts: ["alpha-vhost"]
```

### Creating Secrets for Client Credentials

```bash
# Create secret with client secrets for OIDC providers
kubectl create secret generic waf-oidc-secrets \
  --from-literal=corporate-sso-client-secret="your-secret-here" \
  --from-literal=okta-client-secret="another-secret" \
  -n forms-waf
```

---

## Provider-Specific Setup

### Keycloak

1. **Create a Client**
   - Go to **Clients** → **Create client**
   - Client ID: `waf-admin`
   - Client type: OpenID Connect

2. **Configure Client Settings**
   - Access Type: `confidential`
   - Standard Flow Enabled: ON
   - Valid Redirect URIs: `https://waf-admin.example.com/api/auth/callback/oidc`
   - Web Origins: `https://waf-admin.example.com`

3. **Add Group Mapper**
   - Go to **Client scopes** → **waf-admin-dedicated** → **Add mapper**
   - Mapper type: Group Membership
   - Name: `groups`
   - Token Claim Name: `groups`
   - Full group path: OFF
   - Add to ID token: ON

4. **Configuration**
```yaml
oidc:
  discovery: "https://keycloak.example.com/realms/your-realm/.well-known/openid-configuration"
  clientId: "waf-admin"
  clientSecret: "<from-credentials-tab>"
  scopes: ["openid", "profile", "email", "groups"]
```

### Okta

1. **Create Application**
   - Applications → Create App Integration
   - Sign-in method: OIDC
   - Application type: Web Application

2. **Configure Settings**
   - Sign-in redirect URIs: `https://waf-admin.example.com/api/auth/callback/oidc`
   - Sign-out redirect URIs: `https://waf-admin.example.com/`
   - Assignments: Assign users/groups

3. **Add Groups Claim**
   - Security → API → Authorization Servers → default → Claims
   - Add Claim:
     - Name: `groups`
     - Include in: ID Token
     - Value type: Groups
     - Filter: Matches regex `.*`

4. **Configuration**
```yaml
oidc:
  discovery: "https://your-org.okta.com/.well-known/openid-configuration"
  clientId: "<client-id>"
  clientSecret: "<client-secret>"
  scopes: ["openid", "profile", "email", "groups"]
```

### Azure AD / Entra ID

1. **Register Application**
   - Azure Portal → App registrations → New registration
   - Redirect URI: Web - `https://waf-admin.example.com/api/auth/callback/oidc`

2. **Configure API Permissions**
   - API permissions → Add permission → Microsoft Graph
   - Delegated: `openid`, `profile`, `email`, `User.Read`

3. **Add Groups Claim**
   - Token configuration → Add groups claim
   - Select: Security groups, Groups assigned to the application

4. **Create Client Secret**
   - Certificates & secrets → New client secret

5. **Configuration**
```yaml
oidc:
  discovery: "https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration"
  clientId: "<application-id>"
  clientSecret: "<client-secret>"
  scopes: ["openid", "profile", "email"]
roleMapping:
  claimName: groups  # Azure uses Object IDs for groups
  mappings:
    - group: "<group-object-id>"  # Use Azure AD group Object ID
      role: admin
      vhosts: ["*"]
```

### Auth0

1. **Create Application**
   - Applications → Create Application → Regular Web Application

2. **Configure Settings**
   - Allowed Callback URLs: `https://waf-admin.example.com/api/auth/callback/oidc`
   - Allowed Logout URLs: `https://waf-admin.example.com/`

3. **Add Groups to Token**
   - Actions → Flows → Login → Add Action
   - Create custom action to add groups claim

4. **Configuration**
```yaml
oidc:
  discovery: "https://your-tenant.auth0.com/.well-known/openid-configuration"
  clientId: "<client-id>"
  clientSecret: "<client-secret>"
  scopes: ["openid", "profile", "email", "groups"]
```

### Google Workspace

1. **Create OAuth Client**
   - Google Cloud Console → APIs & Services → Credentials
   - Create OAuth 2.0 Client ID → Web application

2. **Configure Redirect URI**
   - Authorized redirect URIs: `https://waf-admin.example.com/api/auth/callback/oidc`

3. **Configuration**
```yaml
oidc:
  discovery: "https://accounts.google.com/.well-known/openid-configuration"
  clientId: "<client-id>.apps.googleusercontent.com"
  clientSecret: "<client-secret>"
  scopes: ["openid", "profile", "email"]
  # Note: Google doesn't provide groups in standard OIDC
  # Use Google Workspace Directory API for group membership
```

---

## Configuration via Admin UI

1. Navigate to **Admin** → **Auth Providers**
2. Click **Add Provider**
3. Configure:

| Tab | Setting | Description |
|-----|---------|-------------|
| General | ID | Unique identifier (e.g., `okta-prod`) |
| General | Name | Display name on login page |
| General | Type | Select `OIDC` |
| General | Enabled | Toggle provider on/off |
| General | Priority | Order on login page (higher = first) |
| Config | Discovery URL | OIDC well-known endpoint |
| Config | Client ID | OAuth client ID |
| Config | Client Secret | OAuth client secret |
| Config | Scopes | Space-separated scopes |
| Config | SSL Verify | Verify IdP certificates |
| Config | Use PKCE | Enable Proof Key for Code Exchange |
| Role Mapping | Default Role | Role for users with no group match |
| Role Mapping | Claim Name | JWT claim containing groups |
| Role Mapping | Sync on Login | Update role from IdP on each login |
| Role Mapping | Group Mappings | Map IdP groups to WAF roles |

---

## Configuration via API

```bash
# Create OIDC provider
curl -X POST https://waf-admin.example.com/api/auth/providers/config \
  -H "Content-Type: application/json" \
  -H "Cookie: waf_admin_session=<session>" \
  -d '{
    "id": "okta-prod",
    "name": "Okta SSO",
    "type": "oidc",
    "enabled": true,
    "priority": 100,
    "oidc": {
      "discovery": "https://your-org.okta.com/.well-known/openid-configuration",
      "client_id": "your-client-id",
      "client_secret": "your-client-secret",
      "scopes": ["openid", "profile", "email", "groups"],
      "ssl_verify": true,
      "use_pkce": true
    },
    "role_mapping": {
      "default_role": "viewer",
      "default_vhosts": ["*"],
      "claim_name": "groups",
      "sync_on_login": true,
      "mappings": [
        {"group": "WAF-Admins", "role": "admin", "vhosts": ["*"]},
        {"group": "WAF-Operators", "role": "operator", "vhosts": ["*"]}
      ]
    }
  }'

# Test provider connection
curl -X POST https://waf-admin.example.com/api/auth/providers/config/okta-prod/test \
  -H "Cookie: waf_admin_session=<session>"
```

---

## Authentication Flow

```
1. User clicks "Login with Okta SSO" on login page
2. Browser redirects to: /api/auth/sso/oidc?provider=okta-prod
3. OpenResty generates OIDC authorization URL with:
   - client_id
   - redirect_uri: /api/auth/callback/oidc
   - scope: openid profile email groups
   - state: random nonce (stored in Redis)
   - code_challenge: PKCE challenge (if enabled)
4. User authenticates with IdP
5. IdP redirects to /api/auth/callback/oidc with:
   - code: authorization code
   - state: nonce for CSRF protection
6. OpenResty exchanges code for tokens
7. OpenResty validates ID token:
   - Signature verification
   - Issuer validation
   - Audience validation
   - Expiration check
8. User provisioned/updated in Redis with mapped role
9. Session created and cookie set
10. User redirected to Admin UI
```

---

## Role Mapping

### Claim-Based Mapping

The `claim_name` specifies which JWT claim contains group information:

| Provider | Common Claim Name |
|----------|------------------|
| Keycloak | `groups` |
| Okta | `groups` |
| Azure AD | `groups` (contains Object IDs) |
| Auth0 | `https://your-namespace/groups` (custom) |

### Mapping Priority

1. Check mappings in order (first match wins)
2. If no match, apply `default_role` and `default_vhosts`
3. User is created/updated with mapped role and vhost scope

### Vhost Scoping

```yaml
mappings:
  # Global admin - access to all vhosts
  - group: "WAF-Admins"
    role: admin
    vhosts: ["*"]

  # Team-specific operator - limited vhost access
  - group: "Team-Alpha"
    role: operator
    vhosts: ["alpha.example.com", "alpha-staging.example.com"]

  # Read-only viewer for specific vhost
  - group: "Partners"
    role: viewer
    vhosts: ["partner-portal.example.com"]
```

---

## Troubleshooting

### "Discovery failed" error
- Check network connectivity to IdP
- Verify SSL certificates if `ssl_verify: true`
- Ensure discovery URL returns valid JSON

### "Invalid client" error
- Verify client ID is correct
- Check client secret hasn't expired
- Ensure redirect URI matches exactly

### "Token validation failed" error
- Check system clock synchronization
- Verify issuer URL matches exactly
- Ensure audience (client_id) is in token

### Groups not mapped correctly
- Enable debug logging to see actual claims
- Check claim name matches IdP configuration
- Verify group names are exact (case-sensitive)
- For Azure AD, use group Object IDs, not names

### Redirect loop after authentication
- Check redirect URI configuration in IdP
- Verify cookie settings (SameSite, Secure)
- Ensure session is being created

---

## Security Best Practices

1. **Use HTTPS everywhere** - All OIDC communication must be over TLS
2. **Enable PKCE** - Protects against authorization code interception
3. **Verify SSL certificates** - Never disable in production
4. **Rotate secrets regularly** - Use secret management tools
5. **Minimize scopes** - Only request necessary permissions
6. **Enable sync_on_login** - Keep roles updated from IdP
7. **Use short token lifetimes** - Reduce exposure window
8. **Audit authentication events** - Monitor for anomalies

---

## Related Documentation

- [SAML Provider Configuration](./SSO_SAML_SETUP.md)
- [LDAP Provider Configuration](./SSO_LDAP_SETUP.md)
- [Role-Based Access Control](./RBAC.md)
