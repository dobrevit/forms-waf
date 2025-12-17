# SAML SSO Integration Guide

This guide explains how to integrate SAML 2.0 identity providers with the Forms WAF Admin UI using a SAML-to-OIDC bridge approach.

## Overview

Due to the complexity of XML signature validation in SAML responses, the Forms WAF Admin uses a **SAML-to-OIDC bridge** approach rather than native SAML parsing. This is achieved by configuring your identity provider (IdP) or an intermediary like Keycloak or Dex to translate SAML assertions into OIDC tokens.

### Why Use a Bridge?

1. **Security**: XML signature validation requires proper canonicalization and is error-prone
2. **Maintenance**: SAML libraries need constant updates for security patches
3. **Simplicity**: OIDC/JWT tokens are easier to validate and parse
4. **Flexibility**: The bridge can aggregate multiple SAML IdPs into a single OIDC endpoint

## Architecture

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────┐     ┌─────────────┐
│  WAF Admin  │────▶│  Keycloak/Dex   │────▶│  SAML IdP    │     │  Active     │
│  (OIDC)     │◀────│  (SAML-to-OIDC) │◀────│  (Okta/ADFS) │ or  │  Directory  │
└─────────────┘     └─────────────────┘     └──────────────┘     └─────────────┘
```

## Option 1: Keycloak as SAML-to-OIDC Bridge

Keycloak is a full-featured identity broker that can federate with SAML IdPs and expose them as OIDC.

### Step 1: Deploy Keycloak

```yaml
# docker-compose.yml addition
keycloak:
  image: quay.io/keycloak/keycloak:24.0
  environment:
    - KC_DB=postgres
    - KC_DB_URL=jdbc:postgresql://postgres:5432/keycloak
    - KC_DB_USERNAME=keycloak
    - KC_DB_PASSWORD=keycloak
    - KEYCLOAK_ADMIN=admin
    - KEYCLOAK_ADMIN_PASSWORD=admin
  command: start-dev
  ports:
    - "8180:8080"
```

### Step 2: Create a Realm

1. Login to Keycloak admin console at `http://localhost:8180`
2. Create a new realm: **waf-admin**
3. Note your realm's OIDC discovery URL: `http://keycloak:8080/realms/waf-admin/.well-known/openid-configuration`

### Step 3: Configure SAML Identity Provider

1. Go to **Identity Providers** → **Add provider** → **SAML v2.0**
2. Configure your SAML IdP settings:

| Setting | Description |
|---------|-------------|
| Alias | A unique identifier (e.g., `okta-saml`) |
| Display Name | Shown on login page (e.g., `Corporate SSO`) |
| Service Provider Entity ID | `https://keycloak.example.com/realms/waf-admin` |
| Single Sign-On Service URL | Your IdP's SSO URL |
| Single Logout Service URL | Your IdP's SLO URL (optional) |
| NameID Policy Format | Usually `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |

3. Download the Keycloak SAML metadata to configure your IdP:
   `https://keycloak:8080/realms/waf-admin/protocol/saml/descriptor`

### Step 4: Configure SAML IdP (Okta Example)

In Okta:
1. Create a new SAML 2.0 Application
2. Set the SSO URL to: `https://keycloak.example.com/realms/waf-admin/broker/okta-saml/endpoint`
3. Set the Audience URI to: `https://keycloak.example.com/realms/waf-admin`
4. Configure attribute statements:

| Name | Value |
|------|-------|
| email | user.email |
| firstName | user.firstName |
| lastName | user.lastName |
| groups | user.groups |

### Step 5: Create OIDC Client for WAF Admin

1. In Keycloak, go to **Clients** → **Create client**
2. Configure:

| Setting | Value |
|---------|-------|
| Client ID | `waf-admin` |
| Client Protocol | openid-connect |
| Access Type | confidential |
| Valid Redirect URIs | `https://waf-admin.example.com/api/auth/callback/oidc` |
| Web Origins | `https://waf-admin.example.com` |

3. Copy the client secret from the **Credentials** tab

### Step 6: Configure Role Mapping

1. Create mappers to include groups in the ID token:
   - Go to **Clients** → **waf-admin** → **Client scopes** → **waf-admin-dedicated** → **Add mapper**
   - Type: **Group Membership**
   - Token Claim Name: `groups`
   - Add to ID token: ON

### Step 7: Configure WAF Admin Provider

Create the OIDC provider in WAF Admin pointing to Keycloak:

```bash
curl -X POST https://waf-admin.example.com/api/auth/providers/config \
  -H "Content-Type: application/json" \
  -H "Cookie: waf_admin_session=<session>" \
  -d '{
    "id": "corporate-sso",
    "name": "Corporate SSO",
    "type": "oidc",
    "enabled": true,
    "oidc": {
      "discovery": "https://keycloak.example.com/realms/waf-admin/.well-known/openid-configuration",
      "client_id": "waf-admin",
      "client_secret": "your-client-secret",
      "scopes": ["openid", "profile", "email", "groups"]
    },
    "role_mapping": {
      "default_role": "viewer",
      "claim_name": "groups",
      "mappings": [
        {"group": "WAF-Admins", "role": "admin", "vhosts": ["*"]},
        {"group": "WAF-Operators", "role": "operator", "vhosts": ["*"]}
      ]
    }
  }'
```

---

## Option 2: Dex as SAML-to-OIDC Bridge

Dex is a lighter-weight alternative to Keycloak, focused specifically on identity federation.

### Step 1: Deploy Dex

```yaml
# docker-compose.yml addition
dex:
  image: ghcr.io/dexidp/dex:v2.38.0
  volumes:
    - ./dex-config.yaml:/etc/dex/config.yaml
  ports:
    - "5556:5556"
  command: dex serve /etc/dex/config.yaml
```

### Step 2: Configure Dex

```yaml
# dex-config.yaml
issuer: https://dex.example.com

storage:
  type: memory

web:
  http: 0.0.0.0:5556

connectors:
  - type: saml
    id: okta
    name: Corporate SSO
    config:
      ssoURL: https://your-org.okta.com/app/xxx/sso/saml
      ca: /etc/dex/okta-ca.pem
      redirectURI: https://dex.example.com/callback
      entityIssuer: https://dex.example.com
      usernameAttr: email
      emailAttr: email
      groupsAttr: groups

staticClients:
  - id: waf-admin
    secret: your-client-secret
    name: WAF Admin
    redirectURIs:
      - https://waf-admin.example.com/api/auth/callback/oidc

oauth2:
  skipApprovalScreen: true
```

### Step 3: Configure WAF Admin Provider

```bash
curl -X POST https://waf-admin.example.com/api/auth/providers/config \
  -H "Content-Type: application/json" \
  -d '{
    "id": "dex-saml",
    "name": "Corporate SSO",
    "type": "oidc",
    "enabled": true,
    "oidc": {
      "issuer": "https://dex.example.com",
      "client_id": "waf-admin",
      "client_secret": "your-client-secret",
      "scopes": ["openid", "profile", "email", "groups"]
    },
    "role_mapping": {
      "default_role": "viewer",
      "claim_name": "groups",
      "mappings": [
        {"group": "waf-admins", "role": "admin", "vhosts": ["*"]}
      ]
    }
  }'
```

---

## Option 3: Azure AD with SAML

Azure AD can be configured as a SAML IdP, but it also natively supports OIDC, which is simpler to integrate.

### Using Azure AD OIDC (Recommended)

1. Register an application in Azure AD
2. Configure redirect URI: `https://waf-admin.example.com/api/auth/callback/oidc`
3. Note the Application (client) ID and Directory (tenant) ID
4. Create a client secret

```bash
curl -X POST https://waf-admin.example.com/api/auth/providers/config \
  -H "Content-Type: application/json" \
  -d '{
    "id": "azure-ad",
    "name": "Microsoft 365",
    "type": "oidc",
    "enabled": true,
    "oidc": {
      "discovery": "https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration",
      "client_id": "{application-id}",
      "client_secret": "{client-secret}",
      "scopes": ["openid", "profile", "email"]
    },
    "role_mapping": {
      "default_role": "viewer",
      "claim_name": "groups",
      "mappings": [
        {"group": "{azure-ad-group-id}", "role": "admin", "vhosts": ["*"]}
      ]
    }
  }'
```

> **Note**: To include groups in the token, you need to configure "Groups claim" in the Token Configuration of your Azure AD app registration.

---

## Common SAML IdP Configurations

### Okta

| Setting | Value |
|---------|-------|
| SSO URL | `https://your-org.okta.com/app/exampleapp/xxx/sso/saml` |
| NameID Format | EmailAddress |
| Assertion Signature | Signed |
| Response Signature | Signed |

### ADFS

| Setting | Value |
|---------|-------|
| Federation Metadata | `https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml` |
| SSO URL | `https://adfs.example.com/adfs/ls/` |
| Entity ID | `http://adfs.example.com/adfs/services/trust` |

### Google Workspace

| Setting | Value |
|---------|-------|
| SSO URL | `https://accounts.google.com/o/saml2/idp?idpid=xxx` |
| Entity ID | `https://accounts.google.com/o/saml2?idpid=xxx` |

---

## Troubleshooting

### "Invalid signature" errors
- Ensure the SAML certificate is correctly imported into your bridge (Keycloak/Dex)
- Check that clock skew between systems is minimal (< 5 minutes)

### Groups not appearing in OIDC token
- Verify the IdP is sending groups in the SAML assertion
- Check the mapper configuration in Keycloak/Dex
- Ensure the groups claim is included in the ID token scope

### Redirect loop after authentication
- Verify the redirect URI matches exactly (including trailing slashes)
- Check that cookies are being set correctly (SameSite, Secure flags)

### User not provisioned with correct role
- Check the group names match exactly (case-sensitive)
- Verify the `claim_name` in role_mapping matches the token claim
- Enable debug logging to see the actual claims received

---

## Security Considerations

1. **Always use HTTPS** for all SAML and OIDC communications
2. **Verify certificates** - don't disable SSL verification in production
3. **Short token lifetime** - configure access tokens to expire quickly
4. **Audit logging** - enable logging of all authentication events
5. **Regular rotation** - rotate client secrets periodically

---

## Related Documentation

- [OIDC Provider Configuration](./SSO_OIDC_SETUP.md)
- [LDAP Provider Configuration](./SSO_LDAP_SETUP.md)
- [Role-Based Access Control](./RBAC.md)
