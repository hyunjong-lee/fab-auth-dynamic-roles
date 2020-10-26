# Auth plugin for Flask AppBuilder based Applications

![System Diagram](./assets/fab_auth_keycloack.png)

## Goals
- Sync role from keycloak to Flask AppBuilder based applications.
  - It means that you can maintain `Roles` only in `Keycloak`.
- Show a full configuration example with AzureAD, Keycloak, and Apache Superset.

## A Configuration Example

### Azure AD
- Configure Azure AD App
  - Go to https://portal.azure.com
  - ...
  - The keypoint is `Token configuration` for role mapping in `Keycloak`.
  - You need to claim `groups` token to reveal group id list for each user if you want to assign a specific role to a specific group in `Keycloak`.
    - [Azure Document: groups-overage-claim](https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens#groups-overage-claim)
    - ![claim groups](./assets/azuread_token.png)
    - Form of `groups` token is array of group id.
      - `groups: ["e0d3ad3d-0000-1111-2222-3c5f5c52ab9b"]`

### Keycloak
- Go to your keycloak web UI.
- Create `superset` client and register roles which are existing in `Apache Superset` application.
- Configure `Identity Providers` with auth information in `Azure AD`.
- Configure `Mappers` of the configured identity provider.
  - ![Keycloak Mapper](./assets/keycloak_mapper.png)
  - ![Keycloak Mapper](./assets/keycloak_mapper_detail.png)
  - The key point is if you want assign a specific `Role`, check `groups` field in `id_token` with `[GROUP_ID]` using `Regex Claim Values` and select a `Role` of the client application.

### Apache Superset
- Example Flask configuration.

```python
# ----------------------------------------------------
# AUTHENTICATION CONFIG
# ----------------------------------------------------
from flask_appbuilder.security.manager import AUTH_OID

AUTH_TYPE = AUTH_OID
AUTH_ROLE_ADMIN = 'Admin'
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Public"  # registration role to "Public" which is the lowerst permission


from fab_auth_keycloak.security import SupersetOIDCSecurityManager

CUSTOM_SECURITY_MANAGER = SupersetOIDCSecurityManager
OIDC_CLIENT_SECRETS = "[CONFIGURATION_PATH]/oidc_client.json"
OIDC_SCOPES = ['openid', 'email', 'profile']
OIDC_USER_INFO_ENABLED = True
```

- Example`[CONFIGURATION_PATH]/oidc_client.json` configuration.

```json
{
    "web": {
        "realm_public_key": "[FIND IN KEYCLOAK]",
        "issuer": "[FIND IN KEYCLOAK]",
        "auth_uri": "[FIND IN KEYCLOAK]",
        "client_id": "superset",
        "client_secret": "[FIND IN KEYCLOAK SUPERSET CLIENT]",
        "redirect_urls": [
            // URLs which must be redirected to
        ],
        "userinfo_uri": "[FIND IN KEYCLOAK]",
        "token_uri": "[FIND IN KEYCLOAK]",
        "token_introspection_uri": "[FIND IN KEYCLOAK]"
    }
}
```

- Required dependencies

```python
flask-admin>=1.5.6
flask-oidc>=1.4.0
authlib>=0.14.3
fab-auth-keycloak>=0.1.0
```

## References

- [GitHub: `fab-oidc`](https://github.com/ministryofjustice/fab-oidc)
- [A good answer from Stackoverflow](https://stackoverflow.com/a/47787279)
