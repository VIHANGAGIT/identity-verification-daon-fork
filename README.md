# WSO2 Identity Server — Daon TrustX Identity Verification Connector

This connector integrates [Daon TrustX](https://www.daon.com/trustx/) identity verification into WSO2 Identity Server using the OIDC Authorization Code flow. Unlike webhook-based connectors, the Daon connector redirects the user's browser to the Daon-hosted verification UI and receives results synchronously via an OIDC callback.

---

## Prerequisites

- WSO2 Identity Server 7.x
- Maven 3.6+
- JDK 21
- A Daon TrustX tenant with admin access

---

## Building

```bash
mvn clean install
```

The following artifacts are produced:

| Artifact | Location |
|---|---|
| OSGi bundle | `components/org.wso2.carbon.identity.verification.daon.connector/target/org.wso2.carbon.identity.verification.daon.connector-*.jar` |
| API WAR | `components/org.wso2.carbon.identity.verification.daon.api/org.wso2.carbon.identity.verification.daon.api.dispatcher/target/idv#daon.war` |

---

## Deployment

### 1. Copy artifacts to WSO2 IS

```bash
IS_HOME=/path/to/wso2is

# OSGi connector bundle
cp components/org.wso2.carbon.identity.verification.daon.connector/target/\
org.wso2.carbon.identity.verification.daon.connector-*.jar \
$IS_HOME/repository/components/dropins/

# Callback API WAR (deploys at /idv/daon/)
cp components/org.wso2.carbon.identity.verification.daon.api/\
org.wso2.carbon.identity.verification.daon.api.dispatcher/target/idv#daon.war \
$IS_HOME/repository/deployment/server/webapps/

# UI metadata — Daon IdVP (identity verification provider)
cp -r ui-metadata/daon \
$IS_HOME/repository/resources/identity/extensions/identity-verification-providers/

# Daon logo
cp ui-metadata/assets/images/logos/daon.svg \
$IS_HOME/repository/deployment/server/webapps/console/resources/connections/assets/images/logos/
```

### 2. Update deployment.toml

Add the following to `$IS_HOME/repository/conf/deployment.toml`:

```toml
# Enable Identity Verification Providers in the IS Console
[console.identity_verification_providers]
enabled = true

# Allow unauthenticated access to the Daon OIDC callback endpoint
[[resource.access_control]]
context = "/idv/daon/v1/(.*)/callback"
secure = false
http_method = "GET"
```

### 3. Restart WSO2 IS

```bash
$IS_HOME/bin/wso2server.sh restart
```

---

## Registering an OIDC Client in Daon TrustX

1. Log in to your Daon TrustX administration console
2. Create a new **Confidential** OIDC client
3. Add the following as an allowed redirect URI (use a placeholder IdVP ID for now — update it after the provider is created in WSO2 IS):
   ```
   https://<IS_HOST>:<PORT>/idv/daon/v1/<idvp-id>/callback
   ```
4. Enable the required scopes: `openid`, `profile`, `document`
5. Note the **Client ID**, **Client Secret**, and your tenant **Base URL**:
   ```
   https://<tenant>.oak.trustx.com/auth/realms/<tenant>
   ```

---

## Configuring the Connector in WSO2 IS

### Step 1 — Create the Identity Verification Provider

1. Log in to the WSO2 IS Console
2. Navigate to **Identity Verification Providers** → **New Identity Verification Provider**
3. Select **Daon** from the provider list
4. Fill in the creation form:

| Field | Value |
|---|---|
| **Name** | A unique name, e.g. `Daon TrustX` |
| **Client ID** | OIDC Client ID from Daon TrustX |
| **Client Secret** | OIDC Client Secret from Daon TrustX |
| **Base URL** | `https://<tenant>.oak.trustx.com/auth/realms/<tenant>` |
| **Redirect URI** | `https://<IS_HOST>:<PORT>/idv/daon/v1/<idvp-id>/callback` |

5. Save the provider and copy the generated **IdVP ID**
6. Go back to Daon TrustX and update the redirect URI with the real IdVP ID

### Step 2 — Complete the Settings

Open the **Settings** tab of the created provider and fill in the remaining fields:

| Field | Value |
|---|---|
| **Scope** | `openid profile document` |
| **Callback URL** | URL in your application to redirect the user after verification completes |

### Step 3 — Configure Attribute Mappings

Open the **Attributes** tab and map WSO2 local claims to the corresponding Daon OIDC claim names returned in the ID token:

| WSO2 Local Claim | Daon Claim Name |
|---|---|
| `http://wso2.org/claims/givenname` | `given_name` |
| `http://wso2.org/claims/lastname` | `family_name` |
| `http://wso2.org/claims/dob` | `birthdate` |

Add any additional mappings based on the claims your Daon tenant is configured to return.

---

## Verification Flow

```
Application            WSO2 IS              Daon TrustX
     │                    │                      │
     │─── INITIATED ─────▶│                      │
     │                    │─── builds OIDC ─────▶│
     │◀── auth URL ───────│    auth URL          │
     │                    │                      │
     │────────── redirect user──────────────────▶│
     │                    │                      │ (user completes ID&V)
     │                    │◀─── callback ────────│
     │                    │    code + state      │
     │                    │─── exchange code ───▶│
     │                    │◀─── id_token ────────│
     │                    │  (verifiedClaims)    │
     │                    │─── update claims ───▶│ (internal)
     │◀────────── redirect to callback URL ──────│
     │                    │                      │
     │─── check status ──▶│                      │
     │◀── isVerified ─────│                      │
```

---

## Testing with the API

### 1. Initiate Verification

```bash
curl -X POST \
  https://<IS_HOST>:<PORT>/api/users/v1/me/idv/verify \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "idVProviderId": "<idvp-id>",
    "claims": [
      "http://wso2.org/claims/givenname",
      "http://wso2.org/claims/lastname",
      "http://wso2.org/claims/dob"
    ],
    "properties": [
      {
        "key": "status",
        "value": "INITIATED"
      }
    ]
  }'
```

**Response** — each claim includes `daon_authorization_url` in its metadata:

```json
[
  {
    "id": "...",
    "uri": "http://wso2.org/claims/givenname",
    "isVerified": false,
    "claimMetadata": {
      "daon_flow_status": "INITIATED",
      "daon_state": "<uuid>",
      "daon_authorization_url": "https://<tenant>.oak.trustx.com/auth/realms/<tenant>/protocol/openid-connect/auth?response_type=code&client_id=...&state=<uuid>&..."
    }
  }
]
```

> **Note:** `daon_authorization_url` is returned only in this initiation response — it is not persisted to the database.

### 2. Redirect the User

Redirect the user's browser to the `daon_authorization_url` from the response. The user completes identity verification on the Daon-hosted UI.

### 3. Daon Callback (automatic)

After verification, Daon redirects the browser to:
```
GET https://<IS_HOST>:<PORT>/idv/daon/v1/<idvp-id>/callback
    ?code=<authorization_code>
    &state=<uuid>
```

The connector automatically:
1. Validates the `state` parameter against the stored CSRF token
2. Exchanges the authorization code for an ID token at the Daon token endpoint
3. Extracts verified claims from the `verifiedClaims.claims` section of the ID token
4. Compares each Daon-returned value against the user's existing profile attribute value
5. Marks the claim `isVerified = true` only if the values match; sets `daon_verification_status = MISMATCH` otherwise
6. Redirects the user to the configured **Callback URL**

### 4. Re-initiate (if needed)

If the user did not complete verification (e.g. closed the browser), call the verify API again with `"value": "REINITIATED"` in the properties. A fresh authorization URL will be issued.

```bash
curl -X POST \
  https://<IS_HOST>:<PORT>/api/users/v1/me/idv/verify \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "idVProviderId": "<idvp-id>",
    "claims": [
      "http://wso2.org/claims/givenname",
      "http://wso2.org/claims/lastname"
    ],
    "properties": [
      {
        "key": "status",
        "value": "REINITIATED"
      }
    ]
  }'
```

### 5. Check Verification Status

```bash
curl -X GET \
  "https://<IS_HOST>:<PORT>/api/users/v1/me/idv/claims" \
  -H "Authorization: Bearer <access_token>"
```

A successfully verified claim returns:

```json
{
  "uri": "http://wso2.org/claims/givenname",
  "isVerified": true,
  "claimMetadata": {
    "daon_flow_status": "COMPLETED",
    "daon_verification_status": "VERIFIED",
    "daon_completed_at": "2026-04-19T08:30:00Z"
  }
}
```

If the value Daon returned does not match the user's profile attribute, `isVerified` will be `false` and `daon_verification_status` will be `MISMATCH`.

---

## Claim Metadata Reference

The following metadata keys are persisted per claim:

| Key | Description |
|---|---|
| `daon_state` | OIDC state UUID used as CSRF token |
| `daon_flow_status` | `INITIATED` / `REINITIATED` / `COMPLETED` |
| `daon_verification_status` | `VERIFIED` / `MISMATCH` / `FAILED` (set after callback) |
| `daon_completed_at` | ISO-8601 timestamp of callback processing |

> `daon_authorization_url` is returned transiently in the initiation API response but is not stored in the database.

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `404` on callback URL | IdVP ID is in the wrong position in the URL | Correct URL format is `/idv/daon/v1/<idvp-id>/callback` |
| `401` on callback URL | Authorization not disabled for callback endpoint | Add `[[resource.access_control]]` config to `deployment.toml` |
| `401` on token exchange | Wrong `client_id` / `client_secret` | Verify credentials match the Daon TrustX OIDC client |
| `400` on token exchange | Authorization code expired or already used | Re-initiate the flow to get a fresh code |
| `state mismatch` error | User followed a stale authorization URL | Re-initiate to get a new state and URL |
| Claims not verified after callback | Claim name in attribute mapping doesn't match Daon ID token | Check `verifiedClaims.claims` keys in the ID token against your attribute mappings |
| Redirect URI mismatch in Daon | Configured `redirect_uri` doesn't exactly match what's registered | Ensure both values are identical including scheme and port |
| WAR not deploying | Classloading or OSGi dependency issue | Check `$IS_HOME/repository/logs/wso2carbon.log` for errors |
