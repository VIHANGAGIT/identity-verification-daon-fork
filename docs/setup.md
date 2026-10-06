# Setup Guide

## Prerequisites

* WSO2 Identity Server 7.4.0 or above, or WSO2 Identity Platform
* JDK 21, Maven 3.6+ (only to build from source)
* A Daon TrustX tenant with admin access, a confidential OIDC client, and at least one **enrol** and
  one **login** process definition

---

## 1. Build

```bash
mvn clean install
```

| Artifact | Location |
|---|---|
| Connector bundle (authenticator + executor) | `components/org.wso2.carbon.identity.verification.daon.connector/target/org.wso2.carbon.identity.verification.daon.connector-*.jar` |
| Release archive (bundle + both connection templates + setup script) | `components/org.wso2.carbon.identity.verification.daon.connector/target/wso2is-daon-connector-*.zip` |

There is **no WAR** — the connector is a single OSGi bundle.

## 2. Deploy

Using the release archive (recommended):

```bash
IS_HOME=/path/to/wso2is

unzip wso2is-daon-connector-*.zip -d $IS_HOME
cd $IS_HOME/wso2is-daon-connector-*
./setup_daon.sh
```

The script moves the bundle into `repository/components/dropins`, both connection templates into
`repository/resources/identity/extensions/connections/`, and the Quick Start illustrations into the
console webapp.

By hand:

```bash
IS_HOME=/path/to/wso2is
C=components/org.wso2.carbon.identity.verification.daon.connector

cp $C/target/org.wso2.carbon.identity.verification.daon.connector-*.jar \
   $IS_HOME/repository/components/dropins/

cp -r $C/resources/daon-idv $C/resources/daon-authenticator \
   $IS_HOME/repository/resources/identity/extensions/connections/

cp -r $C/resources/console-resources/guides/daon \
   $IS_HOME/repository/deployment/server/webapps/console/resources/connections/guides/
```

`connections` is the extension type the console reads connection templates from, as configured in
`ExtensionManagementService.ExtensionTypes` (`repository/conf/identity/identity.xml`) — a template
placed anywhere else is never served. The `guides/daon` SVGs are the illustrations the two Quick Start
tabs reference; the tabs render without them, but with broken images.

> **Upgrading from an earlier build?** The authenticator and connector bundles were consolidated into
> the single `org.wso2.carbon.identity.verification.daon.connector` bundle. Delete any previously
> deployed `org.wso2.carbon.identity.verification.daon.authenticator-*.jar` from `dropins` before
> restarting; leaving it there registers a second authenticator and executor. No reconfiguration is
> needed — the authenticator name (`DaonAuthenticator`), the executor name (`DaonExecutor`) and both
> template ids are unchanged.

Nothing else has to be registered. The verified state is not added to a user claim, so there are no
custom claims to create and no IDVP resource to provision.

> **Portal resource bundles.** User-facing errors are emitted as i18n tokens
> (`{{daon.identity.verification.not.enrolled.message}}` and friends). Without matching entries in the
> authentication and flow portal bundles, the raw token or a generic message is what the user sees.
> `DAON-60008` has no i18n key at all and falls back to the generic `unable.to.proceed` page.

Restart:

```bash
$IS_HOME/bin/wso2server.sh restart
```

---

## 3. Register the OIDC client in Daon TrustX

1. Log in to the Daon TrustX administration console.
2. Create a **confidential** OIDC client.
3. Add the redirect URIs:
   * `https://<is-host>/commonauth` — used by the **login** flows.
   * Your registration/recovery portal callback — used by the **flow** paths.
   * The exact authorized redirect URI is shown on the connection's **Settings** tab in the WSO2
     console once the connection is created; register that value verbatim.
4. Enable the scopes the connector requests: `openid`, `profile`, `document`.
5. Note the **client id**, **client secret**, the **authorization** and **token** endpoint URLs.
6. Note the **enrol** process definition and the **login** process definition, each as
   `<ProcessDefinitionName:Version>` (e.g. `EnrolProcess:1`, `LoginProcess:1`).

> **Client authentication defaults to the request body.** If your Daon client requires HTTP Basic, the
> `IsBasicAuthEnabled` authenticator property has to be set to `true` through the management API —
> there is no console field for it.

📸 *Screenshots:*
* `images/daon-trustx-oidc-client.png` — the Daon OIDC client page: client id, redirect URIs, scopes.
* `images/daon-trustx-process-definitions.png` — the process-definition list with the enrol and login
  PDs and their versions.

---

## 4. Create the Daon TrustX Identity Verifier connection

**Console → Connections → New Connection → Daon TrustX Identity Verifier.**

| Field | Property key | Required | Value |
|---|---|:---:|---|
| Name | — | ✔ | e.g. `Daon TrustX Identity Verifier` |
| Client ID | `ClientId` | ✔ | From the Daon OIDC client |
| Client Secret | `ClientSecret` | ✔ | From the Daon OIDC client |
| Authorization Endpoint URL | `OAuth2AuthzEPUrl` | ✔ | `https://<tenant>.<region>.trustx.com/auth/realms/<tenant>/protocol/openid-connect/auth` |
| Token Endpoint URL | `OAuth2TokenEPUrl` | ✔ | `https://<tenant>.<region>.trustx.com/auth/realms/<tenant>/protocol/openid-connect/token` |
| Scopes | `Scopes` | | `openid profile document` |
| Enrol Process Definition | `daon_enrol_pd` | | `<Name:Version>` — sent as `acr_values` on every enrolment |

Leave **Daon Verifier ID** (`daon_idp_id`) blank — that is what makes this connection
*self-contained* and the anchor for enrolments.

> ### ⚠️ How many Identity Verifier connections should you create?
>
> **Normally exactly one.** An enrolment belongs to the Identity Verifier connection it was made
> through, so a user enrolled through one verifier can only be verified by login connections that
> reference **that same** verifier. A user enrolled through Verifier A reads as "not enrolled"
> (`DAON-60001`) at any login or recovery step whose connection points at Verifier B, and there is no
> sharing, migration or fallback between the two.
>
> Put the variation in the **login** connections instead — create as many as you need, each with its
> own login process definition, all referencing the one verifier. Create a second Identity Verifier
> only when you deliberately want two separate, non-interchangeable enrolment populations, for
> example a different Daon tenant or OIDC client.

After creating it, open the **Settings** tab and copy the **Authorized redirect URI** back into the
Daon OIDC client.

📸 *Screenshots:*
* `images/connections-new-connection.png` — the New Connection gallery with both Daon templates.
* `images/idv-create-wizard.png` — the Identity Verifier create form, filled in.
* `images/idv-settings-tab.png` — the Settings tab, with the Authorized redirect URI highlighted.

---

## 5. Map attributes

On the **Identity Verifier** connection's **Attributes** tab, map Daon claim names to WSO2 local
claims. These mappings do double duty: they decide which attributes Daon is asked about, and how the
verified claims that come back are written to the profile.

**The mappings are the gate.** Only a mapped claim is ever put in the request, and a mapped claim is
sent as a `{"value": …}` **value-request** — the thing Daon actually compares against the document —
only when its value is already known at that point in the flow (collected earlier in a registration
flow, or set on the profile for an invited user). A mapped claim with no known value
is requested as `null`, meaning "read it off the document and return it". An unmapped claim is never
sent, however it was collected, and a connection with no mappings at all sends no `claims` parameter.

| WSO2 local claim | Daon claim name |
|---|---|
| `http://wso2.org/claims/givenname` | `given_name` |
| `http://wso2.org/claims/lastname` | `family_name` |
| `http://wso2.org/claims/dob` | `birthdate` |
| `http://wso2.org/claims/addresses` | `address` |

Notes:

* Mappings are read **only** from the Identity Verifier connection. A login connection's own
  Attributes tab is never consulted.
* When `given_name` or `family_name` is mapped, `family_name_and_given_name` is requested
  automatically as a fallback for documents that store the full name in one field. The connector
  splits it on `^` in ICAO 9303 MRZ order — `<family>^<given>`.
* Daon's `address` object is flattened to its `formatted` member.
* The five document claims are always requested regardless of mapping, but only reach the profile if
  they are mapped.

Constraints worth knowing before you map:

* **The document-verifiable set is fixed in code**: `given_name`, `family_name`,
  `family_name_and_given_name`, `birthdate`, `document_number`, `document_personal_number`. The
  invited-user flow requires at least one of these to be mapped *and* populated,
  otherwise the step refuses to run (`DAON-65023`). Email, phone and address can be verified as
  attributes but do not satisfy that requirement on their own.
* **The composite name split assumes ICAO 9303 order** — `<family>^<given>`, split on the first `^`.
  Documents that emit the reverse order come back with the names swapped.
* **Nested claims are flattened crudely.** Only `address` is understood (reduced to `formatted`); any
  other JSON object claim is stored as its raw JSON string.
* **The trust framework is fixed** to `daon-identify-1`. It is requested on every enrolment and
  validated on every response; a different value fails with `DAON-65022`. It is not configurable.
* **Value-requests travel as raw query parameters.** A value containing `&`, `=`, `${` or
  `$authparam{` is dropped from the request, or makes the request fail outright (`DAON-65029`). Large
  claim sets can also hit URL-length limits at a proxy or at Daon — there is no PAR (pushed
  authorization request) support.

📸 *Screenshot:* `images/idv-attributes-tab.png` — the Attributes tab with the mappings above.

---

## 6. Create the Daon TrustX Authenticator (login) connection

**Console → Connections → New Connection → Daon TrustX Authenticator.**

| Field | Property key | Required | Value |
|---|---|:---:|---|
| Name | — | ✔ | e.g. `Daon TrustX Login` |
| Daon Identity Verifier | `daon_idp_id` | ✔ | Pick the connection from step 4 in the drop-down |
| Login Process Definition | `daon_login_pd` | | `<Name:Version>` — sent as `acr_values` on every re-verification |

The drop-down lists only the Daon Identity Verifier connections of the organization and stores the
selected connection's **resource ID** in `daon_idp_id`.

> The drop-down needs a console built from the patched `identity-apps` fork (the `select` field type
> plus the `optionsSource` resolver). On a stock console the field falls back to a free-text box —
> paste the Identity Verifier connection's resource ID, visible in the console URL when the
> connection is open.

Create as many login connections as you need — one per application, each with its own login PD. They
all resolve their OIDC configuration from, and share the enrolment of, the Identity Verifier they
reference.

Constraints:

* **One enrol PD and one login PD per connection.** Varying the process definition per application
  means a separate login connection per application — which is the intended pattern, since they can
  all reference the same Identity Verifier.
* **Every login connection must reference the verifier its users enrolled through.** Pointing one at a
  different Identity Verifier makes those users read as not enrolled (`DAON-60001`).
* **The login connection and the Identity Verifier it references must live in the same
  tenant/organization.** The reference is resolved by resource ID against the runtime tenant domain.

📸 *Screenshots:*
* `images/authenticator-create-wizard.png` — the create form with the Identity Verifier drop-down open.
* `images/authenticator-settings-tab.png` — the Settings tab showing the Login Process Definition.

---

## 7. Wire the connections into flows

| Flow | Connection to add | Where |
|---|---|---|
| Self-registration | **Identity Verifier** | After attribute collection, before the password step |
| Invited-user registration | **Identity Verifier** | **Before** the set-password step |
| Application login | **Authenticator** (login) | A step **after** the user is identified (e.g. step 2) |
| Password recovery | **Authenticator** (login) | Where the identity check belongs in the recovery flow |

The node appears in the flow composer as **“Daon TrustX Verification”**.

> **The login step cannot be step 1.** It resolves the user from the last authenticated user in the
> context, so it must run after the user has been identified. It is a step-up mechanism, not a login
> mechanism.

📸 *Screenshots:* `images/self-registration-flow-builder.png`,
`images/invited-user-flow-builder.png`, `images/login-flow-step2.png`,
`images/password-recovery-flow-builder.png`.

---

## 8. Verify the deployment

1. Register a test user through the self-registration flow and complete the Daon journey.
2. Confirm the profile carries the document-verified attributes.
3. Confirm the enrolment: **My Account → Linked accounts** shows an association with the Identity
   Verifier connection (or query the SCIM federated-association endpoint for the user).
4. Sign that user into an application whose login flow has the Daon step — the re-verification
   should run with the login PD.
5. Enable diagnostic logs and look for the `outbound-auth-daon` component's
   `bind-daon-verified-identity` and `populate-daon-verified-user-claims` entries.

📸 *Screenshots:* `images/registration-verified-profile.png`,
`images/myaccount-linked-accounts.png`, `images/diagnostic-logs.png`.

### Managing enrolments afterwards

* **There is no unenrol or re-enrol operation.** Clearing a user's verification is done out-of-band,
  from **My Account → Linked accounts** or through the SCIM federated-association API. The connector
  exposes nothing for this.
* **An enrolment carries no expiry or assurance level** — only the fact that the user is enrolled. Any
  "verified within the last N months" policy has to live outside the connector.
