# Daon TrustX Connector — Documentation

The Daon TrustX connector adds **document-based identity verification** (passport, driver's licence,
national ID) with **facial biometrics and liveness** to WSO2 Identity Server, as a federated OIDC
connection.

| Document | What it covers |
|---|---|
| [Use cases and flows](use-cases.md) | Every flow the connector supports, with a diagram of each |
| [Setup guide](setup.md) | Build, deploy, register the OIDC client in Daon, create and wire the connections |
| [Troubleshooting](troubleshooting.md) | Symptom → cause → fix, and the full `DAON-*` error catalogue ||

---

## At a glance

The connector ships **one OSGi bundle** exposing **one authenticator** and **one flow executor**, and
**two connection templates** that are both of the same `DaonAuthenticator` type:

| Template | Role | Holds |
|---|---|---|
| **Daon TrustX Identity Verifier** (`daon-idv`) | *Self-contained* — the enrolment anchor | OIDC client id/secret, authorization & token endpoints, scopes, **enrol process definition**, and the **attribute mappings** |
| **Daon TrustX Authenticator** (`daon-authenticator`) | *Referencing* — a login/re-verification connection | A pointer to an Identity Verifier connection (`daon_idp_id`) and a **login process definition** |

A connection is *self-contained* when `daon_idp_id` is blank and *referencing* when it is set. The
runtime branches on that: a referencing connection reads its OIDC credentials, endpoints, scopes,
enrol PD and attribute mappings from the connection it points at, and — crucially — **shares that
connection's enrolment**. Several login connections (one per application, with different login
process definitions) can therefore sit on top of a single enrolment.

## The two request shapes

Everything the connector adds to the stock OIDC authorization request comes down to three
parameters:

| Parameter | Value | Sent when |
|---|---|---|
| `acr_values` | `<ProcessDefinitionName:Version>` — the **enrol PD** or the **login PD** | Always, when a PD is configured |
| `claims` | An OIDC `verified_claims` request under trust framework `daon-identify-1`, with the user's known attributes as **value-requests** | Enrolment (self-registration, invited-user) |
| `login_hint` | The Daon `preferred_username` from the association | Re-verification (login, password recovery) |

Token exchange, `state`/`nonce`/PKCE, ID token validation and standard claim mapping are all left to
the stock WSO2 OIDC authenticator and executor.

## Compatibility

|                        |                                                                                                              |
|------------------------|--------------------------------------------------------------------------------------------------------------|
| WSO2 Identity Server   | 7.4.0 and above                                                                                              |
| WSO2 Identity Platform | Supported                                                                                                    |
| JDK                    | 21                                                                                                           |
| Maven                  | 3.6+                                                                                                         |
| Daon TrustX            | A Daon TrustX tenant with a confidential OIDC client and at least one enrol and one login process definition |
