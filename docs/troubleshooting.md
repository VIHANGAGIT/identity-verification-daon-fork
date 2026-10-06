# Troubleshooting

## Symptom → cause → fix

| Symptom | Likely cause | Fix |
|---|---|---|
| Redirect to Daon fails, or the endpoint is missing | Authorization/token endpoint blank on the connection | Set the OIDC endpoint URLs on the Identity Verifier connection's **Settings** tab |
| `401` on the token exchange | Wrong client id or secret | Check them against the Daon OIDC client |
| `401` on the token exchange with the right credentials | The Daon client requires HTTP Basic client authentication; the stock OIDC authenticator sends credentials in the request body | Set the `IsBasicAuthEnabled` authenticator property to `true` on the connection via the management API |
| Redirect URI mismatch reported by Daon | The registered `redirect_uri` differs | Register the exact **Authorized redirect URI** shown on the connection's Settings tab |
| No `acr_values` on the authorize request | Process definition not configured | Set the enrol PD on the Identity Verifier connection, or the login PD on the login connection |
| Enrolment runs plain OIDC with no Daon verification | An ordinary OIDC connection was added to the flow instead of a Daon one | Only a `DaonAuthenticator`-type connection binds `DaonExecutor` — use a **Daon TrustX Identity Verifier** connection |
| Login says "not enrolled" for a user who *was* enrolled | The login connection points at a different Identity Verifier than the one used to enrol | Point every connection at the same Identity Verifier; the association is keyed on its name |
| Login/recovery fails with "not enrolled with Daon" | The user has no association, or `FederatedAssociationManager` is unavailable | Enrol through a registration flow first; confirm the Daon step runs *after* the user is identified |
| Verified attributes are not written to the profile | The attribute mapping is missing, or the flow is invited-user (which validates only) | Add the mapping on the **Identity Verifier** connection's Attributes tab; note invited-user never provisions |
| Given name and surname are swapped | The document emits `family_name_and_given_name` in a non-ICAO order | The connector splits on `^` as `<family>^<given>`; adjust the mapping or the split in `DaonExecutor#populateNameClaims` |
| The Identity Verifier drop-down is a plain text box | The console is not built from the patched `identity-apps` fork | Paste the Identity Verifier connection's resource ID (visible in the console URL) into the field |
| Users see a raw `{{daon.…}}` token instead of a message | The portal resource bundle has no entry for that i18n key | Add the key to the authentication/flow portal bundle |

## Where to look

* **Diagnostic logs** — component `outbound-auth-daon`, actions `bind-daon-verified-identity` and
  `populate-daon-verified-user-claims`.
* **Debug logging** — enable `org.wso2.carbon.identity.verification.daon.connector` at `DEBUG` to see
  which claim mappings resolved, which had values, and the compared identity values (masked unless log
  masking is off).
* **Association state** — **My Account → Linked accounts**, or the SCIM federated-association API for
  the user.

---

## Error catalogue

### Client errors — `DAON-60xxx`

These are shown to the user (via the retry page or the flow portal) and generally mean the user, or
the data they were given, is at fault.

| Code | Meaning | What to do |
|---|---|---|
| `DAON-60001` | No Daon association exists for the user in this flow | Enrol the user through a registration flow |
| `DAON-60002` | Daon returned `access_denied` — the user cancelled or declined | Retry |
| `DAON-60003` | `CLAIMS_VERIFICATION_MISMATCH` — the values sent as value-requests did not match the document | Correct the profile the admin set (invited-user), or the details the user entered |
| `DAON-60004` | Daon returned `FailedToVerifyUser` | Retry, or escalate to support |
| `DAON-60005` | Daon returned an unrecognised error | Read `error` / `error_description` from the log line |
| `DAON-60006` | Recovery: the verified identity ≠ the Daon subject recorded for the account | The wrong person completed the verification |
| `DAON-60008` | Login: the verified identity ≠ the Daon subject recorded for the account | Same, at the login step. Compared identifiers are at `DEBUG` |

### Server errors — `DAON-65xxx`

These indicate configuration or infrastructure problems.

| Code | Meaning |
|---|---|
| `DAON-65001` | Client id or the authorization/token endpoint could not be resolved. For a login connection check its **Daon Verifier ID**; for an Identity Verifier check its own OIDC fields |
| `DAON-65002` | No `id_token` in the Daon token response |
| `DAON-65003` | The ID token is malformed (fewer than two JWT segments) |
| `DAON-65004` | The ID token payload could not be Base64URL-decoded or parsed |
| `DAON-65005` | The `sub` claim is missing from the ID token |
| `DAON-65006` | The `preferred_username` claim is missing from the ID token |
| `DAON-65007` | `IdpManager` is unavailable — the referenced connection cannot be resolved |
| `DAON-65008` | Error resolving the referenced Daon connection |
| `DAON-65009` | No connection exists for the configured `daon_idp_id` |
| `DAON-65010` | The referenced connection has no federated authenticator configuration |
| `DAON-65011` | `FederatedAssociationManager` is unavailable |
| `DAON-65012` | Error reading the federated association — the user is treated as not verified |
| `DAON-65013` | Error creating the federated association (it may already exist) |
| `DAON-65014` | The verification could not be recorded for the user |
| `DAON-65015` | The user's stored claims could not be read, so fewer attributes are verified |
| `DAON-65017` | The OIDC `claims` request parameter could not be built |
| `DAON-65020` | The connector bundle failed to register its OSGi services |
| `DAON-65021` | The ID token carries no `verifiedClaims` (or no nested `claims`) object |
| `DAON-65022` | The ID token reports a `trust_framework` other than `daon-identify-1` |
| `DAON-65023` | None of the mapped, populated attributes is document-verifiable — Daon would have nothing to validate against |
| `DAON-65025` | Daon returned no `preferred_username`, so there is no identity to record |
| `DAON-65027` | The connection referenced by `daon_idp_id` is not a Daon connection |
| `DAON-65028` | The flow user's userstore domain could not be resolved; the association falls back to the primary userstore |
| `DAON-65029` | A process definition, subject or claim value contains a character sequence that cannot be carried in the authorization request's query parameters; the request is refused rather than built |
