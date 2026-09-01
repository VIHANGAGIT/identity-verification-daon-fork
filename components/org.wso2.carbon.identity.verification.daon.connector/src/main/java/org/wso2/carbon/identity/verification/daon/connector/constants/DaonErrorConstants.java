/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.verification.daon.connector.constants;

/**
 * Error catalogue for the connector.
 */
public final class DaonErrorConstants {

    public static final String DAON_ERROR_PREFIX = "DAON-";

    private DaonErrorConstants() {
    }

    /**
     * {@code message} is the user-safe title, {@code description} the diagnostic detail, and {@code i18nKey}
     * the portal bundle entry.
     */
    public enum ErrorMessage {

        // Client errors - DAON-60xxx.

        ERROR_USER_NOT_ENROLLED("60001",
                "Your account is not enrolled with Daon TrustX for identity verification. "
                        + "Please contact your administrator.",
                "No Daon federated association exists for the user in the %s flow.",
                "daon.identity.verification.not.enrolled"),

        ERROR_VERIFICATION_CANCELLED("60002",
                "Identity verification was cancelled or not completed. Please try again.",
                "Daon returned the access_denied error on the callback; the user cancelled or "
                        + "declined the verification.",
                "daon.identity.verification.cancelled"),

        ERROR_CLAIMS_VERIFICATION_MISMATCH("60003",
                "The details you entered do not match your identity document. "
                        + "Please check your information and try again.",
                "Daon reported CLAIMS_VERIFICATION_MISMATCH: the claim values sent as OIDC "
                        + "value-requests did not match the identity document.",
                "daon.identity.verification.details.mismatch"),

        ERROR_IDENTITY_VERIFICATION_FAILED("60004",
                "Your identity could not be verified. Please try again or contact support.",
                "Daon returned the FailedToVerifyUser error on the callback.",
                "daon.identity.verification.failed"),

        ERROR_VERIFICATION_NOT_COMPLETED("60005",
                "Identity verification could not be completed. Please try again or contact support.",
                "Daon returned an unrecognised error on the callback. error: %s, error_description: %s",
                "daon.identity.verification.failed"),

        ERROR_RECOVERY_IDENTITY_MISMATCH("60006",
                "Identity verification failed: the verified identity does not match the user being "
                        + "recovered.",
                "The identity Daon verified does not match the Daon subject recorded for the account "
                        + "being recovered.",
                "daon.identity.verification.identity.mismatch"),

        ERROR_LOGIN_IDENTITY_MISMATCH("60008",
                "Identity verification failed: the verified identity does not match the account you are "
                        + "signing in to.",
                "The identity Daon verified does not match the Daon subject recorded for the "
                        + "authenticating user. The compared identifiers are logged at debug level, so "
                        + "this line carries no personal identifier."),

        ERROR_ALREADY_ENROLLED("60009",
                "Your account is already enrolled for identity verification. Please complete the "
                        + "verification, or contact your administrator if you cannot.",
                "An enrolment was requested for a user who already has a Daon federated association on "
                        + "IDP: %s. Refusing to enrol a second identity for the account."),

        ERROR_DAON_IDENTITY_ALREADY_ENROLLED("60010",
                "The verified identity is already enrolled for another account. "
                        + "Please contact your administrator.",
                "The Daon subject returned by the enrolment is already associated with a different local "
                        + "user on IDP: %s"),

        // Server errors - DAON-65xxx.

        ERROR_OIDC_CONFIG_NOT_RESOLVED("65001",
                "Could not resolve the Daon OIDC configuration. For a login connection, check the Daon "
                        + "Verifier ID it references; for a Daon Identity Verifier connection, check its own "
                        + "client id and endpoint configuration.",
                "The resolved authenticator properties are missing the client id or the %s endpoint."),

        ERROR_ID_TOKEN_NOT_FOUND("65002",
                "ID token not found in the Daon token response.",
                "Daon did not return an id_token in the token response for the %s flow."),

        ERROR_INVALID_ID_TOKEN("65003",
                "The Daon ID token is malformed.",
                "Invalid JWT: expected at least 2 segments, got %s."),

        ERROR_DECODING_ID_TOKEN("65004",
                "Could not decode the Daon ID token.",
                "Failed to Base64URL-decode or parse the payload segment of the Daon ID token."),

        ERROR_SUBJECT_CLAIM_NOT_FOUND("65005",
                "Subject claim not found in the Daon ID token.",
                "The 'sub' claim is missing from the Daon ID token in the %s flow."),

        ERROR_NO_SUBJECT_IDENTITY_IN_ID_TOKEN("65006",
                "No subject identity found in the Daon ID token.",
                "The 'preferred_username' claim is not present in the Daon ID token returned for "
                        + "password recovery."),

        ERROR_IDP_MANAGER_UNAVAILABLE("65007",
                "The identity provider management service is unavailable.",
                "IdpManager is not available; cannot resolve the referenced Daon IDP: %s"),

        ERROR_RESOLVING_REFERENCED_IDP("65008",
                "Could not resolve the referenced Daon identity provider.",
                "Error resolving the referenced Daon IDP for resource id: %s"),

        ERROR_REFERENCED_IDP_NOT_FOUND("65009",
                "The referenced Daon identity provider was not found.",
                "No identity provider exists for the referenced Daon resource id: %s"),

        ERROR_REFERENCED_IDP_NO_AUTHENTICATOR_CONFIG("65010",
                "The referenced Daon identity provider has no authenticator configuration.",
                "The referenced Daon IDP has no federated authenticator configuration: %s"),

        ERROR_FED_ASSOCIATION_MANAGER_UNAVAILABLE("65011",
                "The federated association management service is unavailable.",
                "FederatedAssociationManager is not available; %s"),

        ERROR_RESOLVING_FED_ASSOCIATION("65012",
                "Could not resolve the Daon federated association.",
                "Error resolving the Daon federated association for IDP: %s; treating the user as "
                        + "not verified."),

        ERROR_CREATING_FED_ASSOCIATION("65013",
                "Could not create the Daon federated association.",
                "Error creating the Daon federated association for IDP: %s (the association may "
                        + "already exist)."),

        ERROR_PERSISTING_FED_ASSOCIATION("65014",
                "The Daon verification could not be recorded for the user.",
                "The Daon federated association could not be persisted because %s."),

        ERROR_READING_USER_CLAIMS("65015",
                "Could not read the user's stored claims.",
                "Error reading the stored claims of %s; the corresponding Daon claim value-requests will "
                        + "not be sent, so fewer attributes are verified against the identity document."),

        ERROR_BUILDING_CLAIMS_REQUEST("65017",
                "Could not build the Daon claims request.",
                "Error building the OIDC claims request parameter for the Daon authorization request."),

        ERROR_ACTIVATING_BUNDLE("65020",
                "Could not activate the Daon connector bundle.",
                "Error registering the Daon connector OSGi services; the bundle is active but one or "
                        + "more services may be unregistered."),

        ERROR_VERIFIED_CLAIMS_NOT_FOUND("65021",
                "Daon did not return any verified identity claims.",
                "The Daon ID token for the %s flow carries no 'verifiedClaims' (or no nested 'claims') "
                        + "object, so the verification cannot be treated as successful."),

        ERROR_TRUST_FRAMEWORK_MISMATCH("65022",
                "Daon verified the identity under an unexpected trust framework.",
                "The Daon ID token reports trust_framework '%s' but '%s' was requested; the verification "
                        + "does not meet the expected assurance."),

        ERROR_NO_VERIFIABLE_CLAIM_VALUES("65023",
                "There are no identity attributes to verify against the user's identity document. "
                        + "Check the Daon connection's attribute mappings.",
                "The %s flow sends the user's known attributes to Daon as OIDC claim value-requests, but "
                        + "none of the mapped attributes with a value is document-verifiable, so Daon "
                        + "would have nothing to validate the profile against."),

        ERROR_ENROL_PD_NOT_CONFIGURED("65024",
                "No Daon enrol process definition is configured.",
                "An enrolment was requested at the login step, but no enrol process definition could be "
                        + "resolved from the referenced Daon Identity Verifier connection."),

        ERROR_ENROLMENT_IDENTITY_NOT_RETURNED("65025",
                "Daon did not return an identity to enrol.",
                "The 'preferred_username' claim is not present in the Daon ID token returned for the "
                        + "enrolment, so there is no Daon subject to record for the user."),

        ERROR_REFERENCED_IDP_NOT_DAON("65027",
                "The referenced connection is not a Daon Identity Verifier connection. Check the Daon "
                        + "Verifier ID configured on this connection.",
                "The connection referenced by resource id %s carries no Daon federated authenticator "
                        + "configuration, so it is not a Daon connection and its OIDC client configuration "
                        + "must not be used to build a Daon verification request."),

        ERROR_RESOLVING_USER_STORE_DOMAIN("65028",
                "Could not resolve the user's userstore domain.",
                "Error resolving the userstore domain of the flow user by user id; the Daon association "
                        + "will be keyed on the unqualified username, which resolves to the primary "
                        + "userstore.");

        private final String code;
        private final String message;
        private final String description;
        private final String i18nKey;

        ErrorMessage(String code, String message, String description) {

            this(code, message, description, null);
        }

        ErrorMessage(String code, String message, String description, String i18nKey) {

            this.code = code;
            this.message = message;
            this.description = description;
            this.i18nKey = i18nKey;
        }

        /**
         * @return the prefixed error code, e.g. {@code DAON-65002}.
         */
        public String getCode() {

            return DAON_ERROR_PREFIX + code;
        }

        /**
         * @return the short title; for client errors this is the user-facing text.
         */
        public String getMessage() {

            return message;
        }

        /**
         * @return the diagnostic detail, possibly carrying {@code %s} placeholders.
         */
        public String getDescription() {

            return description;
        }

        /**
         * @return the portal resource bundle key, or {@code null} when this error is not user-facing.
         */
        public String getI18nKey() {

            return i18nKey;
        }

        /**
         * The heading the portal renders. The {@code {{ }}} wrapping is what marks it user-facing.
         */
        public String getUserMessageToken() {

            return i18nKey == null ? null : "{{" + i18nKey + ".message}}";
        }

        /**
         * The body the portal renders, wrapped as with {@link #getUserMessageToken()}.
         *
         * @return e.g. {@code {{daon.identity.verification.cancelled.description}}}, or {@code null}.
         */
        public String getUserDescriptionToken() {

            return i18nKey == null ? null : "{{" + i18nKey + ".description}}";
        }

        @Override
        public String toString() {

            return getCode() + " - " + message;
        }
    }
}
