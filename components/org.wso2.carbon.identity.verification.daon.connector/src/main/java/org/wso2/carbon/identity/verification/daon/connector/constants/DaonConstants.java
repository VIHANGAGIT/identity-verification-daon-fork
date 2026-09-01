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
 * Constants used across the Daon TrustX connector, grouped by the wire or store each name belongs to.
 * Error codes and messages live in {@link DaonErrorConstants}.
 */
public final class DaonConstants {

    private DaonConstants() {
    }

    public static final String AUTHENTICATOR_NAME = "DaonAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Daon TrustX";

    /**
     * OIDC request and callback parameter names exchanged with Daon.
     */
    public static class OIDCParams {

        private OIDCParams() {
        }

        public static final String LOGIN_HINT = "login_hint";
        public static final String ACR_VALUES = "acr_values";
        public static final String CLAIMS = "claims";
        public static final String ERROR_DESCRIPTION = "error_description";
    }

    /**
     * Members of the OIDC {@code claims} request parameter that carries the verified-claims value-requests.
     */
    public static class ClaimsRequest {

        private ClaimsRequest() {
        }

        public static final String ID_TOKEN_CONTAINER = "id_token";
        public static final String VERIFIED_CLAIMS = "verified_claims";
        public static final String VERIFICATION = "verification";
        public static final String TRUST_FRAMEWORK = "trust_framework";
        public static final String TRUST_FRAMEWORK_VALUE = "daon-identify-1";
        public static final String VALUE_MEMBER = "value";
    }

    /**
     * Local claim URIs the connector falls back to when the identity provider has no mapping for a Daon claim.
     */
    public static class LocalClaims {

        private LocalClaims() {
        }

        public static final String FIRST_NAME_CLAIM = "http://wso2.org/claims/givenname";
        public static final String LAST_NAME_CLAIM = "http://wso2.org/claims/lastname";
    }

    /**
     * Claim names Daon verifies against the identity document.
     */
    public static class DaonClaims {

        private DaonClaims() {
        }

        public static final String GIVEN_NAME = "given_name";
        public static final String FAMILY_NAME = "family_name";
        public static final String FAMILY_NAME_AND_GIVEN_NAME = "family_name_and_given_name";
        public static final String BIRTHDATE = "birthdate";
        public static final String DOCUMENT_TYPE = "document_type";
        public static final String DOCUMENT_CLASSIFICATION = "document_classification";
        public static final String DOCUMENT_DATE_OF_EXPIRY = "document_date_of_expiry";
        public static final String DOCUMENT_NUMBER = "document_number";
        public static final String DOCUMENT_PERSONAL_NUMBER = "document_personal_number";
        public static final String ADDRESS = "address";
        public static final String ADDRESS_FORMATTED = "formatted";

        /**
         * Separator Daon uses inside a composite claim value, e.g. {@code family_name_and_given_name}.
         */
        public static final String FIELD_SEPARATOR = "^";
    }

    /**
     * Claims read out of the Daon ID token payload.
     */
    public static class IdTokenClaims {

        private IdTokenClaims() {
        }

        public static final String SUBJECT = "sub";
        public static final String PREFERRED_USERNAME = "preferred_username";
        public static final String VERIFIED_CLAIMS_OBJECT = "verifiedClaims";
        public static final String CLAIMS_OBJECT = "claims";
    }

    /**
     * Authenticator configuration properties of a Daon connection.
     */
    public static class ConnectionProperties {

        private ConnectionProperties() {
        }

        public static final String LOGIN_PD = "daon_login_pd";
        public static final String ENROL_PD = "daon_enrol_pd";
        public static final String IDP_ID = "daon_idp_id";
    }

    /**
     * Adaptive-script runtime parameters.
     */
    public static class RuntimeParams {

        private RuntimeParams() {
        }

        /**
         * Asks the login step to enrol rather than re-verify.
         */
        public static final String ENROL = "enrol";
    }

    /**
     * Internal carrier keys, not connection properties: values passed through the authenticator properties
     * into {@code getAdditionalQueryParams()}, whose signature takes nothing else.
     */
    public static class PropertyCarriers {

        private PropertyCarriers() {
        }

        public static final String SELECTED_PD = "daon_selected_pd";
        public static final String CLAIMS_REQUEST = "daon_claims_request";
        public static final String LOGIN_HINT = "daon_login_hint";
    }

    /**
     * Authentication-context markers describing the in-flight authorize request, stashed when it is built
     * and consumed at the callback.
     */
    public static class ContextProperties {

        private ContextProperties() {
        }

        public static final String EXPECTED_SUBJECT = "daon_expected_subject";
        public static final String ENROLLING_USER = "daon_enrolling_user";

        /**
         * The user's own tenant, which the association is keyed on — in a B2B login not the context's, and
         * writing under one while reading under the other leaves the account permanently not-enrolled.
         */
        public static final String ENROLLING_USER_TENANT = "daon_enrolling_user_tenant";
    }

    /**
     * Names the connector's diagnostic logs are published under.
     */
    public static class LogConstants {

        private LogConstants() {
        }

        public static final String OUTBOUND_AUTH_DAON_SERVICE = "outbound-auth-daon";

        /**
         * Steps a diagnostic log is recorded against.
         */
        public static class ActionIDs {

            private ActionIDs() {
            }

            public static final String POPULATE_VERIFIED_CLAIMS = "populate-daon-verified-user-claims";
            public static final String BIND_VERIFIED_IDENTITY = "bind-daon-verified-identity";
        }
    }

    /**
     * Flow types the executor runs in.
     */
    public static class FlowTypes {

        private FlowTypes() {
        }

        public static final String PASSWORD_RECOVERY = "PASSWORD_RECOVERY";
        public static final String REGISTRATION = "REGISTRATION";
        public static final String INVITED_USER_REGISTRATION = "INVITED_USER_REGISTRATION";
    }
}
