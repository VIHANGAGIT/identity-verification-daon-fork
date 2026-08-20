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
 * Constants used across the Daon TrustX connector. Error codes and messages live in
 * {@link DaonErrorConstants}.
 */
public final class DaonConstants {

    private DaonConstants() {
    }

    public static final String LOGIN_HINT = "login_hint";
    public static final String ACR_VALUES_PARAM = "acr_values";
    public static final String OAUTH2_ERROR_DESCRIPTION = "error_description";

    public static final String CLAIMS_PARAM = "claims";
    public static final String CLAIM_VALUE_MEMBER = "value";
    public static final String VERIFIED_CLAIMS = "verified_claims";
    public static final String VERIFICATION = "verification";
    public static final String TRUST_FRAMEWORK = "trust_framework";
    public static final String TRUST_FRAMEWORK_VALUE = "daon-identify-1";
    public static final String ID_TOKEN_CONTAINER = "id_token";

    public static final String CLAIM_GIVEN_NAME = "given_name";
    public static final String CLAIM_FAMILY_NAME = "family_name";
    public static final String CLAIM_FAMILY_NAME_AND_GIVEN_NAME = "family_name_and_given_name";
    public static final String CLAIM_BIRTHDATE = "birthdate";
    public static final String CLAIM_DOCUMENT_TYPE = "document_type";
    public static final String CLAIM_DOCUMENT_CLASSIFICATION = "document_classification";
    public static final String CLAIM_DOCUMENT_DATE_OF_EXPIRY = "document_date_of_expiry";
    public static final String CLAIM_DOCUMENT_NUMBER = "document_number";
    public static final String CLAIM_DOCUMENT_PERSONAL_NUMBER = "document_personal_number";

    public static final String CLAIM_ADDRESS = "address";
    public static final String CLAIM_ADDRESS_FORMATTED = "formatted";
    public static final String DAON_FIELD_SEPARATOR = "^";

    public static final String JWT_SUBJECT_CLAIM = "sub";
    public static final String JWT_VERIFIED_CLAIMS_OBJECT = "verifiedClaims";
    public static final String JWT_CLAIMS_OBJECT = "claims";
    public static final String JWT_PREFERRED_USERNAME_CLAIM = "preferred_username";

    public static final String AUTHENTICATOR_NAME = "DaonAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Daon TrustX";

    public static final String DAON_LOGIN_PD = "daon_login_pd";
    public static final String DAON_ENROL_PD = "daon_enrol_pd";
    public static final String DAON_IDP_ID = "daon_idp_id";

    /**
     * Adaptive-script parameter asking the login step to enrol rather than re-verify.
     */
    public static final String DAON_RUNTIME_PARAM_ENROL = "enrol";

    /*
     * Internal carrier keys, not connection properties: values passed through the authenticator
     * properties into getAdditionalQueryParams(), whose signature takes nothing else.
     */
    public static final String DAON_SELECTED_PD = "daon_selected_pd";
    public static final String DAON_CLAIMS_REQUEST = "daon_claims_request";
    public static final String DAON_LOGIN_HINT = "daon_login_hint";

    /*
     * Authentication-context markers describing the in-flight authorize request, stashed when it is built
     * and consumed at the callback.
     */
    public static final String DAON_EXPECTED_SUBJECT = "daon_expected_subject";
    public static final String DAON_ENROLLING_USER = "daon_enrolling_user";

    /**
     * The user's own tenant, which the association is keyed on — in a B2B login not the context's, and
     * writing under one while reading under the other leaves the account permanently not-enrolled.
     */
    public static final String DAON_ENROLLING_USER_TENANT = "daon_enrolling_user_tenant";

    /*
     * Flow-context keys carrying the association from DaonExecutor to DaonFederatedAssociationListener.
     */
    public static final String DAON_FED_IDP_NAME = "daon_fed_idp_name";
    public static final String DAON_FED_SUBJECT = "daon_fed_subject";

    public static final String FLOW_TYPE_PASSWORD_RECOVERY = "PASSWORD_RECOVERY";
    public static final String FLOW_TYPE_REGISTRATION = "REGISTRATION";
    public static final String FLOW_TYPE_INVITED_USER_REGISTRATION = "INVITED_USER_REGISTRATION";

    public static final String WSO2_LASTNAME_CLAIM_URI = "http://wso2.org/claims/lastname";
    public static final String WSO2_GIVENNAME_CLAIM_URI = "http://wso2.org/claims/givenname";
}
