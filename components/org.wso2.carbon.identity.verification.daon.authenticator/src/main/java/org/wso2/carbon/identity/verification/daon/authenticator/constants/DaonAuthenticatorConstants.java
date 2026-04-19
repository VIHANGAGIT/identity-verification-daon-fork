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

package org.wso2.carbon.identity.verification.daon.authenticator.constants;

/**
 * Constants for the Daon TrustX federated authenticator.
 */
public class DaonAuthenticatorConstants {

    private DaonAuthenticatorConstants() {
    }

    public static final String AUTHENTICATOR_NAME = "DaonAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Daon TrustX";

    /**
     * The authenticator property key that holds the Daon IdVP UUID.
     * Admins set this to the UUID of the already-configured Daon Identity Verification Provider.
     */
    public static final String DAON_IDVP_ID = "daon_idvp_id";

    /** The /commonauth redirect URI used for the login authentication flow. */
    public static final String COMMON_AUTH_ENDPOINT = "/commonauth";

    /**
     * FlowExecutionContext property keys used to pass verified claim data from {@code DaonExecutor}
     * to {@code DaonRegistrationFlowCompletionListener} within the same flow.
     */
    public static final String FLOW_CONTEXT_DAON_VERIFIED_CLAIMS = "DAON_IDV_CLAIMS";
    public static final String FLOW_CONTEXT_DAON_IDVP_ID = "DAON_IDV_IDVP_ID";

    /**
     * Query parameters on the OIDC callback request.
     */
    public static final String PARAM_CODE = "code";
    public static final String PARAM_STATE = "state";
    public static final String PARAM_SESSION_STATE = "session_state";

    /**
     * Authenticator-specific (login flow) client credentials.
     * The standard ClientId / ClientSecret keys are reserved for the DaonExecutor (signup flow)
     * so that OpenIDConnectExecutor's private auth-URL generation can use them without modification.
     */
    public static final String LOGIN_CLIENT_ID = "daon_login_client_id";
    public static final String LOGIN_CLIENT_SECRET = "daon_login_client_secret";
    public static final String EXECUTOR_SCOPES = "Scopes";

    /**
     * Property key used to pass the comma-separated list of Daon claim names (from the IDVP
     * claim mappings) through the flow context so {@code getAdditionalQueryParams()} can build
     * the {@code claims} request parameter dynamically.
     */
    public static final String DAON_CLAIM_NAMES = "daon_claim_names";

    /**
     * Property key used to carry the resolved {@code login_hint} (Daon {@code preferred_username})
     * into {@code getAdditionalQueryParams()} for the password recovery face-auth flow.
     */
    public static final String DAON_LOGIN_HINT = "daon_login_hint";

    /** Flow type string returned by {@code FlowExecutionContext.getFlowType()} for password recovery. */
    public static final String FLOW_TYPE_PASSWORD_RECOVERY = "PASSWORD_RECOVERY";

    // Claim dialect URI for Daon-specific claims
    public static final String CLAIM_DIALECT_URI = "http://wso2.org/daon/claims";

    // Identity verification provider ID registered in WSO2 IS for Daon
    public static final String DAON_IDV_PROVIDER_ID = "DAON";
    public static final String DAON_IDV_ID = "89463071-0c22-46ad-aed5-c43d11682ab3";

    // Top-level JWT claim field names
    public static final String JWT_SUBJECT_CLAIM = "sub";
    public static final String JWT_VERIFIED_CLAIMS_OBJECT = "verifiedClaims";
    public static final String JWT_CLAIMS_OBJECT = "claims";

    // Daon claim keys inside the "claims" JWT object
    public static final String CLAIM_ADDRESS = "address";
    public static final String CLAIM_ADDRESS_FORMATTED = "formatted";

    public static final String USER_ID_CLAIM = "http://wso2.org/claims/userid";

    // WSO2 standard name claim URIs that may be matched against Daon's combined family_name_and_given_name
    public static final String WSO2_LASTNAME_CLAIM_URI = "http://wso2.org/claims/lastname";
    public static final String WSO2_GIVENNAME_CLAIM_URI = "http://wso2.org/claims/givenname";

    // IS identity claim used to lock a user account
    public static final String ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";

    // Context property key set when IDV claim validation fails (profile vs. Daon-verified values)
    public static final String DAON_CLAIM_MISMATCH_PROPERTY = "daon_claim_mismatch";
}
