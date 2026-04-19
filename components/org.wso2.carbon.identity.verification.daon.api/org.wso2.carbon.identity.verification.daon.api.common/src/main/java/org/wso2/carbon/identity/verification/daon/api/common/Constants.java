/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.verification.daon.api.common;

/**
 * Constants used across the Daon identity verification API.
 */
public class Constants {

    public static final String TENANT_NAME_FROM_CONTEXT = "TenantNameFromContext";
    public static final String CORRELATION_ID_MDC = "Correlation-ID";
    public static final String ERROR_PREFIX = "DIDV-";

    /**
     * Enum for identity verification API related errors.
     */
    public enum ErrorMessage {

        // Server errors
        SERVER_ERROR_RESOLVING_IDVP("65001",
                "Identity verification provider retrieval failed.",
                "An error occurred while attempting to resolve the identity verification provider."),
        SERVER_ERROR_RETRIEVING_TENANT("65002",
                "Tenant retrieval failed.",
                "The system encountered an error while retrieving the tenant ID for the tenant domain: %s."),
        SERVER_ERROR_UPDATING_IDV_CLAIM_VERIFICATION_STATUS("65003",
                "Updating identity verification claims failed.",
                "An error occurred while updating the identity verification claims status."),
        SERVER_ERROR_IDV_PROVIDER_CONFIG_PROPERTIES_INVALID("65004",
                "Invalid Daon configuration properties.",
                "One or more Daon identity verification provider configuration properties are invalid or missing."),
        SERVER_ERROR_GENERAL_ERROR("65005",
                "Internal server error.",
                "An unexpected error occurred while processing the request."),
        SERVER_ERROR_TOKEN_EXCHANGE("65006",
                "Token exchange failed.",
                "An error occurred while exchanging the authorization code for tokens with Daon."),
        SERVER_ERROR_USERINFO_RETRIEVAL("65007",
                "User info retrieval failed.",
                "An error occurred while retrieving user info from Daon."),

        // Client errors
        CLIENT_ERROR_RESOLVING_IDVP("60001",
                "Identity verification provider retrieval failed.",
                "The identity verification provider ID in the URL could not be resolved. " +
                        "It may be unavailable or disabled."),
        CLIENT_ERROR_STATE_MISMATCH("60002",
                "State parameter mismatch.",
                "The state parameter in the callback does not match the stored state. " +
                        "Potential CSRF attack detected."),
        CLIENT_ERROR_INVALID_CALLBACK_PARAMS("60003",
                "Invalid callback parameters.",
                "The callback request is missing required parameters (code or state)."),
        CLIENT_ERROR_INVALID_OR_EXPIRED_CODE("60004",
                "Invalid or expired authorization code.",
                "The authorization code provided is invalid or has already been used."),
        CLIENT_ERROR_INVALID_CREDENTIALS("60005",
                "Invalid client credentials.",
                "The Daon client credentials are invalid. Please check the IdV provider configuration."),
        CLIENT_ERROR_INVALID_REQUEST("60006",
                "Invalid request.",
                "The callback request contains invalid input.");

        private final String code;
        private final String message;
        private final String description;

        ErrorMessage(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
        }

        public String getCode() {

            return ERROR_PREFIX + code;
        }

        public String getMessage() {

            return message;
        }

        public String getDescription() {

            return description;
        }

        @Override
        public String toString() {

            return code + " | " + message;
        }
    }
}
