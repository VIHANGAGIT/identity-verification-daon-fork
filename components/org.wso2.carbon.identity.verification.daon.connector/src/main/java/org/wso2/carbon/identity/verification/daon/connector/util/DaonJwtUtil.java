/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.verification.daon.connector.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Utils for reading Daon ID token payloads and matching the identity a token carries against the one a
 * flow expects.
 */
public final class DaonJwtUtil {

    private static final Log LOG = LogFactory.getLog(DaonJwtUtil.class);

    private DaonJwtUtil() {}

    /**
     * The OIDC base classes have already obtained and validated the token over the back channel; this is a
     * claims read, not a token validation.
     */
    public static JSONObject decodeJwtPayload(String idToken) throws DaonServerException {
        String[] parts = idToken.split("\\.");
        if (parts.length < 2) {
            throw DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_INVALID_ID_TOKEN, parts.length);
        }
        try {
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            return new JSONObject(new String(payload, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException | JSONException e) {
            throw DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_DECODING_ID_TOKEN, e);
        }
    }

    /**
     * Daon nests these as {@code verifiedClaims.claims}. Either level being absent means the token carries no
     * verification result.
     */
    public static JSONObject extractVerifiedClaims(JSONObject idTokenPayload, String flowType)
            throws DaonServerException {

        if (idTokenPayload == null || !idTokenPayload.has(DaonConstants.IdTokenClaims.VERIFIED_CLAIMS_OBJECT)) {
            throw DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_VERIFIED_CLAIMS_NOT_FOUND,
                    flowType);
        }
        JSONObject verifiedClaims = idTokenPayload.optJSONObject(DaonConstants.IdTokenClaims.VERIFIED_CLAIMS_OBJECT);
        if (verifiedClaims == null) {
            throw DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_VERIFIED_CLAIMS_NOT_FOUND,
                    flowType);
        }
        validateTrustFramework(verifiedClaims);
        JSONObject claims = verifiedClaims.optJSONObject(DaonConstants.IdTokenClaims.CLAIMS_OBJECT);
        if (claims == null) {
            throw DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_VERIFIED_CLAIMS_NOT_FOUND,
                    flowType);
        }
        return claims;
    }

    private static void validateTrustFramework(JSONObject verifiedClaims) throws DaonServerException {

        JSONObject verification = verifiedClaims.optJSONObject(DaonConstants.ClaimsRequest.VERIFICATION);
        String trustFramework = verification != null
                ? verification.optString(DaonConstants.ClaimsRequest.TRUST_FRAMEWORK, null) : null;
        if (trustFramework == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("The Daon ID token carries no verification.trust_framework descriptor; accepting the "
                        + "verified claims on the 'claims' object alone.");
            }
            return;
        }
        if (!DaonConstants.ClaimsRequest.TRUST_FRAMEWORK_VALUE.equals(trustFramework)) {
            throw DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_TRUST_FRAMEWORK_MISMATCH,
                    trustFramework, DaonConstants.ClaimsRequest.TRUST_FRAMEWORK_VALUE);
        }
    }

    /**
     * Resolves a claim value to a plain string, flattening Daon's {@code address} object to its
     * {@code formatted} field.
     */
    public static String resolveClaimValue(String key, Object value) {
        if (value == null || JSONObject.NULL.equals(value)) {
            return null;
        }
        if (value instanceof JSONObject) {
            JSONObject nested = (JSONObject) value;
            if (DaonConstants.DaonClaims.ADDRESS.equals(key)
                    && nested.has(DaonConstants.DaonClaims.ADDRESS_FORMATTED)) {
                Object formatted = nested.get(DaonConstants.DaonClaims.ADDRESS_FORMATTED);
                return formatted != null && !JSONObject.NULL.equals(formatted) ? formatted.toString() : null;
            }
            return nested.toString();
        }
        return value.toString();
    }

    /**
     * {@code login_hint} is only a hint per OIDC, so without this anyone who verifies their own enrolled
     * identity satisfies identity proofing for any other user.
     */
    public static boolean isExpectedSubject(String expectedSubject, String returnedPreferredUsername) {

        if (StringUtils.isBlank(expectedSubject) || StringUtils.isBlank(returnedPreferredUsername)) {
            return false;
        }
        return expectedSubject.trim().equalsIgnoreCase(returnedPreferredUsername.trim());
    }
}
