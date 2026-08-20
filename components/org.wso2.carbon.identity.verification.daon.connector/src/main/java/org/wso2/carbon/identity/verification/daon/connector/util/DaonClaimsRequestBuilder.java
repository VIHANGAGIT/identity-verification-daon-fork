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

package org.wso2.carbon.identity.verification.daon.connector.util;

import org.apache.commons.lang.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIMS_PARAM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_BIRTHDATE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_CLASSIFICATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_DATE_OF_EXPIRY;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_NUMBER;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_PERSONAL_NUMBER;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_DOCUMENT_TYPE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_FAMILY_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_FAMILY_NAME_AND_GIVEN_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_GIVEN_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIM_VALUE_MEMBER;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ID_TOKEN_CONTAINER;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.TRUST_FRAMEWORK;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.TRUST_FRAMEWORK_VALUE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.VERIFICATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.VERIFIED_CLAIMS;

/**
 * Builds the OIDC {@code claims} request parameter Daon expects for identity verification.
 */
public final class DaonClaimsRequestBuilder {

    /**
     * Requested alongside the mapped claims, so document details come back regardless of configuration.
     */
    private static final List<String> DOCUMENT_CLAIMS = Arrays.asList(
            CLAIM_DOCUMENT_TYPE,
            CLAIM_DOCUMENT_CLASSIFICATION,
            CLAIM_DOCUMENT_DATE_OF_EXPIRY,
            CLAIM_DOCUMENT_NUMBER,
            CLAIM_DOCUMENT_PERSONAL_NUMBER
    );

    /**
     * The only claims whose value-request proves anything.
     */
    private static final List<String> DOCUMENT_VERIFIABLE_CLAIMS = Arrays.asList(
            CLAIM_GIVEN_NAME,
            CLAIM_FAMILY_NAME,
            CLAIM_FAMILY_NAME_AND_GIVEN_NAME,
            CLAIM_BIRTHDATE,
            CLAIM_DOCUMENT_NUMBER,
            CLAIM_DOCUMENT_PERSONAL_NUMBER
    );

    private DaonClaimsRequestBuilder() {
    }

    /**
     * The Daon claim names a value-request can be checked against an identity document.
     *
     * @return an unmodifiable view of the document-verifiable claims.
     */
    public static List<String> getDocumentVerifiableClaims() {

        return Collections.unmodifiableList(DOCUMENT_VERIFIABLE_CLAIMS);
    }

    /**
     * Whether the values, keyed by Daon claim name, hold at least one attribute Daon can validate against
     * the identity document.
     */
    public static boolean hasDocumentVerifiableValue(Map<String, String> claimValues) {

        if (claimValues == null || claimValues.isEmpty()) {
            return false;
        }
        for (String claimName : DOCUMENT_VERIFIABLE_CLAIMS) {
            if (StringUtils.isNotBlank(claimValues.get(claimName))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Builds the OIDC {@code claims} request parameter.
     */
    public static String buildClaimsParam(List<String> daonClaimNames, Map<String, String> claimValues)
            throws DaonServerException {

        Map<String, String> values = claimValues != null ? claimValues : Collections.emptyMap();
        List<String> effectiveNames =
                new ArrayList<>(daonClaimNames != null ? daonClaimNames : Collections.emptyList());
        // Some documents store the full name as a single field; without this fallback Daon would return
        // neither name claim for those.
        if ((effectiveNames.contains(CLAIM_GIVEN_NAME) || effectiveNames.contains(CLAIM_FAMILY_NAME))
                && !effectiveNames.contains(CLAIM_FAMILY_NAME_AND_GIVEN_NAME)) {
            effectiveNames.add(CLAIM_FAMILY_NAME_AND_GIVEN_NAME);
        }
        for (String docClaim : DOCUMENT_CLAIMS) {
            if (!effectiveNames.contains(docClaim)) {
                effectiveNames.add(docClaim);
            }
        }

        try {
            JSONObject claimsObj = new JSONObject();
            for (String claimName : effectiveNames) {
                String value = values.get(claimName);
                if (StringUtils.isNotBlank(value)) {
                    claimsObj.put(claimName, new JSONObject().put(CLAIM_VALUE_MEMBER, value));
                } else {
                    claimsObj.put(claimName, JSONObject.NULL);
                }
            }
            JSONObject verification = new JSONObject().put(TRUST_FRAMEWORK, TRUST_FRAMEWORK_VALUE);
            JSONObject verifiedClaims = new JSONObject()
                    .put(VERIFICATION, verification)
                    .put(CLAIMS_PARAM, claimsObj);
            JSONObject idToken = new JSONObject().put(VERIFIED_CLAIMS, verifiedClaims);
            return new JSONObject().put(ID_TOKEN_CONTAINER, idToken).toString();
        } catch (JSONException e) {
            throw DaonExceptionMgt.handleServerException(ErrorMessage.ERROR_BUILDING_CLAIMS_REQUEST, e);
        }
    }
}
