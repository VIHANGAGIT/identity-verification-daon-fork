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
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import java.util.HashMap;
import java.util.Map;

/**
 * Reads a connection's claim mappings and re-keys claim values between the local and Daon vocabularies.
 */
public final class DaonClaimMappingUtil {

    private DaonClaimMappingUtil() {
    }

    /**
     * Reads an IDP's claim mappings, skipping any entry missing either side.
     *
     * @return a map of local claim URI to Daon claim name; never {@code null}.
     */
    public static Map<String, String> toClaimMap(ClaimMapping[] claimMappings) {

        Map<String, String> mappings = new HashMap<>();
        if (claimMappings == null) {
            return mappings;
        }
        for (ClaimMapping claimMapping : claimMappings) {
            if (claimMapping == null || claimMapping.getLocalClaim() == null
                    || claimMapping.getRemoteClaim() == null) {
                continue;
            }
            String localClaimUri = claimMapping.getLocalClaim().getClaimUri();
            String remoteClaimUri = claimMapping.getRemoteClaim().getClaimUri();
            if (StringUtils.isNotBlank(localClaimUri) && StringUtils.isNotBlank(remoteClaimUri)) {
                mappings.put(localClaimUri, remoteClaimUri);
            }
        }
        return mappings;
    }

    /**
     * Inverts a claim map so Daon claim names returned on an ID token can be read back as local claim URIs.
     *
     * @return a map of Daon claim name to local claim URI; never {@code null}.
     */
    public static Map<String, String> invert(Map<String, String> claimMappings) {

        Map<String, String> inverted = new HashMap<>();
        if (claimMappings == null) {
            return inverted;
        }
        for (Map.Entry<String, String> entry : claimMappings.entrySet()) {
            inverted.put(entry.getValue(), entry.getKey());
        }
        return inverted;
    }

    /**
     * Re-keys values held by local claim URI into values held by Daon claim name, trimming each value and
     * dropping the ones the user's profile does not carry.
     *
     * @param claimMappings local claim URI to Daon claim name.
     * @param localValues   values by local claim URI.
     * @return the value-requests keyed by Daon claim name; never {@code null}.
     */
    public static Map<String, String> toDaonClaimValues(Map<String, String> claimMappings,
                                                        Map<String, String> localValues) {

        Map<String, String> valuesByDaonName = new HashMap<>();
        if (claimMappings == null || localValues == null) {
            return valuesByDaonName;
        }
        for (Map.Entry<String, String> mapping : claimMappings.entrySet()) {
            String value = localValues.get(mapping.getKey());
            if (StringUtils.isNotBlank(value)) {
                valuesByDaonName.put(mapping.getValue(), value.trim());
            }
        }
        return valuesByDaonName;
    }
}
