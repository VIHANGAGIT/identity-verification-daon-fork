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

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Reads claim values off a user's stored profile. A read that fails is logged and yields no values rather
 * than failing the flow: the value-requests it feeds are a best-effort prefill.
 */
public final class DaonUserClaimReader {

    private static final Log LOG = LogFactory.getLog(DaonUserClaimReader.class);

    private DaonUserClaimReader() {
    }

    /**
     * Reads the given claims for a domain-qualified username.
     *
     * @param subjectDescription the user this read is for, used only in the failure log.
     * @return the non-blank values by claim URI; never {@code null}.
     */
    public static Map<String, String> readByUsername(String tenantDomain, String qualifiedUsername,
                                                     Collection<String> claimUris, String subjectDescription) {

        if (StringUtils.isBlank(qualifiedUsername) || CollectionUtils.isEmpty(claimUris)) {
            return Collections.emptyMap();
        }
        try {
            UserStoreManager userStoreManager = getUserStoreManager(tenantDomain);
            if (userStoreManager == null) {
                return Collections.emptyMap();
            }
            return nonBlankValues(userStoreManager.getUserClaimValues(qualifiedUsername,
                    claimUris.toArray(new String[0]), null));
        } catch (UserStoreException e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_READING_USER_CLAIMS, subjectDescription), e);
            return Collections.emptyMap();
        }
    }

    /**
     * Reads the given claims for a user id. Yields no values when the userstore cannot resolve users by id.
     *
     * @param subjectDescription the user this read is for, used only in the failure log.
     * @return the non-blank values by claim URI; never {@code null}.
     */
    public static Map<String, String> readByUserId(String tenantDomain, String userId,
                                                   Collection<String> claimUris, String subjectDescription) {

        if (StringUtils.isBlank(userId) || CollectionUtils.isEmpty(claimUris)) {
            return Collections.emptyMap();
        }
        try {
            UserStoreManager userStoreManager = getUserStoreManager(tenantDomain);
            if (!(userStoreManager instanceof UniqueIDUserStoreManager)) {
                return Collections.emptyMap();
            }
            return nonBlankValues(((UniqueIDUserStoreManager) userStoreManager)
                    .getUserClaimValuesWithID(userId, claimUris.toArray(new String[0]), null));
        } catch (UserStoreException e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_READING_USER_CLAIMS, subjectDescription), e);
            return Collections.emptyMap();
        }
    }

    private static UserStoreManager getUserStoreManager(String tenantDomain) throws UserStoreException {

        if (DaonConnectorDataHolder.getRealmService() == null) {
            return null;
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        return DaonConnectorDataHolder.getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
    }

    private static Map<String, String> nonBlankValues(Map<String, String> storedClaims) {

        Map<String, String> values = new HashMap<>();
        if (storedClaims == null) {
            return values;
        }
        for (Map.Entry<String, String> claim : storedClaims.entrySet()) {
            if (StringUtils.isNotBlank(claim.getValue())) {
                values.put(claim.getKey(), claim.getValue());
            }
        }
        return values;
    }
}
