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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerClientException;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerException;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.model.FederatedAssociation;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

/**
 * Stores the Daon verification state as a federated identity association.
 */
public final class DaonFederatedAssociationUtil {

    private static final Log LOG = LogFactory.getLog(DaonFederatedAssociationUtil.class);

    private DaonFederatedAssociationUtil() {
    }

    /**
     * Builds the {@link User} an association is keyed on, splitting the userstore domain off the username.
     *
     * @return a user carrying the bare username, its userstore domain and the tenant.
     */
    public static User buildUser(String username, String tenantDomain) {

        User user = new User();
        user.setUserName(UserCoreUtil.removeDomainFromName(username));
        user.setUserStoreDomain(UserCoreUtil.extractDomainFromName(username));
        user.setTenantDomain(tenantDomain);
        return user;
    }

    /**
     * Resolves the flow user's domain-qualified username, from the flow user or the userstore by user id.
     *
     * @return the qualified username, or {@code null} when the flow user carries none.
     */
    public static String resolveQualifiedUsername(FlowUser flowUser, String tenantDomain) {

        if (flowUser == null) {
            return null;
        }
        String username = flowUser.getUsername();
        if (StringUtils.isBlank(username)) {
            return null;
        }
        if (username.contains(UserCoreConstants.DOMAIN_SEPARATOR)) {
            return username;
        }
        if (StringUtils.isNotBlank(flowUser.getUserStoreDomain())) {
            return flowUser.getUserStoreDomain() + UserCoreConstants.DOMAIN_SEPARATOR + username;
        }
        String resolved = resolveDomainQualifiedUsername(flowUser.getUserId(), tenantDomain);
        return resolved != null ? resolved : username;
    }

    private static String resolveDomainQualifiedUsername(String userId, String tenantDomain) {

        if (StringUtils.isBlank(userId) || StringUtils.isBlank(tenantDomain)
                || DaonConnectorDataHolder.getRealmService() == null) {
            return null;
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            UserStoreManager userStoreManager = DaonConnectorDataHolder.getRealmService()
                    .getTenantUserRealm(tenantId).getUserStoreManager();
            if (!(userStoreManager instanceof UniqueIDUserStoreManager)) {
                return null;
            }
            // getDomainQualifiedUsername() rather than getUserNameFromUserID, which is only qualified on
            // one of its two branches.
            org.wso2.carbon.user.core.common.User storeUser =
                    ((UniqueIDUserStoreManager) userStoreManager).getUserWithID(userId, null, null);
            if (storeUser != null && StringUtils.isNotBlank(storeUser.getDomainQualifiedUsername())) {
                return storeUser.getDomainQualifiedUsername();
            }
        } catch (UserStoreException e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_RESOLVING_USER_STORE_DOMAIN), e);
        }
        return null;
    }

    /**
     * Reads the Daon subject from the user's association with the given IDP; {@code null} means not enrolled.
     *
     * @return the recorded subject, or the empty string when the association carries none.
     */
    public static String getAssociatedDaonSubject(User user, String idpName) {

        if (user == null || StringUtils.isBlank(idpName)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Null user or blank IDP name; cannot resolve the Daon verification state.");
            }
            return null;
        }
        FederatedAssociationManager manager = DaonConnectorDataHolder.getFederatedAssociationManager();
        if (manager == null) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_FED_ASSOCIATION_MANAGER_UNAVAILABLE,
                    "cannot resolve the Daon verification state"));
            return null;
        }
        try {
            FederatedAssociation[] associations = manager.getFederatedAssociationsOfUser(user);
            if (associations == null) {
                return null;
            }
            for (FederatedAssociation association : associations) {
                if (association.getIdp() != null && idpName.equals(association.getIdp().getName())) {
                    String subject = association.getFederatedUserId();
                    return subject != null ? subject : StringUtils.EMPTY;
                }
            }
        } catch (FederatedAssociationManagerClientException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not resolve Daon federated associations for the user (the user likely does "
                        + "not exist); treating as not verified. IDP: " + idpName, e);
            }
        } catch (FederatedAssociationManagerException e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_RESOLVING_FED_ASSOCIATION, idpName), e);
        }
        return null;
    }

    /**
     * Looks up the local user that already holds the given Daon subject on the given IDP.
     *
     * @return the username, or {@code null} if unclaimed or the lookup failed.
     */
    public static String getLocalUserForDaonSubject(String tenantDomain, String idpName, String daonSubject) {

        if (StringUtils.isBlank(tenantDomain) || StringUtils.isBlank(idpName)
                || StringUtils.isBlank(daonSubject)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Blank tenant domain, IDP name or Daon subject; cannot resolve the associated user.");
            }
            return null;
        }
        FederatedAssociationManager manager = DaonConnectorDataHolder.getFederatedAssociationManager();
        if (manager == null) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_FED_ASSOCIATION_MANAGER_UNAVAILABLE,
                    "cannot resolve the local user holding the Daon identity"));
            return null;
        }
        try {
            return manager.getUserForFederatedAssociation(tenantDomain, idpName, daonSubject);
        } catch (FederatedAssociationManagerException e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_RESOLVING_FED_ASSOCIATION, idpName), e);
            return null;
        }
    }

    /**
     * Creates the association between the local user and the Daon IDP, logging any failure with its code.
     *
     * @return {@code true} if the association was created.
     */
    public static boolean createAssociation(User user, String idpName, String daonSubject) {

        if (user == null || StringUtils.isBlank(idpName) || StringUtils.isBlank(daonSubject)) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the user, the IDP name or the Daon subject is missing"));
            return false;
        }
        FederatedAssociationManager manager = DaonConnectorDataHolder.getFederatedAssociationManager();
        if (manager == null) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_FED_ASSOCIATION_MANAGER_UNAVAILABLE,
                    "the Daon verification state was not persisted"));
            return false;
        }
        try {
            manager.createFederatedAssociation(user, idpName, daonSubject);
            return true;
        } catch (FederatedAssociationManagerException e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_CREATING_FED_ASSOCIATION, idpName), e);
            return false;
        }
    }
}
