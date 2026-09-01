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
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdpManager;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves the OIDC configuration, IDP name and claim mappings for a Daon connection.
 */
public final class DaonReferencedIdpUtil {

    private static final Log LOG = LogFactory.getLog(DaonReferencedIdpUtil.class);

    /**
     * The keys resolved from the referenced connection.
     */
    private static final List<String> REFERENCED_CONFIG_KEYS = Arrays.asList(
            OIDCAuthenticatorConstants.CLIENT_ID,
            OIDCAuthenticatorConstants.CLIENT_SECRET,
            OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL,
            OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL,
            IdentityApplicationConstants.Authenticator.OIDC.SCOPES,
            DaonConstants.ConnectionProperties.ENROL_PD);

    private DaonReferencedIdpUtil() {
    }

    /**
     * The connection's own properties with the referenced connection's OIDC configuration layered on when
     * {@code daon_idp_id} is set.
     */
    public static Map<String, String> buildEffectiveProperties(Map<String, String> props, String tenantDomain) {

        Map<String, String> effectiveProperties = new HashMap<>(props);
        Map<String, String> oidcConfig = resolveEffectiveOidcConfig(props, tenantDomain);
        for (String key : REFERENCED_CONFIG_KEYS) {
            String value = oidcConfig.get(key);
            if (StringUtils.isNotBlank(value)) {
                effectiveProperties.put(key, value);
            }
        }
        return effectiveProperties;
    }

    private static Map<String, String> resolveEffectiveOidcConfig(Map<String, String> props, String tenantDomain) {

        String idpResourceId = props.get(DaonConstants.ConnectionProperties.IDP_ID);
        if (StringUtils.isNotBlank(idpResourceId)) {
            return resolveOidcConfig(idpResourceId, tenantDomain);
        }
        return props;
    }

    private static Map<String, String> resolveOidcConfig(String idpResourceId, String tenantDomain) {

        Map<String, String> config = new HashMap<>();
        if (StringUtils.isBlank(idpResourceId) || StringUtils.isBlank(tenantDomain)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Blank Daon IDP resource id or tenant domain; nothing to resolve.");
            }
            return config;
        }
        IdentityProvider idp = resolveDaonIdp(idpResourceId, tenantDomain);
        if (idp == null) {
            return config;
        }
        FederatedAuthenticatorConfig authConfig = resolveDaonAuthenticatorConfig(idp);
        if (authConfig == null || authConfig.getProperties() == null) {
            LOG.warn(DaonExceptionMgt.errorLog(
                    ErrorMessage.ERROR_REFERENCED_IDP_NO_AUTHENTICATOR_CONFIG, idpResourceId));
            return config;
        }
        for (Property property : authConfig.getProperties()) {
            if (property != null && StringUtils.isNotBlank(property.getName())) {
                config.put(property.getName(), property.getValue());
            }
        }
        return config;
    }

    private static IdentityProvider resolveDaonIdp(String idpResourceId, String tenantDomain) {

        IdpManager idpManager = DaonConnectorDataHolder.getIdpManager();
        if (idpManager == null) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_IDP_MANAGER_UNAVAILABLE, idpResourceId));
            return null;
        }
        try {
            IdentityProvider idp = idpManager.getIdPByResourceId(idpResourceId, tenantDomain, false);
            if (idp == null) {
                LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_REFERENCED_IDP_NOT_FOUND,
                        idpResourceId));
                return null;
            }
            if (resolveDaonAuthenticatorConfig(idp) == null) {
                LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_REFERENCED_IDP_NOT_DAON,
                        idpResourceId));
                return null;
            }
            return idp;
        } catch (IdentityProviderManagementException e) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_RESOLVING_REFERENCED_IDP, idpResourceId), e);
            return null;
        }
    }

    private static FederatedAuthenticatorConfig resolveDaonAuthenticatorConfig(IdentityProvider idp) {

        FederatedAuthenticatorConfig defaultConfig = idp.getDefaultAuthenticatorConfig();
        if (defaultConfig != null && DaonConstants.AUTHENTICATOR_NAME.equals(defaultConfig.getName())) {
            return defaultConfig;
        }
        FederatedAuthenticatorConfig[] configs = idp.getFederatedAuthenticatorConfigs();
        if (configs == null) {
            return null;
        }
        for (FederatedAuthenticatorConfig config : configs) {
            if (config != null && DaonConstants.AUTHENTICATOR_NAME.equals(config.getName())) {
                return config;
            }
        }
        return null;
    }

    /**
     * The referenced connection's name, or {@code null} if unresolvable.
     */
    public static String resolveIdpName(String idpResourceId, String tenantDomain) {

        if (StringUtils.isBlank(idpResourceId) || StringUtils.isBlank(tenantDomain)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Blank Daon IDP resource id or tenant domain; cannot resolve the IDP name.");
            }
            return null;
        }
        IdentityProvider idp = resolveDaonIdp(idpResourceId, tenantDomain);
        return idp != null ? idp.getIdentityProviderName() : null;
    }

    /**
     * The referenced connection's claim mappings.
     */
    public static Map<String, String> resolveClaimMappings(String idpResourceId, String tenantDomain) {

        Map<String, String> mappings = new HashMap<>();
        if (StringUtils.isBlank(idpResourceId) || StringUtils.isBlank(tenantDomain)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Blank Daon IDP resource id or tenant domain; cannot resolve the claim mappings.");
            }
            return mappings;
        }
        IdentityProvider idp = resolveDaonIdp(idpResourceId, tenantDomain);
        if (idp == null || idp.getClaimConfig() == null) {
            return mappings;
        }
        return DaonClaimMappingUtil.toClaimMap(idp.getClaimConfig().getClaimMappings());
    }

    /**
     * The Daon connection name an association is keyed on: the referenced connection's when this is a login
     * connection, otherwise the connection running the step.
     *
     * @param idpResourceId   the {@code daon_idp_id} property, blank for a self-contained connection.
     * @param externalIdpName the name of the connection running the step, used when no reference is set.
     * @return the connection name, or {@code null} if unresolvable.
     */
    public static String resolveDaonIdpName(String idpResourceId, String externalIdpName, String tenantDomain) {

        if (StringUtils.isNotBlank(idpResourceId)) {
            String referencedIdpName = resolveIdpName(idpResourceId, tenantDomain);
            if (StringUtils.isBlank(referencedIdpName) && LOG.isDebugEnabled()) {
                LOG.debug("Could not resolve the referenced Daon IDP name for resource id: " + idpResourceId);
            }
            return referencedIdpName;
        }
        if (StringUtils.isBlank(externalIdpName) && LOG.isDebugEnabled()) {
            LOG.debug("No external IDP on the context; cannot resolve the Daon IDP name.");
        }
        return externalIdpName;
    }
}
