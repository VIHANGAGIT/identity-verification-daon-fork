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

package org.wso2.carbon.identity.verification.daon.authenticator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.extension.identity.verification.mgt.IdentityVerificationManager;
import org.wso2.carbon.extension.identity.verification.mgt.exception.IdentityVerificationException;
import org.wso2.carbon.extension.identity.verification.mgt.model.IdVClaim;
import org.wso2.carbon.extension.identity.verification.provider.exception.IdVProviderMgtException;
import org.wso2.carbon.extension.identity.verification.provider.model.IdVConfigProperty;
import org.wso2.carbon.extension.identity.verification.provider.model.IdVProvider;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants;
import org.wso2.carbon.identity.verification.daon.authenticator.internal.DaonAuthenticatorDataHolder;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonClientException;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;
import org.wso2.carbon.identity.verification.daon.connector.web.DaonAPIClient;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.COMMON_AUTH_ENDPOINT;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.DAON_IDVP_ID;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.LOGIN_CLIENT_ID;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.LOGIN_CLIENT_SECRET;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.PARAM_CODE;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.PARAM_STATE;

/**
 * Daon TrustX federated authenticator.
 *
 * <p>Performs an OIDC Authorization Code flow against the Daon TrustX authorization server.
 * Configuration (Client ID, Client Secret, endpoints) is read directly from the authenticator
 * properties stored in the connection, following the standard WSO2 IS federated authenticator pattern.
 *
 * <p>When {@code daon_idvp_id} is configured and a prior authentication step has established the
 * user's identity, the authenticator looks up the user's Daon {@code preferred_username} from the
 * IDV claim store and passes it as {@code login_hint} so Daon can match the face against the
 * user's previously verified identity.
 */
public class DaonAuthenticator extends OpenIDConnectAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(DaonAuthenticator.class);
    private static final long serialVersionUID = 1L;

    @Override
    public String getName() {
        return DaonAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return DaonAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {
        return StringUtils.isNotBlank(request.getParameter(PARAM_CODE))
                && StringUtils.isNotBlank(request.getParameter(PARAM_STATE));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(PARAM_STATE);
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> props = context.getAuthenticatorProperties();
        String clientId = props.get(LOGIN_CLIENT_ID);
        String idvpId = props.get(DAON_IDVP_ID);
        Map<String, String> idvpConfig = resolveIdvpConfig(idvpId, context.getTenantDomain());
        String authEndpoint = idvpConfig.get(DaonConstants.AUTHORIZATION_ENDPOINT_URL);
        if (StringUtils.isBlank(authEndpoint)) {
            throw new AuthenticationFailedException("Authorization endpoint not configured in Daon IDVP.");
        }
        String redirectUri = buildCallbackUrl(request);
        String state = context.getContextIdentifier();

        String loginHint = resolveLoginHint(context, idvpId);

        try {
            StringBuilder url = new StringBuilder(authEndpoint)
                    .append("?response_type=code")
                    .append("&client_id=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8))
                    .append("&scope=openid")
                    .append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8))
                    .append("&redirect_uri=").append(URLEncoder.encode(redirectUri, StandardCharsets.UTF_8));
            if (StringUtils.isNotBlank(loginHint)) {
                url.append("&login_hint=").append(URLEncoder.encode(loginHint, StandardCharsets.UTF_8));
            }
            response.sendRedirect(url.toString());
            context.setCurrentAuthenticator(getName());
        } catch (IOException e) {
            throw new AuthenticationFailedException("Failed to redirect to Daon authorization URL.", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        String code = request.getParameter(PARAM_CODE);
        String state = request.getParameter(PARAM_STATE);

        if (!context.getContextIdentifier().equals(state)) {
            throw new AuthenticationFailedException("State parameter mismatch in Daon callback.");
        }

        Map<String, String> props = context.getAuthenticatorProperties();
        String clientId = props.get(LOGIN_CLIENT_ID);
        String clientSecret = props.get(LOGIN_CLIENT_SECRET);
        String idvpId = props.get(DAON_IDVP_ID);
        Map<String, String> idvpConfig = resolveIdvpConfig(idvpId, context.getTenantDomain());
        String tokenEndpoint = idvpConfig.get(DaonConstants.TOKEN_ENDPOINT_URL);
        if (StringUtils.isBlank(tokenEndpoint)) {
            throw new AuthenticationFailedException("Token endpoint not configured in Daon IDVP.");
        }
        String redirectUri = buildCallbackUrl(request);

        JSONObject idTokenClaims;
        try {
            JSONObject tokenResponse = DaonAPIClient.exchangeCodeForTokens(
                    tokenEndpoint, clientId, clientSecret, code, redirectUri);
            String idToken = tokenResponse.optString(DaonConstants.ID_TOKEN);
            idTokenClaims = DaonAPIClient.parseIdToken(idToken);
        } catch (DaonClientException | DaonServerException e) {
            throw new AuthenticationFailedException("Failed to exchange code for tokens.", e);
        }

        String subject = idTokenClaims.optString(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM,
                idTokenClaims.optString("sub", null));
        if (StringUtils.isBlank(subject)) {
            throw new AuthenticationFailedException("No subject found in Daon ID token.");
        }

        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subject);
        context.setSubject(authenticatedUser);
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> properties = new ArrayList<>();

        // Login flow credentials (used by DaonAuthenticator for authentication)
        Property loginClientId = new Property();
        loginClientId.setName(LOGIN_CLIENT_ID);
        loginClientId.setDisplayName("Login Client Id");
        loginClientId.setRequired(true);
        loginClientId.setDescription("Daon TrustX OIDC Client ID for the login (face auth) flow.");
        loginClientId.setDisplayOrder(0);
        properties.add(loginClientId);

        Property loginClientSecret = new Property();
        loginClientSecret.setName(LOGIN_CLIENT_SECRET);
        loginClientSecret.setDisplayName("Login Client Secret");
        loginClientSecret.setRequired(true);
        loginClientSecret.setConfidential(true);
        loginClientSecret.setDescription("Daon TrustX OIDC Client Secret for the login (face auth) flow.");
        loginClientSecret.setDisplayOrder(1);
        properties.add(loginClientSecret);

        Property idvpIdProp = new Property();
        idvpIdProp.setName(DAON_IDVP_ID);
        idvpIdProp.setDisplayName("Daon IdVP ID");
        idvpIdProp.setRequired(true);
        idvpIdProp.setDescription("UUID of the Daon IDV Provider. Used to look up sign-up flow " +
                "credentials and to resolve the user's preferred_username for login_hint.");
        idvpIdProp.setDisplayOrder(2);
        properties.add(idvpIdProp);

        return properties;
    }

    private Map<String, String> resolveIdvpConfig(String idvpId, String tenantDomain)
            throws AuthenticationFailedException {

        if (StringUtils.isBlank(idvpId)) {
            throw new AuthenticationFailedException("Daon IdVP ID is not configured in the connection.");
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            IdVProvider idVProvider = DaonAuthenticatorDataHolder.getIdVProviderManager()
                    .getIdVProvider(idvpId, tenantId);
            if (idVProvider == null) {
                throw new AuthenticationFailedException("Daon IDVP not found for id: " + idvpId);
            }
            Map<String, String> config = new HashMap<>();
            for (IdVConfigProperty prop : idVProvider.getIdVConfigProperties()) {
                config.put(prop.getName(), prop.getValue());
            }
            return config;
        } catch (IdVProviderMgtException e) {
            throw new AuthenticationFailedException("Error loading Daon IDVP config for id: " + idvpId, e);
        }
    }

    /**
     * Looks up the stored Daon {@code preferred_username} for the prior-step authenticated user
     * to use as {@code login_hint} in the authorize request.
     *
     * @return the preferred_username value, or {@code null} if unavailable
     */
    private String resolveLoginHint(AuthenticationContext context, String idvpId) {

        AuthenticatedUser user = context.getLastAuthenticatedUser();
        if (user == null) {
            return null;
        }

        IdentityVerificationManager manager = DaonAuthenticatorDataHolder.getIdentityVerificationManager();
        if (manager == null) {
            LOG.warn("IdentityVerificationManager unavailable; proceeding without login_hint.");
            return null;
        }

        try {
            int tenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());
            String userId = user.getUserId();
            if (StringUtils.isBlank(userId)) {
                return null;
            }
            IdVClaim claim = manager.getIdVClaim(userId, DaonConstants.PREFERRED_USERNAME_CLAIM_URI,
                    idvpId, tenantId);
            if (claim != null && claim.getMetadata() != null) {
                Object val = claim.getMetadata().get(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM);
                if (val != null && StringUtils.isNotBlank(val.toString())) {
                    return val.toString();
                }
            }
        } catch (UserIdNotFoundException e) {
            LOG.warn("Could not resolve user ID for login_hint lookup; proceeding without it.", e);
        } catch (IdentityVerificationException e) {
            LOG.warn("Error retrieving preferred_username for login_hint; proceeding without it.", e);
        }
        return null;
    }

    private String buildCallbackUrl(HttpServletRequest request) {
        return request.getScheme() + "://" + request.getServerName() + ":"
                + request.getServerPort() + COMMON_AUTH_ENDPOINT;
    }
}
