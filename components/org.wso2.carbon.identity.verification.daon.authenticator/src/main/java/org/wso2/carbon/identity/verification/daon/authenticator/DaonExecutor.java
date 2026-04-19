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

package org.wso2.carbon.identity.verification.daon.authenticator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.json.JSONObject;
import org.wso2.carbon.extension.identity.verification.mgt.IdentityVerificationManager;
import org.wso2.carbon.extension.identity.verification.mgt.exception.IdentityVerificationException;
import org.wso2.carbon.extension.identity.verification.mgt.model.IdVClaim;
import org.wso2.carbon.extension.identity.verification.provider.exception.IdVProviderMgtException;
import org.wso2.carbon.extension.identity.verification.provider.model.IdVConfigProperty;
import org.wso2.carbon.extension.identity.verification.provider.model.IdVProvider;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectExecutor;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants;
import org.wso2.carbon.identity.verification.daon.authenticator.internal.DaonAuthenticatorDataHolder;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.web.DaonAPIClient;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.*;

/**
 * Flow executor for Daon identity verification (IDV).
 *
 * <p>Handles the OIDC authorization-code flow against Daon's token endpoint. The returned
 * ID token carries a nested {@code claims} object containing IDV attributes (name, birthdate,
 * document details, address). These are extracted and stored in the {@link FlowExecutionContext}
 * for deferred persistence by {@link DaonRegistrationFlowCompletionListener} once the flow
 * completes and the user ID is available.</p>
 */
public class DaonExecutor extends OpenIDConnectExecutor {

    private static final Log LOG = LogFactory.getLog(DaonExecutor.class);
    private static final String DAON_EXECUTOR_NAME = "DaonExecutor";

    @Override
    public String getName() {
        return DAON_EXECUTOR_NAME;
    }

    @Override
    public String getAMRValue() {
        return DAON_EXECUTOR_NAME;
    }

    @Override
    public String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
        return authenticatorProperties.get(DaonConstants.AUTHORIZATION_ENDPOINT_URL);
    }

    @Override
    public String getTokenEndpoint(Map<String, String> authenticatorProperties) {
        return authenticatorProperties.get(DaonConstants.TOKEN_ENDPOINT_URL);
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext flowExecutionContext) {

        flowExecutionContext.setPortalUrl(buildPortalUrl(flowExecutionContext.getTenantDomain()));
        if (FLOW_TYPE_PASSWORD_RECOVERY.equals(flowExecutionContext.getFlowType())) {
            injectPasswordRecoveryConfigs(flowExecutionContext);
        } else {
            injectIdvpConfigs(flowExecutionContext);
        }
        ExecutorResponse response = super.execute(flowExecutionContext);
        if (Boolean.TRUE.equals(flowExecutionContext.getProperty(DAON_CLAIM_MISMATCH_PROPERTY))) {
            ExecutorResponse errorResponse = new ExecutorResponse();
            errorResponse.setResult(Constants.ExecutorStatus.STATUS_USER_ERROR);
            errorResponse.setErrorMessage(
                    "The details in your profile do not match the identity verified by Daon. " +
                    "Your account has been locked. Please contact support.");
            return errorResponse;
        }
        return response;
    }

    private void injectIdvpConfigs(FlowExecutionContext flowExecutionContext) {

        Map<String, String> props = flowExecutionContext.getAuthenticatorProperties();
        String idvpId = props.get(DAON_IDVP_ID);
        if (StringUtils.isBlank(idvpId)) {
            LOG.warn("daon_idvp_id not configured in the connection; executor cannot resolve IDVP credentials.");
            return;
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(flowExecutionContext.getTenantDomain());
            IdVProvider idVProvider = DaonAuthenticatorDataHolder.getIdVProviderManager()
                    .getIdVProvider(idvpId, tenantId);
            if (idVProvider == null) {
                LOG.warn("No IDVP found for id: " + idvpId + "; executor may fail.");
                return;
            }
            Map<String, String> idvpProps = new HashMap<>();
            for (IdVConfigProperty prop : idVProvider.getIdVConfigProperties()) {
                idvpProps.put(prop.getName(), prop.getValue());
            }
            Map<String, String> enriched = new HashMap<>(props);
            enriched.put(OIDCAuthenticatorConstants.CLIENT_ID, idvpProps.get(DaonConstants.CLIENT_ID));
            enriched.put(OIDCAuthenticatorConstants.CLIENT_SECRET, idvpProps.get(DaonConstants.CLIENT_SECRET));
            enriched.put(IdentityApplicationConstants.OAuth2.CALLBACK_URL,
                    IdentityUtil.getServerURL(String.format(DaonConstants.DAON_CALLBACK_URL_FORMAT, idvpId), true, true));
            enriched.put(DaonConstants.AUTHORIZATION_ENDPOINT_URL, idvpProps.get(DaonConstants.AUTHORIZATION_ENDPOINT_URL));
            enriched.put(DaonConstants.TOKEN_ENDPOINT_URL, idvpProps.get(DaonConstants.TOKEN_ENDPOINT_URL));
            String scope = idvpProps.get(DaonConstants.SCOPE);
            if (StringUtils.isNotBlank(scope)) {
                enriched.put(EXECUTOR_SCOPES, scope);
            }
            Map<String, String> claimMappings = idVProvider.getClaimMappings();
            if (claimMappings != null && !claimMappings.isEmpty()) {
                enriched.put(DAON_CLAIM_NAMES, String.join(",", claimMappings.values()));
            }
            flowExecutionContext.setAuthenticatorProperties(enriched);
        } catch (IdVProviderMgtException e) {
            LOG.error("Failed to look up IDVP configs for id: " + idvpId + "; executor may fail.", e);
        }
    }

    private void injectPasswordRecoveryConfigs(FlowExecutionContext flowExecutionContext) {

        Map<String, String> props = flowExecutionContext.getAuthenticatorProperties();
        String idvpId = props.get(DAON_IDVP_ID);
        if (StringUtils.isBlank(idvpId)) {
            LOG.warn("daon_idvp_id not configured; executor cannot resolve IDVP config for password recovery.");
            return;
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(flowExecutionContext.getTenantDomain());
            IdVProvider idVProvider = DaonAuthenticatorDataHolder.getIdVProviderManager()
                    .getIdVProvider(idvpId, tenantId);
            if (idVProvider == null) {
                LOG.warn("No IDVP found for id: " + idvpId + "; executor may fail.");
                return;
            }
            Map<String, String> idvpProps = new HashMap<>();
            for (IdVConfigProperty prop : idVProvider.getIdVConfigProperties()) {
                idvpProps.put(prop.getName(), prop.getValue());
            }
            Map<String, String> enriched = new HashMap<>(props);
            enriched.put(OIDCAuthenticatorConstants.CLIENT_ID, props.get(LOGIN_CLIENT_ID));
            enriched.put(OIDCAuthenticatorConstants.CLIENT_SECRET, props.get(LOGIN_CLIENT_SECRET));
            enriched.put(IdentityApplicationConstants.OAuth2.CALLBACK_URL,
                    IdentityUtil.getServerURL(String.format(DaonConstants.DAON_CALLBACK_URL_FORMAT, idvpId), true, true));
            enriched.put(DaonConstants.AUTHORIZATION_ENDPOINT_URL, idvpProps.get(DaonConstants.AUTHORIZATION_ENDPOINT_URL));
            enriched.put(DaonConstants.TOKEN_ENDPOINT_URL, idvpProps.get(DaonConstants.TOKEN_ENDPOINT_URL));
            String loginHint = resolveLoginHint(flowExecutionContext, idvpId, tenantId);
            if (StringUtils.isNotBlank(loginHint)) {
                enriched.put(DAON_LOGIN_HINT, loginHint);
            }
            flowExecutionContext.setAuthenticatorProperties(enriched);
        } catch (IdVProviderMgtException e) {
            LOG.error("Failed to look up IDVP configs for id: " + idvpId + "; executor may fail.", e);
        }
    }

    private String resolveLoginHint(FlowExecutionContext context, String idvpId, int tenantId) {

        if (context.getFlowUser() == null) {
            return null;
        }
        String userId = context.getFlowUser().getUserId();
        if (StringUtils.isBlank(userId)) {
            Object userIdClaim = context.getFlowUser().getClaim(USER_ID_CLAIM);
            if (userIdClaim != null) {
                userId = userIdClaim.toString();
            }
        }
        if (StringUtils.isBlank(userId)) {
            LOG.warn("Cannot resolve user ID for login_hint lookup; proceeding without it.");
            return null;
        }
        IdentityVerificationManager manager = DaonAuthenticatorDataHolder.getIdentityVerificationManager();
        if (manager == null) {
            LOG.warn("IdentityVerificationManager unavailable; proceeding without login_hint.");
            return null;
        }
        try {
            IdVClaim claim = manager.getIdVClaim(userId, DaonConstants.PREFERRED_USERNAME_CLAIM_URI, idvpId, tenantId);
            if (claim != null && claim.getMetadata() != null) {
                Object val = claim.getMetadata().get(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM);
                if (val != null && StringUtils.isNotBlank(val.toString())) {
                    return val.toString();
                }
            }
        } catch (IdentityVerificationException e) {
            LOG.warn("Error retrieving preferred_username for login_hint; proceeding without it.", e);
        }
        return null;
    }

    @Override
    public Map<String, String> getAdditionalQueryParams(Map<String, String> authenticatorProperties) {

        Map<String, String> params = new HashMap<>();
        String loginHint = authenticatorProperties.get(DAON_LOGIN_HINT);
        if (StringUtils.isNotBlank(loginHint)) {
            // Password recovery flow: face auth with login_hint, no verified_claims needed.
            try {
                params.put("login_hint", java.net.URLEncoder.encode(loginHint, "UTF-8"));
            } catch (java.io.UnsupportedEncodingException e) {
                LOG.warn("Failed to URL-encode Daon login_hint parameter.", e);
            }
            return params;
        }
        // Registration / invited user flow: request verified_claims from Daon.
        String claimNamesStr = authenticatorProperties.get(DAON_CLAIM_NAMES);
        if (StringUtils.isBlank(claimNamesStr)) {
            return params;
        }
        List<String> claimNames = Arrays.asList(claimNamesStr.split(","));
        try {
            params.put("claims", java.net.URLEncoder.encode(
                    DaonAPIClient.buildClaimsParam(claimNames), "UTF-8"));
        } catch (java.io.UnsupportedEncodingException e) {
            // UTF-8 is always supported; this branch is unreachable
            LOG.warn("Failed to URL-encode Daon claims request parameter.", e);
        }
        return params;
    }

    @Override
    protected Map<String, Object> resolveUserAttributes(FlowExecutionContext flowExecutionContext, String code)
            throws FlowEngineException {

        if (FLOW_TYPE_PASSWORD_RECOVERY.equals(flowExecutionContext.getFlowType())) {
            return resolvePasswordRecoveryAttributes(flowExecutionContext, code);
        }

        OAuthClientResponse oAuthResponse = requestAccessToken(flowExecutionContext, code);
        resolveAccessToken(oAuthResponse);

        String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
        if (StringUtils.isBlank(idToken)) {
            throw handleFlowEngineServerException("ID token is empty or null.", null);
        }

        JSONObject idTokenPayload;
        try {
            idTokenPayload = DaonJwtUtil.decodeJwtPayload(idToken);
        } catch (IllegalArgumentException e) {
            throw handleFlowEngineServerException(e.getMessage(), e);
        }

        String subject = idTokenPayload.optString(DaonAuthenticatorConstants.JWT_SUBJECT_CLAIM, null);
        if (StringUtils.isBlank(subject)) {
            throw handleFlowEngineServerException("Subject (sub) claim not found in Daon ID token.", null);
        }

        Map<String, Object> userAttributes = new HashMap<>();
//        userAttributes.put(USERNAME_CLAIM_URI, subject);

        if (!idTokenPayload.has(DaonAuthenticatorConstants.JWT_VERIFIED_CLAIMS_OBJECT)) {
            LOG.warn("No 'verifiedClaims' object in Daon ID token for subject: " + subject);
            return userAttributes;
        }

        JSONObject verifiedClaims = idTokenPayload.getJSONObject(DaonAuthenticatorConstants.JWT_VERIFIED_CLAIMS_OBJECT);
        if (!verifiedClaims.has(DaonAuthenticatorConstants.JWT_CLAIMS_OBJECT)) {
            LOG.warn("No 'claims' object inside 'verifiedClaims' in Daon ID token for subject: " + subject);
            return userAttributes;
        }

        JSONObject daonClaims = verifiedClaims.getJSONObject(DaonAuthenticatorConstants.JWT_CLAIMS_OBJECT);
        String idvpId = flowExecutionContext.getAuthenticatorProperties().get(DAON_IDVP_ID);
        Map<String, String> claimMappings = getIdvpClaimMappings(idvpId, flowExecutionContext.getTenantDomain());
        Map<String, String> reverseClaimMap = new HashMap<>();
        for (Map.Entry<String, String> entry : claimMappings.entrySet()) {
            reverseClaimMap.put(entry.getValue(), entry.getKey()); // Daon name → WSO2 URI
        }

        Map<String, String> extractedClaims = new HashMap<>();
        for (Object keyObj : daonClaims.keySet()) {
            String key = (String) keyObj;
            String claimValue = DaonJwtUtil.resolveClaimValue(key, daonClaims.get(key));
            if (claimValue == null) {
                continue;
            }
            String claimUri = reverseClaimMap.getOrDefault(key,
                    DaonAuthenticatorConstants.CLAIM_DIALECT_URI + "/" + key);
            extractedClaims.put(claimUri, claimValue);
        }

        String preferredUsername = idTokenPayload.optString(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM, null);
        if (StringUtils.isNotBlank(preferredUsername)) {
            LOG.info("Preferred is present in Daon ID token for subject: " + preferredUsername);
            extractedClaims.put(DaonConstants.PREFERRED_USERNAME_CLAIM_URI, preferredUsername);
        }

        if (flowExecutionContext.getFlowUser() != null) {
            boolean hasProfileClaims = claimMappings.keySet().stream()
                    .anyMatch(uri -> flowExecutionContext.getFlowUser().getClaim(uri) != null);
            if (hasProfileClaims) {
                // Invited user flow: profile claims are pre-populated; validate against Daon-verified values.
                if (!validateProfileClaimsAgainstVerified(
                        flowExecutionContext.getFlowUser(), extractedClaims, claimMappings)) {
                    lockUserAccount(flowExecutionContext);
                    flowExecutionContext.setProperty(DAON_CLAIM_MISMATCH_PROPERTY, Boolean.TRUE);
                    return userAttributes;
                }
            }
        }
        // Store in context for DaonRegistrationFlowCompletionListener, which persists to the
        // IDV_CLAIM table once the flow completes and the user ID is guaranteed available.
        flowExecutionContext.setProperty(FLOW_CONTEXT_DAON_VERIFIED_CLAIMS, extractedClaims);
        flowExecutionContext.setProperty(FLOW_CONTEXT_DAON_IDVP_ID, idvpId);

        return userAttributes;
    }

    private Map<String, Object> resolvePasswordRecoveryAttributes(FlowExecutionContext flowExecutionContext,
                                                                   String code) throws FlowEngineException {

        OAuthClientResponse oAuthResponse = requestAccessToken(flowExecutionContext, code);
        resolveAccessToken(oAuthResponse);

        String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
        if (StringUtils.isBlank(idToken)) {
            throw handleFlowEngineServerException("ID token is empty or null.", null);
        }

        JSONObject idTokenPayload;
        try {
            idTokenPayload = DaonJwtUtil.decodeJwtPayload(idToken);
        } catch (IllegalArgumentException e) {
            throw handleFlowEngineServerException(e.getMessage(), e);
        }

        String returnedSubject = idTokenPayload.optString(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM,
                idTokenPayload.optString(DaonAuthenticatorConstants.JWT_SUBJECT_CLAIM, null));
        if (StringUtils.isBlank(returnedSubject)) {
            throw handleFlowEngineServerException("No subject identity found in Daon ID token.", null);
        }

//        String expectedLoginHint = flowExecutionContext.getAuthenticatorProperties().get(DAON_LOGIN_HINT);
//        if (StringUtils.isNotBlank(expectedLoginHint) && !expectedLoginHint.equals(returnedSubject)) {
//            throw handleFlowEngineServerException(
//                    "Identity verification failed: returned subject does not match the expected user.", null);
//        }

        return new HashMap<>();
    }

    private void lockUserAccount(FlowExecutionContext context) {

        if (context.getFlowUser() == null) {
            LOG.warn("Cannot lock account: flow user is not available in context.");
            return;
        }
        String userId = context.getFlowUser().getUserId();
        if (StringUtils.isBlank(userId)) {
            LOG.warn("Cannot lock account: user ID is blank in flow context.");
            return;
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());
            org.wso2.carbon.user.api.UserStoreManager usm =
                    DaonAuthenticatorDataHolder.getRealmService()
                            .getTenantUserRealm(tenantId)
                            .getUserStoreManager();
            if (usm instanceof UniqueIDUserStoreManager) {
                Map<String, String> claimsToLock = new HashMap<>();
                claimsToLock.put(ACCOUNT_LOCKED_CLAIM, "true");
                ((UniqueIDUserStoreManager) usm).setUserClaimValuesWithID(
                        userId, claimsToLock, null);
                LOG.warn("User account locked due to IDV claim mismatch. User ID: " + userId);
            } else {
                LOG.warn("UniqueIDUserStoreManager not available; account not locked for user: " + userId);
            }
        } catch (UserStoreException e) {
            LOG.error("Failed to lock account for user: " + userId, e);
        }
    }

    private String buildPortalUrl(String tenantDomain) {

        try {
            if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                return IdentityUtil.getServerURL("/accounts/register", true, true);
            }
            if (OrganizationManagementUtil.isOrganization(tenantDomain)) {
                OrganizationManager orgManager = DaonAuthenticatorDataHolder.getOrganizationManager();
                if (orgManager != null) {
                    String orgId = orgManager.resolveOrganizationId(tenantDomain);
                    return IdentityUtil.getServerURL("/o/" + orgId + "/accounts/register", true, true);
                }
            }
            return IdentityUtil.getServerURL("/t/" + tenantDomain + "/accounts/register", true, true);
        } catch (Exception e) {
            LOG.warn("Could not build portal URL for tenant: " + tenantDomain + "; falling back to default.", e);
            return IdentityUtil.getServerURL("/accounts/register", true, true);
        }
    }

    private Map<String, String> getIdvpClaimMappings(String idvpId, String tenantDomain) {

        if (StringUtils.isBlank(idvpId)) {
            return Collections.emptyMap();
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            IdVProvider idVProvider = DaonAuthenticatorDataHolder.getIdVProviderManager()
                    .getIdVProvider(idvpId, tenantId);
            if (idVProvider != null && idVProvider.getClaimMappings() != null) {
                return idVProvider.getClaimMappings();
            }
        } catch (IdVProviderMgtException e) {
            LOG.warn("Failed to load IDVP claim mappings; falling back to Daon dialect URIs.", e);
        }
        return Collections.emptyMap();
    }

    /**
     * Validates each configured IDVP claim URI that has a value in the user's profile against the
     * corresponding Daon-verified value in {@code extractedClaims}.
     *
     * <p>For name claims where Daon returns a combined {@code family_name_and_given_name} field
     * instead of separate {@code given_name}/{@code family_name}, the combined field is used as
     * a fallback (contains check).
     *
     * @return {@code true} if all present profile claims match their verified counterparts,
     *         {@code false} if any mismatch is detected.
     */
    private boolean validateProfileClaimsAgainstVerified(
            FlowUser flowUser,
            Map<String, String> extractedClaims,
            Map<String, String> claimMappings) {

        String combinedName = extractedClaims.get(
                DaonAuthenticatorConstants.CLAIM_DIALECT_URI + "/family_name_and_given_name");

        for (String wso2Uri : claimMappings.keySet()) {
            Object profileClaimObj = flowUser.getClaim(wso2Uri);
            if (profileClaimObj == null) {
                continue;
            }
            String profileValue = profileClaimObj.toString().trim();
            if (StringUtils.isBlank(profileValue)) {
                continue;
            }
            String verifiedValue = extractedClaims.get(wso2Uri);
            if (verifiedValue != null) {
                if (!verifiedValue.toLowerCase().contains(profileValue.toLowerCase())) {
                    LOG.warn("Claim mismatch for URI: " + wso2Uri);
                    return false;
                }
                continue; 
            }
            // No direct Daon claim for this URI. For lastname/givenname, require a match against
            // the combined family_name_and_given_name field; absence or mismatch is a failure.
            boolean isNameClaim = WSO2_LASTNAME_CLAIM_URI.equals(wso2Uri)
                    || WSO2_GIVENNAME_CLAIM_URI.equals(wso2Uri);
            if (isNameClaim) {
                if (combinedName == null || !combinedName.toLowerCase().contains(profileValue.toLowerCase())) {
                    LOG.warn("Claim mismatch for URI: " + wso2Uri
                            + " (no direct Daon value; combined name check failed)");
                    return false;
                }
            } else {
                LOG.warn("No verified value available for claim URI: " + wso2Uri + "; skipping validation.");
            }
        }
        return true;
    }

}

