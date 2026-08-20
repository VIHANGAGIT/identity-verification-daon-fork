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

package org.wso2.carbon.identity.verification.daon.connector;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectExecutor;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.metadata.FlowExecutorMetadata;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonException;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonCallbackErrors;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonClaimsRequestBuilder;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonFederatedAssociationUtil;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonJwtUtil;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonReferencedIdpUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ACR_VALUES_PARAM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIMS_PARAM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_CLAIMS_REQUEST;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_ENROL_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_FED_IDP_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_FED_SUBJECT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_IDP_ID;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_LOGIN_HINT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_LOGIN_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_SELECTED_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.FLOW_TYPE_INVITED_USER_REGISTRATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.FLOW_TYPE_PASSWORD_RECOVERY;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.FLOW_TYPE_REGISTRATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.LOGIN_HINT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.OAUTH2_ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.WSO2_GIVENNAME_CLAIM_URI;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.WSO2_LASTNAME_CLAIM_URI;

/**
 * Flow executor for Daon TrustX, driving the OIDC authorization-code flow for all the flows.
 */
public class DaonExecutor extends OpenIDConnectExecutor {

    private static final Log LOG = LogFactory.getLog(DaonExecutor.class);
    private static final String DAON_EXECUTOR_NAME = "DaonExecutor";

    private static final String PORTAL_PATH_PREFIX = "/accounts/";
    private static final String PORTAL_PATH_RECOVERY = "recovery";
    private static final String PORTAL_PATH_REGISTER = "register";
    private static final String ORGANIZATION_PATH_PREFIX = "/o/";
    private static final String TENANT_PATH_PREFIX = "/t/";

    @Override
    public String getName() {

        return DAON_EXECUTOR_NAME;
    }

    @Override
    public String getAMRValue() {

        return DaonConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public Set<FlowTypes> getSupportedFlowTypes() {

        return EnumSet.allOf(FlowTypes.class);
    }

    @Override
    public FlowExecutorMetadata getExecutorMetadata() {

        return FlowExecutorMetadata.builder()
                .displayName(DaonConstants.AUTHENTICATOR_FRIENDLY_NAME + " Verification")
                .description("Verify user identity with Daon TrustX.")
                .icon("assets/images/icons/daon.svg")
                .associatedAuthenticator(DaonConstants.AUTHENTICATOR_NAME)
                .connectionRequired(true)
                .build();
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext flowExecutionContext) {

        Map<String, String> userInputs = flowExecutionContext.getUserInputData();
        if (userInputs != null
                && StringUtils.isNotBlank(userInputs.get(OIDCAuthenticatorConstants.OAUTH2_ERROR))) {
            String error = userInputs.get(OIDCAuthenticatorConstants.OAUTH2_ERROR);
            String errorDescription = userInputs.get(OAUTH2_ERROR_DESCRIPTION);
            ErrorMessage callbackError = DaonCallbackErrors.resolveError(error, errorDescription);
            if (LOG.isDebugEnabled()) {
                LOG.debug(callbackError.getCode() + " - Daon returned an error on the flow callback. error="
                        + error + ", error_description=" + errorDescription);
            }
            return userError(callbackError);
        }

        flowExecutionContext.setPortalUrl(
                buildPortalUrl(flowExecutionContext.getTenantDomain(), flowExecutionContext.getFlowType()));
        try {
            prepareRequest(flowExecutionContext);
        } catch (FlowEngineException e) {
            // The request cannot be built in a form that actually verifies the user.
            LOG.error(e.getErrorCode() + " - " + e.getDescription(), e);
            ExecutorResponse errorResponse = new ExecutorResponse();
            errorResponse.setResult(Constants.ExecutorStatus.STATUS_ERROR);
            errorResponse.setErrorCode(e.getErrorCode());
            errorResponse.setErrorMessage(e.getMessage());
            errorResponse.setErrorDescription(e.getDescription());
            return errorResponse;
        }
        if (FLOW_TYPE_PASSWORD_RECOVERY.equals(flowExecutionContext.getFlowType())
                && StringUtils.isBlank(flowExecutionContext.getAuthenticatorProperties().get(DAON_LOGIN_HINT))) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_USER_NOT_ENROLLED,
                        flowExecutionContext.getFlowType()));
            }
            return userError(ErrorMessage.ERROR_USER_NOT_ENROLLED);
        }
        return super.execute(flowExecutionContext);
    }

    private ExecutorResponse userError(ErrorMessage error) {

        ExecutorResponse response = new ExecutorResponse();
        response.setResult(Constants.ExecutorStatus.STATUS_USER_ERROR);
        response.setErrorCode(error.getCode());
        response.setErrorMessage(DaonExceptionMgt.userMessage(error));
        response.setErrorDescription(DaonExceptionMgt.userDescription(error));
        return response;
    }

    private void prepareRequest(FlowExecutionContext flowExecutionContext) throws FlowEngineException {

        Map<String, String> props = flowExecutionContext.getAuthenticatorProperties();
        // Inject OIDC props to the referencing connection's effective properties.
        Map<String, String> enriched =
                DaonReferencedIdpUtil.buildEffectiveProperties(props, flowExecutionContext.getTenantDomain());

        boolean recovery = FLOW_TYPE_PASSWORD_RECOVERY.equals(flowExecutionContext.getFlowType());
        Map<String, String> claimMappings = getIdpClaimMappings(flowExecutionContext);
        if (!recovery) {
            Map<String, String> prefilledValues = claimMappings.isEmpty()
                    ? Collections.emptyMap()
                    : resolvePrefilledClaimValues(flowExecutionContext, claimMappings);
            assertProfileCanBeValidated(flowExecutionContext, prefilledValues);
            if (!claimMappings.isEmpty()) {
                enriched.put(DAON_CLAIMS_REQUEST, buildClaimsRequest(claimMappings, prefilledValues));
            }
        }
        // Reading enrol PD from `props` would drop acr_values and let Daon run its default PD.
        String processDefinition = recovery ? enriched.get(DAON_LOGIN_PD) : enriched.get(DAON_ENROL_PD);
        if (StringUtils.isNotBlank(processDefinition)) {
            enriched.put(DAON_SELECTED_PD, processDefinition);
        }

        if (recovery) {
            String loginHint = resolvePreferredUsername(flowExecutionContext);
            if (StringUtils.isNotBlank(loginHint)) {
                enriched.put(DAON_LOGIN_HINT, loginHint);
            }
        }
        flowExecutionContext.setAuthenticatorProperties(enriched);
    }

    private String buildClaimsRequest(Map<String, String> claimMappings, Map<String, String> prefilledValues)
            throws FlowEngineException {

        List<String> claimNames = new ArrayList<>(claimMappings.values());
        try {
            return DaonClaimsRequestBuilder.buildClaimsParam(claimNames, prefilledValues);
        } catch (DaonServerException e) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_BUILDING_CLAIMS_REQUEST), e);
            throw DaonExceptionMgt.toFlowServerException(e);
        }
    }

    private void assertProfileCanBeValidated(FlowExecutionContext flowExecutionContext,
                                             Map<String, String> prefilledValues) throws FlowEngineException {

        if (!FLOW_TYPE_INVITED_USER_REGISTRATION.equals(flowExecutionContext.getFlowType())) {
            return;
        }
        if (DaonClaimsRequestBuilder.hasDocumentVerifiableValue(prefilledValues)) {
            return;
        }
        LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_NO_VERIFIABLE_CLAIM_VALUES,
                flowExecutionContext.getFlowType()));
        throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_NO_VERIFIABLE_CLAIM_VALUES,
                flowExecutionContext.getFlowType());
    }

    @Override
    public Map<String, String> getAdditionalQueryParams(Map<String, String> authenticatorProperties) {

        Map<String, String> params = new HashMap<>();
        String processDefinition = authenticatorProperties.get(DAON_SELECTED_PD);
        if (StringUtils.isNotBlank(processDefinition)) {
            params.put(ACR_VALUES_PARAM, processDefinition);
        }
        String loginHint = authenticatorProperties.get(DAON_LOGIN_HINT);
        if (StringUtils.isNotBlank(loginHint)) {
            params.put(LOGIN_HINT, loginHint);
            return params;
        }
        String claimsRequest = authenticatorProperties.get(DAON_CLAIMS_REQUEST);
        if (StringUtils.isNotBlank(claimsRequest)) {
            params.put(CLAIMS_PARAM, claimsRequest);
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
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND,
                    flowExecutionContext.getFlowType());
        }

        JSONObject idTokenPayload;
        JSONObject daonClaims;
        try {
            idTokenPayload = DaonJwtUtil.decodeJwtPayload(idToken);
            daonClaims = DaonJwtUtil.extractVerifiedClaims(idTokenPayload,
                    flowExecutionContext.getFlowType());
        } catch (DaonException e) {
            LOG.error(e.getErrorCode() + " - " + e.getMessage(), e);
            throw DaonExceptionMgt.toFlowServerException(e);
        }

        if (StringUtils.isBlank(idTokenPayload.optString(DaonConstants.JWT_SUBJECT_CLAIM, null))) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_SUBJECT_CLAIM_NOT_FOUND,
                    flowExecutionContext.getFlowType());
        }

        Map<String, Object> userAttributes = new HashMap<>();

        Map<String, String> claimMappings = getIdpClaimMappings(flowExecutionContext);
        Map<String, String> reverseClaimMap = new HashMap<>();
        for (Map.Entry<String, String> entry : claimMappings.entrySet()) {
            reverseClaimMap.put(entry.getValue(), entry.getKey());
        }

        Map<String, String> extractedClaims = new HashMap<>();
        for (String key : daonClaims.keySet()) {
            String claimUri = reverseClaimMap.get(key);
            if (claimUri == null) {
                continue;
            }
            String claimValue = DaonJwtUtil.resolveClaimValue(key, daonClaims.get(key));
            if (claimValue != null) {
                extractedClaims.put(claimUri, claimValue);
            }
        }

        String preferredUsername = idTokenPayload.optString(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM, null);

        // Self-registration: Daon is the source of truth, so provision the profile. The invited user's
        // admin-defined profile is authoritative and is left untouched.
        if (FLOW_TYPE_REGISTRATION.equals(flowExecutionContext.getFlowType())) {
            userAttributes.putAll(buildProfileClaims(daonClaims, extractedClaims, reverseClaimMap));
        }

        if (StringUtils.isBlank(preferredUsername)) {
            throw DaonExceptionMgt.handleFlowServerException(
                    ErrorMessage.ERROR_ENROLMENT_IDENTITY_NOT_RETURNED);
        }
        String daonIdpName = resolveDaonIdpName(flowExecutionContext);
        if (StringUtils.isBlank(daonIdpName)) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the Daon Verifier name could not be resolved for the " + flowExecutionContext.getFlowType()
                            + " flow");
        }
        flowExecutionContext.setProperty(DAON_FED_IDP_NAME, daonIdpName);
        flowExecutionContext.setProperty(DAON_FED_SUBJECT, preferredUsername);
        return userAttributes;
    }

    private Map<String, Object> resolvePasswordRecoveryAttributes(FlowExecutionContext flowExecutionContext,
                                                                   String code) throws FlowEngineException {

        OAuthClientResponse oAuthResponse = requestAccessToken(flowExecutionContext, code);
        resolveAccessToken(oAuthResponse);

        String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
        if (StringUtils.isBlank(idToken)) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND,
                    flowExecutionContext.getFlowType());
        }
        JSONObject idTokenPayload;
        try {
            idTokenPayload = DaonJwtUtil.decodeJwtPayload(idToken);
        } catch (DaonException e) {
            throw DaonExceptionMgt.toFlowServerException(e);
        }
        String returnedPreferredUsername =
                idTokenPayload.optString(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM, null);
        if (StringUtils.isBlank(returnedPreferredUsername)) {
            throw DaonExceptionMgt.handleFlowServerException(
                    ErrorMessage.ERROR_NO_SUBJECT_IDENTITY_IN_ID_TOKEN);
        }

        String expectedSubject = flowExecutionContext.getAuthenticatorProperties().get(DAON_LOGIN_HINT);
        if (!DaonJwtUtil.isExpectedSubject(expectedSubject, returnedPreferredUsername)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Daon returned an identity that does not match the account being recovered. "
                        + "Expected: " + expectedSubject + ", returned preferred_username: "
                        + returnedPreferredUsername);
            }
            LOG.error(ErrorMessage.ERROR_RECOVERY_IDENTITY_MISMATCH.getCode()
                    + " - The identity Daon verified does not match the Daon subject recorded for the "
                    + "account being recovered.");
            throw DaonExceptionMgt.handleFlowClientException(ErrorMessage.ERROR_RECOVERY_IDENTITY_MISMATCH);
        }
        return new HashMap<>();
    }

    private Map<String, Object> buildProfileClaims(JSONObject daonClaims, Map<String, String> extractedClaims,
                                                   Map<String, String> daonToLocalClaim) {

        Map<String, Object> profileClaims = new HashMap<>(extractedClaims);
        populateNameClaims(daonClaims, profileClaims, daonToLocalClaim);
        return profileClaims;
    }

    private void populateNameClaims(JSONObject daonClaims, Map<String, Object> profileClaims,
                                    Map<String, String> daonToLocalClaim) {

        String givenNameUri = resolveNameClaimUri(daonToLocalClaim, DaonConstants.CLAIM_GIVEN_NAME,
                WSO2_GIVENNAME_CLAIM_URI);
        String familyNameUri = resolveNameClaimUri(daonToLocalClaim, DaonConstants.CLAIM_FAMILY_NAME,
                WSO2_LASTNAME_CLAIM_URI);
        boolean hasGiven = profileClaims.containsKey(givenNameUri);
        boolean hasLast = profileClaims.containsKey(familyNameUri);
        if (hasGiven && hasLast) {
            return;
        }
        String combined = DaonJwtUtil.resolveClaimValue(DaonConstants.CLAIM_FAMILY_NAME_AND_GIVEN_NAME,
                daonClaims.opt(DaonConstants.CLAIM_FAMILY_NAME_AND_GIVEN_NAME));
        if (StringUtils.isBlank(combined)
                || !combined.contains(DaonConstants.DAON_FIELD_SEPARATOR)) {
            return;
        }
        String[] parts = combined.split(
                Pattern.quote(DaonConstants.DAON_FIELD_SEPARATOR), 2);
        String familyName = parts[0].trim();
        String givenName = parts.length > 1 ? parts[1].trim() : null;
        if (!hasGiven && StringUtils.isNotBlank(givenName)) {
            profileClaims.put(givenNameUri, givenName);
        }
        if (!hasLast && StringUtils.isNotBlank(familyName)) {
            profileClaims.put(familyNameUri, familyName);
        }
    }

    private String resolveNameClaimUri(Map<String, String> daonToLocalClaim, String daonClaimName,
                                       String defaultClaimUri) {

        String mappedClaimUri = daonToLocalClaim.get(daonClaimName);
        if (StringUtils.isBlank(mappedClaimUri)) {
            return defaultClaimUri;
        }
        return mappedClaimUri;
    }

    private Map<String, String> resolveInvitedUserClaims(FlowExecutionContext context, Set<String> claimUris) {

        Map<String, String> resolved = new HashMap<>();
        FlowUser flowUser = context.getFlowUser();
        if (flowUser == null || claimUris.isEmpty()) {
            return resolved;
        }
        for (String uri : claimUris) {
            Object value = flowUser.getClaim(uri);
            if (value != null && StringUtils.isNotBlank(value.toString())) {
                resolved.put(uri, value.toString());
            }
        }
        String userId = flowUser.getUserId();
        if (StringUtils.isBlank(userId)) {
            return resolved;
        }
        List<String> missing = new ArrayList<>();
        for (String uri : claimUris) {
            if (!resolved.containsKey(uri)) {
                missing.add(uri);
            }
        }
        if (missing.isEmpty()) {
            return resolved;
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());
            UserStoreManager usm = DaonConnectorDataHolder.getRealmService()
                    .getTenantUserRealm(tenantId).getUserStoreManager();
            if (usm instanceof UniqueIDUserStoreManager) {
                Map<String, String> stored = ((UniqueIDUserStoreManager) usm)
                        .getUserClaimValuesWithID(userId, missing.toArray(new String[0]), null);
                if (stored != null) {
                    for (Map.Entry<String, String> entry : stored.entrySet()) {
                        if (StringUtils.isNotBlank(entry.getValue())) {
                            resolved.put(entry.getKey(), entry.getValue());
                        }
                    }
                }
            }
        } catch (UserStoreException e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_READING_USER_CLAIMS,
                    "the invited user"), e);
        }
        return resolved;
    }

    private String resolvePreferredUsername(FlowExecutionContext context) {

        if (context.getFlowUser() == null) {
            return null;
        }
        String username = DaonFederatedAssociationUtil.resolveQualifiedUsername(context.getFlowUser(),
                context.getTenantDomain());
        if (StringUtils.isBlank(username)) {
            return null;
        }
        String daonIdpName = resolveDaonIdpName(context);
        if (StringUtils.isBlank(daonIdpName)) {
            return null;
        }
        User user = DaonFederatedAssociationUtil.buildUser(username, context.getTenantDomain());
        return DaonFederatedAssociationUtil.getAssociatedDaonSubject(user, daonIdpName);
    }

    private String resolveDaonIdpName(FlowExecutionContext context) {

        String idpResourceId = context.getAuthenticatorProperties().get(DAON_IDP_ID);
        if (StringUtils.isNotBlank(idpResourceId)) {
            return DaonReferencedIdpUtil.resolveIdpName(idpResourceId, context.getTenantDomain());
        }
        return context.getExternalIdPConfig() != null
                ? context.getExternalIdPConfig().getIdPName() : null;
    }

    private String buildPortalUrl(String tenantDomain, String flowType) {

        String portalPath = PORTAL_PATH_PREFIX
                + (FLOW_TYPE_PASSWORD_RECOVERY.equals(flowType) ? PORTAL_PATH_RECOVERY : PORTAL_PATH_REGISTER);
        try {
            if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                return IdentityUtil.getServerURL(portalPath, true, true);
            }
            if (OrganizationManagementUtil.isOrganization(tenantDomain)) {
                OrganizationManager orgManager = DaonConnectorDataHolder.getOrganizationManager();
                if (orgManager != null) {
                    String orgId = orgManager.resolveOrganizationId(tenantDomain);
                    return IdentityUtil.getServerURL(ORGANIZATION_PATH_PREFIX + orgId + portalPath,
                            true, true);
                }
            }
            return IdentityUtil.getServerURL(TENANT_PATH_PREFIX + tenantDomain + portalPath, true, true);
        } catch (Exception e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_BUILDING_PORTAL_URL, tenantDomain), e);
            return IdentityUtil.getServerURL(portalPath, true, true);
        }
    }

    private Map<String, String> resolvePrefilledClaimValues(FlowExecutionContext context,
                                                             Map<String, String> claimMappings) {

        Map<String, String> localValues;
        if (FLOW_TYPE_INVITED_USER_REGISTRATION.equals(context.getFlowType())) {
            localValues = resolveInvitedUserClaims(context, claimMappings.keySet());
        } else {
            localValues = new HashMap<>();
            FlowUser flowUser = context.getFlowUser();
            Map<String, String> collectedClaims = flowUser != null ? flowUser.getClaims() : null;
            if (collectedClaims != null) {
                for (String localUri : claimMappings.keySet()) {
                    String value = collectedClaims.get(localUri);
                    if (StringUtils.isNotBlank(value)) {
                        localValues.put(localUri, value);
                    }
                }
            }
        }

        Map<String, String> valuesByDaonName = new HashMap<>();
        for (Map.Entry<String, String> mapping : claimMappings.entrySet()) {
            String value = localValues.get(mapping.getKey());
            if (StringUtils.isNotBlank(value)) {
                valuesByDaonName.put(mapping.getValue(), value.trim());
            }
        }
        return valuesByDaonName;
    }

    private Map<String, String> getIdpClaimMappings(FlowExecutionContext context) {

        Map<String, String> mappings = new HashMap<>();
        ExternalIdPConfig idpConfig = context.getExternalIdPConfig();
        if (idpConfig == null || idpConfig.getClaimMappings() == null) {
            return mappings;
        }
        for (ClaimMapping claimMapping : idpConfig.getClaimMappings()) {
            if (claimMapping.getLocalClaim() != null && claimMapping.getRemoteClaim() != null
                    && StringUtils.isNotBlank(claimMapping.getLocalClaim().getClaimUri())
                    && StringUtils.isNotBlank(claimMapping.getRemoteClaim().getClaimUri())) {
                mappings.put(claimMapping.getLocalClaim().getClaimUri(),
                        claimMapping.getRemoteClaim().getClaimUri());
            }
        }
        return mappings;
    }
}
