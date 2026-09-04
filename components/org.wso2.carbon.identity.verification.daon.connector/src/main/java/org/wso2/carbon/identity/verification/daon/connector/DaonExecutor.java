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
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.metadata.FlowExecutorMetadata;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonException;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonCallbackErrors;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonClaimMappingUtil;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonClaimsRequestBuilder;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonFederatedAssociationUtil;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonJwtUtil;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonReferencedIdpUtil;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonUserClaimReader;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes.INVITED_USER_REGISTRATION;
import static org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes.PASSWORD_RECOVERY;
import static org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes.REGISTRATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ConnectionProperties.ENROL_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ConnectionProperties.IDP_ID;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ConnectionProperties.LOGIN_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.LocalClaims.FIRST_NAME_CLAIM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.LocalClaims.LAST_NAME_CLAIM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.LogConstants.ActionIDs.BIND_VERIFIED_IDENTITY;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.LogConstants.ActionIDs.POPULATE_VERIFIED_CLAIMS;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.LogConstants.OUTBOUND_AUTH_DAON_SERVICE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.OIDCParams.ACR_VALUES;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.OIDCParams.CLAIMS;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.OIDCParams.ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.PropertyCarriers.CLAIMS_REQUEST;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.PropertyCarriers.SELECTED_PD;

/**
 * Flow executor for Daon TrustX, driving the OIDC authorization-code flow for all the flows.
 */
public class DaonExecutor extends OpenIDConnectExecutor {

    private static final Log LOG = LogFactory.getLog(DaonExecutor.class);
    private static final String DAON_EXECUTOR_NAME = "DaonExecutor";
    private static final String FLOW_TYPE = "flow type";
    private static final String CLAIM_URIS = "claim uris";

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

        return EnumSet.of(REGISTRATION, PASSWORD_RECOVERY, INVITED_USER_REGISTRATION);
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
            String errorDescription = userInputs.get(ERROR_DESCRIPTION);
            ErrorMessage callbackError = DaonCallbackErrors.resolveError(error, errorDescription);
            if (LOG.isDebugEnabled()) {
                LOG.debug(callbackError.getCode() + " - Daon returned an error on the flow callback. error="
                        + error + ", error_description=" + errorDescription);
            }
            return userError(callbackError);
        }

        try {
            prepareRequest(flowExecutionContext);
        } catch (FlowEngineClientException e) {
            // Caused by how the connection is configured or by the user's own data, not by a server fault, so
            // the flow fails as a client error. The throw site has already logged what an admin needs.
            if (LOG.isDebugEnabled()) {
                LOG.debug(e.getErrorCode() + " - " + e.getDescription(), e);
            }
            return failedResponse(Constants.ExecutorStatus.STATUS_USER_ERROR, e);
        } catch (FlowEngineException e) {
            // The request cannot be built in a form that actually verifies the user.
            LOG.error(e.getErrorCode() + " - " + e.getDescription(), e);
            return failedResponse(Constants.ExecutorStatus.STATUS_ERROR, e);
        }
        if (isFlowType(PASSWORD_RECOVERY, flowExecutionContext)
                && StringUtils.isBlank(flowExecutionContext.getAuthenticatorProperties()
                        .get(DaonConstants.PropertyCarriers.LOGIN_HINT))) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_USER_NOT_ENROLLED,
                        flowExecutionContext.getFlowType()));
            }
            return userError(ErrorMessage.ERROR_USER_NOT_ENROLLED);
        }
        return super.execute(flowExecutionContext);
    }

    private ExecutorResponse failedResponse(String status, FlowEngineException e) {

        ExecutorResponse response = new ExecutorResponse();
        response.setResult(status);
        response.setErrorCode(e.getErrorCode());
        response.setErrorMessage(e.getMessage());
        response.setErrorDescription(e.getDescription());
        return response;
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

        boolean isRecovery = isFlowType(PASSWORD_RECOVERY, flowExecutionContext);
        Map<String, String> claimMappings = getIdpClaimMappings(flowExecutionContext);
        if (!isRecovery) {
            Map<String, String> prefilledValues = claimMappings.isEmpty()
                    ? Collections.emptyMap()
                    : resolvePrefilledClaimValues(flowExecutionContext, claimMappings);
            assertProfileCanBeValidated(flowExecutionContext, prefilledValues);
            if (!claimMappings.isEmpty()) {
                enriched.put(CLAIMS_REQUEST, buildClaimsRequest(claimMappings, prefilledValues));
            }
        }
        // Reading enrol PD from `props` would drop acr_values and let Daon run its default PD.
        String processDefinition = isRecovery ? enriched.get(LOGIN_PD) : enriched.get(ENROL_PD);
        if (StringUtils.isNotBlank(processDefinition)) {
            enriched.put(SELECTED_PD, processDefinition);
        }

        if (isRecovery) {
            String loginHint = resolvePreferredUsername(flowExecutionContext);
            if (StringUtils.isNotBlank(loginHint)) {
                enriched.put(DaonConstants.PropertyCarriers.LOGIN_HINT, loginHint);
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

        if (!isFlowType(INVITED_USER_REGISTRATION, flowExecutionContext)) {
            return;
        }
        if (DaonClaimsRequestBuilder.hasDocumentVerifiableValue(prefilledValues)) {
            return;
        }
        LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_NO_VERIFIABLE_CLAIM_VALUES,
                flowExecutionContext.getFlowType()));
        throw DaonExceptionMgt.handleFlowClientException(ErrorMessage.ERROR_NO_VERIFIABLE_CLAIM_VALUES);
    }

    @Override
    public Map<String, String> getAdditionalQueryParams(Map<String, String> authenticatorProperties) {

        Map<String, String> params = new HashMap<>();
        String processDefinition = authenticatorProperties.get(SELECTED_PD);
        if (StringUtils.isNotBlank(processDefinition)) {
            params.put(ACR_VALUES, processDefinition);
        }
        String loginHint = authenticatorProperties.get(DaonConstants.PropertyCarriers.LOGIN_HINT);
        if (StringUtils.isNotBlank(loginHint)) {
            params.put(DaonConstants.OIDCParams.LOGIN_HINT, loginHint);
            return params;
        }
        String claimsRequest = authenticatorProperties.get(CLAIMS_REQUEST);
        if (StringUtils.isNotBlank(claimsRequest)) {
            params.put(CLAIMS, claimsRequest);
        }
        return params;
    }

    @Override
    protected Map<String, Object> resolveUserAttributes(FlowExecutionContext flowExecutionContext, String code)
            throws FlowEngineException {

        if (isFlowType(PASSWORD_RECOVERY, flowExecutionContext)) {
            return resolvePasswordRecoveryAttributes(flowExecutionContext, code);
        }

        JSONObject idTokenPayload = resolveIdTokenPayload(flowExecutionContext, code);
        JSONObject daonClaims;
        try {
            daonClaims = DaonJwtUtil.extractVerifiedClaims(idTokenPayload,
                    flowExecutionContext.getFlowType());
        } catch (DaonException e) {
            LOG.error(e.getErrorCode() + " - " + e.getMessage(), e);
            throw DaonExceptionMgt.toFlowServerException(e);
        }

        if (StringUtils.isBlank(idTokenPayload.optString(DaonConstants.IdTokenClaims.SUBJECT, null))) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_SUBJECT_CLAIM_NOT_FOUND,
                    flowExecutionContext.getFlowType());
        }

        Map<String, Object> userAttributes = new HashMap<>();

        Map<String, String> reverseClaimMap =
                DaonClaimMappingUtil.invert(getIdpClaimMappings(flowExecutionContext));

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

        String preferredUsername = idTokenPayload.optString(DaonConstants.IdTokenClaims.PREFERRED_USERNAME, null);

        if (isFlowType(REGISTRATION, flowExecutionContext)) {
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
        flowExecutionContext.getFlowUser().addFederatedAssociation(daonIdpName, preferredUsername);

        Map<String, Object> params = new HashMap<>();
        params.put(FLOW_TYPE, flowExecutionContext.getFlowType());
        params.put(LogConstants.InputKeys.IDP, daonIdpName);
        logDiagnostic("Bound the identity Daon verified to the user.", DiagnosticLog.ResultStatus.SUCCESS,
                BIND_VERIFIED_IDENTITY, params);
        if (!userAttributes.isEmpty()) {
            // These overwrite whatever the user entered for the same claims.
            params = new HashMap<>();
            params.put(FLOW_TYPE, flowExecutionContext.getFlowType());
            params.put(CLAIM_URIS, userAttributes.keySet());
            logDiagnostic("Populating the user's claims from the identity document Daon verified.",
                    DiagnosticLog.ResultStatus.SUCCESS, POPULATE_VERIFIED_CLAIMS, params);
        }
        return userAttributes;
    }

    @Override
    protected String getDiagnosticLogComponentId() {

        return OUTBOUND_AUTH_DAON_SERVICE;
    }

    /**
     * Exchanges the authorization code and reads the ID token's claims. The OIDC base class has already
     * obtained and validated the token over the back channel, so this is a claims read.
     */
    private JSONObject resolveIdTokenPayload(FlowExecutionContext flowExecutionContext, String code)
            throws FlowEngineException {

        OAuthClientResponse oAuthResponse = requestAccessToken(flowExecutionContext, code);
        resolveAccessToken(oAuthResponse);

        String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
        if (StringUtils.isBlank(idToken)) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_ID_TOKEN_NOT_FOUND,
                    flowExecutionContext.getFlowType());
        }
        try {
            return DaonJwtUtil.decodeJwtPayload(idToken);
        } catch (DaonException e) {
            LOG.error(e.getErrorCode() + " - " + e.getMessage(), e);
            throw DaonExceptionMgt.toFlowServerException(e);
        }
    }

    private Map<String, Object> resolvePasswordRecoveryAttributes(FlowExecutionContext flowExecutionContext,
                                                                   String code) throws FlowEngineException {

        JSONObject idTokenPayload = resolveIdTokenPayload(flowExecutionContext, code);
        String returnedPreferredUsername =
                idTokenPayload.optString(DaonConstants.IdTokenClaims.PREFERRED_USERNAME, null);
        if (StringUtils.isBlank(returnedPreferredUsername)) {
            throw DaonExceptionMgt.handleFlowServerException(
                    ErrorMessage.ERROR_NO_SUBJECT_IDENTITY_IN_ID_TOKEN,
                    flowExecutionContext.getFlowType());
        }

        String expectedSubject = flowExecutionContext.getAuthenticatorProperties()
                .get(DaonConstants.PropertyCarriers.LOGIN_HINT);
        if (!DaonJwtUtil.isExpectedSubject(expectedSubject, returnedPreferredUsername)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Daon returned an identity that does not match the account being recovered. "
                        + "Expected: " + (LoggerUtils.isLogMaskingEnable
                                ? LoggerUtils.getMaskedContent(expectedSubject) : expectedSubject)
                        + ", returned preferred_username: " + (LoggerUtils.isLogMaskingEnable
                                ? LoggerUtils.getMaskedContent(returnedPreferredUsername)
                                : returnedPreferredUsername));
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

        String givenNameUri = resolveNameClaimUri(daonToLocalClaim, DaonConstants.DaonClaims.GIVEN_NAME,
                FIRST_NAME_CLAIM);
        String familyNameUri = resolveNameClaimUri(daonToLocalClaim, DaonConstants.DaonClaims.FAMILY_NAME,
                LAST_NAME_CLAIM);
        boolean hasGiven = profileClaims.containsKey(givenNameUri);
        boolean hasLast = profileClaims.containsKey(familyNameUri);
        if (hasGiven && hasLast) {
            return;
        }
        String combined = DaonJwtUtil.resolveClaimValue(DaonConstants.DaonClaims.FAMILY_NAME_AND_GIVEN_NAME,
                daonClaims.opt(DaonConstants.DaonClaims.FAMILY_NAME_AND_GIVEN_NAME));
        if (StringUtils.isBlank(combined)
                || !combined.contains(DaonConstants.DaonClaims.FIELD_SEPARATOR)) {
            return;
        }
        String[] parts = combined.split(
                Pattern.quote(DaonConstants.DaonClaims.FIELD_SEPARATOR), 2);
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
        List<String> missing = new ArrayList<>();
        for (String uri : claimUris) {
            if (!resolved.containsKey(uri)) {
                missing.add(uri);
            }
        }
        resolved.putAll(DaonUserClaimReader.readByUserId(context.getTenantDomain(), flowUser.getUserId(),
                missing, "the invited user"));
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
        return DaonFederatedAssociationUtil.resolveEnrolledSubject(username, context.getTenantDomain(),
                daonIdpName);
    }

    private String resolveDaonIdpName(FlowExecutionContext context) {

        return DaonReferencedIdpUtil.resolveDaonIdpName(
                context.getAuthenticatorProperties().get(IDP_ID),
                context.getExternalIdPConfig() != null ? context.getExternalIdPConfig().getIdPName() : null,
                context.getTenantDomain());
    }

    private Map<String, String> resolvePrefilledClaimValues(FlowExecutionContext context,
                                                             Map<String, String> claimMappings) {

        Map<String, String> localValues;
        if (isFlowType(INVITED_USER_REGISTRATION, context)) {
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

        return DaonClaimMappingUtil.toDaonClaimValues(claimMappings, localValues);
    }

    private static boolean isFlowType(FlowTypes flowType, FlowExecutionContext flowExecutionContext) {

        return flowType.getType().equals(flowExecutionContext.getFlowType());
    }

    private Map<String, String> getIdpClaimMappings(FlowExecutionContext context) {

        ExternalIdPConfig idpConfig = context.getExternalIdPConfig();
        return DaonClaimMappingUtil.toClaimMap(idpConfig != null ? idpConfig.getClaimMappings() : null);
    }
}
