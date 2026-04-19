/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.verification.daon.api.v1.core;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.extension.identity.verification.mgt.IdentityVerificationManager;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.extension.identity.verification.mgt.exception.IdentityVerificationException;
import org.wso2.carbon.extension.identity.verification.mgt.model.IdVClaim;
import org.wso2.carbon.extension.identity.verification.provider.IdVProviderManager;
import org.wso2.carbon.extension.identity.verification.provider.exception.IdVProviderMgtException;
import org.wso2.carbon.extension.identity.verification.provider.model.IdVConfigProperty;
import org.wso2.carbon.extension.identity.verification.provider.model.IdVProvider;
import org.wso2.carbon.identity.verification.daon.api.common.Constants;
import org.wso2.carbon.identity.verification.daon.api.common.error.APIError;
import org.wso2.carbon.identity.verification.daon.api.common.error.ErrorResponse;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonClientException;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;
import org.wso2.carbon.identity.verification.daon.connector.web.DaonAPIClient;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.verification.daon.api.common.Constants.ErrorMessage.CLIENT_ERROR_INVALID_CALLBACK_PARAMS;
import static org.wso2.carbon.identity.verification.daon.api.common.Constants.ErrorMessage.CLIENT_ERROR_INVALID_CREDENTIALS;
import static org.wso2.carbon.identity.verification.daon.api.common.Constants.ErrorMessage.CLIENT_ERROR_INVALID_OR_EXPIRED_CODE;
import static org.wso2.carbon.identity.verification.daon.api.common.Constants.ErrorMessage.CLIENT_ERROR_RESOLVING_IDVP;
import static org.wso2.carbon.identity.verification.daon.api.common.Constants.ErrorMessage.CLIENT_ERROR_STATE_MISMATCH;
import static org.wso2.carbon.identity.verification.daon.api.common.Constants.ErrorMessage.SERVER_ERROR_GENERAL_ERROR;
import static org.wso2.carbon.identity.verification.daon.api.common.Constants.ErrorMessage.SERVER_ERROR_IDV_PROVIDER_CONFIG_PROPERTIES_INVALID;
import static org.wso2.carbon.identity.verification.daon.api.common.Constants.ErrorMessage.SERVER_ERROR_RESOLVING_IDVP;
import static org.wso2.carbon.identity.verification.daon.api.common.Constants.ErrorMessage.SERVER_ERROR_TOKEN_EXCHANGE;
import static org.wso2.carbon.identity.verification.daon.api.common.Constants.ErrorMessage.SERVER_ERROR_UPDATING_IDV_CLAIM_VERIFICATION_STATUS;
import static org.wso2.carbon.identity.verification.daon.api.common.Util.getTenantId;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLAIMS_PARAM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.TOKEN_ENDPOINT_URL;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CALLBACK_URL;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLIENT_ID;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_CALLBACK_URL_FORMAT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_COMPLETED_AT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_FLOW_STATUS;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_STATE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_VERIFICATION_STATUS;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.SCOPE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.VERIFIED_CLAIMS_ID_TOKEN;

/**
 * Handles the Daon TrustX OIDC callback after the user completes identity verification.
 *
 * <p>Processing steps:
 * <ol>
 *   <li>Validates code and state query parameters</li>
 *   <li>Resolves the IdV provider from the URL path</li>
 *   <li>Looks up claims by stored daon_state metadata (CSRF check)</li>
 *   <li>Exchanges the authorization code for tokens</li>
 *   <li>Fetches user info from Daon userinfo endpoint</li>
 *   <li>Updates each claim's isVerified flag and metadata</li>
 *   <li>Returns 302 redirect to the configured callback URL</li>
 * </ol>
 */
public class DaonCallbackService {

    private static final Log log = LogFactory.getLog(DaonCallbackService.class);

    private final IdVProviderManager idVProviderManager;
    private final IdentityVerificationManager identityVerificationManager;

    public DaonCallbackService(IdVProviderManager idVProviderManager,
                                IdentityVerificationManager identityVerificationManager) {

        this.idVProviderManager = idVProviderManager;
        this.identityVerificationManager = identityVerificationManager;
    }

    /**
     * Processes the OIDC callback from Daon and returns a redirect to the configured post-verification page.
     *
     * @param idvpId       The IdV provider UUID from the URL path.
     * @param code         The authorization code from Daon.
     * @param state        The state parameter (CSRF token) from Daon.
     * @param sessionState The optional session_state parameter from Daon.
     * @return HTTP 302 redirect to the configured callback URL.
     */
    public Response handleCallback(String idvpId, String code, String state, String sessionState) {

        if (StringUtils.isBlank(code) || StringUtils.isBlank(state)) {
            throw buildClientError(CLIENT_ERROR_INVALID_CALLBACK_PARAMS, Response.Status.BAD_REQUEST);
        }

        int tenantId = getTenantId();

        IdVProvider idVProvider = getIdVProvider(idvpId, tenantId);
        Map<String, String> configProperties = getValidatedConfigProperties(idVProvider);

        IdVClaim[] claims = getClaimsByState(state, idvpId, tenantId);
        validateStateMatch(claims, state);

        String redirectUri = IdentityUtil.getServerURL(
                String.format(DAON_CALLBACK_URL_FORMAT, idvpId), true, true);

        JSONObject tokenResponse;
        try {
            tokenResponse = DaonAPIClient.exchangeCodeForTokens(configProperties, code, redirectUri);
        } catch (DaonClientException e) {
            if (DaonConstants.ErrorMessage.ERROR_INVALID_OR_EXPIRED_CODE.getCode().equals(e.getErrorCode())) {
                throw buildClientError(CLIENT_ERROR_INVALID_OR_EXPIRED_CODE, Response.Status.BAD_REQUEST);
            }
            throw buildClientError(CLIENT_ERROR_INVALID_CREDENTIALS, Response.Status.UNAUTHORIZED);
        } catch (DaonServerException e) {
            throw buildServerError(SERVER_ERROR_TOKEN_EXCHANGE, Response.Status.INTERNAL_SERVER_ERROR, e);
        }

        String idToken = tokenResponse.optString(DaonConstants.ID_TOKEN);
        JSONObject idTokenClaims = DaonAPIClient.parseIdToken(idToken);

        updateIdVClaims(idVProvider, claims, idTokenClaims, tenantId);

        String preferredUsername = idTokenClaims.optString(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM, null);
        if (StringUtils.isNotBlank(preferredUsername)) {
            storePreferredUsernameClaim(claims[0].getUserId(), preferredUsername, idvpId, tenantId);
        }

        String callbackUrl = configProperties.get(CALLBACK_URL);
        try {
            return Response.seeOther(new URI(callbackUrl)).build();
        } catch (URISyntaxException e) {
            log.error("Invalid callback URL configured: " + callbackUrl, e);
            return Response.status(Response.Status.FOUND)
                    .header("Location", callbackUrl).build();
        }
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    private IdVProvider getIdVProvider(String idvpId, int tenantId) {

        try {
            IdVProvider idVProvider = idVProviderManager.getIdVProvider(idvpId, tenantId);
            if (idVProvider == null || !idVProvider.isEnabled()) {
                throw buildClientError(CLIENT_ERROR_RESOLVING_IDVP, Response.Status.NOT_FOUND);
            }
            return idVProvider;
        } catch (IdVProviderMgtException e) {
            throw buildServerError(SERVER_ERROR_RESOLVING_IDVP, Response.Status.INTERNAL_SERVER_ERROR, e);
        }
    }

    private Map<String, String> getValidatedConfigProperties(IdVProvider idVProvider) {

        IdVConfigProperty[] configProperties = idVProvider.getIdVConfigProperties();
        if (ArrayUtils.isEmpty(configProperties)) {
            throw buildServerError(SERVER_ERROR_IDV_PROVIDER_CONFIG_PROPERTIES_INVALID,
                    Response.Status.INTERNAL_SERVER_ERROR, null);
        }

        Map<String, String> props = new HashMap<>();
        for (IdVConfigProperty property : configProperties) {
            props.put(property.getName(), property.getValue());
        }

        if (StringUtils.isBlank(props.get(CLIENT_ID))
                || StringUtils.isBlank(props.get(CLIENT_SECRET))
                || StringUtils.isBlank(props.get(TOKEN_ENDPOINT_URL))
                || StringUtils.isBlank(props.get(SCOPE))
                || StringUtils.isBlank(props.get(CALLBACK_URL))) {
            throw buildServerError(SERVER_ERROR_IDV_PROVIDER_CONFIG_PROPERTIES_INVALID,
                    Response.Status.INTERNAL_SERVER_ERROR, null);
        }
        return props;
    }

    private IdVClaim[] getClaimsByState(String state, String idvpId, int tenantId) {

        try {
            IdVClaim[] claims = identityVerificationManager.getIdVClaimsByMetadata(
                    DAON_STATE, state, idvpId, tenantId);
            if (ArrayUtils.isEmpty(claims)) {
                throw buildClientError(CLIENT_ERROR_STATE_MISMATCH, Response.Status.BAD_REQUEST);
            }
            return claims;
        } catch (IdentityVerificationException e) {
            throw buildServerError(SERVER_ERROR_GENERAL_ERROR, Response.Status.INTERNAL_SERVER_ERROR, e);
        }
    }

    private void validateStateMatch(IdVClaim[] claims, String state) {

        String storedState = (String) claims[0].getMetadata().get(DAON_STATE);
        if (!state.equals(storedState)) {
            throw buildClientError(CLIENT_ERROR_STATE_MISMATCH, Response.Status.BAD_REQUEST);
        }
    }

    private void updateIdVClaims(IdVProvider idVProvider, IdVClaim[] claims, JSONObject idTokenClaims,
                                   int tenantId) {

        Map<String, String> claimMappings = idVProvider.getClaimMappings();
        String completedAt = Instant.now().toString();

        JSONObject verifiedClaimsContainer = idTokenClaims.optJSONObject(VERIFIED_CLAIMS_ID_TOKEN);
        JSONObject verifiedClaimValues = verifiedClaimsContainer != null
                ? verifiedClaimsContainer.optJSONObject(CLAIMS_PARAM) : null;

        if (log.isDebugEnabled()) {
            log.debug("Daon ID token verifiedClaims container: " + verifiedClaimsContainer);
            log.debug("Daon verified claim values: " + verifiedClaimValues);
        }

        for (IdVClaim claim : claims) {
            String wso2ClaimUri = claim.getClaimUri();
            String daonClaimName = claimMappings.get(wso2ClaimUri);

            if (log.isDebugEnabled()) {
                log.debug("Processing claim - WSO2 URI: " + wso2ClaimUri + ", Daon claim name: " + daonClaimName);
            }

            boolean verified = false;
            String verificationStatus = DaonConstants.DaonVerificationStatus.FAILED.getStatus();
            if (daonClaimName != null && verifiedClaimValues != null && verifiedClaimValues.has(daonClaimName)) {
                String daonValue = verifiedClaimValues.optString(daonClaimName);
                String profileValue = claim.getClaimValue();
                if (StringUtils.equalsIgnoreCase(
                        StringUtils.trimToEmpty(profileValue), StringUtils.trimToEmpty(daonValue))) {
                    verified = true;
                    verificationStatus = DaonConstants.DaonVerificationStatus.VERIFIED.getStatus();
                    if (log.isDebugEnabled()) {
                        log.debug("Claim verified - " + wso2ClaimUri + " = " + daonValue);
                    }
                } else {
                    verificationStatus = DaonConstants.DaonVerificationStatus.MISMATCH.getStatus();
                    if (log.isDebugEnabled()) {
                        log.debug("Claim value mismatch for " + wso2ClaimUri
                                + " - profile value does not match Daon verified value");
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Claim not verified - " + wso2ClaimUri
                            + " (daonClaimName=" + daonClaimName
                            + ", verifiedClaimValues=" + verifiedClaimValues + ")");
                }
            }

            claim.setIsVerified(verified);
            Map<String, Object> metadata = claim.getMetadata() != null ? claim.getMetadata() : new HashMap<>();
            metadata.put(DAON_FLOW_STATUS, DaonConstants.VerificationFlowStatus.COMPLETED.getStatus());
            metadata.put(DAON_COMPLETED_AT, completedAt);
            metadata.put(DAON_VERIFICATION_STATUS, verificationStatus);
            claim.setMetadata(metadata);

            try {
                identityVerificationManager.updateIdVClaim(claim.getUserId(), claim, tenantId);
            } catch (IdentityVerificationException e) {
                throw buildServerError(SERVER_ERROR_UPDATING_IDV_CLAIM_VERIFICATION_STATUS,
                        Response.Status.INTERNAL_SERVER_ERROR, e);
            }
        }
    }

    private void storePreferredUsernameClaim(String userId, String preferredUsername,
                                               String idvpId, int tenantId) {

        IdVClaim claim = new IdVClaim();
        claim.setUuid(UUID.randomUUID().toString());
        claim.setUserId(userId);
        claim.setClaimUri(DaonConstants.PREFERRED_USERNAME_CLAIM_URI);
        claim.setIdVPId(idvpId);
        claim.setIsVerified(true);

        Map<String, Object> metadata = new HashMap<>();
        metadata.put(DAON_FLOW_STATUS, DaonConstants.VerificationFlowStatus.COMPLETED.getStatus());
        metadata.put(DAON_VERIFICATION_STATUS, DaonConstants.DaonVerificationStatus.VERIFIED.getStatus());
        metadata.put(DAON_COMPLETED_AT, Instant.now().toString());
        metadata.put(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM, preferredUsername);
        claim.setMetadata(metadata);

        try {
            identityVerificationManager.addIdVClaims(userId, Collections.singletonList(claim), tenantId);
        } catch (IdentityVerificationException e) {
            log.warn("Failed to persist Daon preferred_username claim for user: " + userId, e);
        }
    }

    private APIError buildClientError(Constants.ErrorMessage errorMessage, Response.Status status) {

        return new APIError(status, new ErrorResponse.Builder()
                .withCode(errorMessage.getCode())
                .withMessage(errorMessage.getMessage())
                .withDescription(errorMessage.getDescription())
                .build(log, errorMessage.getMessage(), true));
    }

    private APIError buildServerError(Constants.ErrorMessage errorMessage, Response.Status status, Exception e) {

        if (e != null) {
            return new APIError(status, new ErrorResponse.Builder()
                    .withCode(errorMessage.getCode())
                    .withMessage(errorMessage.getMessage())
                    .withDescription(errorMessage.getDescription())
                    .build(log, e, errorMessage.getMessage(), false));
        }
        return new APIError(status, new ErrorResponse.Builder()
                .withCode(errorMessage.getCode())
                .withMessage(errorMessage.getMessage())
                .withDescription(errorMessage.getDescription())
                .build(log, errorMessage.getMessage(), false));
    }
}
