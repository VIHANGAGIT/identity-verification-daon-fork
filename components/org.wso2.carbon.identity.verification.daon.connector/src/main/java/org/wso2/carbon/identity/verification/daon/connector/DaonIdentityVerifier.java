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

package org.wso2.carbon.identity.verification.daon.connector;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.verification.mgt.AbstractIdentityVerifier;
import org.wso2.carbon.extension.identity.verification.mgt.exception.IdentityVerificationClientException;
import org.wso2.carbon.extension.identity.verification.mgt.exception.IdentityVerificationException;
import org.wso2.carbon.extension.identity.verification.mgt.exception.IdentityVerificationServerException;
import org.wso2.carbon.extension.identity.verification.mgt.model.IdVClaim;
import org.wso2.carbon.extension.identity.verification.mgt.model.IdVProperty;
import org.wso2.carbon.extension.identity.verification.mgt.model.IdentityVerifierData;
import org.wso2.carbon.extension.identity.verification.mgt.utils.IdentityVerificationConstants;
import org.wso2.carbon.extension.identity.verification.mgt.utils.IdentityVerificationExceptionMgt;
import org.wso2.carbon.extension.identity.verification.provider.model.IdVProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonClientException;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonIDVDataHolder;
import org.wso2.carbon.identity.verification.daon.connector.web.DaonAPIClient;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.wso2.carbon.extension.identity.verification.mgt.utils.IdentityVerificationConstants.ErrorMessage.ERROR_GETTING_USER_STORE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.AUTHORIZATION_ENDPOINT_URL;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CALLBACK_URL;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLIENT_ID;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_AUTHORIZATION_URL;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_CALLBACK_URL_FORMAT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_FLOW_STATUS;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_STATE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.SCOPE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.STATUS;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_CLAIM_MAPPING_NOT_FOUND;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_CLAIM_VALUE_NOT_EXIST;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_DAON_STATE_NOT_FOUND;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_IDV_PROVIDER_CONFIG_PROPERTIES_EMPTY;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_IDV_PROVIDER_INVALID_OR_DISABLED;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_INITIATING_DAON_VERIFICATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_INVALID_DAON_VERIFICATION_FLOW_STATUS;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_REINITIATING_DAON_VERIFICATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_REINITIATION_NOT_ALLOWED;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_RETRIEVING_CLAIMS_AGAINST_STATE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_VERIFICATION_FLOW_STATUS_NOT_FOUND;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_VERIFICATION_REQUIRED_CLAIMS_NOT_FOUND;
import static org.wso2.carbon.user.core.constants.UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER;

/**
 * Daon TrustX identity verifier implementation.
 *
 * <p>Verification uses the OIDC Authorization Code flow:
 * <ol>
 *   <li>INITIATED  — builds authorization URL and returns it to the client</li>
 *   <li>REINITIATED — builds a fresh authorization URL for an incomplete flow</li>
 *   <li>COMPLETED  — read-only; the callback endpoint already stored results</li>
 * </ol>
 */
public class DaonIdentityVerifier extends AbstractIdentityVerifier {

    private static final Log log = LogFactory.getLog(DaonIdentityVerifier.class);

    @Override
    public IdentityVerifierData verifyIdentity(String userId, IdentityVerifierData identityVerifierData, int tenantId)
            throws IdentityVerificationException {

        IdVProvider idVProvider = getValidatedIdVProvider(identityVerifierData, tenantId);
        Map<String, String> idVProviderConfigProperties = getValidatedIdVConfigProperties(idVProvider);
        DaonConstants.VerificationFlowStatus verificationFlowStatus = getVerificationFlowStatus(identityVerifierData);

        List<IdVClaim> idVClaims;
        switch (verificationFlowStatus) {
            case INITIATED:
                idVClaims = initiateDaonVerification(userId, identityVerifierData, idVProvider,
                        idVProviderConfigProperties, tenantId);
                break;
            case REINITIATED:
                idVClaims = reinitiateDaonVerification(userId, identityVerifierData, idVProvider,
                        idVProviderConfigProperties, tenantId);
                break;
            case COMPLETED:
                idVClaims = completeDaonVerification(userId, identityVerifierData, idVProvider, tenantId);
                break;
            default:
                throw new IdentityVerificationClientException(ERROR_INVALID_DAON_VERIFICATION_FLOW_STATUS.getCode(),
                        ERROR_INVALID_DAON_VERIFICATION_FLOW_STATUS.getMessage());
        }
        identityVerifierData.setIdVClaims(idVClaims);
        return identityVerifierData;
    }

    /**
     * Initiates Daon verification: validates claims, generates an OIDC state UUID, builds the
     * authorization URL, persists metadata, and returns the URL in the claim metadata.
     */
    private List<IdVClaim> initiateDaonVerification(String userId, IdentityVerifierData identityVerifierData,
                                                     IdVProvider idVProvider,
                                                     Map<String, String> idVProviderConfigProperties, int tenantId)
            throws IdentityVerificationException {

        List<IdVClaim> verificationRequiredClaims = getVerificationRequiredClaims(identityVerifierData);
        List<IdVClaim> claimsToUpdate = new ArrayList<>();

        Map<String, String> claimsMap = getClaimsWithValueMap(userId, tenantId, idVProvider,
                verificationRequiredClaims, claimsToUpdate);

        try {
            String state = UUID.randomUUID().toString();
            List<String> daonClaimNames = new ArrayList<>(claimsMap.keySet());
            String redirectUri = IdentityUtil.getServerURL(
                    String.format(DAON_CALLBACK_URL_FORMAT, idVProvider.getIdVProviderUuid()), true, true);
            String authorizationUrl = DaonAPIClient.buildAuthorizationUrl(idVProviderConfigProperties, state,
                    daonClaimNames, redirectUri);

            Map<String, Object> persistedMetadata = buildInitiatedMetadata(state);
            updateAndStoreClaims(userId, tenantId, idVProvider, verificationRequiredClaims, claimsToUpdate,
                    persistedMetadata);

            Map<String, Object> responseMetadata = new HashMap<>(persistedMetadata);
            responseMetadata.put(DAON_AUTHORIZATION_URL, authorizationUrl);
            for (IdVClaim idVClaim : verificationRequiredClaims) {
                idVClaim.setMetadata(responseMetadata);
            }
        } catch (DaonServerException e) {
            throw new IdentityVerificationServerException(ERROR_INITIATING_DAON_VERIFICATION.getCode(),
                    String.format(ERROR_INITIATING_DAON_VERIFICATION.getMessage(), userId), e);
        }
        return verificationRequiredClaims;
    }

    /**
     * Reinitiates Daon verification: generates a new state UUID and a fresh authorization URL.
     * Rejected if the flow status is already COMPLETED.
     */
    private List<IdVClaim> reinitiateDaonVerification(String userId, IdentityVerifierData identityVerifierData,
                                                       IdVProvider idVProvider,
                                                       Map<String, String> idVProviderConfigProperties, int tenantId)
            throws IdentityVerificationException {

        String existingState = getDaonState(userId, tenantId, idVProvider, identityVerifierData);
        List<IdVClaim> idVClaims = getIdVClaimsByState(existingState, idVProvider.getIdVProviderUuid(), tenantId);

        String flowStatus = (String) idVClaims.get(0).getMetadata().get(DAON_FLOW_STATUS);
        if (DaonConstants.VerificationFlowStatus.COMPLETED.getStatus().equals(flowStatus)) {
            throw new IdentityVerificationClientException(ERROR_REINITIATION_NOT_ALLOWED.getCode(),
                    ERROR_REINITIATION_NOT_ALLOWED.getMessage());
        }

        try {
            String newState = UUID.randomUUID().toString();
            Map<String, String> claimMappings = idVProvider.getClaimMappings();
            List<String> daonClaimNames = idVClaims.stream()
                    .map(c -> claimMappings.get(c.getClaimUri()))
                    .filter(name -> name != null)
                    .collect(Collectors.toList());
            String redirectUri = IdentityUtil.getServerURL(
                    String.format(DAON_CALLBACK_URL_FORMAT, idVProvider.getIdVProviderUuid()), true, true);
            String authorizationUrl = DaonAPIClient.buildAuthorizationUrl(idVProviderConfigProperties, newState,
                    daonClaimNames, redirectUri);

            for (IdVClaim idVClaim : idVClaims) {
                Map<String, Object> metadata = idVClaim.getMetadata();
                metadata.put(DAON_STATE, newState);
                metadata.put(DAON_FLOW_STATUS, DaonConstants.VerificationFlowStatus.REINITIATED.getStatus());
                idVClaim.setMetadata(metadata);
                updateIdVClaim(userId, idVClaim, tenantId);
            }
            for (IdVClaim idVClaim : idVClaims) {
                idVClaim.getMetadata().put(DAON_AUTHORIZATION_URL, authorizationUrl);
            }
        } catch (DaonServerException e) {
            throw new IdentityVerificationServerException(ERROR_REINITIATING_DAON_VERIFICATION.getCode(),
                    ERROR_REINITIATING_DAON_VERIFICATION.getMessage(), e);
        }
        return idVClaims;
    }

    /**
     * Completes the Daon verification flow. This is a read-only operation — the callback endpoint
     * already exchanged the OIDC code and stored the results. Simply return the current claim state.
     */
    private List<IdVClaim> completeDaonVerification(String userId, IdentityVerifierData identityVerifierData,
                                                     IdVProvider idVProvider, int tenantId)
            throws IdentityVerificationException {

        String state = getDaonState(userId, tenantId, idVProvider, identityVerifierData);
        return getIdVClaimsByState(state, idVProvider.getIdVProviderUuid(), tenantId);
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private IdVProvider getValidatedIdVProvider(IdentityVerifierData identityVerifierData, int tenantId)
            throws IdentityVerificationException {

        IdVProvider idVProvider = getIdVProvider(identityVerifierData, tenantId);
        if (idVProvider == null || !idVProvider.isEnabled()) {
            throw new IdentityVerificationClientException(ERROR_IDV_PROVIDER_INVALID_OR_DISABLED.getCode(),
                    ERROR_IDV_PROVIDER_INVALID_OR_DISABLED.getMessage());
        }
        return idVProvider;
    }

    private Map<String, String> getValidatedIdVConfigProperties(IdVProvider idVProvider)
            throws IdentityVerificationClientException {

        Map<String, String> props = getIdVConfigPropertyMap(idVProvider);
        if (props == null || props.isEmpty()
                || StringUtils.isBlank(props.get(CLIENT_ID))
                || StringUtils.isBlank(props.get(CLIENT_SECRET))
                || StringUtils.isBlank(props.get(AUTHORIZATION_ENDPOINT_URL))
                || StringUtils.isBlank(props.get(SCOPE))
                || StringUtils.isBlank(props.get(CALLBACK_URL))) {
            throw new IdentityVerificationClientException(ERROR_IDV_PROVIDER_CONFIG_PROPERTIES_EMPTY.getCode(),
                    ERROR_IDV_PROVIDER_CONFIG_PROPERTIES_EMPTY.getMessage());
        }
        return props;
    }

    private static List<IdVClaim> getVerificationRequiredClaims(IdentityVerifierData identityVerifierData)
            throws IdentityVerificationClientException {

        List<IdVClaim> claims = identityVerifierData.getIdVClaims();
        if (claims == null || claims.isEmpty()) {
            throw new IdentityVerificationClientException(ERROR_VERIFICATION_REQUIRED_CLAIMS_NOT_FOUND.getCode(),
                    ERROR_VERIFICATION_REQUIRED_CLAIMS_NOT_FOUND.getMessage());
        }
        return claims;
    }

    private DaonConstants.VerificationFlowStatus getVerificationFlowStatus(IdentityVerifierData identityVerifierData)
            throws IdentityVerificationClientException {

        String statusValue = getPropertyValue(identityVerifierData, STATUS, ERROR_VERIFICATION_FLOW_STATUS_NOT_FOUND);
        try {
            return DaonConstants.VerificationFlowStatus.fromString(statusValue);
        } catch (DaonClientException e) {
            throw new IdentityVerificationClientException(ERROR_INVALID_DAON_VERIFICATION_FLOW_STATUS.getCode(),
                    ERROR_INVALID_DAON_VERIFICATION_FLOW_STATUS.getMessage());
        }
    }

    private String getPropertyValue(IdentityVerifierData identityVerifierData, String propertyName,
                                    DaonConstants.ErrorMessage errorMessage)
            throws IdentityVerificationClientException {

        List<IdVProperty> properties = identityVerifierData.getIdVProperties();
        if (properties == null || properties.isEmpty()) {
            throw new IdentityVerificationClientException(errorMessage.getCode(), errorMessage.getMessage());
        }
        for (IdVProperty property : properties) {
            if (StringUtils.equals(property.getName(), propertyName) && StringUtils.isNotBlank(property.getValue())) {
                return property.getValue();
            }
        }
        throw new IdentityVerificationClientException(errorMessage.getCode(), errorMessage.getMessage());
    }

    private Map<String, String> getClaimsWithValueMap(String userId, int tenantId, IdVProvider idVProvider,
                                                        List<IdVClaim> verificationRequiredClaims,
                                                        List<IdVClaim> claimsToUpdate)
            throws IdentityVerificationException {

        Map<String, String> idVProviderClaimWithValueMap = new HashMap<>();
        try {
            Map<String, String> idVClaimMap = idVProvider.getClaimMappings();
            UniqueIDUserStoreManager uniqueIDUserStoreManager = getUniqueIdEnabledUserStoreManager(tenantId);

            for (IdVClaim idVClaim : verificationRequiredClaims) {
                String claimUri = idVClaim.getClaimUri();
                IdVClaim existingIdVClaim = DaonIDVDataHolder.getIdentityVerificationManager()
                        .getIdVClaim(userId, claimUri, idVProvider.getIdVProviderUuid(), tenantId);

                String claimValue = uniqueIDUserStoreManager.getUserClaimValueWithID(userId, claimUri, null);
                if (StringUtils.isEmpty(claimValue)) {
                    throw new IdentityVerificationClientException(ERROR_CLAIM_VALUE_NOT_EXIST.getCode(),
                            String.format(ERROR_CLAIM_VALUE_NOT_EXIST.getMessage(), claimUri));
                }
                if (!idVClaimMap.containsKey(claimUri)) {
                    throw new IdentityVerificationClientException(ERROR_CLAIM_MAPPING_NOT_FOUND.getCode(),
                            String.format(ERROR_CLAIM_MAPPING_NOT_FOUND.getMessage(), claimUri));
                }
                idVProviderClaimWithValueMap.put(idVClaimMap.get(claimUri), claimValue);

                if (existingIdVClaim != null) {
                    existingIdVClaim.setClaimValue(claimValue);
                    claimsToUpdate.add(existingIdVClaim);
                } else {
                    idVClaim.setClaimValue(claimValue);
                }
            }
        } catch (UserStoreException e) {
            if (StringUtils.isNotBlank(e.getMessage()) &&
                    e.getMessage().contains(ERROR_CODE_NON_EXISTING_USER.getCode())) {
                if (log.isDebugEnabled()) {
                    log.debug("User does not exist with the given user id: " + userId);
                }
            }
            throw IdentityVerificationExceptionMgt.handleServerException(
                    IdentityVerificationConstants.ErrorMessage.ERROR_RETRIEVING_IDV_CLAIM_MAPPINGS, userId, e);
        }
        return idVProviderClaimWithValueMap;
    }

    private Map<String, Object> buildInitiatedMetadata(String state) {

        Map<String, Object> metadata = new HashMap<>();
        metadata.put(DAON_STATE, state);
        metadata.put(DAON_FLOW_STATUS, DaonConstants.VerificationFlowStatus.INITIATED.getStatus());
        return metadata;
    }

    private void updateAndStoreClaims(String userId, int tenantId, IdVProvider idVProvider,
                                       List<IdVClaim> verificationRequiredClaims, List<IdVClaim> claimsToUpdate,
                                       Map<String, Object> metadata) throws IdentityVerificationException {

        Set<String> updateClaimUris = claimsToUpdate.stream()
                .map(IdVClaim::getClaimUri)
                .collect(Collectors.toSet());

        for (IdVClaim claim : claimsToUpdate) {
            claim.setIsVerified(false);
            claim.setMetadata(metadata);
            updateIdVClaim(userId, claim, tenantId);
        }

        List<IdVClaim> claimsToStore = new ArrayList<>();
        for (IdVClaim claim : verificationRequiredClaims) {
            if (!updateClaimUris.contains(claim.getClaimUri())) {
                claim.setIsVerified(false);
                claim.setUserId(userId);
                claim.setIdVPId(idVProvider.getIdVProviderUuid());
                claim.setMetadata(metadata);
                claimsToStore.add(claim);
            }
        }
        if (!claimsToStore.isEmpty()) {
            storeIdVClaims(userId, claimsToStore, tenantId);
        }
    }

    private static String getDaonState(String userId, int tenantId, IdVProvider idVProvider,
                                        IdentityVerifierData identityVerifierData)
            throws IdentityVerificationException {

        List<IdVClaim> verificationRequiredClaims = getVerificationRequiredClaims(identityVerifierData);
        Set<String> verificationRequiredClaimsUri = verificationRequiredClaims.stream()
                .map(IdVClaim::getClaimUri)
                .collect(Collectors.toSet());

        IdVClaim[] idVClaims = DaonIDVDataHolder.getIdentityVerificationManager()
                .getIdVClaims(userId, idVProvider.getIdVProviderUuid(), null, tenantId);
        for (IdVClaim idVClaim : idVClaims) {
            if (idVClaim != null && idVClaim.getMetadata() != null
                    && idVClaim.getMetadata().get(DAON_STATE) != null
                    && verificationRequiredClaimsUri.contains(idVClaim.getClaimUri())) {
                return (String) idVClaim.getMetadata().get(DAON_STATE);
            }
        }
        throw new IdentityVerificationClientException(ERROR_DAON_STATE_NOT_FOUND.getCode(),
                ERROR_DAON_STATE_NOT_FOUND.getMessage());
    }

    private List<IdVClaim> getIdVClaimsByState(String state, String idVProviderUuid, int tenantId)
            throws IdentityVerificationException {

        IdVClaim[] idVClaimArray = DaonIDVDataHolder.getIdentityVerificationManager()
                .getIdVClaimsByMetadata(DAON_STATE, state, idVProviderUuid, tenantId);
        List<IdVClaim> idVClaims = new ArrayList<>(Arrays.asList(idVClaimArray));
        if (idVClaims.isEmpty()) {
            throw new IdentityVerificationClientException(ERROR_RETRIEVING_CLAIMS_AGAINST_STATE.getCode(),
                    ERROR_RETRIEVING_CLAIMS_AGAINST_STATE.getMessage());
        }
        return idVClaims;
    }

    private UniqueIDUserStoreManager getUniqueIdEnabledUserStoreManager(int tenantId)
            throws IdentityVerificationServerException, UserStoreException {

        RealmService realmService = DaonIDVDataHolder.getRealmService();
        UserStoreManager userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
        if (!(userStoreManager instanceof UniqueIDUserStoreManager)) {
            throw IdentityVerificationExceptionMgt.handleServerException(ERROR_GETTING_USER_STORE);
        }
        return (UniqueIDUserStoreManager) userStoreManager;
    }
}
