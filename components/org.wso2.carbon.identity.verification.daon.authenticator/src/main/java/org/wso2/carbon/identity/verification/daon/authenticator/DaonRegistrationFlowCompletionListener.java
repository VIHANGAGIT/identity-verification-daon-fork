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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.verification.mgt.exception.IdentityVerificationException;
import org.wso2.carbon.extension.identity.verification.mgt.model.IdVClaim;
import org.wso2.carbon.extension.identity.verification.provider.exception.IdVProviderMgtException;
import org.wso2.carbon.extension.identity.verification.provider.model.IdVProvider;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.listener.AbstractFlowExecutionListener;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionStep;
import org.wso2.carbon.identity.verification.daon.authenticator.internal.DaonAuthenticatorDataHolder;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.FLOW_CONTEXT_DAON_IDVP_ID;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.FLOW_CONTEXT_DAON_VERIFIED_CLAIMS;

/**
 * Flow execution listener that persists Daon TrustX verified claims to the IDV_CLAIM table
 * when a registration flow completes.
 *
 * <p>Handles both the self sign-up flow (user created during the flow) and the invited user
 * registration flow (user pre-existing). In both cases the {@link DaonExecutor} stores extracted
 * claims in the {@link FlowExecutionContext} and this listener writes them to the IDV store once
 * the flow status reaches {@code COMPLETE} and the user ID is guaranteed to be available.</p>
 */
public class DaonRegistrationFlowCompletionListener extends AbstractFlowExecutionListener {

    private static final Log LOG = LogFactory.getLog(DaonRegistrationFlowCompletionListener.class);

    @Override
    public int getExecutionOrderId() {
        return 10;
    }

    @Override
    public int getDefaultOrderId() {
        return 10;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean doPostExecute(FlowExecutionStep step, FlowExecutionContext context) {

        if (!Constants.STATUS_COMPLETE.equals(step.getFlowStatus())) {
            return true;
        }
        Object claimsObj = context.getProperty(FLOW_CONTEXT_DAON_VERIFIED_CLAIMS);
        if (claimsObj == null) {
            return true;
        }
        @SuppressWarnings("unchecked")
        Map<String, String> verifiedClaims = (Map<String, String>) claimsObj;
        String idvpId = (String) context.getProperty(FLOW_CONTEXT_DAON_IDVP_ID);
        String userId = context.getFlowUser().getUserId();
        int tenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());

        List<IdVClaim> idVClaims = buildIdVClaims(userId, idvpId, tenantId, verifiedClaims);
        if (idVClaims.isEmpty()) {
            return true;
        }
        try {
            DaonAuthenticatorDataHolder.getIdentityVerificationManager()
                    .addIdVClaims(userId, idVClaims, tenantId);
        } catch (IdentityVerificationException e) {
            LOG.error("Error persisting Daon verified claims for user: " + userId, e);
        }
        return true;
    }

    private List<IdVClaim> buildIdVClaims(String userId, String idvpId, int tenantId,
                                           Map<String, String> verifiedClaims) {

        List<IdVClaim> idVClaims = new ArrayList<>();
        IdVProvider idVProvider = null;
        try {
            idVProvider = DaonAuthenticatorDataHolder.getIdVProviderManager()
                    .getIdVProvider(idvpId, tenantId);
        } catch (IdVProviderMgtException e) {
            LOG.error("Error retrieving Daon IDVP for claim persistence. IDVP id: " + idvpId, e);
        }
        if (idVProvider == null) {
            LOG.error("Daon IDVP not found for id: " + idvpId + "; cannot persist IDV claims.");
            return idVClaims;
        }
        String completedAt = Instant.now().toString();
        for (Map.Entry<String, String> entry : verifiedClaims.entrySet()) {
            IdVClaim claim = new IdVClaim();
            claim.setUuid(UUID.randomUUID().toString());
            claim.setUserId(userId);
            claim.setClaimUri(entry.getKey());
            claim.setIdVPId(idVProvider.getIdVProviderUuid());
            claim.setIsVerified(true);
            Map<String, Object> metadata = new HashMap<>();
            metadata.put(DaonConstants.DAON_FLOW_STATUS,
                    DaonConstants.VerificationFlowStatus.COMPLETED.getStatus());
            metadata.put(DaonConstants.DAON_VERIFICATION_STATUS,
                    DaonConstants.DaonVerificationStatus.VERIFIED.getStatus());
            metadata.put(DaonConstants.DAON_COMPLETED_AT, completedAt);
            if (DaonConstants.PREFERRED_USERNAME_CLAIM_URI.equals(entry.getKey())) {
                metadata.put(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM, entry.getValue());
            }
            claim.setMetadata(metadata);
            idVClaims.add(claim);
        }
        return idVClaims;
    }
}
