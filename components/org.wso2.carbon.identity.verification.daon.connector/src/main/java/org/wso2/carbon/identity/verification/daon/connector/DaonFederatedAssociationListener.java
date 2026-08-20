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

package org.wso2.carbon.identity.verification.daon.connector;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.listener.AbstractFlowExecutionListener;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionStep;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonFederatedAssociationUtil;

import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_FED_IDP_NAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_FED_SUBJECT;

/**
 * Persists the Daon federated association once a registration flow completes.
 */
public class DaonFederatedAssociationListener extends AbstractFlowExecutionListener {

    private static final Log LOG = LogFactory.getLog(DaonFederatedAssociationListener.class);

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
    public boolean doPostExecute(FlowExecutionStep step, FlowExecutionContext context) throws FlowEngineException {

        if (!Constants.STATUS_COMPLETE.equals(step.getFlowStatus())) {
            return true;
        }
        String daonSubject = (String) context.getProperty(DAON_FED_SUBJECT);
        String idpName = (String) context.getProperty(DAON_FED_IDP_NAME);
        if (StringUtils.isBlank(daonSubject) && StringUtils.isBlank(idpName)) {
            return true;
        }
        if (StringUtils.isBlank(daonSubject) || StringUtils.isBlank(idpName)) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the Daon subject or the IDP name is missing from the flow context");
        }
        if (context.getFlowUser() == null) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the completed flow has no flow user");
        }
        String username = DaonFederatedAssociationUtil.resolveQualifiedUsername(context.getFlowUser(),
                context.getTenantDomain());
        if (StringUtils.isBlank(username)) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the flow user has no username");
        }
        User user = DaonFederatedAssociationUtil.buildUser(username, context.getTenantDomain());
        if (daonSubject.equals(DaonFederatedAssociationUtil.getAssociatedDaonSubject(user, idpName))) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("The Daon enrolment is already recorded for the flow user on IDP: " + idpName);
            }
            return true;
        }
        String claimedBy = DaonFederatedAssociationUtil.getLocalUserForDaonSubject(context.getTenantDomain(),
                idpName, daonSubject);
        if (StringUtils.isNotBlank(claimedBy)) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_DAON_IDENTITY_ALREADY_ENROLLED, idpName));
            throw DaonExceptionMgt.handleFlowClientException(ErrorMessage.ERROR_DAON_IDENTITY_ALREADY_ENROLLED);
        }
        if (!DaonFederatedAssociationUtil.createAssociation(user, idpName, daonSubject)) {
            throw DaonExceptionMgt.handleFlowServerException(ErrorMessage.ERROR_CREATING_FED_ASSOCIATION, idpName);
        }
        return true;
    }
}
