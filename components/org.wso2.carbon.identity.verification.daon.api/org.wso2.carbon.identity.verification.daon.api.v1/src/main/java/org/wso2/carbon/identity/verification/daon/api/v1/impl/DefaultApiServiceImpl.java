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

package org.wso2.carbon.identity.verification.daon.api.v1.impl;

import org.wso2.carbon.identity.verification.daon.api.v1.DefaultApiService;
import org.wso2.carbon.identity.verification.daon.api.v1.core.DaonCallbackService;
import org.wso2.carbon.identity.verification.daon.api.v1.factories.DaonCallbackServiceFactory;

import javax.ws.rs.core.Response;

/**
 * Default implementation of the Daon callback API service.
 */
public class DefaultApiServiceImpl implements DefaultApiService {

    private final DaonCallbackService daonCallbackService;

    public DefaultApiServiceImpl() {

        try {
            this.daonCallbackService = DaonCallbackServiceFactory.getDaonCallbackService();
        } catch (IllegalStateException e) {
            throw new RuntimeException("Error occurred while initiating DaonCallbackService.", e);
        }
    }

    @Override
    public Response callback(String idvpId, String code, String state, String sessionState) {

        return daonCallbackService.handleCallback(idvpId, code, state, sessionState);
    }
}
