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

package org.wso2.carbon.identity.verification.daon.api.dispatcher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.verification.daon.api.common.error.ErrorDTO;
import org.wso2.carbon.identity.verification.daon.api.common.error.ErrorResponse;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 * Handles all unhandled server errors and returns a default error response.
 */
public class DefaultExceptionMapper implements ExceptionMapper<Throwable> {

    public static final String PROCESSING_ERROR_CODE = "DIDV-65000";
    public static final String PROCESSING_ERROR_MESSAGE = "Unexpected Processing Error";
    public static final String PROCESSING_ERROR_DESCRIPTION = "Server encountered an error while serving the request";
    private static final Log log = LogFactory.getLog(DefaultExceptionMapper.class);

    @Override
    public Response toResponse(Throwable e) {

        log.error("Server encountered an error while serving the request", e);
        ErrorDTO errorDTO = new ErrorResponse.Builder().withCode(PROCESSING_ERROR_CODE)
                .withMessage(PROCESSING_ERROR_MESSAGE)
                .withDescription(PROCESSING_ERROR_DESCRIPTION).build();
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(errorDTO)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).build();
    }
}
