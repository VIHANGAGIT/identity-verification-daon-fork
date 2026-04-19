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

import org.wso2.carbon.identity.verification.daon.api.common.error.APIError;

import java.util.ResourceBundle;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 * Maps APIError exceptions to HTTP responses.
 */
public class APIErrorExceptionMapper implements ExceptionMapper<WebApplicationException> {

    static final String BUNDLE = "ErrorMappings";
    static ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE);

    private static Response.Status getHttpStatusCode(String errorCode, Response.Status defaultStatus) {

        Response.Status mappedStatus = null;
        try {
            String statusCodeValue = resourceBundle.getString(errorCode);
            mappedStatus = Response.Status.fromStatusCode(Integer.parseInt(statusCodeValue));
        } catch (Throwable ignored) {
        }
        return mappedStatus != null ? mappedStatus : defaultStatus;
    }

    @Override
    public Response toResponse(WebApplicationException e) {

        if (e instanceof APIError) {
            Object response = ((APIError) e).getResponseEntity();
            Response.Status status = getHttpStatusCode(((APIError) e).getCode(), ((APIError) e).getStatus());
            return buildResponse(response, status);
        }
        return e.getResponse();
    }

    private Response buildResponse(Object response, Response.Status status) {

        if (response != null) {
            return Response.status(status).entity(response)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).build();
        }
        return Response.status(status).header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).build();
    }
}
