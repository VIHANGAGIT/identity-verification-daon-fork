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

package org.wso2.carbon.identity.verification.daon.api.v1;

import org.wso2.carbon.identity.verification.daon.api.v1.factories.DefaultApiServiceFactory;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

/**
 * JAX-RS resource class for the Daon OIDC callback endpoint.
 */
@Path("/")
@Api(description = "Daon TrustX Identity Verification Callback API")
public class DefaultApi {

    private final DefaultApiService delegate;

    public DefaultApi() {

        delegate = DefaultApiServiceFactory.getDefaultApi();
    }

    @GET
    @Path("/{idvp-id}/callback")
    @Produces({ "application/json" })
    @ApiOperation(value = "Handle Daon OIDC callback",
            notes = "Processes the OIDC authorization code callback from Daon TrustX after identity verification.",
            response = Void.class,
            tags = { "Identity Verification" })
    @ApiResponses(value = {
        @ApiResponse(code = 302, message = "Redirect to callback URL after processing", response = Void.class),
        @ApiResponse(code = 400, message = "Bad Request", response = Void.class),
        @ApiResponse(code = 500, message = "Server Error", response = Void.class)
    })
    public Response callback(
            @ApiParam(value = "Id of the identity verification provider", required = true)
            @PathParam("idvp-id") String idvpId,
            @ApiParam(value = "Authorization code returned by Daon", required = true)
            @QueryParam("code") String code,
            @ApiParam(value = "State parameter for CSRF protection", required = true)
            @QueryParam("state") String state,
            @ApiParam(value = "Session state returned by Daon")
            @QueryParam("session_state") String sessionState) {

        return delegate.callback(idvpId, code, state, sessionState);
    }
}
