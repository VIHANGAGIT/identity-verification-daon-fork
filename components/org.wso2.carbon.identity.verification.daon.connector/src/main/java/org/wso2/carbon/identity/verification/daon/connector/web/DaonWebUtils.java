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

package org.wso2.carbon.identity.verification.daon.connector.web;

import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.BufferedHttpEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicHttpResponse;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonClientException;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;

import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.APPLICATION_FORM_URLENCODED;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.APPLICATION_JSON;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.BASIC_PREFIX;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.BEARER_PREFIX;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_IDENTITY_VERIFICATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_INVALID_BASE_URL;

/**
 * HTTP utility methods for the Daon TrustX connector.
 */
public class DaonWebUtils {

    private DaonWebUtils() {

    }

    /**
     * Sends an HTTP POST request to the Daon token endpoint using Basic auth and form-urlencoded body.
     *
     * @param clientId     OIDC client ID.
     * @param clientSecret OIDC client secret.
     * @param requestURL   The token endpoint URL.
     * @param requestBody  URL-encoded form body (e.g., grant_type=authorization_code&code=...).
     * @return The HTTP response.
     */
    public static HttpResponse httpPostWithBasicAuth(String clientId, String clientSecret,
                                                     String requestURL, String requestBody)
            throws DaonServerException, DaonClientException {

        HttpPost request = new HttpPost(requestURL);
        String credentials = Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        request.addHeader(HttpHeaders.AUTHORIZATION, BASIC_PREFIX + credentials);
        request.addHeader(HttpHeaders.CONTENT_TYPE, APPLICATION_FORM_URLENCODED);
        request.setEntity(new StringEntity(requestBody,
                ContentType.create(APPLICATION_FORM_URLENCODED, StandardCharsets.UTF_8)));

        CloseableHttpClient client = HTTPClientManager.getInstance().getHttpClient();
        try (CloseableHttpResponse response = client.execute(request)) {
            return toHttpResponse(response);
        } catch (UnknownHostException e) {
            throw new DaonClientException(ERROR_INVALID_BASE_URL.getCode(),
                    ERROR_INVALID_BASE_URL.getMessage(), e);
        } catch (IOException e) {
            throw new DaonServerException(ERROR_IDENTITY_VERIFICATION.getCode(),
                    ERROR_IDENTITY_VERIFICATION.getMessage(), e);
        }
    }

    /**
     * Sends an HTTP GET request to the Daon userinfo endpoint using Bearer token auth.
     *
     * @param accessToken The OAuth2 access token.
     * @param requestURL  The userinfo endpoint URL.
     * @return The HTTP response.
     */
    public static HttpResponse httpGetWithBearerAuth(String accessToken, String requestURL)
            throws DaonServerException, DaonClientException {

        HttpGet request = new HttpGet(requestURL);
        request.addHeader(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken);
        request.addHeader(HttpHeaders.ACCEPT, APPLICATION_JSON);

        CloseableHttpClient client = HTTPClientManager.getInstance().getHttpClient();
        try (CloseableHttpResponse response = client.execute(request)) {
            return toHttpResponse(response);
        } catch (UnknownHostException e) {
            throw new DaonClientException(ERROR_INVALID_BASE_URL.getCode(),
                    ERROR_INVALID_BASE_URL.getMessage(), e);
        } catch (IOException e) {
            throw new DaonServerException(ERROR_IDENTITY_VERIFICATION.getCode(),
                    ERROR_IDENTITY_VERIFICATION.getMessage(), e);
        }
    }

    private static HttpResponse toHttpResponse(CloseableHttpResponse response) throws IOException {

        HttpResponse result = new BasicHttpResponse(response.getStatusLine());
        if (response.getEntity() != null) {
            result.setEntity(new BufferedHttpEntity(response.getEntity()));
        }
        return result;
    }
}
