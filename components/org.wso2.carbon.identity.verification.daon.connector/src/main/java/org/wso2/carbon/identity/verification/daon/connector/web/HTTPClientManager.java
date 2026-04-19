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

import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;

import java.io.IOException;

import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ErrorMessage.ERROR_CREATING_HTTP_CLIENT;

/**
 * Manages HTTP client connections for the Daon connector using a singleton pool.
 */
public class HTTPClientManager {

    private static final int HTTP_CONNECTION_TIMEOUT = 3000;
    private static final int HTTP_READ_TIMEOUT = 3000;
    private static final int HTTP_CONNECTION_REQUEST_TIMEOUT = 3000;
    private static final int DEFAULT_MAX_CONNECTIONS = 20;
    private static volatile HTTPClientManager httpClientManagerInstance;
    private final CloseableHttpClient httpClient;

    private HTTPClientManager(CloseableHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public static HTTPClientManager getInstance() throws DaonServerException {

        if (httpClientManagerInstance == null) {
            synchronized (HTTPClientManager.class) {
                if (httpClientManagerInstance == null) {
                    httpClientManagerInstance = createInstance();
                }
            }
        }
        return httpClientManagerInstance;
    }

    private static HTTPClientManager createInstance() throws DaonServerException {

        try {
            PoolingHttpClientConnectionManager connectionManager = createPoolingConnectionManager();
            RequestConfig config = createRequestConfig();
            CloseableHttpClient httpClient = HttpClients.custom()
                    .setDefaultRequestConfig(config)
                    .setConnectionManager(connectionManager)
                    .build();
            return new HTTPClientManager(httpClient);
        } catch (IOException e) {
            throw new DaonServerException(ERROR_CREATING_HTTP_CLIENT.getCode(),
                    ERROR_CREATING_HTTP_CLIENT.getMessage(), e);
        }
    }

    public CloseableHttpClient getHttpClient() throws DaonServerException {

        return httpClient;
    }

    private static RequestConfig createRequestConfig() {

        return RequestConfig.custom()
                .setConnectTimeout(HTTP_CONNECTION_TIMEOUT)
                .setConnectionRequestTimeout(HTTP_CONNECTION_REQUEST_TIMEOUT)
                .setSocketTimeout(HTTP_READ_TIMEOUT)
                .setRedirectsEnabled(false)
                .setRelativeRedirectsAllowed(false)
                .build();
    }

    private static PoolingHttpClientConnectionManager createPoolingConnectionManager() throws IOException {

        PoolingHttpClientConnectionManager poolingHttpClientConnectionMgr = new PoolingHttpClientConnectionManager();
        poolingHttpClientConnectionMgr.setMaxTotal(DEFAULT_MAX_CONNECTIONS);
        poolingHttpClientConnectionMgr.setDefaultMaxPerRoute(DEFAULT_MAX_CONNECTIONS);
        return poolingHttpClientConnectionMgr;
    }
}
