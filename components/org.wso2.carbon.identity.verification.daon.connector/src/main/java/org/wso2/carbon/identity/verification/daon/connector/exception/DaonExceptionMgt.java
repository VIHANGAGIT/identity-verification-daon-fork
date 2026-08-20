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

package org.wso2.carbon.identity.verification.daon.connector.exception;

import org.apache.commons.lang.ArrayUtils;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;

/**
 * Builds exceptions and log lines from the {@link ErrorMessage} catalogue, bridging it to the flow-engine,
 * authentication-framework and internal exception families.
 */
public final class DaonExceptionMgt {

    private DaonExceptionMgt() {
    }

    private static String describe(ErrorMessage error, Object... data) {

        if (ArrayUtils.isNotEmpty(data)) {
            return String.format(error.getDescription(), data);
        }
        return error.getDescription();
    }

    /**
     * Renders an error as a log line, for sites that log and continue rather than throwing.
     *
     * @return e.g. {@code "DAON-65008 - Error resolving the referenced Daon IDP for resource id: abc"}.
     */
    public static String errorLog(ErrorMessage error, Object... data) {

        return error.getCode() + " - " + describe(error, data);
    }

    // Internal exceptions.

    public static DaonServerException handleServerException(ErrorMessage error, Object... data) {

        return new DaonServerException(error.getCode(), describe(error, data));
    }

    public static DaonServerException handleServerException(ErrorMessage error, Throwable cause,
                                                            Object... data) {

        return new DaonServerException(error.getCode(), describe(error, data), cause);
    }

    // Flow execution engine exceptions.

    /**
     * Builds a client exception carrying the i18n tokens the flow portal renders.
     */
    public static FlowEngineClientException handleFlowClientException(ErrorMessage error) {

        return new FlowEngineClientException(error.getCode(), userMessage(error), userDescription(error));
    }

    /**
     * The heading the flow portal should render for an error.
     */
    public static String userMessage(ErrorMessage error) {

        return error.getUserMessageToken() != null ? error.getUserMessageToken() : error.getMessage();
    }

    /**
     * The body the flow portal should render for an error.
     */
    public static String userDescription(ErrorMessage error) {

        return error.getUserDescriptionToken() != null
                ? error.getUserDescriptionToken() : error.getMessage();
    }

    public static FlowEngineServerException handleFlowServerException(ErrorMessage error, Object... data) {

        return new FlowEngineServerException(error.getCode(), error.getMessage(), describe(error, data));
    }

    /**
     * Preserves the original error code.
     */
    public static FlowEngineServerException toFlowServerException(DaonException e) {

        return new FlowEngineServerException(e.getErrorCode(), e.getMessage(), e.getMessage(), e);
    }

    public static AuthenticationFailedException handleAuthFailedException(ErrorMessage error) {

        return new AuthenticationFailedException(error.getCode(), error.getMessage());
    }

    public static AuthenticationFailedException handleAuthFailedException(ErrorMessage error,
                                                                          Throwable cause) {

        return new AuthenticationFailedException(error.getCode(), error.getMessage(), cause);
    }
}
