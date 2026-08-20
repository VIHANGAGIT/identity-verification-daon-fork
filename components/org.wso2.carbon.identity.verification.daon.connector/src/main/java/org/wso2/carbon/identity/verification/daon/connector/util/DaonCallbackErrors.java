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

package org.wso2.carbon.identity.verification.daon.connector.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;

/**
 * Maps the OAuth2 {@code error} Daon returns on the callback to a coded, user-facing error.
 */
public final class DaonCallbackErrors {

    private static final String ERROR_ACCESS_DENIED = "access_denied";
    private static final String ERROR_FAILED_TO_VERIFY_USER = "FailedToVerifyUser";

    /**
     * Daon reason token carried inside {@code error_description}.
     */
    private static final String REASON_CLAIMS_VERIFICATION_MISMATCH = "CLAIMS_VERIFICATION_MISMATCH";

    private DaonCallbackErrors() {
    }

    /**
     * Resolves the Daon error for an OAuth2 error callback.
     */
    public static ErrorMessage resolveError(String error, String errorDescription) {

        String normalizedError = StringUtils.trimToEmpty(error);
        String normalizedDescription = StringUtils.trimToEmpty(errorDescription);

        if (ERROR_ACCESS_DENIED.equalsIgnoreCase(normalizedError)) {
            return ErrorMessage.ERROR_VERIFICATION_CANCELLED;
        }
        if (normalizedDescription.contains(REASON_CLAIMS_VERIFICATION_MISMATCH)) {
            return ErrorMessage.ERROR_CLAIMS_VERIFICATION_MISMATCH;
        }
        if (ERROR_FAILED_TO_VERIFY_USER.equalsIgnoreCase(normalizedError)) {
            return ErrorMessage.ERROR_IDENTITY_VERIFICATION_FAILED;
        }
        return ErrorMessage.ERROR_VERIFICATION_NOT_COMPLETED;
    }
}
