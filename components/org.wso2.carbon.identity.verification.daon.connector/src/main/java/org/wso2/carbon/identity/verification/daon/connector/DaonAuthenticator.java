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
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonExceptionMgt;
import org.wso2.carbon.identity.verification.daon.connector.exception.DaonServerException;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonCallbackErrors;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonClaimsRequestBuilder;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonFederatedAssociationUtil;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonJwtUtil;
import org.wso2.carbon.identity.verification.daon.connector.util.DaonReferencedIdpUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ACR_VALUES_PARAM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_ENROL_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_IDP_ID;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.DAON_LOGIN_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.LOGIN_HINT;

/**
 * Daon TrustX federated authenticator (login step).
 */
public class DaonAuthenticator extends OpenIDConnectAuthenticator {

    private static final long serialVersionUID = 1L;
    private static final Log LOG = LogFactory.getLog(DaonAuthenticator.class);

    private static final String RETRY_PAGE_STATUS_KEY = "unable.to.proceed";

    private static final String AUTHORIZATION = "authorization";
    private static final String TOKEN = "token";
    private static final String OPERATION_LOGIN = "login";
    private static final String OPERATION_ENROLMENT = "enrolment";

    /*
     * Query-string syntax of the additionalQueryParameters.
     */
    private static final String QUERY_PARAM_SEPARATOR = "&";
    private static final String QUERY_PARAM_ASSIGNMENT = "=";

    @Override
    public String getName() {

        return DaonConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return DaonConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> props = prepareRequest(context);
        if (StringUtils.isBlank(props.get(OIDCAuthenticatorConstants.CLIENT_ID))
                || StringUtils.isBlank(props.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL))) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_OIDC_CONFIG_NOT_RESOLVED, AUTHORIZATION));
            failRequest(request, response, context, ErrorMessage.ERROR_OIDC_CONFIG_NOT_RESOLVED);
            return;
        }

        String daonSubject = resolveDaonSubject(context);
        Map<String, String> runtimeParams = getRuntimeParams(context);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Daon login step. Enrolled: " + (daonSubject != null)
                    + ", usable login_hint: " + StringUtils.isNotBlank(daonSubject)
                    + ", runtime parameters from the adaptive script: " + runtimeParams.keySet());
        }

        if (Boolean.parseBoolean(runtimeParams.get(DaonConstants.DAON_RUNTIME_PARAM_ENROL))) {
            if (daonSubject != null) {
                LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_ALREADY_ENROLLED,
                        resolveDaonIdpName(context)));
                failRequest(request, response, context, ErrorMessage.ERROR_ALREADY_ENROLLED);
                return;
            }
            initiateEnrolmentRequest(request, response, context, props);
            return;
        }
        if (StringUtils.isBlank(daonSubject)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_USER_NOT_ENROLLED, OPERATION_LOGIN));
            }
            failRequest(request, response, context, ErrorMessage.ERROR_USER_NOT_ENROLLED);
            return;
        }
        // Remember the identity this request is asking Daon to verify, so the callback can be bound to it.
        context.setProperty(DaonConstants.DAON_EXPECTED_SUBJECT, daonSubject);
        addDaonQueryParams(props, props.get(DAON_LOGIN_PD), daonSubject, null);
        super.initiateAuthenticationRequest(request, response, context);
    }

    private void initiateEnrolmentRequest(HttpServletRequest request, HttpServletResponse response,
                                          AuthenticationContext context, Map<String, String> props)
            throws AuthenticationFailedException {

        String enrolProcessDefinition = props.get(DAON_ENROL_PD);
        if (StringUtils.isBlank(enrolProcessDefinition)) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_ENROL_PD_NOT_CONFIGURED));
            failRequest(request, response, context, ErrorMessage.ERROR_ENROL_PD_NOT_CONFIGURED);
            return;
        }
        AuthenticatedUser authenticatedUser = context.getLastAuthenticatedUser();
        String qualifiedUsername = resolveQualifiedUsername(authenticatedUser);
        if (StringUtils.isBlank(qualifiedUsername)) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the authenticating user could not be resolved at the login step"));
            failRequest(request, response, context, ErrorMessage.ERROR_USER_NOT_ENROLLED);
            return;
        }

        Map<String, String> claimMappings = resolveClaimMappings(context);
        Map<String, String> valueRequests =
                resolveValueRequests(context, authenticatedUser, qualifiedUsername, claimMappings);
        if (!DaonClaimsRequestBuilder.hasDocumentVerifiableValue(valueRequests)) {
            // With no document-verifiable attribute we cannot bind an identity to this account.
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_NO_VERIFIABLE_CLAIM_VALUES, OPERATION_ENROLMENT));
            LOG.error("Daon enrolment could not be attempted: " + claimMappings.size() + " attribute "
                    + "mapping(s) resolved (Daon claims: " + claimMappings.values() + "), of which "
                    + valueRequests.size() + " had a value on the user's profile (Daon claims: "
                    + valueRequests.keySet() + "). At least one of "
                    + String.join(", ", DaonClaimsRequestBuilder.getDocumentVerifiableClaims())
                    + " must be mapped and populated.");
            failRequest(request, response, context, ErrorMessage.ERROR_NO_VERIFIABLE_CLAIM_VALUES);
            return;
        }
        String claimsRequest;
        try {
            claimsRequest = DaonClaimsRequestBuilder.buildClaimsParam(
                    new ArrayList<>(claimMappings.values()), valueRequests);
        } catch (DaonServerException e) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_BUILDING_CLAIMS_REQUEST), e);
            failRequest(request, response, context, ErrorMessage.ERROR_BUILDING_CLAIMS_REQUEST);
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Enrolling a user with no Daon enrolment at the login step, using the enrol process "
                    + "definition: " + enrolProcessDefinition);
        }
        context.setProperty(DaonConstants.DAON_ENROLLING_USER, qualifiedUsername);
        context.setProperty(DaonConstants.DAON_ENROLLING_USER_TENANT,
                resolveUserTenantDomain(authenticatedUser, context));
        addDaonQueryParams(props, enrolProcessDefinition, null, claimsRequest);
        super.initiateAuthenticationRequest(request, response, context);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        // Handle OAuth2 error on cancellations and failures, before the parent tries to read a code off the callback.
        String error = request.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR);
        if (StringUtils.isNotBlank(error)) {
            String errorDescription = request.getParameter(DaonConstants.OAUTH2_ERROR_DESCRIPTION);
            ErrorMessage callbackError = DaonCallbackErrors.resolveError(error, errorDescription);
            if (LOG.isDebugEnabled()) {
                LOG.debug(callbackError.getCode() + " - Daon returned an error on the login callback. error="
                        + error + ", error_description=" + errorDescription);
            }
            throw failCallback(context, callbackError);
        }

        Map<String, String> props = prepareRequest(context);
        if (StringUtils.isBlank(props.get(OIDCAuthenticatorConstants.CLIENT_ID))
                || StringUtils.isBlank(props.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL))) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_OIDC_CONFIG_NOT_RESOLVED, TOKEN));
            throw failCallback(context, ErrorMessage.ERROR_OIDC_CONFIG_NOT_RESOLVED);
        }
        super.processAuthenticationResponse(request, response, context);
        // The context outlives the request. Prevents a stale marker from skipping the identity binding check below.
        String enrollingUser = (String) context.getProperty(DaonConstants.DAON_ENROLLING_USER);
        String enrollingUserTenant = (String) context.getProperty(DaonConstants.DAON_ENROLLING_USER_TENANT);
        String expectedSubject = (String) context.getProperty(DaonConstants.DAON_EXPECTED_SUBJECT);
        context.removeProperty(DaonConstants.DAON_ENROLLING_USER);
        context.removeProperty(DaonConstants.DAON_ENROLLING_USER_TENANT);
        context.removeProperty(DaonConstants.DAON_EXPECTED_SUBJECT);

        if (StringUtils.isNotBlank(enrollingUser)) {
            persistEnrolment(context, enrollingUser, enrollingUserTenant);
            return;
        }
        assertVerifiedIdentityMatchesUser(context, expectedSubject);
    }

    private void persistEnrolment(AuthenticationContext context, String qualifiedUsername,
                                  String userTenantDomain)
            throws AuthenticationFailedException {

        String tenantDomain = StringUtils.isNotBlank(userTenantDomain)
                ? userTenantDomain : context.getTenantDomain();

        String daonSubject = getClaimValue(context.getSubject(), DaonConstants.JWT_PREFERRED_USERNAME_CLAIM);
        if (StringUtils.isBlank(daonSubject)) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_ENROLMENT_IDENTITY_NOT_RETURNED));
            throw failCallback(context, ErrorMessage.ERROR_ENROLMENT_IDENTITY_NOT_RETURNED);
        }
        String daonIdpName = resolveDaonIdpName(context);
        if (StringUtils.isBlank(daonIdpName)) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_PERSISTING_FED_ASSOCIATION,
                    "the Daon IDP name could not be resolved at the enrolment callback"));
            throw failCallback(context, ErrorMessage.ERROR_CREATING_FED_ASSOCIATION);
        }
        String existingUser = DaonFederatedAssociationUtil.getLocalUserForDaonSubject(
                tenantDomain, daonIdpName, daonSubject);
        if (StringUtils.isNotBlank(existingUser)) {
            LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_DAON_IDENTITY_ALREADY_ENROLLED,
                    daonIdpName));
            throw failCallback(context, ErrorMessage.ERROR_DAON_IDENTITY_ALREADY_ENROLLED);
        }
        User associationUser =
                DaonFederatedAssociationUtil.buildUser(qualifiedUsername, tenantDomain);
        if (!DaonFederatedAssociationUtil.createAssociation(associationUser, daonIdpName, daonSubject)) {
            throw failCallback(context, ErrorMessage.ERROR_CREATING_FED_ASSOCIATION);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Recorded the Daon enrolment performed at the login step, for IDP: " + daonIdpName);
        }
    }

    /*
     * Binds the identity Daon verified back to the user this login step is running for.
     */
    private void assertVerifiedIdentityMatchesUser(AuthenticationContext context, String expectedSubject)
            throws AuthenticationFailedException {

        String preferredUsername =
                getClaimValue(context.getSubject(), DaonConstants.JWT_PREFERRED_USERNAME_CLAIM);

        if (DaonJwtUtil.isExpectedSubject(expectedSubject, preferredUsername)) {
            return;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(ErrorMessage.ERROR_LOGIN_IDENTITY_MISMATCH.getCode()
                    + " - Daon verified an identity that does not match the authenticating user. Expected: "
                    + expectedSubject + ", returned preferred_username: " + preferredUsername);
        }
        LOG.error(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_LOGIN_IDENTITY_MISMATCH));
        throw failCallback(context, ErrorMessage.ERROR_LOGIN_IDENTITY_MISMATCH);
    }

    private String getClaimValue(AuthenticatedUser user, String claimName) {

        if (user == null || user.getUserAttributes() == null) {
            return null;
        }
        for (Map.Entry<ClaimMapping, String> entry : user.getUserAttributes().entrySet()) {
            ClaimMapping mapping = entry.getKey();
            if (mapping == null) {
                continue;
            }
            if (mapping.getLocalClaim() != null
                    && claimName.equals(mapping.getLocalClaim().getClaimUri())) {
                return entry.getValue();
            }
            if (mapping.getRemoteClaim() != null
                    && claimName.equals(mapping.getRemoteClaim().getClaimUri())) {
                return entry.getValue();
            }
        }
        return null;
    }

    @Override
    protected String getAuthenticateUser(AuthenticationContext context, Map<String, Object> oidcClaims,
                                         OAuthClientResponse oidcResponse) {

        Object preferredUsername = oidcClaims.get(DaonConstants.JWT_PREFERRED_USERNAME_CLAIM);
        if (preferredUsername != null && StringUtils.isNotBlank(preferredUsername.toString())) {
            return preferredUsername.toString();
        }
        return super.getAuthenticateUser(context, oidcClaims, oidcResponse);
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> properties = new ArrayList<>();

        properties.add(buildProperty(OIDCAuthenticatorConstants.CLIENT_ID, "Client ID", false,
                "Daon TrustX OIDC Client ID (self-contained Identity Verifier connection).", 0));
        properties.add(buildProperty(OIDCAuthenticatorConstants.CLIENT_SECRET, "Client Secret", true,
                "Daon TrustX OIDC Client Secret (self-contained Identity Verifier connection).", 1));
        properties.add(buildProperty(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL, "Authorization Endpoint URL",
                false, "Daon TrustX OIDC authorization endpoint URL "
                        + "(self-contained Identity Verifier connection).", 2));
        properties.add(buildProperty(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, "Token Endpoint URL",
                false, "Daon TrustX OIDC token endpoint URL "
                        + "(self-contained Identity Verifier connection).", 3));
        properties.add(buildProperty(IdentityApplicationConstants.Authenticator.OIDC.SCOPES, "Scopes", false,
                "OIDC scopes to request from Daon, e.g. openid profile document "
                        + "(self-contained Identity Verifier connection).", 4));
        properties.add(buildProperty(DAON_IDP_ID, "Daon Verifier ID", false,
                "Resource ID (UUID) of the Daon Identity Verifier connection whose OIDC client "
                        + "credentials and endpoints a login connection uses. Leave blank for a "
                        + "self-contained Identity Verifier connection.", 5));
        properties.add(buildProperty(DAON_ENROL_PD, "Enrol Process Definition", false,
                "Daon process definition for the enrolment flows (registration and invited-user), as "
                        + "<ProcessDefinitionName:Version>, sent as acr_values "
                        + "(self-contained Identity Verifier connection).", 6));
        properties.add(buildProperty(DAON_LOGIN_PD, "Login Process Definition", false,
                "Daon process definition for the login and password-recovery (re-verification) flows, as "
                        + "<ProcessDefinitionName:Version>, sent as acr_values (login connection).", 7));
        return properties;
    }

    private Property buildProperty(String name, String displayName, boolean confidential,
                                   String description, int displayOrder) {

        Property property = new Property();
        property.setName(name);
        property.setDisplayName(displayName);
        property.setRequired(false);
        property.setConfidential(confidential);
        property.setDescription(description);
        property.setDisplayOrder(displayOrder);
        return property;
    }

    private Map<String, String> prepareRequest(AuthenticationContext context) {

        Map<String, String> props = DaonReferencedIdpUtil.buildEffectiveProperties(
                context.getAuthenticatorProperties(), context.getTenantDomain());
        context.setAuthenticatorProperties(props);
        return props;
    }

    private void addDaonQueryParams(Map<String, String> props, String processDefinition, String loginHint,
                                    String claimsRequest) {

        List<String> queryParams = new ArrayList<>();
        String configuredQueryParams = props.get(FrameworkConstants.QUERY_PARAMS);
        if (StringUtils.isNotBlank(configuredQueryParams)) {
            queryParams.add(configuredQueryParams);
        }
        if (StringUtils.isNotBlank(processDefinition)) {
            queryParams.add(ACR_VALUES_PARAM + QUERY_PARAM_ASSIGNMENT + processDefinition);
        }
        if (StringUtils.isNotBlank(loginHint)) {
            queryParams.add(LOGIN_HINT + QUERY_PARAM_ASSIGNMENT + loginHint);
        }
        if (StringUtils.isNotBlank(claimsRequest)) {
            queryParams.add(DaonConstants.CLAIMS_PARAM + QUERY_PARAM_ASSIGNMENT + claimsRequest);
        }
        props.put(FrameworkConstants.QUERY_PARAMS, String.join(QUERY_PARAM_SEPARATOR, queryParams));
    }

    private Map<String, String> resolveClaimMappings(AuthenticationContext context) {

        Map<String, String> mappings = readClaimMappings(
                context.getExternalIdP() != null ? context.getExternalIdP().getClaimMappings() : null);
        if (!mappings.isEmpty()) {
            return mappings;
        }
        String idpResourceId = context.getAuthenticatorProperties().get(DAON_IDP_ID);
        if (StringUtils.isBlank(idpResourceId)) {
            return mappings;
        }
        mappings = DaonReferencedIdpUtil.resolveClaimMappings(idpResourceId, context.getTenantDomain());
        if (LOG.isDebugEnabled()) {
            LOG.debug("The login connection has no attribute mappings of its own; using the "
                    + mappings.size() + " mapping(s) of the referenced Daon Identity Verifier for the "
                    + "enrolment claim value-requests.");
        }
        return mappings;
    }

    private Map<String, String> readClaimMappings(ClaimMapping[] claimMappings) {

        Map<String, String> mappings = new HashMap<>();
        if (claimMappings == null) {
            return mappings;
        }
        for (ClaimMapping claimMapping : claimMappings) {
            if (claimMapping == null || claimMapping.getLocalClaim() == null
                    || claimMapping.getRemoteClaim() == null) {
                continue;
            }
            String localClaimUri = claimMapping.getLocalClaim().getClaimUri();
            String remoteClaimUri = claimMapping.getRemoteClaim().getClaimUri();
            if (StringUtils.isNotBlank(localClaimUri) && StringUtils.isNotBlank(remoteClaimUri)) {
                mappings.put(localClaimUri, remoteClaimUri);
            }
        }
        return mappings;
    }

    private Map<String, String> resolveValueRequests(AuthenticationContext context,
                                                     AuthenticatedUser authenticatedUser,
                                                     String qualifiedUsername,
                                                     Map<String, String> claimMappings) {

        if (claimMappings.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, String> localValues = new HashMap<>();
        List<String> unresolved = new ArrayList<>();
        for (String localClaimUri : claimMappings.keySet()) {
            String value = getClaimValue(authenticatedUser, localClaimUri);
            if (StringUtils.isNotBlank(value)) {
                localValues.put(localClaimUri, value);
            } else {
                unresolved.add(localClaimUri);
            }
        }
        if (!unresolved.isEmpty()) {
            localValues.putAll(readStoredClaims(resolveUserTenantDomain(authenticatedUser, context),
                    qualifiedUsername, unresolved));
        }

        Map<String, String> valuesByDaonClaimName = new HashMap<>();
        for (Map.Entry<String, String> mapping : claimMappings.entrySet()) {
            String value = localValues.get(mapping.getKey());
            if (StringUtils.isBlank(value)) {
                continue;
            }
            value = value.trim();
            if (value.contains(QUERY_PARAM_SEPARATOR) || value.contains(QUERY_PARAM_ASSIGNMENT)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Skipping the Daon claim value-request for '" + mapping.getValue()
                            + "': the value contains a character the authorization request's additional "
                            + "query parameters cannot carry.");
                }
                continue;
            }
            valuesByDaonClaimName.put(mapping.getValue(), value);
        }
        return valuesByDaonClaimName;
    }

    private Map<String, String> readStoredClaims(String tenantDomain, String qualifiedUsername,
                                                 List<String> claimUris) {

        Map<String, String> values = new HashMap<>();
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            UserStoreManager userStoreManager = DaonConnectorDataHolder.getRealmService()
                    .getTenantUserRealm(tenantId).getUserStoreManager();
            Map<String, String> storedClaims = userStoreManager.getUserClaimValues(qualifiedUsername,
                    claimUris.toArray(new String[0]), null);
            if (storedClaims != null) {
                for (Map.Entry<String, String> claim : storedClaims.entrySet()) {
                    if (StringUtils.isNotBlank(claim.getValue())) {
                        values.put(claim.getKey(), claim.getValue());
                    }
                }
            }
        } catch (UserStoreException e) {
            LOG.warn(DaonExceptionMgt.errorLog(ErrorMessage.ERROR_READING_USER_CLAIMS,
                    "the user being enrolled at the login step"), e);
        }
        return values;
    }

    private String resolveQualifiedUsername(AuthenticatedUser authenticatedUser) {

        if (authenticatedUser == null || StringUtils.isBlank(authenticatedUser.getUserName())) {
            return null;
        }
        String username = UserCoreUtil.removeDomainFromName(authenticatedUser.getUserName());
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        if (StringUtils.isNotBlank(userStoreDomain)) {
            username = userStoreDomain + UserCoreConstants.DOMAIN_SEPARATOR + username;
        }
        return username;
    }

    private String resolveDaonSubject(AuthenticationContext context) {

        AuthenticatedUser authenticatedUser = context.getLastAuthenticatedUser();
        if (authenticatedUser == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No last authenticated user in the context; cannot resolve the Daon subject.");
            }
            return null;
        }
        String daonIdpName = resolveDaonIdpName(context);
        if (StringUtils.isBlank(daonIdpName)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not resolve the Daon IDP name; cannot resolve the Daon subject.");
            }
            return null;
        }
        String username = resolveQualifiedUsername(authenticatedUser);
        if (StringUtils.isBlank(username)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("The last authenticated user carries no username; cannot resolve the Daon subject.");
            }
            return null;
        }
        User associationUser = DaonFederatedAssociationUtil.buildUser(username,
                resolveUserTenantDomain(authenticatedUser, context));
        return DaonFederatedAssociationUtil.getAssociatedDaonSubject(associationUser, daonIdpName);
    }

    private String resolveUserTenantDomain(AuthenticatedUser authenticatedUser,
                                           AuthenticationContext context) {

        if (authenticatedUser != null && StringUtils.isNotBlank(authenticatedUser.getTenantDomain())) {
            return authenticatedUser.getTenantDomain();
        }
        return context.getTenantDomain();
    }

    private String resolveDaonIdpName(AuthenticationContext context) {

        String idpResourceId = context.getAuthenticatorProperties().get(DAON_IDP_ID);
        if (StringUtils.isNotBlank(idpResourceId)) {
            String referencedIdpName =
                    DaonReferencedIdpUtil.resolveIdpName(idpResourceId, context.getTenantDomain());
            if (StringUtils.isBlank(referencedIdpName)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not resolve the referenced Daon IDP name for resource id: " + idpResourceId);
                }
            }
            return referencedIdpName;
        }
        if (context.getExternalIdP() == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No external IDP in the authentication context; cannot resolve the Daon IDP name.");
            }
            return null;
        }
        return context.getExternalIdP().getIdPName();
    }

    private void setErrorInformation(AuthenticationContext context, ErrorMessage error) {

        context.setProperty(FrameworkConstants.AUTH_ERROR_CODE, error.getCode());
        context.setProperty(FrameworkConstants.AUTH_ERROR_MSG, error.getMessage());
    }

    private boolean isAdaptiveScriptDriven(AuthenticationContext context) {

        return context.getSequenceConfig() != null
                && context.getSequenceConfig().getAuthenticationGraph() != null
                && context.getSequenceConfig().getAuthenticationGraph().isEnabled();
    }

    private void failRequest(HttpServletRequest request, HttpServletResponse response,
                             AuthenticationContext context, ErrorMessage error)
            throws AuthenticationFailedException {

        setErrorInformation(context, error);
        if (isAdaptiveScriptDriven(context)) {
            throw DaonExceptionMgt.handleAuthFailedException(error);
        }
        try {
            FrameworkUtils.sendToRetryPage(request, response, context, resolveRetryPageStatus(error),
                    DaonExceptionMgt.userDescription(error));
            context.setCurrentAuthenticator(getName());
        } catch (IOException e) {
            LOG.error(DaonExceptionMgt.errorLog(error), e);
            throw DaonExceptionMgt.handleAuthFailedException(error, e);
        }
    }

    private String resolveRetryPageStatus(ErrorMessage error) {

        return error.getUserMessageToken() != null ? error.getUserMessageToken() : RETRY_PAGE_STATUS_KEY;
    }

    private AuthenticationFailedException failCallback(AuthenticationContext context, ErrorMessage error) {

        setErrorInformation(context, error);
        return DaonExceptionMgt.handleAuthFailedException(error);
    }
}
