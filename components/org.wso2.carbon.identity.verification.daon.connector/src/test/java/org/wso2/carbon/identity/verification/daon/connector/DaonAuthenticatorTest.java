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

import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.json.JSONObject;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.model.AssociatedIdentityProvider;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.model.FederatedAssociation;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonErrorConstants.ErrorMessage;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ConnectionProperties.ENROL_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ConnectionProperties.IDP_ID;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ConnectionProperties.LOGIN_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ContextProperties.ENROLLING_USER;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ContextProperties.ENROLLING_USER_TENANT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ContextProperties.EXPECTED_SUBJECT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.IdTokenClaims.PREFERRED_USERNAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.LocalClaims.FIRST_NAME_CLAIM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.LocalClaims.LAST_NAME_CLAIM;

/**
 * Tests the login-step authenticator: the request it composes for a login or an enrolment, and how it binds
 * what Daon verified back to the account the step is running for.
 */
public class DaonAuthenticatorTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String USER_TENANT_DOMAIN = "org1.com";
    private static final String IDP_NAME = "Daon Identity Verifier";
    private static final String ENROL_PROCESS_DEFINITION = "EnrolProcess:1.0";
    private static final String LOGIN_PROCESS_DEFINITION = "LoginProcess:2.0";
    private static final String DAON_SUBJECT = "daon-user-9001";
    private static final String QUALIFIED_USERNAME = "PRIMARY/alex";
    private static final String EMAIL_CLAIM_URI = "http://wso2.org/claims/emailaddress";
    private static final String DOB_CLAIM_URI = "http://wso2.org/claims/dob";

    private TestDaonAuthenticator authenticator;
    private FederatedAssociationManager associationManager;
    private MockedStatic<FrameworkUtils> frameworkUtils;
    private MockedStatic<LoggerUtils> loggerUtils;
    private HttpServletRequest request;
    private HttpServletResponse response;

    /**
     * Holds the OIDC parent's off-box work at its own extension points — the login-page build and the token
     * exchange — leaving only this connector's behaviour under test.
     */
    private static class TestDaonAuthenticator extends DaonAuthenticator {

        private static final long serialVersionUID = 1L;

        private final Map<String, String> runtimeParams = new HashMap<>();
        private AuthenticatedUser subjectFromDaon;
        private boolean oidcRequestInitiated;
        private boolean oidcResponseProcessed;

        @Override
        public Map<String, String> getRuntimeParams(AuthenticationContext context) {

            return runtimeParams;
        }

        @Override
        protected String prepareLoginPage(HttpServletRequest request, AuthenticationContext context) {

            // The parent redirects to whatever this returns; the request under test is the properties it
            // was built from, which the connector has already put on the context by this point.
            oidcRequestInitiated = true;
            return "https://daon.example/authorize?stub";
        }

        @Override
        protected void processAuthResponse(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context) {

            oidcResponseProcessed = true;
            // Stands in for the parent populating the context subject from the validated ID token.
            context.setSubject(subjectFromDaon);
        }
    }

    @BeforeMethod
    public void setUp() {

        authenticator = new TestDaonAuthenticator();
        associationManager = mock(FederatedAssociationManager.class);
        DaonConnectorDataHolder.setFederatedAssociationManager(associationManager);
        frameworkUtils = mockStatic(FrameworkUtils.class);
        loggerUtils = mockStatic(LoggerUtils.class);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
    }

    @AfterMethod
    public void tearDown() {

        frameworkUtils.close();
        loggerUtils.close();
        DaonConnectorDataHolder.setFederatedAssociationManager(null);
    }

    // ---------- connection metadata ----------

    @Test
    public void testTheConnectorIsIdentifiedByItsOwnNames() {

        assertEquals(authenticator.getName(), DaonConstants.AUTHENTICATOR_NAME);
        assertEquals(authenticator.getFriendlyName(), DaonConstants.AUTHENTICATOR_FRIENDLY_NAME);
        assertEquals(authenticator.getComponentId(),
                DaonConstants.LogConstants.OUTBOUND_AUTH_DAON_SERVICE);
    }

    @Test
    public void testTheConfigurationPropertiesAreOfferedInDisplayOrder() {

        List<Property> properties = authenticator.getConfigurationProperties();

        String[] expected = {OIDCAuthenticatorConstants.CLIENT_ID, OIDCAuthenticatorConstants.CLIENT_SECRET,
                OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL, OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL,
                IdentityApplicationConstants.Authenticator.OIDC.SCOPES, IDP_ID, ENROL_PD, LOGIN_PD};
        assertEquals(properties.size(), expected.length);
        for (int i = 0; i < expected.length; i++) {
            assertEquals(properties.get(i).getName(), expected[i]);
            assertEquals(properties.get(i).getDisplayOrder(), i);
        }
    }

    /*
     * The secret is the only property whose value must never be rendered back to an administrator.
     */
    @Test
    public void testOnlyTheClientSecretIsConfidential() {

        for (Property property : authenticator.getConfigurationProperties()) {
            assertEquals(property.isConfidential(),
                    OIDCAuthenticatorConstants.CLIENT_SECRET.equals(property.getName()),
                    "Unexpected confidentiality on: " + property.getName());
        }
    }

    @Test
    public void testTheDaonIdentityIsPreferredAsTheAuthenticatedUser() {

        Map<String, Object> oidcClaims = new HashMap<>();
        oidcClaims.put(DaonConstants.IdTokenClaims.SUBJECT, "opaque-oidc-sub");
        oidcClaims.put(PREFERRED_USERNAME, DAON_SUBJECT);

        assertEquals(authenticator.getAuthenticateUser(loginContext(), oidcClaims, null), DAON_SUBJECT);
    }

    /*
     * A Daon enrolment is keyed on preferred_username alone, so naming the user by 'sub' instead would let
     * the step appear to verify while binding nothing. The OIDC parent's fallback must not be reached.
     */
    @Test
    public void testABlankDaonIdentityIsNotSubstitutedWithTheOidcSubject() {

        AuthenticationContext context = loginContext();

        assertNull(authenticator.getAuthenticateUser(context, idTokenClaims(
                DaonConstants.IdTokenClaims.SUBJECT, "opaque-oidc-sub", PREFERRED_USERNAME, "   "), null));
    }

    @Test
    public void testAMissingDaonIdentityIsNotSubstitutedWithTheOidcSubject() {

        AuthenticationContext context = loginContext();

        assertNull(authenticator.getAuthenticateUser(
                context, idTokenClaims(DaonConstants.IdTokenClaims.SUBJECT, "opaque-oidc-sub"), null));
    }

    @Test
    public void testNoClaimsAtAllNamesNoUser() {

        AuthenticationContext context = loginContext();

        assertNull(authenticator.getAuthenticateUser(context, idTokenClaims(), null));
        assertNull(authenticator.getAuthenticateUser(context, null, null));
    }

    // ---------- composing the request ----------

    @Test
    public void testLoginFailsWhenTheAuthorizationEndpointIsNotResolved() throws Exception {

        AuthenticationContext context = loginContext();
        context.getAuthenticatorProperties().remove(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);

        authenticator.initiateAuthenticationRequest(request, response, context);

        assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE), "DAON-65001");
        assertFalse(authenticator.oidcRequestInitiated, "Daon must not be called without an endpoint.");
        // 65001 is a configuration fault with nothing user-actionable, so it renders the generic status.
        frameworkUtils.verify(() -> FrameworkUtils.sendToRetryPage(request, response, context,
                "unable.to.proceed", ErrorMessage.ERROR_OIDC_CONFIG_NOT_RESOLVED.getMessage()));
    }

    @Test
    public void testLoginFailsWhenTheClientIdIsNotResolved() throws Exception {

        AuthenticationContext context = loginContext();
        context.getAuthenticatorProperties().remove(OIDCAuthenticatorConstants.CLIENT_ID);

        authenticator.initiateAuthenticationRequest(request, response, context);

        assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE), "DAON-65001");
        assertFalse(authenticator.oidcRequestInitiated);
    }

    /*
     * A login step re-verifies an identity the account is already bound to. With no enrolment there is
     * nothing to re-verify, and letting the step run would enrol whoever happens to present a document.
     */
    @Test
    public void testLoginRefusesAnAccountWithNoEnrolment() throws Exception {

        AuthenticationContext context = loginContext();
        givenNoEnrolment();

        authenticator.initiateAuthenticationRequest(request, response, context);

        assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE), "DAON-60001");
        assertFalse(authenticator.oidcRequestInitiated);
    }

    /*
     * An association can exist while carrying no Daon subject. There is then no identity to name on the
     * request, so the step must refuse rather than send a login_hint-less re-verification.
     */
    @Test
    public void testLoginRefusesAnEnrolmentRecordCarryingNoDaonSubject() throws Exception {

        AuthenticationContext context = loginContext();
        givenEnrolment(null);

        authenticator.initiateAuthenticationRequest(request, response, context);

        assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE), "DAON-60001");
        assertFalse(authenticator.oidcRequestInitiated);
    }

    @Test
    public void testLoginPinsTheRequestToTheEnrolledSubject() throws Exception {

        AuthenticationContext context = loginContext();
        givenEnrolment(DAON_SUBJECT);

        authenticator.initiateAuthenticationRequest(request, response, context);

        assertTrue(authenticator.oidcRequestInitiated);
        assertTrue(queryParams(context).contains("acr_values=" + LOGIN_PROCESS_DEFINITION));
        assertTrue(queryParams(context).contains("login_hint=" + DAON_SUBJECT));
        assertFalse(queryParams(context).contains("claims="),
                "A login re-verifies a known identity; it does not collect a profile.");
        assertEquals(context.getProperty(EXPECTED_SUBJECT), DAON_SUBJECT,
                "The callback has to know which identity this request asked Daon to verify.");
    }

    /*
     * The connection's own additional query parameters are configuration an administrator set; the Daon
     * parameters are appended to them rather than replacing them.
     */
    @Test
    public void testTheConnectionsOwnQueryParametersSurvive() throws Exception {

        AuthenticationContext context = loginContext();
        context.getAuthenticatorProperties().put(FrameworkConstants.QUERY_PARAMS, "ui_locales=fr");
        givenEnrolment(DAON_SUBJECT);

        authenticator.initiateAuthenticationRequest(request, response, context);

        assertEquals(queryParams(context),
                "ui_locales=fr&acr_values=" + LOGIN_PROCESS_DEFINITION + "&login_hint=" + DAON_SUBJECT);
    }

    /*
     * An enrolment is driven by an adaptive script, which needs the failure as an exception it can branch
     * on; a retry-page redirect would abandon the script mid-sequence.
     */
    @Test
    public void testEnrolmentRefusesAnAccountThatIsAlreadyEnrolled() {

        AuthenticationContext context = loginContext();
        authenticator.runtimeParams.put(DaonConstants.RuntimeParams.ENROL, "true");
        givenEnrolment(DAON_SUBJECT);

        assertRequestFailure(context, "DAON-60009");
        frameworkUtils.verify(() -> FrameworkUtils.sendToRetryPage(any(), any(), any(), anyString(),
                anyString()), never());
    }

    /*
     * An association with no subject still means the account holds an enrolment, so a second identity must
     * not be bound to it.
     */
    @Test
    public void testEnrolmentRefusesAnAccountHoldingASubjectlessEnrolment() {

        AuthenticationContext context = loginContext();
        authenticator.runtimeParams.put(DaonConstants.RuntimeParams.ENROL, "true");
        givenEnrolment(null);

        assertRequestFailure(context, "DAON-60009");
    }

    @Test
    public void testEnrolmentFailsWithoutAnEnrolProcessDefinition() {

        AuthenticationContext context = loginContext();
        context.getAuthenticatorProperties().remove(ENROL_PD);
        authenticator.runtimeParams.put(DaonConstants.RuntimeParams.ENROL, "true");
        givenNoEnrolment();

        assertRequestFailure(context, "DAON-65024");
    }

    /*
     * Enrolling binds a verified identity to this account. Without an attribute Daon can check against the
     * document, the binding would rest on nothing the document actually proves.
     */
    @Test
    public void testEnrolmentIsRefusedWithNoDocumentVerifiableAttribute() {

        AuthenticationContext context = loginContext();
        context.setExternalIdP(externalIdp(ClaimMapping.build(EMAIL_CLAIM_URI, "email", null, true)));
        context.setSubject(userWithClaims(EMAIL_CLAIM_URI, "alex@example.com"));
        authenticator.runtimeParams.put(DaonConstants.RuntimeParams.ENROL, "true");
        givenNoEnrolment();

        assertRequestFailure(context, "DAON-65023");
    }

    @Test
    public void testEnrolmentIsRefusedWhenTheConnectionMapsNoAttributes() {

        AuthenticationContext context = loginContext();
        context.setExternalIdP(externalIdp());
        authenticator.runtimeParams.put(DaonConstants.RuntimeParams.ENROL, "true");
        givenNoEnrolment();

        assertRequestFailure(context, "DAON-65023");
    }

    @Test
    public void testEnrolmentFailsWhenTheAuthenticatingUserCannotBeResolved() {

        // Built without a subject: setSubject(null) would leave the last authenticated user in place.
        AuthenticationContext context = loginContext();
        AuthenticationContext anonymous = new AuthenticationContext();
        anonymous.setTenantDomain(TENANT_DOMAIN);
        anonymous.setAuthenticatorProperties(context.getAuthenticatorProperties());
        anonymous.setExternalIdP(context.getExternalIdP());
        authenticator.runtimeParams.put(DaonConstants.RuntimeParams.ENROL, "true");

        assertRequestFailure(anonymous, "DAON-60001");
    }

    @Test
    public void testEnrolmentSendsTheClaimsRequestAndRemembersWhoIsEnrolling() throws Exception {

        AuthenticationContext context = loginContext();
        authenticator.runtimeParams.put(DaonConstants.RuntimeParams.ENROL, "true");
        givenNoEnrolment();

        authenticator.initiateAuthenticationRequest(request, response, context);

        assertTrue(authenticator.oidcRequestInitiated);
        assertTrue(queryParams(context).contains("acr_values=" + ENROL_PROCESS_DEFINITION));
        assertFalse(queryParams(context).contains("login_hint="),
                "There is no Daon identity to hint at until the enrolment completes.");
        assertEquals(requestedClaimValue(queryParams(context), "given_name"), "Alex");
        assertEquals(context.getProperty(ENROLLING_USER), QUALIFIED_USERNAME,
                "The callback has to know which account the new enrolment belongs to.");
        assertEquals(context.getProperty(ENROLLING_USER_TENANT), TENANT_DOMAIN);
    }

    /*
     * A B2B login runs in the organisation's context while the account lives in its own tenant. The
     * association is keyed on the user's tenant, so that is the one the callback has to write under.
     */
    @Test
    public void testEnrolmentRemembersTheUsersOwnTenant() throws Exception {

        AuthenticationContext context = loginContext();
        AuthenticatedUser user = userWithClaims(FIRST_NAME_CLAIM, "Alex");
        user.setTenantDomain(USER_TENANT_DOMAIN);
        context.setSubject(user);
        authenticator.runtimeParams.put(DaonConstants.RuntimeParams.ENROL, "true");
        givenNoEnrolment();

        authenticator.initiateAuthenticationRequest(request, response, context);

        assertEquals(context.getProperty(ENROLLING_USER_TENANT), USER_TENANT_DOMAIN);
    }

    /*
     * The value-requests ride on the raw additional query parameters, so a value carrying a separator would
     * corrupt the authorization request rather than reach Daon.
     */
    @Test
    public void testEnrolmentDropsClaimValuesTheQueryStringCannotCarry() throws Exception {

        AuthenticationContext context = loginContext();
        context.setExternalIdP(externalIdp(
                ClaimMapping.build(FIRST_NAME_CLAIM, "given_name", null, true),
                ClaimMapping.build(DOB_CLAIM_URI, "birthdate", null, true)));
        context.setSubject(userWithClaims(FIRST_NAME_CLAIM, "Alex&Sam", DOB_CLAIM_URI, "1990-01-01"));
        authenticator.runtimeParams.put(DaonConstants.RuntimeParams.ENROL, "true");
        givenNoEnrolment();

        authenticator.initiateAuthenticationRequest(request, response, context);

        assertTrue(authenticator.oidcRequestInitiated);
        assertEquals(requestedClaimValue(queryParams(context), "birthdate"), "1990-01-01");
        assertNull(requestedClaimValue(queryParams(context), "given_name"),
                "A value holding a query separator must not be sent as a value-request.");
    }

    @Test
    public void testALoginFailureSendsTheUserToTheRetryPage() throws Exception {

        AuthenticationContext context = loginContext();
        givenNoEnrolment();

        authenticator.initiateAuthenticationRequest(request, response, context);

        frameworkUtils.verify(() -> FrameworkUtils.sendToRetryPage(request, response, context,
                ErrorMessage.ERROR_USER_NOT_ENROLLED.getUserMessageToken(),
                ErrorMessage.ERROR_USER_NOT_ENROLLED.getUserDescriptionToken()));
        assertEquals(context.getCurrentAuthenticator(), DaonConstants.AUTHENTICATOR_NAME,
                "The retry page has to attribute the failure to this step.");
    }

    @Test
    public void testAFailedRetryRedirectIsReportedAsAnAuthenticationFailure() {

        AuthenticationContext context = loginContext();
        givenNoEnrolment();
        frameworkUtils.when(() -> FrameworkUtils.sendToRetryPage(any(), any(), any(), anyString(),
                anyString())).thenThrow(new IOException("the response is already committed"));

        assertRequestFailure(context, "DAON-60001");
    }

    // ---------- handling the callback ----------

    @Test
    public void testACancelledVerificationIsMappedToACodedFailure() {

        AuthenticationContext context = loginContext();
        when(request.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn("access_denied");

        assertCallbackFailure(context, "DAON-60002");
        assertFalse(authenticator.oidcResponseProcessed,
                "An error callback carries no code; the parent must not try to exchange one.");
    }

    @Test
    public void testAClaimsMismatchIsReportedDistinctlyFromAGenericFailure() {

        AuthenticationContext context = loginContext();
        when(request.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR))
                .thenReturn("FailedToVerifyUser");
        when(request.getParameter(DaonConstants.OIDCParams.ERROR_DESCRIPTION))
                .thenReturn("reason=CLAIMS_VERIFICATION_MISMATCH detail=dob");

        assertCallbackFailure(context, "DAON-60003");
    }

    @Test
    public void testAnUnrecognisedCallbackErrorIsStillReported() {

        AuthenticationContext context = loginContext();
        when(request.getParameter(OIDCAuthenticatorConstants.OAUTH2_ERROR)).thenReturn("server_error");

        assertCallbackFailure(context, "DAON-60005");
    }

    @Test
    public void testTheCallbackFailsWhenTheTokenEndpointIsNotResolved() {

        AuthenticationContext context = loginContext();
        context.getAuthenticatorProperties().remove(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);

        assertCallbackFailure(context, "DAON-65001");
        assertFalse(authenticator.oidcResponseProcessed);
    }

    /*
     * login_hint is only a hint per OIDC. Daon may return a different identity than the one asked for, and
     * without this check any enrolled user could satisfy the login step for any other account.
     */
    @Test
    public void testALoginVerifiedByADifferentIdentityIsRejected() {

        AuthenticationContext context = loginContext();
        context.setProperty(EXPECTED_SUBJECT, DAON_SUBJECT);
        authenticator.subjectFromDaon = userWithClaims(PREFERRED_USERNAME, "someone-elses-daon-id");

        assertCallbackFailure(context, "DAON-60008");
    }

    /*
     * The marker is the only record of which identity was asked for. Without it the callback cannot be
     * bound to anything, so it must fail rather than accept whatever came back.
     */
    @Test
    public void testACallbackThatAskedForNoIdentityIsRejected() {

        AuthenticationContext context = loginContext();
        authenticator.subjectFromDaon = userWithClaims(PREFERRED_USERNAME, DAON_SUBJECT);

        assertCallbackFailure(context, "DAON-60008");
    }

    /*
     * The misconfiguration has to stop the step with a Daon code, before the parent resolves a subject from
     * the token at all.
     */
    @Test
    public void testAnIdTokenNamingNoDaonIdentityFailsTheStep() {

        assertIdTokenRejected(idToken("{\"sub\":\"opaque-oidc-sub\"}"), "DAON-65006");
    }

    @Test
    public void testAnIdTokenWhoseDaonIdentityIsBlankFailsTheStep() {

        assertIdTokenRejected(idToken("{\"sub\":\"abc\",\"preferred_username\":\"   \"}"),
                "DAON-65006");
    }

    @Test
    public void testATokenResponseWithNoIdTokenFailsTheStep() {

        assertIdTokenRejected(null, "DAON-65002");
    }

    @Test
    public void testAnIdTokenOfOneSegmentFailsTheStep() {

        assertIdTokenRejected("not-a-jwt", "DAON-65003");
    }

    @Test
    public void testAnUndecodableIdTokenPayloadFailsTheStep() {

        assertIdTokenRejected("header.!!not-base64!!.sig", "DAON-65004");
    }

    @Test
    public void testAnIdTokenNamingTheDaonIdentityIsPassedThrough() throws Exception {

        String idToken = idToken("{\"sub\":\"abc\",\"preferred_username\":\"" + DAON_SUBJECT + "\"}");

        assertEquals(authenticator.mapIdToken(loginContext(), request, tokenResponse(idToken)), idToken);
    }

    @Test
    public void testACallbackCarryingNoIdentityAtAllIsRejected() {

        AuthenticationContext context = loginContext();
        context.setProperty(EXPECTED_SUBJECT, DAON_SUBJECT);
        authenticator.subjectFromDaon = userWithClaims(FIRST_NAME_CLAIM, "Alex");

        assertCallbackFailure(context, "DAON-60008");
    }

    @Test
    public void testALoginVerifiedByTheExpectedIdentityIsAccepted() throws Exception {

        AuthenticationContext context = loginContext();
        context.setProperty(EXPECTED_SUBJECT, DAON_SUBJECT);
        // Daon echoes the identity back in its own casing and padding.
        authenticator.subjectFromDaon = userWithClaims(PREFERRED_USERNAME, "  DAON-USER-9001 ");

        authenticator.processAuthenticationResponse(request, response, context);

        assertTrue(authenticator.oidcResponseProcessed);
        assertNull(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE));
    }

    /*
     * The context outlives a single request. A marker left behind would make the next callback skip the
     * identity-binding check, or persist an enrolment for a request that never asked for one.
     */
    @Test
    public void testTheCallbackMarkersAreClearedOnceTheCallbackIsHandled() throws Exception {

        AuthenticationContext context = loginContext();
        context.setProperty(EXPECTED_SUBJECT, DAON_SUBJECT);
        authenticator.subjectFromDaon = userWithClaims(PREFERRED_USERNAME, DAON_SUBJECT);

        authenticator.processAuthenticationResponse(request, response, context);

        assertNull(context.getProperty(EXPECTED_SUBJECT));
        assertNull(context.getProperty(ENROLLING_USER));
        assertNull(context.getProperty(ENROLLING_USER_TENANT));
    }

    @Test
    public void testAnEnrolmentPerformedAtTheLoginStepIsRecorded() throws Exception {

        AuthenticationContext context = loginContext();
        context.setProperty(ENROLLING_USER, QUALIFIED_USERNAME);
        authenticator.subjectFromDaon = userWithClaims(PREFERRED_USERNAME, DAON_SUBJECT);

        authenticator.processAuthenticationResponse(request, response, context);

        ArgumentCaptor<User> user = ArgumentCaptor.forClass(User.class);
        verify(associationManager).createFederatedAssociation(user.capture(), eq(IDP_NAME), eq(DAON_SUBJECT));
        assertEquals(user.getValue().getUserName(), "alex");
        assertEquals(user.getValue().getUserStoreDomain(), "PRIMARY");
        assertEquals(user.getValue().getTenantDomain(), TENANT_DOMAIN);
    }

    /*
     * Writing the association under the context tenant while the login step reads it back under the user's
     * own would leave a B2B account permanently not-enrolled.
     */
    @Test
    public void testTheEnrolmentIsRecordedUnderTheUsersOwnTenant() throws Exception {

        AuthenticationContext context = loginContext();
        context.setProperty(ENROLLING_USER, QUALIFIED_USERNAME);
        context.setProperty(ENROLLING_USER_TENANT, USER_TENANT_DOMAIN);
        authenticator.subjectFromDaon = userWithClaims(PREFERRED_USERNAME, DAON_SUBJECT);

        authenticator.processAuthenticationResponse(request, response, context);

        verify(associationManager)
                .getUserForFederatedAssociation(USER_TENANT_DOMAIN, IDP_NAME, DAON_SUBJECT);
        ArgumentCaptor<User> user = ArgumentCaptor.forClass(User.class);
        verify(associationManager).createFederatedAssociation(user.capture(), eq(IDP_NAME), eq(DAON_SUBJECT));
        assertEquals(user.getValue().getTenantDomain(), USER_TENANT_DOMAIN);
    }

    /*
     * An enrolment callback binds a brand new identity, so there is nothing yet to compare a login_hint
     * against; the enrolment must take the callback rather than the identity check.
     */
    @Test
    public void testAnEnrolmentIsRecordedInPreferenceToTheIdentityCheck() throws Exception {

        AuthenticationContext context = loginContext();
        context.setProperty(ENROLLING_USER, QUALIFIED_USERNAME);
        context.setProperty(EXPECTED_SUBJECT, "a-stale-expected-subject");
        authenticator.subjectFromDaon = userWithClaims(PREFERRED_USERNAME, DAON_SUBJECT);

        authenticator.processAuthenticationResponse(request, response, context);

        verify(associationManager).createFederatedAssociation(any(), eq(IDP_NAME), eq(DAON_SUBJECT));
    }

    @Test
    public void testAnIdentityAnotherAccountAlreadyHoldsIsNotEnrolledAgain() throws Exception {

        AuthenticationContext context = loginContext();
        context.setProperty(ENROLLING_USER, QUALIFIED_USERNAME);
        authenticator.subjectFromDaon = userWithClaims(PREFERRED_USERNAME, DAON_SUBJECT);
        when(associationManager.getUserForFederatedAssociation(TENANT_DOMAIN, IDP_NAME, DAON_SUBJECT))
                .thenReturn("PRIMARY/sam");

        assertCallbackFailure(context, "DAON-60010");
        verify(associationManager, never()).createFederatedAssociation(any(), anyString(), anyString());
    }

    /*
     * A defence-in-depth guard: mapIdToken() already rejects a token naming no identity, so this is only
     * reachable if the token's claims and the subject's attributes disagree.
     */
    @Test
    public void testAnEnrolmentFailsWhenTheSubjectCarriesNoIdentity() {

        AuthenticationContext context = loginContext();
        context.setProperty(ENROLLING_USER, QUALIFIED_USERNAME);
        authenticator.subjectFromDaon = userWithClaims(FIRST_NAME_CLAIM, "Alex");

        assertCallbackFailure(context, "DAON-65025");
    }

    /*
     * The association is keyed on the connection name, so without one there is nothing to record the
     * enrolment against.
     */
    @Test
    public void testAnEnrolmentFailsWhenTheDaonConnectionNameCannotBeResolved() {

        AuthenticationContext context = loginContext();
        context.setExternalIdP(null);
        context.setProperty(ENROLLING_USER, QUALIFIED_USERNAME);
        authenticator.subjectFromDaon = userWithClaims(PREFERRED_USERNAME, DAON_SUBJECT);

        assertCallbackFailure(context, "DAON-65013");
    }

    /*
     * Completing the step with the association unwritten would report a successful enrolment the next login
     * cannot find.
     */
    @Test
    public void testAnEnrolmentFailsWhenTheAssociationCannotBeWritten() {

        AuthenticationContext context = loginContext();
        context.setProperty(ENROLLING_USER, QUALIFIED_USERNAME);
        authenticator.subjectFromDaon = userWithClaims(PREFERRED_USERNAME, DAON_SUBJECT);
        DaonConnectorDataHolder.setFederatedAssociationManager(null);

        assertCallbackFailure(context, "DAON-65013");
    }

    // ---------- helpers ----------

    /**
     * The additional query parameters the connector composed onto the request it handed the OIDC parent.
     */
    private String queryParams(AuthenticationContext context) {

        return context.getAuthenticatorProperties().get(FrameworkConstants.QUERY_PARAMS);
    }

    private void assertRequestFailure(AuthenticationContext context, String expectedCode) {

        try {
            authenticator.initiateAuthenticationRequest(request, response, context);
            fail("Expected the request to fail with " + expectedCode);
        } catch (AuthenticationFailedException e) {
            assertEquals(e.getErrorCode(), expectedCode);
        }
        assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE), expectedCode);
        assertFalse(authenticator.oidcRequestInitiated);
    }

    private void assertCallbackFailure(AuthenticationContext context, String expectedCode) {

        try {
            authenticator.processAuthenticationResponse(request, response, context);
            fail("Expected the callback to fail with " + expectedCode);
        } catch (AuthenticationFailedException e) {
            assertEquals(e.getErrorCode(), expectedCode);
        }
        assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE), expectedCode);
    }

    /**
     * The value Daon is asked to check the named claim against, or {@code null} when it was only requested.
     */
    private String requestedClaimValue(String queryParams, String daonClaimName) {

        int start = queryParams.indexOf("claims=");
        assertTrue(start >= 0, "No claims request was sent.");
        JSONObject claims = new JSONObject(queryParams.substring(start + "claims=".length()))
                .getJSONObject("id_token")
                .getJSONObject("verified_claims")
                .getJSONObject("claims");
        assertTrue(claims.has(daonClaimName), "The claim was not requested at all: " + daonClaimName);
        JSONObject request = claims.optJSONObject(daonClaimName);
        return request != null ? request.optString("value", null) : null;
    }

    private void givenEnrolment(String daonSubject) {

        AssociatedIdentityProvider idp = new AssociatedIdentityProvider();
        idp.setName(IDP_NAME);
        givenAssociations(new FederatedAssociation[]{new FederatedAssociation("a1", idp, daonSubject)});
    }

    private void givenNoEnrolment() {

        givenAssociations(new FederatedAssociation[0]);
    }

    private void givenAssociations(FederatedAssociation[] associations) {

        try {
            when(associationManager.getFederatedAssociationsOfUser(any())).thenReturn(associations);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private AuthenticationContext loginContext() {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(TENANT_DOMAIN);

        Map<String, String> props = new HashMap<>();
        props.put(OIDCAuthenticatorConstants.CLIENT_ID, "daon-client");
        props.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "daon-secret");
        props.put(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL, "https://daon.example/authorize");
        props.put(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, "https://daon.example/token");
        props.put(ENROL_PD, ENROL_PROCESS_DEFINITION);
        props.put(LOGIN_PD, LOGIN_PROCESS_DEFINITION);
        context.setAuthenticatorProperties(props);

        context.setExternalIdP(externalIdp(
                ClaimMapping.build(FIRST_NAME_CLAIM, "given_name", null, true),
                ClaimMapping.build(LAST_NAME_CLAIM, "family_name", null, true)));
        context.setSubject(userWithClaims(FIRST_NAME_CLAIM, "Alex"));
        return context;
    }

    private ExternalIdPConfig externalIdp(ClaimMapping... claimMappings) {

        IdentityProvider idp = new IdentityProvider();
        idp.setIdentityProviderName(IDP_NAME);
        ClaimConfig claimConfig = new ClaimConfig();
        claimConfig.setClaimMappings(claimMappings);
        idp.setClaimConfig(claimConfig);
        return new ExternalIdPConfig(idp);
    }

    private void assertIdTokenRejected(String idToken, String expectedCode) {

        AuthenticationContext context = loginContext();
        try {
            authenticator.mapIdToken(context, request, tokenResponse(idToken));
            fail("Expected the ID token to be rejected with " + expectedCode);
        } catch (AuthenticationFailedException e) {
            assertEquals(e.getErrorCode(), expectedCode);
        }
        assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE), expectedCode);
    }

    private OAuthClientResponse tokenResponse(String idToken) {

        OAuthClientResponse response = mock(OAuthClientResponse.class);
        when(response.getParam(OIDCAuthenticatorConstants.ID_TOKEN)).thenReturn(idToken);
        return response;
    }

    /**
     * A JWT carrying the given payload. The connector only reads the payload; the parent validates the token.
     */
    private String idToken(String payload) {

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + ".c2lnbmF0dXJl";
    }

    /**
     * The claims the OIDC parent would hand to {@code getAuthenticateUser}, as name and value pairs.
     */
    private Map<String, Object> idTokenClaims(String... claimNameValuePairs) {

        Map<String, Object> claims = new HashMap<>();
        for (int i = 0; i < claimNameValuePairs.length; i += 2) {
            claims.put(claimNameValuePairs[i], claimNameValuePairs[i + 1]);
        }
        return claims;
    }

    /**
     * The authenticating user, carrying the given claim URI and value pairs as its attributes.
     */
    private AuthenticatedUser userWithClaims(String... claimUriValuePairs) {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("alex");
        user.setUserStoreDomain("PRIMARY");
        user.setTenantDomain(TENANT_DOMAIN);
        Map<ClaimMapping, String> attributes = new HashMap<>();
        for (int i = 0; i < claimUriValuePairs.length; i += 2) {
            String claimUri = claimUriValuePairs[i];
            attributes.put(ClaimMapping.build(claimUri, claimUri, null, false), claimUriValuePairs[i + 1]);
        }
        user.setUserAttributes(attributes);
        return user;
    }
}
