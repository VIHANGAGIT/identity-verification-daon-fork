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
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineClientException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.model.AssociatedIdentityProvider;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.model.FederatedAssociation;
import org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants;
import org.wso2.carbon.identity.verification.daon.connector.internal.DaonConnectorDataHolder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import static org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes.INVITED_USER_REGISTRATION;
import static org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes.PASSWORD_RECOVERY;
import static org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes.REGISTRATION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ClaimsRequest.TRUST_FRAMEWORK;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ClaimsRequest.TRUST_FRAMEWORK_VALUE;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ConnectionProperties.ENROL_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.ConnectionProperties.LOGIN_PD;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.IdTokenClaims.CLAIMS_OBJECT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.IdTokenClaims.PREFERRED_USERNAME;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.IdTokenClaims.SUBJECT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.IdTokenClaims.VERIFIED_CLAIMS_OBJECT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.LocalClaims.FIRST_NAME_CLAIM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.LocalClaims.LAST_NAME_CLAIM;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.OIDCParams.ACR_VALUES;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.OIDCParams.CLAIMS;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.OIDCParams.ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.OIDCParams.LOGIN_HINT;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.PropertyCarriers.CLAIMS_REQUEST;
import static org.wso2.carbon.identity.verification.daon.connector.constants.DaonConstants.PropertyCarriers.SELECTED_PD;

/**
 * Tests the flow executor: what it puts on the authorization request for each flow, and what it makes of the
 * ID token Daon returns.
 */
public class DaonExecutorTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String IDP_NAME = "Daon Identity Verifier";
    private static final String ENROL_PROCESS_DEFINITION = "EnrolProcess:1.0";
    private static final String LOGIN_PROCESS_DEFINITION = "LoginProcess:2.0";
    private static final String DAON_SUBJECT = "daon-user-9001";
    private static final String QUALIFIED_USERNAME = "PRIMARY/alex";
    private static final String DOB_CLAIM_URI = "http://wso2.org/claims/dob";
    private static final String EMAIL_CLAIM_URI = "http://wso2.org/claims/emailaddress";
    private static final String ADDRESS_CLAIM_URI = "http://wso2.org/claims/addresses";
    private static final String AUTH_CODE = "auth-code";

    private TestDaonExecutor executor;
    private FederatedAssociationManager associationManager;
    private MockedStatic<LoggerUtils> loggerUtils;

    /**
     * Holds the OIDC parent's back-channel token call at its own extension points. The redirect the parent
     * builds needs no stubbing — it is assembled locally from the properties the executor put on the
     * context, which is what these tests read back.
     */
    private static class TestDaonExecutor extends DaonExecutor {

        private String idToken;

        @Override
        protected OAuthClientResponse requestAccessToken(FlowExecutionContext context, String code) {

            OAuthClientResponse response = mock(OAuthClientResponse.class);
            when(response.getParam(OIDCAuthenticatorConstants.ID_TOKEN)).thenReturn(idToken);
            return response;
        }

        @Override
        protected String resolveAccessToken(OAuthClientResponse response) {

            return "stub-access-token";
        }
    }

    @BeforeMethod
    public void setUp() {

        executor = new TestDaonExecutor();
        associationManager = mock(FederatedAssociationManager.class);
        DaonConnectorDataHolder.setFederatedAssociationManager(associationManager);
        loggerUtils = mockStatic(LoggerUtils.class);
    }

    @AfterMethod
    public void tearDown() {

        loggerUtils.close();
        DaonConnectorDataHolder.setFederatedAssociationManager(null);
    }

    // ---------- executor metadata ----------

    @Test
    public void testTheExecutorIsIdentifiedByItsOwnNames() {

        assertEquals(executor.getName(), "DaonExecutor");
        assertEquals(executor.getAMRValue(), DaonConstants.AUTHENTICATOR_NAME);
        assertEquals(executor.getDiagnosticLogComponentId(),
                DaonConstants.LogConstants.OUTBOUND_AUTH_DAON_SERVICE);
    }

    // A later flow type must be opted in.
    @Test
    public void testFlowTypesAreSupported() {

        assertEquals(executor.getSupportedFlowTypes(),
                EnumSet.of(REGISTRATION, PASSWORD_RECOVERY, INVITED_USER_REGISTRATION));
    }

    @Test
    public void testTheExecutorMetadataNamesTheDaonAuthenticator() {

        assertEquals(executor.getExecutorMetadata().getAssociatedAuthenticator(),
                DaonConstants.AUTHENTICATOR_NAME);
        assertTrue(executor.getExecutorMetadata().isConnectionRequired(),
                "The executor cannot verify anything without a Daon connection.");
    }

    // ---------- the authorization request ----------

    @Test
    public void testSelfRegistrationSendsTheEnrolProcessDefinitionAndClaimsRequest() {

        FlowExecutionContext context = flowContext(REGISTRATION);

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION);
        assertEquals(requestProperties(context).get(SELECTED_PD), ENROL_PROCESS_DEFINITION,
                "Self-registration must run the enrol process definition.");
        assertNotNull(requestProperties(context).get(CLAIMS_REQUEST),
                "Registration must ask Daon for the mapped claims.");
        assertNull(requestProperties(context).get(DaonConstants.PropertyCarriers.LOGIN_HINT),
                "A user being registered has no Daon identity to hint at yet.");
    }

    /*
     * A self-registering user has entered these values but nothing has checked them, so Daon is asked to
     * validate them against the identity document.
     */
    @Test
    public void testSelfRegistrationSendsTheValuesTheUserEntered() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        context.getFlowUser().addClaim(FIRST_NAME_CLAIM, "Alex");

        executor.execute(context);

        assertEquals(requestedClaimValue(context, "given_name"), "Alex");
        assertNull(requestedClaimValue(context, "family_name"),
                "A claim the user left blank is requested but has nothing to check against.");
    }

    /*
     * With nothing mapped there is no profile to collect, but the enrolment itself is still worth running,
     * so the request goes out without a claims request rather than failing.
     */
    @Test
    public void testSelfRegistrationRunsWithoutAnyAttributeMappings() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        context.setExternalIdPConfig(externalIdp());

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION);
        assertNull(requestProperties(context).get(CLAIMS_REQUEST));
        assertEquals(requestProperties(context).get(SELECTED_PD), ENROL_PROCESS_DEFINITION);
    }

    /*
     * Recovery re-verifies a known identity, so it must run the login definition and pin the request to the
     * Daon subject already recorded for the account.
     */
    @Test
    public void testPasswordRecoveryIsPinnedToTheEnrolledDaonSubject() {

        FlowExecutionContext context = flowContext(PASSWORD_RECOVERY);
        givenEnrolment(DAON_SUBJECT);

        executor.execute(context);

        assertEquals(requestProperties(context).get(SELECTED_PD), LOGIN_PROCESS_DEFINITION);
        assertEquals(requestProperties(context).get(DaonConstants.PropertyCarriers.LOGIN_HINT),
                DAON_SUBJECT);
        assertNull(requestProperties(context).get(CLAIMS_REQUEST),
                "Recovery re-verifies an identity; it does not collect a profile.");
    }

    @Test
    public void testPasswordRecoveryIsRefusedForAUserWithNoEnrolment() {

        FlowExecutionContext context = flowContext(PASSWORD_RECOVERY);
        givenNoEnrolment();

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_ERROR);
        assertEquals(response.getErrorCode(), "DAON-60001");
        assertNull(requestProperties(context).get(DaonConstants.PropertyCarriers.LOGIN_HINT),
                "There is no enrolled identity to pin the request to.");
    }

    /*
     * An association can exist while carrying no Daon subject; there is then no identity to re-verify the
     * account against.
     */
    @Test
    public void testPasswordRecoveryIsRefusedForASubjectlessEnrolment() {

        FlowExecutionContext context = flowContext(PASSWORD_RECOVERY);
        givenEnrolment(null);

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_ERROR);
        assertEquals(response.getErrorCode(), "DAON-60001");
    }

    @Test
    public void testPasswordRecoveryIsRefusedWhenTheFlowCarriesNoUser() {

        FlowExecutionContext context = flowContext(PASSWORD_RECOVERY);
        context.setFlowUser(null);

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_ERROR);
        assertEquals(response.getErrorCode(), "DAON-60001");
    }

    /*
     * An invited user's profile is admin-defined, so Daon has to be given something off it to check the
     * identity document against. With nothing checkable the step would verify a document belonging to anyone.
     */
    @Test
    public void testInvitedUserRegistrationIsRefusedWithNothingToVerifyAgainst() {

        FlowExecutionContext context = flowContext(INVITED_USER_REGISTRATION);

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_ERROR);
        assertEquals(response.getErrorCode(), "DAON-65023");
        assertNull(requestProperties(context).get(SELECTED_PD));
    }

    /*
     * An email address is not printed on an identity document, so a value-request for it proves nothing.
     */
    @Test
    public void testInvitedUserRegistrationIsRefusedWithOnlyANonDocumentAttribute() {

        FlowExecutionContext context = flowContext(INVITED_USER_REGISTRATION);
        context.setExternalIdPConfig(externalIdp(ClaimMapping.build(EMAIL_CLAIM_URI, "email", null, true)));
        context.getFlowUser().addClaim(EMAIL_CLAIM_URI, "alex@example.com");

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_ERROR);
        assertEquals(response.getErrorCode(), "DAON-65023");
    }

    @Test
    public void testInvitedUserRegistrationSendsTheProfileValuesForDaonToCheck() {

        FlowExecutionContext context = flowContext(INVITED_USER_REGISTRATION);
        context.getFlowUser().addClaim(FIRST_NAME_CLAIM, "Alex");
        context.getFlowUser().addClaim(LAST_NAME_CLAIM, "Kim");

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION);
        assertEquals(requestedClaimValue(context, "given_name"), "Alex");
        assertEquals(requestedClaimValue(context, "family_name"), "Kim");
        assertEquals(requestedTrustFramework(context), TRUST_FRAMEWORK_VALUE,
                "The request has to name the assurance the verification is expected to meet.");
    }

    @Test
    public void testACancelledVerificationIsReportedAsAUserError() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        context.setUserInputData(callbackError("access_denied", "The user cancelled."));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_ERROR);
        assertEquals(response.getErrorCode(), "DAON-60002");
        assertNull(requestProperties(context).get(SELECTED_PD));
    }

    @Test
    public void testAClaimsMismatchIsReportedDistinctlyFromAGenericFailure() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        context.setUserInputData(callbackError("FailedToVerifyUser",
                "reason=CLAIMS_VERIFICATION_MISMATCH detail=dob"));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_ERROR);
        assertEquals(response.getErrorCode(), "DAON-60003",
                "A details mismatch is actionable by the user and must not be flattened into a generic error.");
    }

    @Test
    public void testAnUnrecognisedCallbackErrorIsStillReported() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        context.setUserInputData(callbackError("server_error", "Something went wrong upstream."));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_ERROR);
        assertEquals(response.getErrorCode(), "DAON-60005");
    }

    /*
     * The callback delivers the authorization code through the same user inputs, so a blank error must not
     * be mistaken for a failed verification.
     */
    @Test
    public void testABlankCallbackErrorDoesNotAbortTheFlow() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        context.setUserInputData(callbackError("  ", null));

        ExecutorResponse response = executor.execute(context);

        assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION);
    }

    @Test
    public void testTheSelectedProcessDefinitionGoesOnTheQueryParams() {

        Map<String, String> props = new HashMap<>();
        props.put(SELECTED_PD, ENROL_PROCESS_DEFINITION);
        props.put(CLAIMS_REQUEST, "{\"id_token\":{}}");

        Map<String, String> params = executor.getAdditionalQueryParams(props);

        assertEquals(params.get(ACR_VALUES), ENROL_PROCESS_DEFINITION);
        assertEquals(params.get(CLAIMS), "{\"id_token\":{}}");
    }

    /*
     * A login hint names the identity Daon must verify; a claims request asks it to collect one. Sending both
     * would let Daon fall back to collecting a fresh identity for a flow that meant to re-verify a known one.
     */
    @Test
    public void testNoFreshIdentityIsAskedForWhenOneIsAlreadyNamed() {

        Map<String, String> props = new HashMap<>();
        props.put(SELECTED_PD, LOGIN_PROCESS_DEFINITION);
        props.put(DaonConstants.PropertyCarriers.LOGIN_HINT, DAON_SUBJECT);
        props.put(CLAIMS_REQUEST, "{\"id_token\":{}}");

        Map<String, String> params = executor.getAdditionalQueryParams(props);

        assertEquals(params.get(LOGIN_HINT), DAON_SUBJECT);
        assertFalse(params.containsKey(CLAIMS));
    }

    @Test
    public void testNoQueryParamsAreAddedWhenNothingWasSelected() {

        assertTrue(executor.getAdditionalQueryParams(new HashMap<>()).isEmpty());
    }

    // ---------- the ID token coming back ----------

    @Test
    public void testSelfRegistrationProvisionsTheVerifiedProfile() throws Exception {

        FlowExecutionContext context = flowContext(REGISTRATION);
        executor.idToken = idToken(DAON_SUBJECT, verifiedClaims(
                "given_name", "Alex", "family_name", "Kim", "birthdate", "1990-01-01"));

        Map<String, Object> attributes = executor.resolveUserAttributes(context, AUTH_CODE);

        assertEquals(attributes.get(FIRST_NAME_CLAIM), "Alex");
        assertEquals(attributes.get(LAST_NAME_CLAIM), "Kim");
        assertEquals(attributes.get(DOB_CLAIM_URI), "1990-01-01");
        assertEquals(context.getFlowUser().getFederatedAssociations().get(IDP_NAME), DAON_SUBJECT,
                "The enrolment has to be recorded against the Daon connection.");
    }

    @Test
    public void testAnUnmappedDaonClaimIsNotProvisioned() throws Exception {

        FlowExecutionContext context = flowContext(REGISTRATION);
        executor.idToken = idToken(DAON_SUBJECT,
                verifiedClaims("given_name", "Alex", "document_number", "X1234567"));

        Map<String, Object> attributes = executor.resolveUserAttributes(context, AUTH_CODE);

        assertEquals(attributes.get(FIRST_NAME_CLAIM), "Alex");
        assertFalse(attributes.containsValue("X1234567"),
                "A document detail with no attribute mapping has nowhere to be stored.");
    }

    /*
     * Daon returns the address as an object; the profile holds a single string, so the formatted rendering
     * is what gets provisioned.
     */
    @Test
    public void testAStructuredAddressIsFlattenedForTheProfile() throws Exception {

        FlowExecutionContext context = flowContext(REGISTRATION);
        context.setExternalIdPConfig(externalIdp(
                ClaimMapping.build(ADDRESS_CLAIM_URI, "address", null, true)));
        JSONObject claims = new JSONObject().put("address",
                new JSONObject().put("formatted", "10 Main St, Springfield").put("country", "US"));
        executor.idToken = idToken(DAON_SUBJECT, wrapVerifiedClaims(claims));

        Map<String, Object> attributes = executor.resolveUserAttributes(context, AUTH_CODE);

        assertEquals(attributes.get(ADDRESS_CLAIM_URI), "10 Main St, Springfield");
    }

    /*
     * Some documents carry the whole name in one field. Without the split the profile would be provisioned
     * with no name at all.
     */
    @Test
    public void testACombinedNameFieldIsSplitIntoGivenAndFamilyName() throws Exception {

        FlowExecutionContext context = flowContext(REGISTRATION);
        executor.idToken = idToken(DAON_SUBJECT,
                verifiedClaims("family_name_and_given_name", "KIM^ALEX"));

        Map<String, Object> attributes = executor.resolveUserAttributes(context, AUTH_CODE);

        assertEquals(attributes.get(LAST_NAME_CLAIM), "KIM");
        assertEquals(attributes.get(FIRST_NAME_CLAIM), "ALEX");
    }

    /*
     * The dedicated fields are the more precise reading of the document, so the composite must not displace
     * one Daon also returned on its own.
     */
    @Test
    public void testACombinedNameFieldDoesNotDisplaceTheDedicatedFields() throws Exception {

        FlowExecutionContext context = flowContext(REGISTRATION);
        executor.idToken = idToken(DAON_SUBJECT, verifiedClaims(
                "given_name", "Alexander", "family_name_and_given_name", "KIM^ALEX"));

        Map<String, Object> attributes = executor.resolveUserAttributes(context, AUTH_CODE);

        assertEquals(attributes.get(FIRST_NAME_CLAIM), "Alexander");
        assertEquals(attributes.get(LAST_NAME_CLAIM), "KIM",
                "The half the document only carries in the composite is still worth reading.");
    }

    @Test
    public void testACombinedNameFieldWithoutTheSeparatorIsIgnored() throws Exception {

        FlowExecutionContext context = flowContext(REGISTRATION);
        executor.idToken = idToken(DAON_SUBJECT,
                verifiedClaims("family_name_and_given_name", "KIM ALEX"));

        Map<String, Object> attributes = executor.resolveUserAttributes(context, AUTH_CODE);

        assertFalse(attributes.containsKey(FIRST_NAME_CLAIM));
        assertFalse(attributes.containsKey(LAST_NAME_CLAIM));
    }

    /*
     * The invited user's profile was set by an administrator; Daon checked it rather than supplying it, so
     * the flow must not overwrite it with what the document happened to say.
     */
    @Test
    public void testAnInvitedUsersAdminDefinedProfileIsNotOverwritten() throws Exception {

        FlowExecutionContext context = flowContext(INVITED_USER_REGISTRATION);
        executor.idToken = idToken(DAON_SUBJECT, verifiedClaims("given_name", "Alexander"));

        Map<String, Object> attributes = executor.resolveUserAttributes(context, AUTH_CODE);

        assertTrue(attributes.isEmpty(), "An invited-user flow provisions no claims from the document.");
        assertEquals(context.getFlowUser().getFederatedAssociations().get(IDP_NAME), DAON_SUBJECT,
                "The enrolment itself is still recorded.");
    }

    /*
     * login_hint is only a hint per OIDC. Without this check, anyone who verifies their own enrolled identity
     * would satisfy the recovery step for somebody else's account.
     */
    @Test
    public void testARecoveryVerifiedByADifferentIdentityIsRejected() {

        FlowExecutionContext context = flowContext(PASSWORD_RECOVERY);
        context.getAuthenticatorProperties().put(DaonConstants.PropertyCarriers.LOGIN_HINT, DAON_SUBJECT);
        executor.idToken = idToken("someone-elses-daon-id", verifiedClaims());

        FlowEngineException failure = assertFlowFailure(context, "DAON-60006");
        assertTrue(failure instanceof FlowEngineClientException,
                "A mismatched identity is the user's problem, not a server fault.");
    }

    @Test
    public void testARecoveryVerifiedByTheEnrolledIdentityIsAccepted() throws Exception {

        FlowExecutionContext context = flowContext(PASSWORD_RECOVERY);
        context.getAuthenticatorProperties().put(DaonConstants.PropertyCarriers.LOGIN_HINT, DAON_SUBJECT);
        // Daon echoes the identity back in its own casing.
        executor.idToken = idToken(DAON_SUBJECT.toUpperCase(), verifiedClaims());

        Map<String, Object> attributes = executor.resolveUserAttributes(context, AUTH_CODE);

        assertTrue(attributes.isEmpty(), "Recovery provisions nothing; it only proves the identity.");
        assertTrue(context.getFlowUser().getFederatedAssociations().isEmpty(),
                "Recovery re-verifies an existing enrolment rather than recording a new one.");
    }

    @Test
    public void testARecoveryCarryingNoIdentityIsRejected() {

        FlowExecutionContext context = flowContext(PASSWORD_RECOVERY);
        context.getAuthenticatorProperties().put(DaonConstants.PropertyCarriers.LOGIN_HINT, DAON_SUBJECT);
        executor.idToken = idToken(null, verifiedClaims());

        assertFlowFailure(context, "DAON-65006");
    }

    @Test
    public void testTheFlowFailsWhenDaonReturnsNoIdToken() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        executor.idToken = null;

        assertFlowFailure(context, "DAON-65002");
    }

    @Test
    public void testTheFlowFailsOnAMalformedIdToken() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        executor.idToken = "not-a-jwt";

        assertFlowFailure(context, "DAON-65003");
    }

    /*
     * A token with no verified_claims is an unverified sign-in, not an identity-proofing result.
     */
    @Test
    public void testTheFlowFailsWhenTheTokenCarriesNoVerificationResult() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        executor.idToken = encode(new JSONObject()
                .put(SUBJECT, "daon-sub-abc")
                .put(PREFERRED_USERNAME, DAON_SUBJECT));

        assertFlowFailure(context, "DAON-65021");
    }

    @Test
    public void testTheFlowFailsWhenTheVerificationCarriesNoClaims() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        executor.idToken = idToken(DAON_SUBJECT, new JSONObject()
                .put(DaonConstants.ClaimsRequest.VERIFICATION,
                        new JSONObject().put(TRUST_FRAMEWORK, TRUST_FRAMEWORK_VALUE)));

        assertFlowFailure(context, "DAON-65021");
    }

    /*
     * A different trust framework means the claims were proven to a standard this connector did not ask for.
     */
    @Test
    public void testTheFlowFailsWhenTheVerificationUsedAnotherTrustFramework() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        JSONObject verifiedClaims = new JSONObject()
                .put(DaonConstants.ClaimsRequest.VERIFICATION,
                        new JSONObject().put(TRUST_FRAMEWORK, "some-other-framework"))
                .put(CLAIMS_OBJECT, new JSONObject().put("given_name", "Alex"));
        executor.idToken = idToken(DAON_SUBJECT, verifiedClaims);

        assertFlowFailure(context, "DAON-65022");
    }

    @Test
    public void testTheFlowFailsWhenTheTokenCarriesNoOidcSubject() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        String payload = encode(new JSONObject()
                .put(PREFERRED_USERNAME, DAON_SUBJECT)
                .put(VERIFIED_CLAIMS_OBJECT, verifiedClaims("given_name", "Alex")));
        executor.idToken = payload;

        assertFlowFailure(context, "DAON-65005");
    }

    @Test
    public void testTheFlowFailsWhenTheTokenNamesNoDaonIdentityToEnrol() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        executor.idToken = idToken(null, verifiedClaims("given_name", "Alex"));

        assertFlowFailure(context, "DAON-65025");
    }

    /*
     * The association is keyed on the connection name, so without one the enrolment cannot be recorded and
     * the flow must not complete as though it had been.
     */
    @Test
    public void testTheFlowFailsWhenTheDaonConnectionNameCannotBeResolved() {

        FlowExecutionContext context = flowContext(REGISTRATION);
        context.setExternalIdPConfig(null);
        executor.idToken = idToken(DAON_SUBJECT, verifiedClaims("given_name", "Alex"));

        assertFlowFailure(context, "DAON-65014");
    }

    // ---------- helpers ----------

    /**
     * The authenticator properties the executor composed for the authorization request; the parent builds
     * its redirect from these, and {@code prepareRequest} leaves them on the context.
     */
    private Map<String, String> requestProperties(FlowExecutionContext context) {

        return context.getAuthenticatorProperties();
    }

    private FlowEngineException assertFlowFailure(FlowExecutionContext context, String expectedCode) {

        try {
            executor.resolveUserAttributes(context, AUTH_CODE);
            fail("Expected the flow to fail with " + expectedCode);
            return null;
        } catch (FlowEngineException e) {
            assertEquals(e.getErrorCode(), expectedCode);
            return e;
        }
    }

    /**
     * The value Daon is asked to check the named claim against, or {@code null} when it was only requested.
     */
    private String requestedClaimValue(FlowExecutionContext context, String daonClaimName) {

        JSONObject claims = requestedVerifiedClaims(context).getJSONObject(CLAIMS_OBJECT);
        assertTrue(claims.has(daonClaimName), "The claim was not requested at all: " + daonClaimName);
        JSONObject request = claims.optJSONObject(daonClaimName);
        return request != null ? request.optString("value", null) : null;
    }

    private String requestedTrustFramework(FlowExecutionContext context) {

        return requestedVerifiedClaims(context).getJSONObject(DaonConstants.ClaimsRequest.VERIFICATION)
                .getString(TRUST_FRAMEWORK);
    }

    private JSONObject requestedVerifiedClaims(FlowExecutionContext context) {

        String claimsRequest = requestProperties(context).get(CLAIMS_REQUEST);
        assertNotNull(claimsRequest, "No claims request was sent.");
        return new JSONObject(claimsRequest)
                .getJSONObject(DaonConstants.ClaimsRequest.ID_TOKEN_CONTAINER)
                .getJSONObject(DaonConstants.ClaimsRequest.VERIFIED_CLAIMS);
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

    private Map<String, String> callbackError(String error, String description) {

        Map<String, String> inputs = new HashMap<>();
        inputs.put(OIDCAuthenticatorConstants.OAUTH2_ERROR, error);
        inputs.put(ERROR_DESCRIPTION, description);
        return inputs;
    }

    private FlowExecutionContext flowContext(FlowTypes flowType) {

        FlowExecutionContext context = new FlowExecutionContext();
        context.setTenantDomain(TENANT_DOMAIN);
        context.setFlowType(flowType.getType());

        Map<String, String> props = new HashMap<>();
        props.put(OIDCAuthenticatorConstants.CLIENT_ID, "daon-client");
        props.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "daon-secret");
        props.put(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL, "https://daon.example/authorize");
        props.put(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL, "https://daon.example/token");
        props.put(ENROL_PD, ENROL_PROCESS_DEFINITION);
        props.put(LOGIN_PD, LOGIN_PROCESS_DEFINITION);
        context.setAuthenticatorProperties(props);

        FlowUser flowUser = new FlowUser();
        // Always set: FlowUser.getUsername() resolves through the collected claims when it is unset.
        flowUser.setUsername(QUALIFIED_USERNAME);
        context.setFlowUser(flowUser);

        context.setExternalIdPConfig(externalIdp(
                ClaimMapping.build(FIRST_NAME_CLAIM, "given_name", null, true),
                ClaimMapping.build(LAST_NAME_CLAIM, "family_name", null, true),
                ClaimMapping.build(DOB_CLAIM_URI, "birthdate", null, true)));
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

    private JSONObject verifiedClaims(String... claimPairs) {

        JSONObject claims = new JSONObject();
        for (int i = 0; i < claimPairs.length; i += 2) {
            claims.put(claimPairs[i], claimPairs[i + 1]);
        }
        return wrapVerifiedClaims(claims);
    }

    private JSONObject wrapVerifiedClaims(JSONObject claims) {

        return new JSONObject()
                .put(DaonConstants.ClaimsRequest.VERIFICATION,
                        new JSONObject().put(TRUST_FRAMEWORK, TRUST_FRAMEWORK_VALUE))
                .put(CLAIMS_OBJECT, claims);
    }

    private String idToken(String preferredUsername, JSONObject verifiedClaims) {

        JSONObject payload = new JSONObject()
                .put(SUBJECT, "daon-sub-abc")
                .put(VERIFIED_CLAIMS_OBJECT, verifiedClaims);
        if (preferredUsername != null) {
            payload.put(PREFERRED_USERNAME, preferredUsername);
        }
        return encode(payload);
    }

    private String encode(JSONObject payload) {

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8));
        String body = encoder.encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8));
        return header + "." + body + ".c2lnbmF0dXJl";
    }
}
