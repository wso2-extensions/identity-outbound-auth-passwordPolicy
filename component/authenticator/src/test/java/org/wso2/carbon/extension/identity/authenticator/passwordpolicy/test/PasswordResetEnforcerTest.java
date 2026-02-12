/*
 *  Copyright (c) 2018-2026, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.extension.identity.authenticator.passwordpolicy.test;

import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Spy;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.mgt.policy.PolicyViolationException;
import org.wso2.carbon.identity.password.history.exeption.IdentityPasswordHistoryException;
import org.wso2.carbon.identity.policy.password.PasswordPolicyConstants;
import org.wso2.carbon.identity.policy.password.PasswordPolicyUtils;
import org.wso2.carbon.identity.policy.password.PasswordResetEnforcer;
import org.wso2.carbon.identity.policy.password.internal.PasswordPolicyDataHolder;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.Claim;
import  org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doThrow;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@PowerMockIgnore({"jdk.internal.*", "javax.*", "sun.*", "org.mockito.*", "org.w3c.*", "org.xml.*"})
@PrepareForTest({IdentityTenantUtil.class, ConfigurationFacade.class, FrameworkUtils.class, CarbonUtils.class,
        IdentityProviderManager.class, PasswordPolicyUtils.class, MultitenantUtils.class, UserCoreUtil.class,
        org.wso2.carbon.identity.password.expiry.util.PasswordPolicyUtils.class})
public class PasswordResetEnforcerTest {
    private PasswordResetEnforcer passwordResetEnforcer;

    @Mock
    private ConfigurationFacade configurationFacade;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Spy
    private AuthenticationContext context;

    @Mock
    private SequenceConfig sequenceConfig;

    @Mock
    private Map<Integer, StepConfig> mockedMap;

    @Mock
    private StepConfig stepConfig;

    @Mock
    private AuthenticatorConfig authenticatorConfig;

    @Mock
    private ApplicationAuthenticator applicationAuthenticator;

    @Mock
    private LocalApplicationAuthenticator localApplicationAuthenticator;

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private ClaimManager claimManager;

    @Mock
    private RealmConfiguration realmConfiguration;

    @Mock
    private UserRealm userRealm;

    @Mock
    private RealmService realmService;

    @Mock
    private IdentityGovernanceService identityGovernanceService;

    @Mock
    private IdentityProviderManager identityProviderManager;

    static {
        // Set the CARBON_HOME system property
        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
    }


    @BeforeMethod
    public void setUp() throws Exception {
        passwordResetEnforcer = new PasswordResetEnforcer();
        initMocks(this);
        PasswordPolicyDataHolder.getInstance().setIdentityGovernanceService(identityGovernanceService);

        // Ensure that the mocks are correctly set up
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
    }

    @Test
    public void testCanHandleTrue() {
        Assert.assertEquals(passwordResetEnforcer.canHandle(httpServletRequest), true);
    }

    @Test
    public void testGetFriendlyName() {
        Assert.assertEquals(passwordResetEnforcer.getFriendlyName(),
                PasswordPolicyConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    @Test
    public void testGetName() {
        Assert.assertEquals(passwordResetEnforcer.getName(),
                PasswordPolicyConstants.AUTHENTICATOR_NAME);
    }

    @Test
    public void testGetContextIdentifier() {
        when(httpServletRequest.getParameter(PasswordPolicyConstants.STATE)).thenReturn("abc");
        Assert.assertEquals(passwordResetEnforcer.getContextIdentifier(httpServletRequest),
                "abc");
    }


    @Test
    public void testGetUser() throws Exception {
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        Whitebox.invokeMethod(passwordResetEnforcer, "getUser", context);
    }

    @Test
    public void testUpdateAuthenticatedUserInStepConfig() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        Whitebox.invokeMethod(passwordResetEnforcer, "updateAuthenticatedUserInStepConfig",
                context, authenticatedUser);
    }

    @Test
    public void testProcessWithLogoutTrue() throws AuthenticationFailedException, LogoutFailedException {
        when(context.isLogoutRequest()).thenReturn(true);
        AuthenticatorFlowStatus status = passwordResetEnforcer.process(httpServletRequest,
                httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testProcessWithLogoutFailure() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(UserCoreUtil.class);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.isLogoutRequest()).thenReturn(false);
        when(httpServletRequest.getParameter(PasswordPolicyConstants.CURRENT_PWD)).thenReturn("1234");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD)).thenReturn("7894");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD_CONFIRMATION)).thenReturn("7894");
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(applicationAuthenticator);
        when(Whitebox.invokeMethod(passwordResetEnforcer, "getUser", context)).
                thenReturn(authenticatedUser);

        AuthenticatorFlowStatus status = passwordResetEnforcer.process(httpServletRequest,
                httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testProcessWithLogout() throws Exception {
        when(context.isLogoutRequest()).thenReturn(false);
        when(httpServletRequest.getParameter(PasswordPolicyConstants.CURRENT_PWD)).thenReturn("");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD)).thenReturn("");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD_CONFIRMATION)).thenReturn("");
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(applicationAuthenticator);

        AuthenticatorFlowStatus status = passwordResetEnforcer.process(httpServletRequest,
                httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testInitiateAuthRequestWithException() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(PasswordPolicyUtils.class);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(applicationAuthenticator);
        when(PasswordPolicyUtils.isUserStoreBasedIdentityDataStore()).thenReturn(false);
        when(PasswordPolicyUtils.isActiveDirectoryUserStore((UserStoreManager) anyObject())).thenReturn(false);
        when(Whitebox.invokeMethod(passwordResetEnforcer, "initiateAuthRequest",
                httpServletResponse, context, ""))
                .thenReturn(authenticatedUser);

        AuthenticatorFlowStatus status = Whitebox
                .invokeMethod(passwordResetEnforcer, "initiateAuthRequest",
                        httpServletResponse, context, "");
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testInitiateAuthRequestForFederatedUser() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(PasswordPolicyUtils.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(UserCoreUtil.class);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("fooUser");
        authenticatedUser.setFederatedUser(true);

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(applicationAuthenticator);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(PasswordPolicyUtils.isUserStoreBasedIdentityDataStore()).thenReturn(false);
        when(PasswordPolicyUtils.isActiveDirectoryUserStore((UserStoreManager) anyObject())).thenReturn(false);

        AuthenticatorFlowStatus status = Whitebox
                .invokeMethod(passwordResetEnforcer, "initiateAuthRequest",
                        httpServletResponse, context, "");
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testInitiateAuthRequestSuccess() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(ConfigurationFacade.class);
        mockStatic(FrameworkUtils.class);
        mockStatic(CarbonUtils.class);
        mockStatic(IdentityProviderManager.class);
        mockStatic(PasswordPolicyUtils.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(UserCoreUtil.class);
        mockStatic(org.wso2.carbon.identity.password.expiry.util.PasswordPolicyUtils.class);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        String path = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        when(CarbonUtils.getCarbonConfigDirPath()).thenReturn(path);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(localApplicationAuthenticator);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userRealm.getClaimManager()).thenReturn(claimManager);
        when(userRealm.getClaimManager().getClaim(PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM))
                .thenReturn(new Claim());
        when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM, null))
                .thenReturn("1461315067665");
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("login.do");
        when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn(null);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP("carbon.super")).thenReturn(null);
        when(PasswordPolicyUtils.isUserStoreBasedIdentityDataStore()).thenReturn(false);
        when(PasswordPolicyUtils.isActiveDirectoryUserStore((UserStoreManager) anyObject())).thenReturn(false);
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("admin");
        when(UserCoreUtil.extractDomainFromName(anyString())).thenReturn("PRIMARY");
        when(UserCoreUtil.addTenantDomainToEntry(anyString(), anyString())).thenReturn("admin@carbon.super");
        when(org.wso2.carbon.identity.password.expiry.util.PasswordPolicyUtils.isPasswordExpired(
                anyString(), anyString())).thenReturn(true);

        AuthenticatorFlowStatus status = Whitebox.invokeMethod(passwordResetEnforcer, "initiateAuthRequest",
                httpServletResponse, context, "");
        verify(httpServletResponse)
                .sendRedirect(Matchers.matches(".*" + PasswordPolicyConstants.AUTHENTICATOR_NAME + ".*"));
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void testInitiateAuthRequestSuccessWithRetrying() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(ConfigurationFacade.class);
        mockStatic(FrameworkUtils.class);
        mockStatic(CarbonUtils.class);
        mockStatic(IdentityProviderManager.class);
        mockStatic(PasswordPolicyUtils.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(UserCoreUtil.class);
        mockStatic(org.wso2.carbon.identity.password.expiry.util.PasswordPolicyUtils.class);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        String path = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        when(CarbonUtils.getCarbonConfigDirPath()).thenReturn(path);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        when(authenticatorConfig.getApplicationAuthenticator()).thenReturn(localApplicationAuthenticator);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userRealm.getClaimManager()).thenReturn(claimManager);
        when(userRealm.getClaimManager().getClaim(PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM))
                .thenReturn(new Claim());
        when(userRealm.getUserStoreManager()
                .getUserClaimValue(MultitenantUtils.getTenantAwareUsername("admin"),
                        PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM, null))
                .thenReturn("1461315067665");
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn("login.do");
        when(FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier())).thenReturn(null);

        when(userStoreManager.getUserClaimValue(eq("admin"),
                eq(PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM), isNull(String.class)))
                .thenReturn(null);
        when(context.isRetrying()).thenReturn(true);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP("carbon.super")).thenReturn(null);
        when(PasswordPolicyUtils.isUserStoreBasedIdentityDataStore()).thenReturn(false);
        when(PasswordPolicyUtils.isActiveDirectoryUserStore((UserStoreManager) anyObject())).thenReturn(false);
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("admin");
        when(UserCoreUtil.extractDomainFromName(anyString())).thenReturn("PRIMARY");
        when(UserCoreUtil.addTenantDomainToEntry(anyString(), anyString())).thenReturn("admin@carbon.super");
        when(org.wso2.carbon.identity.password.expiry.util.PasswordPolicyUtils.isPasswordExpired(
                anyString(), anyString())).thenReturn(true);

        AuthenticatorFlowStatus status = Whitebox
                .invokeMethod(passwordResetEnforcer, "initiateAuthRequest",
                        httpServletResponse, context, "");
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        verify(httpServletResponse, times(1))
                .sendRedirect(Matchers.matches(".*&authFailure=true&authFailureMsg=.*"));
    }

    @Test
    public void testProcessAuthenticationResponse() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(UserCoreUtil.class);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(realmConfiguration.getUserStoreProperty("PasswordJavaRegEx")).thenReturn("^[\\S]{5,30}$");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.CURRENT_PWD)).thenReturn("123456");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD)).thenReturn("456789");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD_CONFIRMATION)).thenReturn("456789");

        Whitebox.invokeMethod(passwordResetEnforcer, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testProcessAuthenticationResponseWithException() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(UserCoreUtil.class);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(httpServletRequest.getParameter(PasswordPolicyConstants.CURRENT_PWD)).thenReturn(null);
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD)).thenReturn(null);
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD_CONFIRMATION)).thenReturn(null);

        Whitebox.invokeMethod(passwordResetEnforcer, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testProcessResponseWithSamePassword() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(UserCoreUtil.class);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(httpServletRequest.getParameter(PasswordPolicyConstants.CURRENT_PWD)).thenReturn("12345");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD)).thenReturn("12345");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD_CONFIRMATION)).thenReturn("12345");
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("admin");
        when(UserCoreUtil.extractDomainFromName(anyString())).thenReturn("PRIMARY");

        Whitebox.invokeMethod(passwordResetEnforcer, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testProcessResponseWithMismatchPassword() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(UserCoreUtil.class);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(httpServletRequest.getParameter(PasswordPolicyConstants.CURRENT_PWD)).thenReturn("12345");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD)).thenReturn("456789");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD_CONFIRMATION)).thenReturn("12345");
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("admin");
        when(UserCoreUtil.extractDomainFromName(anyString())).thenReturn("PRIMARY");

        Whitebox.invokeMethod(passwordResetEnforcer, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testProcessResponseWithEmptyPassword() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(UserCoreUtil.class);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(realmConfiguration.getUserStoreProperty("PasswordJavaRegEx")).thenReturn("^[\\S]{5,30}$");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.CURRENT_PWD)).thenReturn("12345");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD)).thenReturn("");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD_CONFIRMATION)).thenReturn("");
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("admin");
        when(UserCoreUtil.extractDomainFromName(anyString())).thenReturn("PRIMARY");

        Whitebox.invokeMethod(passwordResetEnforcer, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testProcessResponseWithInvalidPasswordFormat() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(UserCoreUtil.class);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(realmConfiguration.getUserStoreProperty("PasswordJavaRegEx")).thenReturn("^[\\S]{5,30}$");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.CURRENT_PWD)).thenReturn("12345");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD)).thenReturn("123");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD_CONFIRMATION)).thenReturn("123");
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("admin");
        when(UserCoreUtil.extractDomainFromName(anyString())).thenReturn("PRIMARY");

        Whitebox.invokeMethod(passwordResetEnforcer, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testProcessResponseWithInvalidOperation() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(UserCoreUtil.class);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(realmConfiguration.getUserStoreProperty("PasswordJavaRegEx")).thenReturn("^[\\S]{5,30}$");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.CURRENT_PWD)).thenReturn("12345");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD)).thenReturn("123456");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD_CONFIRMATION)).thenReturn("123456");
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("admin");
        when(UserCoreUtil.extractDomainFromName(anyString())).thenReturn("PRIMARY");

        doThrow(new UserStoreException("InvalidOperation dummy exception"))
                .when(userStoreManager).updateCredential("admin", "123456", "12345");

        Whitebox.invokeMethod(passwordResetEnforcer, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testProcessResponseWithInvalidCurrentPassword() throws Exception {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(UserCoreUtil.class);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");

        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getBootstrapRealmConfiguration()).thenReturn(realmConfiguration);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
        when(stepConfig.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);
        when(realmConfiguration.getUserStoreProperty("PasswordJavaRegEx")).thenReturn("^[\\S]{5,30}$");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.CURRENT_PWD)).thenReturn("12345");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD)).thenReturn("123456");
        when(httpServletRequest.getParameter(PasswordPolicyConstants.NEW_PWD_CONFIRMATION)).thenReturn("123456");
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("admin");
        when(UserCoreUtil.extractDomainFromName(anyString())).thenReturn("PRIMARY");

        doThrow(new UserStoreException("PasswordInvalid dummy exception"))
                .when(userStoreManager).updateCredential("admin", "123456", "12345");

        Whitebox.invokeMethod(passwordResetEnforcer, "processAuthenticationResponse",
                httpServletRequest, httpServletResponse, context);
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        Assert.assertTrue(passwordResetEnforcer.isAPIBasedAuthenticationSupported());
    }

    @Test
    public void testGetAuthInitiationDataWithNullContext() {

        Optional<AuthenticatorData> result = passwordResetEnforcer.getAuthInitiationData(null);
        Assert.assertTrue(result.isPresent());
        AuthenticatorData data = result.get();
        Assert.assertEquals(data.getName(), PasswordPolicyConstants.AUTHENTICATOR_NAME);
        Assert.assertEquals(data.getDisplayName(), PasswordPolicyConstants.AUTHENTICATOR_FRIENDLY_NAME);
        Assert.assertNull(data.getIdp());
        Assert.assertEquals(data.getPromptType(), FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);

        List<String> requiredParams = data.getRequiredParams();
        Assert.assertEquals(requiredParams.size(), 3);
        Assert.assertTrue(requiredParams.contains(PasswordPolicyConstants.CURRENT_PWD));
        Assert.assertTrue(requiredParams.contains(PasswordPolicyConstants.NEW_PWD));
        Assert.assertTrue(requiredParams.contains(PasswordPolicyConstants.NEW_PWD_CONFIRMATION));

        List<AuthenticatorParamMetadata> authParams = data.getAuthParams();
        Assert.assertNotNull(authParams);
        Assert.assertEquals(authParams.size(), 3);

        AuthenticatorMessage message = data.getMessage();
        Assert.assertNotNull(message);
        Assert.assertEquals(message.getType(), FrameworkConstants.AuthenticatorMessageType.INFO);
        Assert.assertEquals(message.getCode(), PasswordPolicyConstants.PASSWORD_EXPIRED_MESSAGE_KEY);
        Assert.assertEquals(message.getMessage(), PasswordPolicyConstants.PASSWORD_EXPIRED_MESSAGE);
    }

    @Test
    public void testGetAuthInitiationDataWithExternalIdP() {

        ExternalIdPConfig externalIdPConfig = mock(ExternalIdPConfig.class);
        when(externalIdPConfig.getIdPName()).thenReturn("testIdP");
        when(context.getExternalIdP()).thenReturn(externalIdPConfig);
        when(context.isRetrying()).thenReturn(false);

        Optional<AuthenticatorData> result = passwordResetEnforcer.getAuthInitiationData(context);
        Assert.assertTrue(result.isPresent());
        Assert.assertEquals(result.get().getIdp(), "testIdP");
    }

    @Test
    public void testGetAuthInitiationDataWithNoExternalIdP() {

        when(context.getExternalIdP()).thenReturn(null);
        when(context.isRetrying()).thenReturn(false);

        Optional<AuthenticatorData> result = passwordResetEnforcer.getAuthInitiationData(context);
        Assert.assertTrue(result.isPresent());
        Assert.assertNull(result.get().getIdp());
    }

    @Test
    public void testGetAuthInitiationDataNotRetrying() {

        when(context.getExternalIdP()).thenReturn(null);
        when(context.isRetrying()).thenReturn(false);

        Optional<AuthenticatorData> result = passwordResetEnforcer.getAuthInitiationData(context);
        Assert.assertTrue(result.isPresent());

        AuthenticatorMessage message = result.get().getMessage();
        Assert.assertEquals(message.getType(), FrameworkConstants.AuthenticatorMessageType.INFO);
        Assert.assertEquals(message.getCode(), PasswordPolicyConstants.PASSWORD_EXPIRED_MESSAGE_KEY);
        Assert.assertEquals(message.getMessage(), PasswordPolicyConstants.PASSWORD_EXPIRED_MESSAGE);
    }

    @Test
    public void testGetAuthInitiationDataRetryingWithErrorMessage() {

        when(context.getExternalIdP()).thenReturn(null);
        when(context.isRetrying()).thenReturn(true);
        when(context.getProperty(PasswordPolicyConstants.PASSWORD_RESET_ERROR_MESSAGE))
                .thenReturn("Password validation failed");

        Optional<AuthenticatorData> result = passwordResetEnforcer.getAuthInitiationData(context);
        Assert.assertTrue(result.isPresent());

        AuthenticatorMessage message = result.get().getMessage();
        Assert.assertEquals(message.getType(), FrameworkConstants.AuthenticatorMessageType.ERROR);
        Assert.assertEquals(message.getCode(), PasswordPolicyConstants.PASSWORD_RESET_ERROR_KEY);
        Assert.assertEquals(message.getMessage(), "Password validation failed");
    }

    @Test
    public void testGetAuthInitiationDataRetryingWithoutErrorMessage() {

        when(context.getExternalIdP()).thenReturn(null);
        when(context.isRetrying()).thenReturn(true);
        when(context.getProperty(PasswordPolicyConstants.PASSWORD_RESET_ERROR_MESSAGE)).thenReturn(null);

        Optional<AuthenticatorData> result = passwordResetEnforcer.getAuthInitiationData(context);
        Assert.assertTrue(result.isPresent());

        AuthenticatorMessage message = result.get().getMessage();
        Assert.assertEquals(message.getType(), FrameworkConstants.AuthenticatorMessageType.INFO);
        Assert.assertEquals(message.getCode(), PasswordPolicyConstants.PASSWORD_EXPIRED_MESSAGE_KEY);
    }

    @Test
    public void testGetAuthenticatorParamMetadata() throws Exception {

        Method method = PasswordResetEnforcer.class.getDeclaredMethod("getAuthenticatorParamMetadata");
        method.setAccessible(true);
        List<AuthenticatorParamMetadata> result =
                (List<AuthenticatorParamMetadata>) method.invoke(passwordResetEnforcer);
        Assert.assertNotNull(result);
        Assert.assertEquals(result.size(), 3);

        AuthenticatorParamMetadata currentPwd = result.get(0);
        Assert.assertEquals(currentPwd.getName(), PasswordPolicyConstants.CURRENT_PWD);
        Assert.assertEquals(currentPwd.getDisplayName(), PasswordPolicyConstants.CURRENT_PWD_DISPLAY_NAME);
        Assert.assertEquals(currentPwd.getParamOrder(), 0);
        Assert.assertTrue(currentPwd.isConfidential());

        AuthenticatorParamMetadata newPwd = result.get(1);
        Assert.assertEquals(newPwd.getName(), PasswordPolicyConstants.NEW_PWD);
        Assert.assertEquals(newPwd.getDisplayName(), PasswordPolicyConstants.NEW_PWD_DISPLAY_NAME);
        Assert.assertEquals(newPwd.getParamOrder(), 1);
        Assert.assertTrue(newPwd.isConfidential());

        AuthenticatorParamMetadata confirmPwd = result.get(2);
        Assert.assertEquals(confirmPwd.getName(), PasswordPolicyConstants.NEW_PWD_CONFIRMATION);
        Assert.assertEquals(confirmPwd.getDisplayName(), PasswordPolicyConstants.NEW_PWD_CONFIRMATION_DISPLAY_NAME);
        Assert.assertEquals(confirmPwd.getParamOrder(), 2);
        Assert.assertTrue(confirmPwd.isConfidential());
    }

    @Test
    public void testIsPasswordPolicyViolationErrorWithPolicyViolation() throws Exception {

        PolicyViolationException policyViolation = mock(PolicyViolationException.class);
        Exception e = new Exception("Error", policyViolation);

        Method method = PasswordResetEnforcer.class.getDeclaredMethod(
                "isPasswordPolicyViolationError", Throwable.class);
        method.setAccessible(true);
        boolean result = (boolean) method.invoke(passwordResetEnforcer, e);
        Assert.assertTrue(result);
    }

    @Test
    public void testIsPasswordPolicyViolationErrorWithPasswordHistory() throws Exception {

        IdentityPasswordHistoryException historyException = mock(IdentityPasswordHistoryException.class);
        Exception e = new Exception("Error", historyException);

        Method method = PasswordResetEnforcer.class.getDeclaredMethod(
                "isPasswordPolicyViolationError", Throwable.class);
        method.setAccessible(true);
        boolean result = (boolean) method.invoke(passwordResetEnforcer, e);
        Assert.assertTrue(result);
    }

    @Test
    public void testIsPasswordPolicyViolationErrorWithIdentityEventException() throws Exception {

        IdentityEventException identityEventException = mock(IdentityEventException.class);
        when(identityEventException.getErrorCode())
                .thenReturn(PasswordPolicyConstants.PASSWORD_HISTORY_VIOLATION_ERROR_CODE);
        Exception e = new Exception("Error", identityEventException);

        Method method = PasswordResetEnforcer.class.getDeclaredMethod(
                "isPasswordPolicyViolationError", Throwable.class);
        method.setAccessible(true);
        boolean result = (boolean) method.invoke(passwordResetEnforcer, e);
        Assert.assertTrue(result);
    }

    @Test
    public void testIsPasswordPolicyViolationErrorWithNonMatchingException() throws Exception {

        Exception e = new Exception("Some generic error", new RuntimeException("random"));

        Method method = PasswordResetEnforcer.class.getDeclaredMethod(
                "isPasswordPolicyViolationError", Throwable.class);
        method.setAccessible(true);
        boolean result = (boolean) method.invoke(passwordResetEnforcer, e);
        Assert.assertFalse(result);
    }

    @Test
    public void testIsPasswordPolicyViolationErrorWithNoCause() throws Exception {

        Exception e = new Exception("No cause");

        Method method = PasswordResetEnforcer.class.getDeclaredMethod(
                "isPasswordPolicyViolationError", Throwable.class);
        method.setAccessible(true);
        boolean result = (boolean) method.invoke(passwordResetEnforcer, e);
        Assert.assertFalse(result);
    }

    @Test
    public void testGetAuthenticationErrorMessageWithPolicyViolation() throws Exception {

        PolicyViolationException policyViolation = mock(PolicyViolationException.class);
        Exception e = new Exception("Password must contain special characters", policyViolation);

        Method method = PasswordResetEnforcer.class.getDeclaredMethod(
                "getAuthenticationErrorMessage", Exception.class);
        method.setAccessible(true);
        String result = (String) method.invoke(passwordResetEnforcer, e);
        Assert.assertEquals(result, "Password must contain special characters");
    }

    @Test
    public void testGetAuthenticationErrorMessageWithPasswordHistoryViolation() throws Exception {

        IdentityPasswordHistoryException historyException = mock(IdentityPasswordHistoryException.class);
        Exception e = new Exception("Cannot reuse recent passwords", historyException);

        Method method = PasswordResetEnforcer.class.getDeclaredMethod(
                "getAuthenticationErrorMessage", Exception.class);
        method.setAccessible(true);
        String result = (String) method.invoke(passwordResetEnforcer, e);
        Assert.assertEquals(result, "Cannot reuse recent passwords");
    }

    @Test
    public void testGetAuthenticationErrorMessageWithGenericError() throws Exception {

        Exception e = new Exception("Some generic error");

        Method method = PasswordResetEnforcer.class.getDeclaredMethod(
                "getAuthenticationErrorMessage", Exception.class);
        method.setAccessible(true);
        String result = (String) method.invoke(passwordResetEnforcer, e);
        Assert.assertEquals(result, "Error occurred while updating the password");
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }
}
