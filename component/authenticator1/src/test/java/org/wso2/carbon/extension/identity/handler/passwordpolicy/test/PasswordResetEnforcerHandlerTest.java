/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.extension.identity.handler.passwordpolicy.test;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.post.authn.handler.disclaimer.EnforcePasswordResetAuthenticationHandler;
import org.wso2.carbon.identity.post.authn.handler.disclaimer.PasswordPolicyUtils;
import org.wso2.carbon.identity.post.authn.handler.disclaimer.internal.EnforcePasswordResetPostAuthenticationHandlerDataHolder;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.*;

@PrepareForTest({IdentityTenantUtil.class, MultitenantUtils.class, IdentityUtil.class, PasswordPolicyUtils.class,
        UserStoreManager.class, EnforcePasswordResetPostAuthenticationHandlerDataHolder.class, FrameworkServiceDataHolder.class})
public class PasswordResetEnforcerHandlerTest {
    @InjectMocks
    private EnforcePasswordResetAuthenticationHandler passwordChangeHandler;

    @Mock
    private AuthenticationContext authenticationContext;


    @BeforeClass
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @ObjectFactory
    public org.testng.IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @Test
    public void testHandle_withoutAuthenticatedIdPs() throws Exception {

        SequenceConfig sequenceConfig = mock(SequenceConfig.class);
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);

        when(authenticationContext.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getAuthenticatedUser()).thenReturn(authenticatedUser);
        when(authenticatedUser.getTenantDomain()).thenReturn("carbon.super");
        when(authenticatedUser.getUserName()).thenReturn("admin");
        when(authenticatedUser.getUserStoreDomain()).thenReturn("PRIMARY");
        when(authenticatedUser.getAuthenticatedSubjectIdentifier()).thenReturn("admin");
        when(authenticatedUser.isFederatedUser()).thenReturn(false);
        when(authenticatedUser.getAuthenticatedSubjectIdentifier())
                .thenReturn("john");

        Map<String, AuthenticatedIdPData> idPs = new HashMap<>();
        AuthenticatedIdPData authenticatedIdPData = mock(AuthenticatedIdPData.class);
        idPs.put("LOCAL", authenticatedIdPData);
        List<AuthenticatorConfig> authenticators = new ArrayList<>();
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setName("BasicAuthenticator");
        authenticators.add(authenticatorConfig);

        when(authenticationContext.getCurrentAuthenticatedIdPs()).thenReturn(idPs);

        mockStatic(PasswordPolicyUtils.class);
        mockStatic(MultitenantUtils.class);
        PowerMockito.when(passwordChangeHandler, "isPasswordHistoryEnabled", "carbon.super").thenReturn("true");

        PowerMockito.mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);
        when(MultitenantUtils.getTenantAwareUsername("john")).thenReturn("bob");
        String[] claimURIs = new String[]{"http://wso2.org/claims/identity/lastPasswordUpdateTime"};
        Map<String, String> claimValueMap = new HashMap<>();
        claimValueMap.put("http://wso2.org/claims/identity/lastPasswordUpdateTime", "1677845659");


        RealmService mockRealmService = mock(RealmService.class);

        UserRealm userRealm = mock(UserRealm.class);
        UserStoreManager mockUserStoreManager = mock(UserStoreManager.class);

        mockStatic(EnforcePasswordResetPostAuthenticationHandlerDataHolder.class);

        EnforcePasswordResetAuthenticationHandler passwordChangeHandler = PowerMockito.spy(new EnforcePasswordResetAuthenticationHandler());
        EnforcePasswordResetPostAuthenticationHandlerDataHolder dataHolder = PowerMockito.mock(EnforcePasswordResetPostAuthenticationHandlerDataHolder.class);
        PowerMockito.when(EnforcePasswordResetPostAuthenticationHandlerDataHolder.getInstance()).thenReturn(dataHolder);
        PowerMockito.when(dataHolder.getRealmService()).thenReturn(mockRealmService);

        EnforcePasswordResetPostAuthenticationHandlerDataHolder.getInstance().setRealmService(mockRealmService);
        when(mockRealmService.getTenantUserRealm(MultitenantConstants.SUPER_TENANT_ID)).thenReturn((UserRealm) userRealm);


        when(userRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getUserClaimValues("bob", claimURIs , null)).thenReturn(claimValueMap);

        doReturn(authenticators).when(idPs.get("LOCAL")).getAuthenticators();

        when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);


        PostAuthnHandlerFlowStatus status = passwordChangeHandler.handle(
                mock(HttpServletRequest.class),
                mock(HttpServletResponse.class),
                authenticationContext);
    }

}
