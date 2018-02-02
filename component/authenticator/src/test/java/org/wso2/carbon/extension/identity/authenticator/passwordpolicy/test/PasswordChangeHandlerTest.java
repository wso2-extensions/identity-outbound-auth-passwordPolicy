/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.policy.password.PasswordChangeHandler;
import org.wso2.carbon.identity.policy.password.internal.PasswordResetEnforcerDataHolder;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@PrepareForTest(IdentityTenantUtil.class)
public class PasswordChangeHandlerTest {
    private PasswordChangeHandler passwordChangeHandler;

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private UserRealm userRealm;

    @Mock
    private RealmService realmService;

    @Mock
    private EventStreamService eventStreamService;

    @BeforeMethod
    public void setUp() throws Exception {
        passwordChangeHandler = new PasswordChangeHandler();
        initMocks(this);
        PasswordResetEnforcerDataHolder.getInstance().setEventStreamService(eventStreamService);
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @Test
    public void testDoPostUpdateCredentialByAdmin() throws UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        UserStoreManager userStoreManager = userRealm.getUserStoreManager();
        RealmConfiguration realmConfig = new RealmConfiguration();
        realmConfig.getUserStoreProperties().put("DomainName", "domain");
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfig);

        Event event = new Event("POST_UPDATE_CREDENTIAL_BY_ADMIN");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, "user");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_ID, -1234);
        try {
            passwordChangeHandler.handleEvent(event);
        } catch (IdentityEventException e) {
            Assert.fail("Authenticator failed to handle POST_UPDATE_CREDENTIAL_BY_ADMIN", e);
        }
    }

    @Test
    public void testDoPostUpdateCredential() throws UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        UserStoreManager userStoreManager = userRealm.getUserStoreManager();
        RealmConfiguration realmConfig = new RealmConfiguration();
        realmConfig.getUserStoreProperties().put("DomainName", "domain");
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfig);

        Event event = new Event("POST_UPDATE_CREDENTIAL");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, "user");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_ID, -1234);
        try {
            passwordChangeHandler.handleEvent(event);
        } catch (IdentityEventException e) {
            Assert.fail("Authenticator failed to handle POST_UPDATE_CREDENTIAL", e);
        }
    }

    @Test
    public void testDoAddUser() throws UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(-1234)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        UserStoreManager userStoreManager = userRealm.getUserStoreManager();
        RealmConfiguration realmConfig = new RealmConfiguration();
        realmConfig.getUserStoreProperties().put("DomainName", "domain");
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfig);

        Event event = new Event("POST_UPDATE_CREDENTIAL");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, "user");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_ID, -1234);
        try {
            passwordChangeHandler.handleEvent(event);
        } catch (IdentityEventException e) {
            Assert.fail("Authenticator failed to handle POST_UPDATE_CREDENTIAL", e);
        }
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }
}