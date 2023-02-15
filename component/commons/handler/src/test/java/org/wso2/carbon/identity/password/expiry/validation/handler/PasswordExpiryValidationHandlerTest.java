/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.password.expiry.validation.handler;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@PrepareForTest({IdentityTenantUtil.class, MultitenantUtils.class, PasswordExpiryPolicyUtils.class, UserStoreManager.class})
public class PasswordExpiryValidationHandlerTest {
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String USERNAME = "admin";
    private static final int TENANT_ID = -1234;
    @Mock
    private UserStoreManager userStoreManager;
    @Mock
    private ClaimManager claimManager;

    @Mock
    private UserRealm userRealm;

    @Mock
    private RealmService realmService;

    @Mock
    private Claim claim;
    private PasswordExpiryValidationHandler passwordExpiryValidationHandler;


    @BeforeMethod
    public void setUp(){
        passwordExpiryValidationHandler = new PasswordExpiryValidationHandler();
        initMocks(this);
    }

   @Test
  public void testHandleEventForPasswordNonExpiredUserWithLastPasswordClaim() throws UserStoreException {
    mockStatic(IdentityTenantUtil.class);
    mockStatic(PasswordExpiryPolicyUtils.class);
    mockStatic(UserStoreManager.class);
    mockStatic(MultitenantUtils.class);
    Event event = new Event("PASSWORD_EXPIRY_VALIDATION");
    event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, USERNAME);
    event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
    event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);
    when(MultitenantUtils.getTenantAwareUsername(USERNAME)).thenReturn(USERNAME);
    when(PasswordExpiryPolicyUtils.getResidentIdpProperty(TENANT_DOMAIN,
            PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn("20");

    Map<String, String> claimValueMap = new HashMap<>();
    String timestamp = String.valueOf(System.currentTimeMillis());
    claimValueMap.put(PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM,timestamp);
    String[] claimURIs = new String[]{PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM};

   when(userStoreManager.getUserClaimValues(USERNAME, claimURIs, null)).thenReturn(claimValueMap);
    try {
        passwordExpiryValidationHandler.handleEvent(event);
    } catch (IdentityEventException e) {
        Assert.fail("Identity Event Exception!");
    }
   }

   @Test
    public void testHandleEventForPasswordExpiredUserWithLastPasswordClaim() throws UserStoreException{
        mockStatic(IdentityTenantUtil.class);
        mockStatic(PasswordExpiryPolicyUtils.class);
        mockStatic(UserStoreManager.class);
        mockStatic(MultitenantUtils.class);
        Event event = new Event("PASSWORD_EXPIRY_VALIDATION");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, USERNAME);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);
        when(MultitenantUtils.getTenantAwareUsername(USERNAME)).thenReturn(USERNAME);
        when(PasswordExpiryPolicyUtils.getResidentIdpProperty(TENANT_DOMAIN,
                PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn("20");

        Map<String, String> claimValueMap = new HashMap<>();
        claimValueMap.put(PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM,"1672559229000");
        String[] claimURIs = new String[]{PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM};

        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs, null)).thenReturn(claimValueMap);
        try {
            passwordExpiryValidationHandler.handleEvent(event);
            Assert.fail("This should throw identity event exception");
        } catch (IdentityEventException e) {
            Assert.assertEquals(PasswordExpiryValidationConstants.PASSWORD_EXPIRED_ERROR_MESSAGE,e.getMessage());
        }
    }

    @Test
    public void testHandleEventForPasswordNonExpiredUserWithNonIdentityClaim() throws UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(PasswordExpiryPolicyUtils.class);
        mockStatic(UserStoreManager.class);
        mockStatic(MultitenantUtils.class);
        Event event = new Event("PASSWORD_EXPIRY_VALIDATION");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, USERNAME);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);

        when(MultitenantUtils.getTenantAwareUsername(USERNAME)).thenReturn(USERNAME);
        when(PasswordExpiryPolicyUtils.getResidentIdpProperty(TENANT_DOMAIN,
                PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn("20");
        when(IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getClaimManager()).thenReturn(claimManager);
        when(claimManager.getClaim(PasswordExpiryValidationConstants.LAST_CREDENTIAL_CHANGED_TIMESTAMP_CLAIM_NON_IDENTITY)).thenReturn(claim);

        String time = String.valueOf(System.currentTimeMillis());
        Map<String, String> claimValueMap = new HashMap<>();

        claimValueMap.put(PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM,null);
        claimValueMap.put(PasswordExpiryValidationConstants.LAST_CREDENTIAL_CHANGED_TIMESTAMP_CLAIM_NON_IDENTITY, time);

        String[] claimURIs = new String[]{PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM};
        String[] claimURIs1 = new String[]{PasswordExpiryValidationConstants.LAST_CREDENTIAL_CHANGED_TIMESTAMP_CLAIM_NON_IDENTITY};
        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs, null)).thenReturn(claimValueMap);
        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs1, null)).thenReturn(claimValueMap);
        try {
            passwordExpiryValidationHandler.handleEvent(event);
        } catch (IdentityEventException e) {
            Assert.fail("Identity Event Exception!");
        }
    }

    @Test
    public void testHandleEventForUserClaimsNull() throws UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(PasswordExpiryPolicyUtils.class);
        mockStatic(UserStoreManager.class);
        mockStatic(MultitenantUtils.class);
        Event event = new Event("PASSWORD_EXPIRY_VALIDATION");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, USERNAME);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);

        when(MultitenantUtils.getTenantAwareUsername(USERNAME)).thenReturn(USERNAME);
        when(PasswordExpiryPolicyUtils.getResidentIdpProperty(TENANT_DOMAIN,
                PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn("20");
        when(IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getClaimManager()).thenReturn(claimManager);
        when(claimManager.getClaim(PasswordExpiryValidationConstants.LAST_CREDENTIAL_CHANGED_TIMESTAMP_CLAIM_NON_IDENTITY)).thenReturn(claim);

        Map<String, String> claimValueMap = new HashMap<>();
        claimValueMap.put(PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM,null);
        claimValueMap.put(PasswordExpiryValidationConstants.LAST_CREDENTIAL_CHANGED_TIMESTAMP_CLAIM_NON_IDENTITY,null);
        String[] claimURIs = new String[]{PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM};
        String[] claimURIs1 = new String[]{PasswordExpiryValidationConstants.LAST_CREDENTIAL_CHANGED_TIMESTAMP_CLAIM_NON_IDENTITY};

        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs, null)).thenReturn(claimValueMap);
        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs1, null)).thenReturn(claimValueMap);
        try {
            passwordExpiryValidationHandler.handleEvent(event);
            Assert.fail("This should throw identity event exception");
        } catch (IdentityEventException e) {
            Assert.assertEquals(PasswordExpiryValidationConstants.PASSWORD_EXPIRED_ERROR_MESSAGE, e.getMessage());
        }
    }

    @Test
    public void testHandleEventForPasswordExpiredUserWithNonIdentityClaim() throws UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(PasswordExpiryPolicyUtils.class);
        mockStatic(UserStoreManager.class);
        mockStatic(MultitenantUtils.class);
        Event event = new Event("PASSWORD_EXPIRY_VALIDATION");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, USERNAME);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);
        when(MultitenantUtils.getTenantAwareUsername(USERNAME)).thenReturn(USERNAME);
        when(PasswordExpiryPolicyUtils.getResidentIdpProperty(TENANT_DOMAIN,
                PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn("20");
        when(IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        when(IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getClaimManager()).thenReturn(claimManager);
        when(claimManager.getClaim(PasswordExpiryValidationConstants.LAST_CREDENTIAL_CHANGED_TIMESTAMP_CLAIM_NON_IDENTITY)).thenReturn(claim);

        Map<String, String> claimValueMap = new HashMap<>();

        String time = "1672559229000";
        claimValueMap.put(PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM,null);
        claimValueMap.put(PasswordExpiryValidationConstants.LAST_CREDENTIAL_CHANGED_TIMESTAMP_CLAIM_NON_IDENTITY,time);
        String[] claimURIs = new String[]{PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM};
        String[] claimURIs1 = new String[]{PasswordExpiryValidationConstants.LAST_CREDENTIAL_CHANGED_TIMESTAMP_CLAIM_NON_IDENTITY};
        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs, null)).thenReturn(claimValueMap);
        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs1, null)).thenReturn(claimValueMap);
        try {
            passwordExpiryValidationHandler.handleEvent(event);
            Assert.fail("This should throw identity event exception");
        } catch (IdentityEventException e) {
            Assert.assertEquals(PasswordExpiryValidationConstants.PASSWORD_EXPIRED_ERROR_MESSAGE, e.getMessage());
        }
    }

    @Test
    public void testHandleEventForUserNotConfiguredPasswordExpiredInDays()
            throws org.wso2.carbon.user.core.UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(PasswordExpiryPolicyUtils.class);
        mockStatic(UserStoreManager.class);
        mockStatic(MultitenantUtils.class);
        Event event = new Event("PASSWORD_EXPIRY_VALIDATION");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, USERNAME);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);
        when(MultitenantUtils.getTenantAwareUsername(USERNAME)).thenReturn(USERNAME);
        when(PasswordExpiryPolicyUtils.getResidentIdpProperty(TENANT_DOMAIN,
                PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn(null);
        when(PasswordExpiryPolicyUtils.getIdentityEventProperty(TENANT_DOMAIN,
                PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn(null);

        Map<String, String> claimValueMap = new HashMap<>();
        String timestamp = String.valueOf(System.currentTimeMillis());
        claimValueMap.put(PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM,timestamp);
        String[] claimURIs = new String[]{PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM};

        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs, null)).thenReturn(claimValueMap);
        try {
            passwordExpiryValidationHandler.handleEvent(event);
        } catch (IdentityEventException e) {
            Assert.fail("Identity Event Exception!");
        }
    }

    @Test
    public void testGetName(){
        Assert.assertEquals(passwordExpiryValidationHandler.getName(),
                PasswordExpiryValidationConstants.PASSWORD_EXPIRY_VALIDATION_EVENT_HANDLER_NAME);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
    return new PowerMockObjectFactory();
    }
}
