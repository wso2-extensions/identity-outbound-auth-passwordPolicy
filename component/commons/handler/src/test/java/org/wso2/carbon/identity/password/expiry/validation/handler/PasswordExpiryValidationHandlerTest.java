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
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
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
    @Mock
    private UserStoreManager userStoreManager;
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
    when(PasswordExpiryPolicyUtils.getResidentIdpProperty(TENANT_DOMAIN, PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn("20");

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
        when(PasswordExpiryPolicyUtils.getResidentIdpProperty(TENANT_DOMAIN, PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn("20");

        Map<String, String> claimValueMap = new HashMap<>();
        claimValueMap.put(PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM,"1672559229000");
        String[] claimURIs = new String[]{PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM};

        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs, null)).thenReturn(claimValueMap);
        try {
            passwordExpiryValidationHandler.handleEvent(event);
            Assert.fail("This should throw identity event exception");
        } catch (IdentityEventException e) {
            Assert.assertEquals("Password expired for user with username: admin",e.getMessage());
        }
    }

    @Test
    public void testHandleEventForPasswordNonExpiredUserWithCreatedClaim() throws UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(PasswordExpiryPolicyUtils.class);
        mockStatic(UserStoreManager.class);
        mockStatic(MultitenantUtils.class);
        Event event = new Event("PASSWORD_EXPIRY_VALIDATION");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, USERNAME);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);
        when(MultitenantUtils.getTenantAwareUsername(USERNAME)).thenReturn(USERNAME);
        when(PasswordExpiryPolicyUtils.getResidentIdpProperty(TENANT_DOMAIN, PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn("20");

        Map<String, String> claimValueMap = new HashMap<>();
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
        Date date = new Date();

        String createdTime = formatter.format(date) + "T00:00:00.000Z";
        claimValueMap.put(PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM,null);
        claimValueMap.put(PasswordExpiryValidationConstants.CREATED_CLAIM,createdTime);
        String[] claimURIs = new String[]{PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM};
        String[] claimURIs1 = new String[]{PasswordExpiryValidationConstants.CREATED_CLAIM};
        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs, null)).thenReturn(claimValueMap);
        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs1, null)).thenReturn(claimValueMap);
        try {
            passwordExpiryValidationHandler.handleEvent(event);
        } catch (IdentityEventException e) {
            Assert.fail("Identity Event Exception!");
        }
    }

    @Test
    public void testHandleEventForUserClaimsNull() throws org.wso2.carbon.user.core.UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(PasswordExpiryPolicyUtils.class);
        mockStatic(UserStoreManager.class);
        mockStatic(MultitenantUtils.class);
        Event event = new Event("PASSWORD_EXPIRY_VALIDATION");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, USERNAME);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);
        when(MultitenantUtils.getTenantAwareUsername(USERNAME)).thenReturn(USERNAME);
        when(PasswordExpiryPolicyUtils.getResidentIdpProperty(TENANT_DOMAIN, PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn("20");

        Map<String, String> claimValueMap = new HashMap<>();
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
        Date date = new Date();

        String createdTime = formatter.format(date) + "T00:00:00.000Z";
        claimValueMap.put(PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM,null);
        claimValueMap.put(PasswordExpiryValidationConstants.CREATED_CLAIM,null);
        String[] claimURIs = new String[]{PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM};
        String[] claimURIs1 = new String[]{PasswordExpiryValidationConstants.CREATED_CLAIM};
        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs, null)).thenReturn(claimValueMap);
        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs1, null)).thenReturn(claimValueMap);
        try {
            passwordExpiryValidationHandler.handleEvent(event);
            Assert.fail("This should throw identity event exception");
        } catch (IdentityEventException e) {
            Assert.assertEquals("Password expired for user with username: admin",e.getMessage());
        }
    }

    @Test
    public void testHandleEventForPasswordExpiredUserWithCreatedClaim() throws UserStoreException {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(PasswordExpiryPolicyUtils.class);
        mockStatic(UserStoreManager.class);
        mockStatic(MultitenantUtils.class);
        Event event = new Event("PASSWORD_EXPIRY_VALIDATION");
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_NAME, USERNAME);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        event.getEventProperties().put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);
        when(MultitenantUtils.getTenantAwareUsername(USERNAME)).thenReturn(USERNAME);
        when(PasswordExpiryPolicyUtils.getResidentIdpProperty(TENANT_DOMAIN, PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn("20");

        Map<String, String> claimValueMap = new HashMap<>();

        String createdTime = "2023-01-04T06:00:28.542Z";
        claimValueMap.put(PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM,null);
        claimValueMap.put(PasswordExpiryValidationConstants.CREATED_CLAIM,createdTime);
        String[] claimURIs = new String[]{PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM};
        String[] claimURIs1 = new String[]{PasswordExpiryValidationConstants.CREATED_CLAIM};
        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs, null)).thenReturn(claimValueMap);
        when(userStoreManager.getUserClaimValues(USERNAME, claimURIs1, null)).thenReturn(claimValueMap);
        try {
            passwordExpiryValidationHandler.handleEvent(event);
            Assert.fail("This should throw identity event exception");
        } catch (IdentityEventException e) {
            Assert.assertEquals("Password expired for user with username: admin",e.getMessage());
        }
    }

    @Test
    public void testHandleEventForUserNotConfiguredPasswordConfiguredInDays()
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
        when(PasswordExpiryPolicyUtils.getResidentIdpProperty(TENANT_DOMAIN, PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn(null);
        when(PasswordExpiryPolicyUtils.getIdentityEventProperty(TENANT_DOMAIN, PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS)).thenReturn(null);

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
        Assert.assertEquals(passwordExpiryValidationHandler.getName(),"passwordExpiryValidation");
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
    return new PowerMockObjectFactory();
    }
}
