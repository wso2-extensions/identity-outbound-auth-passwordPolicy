package org.wso2.carbon.identity.password.expiry.validation.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.user.api.ClaimManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Calendar;
import java.util.Map;

public class PasswordExpiryValidationHandler extends AbstractEventHandler{
    private static final Log log = LogFactory.getLog(PasswordExpiryValidationHandler.class);

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        String username = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_NAME);
        String tenantDomain = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
        int tenantId = (int) event.getEventProperties().get(IdentityEventConstants.EventProperty.TENANT_ID);
        UserStoreManager userStoreManager = (UserStoreManager) event.getEventProperties()
                .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);

        try {
            if(isPasswordExpired(tenantDomain, tenantAwareUsername, userStoreManager, tenantId)){
                if(log.isDebugEnabled()){
                    log.debug("User: "+username+" password is expired.");
                }
                throw new IdentityEventException("Password Expired");
            }
        } catch (UserStoreException e) {
            throw new IdentityEventException("UserStore Exception occurred while password expiry validation", e);
        } catch (Exception e){
            throw new IdentityEventException("Exception occurred while password expiry validation", e);
        }
    }

    private boolean isPasswordExpired(String tenantDomain, String tenantAwareUsername, UserStoreManager userStoreManager, int tenantId)
            throws UserStoreException {

        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm = realmService.getTenantUserRealm(tenantId);

        String passwordLastChangedTime = getLastPasswordUpdateTime(userStoreManager,PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM,tenantAwareUsername);
        if (passwordLastChangedTime == null) {
            ClaimManager claimManager = userRealm.getClaimManager();
            if (claimManager.getClaim(PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM_NON_IDENTITY) != null) {
                passwordLastChangedTime =
                        getLastPasswordUpdateTime(userStoreManager, PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM_NON_IDENTITY, tenantAwareUsername);
            }
        }

        String passwordExpiryInDaysConfiguredValue = PasswordExpiryPolicyUtils.getResidentIdpProperty(tenantDomain,PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS);
        if(passwordExpiryInDaysConfiguredValue == null || StringUtils.isEmpty(passwordExpiryInDaysConfiguredValue)){
            String passwordExpiryInDaysIdentityEventProperty = PasswordExpiryPolicyUtils.getIdentityEventProperty(tenantDomain,PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS);
            passwordExpiryInDaysConfiguredValue =
                    passwordExpiryInDaysIdentityEventProperty != null ? passwordExpiryInDaysIdentityEventProperty:
                            PasswordExpiryValidationConstants.PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE;
        }
        int passwordExpiryInDays =  Integer.parseInt(passwordExpiryInDaysConfiguredValue);

        long passwordChangedTime = 0;
        if(passwordLastChangedTime != null) {
            passwordChangedTime = Long.parseLong(passwordLastChangedTime);
        }
        int daysDifference = 0;
        long currentTimeMillis = System.currentTimeMillis();
        if (passwordChangedTime > 0) {
            Calendar currentTime = Calendar.getInstance();
            currentTime.add(Calendar.DATE, (int) currentTime.getTimeInMillis());
            daysDifference = (int) ((currentTimeMillis - passwordChangedTime) / (1000 * 60 * 60 * 24));
        }
        if(log.isDebugEnabled()){
            log.debug("User: "+tenantAwareUsername+" password is updated before "+daysDifference+" Days");
        }
        return daysDifference > passwordExpiryInDays;
    }

    private String getLastPasswordUpdateTime(UserStoreManager userStoreManager, String claimURI,
                                             String tenantAwareUsername) throws UserStoreException {

        String[] claimURIs = new String[]{claimURI};
        Map<String, String> claimValueMap =
                userStoreManager.getUserClaimValues(tenantAwareUsername, claimURIs, null);
        if (claimValueMap != null && claimValueMap.get(claimURI) != null) {
            return claimValueMap.get(claimURI);
        }
        return null;
    }

    @Override
    public String getName() {
        return "passwordExpiryValidation";
    }
}
