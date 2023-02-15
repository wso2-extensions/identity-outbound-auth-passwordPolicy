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

import java.text.ParseException;
import java.util.Calendar;
import java.util.Map;

/**
 * Handler to check whether the password is expired. This will throw an identity event exception if password is expired.
 */
public class PasswordExpiryValidationHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(PasswordExpiryValidationHandler.class);

    /**
     * Validate password expiry.
     * @param event
     * @throws IdentityEventException Password has expire exception if password expired
     */
    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        String username = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_NAME);
        String tenantDomain = (String) event.getEventProperties()
                .get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
        UserStoreManager userStoreManager = (UserStoreManager) event.getEventProperties()
                .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);

        try {
            if (isPasswordExpired(tenantDomain, tenantAwareUsername, userStoreManager)) {
                if (log.isDebugEnabled()) {
                    log.debug("User: " + username + " password is expired.");
                }
                throw new IdentityEventException(PasswordExpiryValidationConstants.PASSWORD_EXPIRED_ERROR_MESSAGE);
            }
        } catch (UserStoreException e) {
            throw new IdentityEventException("UserStore Exception occurred while password expiry validation", e);
        }
    }
     /**
     * Check whether the password is expired or not.
     * @param tenantDomain user tenant domain
     * @param tenantAwareUsername The tenant aware username of the user trying to authenticate
     * @param userStoreManager
     * @return true if password is expired or password last update time is null
     * @throws UserStoreException
     * @throws ParseException
     */
    private boolean isPasswordExpired(String tenantDomain, String tenantAwareUsername,
                                      UserStoreManager userStoreManager) throws UserStoreException {

        String passwordLastChangedTime = getPasswordLastChangeTime(tenantDomain, tenantAwareUsername, userStoreManager);
        int passwordExpiryInDays =  getPasswordExpiryInDaysConfig(tenantDomain);

        long passwordChangedTime = 0;
        if (passwordLastChangedTime != null) {
            passwordChangedTime = Long.parseLong(passwordLastChangedTime);
        }
        int daysDifference = 0;
        long currentTimeMillis = System.currentTimeMillis();
        if (passwordChangedTime > 0) { // obtain the day difference from last password changed time to current time
            Calendar currentTime = Calendar.getInstance();
            currentTime.add(Calendar.DATE, (int) currentTime.getTimeInMillis());
            daysDifference = (int) ((currentTimeMillis - passwordChangedTime) / (1000 * 60 * 60 * 24));
        }
        if (log.isDebugEnabled()) {
            log.debug("User: " + tenantAwareUsername + " password is updated before " + daysDifference + " Days");
        }
        return (daysDifference > passwordExpiryInDays || passwordLastChangedTime == null);
    }

    /**
     * get users last password change time from the claims.
     *
     * @param tenantDomain user tenant domain
     * @param tenantAwareUsername The tenant aware username of the user trying to authenticate
     * @param userStoreManager
     * @return  last password change time
     * @throws UserStoreException
     * @throws ParseException
     */
    private String getPasswordLastChangeTime(String tenantDomain, String tenantAwareUsername,
                                             UserStoreManager userStoreManager) throws UserStoreException {

        String claimURI = PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM;
        String passwordLastChangedTime = getClaimValue(userStoreManager, claimURI, tenantAwareUsername);

        if (passwordLastChangedTime == null) {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
            ClaimManager claimManager = userRealm.getClaimManager();
            claimURI = PasswordExpiryValidationConstants.LAST_CREDENTIAL_CHANGED_TIMESTAMP_CLAIM_NON_IDENTITY;
            if (claimManager.getClaim(claimURI) != null) {
                passwordLastChangedTime = getClaimValue(userStoreManager, claimURI, tenantAwareUsername);
            }
        }

        return passwordLastChangedTime;
    }

    /**
     * get password expiry in days configured value.
     * @param tenantDomain user tenant domain
     * @return password expiry days as a int
     */
    private int getPasswordExpiryInDaysConfig(String tenantDomain) {

        String passwordExpiryInDaysConfiguredValue = PasswordExpiryPolicyUtils.getResidentIdpProperty(tenantDomain,
                PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS);
        if (passwordExpiryInDaysConfiguredValue == null || StringUtils.isEmpty(passwordExpiryInDaysConfiguredValue)) {
            String passwordExpiryInDaysIdentityEventProperty = PasswordExpiryPolicyUtils.getIdentityEventProperty(
                    tenantDomain, PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS);
            if (passwordExpiryInDaysIdentityEventProperty != null) {
                passwordExpiryInDaysConfiguredValue = passwordExpiryInDaysIdentityEventProperty;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Password expiry in days configuration can not be fetched or null. Hence using the " +
                            "default: 30 days");
                }
                passwordExpiryInDaysConfiguredValue =
                        PasswordExpiryValidationConstants.PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE;
            }

        }
        return Integer.parseInt(passwordExpiryInDaysConfiguredValue);
    }

    /**
     * Get value of provided claim uri.
     *
     * @param userStoreManager
     * @param tenantAwareUsername The tenant aware username of the user trying to authenticate
     * @return claim value
     * @throws UserStoreException
     */
    private String getClaimValue(UserStoreManager userStoreManager, String claimURI,
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
        return PasswordExpiryValidationConstants.PASSWORD_EXPIRY_VALIDATION_EVENT_HANDLER_NAME;
    }
}
