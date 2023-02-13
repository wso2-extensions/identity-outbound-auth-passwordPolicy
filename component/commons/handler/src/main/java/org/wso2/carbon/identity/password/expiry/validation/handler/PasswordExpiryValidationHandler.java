/*
 * Copyright (c) 2010-2022, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
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
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Map;
import java.util.TimeZone;

/**
 * Handler to check whether the password is expired. This will throw an identity event exception if password is expired.
 */
public class PasswordExpiryValidationHandler extends AbstractEventHandler {
    private static final Log log = LogFactory.getLog(PasswordExpiryValidationHandler.class);

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
                throw new IdentityEventException("Password expired for user with username: " + tenantAwareUsername);
            }
        } catch (UserStoreException e) {
            throw new IdentityEventException("UserStore Exception occurred while password expiry validation", e);
        } catch (ParseException e) {
            throw new IdentityEventException("Parse Exception occurred while password expiry validation", e);
        }
    }
     /**
     * Check whether the password is expired or not.
     * @param tenantDomain
     * @param tenantAwareUsername
     * @param userStoreManager
     * @return true if password is expired or password last update time is null
     * @throws UserStoreException
     * @throws ParseException
     */
    private boolean isPasswordExpired(String tenantDomain, String tenantAwareUsername,
                                      UserStoreManager userStoreManager) throws UserStoreException, ParseException {

        String passwordLastChangedTime = getClaimValue(userStoreManager,
                PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM, tenantAwareUsername);

        if (passwordLastChangedTime == null) {
            String createdClaimValue = getClaimValue(userStoreManager,
                    PasswordExpiryValidationConstants.CREATED_CLAIM, tenantAwareUsername);
            if (createdClaimValue != null) {
                if (log.isDebugEnabled()) {
                    log.debug("User: " + tenantAwareUsername + " Claim: "
                            + PasswordExpiryValidationConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM +
                            " is null.Hence considered claim:" + PasswordExpiryValidationConstants.CREATED_CLAIM);
                }
                passwordLastChangedTime = convertCreatedDateToEpochString(createdClaimValue);
            }
        }

        String passwordExpiryInDaysConfiguredValue = PasswordExpiryPolicyUtils.getResidentIdpProperty(tenantDomain,
                PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS);
        if (passwordExpiryInDaysConfiguredValue == null || StringUtils.isEmpty(passwordExpiryInDaysConfiguredValue)) {
            String passwordExpiryInDaysIdentityEventProperty = PasswordExpiryPolicyUtils.getIdentityEventProperty(
                    tenantDomain, PasswordExpiryValidationConstants.CONFIG_PASSWORD_EXPIRY_IN_DAYS);
            passwordExpiryInDaysConfiguredValue =
                    passwordExpiryInDaysIdentityEventProperty != null ? passwordExpiryInDaysIdentityEventProperty :
                            PasswordExpiryValidationConstants.PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE;
        }
        int passwordExpiryInDays =  Integer.parseInt(passwordExpiryInDaysConfiguredValue);

        long passwordChangedTime = 0;
        if (passwordLastChangedTime != null) {
            passwordChangedTime = Long.parseLong(passwordLastChangedTime);
        }
        int daysDifference = 0;
        long currentTimeMillis = System.currentTimeMillis();
        if (passwordChangedTime > 0) {
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

    /**
     * Convert created time claim to epoch string.
     *
     * @param createdDate created date claim value
     * @return converted timestamp as a string
     * @throws ParseException
     */
    private static String convertCreatedDateToEpochString(String createdDate) throws ParseException {

        SimpleDateFormat simpleDateFormat =
                new SimpleDateFormat(PasswordExpiryValidationConstants.CREATED_CLAIM_FORMAT);
        simpleDateFormat.setTimeZone(TimeZone.getTimeZone(PasswordExpiryValidationConstants.CREATED_CLAIM_TIMEZONE));

        return String.valueOf(simpleDateFormat.parse(createdDate).getTime());
    }

    @Override
    public String getName() {
        return "passwordExpiryValidation";
    }
}
