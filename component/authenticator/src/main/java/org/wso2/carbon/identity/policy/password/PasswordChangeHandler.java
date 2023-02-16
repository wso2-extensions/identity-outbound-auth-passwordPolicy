/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.policy.password;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.user.api.ClaimManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.text.ParseException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Event Handler class which handles password update by user, password update by admin and add user events.
 * <p>
 * This updates the http://wso2.org/claims/lastPasswordChangedTimestamp claim upon the password change.
 * This also publishes the password change event to IS Analytics.
 */
public class PasswordChangeHandler extends AbstractEventHandler implements IdentityConnectorConfig {
    private static final Log log = LogFactory.getLog(PasswordChangeHandler.class);


    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        String eventName = event.getEventName();
        // Fetching event properties
        String username = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_NAME);
        UserStoreManager userStoreManager = (UserStoreManager) event.getEventProperties()
                .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);

        //password grant handler - password expiry validation
        if (eventName.equals(PasswordPolicyConstants.PASSWORD_GRANT_POST_AUTHENTICATION_EVENT)) {
            String tenantDomain = (String) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            boolean authenticationStatus = (boolean) event.getEventProperties().get(
                    PasswordPolicyConstants.AUTHENTICATION_STATUS);

            if (authenticationStatus) { // only validate password expiry if user is authenticated
                if (log.isDebugEnabled()) {
                    log.info("Checking password validity of " + username);
                }
                try {
                    if (isPasswordExpired(tenantDomain, tenantAwareUsername, userStoreManager)) {
                        if (log.isDebugEnabled()) {
                            log.debug("User: " + username + " password is expired.");
                        }
                        throw new IdentityEventException(PasswordPolicyConstants.PASSWORD_EXPIRED_ERROR_MESSAGE);
                    }
                } catch (org.wso2.carbon.user.api.UserStoreException e) {
                    throw new IdentityEventException("UserStore Exception occurred while password expiry validation", e)
                            ;
                }
            }
            return;
        }

        long timestamp = System.currentTimeMillis();

        // Updating the last password changed claim
        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM, Long.toString(timestamp));
        try {
            userStoreManager.setUserClaimValues(username, claimMap, null);
            if (log.isDebugEnabled()) {
                log.debug("The claim uri "
                        + PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM + " of "
                        + username + " updated with the current timestamp");
            }
        } catch (UserStoreException e) {
            throw new IdentityEventException("An Error Occurred in updating the password. Please contact admin.", e);
        }
    }

    @Override
    public String getName() {
        return PasswordPolicyConstants.PASSWORD_CHANGE_EVENT_HANDLER_NAME;
    }

    @Override
    public String getFriendlyName() {
        return PasswordPolicyConstants.CONNECTOR_CONFIG_FRIENDLY_NAME;
    }

    @Override
    public String getCategory() {
        return PasswordPolicyConstants.CONNECTOR_CONFIG_CATEGORY;
    }

    @Override
    public String getSubCategory() {
        return PasswordPolicyConstants.CONNECTOR_CONFIG_SUB_CATEGORY;
    }

    @Override
    public int getOrder() {
        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS,
                PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DISPLAYED_NAME);
        nameMapping.put(PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS,
                PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS_DISPLAYED_NAME);
        nameMapping.put(PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_REMINDER_TIME_IN_DAYS,
                PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_REMINDER_TIME_IN_DAYS_DISPLAYED_NAME);
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS,
                PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DESCRIPTION);
        nameMapping.put(PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS,
                PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS_DESCRIPTION);
        nameMapping.put(PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_REMINDER_TIME_IN_DAYS,
                PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_REMINDER_TIME_IN_DAYS_DESCRIPTION);
        return nameMapping;
    }

    @Override
    public String[] getPropertyNames() {
        return PasswordPolicyUtils.getPasswordExpiryPropertyNames();
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {
        Properties properties = new Properties();

        // Setting the password expiry in days default value
        String passwordExpiryInDays = PasswordPolicyUtils.getIdentityEventProperty(tenantDomain,
                PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS);
        if (passwordExpiryInDays == null) {     // To avoid null pointer exceptions if user had not added module config
            passwordExpiryInDays =
                    Integer.toString(PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE);
            if (log.isDebugEnabled()) {
                log.debug("Using the default property value: " +
                        PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE + " for the " +
                        "configuration: " + PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS
                        + " because no module configuration is present.");
            }
        }
        properties.setProperty(PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS, passwordExpiryInDays);

        // Setting the enable email notifications default value
        String enableDataPublishing = PasswordPolicyUtils.getIdentityEventProperty(tenantDomain,
                PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS);
        if (enableDataPublishing == null) {     // To avoid null pointer exceptions if user had not added module config
            enableDataPublishing =
                    Boolean.toString(PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS_DEFAULT_VALUE);
            if (log.isDebugEnabled()) {
                log.debug("Using the default property value: " +
                        PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS_DEFAULT_VALUE + " for the "
                        + "configuration: " + PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS
                        + " because no module configuration is present.");
            }
        }
        properties.setProperty(PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS,
                enableDataPublishing);

        // Setting the prior notice in days default value
        String priorReminderTimeInDays = PasswordPolicyUtils.getIdentityEventProperty(tenantDomain,
                PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_REMINDER_TIME_IN_DAYS);
        if (priorReminderTimeInDays == null) {   // To avoid null pointer exceptions if user had not added module config
            priorReminderTimeInDays =
                    Integer.toString(PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS_DEFAULT_VALUE);
            if (log.isDebugEnabled()) {
                log.debug("Using the default property value: " +
                        PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS_DEFAULT_VALUE + " for the "
                        + "configuration: " + PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_REMINDER_TIME_IN_DAYS
                        + " because no module configuration is present.");
            }
        }
        properties.setProperty(PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_REMINDER_TIME_IN_DAYS,
                priorReminderTimeInDays);

        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain)
            throws IdentityGovernanceException {
        return null;
    }

    /**
     * Check whether the password is expired or not.
     * @param tenantDomain user tenant domain
     * @param tenantAwareUsername The tenant aware username of the user trying to authenticate
     * @param userStoreManager
     * @return true if password is expired or password last update time is null
     * @throws org.wso2.carbon.user.api.UserStoreException
     * @throws ParseException
     */
    private boolean isPasswordExpired(String tenantDomain, String tenantAwareUsername,
                                      UserStoreManager userStoreManager) throws
            org.wso2.carbon.user.api.UserStoreException {

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
            daysDifference = (int) ((currentTimeMillis - passwordChangedTime) / (1000 * 60 * 60 * 24)); // convert to
            // days
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
     * @throws org.wso2.carbon.user.api.UserStoreException
     * @throws ParseException
     */
    private String getPasswordLastChangeTime(String tenantDomain, String tenantAwareUsername,
                                             UserStoreManager userStoreManager) throws
            org.wso2.carbon.user.api.UserStoreException {

        String claimURI = PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM;
        String passwordLastChangedTime = getClaimValue(userStoreManager, claimURI, tenantAwareUsername);

        if (passwordLastChangedTime == null) {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
            ClaimManager claimManager = userRealm.getClaimManager();
            claimURI = PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM_NON_IDENTITY;
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

        String passwordExpiryInDaysConfiguredValue = null;
        try {
            passwordExpiryInDaysConfiguredValue = PasswordPolicyUtils.getResidentIdpProperty(tenantDomain,
                    PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS);
        } catch (AuthenticationFailedException e) {
            log.warn("Authentication Exception occurred while reading password expiry residentIdp property");
        }

        if (passwordExpiryInDaysConfiguredValue == null || StringUtils.isEmpty(passwordExpiryInDaysConfiguredValue)) {
            String passwordExpiryInDaysIdentityEventProperty = this.configs.getModuleProperties().getProperty(
                    PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS);
            if (StringUtils.isNotEmpty(passwordExpiryInDaysIdentityEventProperty)) {
                passwordExpiryInDaysConfiguredValue = passwordExpiryInDaysIdentityEventProperty;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Password expiry in days configuration can not be fetched or null. Hence using the " +
                            "default: " + PasswordPolicyConstants.PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE + " days");
                }
                passwordExpiryInDaysConfiguredValue =
                        PasswordPolicyConstants.PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE;
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
     * @throws org.wso2.carbon.user.api.UserStoreException
     */
    private String getClaimValue(UserStoreManager userStoreManager, String claimURI,
                                 String tenantAwareUsername) throws org.wso2.carbon.user.api.UserStoreException {

        String[] claimURIs = new String[]{claimURI};
        Map<String, String> claimValueMap =
                userStoreManager.getUserClaimValues(tenantAwareUsername, claimURIs, null);
        if (claimValueMap != null && claimValueMap.get(claimURI) != null) {
            return claimValueMap.get(claimURI);
        }
        return null;
    }

}
