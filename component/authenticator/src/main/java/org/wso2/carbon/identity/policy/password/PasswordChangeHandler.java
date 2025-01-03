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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.PostAuthenticationFailedException;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

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
        if (PasswordPolicyConstants.PASSWORD_GRANT_POST_AUTHENTICATION_EVENT.equals(eventName)) {
            String tenantDomain = (String) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            boolean authenticationStatus = (boolean) event.getEventProperties().get(
                    PasswordPolicyConstants.AUTHENTICATION_STATUS);

            if (authenticationStatus) { // only validate password expiry if user is authenticated
                if (log.isDebugEnabled()) {
                    log.debug("Checking password validity of " + username);
                }
                try {
                    if (isPasswordExpired(tenantDomain, tenantAwareUsername)) {
                        if (log.isDebugEnabled()) {
                            log.debug("User: " + username + " password is expired.");
                        }
                        throw new IdentityEventException(PasswordPolicyConstants.PASSWORD_EXPIRED_ERROR_MESSAGE);
                    }
                } catch (org.wso2.carbon.user.api.UserStoreException e) {
                    throw new IdentityEventException("UserStore Exception occurred while password expiry validation", e)
                            ;
                } catch (AuthenticationFailedException e) {
                    throw new IdentityEventException("Authentication Exception occurred while password expiry " +
                            "validation", e)
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
     * @return true if password is expired or password last update time is null
     * @throws org.wso2.carbon.user.api.UserStoreException
     * @throws AuthenticationFailedException
     */
    private boolean isPasswordExpired(String tenantDomain, String tenantAwareUsername) throws AuthenticationFailedException,
            org.wso2.carbon.user.api.UserStoreException {

        try {
            return org.wso2.carbon.identity.password.expiry.util.PasswordPolicyUtils.isPasswordExpired(tenantDomain,
                    tenantAwareUsername);
        } catch (PostAuthenticationFailedException e) {
            throw new AuthenticationFailedException("Error occurred while checking if the password had expired", e);
        }
    }

}
