/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ApplicationBasicInfo;
import org.wso2.carbon.identity.application.common.model.AuthenticationStep;
import org.wso2.carbon.identity.application.common.model.LocalAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.policy.password.internal.PasswordResetEnforcerDataHolder;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
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
        // Fetching event properties
        String username = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_NAME);
        String tenantDomain = (String) event.getEventProperties()
                .get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);

        if (isAuthenticatorApplied(username, tenantDomain)) {
            UserStoreManager userStoreManager = (UserStoreManager) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
            String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
            long timestamp = System.currentTimeMillis();

            // Updating the last password changed claim
            Map<String, String> claimMap = new HashMap<>();
            claimMap.put(PasswordChangeEnforceConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM,
                    Long.toString(timestamp));
            try {
                userStoreManager.setUserClaimValues(username, claimMap, null);
                if (log.isDebugEnabled()) {
                    log.debug("The claim uri "
                            + PasswordChangeEnforceConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM + " of "
                            + username + " updated with the current timestamp");
                }
            } catch (UserStoreException e) {
                log.error("Failed to update claim value for "
                        + PasswordChangeEnforceConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM
                        + " claim due to " + e.getMessage(), e);
            }

            // Getting the event listener config in identity.xml
            IdentityEventListenerConfig eventListenerConfig = IdentityUtil.readEventListenerProperty(
                    PasswordChangeEnforceConstants.IDENTITY_MESSAGE_HANDLER_TYPE,
                    this.getClass().getName()
            );

            // Checking whether data publishing is enabled
            boolean isPublishingToISAnalyticsEnabled = false;
            if (eventListenerConfig != null) {
                isPublishingToISAnalyticsEnabled = Boolean.parseBoolean((String) eventListenerConfig.getProperties()
                        .get(PasswordChangeEnforceConstants.DATA_PUBLISHING_ENABLED_PROPERTY_NAME));
            }

            if (isPublishingToISAnalyticsEnabled) {
                publishToISAnalytics(username, userStoreDomain, tenantDomain, userStoreManager, timestamp);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Password changed claim not updated and data not published to IS analytics " +
                        "for user " + username + "@" + tenantDomain + " " +
                        "since the authenticator was not added to the an application in this tenant: " +
                        event.getEventProperties().get(IdentityEventConstants.EventProperty.TENANT_ID));
            }
        }
    }

    /**
     * Check if the password expiry authenticator had been applied to at least one of the applications
     * that the user has access to
     *
     * @param username     The username of the user
     * @param tenantDomain The tenant domain to which the user belongs to
     * @return True if there is at least one application managed by this user to which the authenticator was applied
     */
    private boolean isAuthenticatorApplied(String username, String tenantDomain) {
        boolean isAuthenticatorApplied = false;
        try {
            ApplicationManagementService applicationManagementService = PasswordResetEnforcerDataHolder
                    .getInstance().getApplicationManagementService();

            // Looping the applications
            ApplicationBasicInfo[] allApplicationBasicInfos = applicationManagementService
                    .getAllApplicationBasicInfo(tenantDomain, username);
            for (ApplicationBasicInfo applicationBasicInfo : allApplicationBasicInfos) {
                String applicationName = applicationBasicInfo.getApplicationName();
                ServiceProvider serviceProvider = applicationManagementService
                        .getApplicationExcludingFileBasedSPs(applicationName, tenantDomain);
                AuthenticationStep[] authenticationSteps = serviceProvider
                        .getLocalAndOutBoundAuthenticationConfig().getAuthenticationSteps();

                // Looping the authentication steps
                for (AuthenticationStep authenticationStep : authenticationSteps) {
                    LocalAuthenticatorConfig[] configs = authenticationStep.getLocalAuthenticatorConfigs();
                    // Looping the authenticators in the step
                    for (LocalAuthenticatorConfig config : configs) {
                        if (Objects.equals(config.getName(), PasswordChangeEnforceConstants.AUTHENTICATOR_NAME)) {
                            isAuthenticatorApplied = true;
                            break;
                        }
                    }
                    if (isAuthenticatorApplied) {
                        break;
                    }
                }
                if (isAuthenticatorApplied) {
                    break;
                }
            }
        } catch (IdentityApplicationManagementException e) {
            log.warn("Considering the credentials of the user logging in as expirable since " +
                    "retrieving of service provider data failed due to " + e.getMessage(), e);
        }
        return isAuthenticatorApplied;
    }

    /**
     * Publish the password change event to IS Analytics
     *
     * @param username         The username of the user
     * @param userStoreDomain  The user store domain of the user
     * @param tenantDomain     The tenant domain of the user
     * @param userStoreManager The user store manager of the user
     * @param timestamp        The password changed timestamp
     */
    private void publishToISAnalytics(String username, String userStoreDomain, String tenantDomain,
                                      UserStoreManager userStoreManager, long timestamp) {
        // Fetching the email
        String email = null;
        try {
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            email = userStoreManager.getUserClaimValue(tenantAwareUsername,
                    PasswordChangeEnforceConstants.EMAIL_ADDRESS_CLAIM, null);
        } catch (UserStoreException e) {
            log.error("Failed to fetch the email due to " + e.getMessage(), e);
        }

        EventStreamService service = PasswordResetEnforcerDataHolder.getInstance().getEventStreamService();

        // Creating the event to be sent
        org.wso2.carbon.databridge.commons.Event dataBridgeEvent = new org.wso2.carbon.databridge.commons.Event();
        dataBridgeEvent.setTimeStamp(timestamp);
        dataBridgeEvent.setStreamId(PasswordChangeEnforceConstants.PASSWORD_CHANGE_STREAM_NAME);

        // Creating the payload data
        Object[] payloadData = new Object[5];
        payloadData[0] = tenantDomain;
        payloadData[1] = userStoreDomain;
        payloadData[2] = username;
        payloadData[3] = email;
        payloadData[4] = timestamp;
        dataBridgeEvent.setPayloadData(payloadData);

        service.publish(dataBridgeEvent);
        if (log.isDebugEnabled()) {
            log.debug("Published " + dataBridgeEvent.toString() + " to IS Analytics");
        }
    }

    @Override
    public String getName() {
        return PasswordChangeEnforceConstants.PASSWORD_CHANGE_EVENT_HANDLER_NAME;
    }

    @Override
    public String getFriendlyName() {
        return PasswordChangeEnforceConstants.CONNECTOR_CONFIG_FRIENDLY_NAME;
    }

    @Override
    public String getCategory() {
        return PasswordChangeEnforceConstants.CONNECTOR_CONFIG_CATEGORY;
    }

    @Override
    public String getSubCategory() {
        return PasswordChangeEnforceConstants.CONNECTOR_CONFIG_SUB_CATEGORY;
    }

    @Override
    public int getOrder() {
        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS,
                PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DISPLAYED_NAME);
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS,
                PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DESCRIPTION);
        return nameMapping;
    }

    @Override
    public String[] getPropertyNames() {
        return PasswordChangeUtils.getPasswordExpiryPropertyNames();
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {
        Properties properties = new Properties();
        properties.put(PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS,
                configs.getModuleProperties()
                        .getProperty(PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS));
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain)
            throws IdentityGovernanceException {
        return null;
    }
}
