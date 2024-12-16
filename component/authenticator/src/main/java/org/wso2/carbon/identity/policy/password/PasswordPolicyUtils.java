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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.PostAuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConfigBuilder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.governance.bean.ConnectorConfig;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.event.bean.ModuleConfiguration;
import org.wso2.carbon.identity.governance.listener.IdentityStoreEventListener;
import org.wso2.carbon.identity.governance.store.UserStoreBasedIdentityDataStore;
import org.wso2.carbon.identity.policy.password.models.PasswordExpiryRuleOperatorEnum;
import org.wso2.carbon.identity.policy.password.internal.PasswordPolicyDataHolder;
import org.wso2.carbon.identity.policy.password.models.PasswordExpiryRule;
import org.wso2.carbon.identity.policy.password.models.PasswordExpiryRuleAttributeEnum;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.Group;

import java.util.*;
import java.util.stream.Collectors;

import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.jdbc.UniqueIDJDBCUserStoreManager;
import org.wso2.carbon.user.core.ldap.UniqueIDActiveDirectoryUserStoreManager;

import static org.wso2.carbon.identity.policy.password.PasswordPolicyConstants.*;

/**
 * Utilities for password change enforcing.
 */
public class PasswordPolicyUtils {
    private static final Log log = LogFactory.getLog(PasswordPolicyUtils.class);

    private PasswordPolicyUtils() {
    }

    /**
     * Get the property names required by the password expiry policy.
     *
     * @return The password expiry policy
     */
    public static String[] getPasswordExpiryPropertyNames() {
        List<String> properties = new ArrayList<>();
        properties.add(PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS);
        properties.add(PasswordPolicyConstants.CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS);
        properties.add(PasswordPolicyConstants.CONNECTOR_CONFIG_PRIOR_REMINDER_TIME_IN_DAYS);
        return properties.toArray(new String[properties.size()]);
    }

    /**
     * Get the identity property specified in identity-event.properties
     *
     * @param tenantDomain The tenant domain to which the user belongs to
     * @param propertyName The name of the property which should be fetched
     * @return The required property
     */
    public static String getIdentityEventProperty(String tenantDomain, String propertyName) {

        // Retrieving properties set in identity event properties
        String propertyValue = null;
        try {
            ModuleConfiguration moduleConfiguration = IdentityEventConfigBuilder.getInstance()
                    .getModuleConfigurations(PasswordPolicyConstants.PASSWORD_CHANGE_EVENT_HANDLER_NAME);

            if (moduleConfiguration != null) {
                propertyValue = moduleConfiguration.getModuleProperties().getProperty(propertyName);
            }
        } catch (IdentityEventException e) {
            log.warn("An error occurred while retrieving module properties");
            if (log.isDebugEnabled()) {
                log.debug("An error occurred while retrieving module properties because " + e.getMessage(), e);
            }
        }
        return propertyValue;
    }

    /**
     * Retrieve the password expiry property from resident IdP.
     *
     * @param tenantDomain tenant domain which user belongs to
     * @param propertyName name of the property to be retrieved
     * @return the value of the requested property
     * @throws AuthenticationFailedException if retrieving property from resident idp fails
     */
    public static String getResidentIdpProperty(String tenantDomain, String propertyName)
            throws AuthenticationFailedException {

        IdentityProvider residentIdP;
        try {
            residentIdP = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw new AuthenticationFailedException("Error occurred while retrieving the resident IdP for tenant: " +
                    tenantDomain, e);
        }

        if (residentIdP == null) {
            if (log.isDebugEnabled()) {
                log.debug("Resident IdP is not found for tenant: " + tenantDomain);
            }
            return null;
        }
        IdentityProviderProperty property = IdentityApplicationManagementUtil
                .getProperty(residentIdP.getIdpProperties(), propertyName);

        String propertyValue = null;
        if (property != null) {
            propertyValue = property.getValue();
        }
        return propertyValue;
    }

    /**
     * Check whether the user store is based on identity data store.
     *
     * @return true if the user store is based on identity data store.
     * @throws AuthenticationFailedException if an error occurs while initializing the UserStoreBasedIdentityDataStore.
     */
    public static boolean isUserStoreBasedIdentityDataStore() throws AuthenticationFailedException {

        try {
            String storeClassName = IdentityUtil.readEventListenerProperty(USER_OPERATION_EVENT_LISTENER_TYPE,
                            IdentityStoreEventListener.class.getName()).getProperties()
                    .get(DATA_STORE_PROPERTY_NAME).toString();
            Class clazz = Class.forName(storeClassName.trim());
            Object identityDataStore = clazz.newInstance();
            return identityDataStore instanceof UserStoreBasedIdentityDataStore;
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw new AuthenticationFailedException("Error while initializing the UserStoreBasedIdentityDataStore", e);
        }
    }

    /**
     * Check whether the user store is based on Active Directory.
     *
     * @param userStoreManager The user store manager.
     * @return true if the user store is based on Active Directory.
     */
    public static boolean isActiveDirectoryUserStore(UserStoreManager userStoreManager) {

        return userStoreManager instanceof UniqueIDJDBCUserStoreManager
                && userStoreManager.getSecondaryUserStoreManager() instanceof UniqueIDActiveDirectoryUserStoreManager;
    }

    /**
     * Converts a Windows FileTime string to Unix time in milliseconds.
     *
     * Windows FileTime is a 64-bit value representing the number of 100-nanosecond
     * intervals since January 1, 1601 (UTC).
     *
     * The conversion to Unix time (milliseconds since January 1, 1970, UTC) involves two steps:
     *
     * 1. Convert the Windows FileTime value from 100-nanosecond intervals to milliseconds:
     *    - This is done by dividing the FileTime value by 10,000 (HUNDREDS_OF_NANOSECONDS).
     *    - This converts the FileTime value from 100-nanosecond intervals to milliseconds.
     *
     * 2. Adjust for the difference in epoch start dates between Windows and Unix:
     *    - Windows epoch starts on January 1, 1601, while Unix epoch starts on January 1, 1970.
     *    - The difference between these two epochs is 11644473600000 milliseconds (WINDOWS_EPOCH_DIFF).
     *    - Subtracting this value aligns the converted milliseconds with the Unix epoch.
     *
     * The resulting value represents the number of milliseconds since the Unix epoch,
     * which is returned as a string.
     *
     * @param windowsFileTime A string representing the Windows FileTime to be converted.
     * @return A string representing the Unix time in milliseconds.
     */
    public static String convertWindowsFileTimeToUnixTime(String windowsFileTime) {

        long fileTime = Long.parseLong(windowsFileTime);
        long millisSinceEpoch = (fileTime / HUNDREDS_OF_NANOSECONDS) - WINDOWS_EPOCH_DIFF;
        return String.valueOf(millisSinceEpoch);
    }

    /**
     * Get password expiry rules.
     *
     * @param tenantDomain Tenant domain.
     * @return List of password expiry rules.
     * @throws AuthenticationFailedException If an error occurred while getting the password expiry rules.
     */
    @SuppressFBWarnings("CRLF_INJECTION_LOGS")
    public static List<PasswordExpiryRule> getPasswordExpiryRules(String tenantDomain)
            throws AuthenticationFailedException {

        List<PasswordExpiryRule> passwordExpiryRules = new ArrayList<>();
        try {
            IdentityGovernanceService governanceService =
                    PasswordPolicyDataHolder.getInstance().getIdentityGovernanceService();
            ConnectorConfig connectorConfig =
                    governanceService.getConnectorWithConfigs(tenantDomain, CONNECTOR_CONFIG_NAME);
            if (connectorConfig == null) {
                return passwordExpiryRules;
            }
            Property[] properties = connectorConfig.getProperties();
            if (properties == null) {
                return passwordExpiryRules;
            }

            for (Property property : properties) {
                if (StringUtils.startsWith(property.getName(), PASSWORD_EXPIRY_RULES_PREFIX) &&
                        StringUtils.isNotEmpty(property.getValue())) {
                    try {
                        PasswordExpiryRule passwordExpiryRule = new PasswordExpiryRule(property.getValue());
                        passwordExpiryRules.add(passwordExpiryRule);
                    } catch (Exception e) {
                        // Log and skip the rule if an error occurred while parsing the rule, without failing the
                        // authentication flow.
                        if (log.isDebugEnabled()) {
                            log.debug(String.format("Error parsing password expiry rule: %s. Rule will be skipped.",
                                    property.getValue()));
                        }
                        log.error("Error parsing password expiry rule.", e);
                    }
                }
            }
        } catch (IdentityGovernanceException e) {
            throw new AuthenticationFailedException("Error occurred while retrieving the password expiry rules for " +
                    "tenant: " + tenantDomain, e);
        }
        return passwordExpiryRules;
    }

    /**
     * Check if the given rule is applicable for the user.
     *
     * @param rule                   Password expiry rule.
     * @param fetchedUserAttributes  Fetched user attributes.
     * @param tenantDomain           Tenant domain.
     * @param userId                 User ID.
     * @param userStoreManager       User store manager.
     * @return true if the rule is applicable, false otherwise.
     * @throws AuthenticationFailedException If an error occurred while checking the rule applicability.
     */
    private static boolean isRuleApplicable(PasswordExpiryRule rule,
                                            Map<PasswordExpiryRuleAttributeEnum, Set<String>> fetchedUserAttributes,
                                            String tenantDomain, String userId,
                                            UserStoreManager userStoreManager) throws AuthenticationFailedException {

        PasswordExpiryRuleAttributeEnum ruleAttribute = rule.getAttribute();
        Set<String> userAttributeValues =
                getUserAttributes(ruleAttribute, fetchedUserAttributes, tenantDomain, userId, userStoreManager);
        if (CollectionUtils.isEmpty(userAttributeValues)) {
            return false;
        }
        return userAttributeValues.containsAll(rule.getValues());
    }

    /**
     * Get the user attribute values for the given password expiry rule attribute.
     *
     * @param attribute              Password expiry rule attribute.
     * @param fetchedUserAttributes  Fetched user attributes.
     * @param tenantDomain           Tenant domain.
     * @param userId                 User ID.
     * @param userStoreManager       User store manager.
     * @return  The user attribute values.
     * @throws AuthenticationFailedException If an error occurred while getting the user attributes.
     */
    private static Set<String> getUserAttributes(PasswordExpiryRuleAttributeEnum attribute,
                                                 Map<PasswordExpiryRuleAttributeEnum, Set<String>> fetchedUserAttributes,
                                                 String tenantDomain, String userId,
                                                 UserStoreManager userStoreManager)
            throws AuthenticationFailedException {

        if (!fetchedUserAttributes.containsKey(attribute)) {
            try {
                switch (attribute) {
                    case ROLES:
                        List<RoleBasicInfo> userRoles = getUserRoles(tenantDomain, userId);
                        Set<String> userRoleIds = userRoles.stream().map(RoleBasicInfo::getId).collect(Collectors.toSet());
                        fetchedUserAttributes.put(PasswordExpiryRuleAttributeEnum.ROLES, userRoleIds);
                        break;
                    case GROUPS:
                        List<Group> userGroups =
                                ((AbstractUserStoreManager) userStoreManager).getGroupListOfUser(userId,
                                        null, null);
                        Set<String> userGroupIds = userGroups.stream().map(Group::getGroupID).collect(Collectors.toSet());
                        fetchedUserAttributes.put(PasswordExpiryRuleAttributeEnum.GROUPS, userGroupIds);
                        break;
                }
            } catch (UserStoreException e) {
                throw new AuthenticationFailedException("Error occurred while retrieving the password expiry rules for " +
                        "tenant: " + tenantDomain, e);
            }
        }
        return fetchedUserAttributes.get(attribute);
    }

    /**
     * Check if the password has expired according to the default password expiry policy.
     *
     * @param tenantDomain            The tenant domain.
     * @param daysDifference          The number of days since the password was last updated.
     * @param lastPasswordUpdatedTime The last password updated time.
     * @return true if the password has expired, false otherwise.
     * @throws AuthenticationFailedException If an error occurs while checking the password expiry.
     */
    private static boolean isPasswordExpiredUnderDefaultPolicy(String tenantDomain, double daysDifference,
                                                               String lastPasswordUpdatedTime,
                                                               boolean skipIfNoApplicableRules)
            throws AuthenticationFailedException {

        if (skipIfNoApplicableRules) return false;
        return lastPasswordUpdatedTime == null || daysDifference >= (double) getPasswordExpiryInDays(tenantDomain);
    }

    /**
     * Get the roles of a given user.
     *
     * @param tenantDomain The tenant domain.
     * @param userId       The user ID.
     * @return The roles of the user.
     * @throws AuthenticationFailedException If an error occurs while getting the user roles.
     */
    public static List<RoleBasicInfo> getUserRoles(String tenantDomain, String userId)
            throws AuthenticationFailedException {

        try {
            RoleManagementService roleManagementService = PasswordPolicyDataHolder.getInstance()
                    .getRoleManagementService();
            return roleManagementService.getRoleListOfUser(userId, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new AuthenticationFailedException("Error occurred while retrieving the password expiry rules for " +
                    "tenant: " + tenantDomain, e);
        }
    }

    /**
     * This method checks if the "skip if no applicable rules" option is enabled for a given tenant domain.
     *
     * @param tenantDomain The tenant domain to check for the configuration.
     * @return true if "skip if no applicable rules" is enabled, false otherwise.
     * @throws AuthenticationFailedException If an error occurs while reading system configurations.
     */
    public static boolean isSkipIfNoApplicableRulesEnabled(String tenantDomain)
            throws AuthenticationFailedException {

        try {
            return Boolean.parseBoolean(PasswordPolicyUtils.getPasswordExpiryConfig(tenantDomain,
                    CONNECTOR_CONFIG_SKIP_IF_NO_APPLICABLE_RULES));
        } catch (IdentityGovernanceException e) {
            throw new AuthenticationFailedException("Error occurred while retrieving the password expiry rules for " +
                    "tenant: " + tenantDomain, e);
        }
    }

    /**
     * Get password expiry config related to the given key.
     *
     * @param tenantDomain Tenant domain.
     * @param key          Password  expiry config key.
     * @return Value associated with the given config key.
     * @throws IdentityGovernanceException If an error occurred while getting th config value.
     */
    public static String getPasswordExpiryConfig(String tenantDomain, String key) throws IdentityGovernanceException {
        Property[] connectorConfigs;
        IdentityGovernanceService governanceService =
                PasswordPolicyDataHolder.getInstance().getIdentityGovernanceService();
        connectorConfigs = governanceService.getConfiguration(new String[]{key}, tenantDomain);
        if(connectorConfigs == null || connectorConfigs.length == 0) {
            return null;
        }
        return connectorConfigs[0].getValue();
    }

    /**
     * This method retrieves the password expiry in days configured for the given tenant domain.
     *
     * @param tenantDomain The tenant domain to retrieve the password expiry in days.
     * @return The password expiry in days.
     */
    private static int getPasswordExpiryInDays(String tenantDomain) {

        int passwordExpiryInDays = CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE;
        String passwordExpiryInDaysConfiguredValue =  null;
        try {
            // Getting the configured number of days before password expiry in days
            passwordExpiryInDaysConfiguredValue = PasswordPolicyUtils
                    .getResidentIdpProperty(tenantDomain, CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS);
        } catch (AuthenticationFailedException e) {
            log.warn("Authentication Exception occurred while reading password expiry residentIdp property");
        }

        if (StringUtils.isEmpty(passwordExpiryInDaysConfiguredValue)) {
            passwordExpiryInDaysConfiguredValue = getIdentityEventProperty(tenantDomain,
                    PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS);
        }

        if (passwordExpiryInDaysConfiguredValue != null) {
            passwordExpiryInDays = Integer.parseInt(passwordExpiryInDaysConfiguredValue);
        }
        return passwordExpiryInDays;
    }

    public static boolean isPasswordExpiredForUser(String tenantDomain, double daysDifference,
                                                   String lastPasswordUpdatedTime, String tenantAwareUsername, UserStoreManager
                                                           userStoreManager) throws AuthenticationFailedException,
            org.wso2.carbon.user.core.UserStoreException {

        try {
            String userId = ((AbstractUserStoreManager) userStoreManager).getUserIDFromUserName(tenantAwareUsername);

            if (userId == null || userId.isEmpty()) {
                throw new AuthenticationFailedException("User not found in the user store.");
            }
            List<PasswordExpiryRule> passwordExpiryRules = getPasswordExpiryRules(tenantDomain);
            boolean skipIfNoApplicableRules = isSkipIfNoApplicableRulesEnabled(tenantDomain);

            // Apply default password expiry policy if no rules given.
            if (passwordExpiryRules == null || CollectionUtils.isEmpty(passwordExpiryRules)) {
                return isPasswordExpiredUnderDefaultPolicy(tenantDomain, daysDifference, lastPasswordUpdatedTime,
                        skipIfNoApplicableRules);
            }

            // If the default behavior is to skip the password expiry, rules with skip logic are not necessary.
            List<PasswordExpiryRule> filteredRules = passwordExpiryRules.stream()
                    .filter(rule -> !skipIfNoApplicableRules ||
                            !PasswordExpiryRuleOperatorEnum.NE.equals(rule.getOperator()))
                    .collect(Collectors.toList());

            Map<PasswordExpiryRuleAttributeEnum, Set<String>> fetchedUserAttributes =
                    new EnumMap<>(PasswordExpiryRuleAttributeEnum.class);

            for (PasswordExpiryRule rule : filteredRules) {
                if (isRuleApplicable(rule, fetchedUserAttributes, tenantDomain, userId, userStoreManager)) {
                    // Skip the rule if the operator is not equals.
                    if (PasswordExpiryRuleOperatorEnum.NE.equals(rule.getOperator())) {
                        return false;
                    }
                    int expiryDays =
                            rule.getExpiryDays() > 0 ? rule.getExpiryDays() : getPasswordExpiryInDays(tenantDomain);
                    return daysDifference >= expiryDays || lastPasswordUpdatedTime == null;
                }
            }
            // Apply default password expiry policy if no specific rule applies.
            return isPasswordExpiredUnderDefaultPolicy(tenantDomain, daysDifference, lastPasswordUpdatedTime,
                    skipIfNoApplicableRules);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while retrieving the password expiry rules for " +
                    "tenant: " + tenantDomain, e);
        }
    }
}
