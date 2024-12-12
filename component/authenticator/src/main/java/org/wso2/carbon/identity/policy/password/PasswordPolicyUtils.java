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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.PostAuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConfigBuilder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.ModuleConfiguration;
import org.wso2.carbon.identity.governance.listener.IdentityStoreEventListener;
import org.wso2.carbon.identity.governance.store.UserStoreBasedIdentityDataStore;
import org.wso2.carbon.identity.password.expiry.models.PasswordExpiryRule;
import org.wso2.carbon.identity.password.expiry.models.PasswordExpiryRuleAttributeEnum;
import org.wso2.carbon.identity.password.expiry.models.PasswordExpiryRuleOperatorEnum;
import org.wso2.carbon.identity.policy.password.internal.PasswordPolicyDataHolder;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.Group;
import org.wso2.carbon.user.core.jdbc.UniqueIDJDBCUserStoreManager;
import org.wso2.carbon.user.core.ldap.UniqueIDActiveDirectoryUserStoreManager;
import static org.wso2.carbon.identity.policy.password.PasswordPolicyConstants.DATA_STORE_PROPERTY_NAME;
import static org.wso2.carbon.identity.policy.password.PasswordPolicyConstants.HUNDREDS_OF_NANOSECONDS;
import static org.wso2.carbon.identity.policy.password.PasswordPolicyConstants.USER_OPERATION_EVENT_LISTENER_TYPE;
import static org.wso2.carbon.identity.policy.password.PasswordPolicyConstants.WINDOWS_EPOCH_DIFF;

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

    public static boolean isPasswordExpiredForUser(String tenantDomain, double daysDifference,
                                                   String passwordLastChangedTime, String userId, UserStoreManager
                                                           userStoreManager) throws AuthenticationFailedException {
        try {
            List<PasswordExpiryRule> passwordExpiryRules =
                    org.wso2.carbon.identity.password.expiry.util.PasswordPolicyUtils
                            .getPasswordExpiryRules(tenantDomain);
            boolean skipIfNoApplicableRules =
                    org.wso2.carbon.identity.password.expiry.util.PasswordPolicyUtils
                            .isSkipIfNoApplicableRulesEnabled(tenantDomain);
            // Apply default password expiry policy if no rules given.
            if (CollectionUtils.isEmpty(passwordExpiryRules)) {
                return isPasswordExpiredUnderDefaultPolicy(tenantDomain, daysDifference, passwordLastChangedTime,
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
                    return daysDifference >= expiryDays || passwordLastChangedTime == null;
                }
            }
            // Apply default password expiry policy if no specific rule applies.
            return isPasswordExpiredUnderDefaultPolicy(tenantDomain, daysDifference, passwordLastChangedTime,
                    skipIfNoApplicableRules);

        } catch (PostAuthenticationFailedException e) {
            throw new AuthenticationFailedException("Error while reading the password expiry rules", e);
        }
    }

    /**
     * Check if the password has expired according to the default password expiry policy.
     *
     * @param tenantDomain            The tenant domain.
     * @param daysDifference          The number of days since the password was last updated.
     * @param lastPasswordUpdatedTime The last password updated time.
     * @return true if the password has expired, false otherwise.
     * @throws PostAuthenticationFailedException If an error occurs while checking the password expiry.
     */
    private static boolean isPasswordExpiredUnderDefaultPolicy(String tenantDomain, double daysDifference,
                                                               String lastPasswordUpdatedTime,
                                                               boolean skipIfNoApplicableRules)
            throws AuthenticationFailedException {

        if (skipIfNoApplicableRules) return false;
        return lastPasswordUpdatedTime == null || daysDifference >= (double) getPasswordExpiryInDays(tenantDomain);
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
     * @throws PostAuthenticationFailedException If an error occurred while checking the rule applicability.
     */
    private static boolean isRuleApplicable(PasswordExpiryRule rule,
                                            Map<PasswordExpiryRuleAttributeEnum, Set<String>> fetchedUserAttributes,
                                            String tenantDomain, String userId,
                                            UserStoreManager userStoreManager)
            throws AuthenticationFailedException {

        PasswordExpiryRuleAttributeEnum ruleAttribute = rule.getAttribute();
        Set<String> userAttributeValues =
                getUserAttributes(ruleAttribute, fetchedUserAttributes, tenantDomain, userId, userStoreManager);
        if (CollectionUtils.isEmpty(userAttributeValues)) {
            return false;
        }
        return userAttributeValues.containsAll(rule.getValues());
    }

    private static Set<String> getUserAttributes(PasswordExpiryRuleAttributeEnum attribute,
                                                 Map<PasswordExpiryRuleAttributeEnum, Set<String>> fetchedUserAttributes,
                                                 String tenantDomain, String userId,
                                                 UserStoreManager userStoreManager)
            throws AuthenticationFailedException {

        if (!fetchedUserAttributes.containsKey(attribute)) {
            switch (attribute) {
                case ROLES:
                    // Fetch roles assigned to user via groups.
                    Set<String> userGroupIds;
                    if (fetchedUserAttributes.containsKey(PasswordExpiryRuleAttributeEnum.GROUPS)) {
                        userGroupIds = fetchedUserAttributes.get(PasswordExpiryRuleAttributeEnum.GROUPS);
                    } else {
                        userGroupIds = getUserGroupIds(userId, userStoreManager);
                        fetchedUserAttributes.put(PasswordExpiryRuleAttributeEnum.GROUPS, userGroupIds);
                    }
                    List<String> roleIdsOfGroups = getRoleIdsOfGroups(new ArrayList<>(userGroupIds), tenantDomain);

                    List<RoleBasicInfo> userRoles = getUserRoles(tenantDomain, userId);
                    Set<String> userRoleIds =
                            userRoles.stream().map(RoleBasicInfo::getId).collect(Collectors.toSet());
                    userRoleIds.addAll(roleIdsOfGroups);
                    fetchedUserAttributes.put(PasswordExpiryRuleAttributeEnum.ROLES, userRoleIds);
                    break;
                case GROUPS:
                    Set<String> groupIds = getUserGroupIds(userId, userStoreManager);
                    fetchedUserAttributes.put(PasswordExpiryRuleAttributeEnum.GROUPS, groupIds);
                    break;
            }
        }
        return fetchedUserAttributes.get(attribute);
    }

    /**
     * Get the group IDs of the given user.
     *
     * @param userId           The user ID.
     * @param userStoreManager The user store manager.
     * @return The group IDs of the user.
     * @throws AuthenticationFailedException If an error occurs while getting the group IDs of the user.
     */
    private static Set<String> getUserGroupIds(String userId, UserStoreManager userStoreManager)
            throws AuthenticationFailedException {

        try {
            List<Group> userGroups =
                    ((AbstractUserStoreManager) userStoreManager).getGroupListOfUser(userId,
                            null, null);
            return userGroups.stream().map(Group::getGroupID).collect(Collectors.toSet());
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error while retrieving user groups.", e);
        }
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
            throw new AuthenticationFailedException("Error while retrieving user roles.", e);
        }
    }

    /**
     * Get the role IDs of the given groups.
     *
     * @param groupIds     The group IDs.
     * @param tenantDomain The tenant domain.
     * @return The role IDs of the groups.
     * @throws AuthenticationFailedException If an error occurs while getting the role IDs of the groups.
     */
    private static List<String> getRoleIdsOfGroups(List<String> groupIds, String tenantDomain)
            throws AuthenticationFailedException {

        try {
            RoleManagementService roleManagementService = PasswordPolicyDataHolder.getInstance()
                    .getRoleManagementService();
            return roleManagementService.getRoleIdListOfGroups(groupIds, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            throw new AuthenticationFailedException("Error while retrieving user roles.", e);
        }
    }

    /**
     * This method retrieves the password expiry in days configured for the given tenant domain.
     *
     * @param tenantDomain The tenant domain to retrieve the password expiry in days.
     * @return The password expiry in days.
     * @throws AuthenticationFailedException If an error occurs while retrieving the password expiry configuration.
     */
    private static int getPasswordExpiryInDays(String tenantDomain) throws AuthenticationFailedException {

        int passwordExpiryInDays = PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE;

        // Getting the configured number of days before password expiry in days
        String passwordExpiryInDaysConfiguredValue = PasswordPolicyUtils
                .getResidentIdpProperty(tenantDomain, PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS);

        if (StringUtils.isEmpty(passwordExpiryInDaysConfiguredValue)) {
            passwordExpiryInDaysConfiguredValue = PasswordPolicyUtils.getIdentityEventProperty(tenantDomain,
                    PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS);
        }

        if (passwordExpiryInDaysConfiguredValue != null) {
            passwordExpiryInDays = Integer.parseInt(passwordExpiryInDaysConfiguredValue);
        }
        return passwordExpiryInDays;
    }
}
