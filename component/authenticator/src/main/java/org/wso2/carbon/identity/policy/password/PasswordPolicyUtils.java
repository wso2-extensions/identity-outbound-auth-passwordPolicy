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
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.event.IdentityEventConfigBuilder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.ModuleConfiguration;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.util.ArrayList;
import java.util.List;

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
        properties.add(PasswordPolicyConstants.CONNECTOR_CONFIG_STORE_TIME_AS_NANOSECONDS);
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
}
