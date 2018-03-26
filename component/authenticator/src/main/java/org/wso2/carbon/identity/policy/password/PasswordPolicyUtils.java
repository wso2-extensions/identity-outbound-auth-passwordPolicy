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
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.event.IdentityEventConfigBuilder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.ModuleConfiguration;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.policy.password.internal.PasswordPolicyDataHolder;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

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
        Property[] identityProperties = null;
        try {
            identityProperties = PasswordPolicyDataHolder.getInstance().getIdentityGovernanceService()
                    .getConfiguration(PasswordPolicyUtils.getPasswordExpiryPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            log.warn("Using default property values because error occurred while retrieving password expiry " +
                    "properties due to " + e.getMessage(), e);
        }

        // Getting the password expiry in days
        String propertyValue = null;
        if (identityProperties != null) {
            for (Property identityProperty : identityProperties) {
                if (Objects.equals(propertyName, identityProperty.getName())) {
                    propertyValue = identityProperty.getValue();
                }
            }
        }

        if (propertyValue == null) {
            // Loading default value from module configuration
            try {
                ModuleConfiguration moduleConfiguration = IdentityEventConfigBuilder.getInstance()
                        .getModuleConfigurations(PasswordPolicyConstants.PASSWORD_CHANGE_EVENT_HANDLER_NAME);

                if (moduleConfiguration != null) {
                    propertyValue = moduleConfiguration.getModuleProperties().getProperty(propertyName);
                } else {
                    log.warn("Using default property values because no module configurations are present.");
                }
            } catch (IdentityEventException e) {
                log.warn("Using default property values because error occurred while retrieving module properties " +
                        "because " + e.getMessage(), e);
            }
        }
        return propertyValue;
    }
}
