package org.wso2.carbon.identity.password.expiry.validation.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.event.IdentityEventConfigBuilder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.ModuleConfiguration;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

public class PasswordExpiryPolicyUtils {
    private static final Log log = LogFactory.getLog(PasswordExpiryPolicyUtils.class);

    private PasswordExpiryPolicyUtils(){}

    public static String getIdentityEventProperty(String tenantDomain, String propertyName) {

        // Retrieving properties set in identity event properties
        String propertyValue = null;
        try {
            ModuleConfiguration moduleConfiguration = IdentityEventConfigBuilder.getInstance()
                    .getModuleConfigurations(PasswordExpiryValidationConstants.PASSWORD_CHANGE_EVENT_HANDLER_NAME);

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

    public static String getResidentIdpProperty(String tenantDomain, String propertyName)
             {

        IdentityProvider residentIdP = null;
        try {
            residentIdP = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {

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
