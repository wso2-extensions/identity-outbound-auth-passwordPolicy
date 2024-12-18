/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.policy.password.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.policy.password.PasswordChangeHandler;
import org.wso2.carbon.identity.policy.password.PasswordResetEnforcer;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;

@Component(
        name = "org.wso2.carbon.identity.policy.password.component",
        immediate = true
)
public class PasswordPolicyServiceComponent {
    private static final Log log = LogFactory.getLog(PasswordPolicyServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            BundleContext bundleContext = ctxt.getBundleContext();
            PasswordChangeHandler passwordChangeHandler = new PasswordChangeHandler();

            // Register the connector to enforce password change upon expiration.
            bundleContext.registerService(ApplicationAuthenticator.class.getName(),
                    new PasswordResetEnforcer(), null);

            // Register the listener to capture password change events.
            bundleContext.registerService(AbstractEventHandler.class.getName(), passwordChangeHandler, null);

            // Register the connector config to render the resident identity provider configurations
            bundleContext.registerService(IdentityConnectorConfig.class.getName(), passwordChangeHandler, null);
            if (log.isDebugEnabled()) {
                log.debug("PasswordResetEnforcer handler is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error while activating the PasswordResetEnforcer handler. " +
                    "You will be prompted to reset the password every time you login " +
                    "since last password update time will not be set.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("PasswordResetEnforcer is deactivated");
        }
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService"
    )
    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {
        PasswordPolicyDataHolder.getInstance().setIdentityGovernanceService(idpManager);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {
        PasswordPolicyDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    @Reference(
            name = "role.management.service",
            service = RoleManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRoleManagementService"
    )
    protected void setRoleManagementService(RoleManagementService roleManagementService) {

        PasswordPolicyDataHolder.getInstance().setRoleManagementService(roleManagementService);
    }

    protected void unsetRoleManagementService(RoleManagementService roleManagementService) {

        PasswordPolicyDataHolder.getInstance().setRoleManagementService(null);
    }
}
