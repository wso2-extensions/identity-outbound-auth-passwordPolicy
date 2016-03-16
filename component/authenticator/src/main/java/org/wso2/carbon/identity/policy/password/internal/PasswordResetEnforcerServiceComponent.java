/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.policy.password.PasswordChangeEnforcerOnExpiration;
import org.wso2.carbon.identity.policy.password.PasswordChangeUserOperationListener;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Hashtable;

/**
 * @scr.component name="org.wso2.carbon.identity.policy.password.component" immediate="true"
 */
public class PasswordResetEnforcerServiceComponent {

    private static Log log = LogFactory.getLog(PasswordResetEnforcerServiceComponent.class);

    private static RealmService realmService;

    /**
     * @return get the realm service
     */
    public static RealmService getRealmService() {
        return realmService;
    }

    /**
     * @param realmService realm service
     */
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        PasswordResetEnforcerServiceComponent.realmService = realmService;
    }

    /**
     * Activate the application authenticator and user operation event listener event components
     *
     * @param ctxt the component context.
     */
    protected void activate(ComponentContext ctxt) {
        try {
            // register the connector to enforce password change upon expiration.
            PasswordChangeEnforcerOnExpiration authenticator = new PasswordChangeEnforcerOnExpiration();
            Hashtable<String, String> props = new Hashtable<String, String>();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), authenticator, props);

            // register the n to capture password change events.
            ctxt.getBundleContext().registerService(UserOperationEventListener.class.getName(),
                    new PasswordChangeUserOperationListener(), props);
            if (log.isDebugEnabled()) {
                log.debug("PasswordChangeEnforcerOnExpiration handler is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error while activating the PasswordChangeEnforcerOnExpiration handler ", e);
        }
    }

    /**
     * Deactivate the component
     *
     * @param ctxt the component context.
     */
    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("PasswordChangeEnforcerOnExpiration is deactivated");
        }
    }

    /**
     * Un setting the realm service
     *
     * @param realmService the realm service.
     */
    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Un setting the Realm Service");
        }
        PasswordResetEnforcerServiceComponent.realmService = null;
    }
}
