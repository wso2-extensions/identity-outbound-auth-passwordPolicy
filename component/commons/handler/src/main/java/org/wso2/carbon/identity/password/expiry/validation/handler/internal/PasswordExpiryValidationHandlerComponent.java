/*
 * Copyright (c) 2010-2022, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.password.expiry.validation.handler.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.password.expiry.validation.handler.PasswordExpiryValidationHandler;

@Component(
        name = "org.wso2.carbon.identity.password.expiry.validation.handler.component",
        immediate = true
)
public class PasswordExpiryValidationHandlerComponent {
    private static final Log log = LogFactory.getLog(PasswordExpiryValidationHandlerComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            BundleContext bundleContext = ctxt.getBundleContext();
            PasswordExpiryValidationHandler passwordExpiryValidationHandler = new PasswordExpiryValidationHandler();

            // Register the listener to capture password expiry validation events.
            bundleContext.registerService(AbstractEventHandler.class.getName(), passwordExpiryValidationHandler, null);

            if (log.isDebugEnabled()) {
                log.debug("PasswordExpiryValidation handler is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error while activating the PasswordExpiryValidation handler", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("PasswordExpiryValidation handler is deactivated");
        }
    }
}
