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
            log.info("PasswordExpiryValidation handler is activated successfully");
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
