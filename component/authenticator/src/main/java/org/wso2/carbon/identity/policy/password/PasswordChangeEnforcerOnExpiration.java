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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.policy.password.internal.PasswordResetEnforcerDataHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.util.Calendar;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * this connector must only be present in an authentication step, where the user
 * is already identified by a previous step.
 */
public class PasswordChangeEnforcerOnExpiration extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(PasswordChangeEnforcerOnExpiration.class);

    private static final long serialVersionUID = 307784186695787941L;

    @Override
    public boolean canHandle(HttpServletRequest arg0) {
        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(PasswordChangeEnforceConstants.STATE);
    }

    @Override
    public String getFriendlyName() {
        return PasswordChangeEnforceConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return PasswordChangeEnforceConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException {
        // if the logout request comes, then no need to go through and doing complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        if (StringUtils.isNotEmpty(request.getParameter(PasswordChangeEnforceConstants.CURRENT_PWD))
                && StringUtils.isNotEmpty(request.getParameter(PasswordChangeEnforceConstants.NEW_PWD))
                && StringUtils.isNotEmpty(request.getParameter(PasswordChangeEnforceConstants.NEW_PWD_CONFIRMATION))) {
            try {
                processAuthenticationResponse(request, response, context);
            } catch (Exception e) {
                context.setRetrying(true);
                context.setCurrentAuthenticator(getName());
                return initiateAuthRequest(response, context, e.getMessage());
            }
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else {
            return initiateAuthRequest(response, context, null);
        }
    }

    /**
     * this will prompt user to change the credentials only if the last password
     * changed time has gone beyond the pre-configured value.
     *
     * @param response the response
     * @param context  the authentication context
     */
    private AuthenticatorFlowStatus initiateAuthRequest(HttpServletResponse response, AuthenticationContext context,
                                                        String errorMessage)
            throws AuthenticationFailedException {
        // Find the authenticated user.
        AuthenticatedUser authenticatedUser = getUser(context);
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);

        if (authenticatedUser == null) {
            throw new AuthenticationFailedException("Authentication failed!. " +
                    "Cannot proceed further without identifying the user");
        }

        // The password reset flow for local authenticator
        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof
                LocalApplicationAuthenticator) {
            String tenantDomain = authenticatedUser.getTenantDomain();
            String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);

            if (hadPasswordExpired(tenantDomain, tenantAwareUsername)) {
                // The password has expired or the password changed time is not set
                try {
                    // Creating the URL to which the user will be redirected
                    String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                            .replace("login.do", "pwd-reset.jsp");
                    String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                            context.getCallerSessionKey(), context.getContextIdentifier());
                    String retryParam = "";
                    if (context.isRetrying()) {
                        retryParam = "&authFailure=true&authFailureMsg=" + errorMessage;
                    }
                    String fullyQualifiedUsername = UserCoreUtil.addTenantDomainToEntry(tenantAwareUsername,
                            tenantDomain);
                    String encodedUrl = (loginPage + ("?" + queryParams + "&username=" + fullyQualifiedUsername))
                            + "&authenticators=" + getName() + ":" + PasswordChangeEnforceConstants.AUTHENTICATOR_TYPE
                            + retryParam;

                    response.sendRedirect(encodedUrl);
                } catch (IOException e) {
                    throw new AuthenticationFailedException(e.getMessage(), e);
                }
                context.setCurrentAuthenticator(getName());
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
        }
        // Authentication is now completed in this step. Update the authenticated user information.
        updateAuthenticatedUserInStepConfig(context, authenticatedUser);
        return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
    }

    /**
     * Update the updateCredential.
     *
     * @param request  the request
     * @param response the response
     * @param context  the authentication context
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        AuthenticatedUser authenticatedUser = getUser(context);
        String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);

        String currentPassword = request.getParameter(PasswordChangeEnforceConstants.CURRENT_PWD);
        String newPassword = request.getParameter(PasswordChangeEnforceConstants.NEW_PWD);
        String newPasswordConfirmation = request.getParameter(PasswordChangeEnforceConstants.NEW_PWD_CONFIRMATION);

        // Checking current, new and repeat new passwords
        if (currentPassword == null || newPassword == null || newPasswordConfirmation == null) {
            throw new AuthenticationFailedException("All fields are required");
        }
        if (currentPassword.equals(newPassword)) {
            throw new AuthenticationFailedException("You cannot use your previous password as your new password");
        }
        if (newPassword.equals(newPasswordConfirmation)) {
            // Fetching user store manager
            UserStoreManager userStoreManager;
            try {
                String tenantDomain = authenticatedUser.getTenantDomain();
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                RealmService realmService = IdentityTenantUtil.getRealmService();
                UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
                userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
            } catch (UserStoreException e) {
                throw new AuthenticationFailedException("Error occurred while loading user realm or user store manager",
                        e);
            }

            // Updating the credentials
            try {
                validatePassword(userStoreManager, newPassword);

                // Since password is valid updating credentials
                userStoreManager.updateCredential(tenantAwareUsername, newPassword, currentPassword);
                if (log.isDebugEnabled()) {
                    log.debug("Updated user credentials of " + tenantAwareUsername);
                }
            } catch (UserStoreException e) {
                String errorMessage = getAuthenticationErrorMessage(e);
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new AuthenticationFailedException(errorMessage, e);
            }

            // Authentication is now completed in this step. Update the authenticated user information.
            updateAuthenticatedUserInStepConfig(context, authenticatedUser);
        } else {
            throw new AuthenticationFailedException("The new password and confirmation password do not match");
        }
    }

    /**
     * Checks if the password had expired.
     *
     * @param tenantDomain        The tenant domain of the user trying to authenticate
     * @param tenantAwareUsername The tenant aware username of the user trying to authenticate
     * @return True if the password had expired
     * @throws AuthenticationFailedException if the authentication failed for the user trying to login
     */
    private boolean hadPasswordExpired(String tenantDomain, String tenantAwareUsername)
            throws AuthenticationFailedException {
        UserStoreManager userStoreManager;
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
            userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user manager from user realm", e);
        }

        String passwordLastChangedTime;
        try {
            passwordLastChangedTime = userStoreManager.getUserClaimValue(tenantAwareUsername,
                    PasswordChangeEnforceConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM, null);
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user claim - "
                    + PasswordChangeEnforceConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM, e);
        }

        long passwordChangedTime = 0;
        if (passwordLastChangedTime != null) {
            passwordChangedTime = Long.parseLong(passwordLastChangedTime);
        }

        int daysDifference = 0;
        long currentTimeMillis = System.currentTimeMillis();
        if (passwordChangedTime > 0) {
            Calendar currentTime = Calendar.getInstance();
            currentTime.add(Calendar.DATE, (int) currentTime.getTimeInMillis());
            daysDifference = (int) ((currentTimeMillis - passwordChangedTime) / (1000 * 60 * 60 * 24));
        }

        // Retrieving properties set in identity event properties
        Property[] identityProperties = null;
        try {
            identityProperties = PasswordResetEnforcerDataHolder.getInstance().getIdentityGovernanceService()
                    .getConfiguration(PasswordChangeUtils.getPasswordExpiryPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            log.warn("Error while retrieving password expiry properties. Using default property values.", e);
        }

        // Getting the password expiry in days
        int passwordExpiryInDays = PasswordChangeEnforceConstants.DEFAULT_CREDENTIAL_EXP_IN_DAYS;
        if (identityProperties != null) {
            for (Property identityProperty : identityProperties) {
                if (PasswordChangeEnforceConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS
                        .equals(identityProperty.getName())) {
                    passwordExpiryInDays = Integer.parseInt(identityProperty.getValue());
                }
            }
        }

        return (daysDifference > passwordExpiryInDays || passwordLastChangedTime == null);
    }

    /**
     * Validate a password
     *
     * @param userStoreManager The user store to which the user belongs to
     * @param password         The password that needs to be validated
     * @throws AuthenticationFailedException If the password is invalid
     */
    private void validatePassword(UserStoreManager userStoreManager, String password)
            throws AuthenticationFailedException {
        String regularExpression = userStoreManager.getRealmConfiguration()
                .getUserStoreProperty("PasswordJavaRegEx");
        if (StringUtils.isNotEmpty(regularExpression) && !isFormatCorrect(regularExpression, password)) {
            String errorMsg = userStoreManager.getRealmConfiguration()
                    .getUserStoreProperty("PasswordJavaRegExViolationErrorMsg");

            if (StringUtils.isEmpty(errorMsg)) {
                errorMsg = "New password doesn't meet the policy requirement. " +
                        "It must be in the following format, " + regularExpression;
            }

            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            throw new AuthenticationFailedException(errorMsg);
        }
    }

    /**
     * Check if the format of the password is correct
     *
     * @param regularExpression The regular expression indicating the password format
     * @param password          The password to be checked
     * @return True if the password matches the format. False otherwise.
     */
    private boolean isFormatCorrect(String regularExpression, String password) {
        Pattern p2 = Pattern.compile(regularExpression);
        Matcher m2 = p2.matcher(password);
        return m2.matches();
    }

    /**
     * Get a user readable error message for an exception
     *
     * @param e The exception for which the error message should be returned
     * @return The user readable error message
     */
    private String getAuthenticationErrorMessage(Exception e) {
        String errorMessage = "Error occurred while updating the password";
        if (e.getMessage().contains("InvalidOperation")) {
            errorMessage = "Invalid operation. User store is read only.";
        }
        if (e.getMessage().contains("PasswordInvalid")) {
            errorMessage = "Invalid credentials. Cannot proceed with the password change.";
        }
        return errorMessage;
    }

    /**
     * Get the username from authentication context.
     *
     * @param context the authentication context
     * @return The authenticated user
     */
    private AuthenticatedUser getUser(AuthenticationContext context) {
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        return stepConfig.getAuthenticatedUser();
    }

    /**
     * Update the authenticated user context.
     *
     * @param context           the authentication context
     * @param authenticatedUser the authenticated user's name
     */
    private void updateAuthenticatedUserInStepConfig(AuthenticationContext context,
                                                     AuthenticatedUser authenticatedUser) {
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (int i = 1; i <= stepConfigMap.size(); i++) {
            stepConfigMap.get(i).setAuthenticatedUser(authenticatedUser);
        }
        context.setSubject(authenticatedUser);
    }
}
