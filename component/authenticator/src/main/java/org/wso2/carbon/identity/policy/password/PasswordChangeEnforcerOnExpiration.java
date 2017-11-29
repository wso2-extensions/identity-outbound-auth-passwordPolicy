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
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.PrivilegedActionException;
import java.util.Calendar;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
        return PasswordChangeEnforceConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getName() {
        return PasswordChangeEnforceConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
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
                return initiateAuthRequest(request, response, context, e.getMessage());
            }
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else {
            return initiateAuthRequest(request, response, context, null);
        }
    }

    /**
     * this will prompt user to change the credentials only if the last password
     * changed time has gone beyond the pre-configured value.
     *
     * @param request  the request
     * @param response the response
     * @param context  the authentication context
     */
    protected AuthenticatorFlowStatus initiateAuthRequest(HttpServletRequest request, HttpServletResponse response,
                                                          AuthenticationContext context, String errorMessage)
            throws AuthenticationFailedException {
        String username;
        String tenantDomain;
        String userStoreDomain;
        int tenantId;
        String tenantAwareUsername;
        String fullyQualifiedUsername;
        long passwordChangedTime = 0;
        int daysDifference = 0;
        String passwordLastChangedTime;
        long currentTimeMillis;

        // find the authenticated user.
        AuthenticatedUser authenticatedUser = getUsername(context);
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (authenticatedUser == null) {
            throw new AuthenticationFailedException
                    ("Authentication failed!. Cannot proceed further without identifying the user");
        }
        // The password reset flow for local authenticator
        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof
                LocalApplicationAuthenticator) {
            username = authenticatedUser.getAuthenticatedSubjectIdentifier();
            tenantDomain = authenticatedUser.getTenantDomain();
            userStoreDomain = authenticatedUser.getUserStoreDomain();
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            fullyQualifiedUsername = UserCoreUtil.addTenantDomainToEntry(tenantAwareUsername, tenantDomain);
            tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            UserRealm userRealm;
            UserStoreManager userStoreManager;
            try {
                userRealm = realmService.getTenantUserRealm(tenantId);
                userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
            } catch (UserStoreException e) {
                throw new AuthenticationFailedException("Error occurred while loading user manager from user realm", e);
            }
            currentTimeMillis = System.currentTimeMillis();
            try {
                passwordLastChangedTime = userStoreManager.getUserClaimValue(tenantAwareUsername,
                        PasswordChangeUtils.LAST_PASSWORD_CHANGED_TIMESTAMP_CLAIM, null);
            } catch (org.wso2.carbon.user.core.UserStoreException e) {
                throw new AuthenticationFailedException("Error occurred while loading user claim - "
                        + PasswordChangeUtils.LAST_PASSWORD_CHANGED_TIMESTAMP_CLAIM, e);
            }
            if (passwordLastChangedTime != null) {
                passwordChangedTime = Long.parseLong(passwordLastChangedTime);
            }
            if (passwordChangedTime > 0) {
                Calendar currentTime = Calendar.getInstance();
                currentTime.add(Calendar.DATE, (int) currentTime.getTimeInMillis());
                daysDifference = (int) ((currentTimeMillis - passwordChangedTime) / (1000 * 60 * 60 * 24));
            }
            if ((daysDifference > PasswordChangeUtils.getPasswordExpirationInDays() || passwordLastChangedTime == null)) {
                // the password has changed or the password changed time is not set.
                String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL().replace("login.do",
                        "pwd-reset.jsp");
                String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                        context.getCallerSessionKey(), context.getContextIdentifier());
                try {
                    String retryParam = "";
                    if (context.isRetrying()) {
                        retryParam = "&authFailure=true&authFailureMsg=" + errorMessage;
                    }
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
        // authentication is now completed in this step. update the authenticated user information.
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
        String currentPassword;
        String newPassword;
        String repeatPassword;
        AuthenticatedUser authenticatedUser = getUsername(context);
        String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        String tenantDomain = authenticatedUser.getTenantDomain();
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm;
        UserStoreManager userStoreManager;
        try {
            userRealm = realmService.getTenantUserRealm(tenantId);
            userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user realm or user store manager", e);
        }
        currentPassword = request.getParameter(PasswordChangeEnforceConstants.CURRENT_PWD);
        newPassword = request.getParameter(PasswordChangeEnforceConstants.NEW_PWD);
        repeatPassword = request.getParameter(PasswordChangeEnforceConstants.NEW_PWD_CONFIRMATION);
        if (currentPassword == null || newPassword == null || repeatPassword == null) {
            throw new AuthenticationFailedException("All fields are required");
        }
        if (currentPassword.equals(newPassword)) {
            throw new AuthenticationFailedException("You cannot use your previous password as your new password");
        }
        if (newPassword.equals(repeatPassword)) {
            try {
                String regularExpression = userStoreManager.getRealmConfiguration().getUserStoreProperty("PasswordJavaRegEx");
                if(StringUtils.isNotEmpty(regularExpression)) {
                    if(!isFormatCorrect(regularExpression, newPassword)){
                        String errorMsg = userStoreManager.getRealmConfiguration()
                                .getUserStoreProperty("PasswordJavaRegExViolationErrorMsg");
                        if(StringUtils.isNotEmpty(errorMsg)){
                            if (log.isDebugEnabled()) {
                                log.debug(errorMsg);
                            }
                            throw new AuthenticationFailedException(errorMsg);
                        }
                        if (log.isDebugEnabled()) {
                            log.debug(
                                "New password doesn't meet the policy requirement. It must be in the following format, "
                                + regularExpression);
                        }
                        throw new AuthenticationFailedException(
                                "New password doesn't meet the policy requirement. It must be in the following format, "
                                + regularExpression);
                    }
                }
                userStoreManager.updateCredential(tenantAwareUsername, newPassword, currentPassword);
                if (log.isDebugEnabled()) {
                    log.debug("Updated user credentials of " + tenantAwareUsername);
                }
            } catch (org.wso2.carbon.user.core.UserStoreException e) {
                if(e.getMessage().contains("InvalidOperation")){
                    if (log.isDebugEnabled()) {
                        log.debug("Invalid operation. User store is read only.", e);
                    }
                    throw new AuthenticationFailedException(
                            "Invalid operation. User store is read only", e);
                }
                if(e.getMessage().contains("PasswordInvalid")){
                    if (log.isDebugEnabled()) {
                        log.debug("Invalid credentials. Cannot proceed with the password change.", e);
                    }
                    throw new AuthenticationFailedException(
                            "Invalid credentials. Cannot proceed with the password change.", e);
                }
                throw new AuthenticationFailedException("Error occurred while updating the password", e);
            }
            // authentication is now completed in this step. update the authenticated user information.
            updateAuthenticatedUserInStepConfig(context, authenticatedUser);
        } else {
            throw new AuthenticationFailedException("The new password and confirmation password do not match");
        }
    }

    private boolean isFormatCorrect(String regularExpression, String password) {
        Pattern p2 = Pattern.compile(regularExpression);
        Matcher m2 = p2.matcher(password);
        return m2.matches();
    }

    /**
     * Get the username from authentication context.
     *
     * @param context the authentication context
     */
    private AuthenticatedUser getUsername(AuthenticationContext context) {
        AuthenticatedUser authenticatedUser = null;
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedUser() != null) {
            authenticatedUser = stepConfig.getAuthenticatedUser();
        }

        return authenticatedUser;
    }

    /**
     * Update the authenticated user context.
     *
     * @param context           the authentication context
     * @param authenticatedUser the authenticated user's name
     */
    private void updateAuthenticatedUserInStepConfig(AuthenticationContext context,
                                                     AuthenticatedUser authenticatedUser) {
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
            stepConfig.setAuthenticatedUser(authenticatedUser);
        }
        context.setSubject(authenticatedUser);
    }
}