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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Calendar;

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

        // find the authenticated user.
        AuthenticatedUser authenticatedUser = getUsername(context);

        if (authenticatedUser == null) {
            throw new AuthenticationFailedException("Authentication failed!. Cannot proceed further without identifying the user");
        }

        String username;
        String tenantDomain;
        String userStoreDomain;
        username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        tenantDomain = authenticatedUser.getTenantDomain();
        userStoreDomain = authenticatedUser.getUserStoreDomain();
        String tenantAwareUsername = UserCoreUtil.addDomainToName(username, userStoreDomain);
        String fullyQualifiedUsername = UserCoreUtil.addTenantDomainToEntry(tenantAwareUsername, tenantDomain);
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        long passwordChangedTime = 0;
        int daysDifference = 0;

        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm;
        UserStoreManager userStoreManager;

        try {
            userRealm = realmService.getTenantUserRealm(tenantId);
            userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user manager from user realm", e);
        }

        long currentTimeMillis = System.currentTimeMillis();
        String passwordLastChangedTime;

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

        if (daysDifference > PasswordChangeUtils.getPasswordExpirationInDays() || passwordLastChangedTime == null) {
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

                response.sendRedirect(response
                        .encodeRedirectURL(loginPage + ("?" + queryParams + "&username=" + fullyQualifiedUsername))
                        + "&authenticators=" + getName() + ":" + PasswordChangeEnforceConstants.AUTHENTICATOR_TYPE + retryParam);
            } catch (IOException e) {
                throw new AuthenticationFailedException(e.getMessage(), e);
            }
            context.setCurrentAuthenticator(getName());
            return AuthenticatorFlowStatus.INCOMPLETE;
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

        char[] currentPassword;
        char[] newPassword;
        char[] repeatPassword;

        AuthenticatedUser authenticatedUser = getUsername(context);
        String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        String tenantDomain = authenticatedUser.getTenantDomain();
        String userStoreDomain = authenticatedUser.getUserStoreDomain();

        String tenantAwareUsername = UserCoreUtil.addDomainToName(username, userStoreDomain);

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

        currentPassword = request.getParameter(PasswordChangeEnforceConstants.CURRENT_PWD).toCharArray();
        newPassword = request.getParameter(PasswordChangeEnforceConstants.NEW_PWD).toCharArray();
        repeatPassword = request.getParameter(PasswordChangeEnforceConstants.NEW_PWD_CONFIRMATION).toCharArray();

        if (Arrays.equals(newPassword, repeatPassword)) {
            try {
                userStoreManager.updateCredential(tenantAwareUsername, Arrays.toString(newPassword), Arrays.toString(currentPassword));
                if (log.isDebugEnabled()) {
                    log.debug("Updated user credentials of " + tenantAwareUsername);
                }
            } catch (org.wso2.carbon.user.core.UserStoreException e) {
                throw new AuthenticationFailedException("Incorrect current password", e);
            }
            // authentication is now completed in this step. update the authenticated user information.
            updateAuthenticatedUserInStepConfig(context, authenticatedUser);

        } else {
            throw new AuthenticationFailedException("New password does not match with the new password confirmation");
        }

    }

    /**
     * Get the username from authentication context.
     *
     * @param context the authentication context
     */
    private AuthenticatedUser getUsername(AuthenticationContext context) {
        AuthenticatedUser authenticatedUser = null;
        for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
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