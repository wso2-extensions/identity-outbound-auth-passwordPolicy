/*
 * Copyright (c) 2023, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.post.authn.handler.disclaimer;


import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.PostAuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.AbstractPostAuthnHandler;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import org.wso2.carbon.identity.post.authn.handler.disclaimer.internal.EnforcePasswordResetPostAuthenticationHandlerDataHolder;
import org.wso2.carbon.user.api.ClaimManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;


import java.util.Calendar;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.post.authn.handler.disclaimer.PasswordPolicyConstants.ErrorMessages.*;

public class EnforcePasswordResetAuthenticationHandler extends AbstractPostAuthnHandler {

    @Override
    public PostAuthnHandlerFlowStatus handle(HttpServletRequest httpServletRequest,
                                             HttpServletResponse httpServletResponse,
                                             AuthenticationContext authenticationContext)
                                             throws PostAuthenticationFailedException {


        // Find the authenticated user.
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(authenticationContext);
        String tenantDomain = authenticatedUser.getTenantDomain();

        validateUser(authenticatedUser);

        if (!authenticationContext.getCurrentAuthenticatedIdPs().containsKey(PasswordPolicyConstants.
                AUTHENTICATOR_TYPE )) {
            return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
        }

        if (!isPasswordHistoryEnabled(tenantDomain)) {
            return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
        }

        List<AuthenticatorConfig> authenticators =
                    authenticationContext.getCurrentAuthenticatedIdPs().get(PasswordPolicyConstants.AUTHENTICATOR_TYPE )
                            .getAuthenticators();

            for(AuthenticatorConfig authenticator : authenticators) {
                if("BasicAuthenticator".equals(authenticator.getName())) {
                    if (!authenticatedUser.isFederatedUser()) {

                        String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
                        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
                        if (isPasswordExpired(tenantDomain, tenantAwareUsername)) {
                            // TODO Redirect to the password reset page.
                            return PostAuthnHandlerFlowStatus.INCOMPLETE;
                        }
                        return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
                    }
                }
            }

        return PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
    }

    /**
     * This method checks if password history is enabled for a given tenant domain.
     *
     * @param tenantDomain the tenant domain to check for password history configuration
     * @return true if password history is enabled, false otherwise
     * @throws PostAuthenticationFailedException if there is an error while reading system configurations
     */
    private boolean isPasswordHistoryEnabled(String tenantDomain) throws PostAuthenticationFailedException {
        try {
            return Boolean.parseBoolean(PasswordPolicyUtils.getResidentIdpProperty(tenantDomain, "passwordHistory.enable"));
        } catch (AuthenticationFailedException e) {
            throw new PostAuthenticationFailedException(ERROR_WHILE_READING_SYSTEM_CONFIGURATIONS.getCode(),
                    ERROR_WHILE_READING_SYSTEM_CONFIGURATIONS.getMessage());
        }
    }

    /**
     * This method validates the authenticated user object.
     *
     * @param authenticatedUser the authenticated user object to validate
     * @throws PostAuthenticationFailedException if the authenticated user object is null
     */
    private static void validateUser(AuthenticatedUser authenticatedUser) throws PostAuthenticationFailedException {

        if (authenticatedUser == null) {
            throw new PostAuthenticationFailedException(ERROR_WHILE_GETTING_FEDERATED_USERNAME.getCode(),
                    "Authentication failed!. " +
                            "Cannot proceed further without identifying the user");
        }
    }

    @Override
    public String getName() {

        return "EnforcePasswordResetHandler";
    }

    /**
     * This method retrieves the authenticated user object from the authentication context.
     *
     * @param authenticationContext the authentication context to retrieve the authenticated user from
     * @return the authenticated user object
     */
    private AuthenticatedUser getAuthenticatedUser(AuthenticationContext authenticationContext) {

        AuthenticatedUser user = authenticationContext.getSequenceConfig().getAuthenticatedUser();
        return user;
    }


    /**
     * This method checks if the password has expired.
     *
     * @param tenantDomain        the tenant domain of the user trying to authenticate
     * @param tenantAwareUsername the tenant aware username of the user trying to authenticate
     * @return true if the password had expired
     * @throws AuthenticationFailedException if the authentication failed for the user trying to login
     */
    private boolean isPasswordExpired(String tenantDomain, String tenantAwareUsername)
            throws PostAuthenticationFailedException {

       UserRealm userRealm = getUserRealm(tenantDomain);
       UserStoreManager userStoreManager = getUserStoreManager(userRealm);
       String lastPasswordUpdatedTime = getLastPasswordUpdatedTime(tenantAwareUsername, userStoreManager, userRealm);
       long lastPasswordUpdatedTimeinMillis = getLastPasswordUpdatedTimeinMillis(lastPasswordUpdatedTime);
       int daysDifference = getDaysDifference(lastPasswordUpdatedTimeinMillis);
       int passwordExpiryInDays = PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE;

       // Getting the configured number of days before password expiry in days
        passwordExpiryInDays = getPasswordExpiryInDays(tenantDomain, passwordExpiryInDays);

        return (daysDifference > passwordExpiryInDays || lastPasswordUpdatedTime == null);
    }

    /**
     * This method retrieves the last password updated time in milliseconds.
     *
     * @param lastPasswordUpdatedTime the last password updated time in string format
     * @return the last password updated time in milliseconds
     */
    private static long getLastPasswordUpdatedTimeinMillis(String lastPasswordUpdatedTime) {
        return StringUtils.isEmpty(lastPasswordUpdatedTime) ? 0 : Long.parseLong(lastPasswordUpdatedTime);
    }

    /**
     * This method retrieves the user store manager object from the user realm.
     *
     * @param userRealm the user realm to retrieve the user store manager from
     * @return the user store manager object
     * @throws PostAuthenticationFailedException if an error occurs while retrieving the user store manager
     */
    private static UserStoreManager getUserStoreManager(UserRealm userRealm) throws PostAuthenticationFailedException {

        UserStoreManager userStoreManager;
        try {
            userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw new PostAuthenticationFailedException(ERROR_WHILE_GETTING_USER_STORE_DOMAIN.getCode(),
                    ERROR_WHILE_GETTING_USER_STORE_DOMAIN.getMessage());
        }

        return userStoreManager;
    }

    /**
     * This method retrieves the user realm object for the given tenant domain.
     *
     * @param tenantDomain the tenant domain to retrieve the user realm for
     * @return the user realm object
     * @throws PostAuthenticationFailedException if an error occurs while retrieving the user realm
     */
    private static UserRealm getUserRealm(String tenantDomain) throws PostAuthenticationFailedException {

        UserRealm userRealm;
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = EnforcePasswordResetPostAuthenticationHandlerDataHolder.getInstance()
                    .getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw new PostAuthenticationFailedException(ERROR_WHILE_GETTING_USER_STORE_DOMAIN.getCode(),
                    ERROR_WHILE_GETTING_USER_STORE_DOMAIN.getMessage());
        }

        return userRealm;
    }

    /**
     * This method retrieves the password expiry in days configured for the given tenant domain.
     *
     * @param tenantDomain the tenant domain to retrieve the password expiry in days for
     * @param passwordExpiryInDays the default password expiry in days to use if none is configured
     * @return the password expiry in days
     * @throws PostAuthenticationFailedException if an error occurs while retrieving the password expiry configuration
     */
    private static int getPasswordExpiryInDays(String tenantDomain, int passwordExpiryInDays)
            throws PostAuthenticationFailedException {

        try {
            String passwordExpiryInDaysConfiguredValue = PasswordPolicyUtils.getResidentIdpProperty(tenantDomain,
                    PasswordPolicyConstants.CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS);
            return (passwordExpiryInDaysConfiguredValue != null) ? Integer.parseInt(passwordExpiryInDaysConfiguredValue)
                    : passwordExpiryInDays;
        } catch (AuthenticationFailedException e) {
            throw new PostAuthenticationFailedException(ERROR_WHILE_READING_SYSTEM_CONFIGURATIONS.getCode(),
                    ERROR_WHILE_READING_SYSTEM_CONFIGURATIONS.getMessage());
        }
    }

    /**
     * This method retrieves the password expiry in days configured for the given tenant domain.
     * @param passwordChangedTime the last password updated time in milliseconds
     * @return the number of days since the password was last updated
     */
    private static int getDaysDifference(long passwordChangedTime) {

        long currentTimeMillis = System.currentTimeMillis();
        int daysDifference = (int) ((currentTimeMillis - passwordChangedTime) / (1000 * 60 * 60 * 24));
        return daysDifference;
    }


    /**
     * This method retrieves the last password updated time from the user store.
     * @param tenantAwareUsername the tenant aware username of the user trying to authenticate
     * @param userStoreManager  the user store manager to retrieve the last password updated time from
     * @param userRealm the user realm to retrieve the claim manager from
     * @return the last password updated time
     * @throws PostAuthenticationFailedException
     */
    private String getLastPasswordUpdatedTime(String tenantAwareUsername,
                                              UserStoreManager userStoreManager,
                                              UserRealm userRealm) throws PostAuthenticationFailedException {

        String lastPasswordUpdatedTime;
        String claimURI = PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM;
        try {
            lastPasswordUpdatedTime = getLastPasswordUpdateTime(userStoreManager, claimURI, tenantAwareUsername);
            if (StringUtils.isEmpty(lastPasswordUpdatedTime)) {
                ClaimManager claimManager = userRealm.getClaimManager();
                claimURI = PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM_NON_IDENTITY;
                if (claimManager.getClaim(claimURI) != null) {
                    lastPasswordUpdatedTime =
                            getLastPasswordUpdateTime(userStoreManager, claimURI, tenantAwareUsername);
                }
            }
        } catch (UserStoreException e) {
            throw new PostAuthenticationFailedException(ERROR_WHILE_GETTING_CLAIM_MAPPINGS.getCode(),
                    ERROR_WHILE_GETTING_CLAIM_MAPPINGS.getMessage() + claimURI);
        }

        return lastPasswordUpdatedTime;
    }

    /**
     * This method retrieves the last password updated time for a given user.
     * @param userStoreManager user store manager instance used to retrieve user claim
     * @param claimURI the URI of the claim to retrieve
     * @param tenantAwareUsername the username of the user to retrieve the claim value
     * @return the last password updated time
     * @throws UserStoreException if an error occurs while retrieving the claim value
     */
    private String getLastPasswordUpdateTime(UserStoreManager userStoreManager, String claimURI,
                                             String tenantAwareUsername) throws UserStoreException {

        String[] claimURIs = new String[]{claimURI};
        Map<String, String> claimValueMap =
                userStoreManager.getUserClaimValues(tenantAwareUsername, claimURIs, null);
        if (claimValueMap != null && claimValueMap.get(claimURI) != null) {
            return claimValueMap.get(claimURI);
        }

        return StringUtils.EMPTY;
    }

}
