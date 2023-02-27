/*
 *  Copyright (c) 2023, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.post.authn.handler.passwordPolicyEnforcer;

/**
 * Password Change authenticator's constants
 */
public class PasswordPolicyConstants {
    public static final String AUTHENTICATOR_TYPE = "LOCAL";
    public static final String LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM =
            "http://wso2.org/claims/identity/lastPasswordUpdateTime";
    public static final String LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM_NON_IDENTITY =
            "http://wso2.org/claims/lastPasswordChangedTimestamp";
    public static final String PASSWORD_CHANGE_STREAM_NAME =
            "org.wso2.carbon.identity.policy.password.PendingNotifications:1.0.0";
    public static final String PASSWORD_CHANGE_EVENT_HANDLER_NAME = "passwordExpiry";
    public static final String CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS = "passwordExpiry.passwordExpiryInDays";
    public static final String CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DISPLAYED_NAME = "Password Expiry In Days";
    public static final String CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DESCRIPTION =
            "Number of days after which the password will expire";
    public static final int CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE = 30;
    public static final String CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS = "passwordExpiry.enableEmailNotifications";
    public static final String CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS_DISPLAYED_NAME =
            "Enable Sending Email Notifications";
    public static final String CONNECTOR_CONFIG_PRIOR_REMINDER_TIME_IN_DAYS = "passwordExpiry.priorReminderTimeInDays";
    public static final String CONNECTOR_CONFIG_PRIOR_REMINDER_TIME_IN_DAYS_DISPLAYED_NAME =
            "Prior Reminder Time In Days";
    public static final String ENFORCE_PASSWORD_RESET_HANDLER = "EnforcePasswordResetHandler";
    public static final String BASIC_AUTHENTICATOR = "BasicAuthenticator";

    public enum ErrorMessages {
        ERROR_WHILE_GETTING_FEDERATED_USERNAME("80027", "Error while getting the federated username"),
        ERROR_WHILE_GETTING_USER_STORE_DOMAIN("80020", "Error occurred while getting the user store domain."),
        ERROR_WHILE_GETTING_USER_REALM("80029", "Error occurred while getting the user realm."),
        ERROR_WHILE_GETTING_CLAIM_MAPPINGS("80013", "Error while getting claim mappings for user, %s"),
        ERROR_WHILE_READING_SYSTEM_CONFIGURATIONS("80028", "Error while reading the configurations.");
        private final String code;
        private final String message;

        /**
         * Create an Error Message.
         *
         * @param code    Relevant error code.
         * @param message Relevant error message.
         */
        ErrorMessages(String code, String message) {
            this.code = code;
            this.message = message;
        }

        /**
         * To get the code of specific error.
         *
         * @return Error code.
         */
        public String getCode() {
            return code;
        }

        /**
         * To get the message of specific error.
         *
         * @return Error message.
         */
        public String getMessage() {
            return message;
        }

        @Override
        public String toString() {
            return code + " - " + message;
        }
    }
}
