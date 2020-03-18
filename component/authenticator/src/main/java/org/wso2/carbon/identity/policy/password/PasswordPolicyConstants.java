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

package org.wso2.carbon.identity.policy.password;

/**
 * Password Change authenticator's constants
 */
public class PasswordPolicyConstants {
    public static final String AUTHENTICATOR_NAME = "password-reset-enforcer";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Password Reset Enforcer";
    public static final String AUTHENTICATOR_TYPE = "LOCAL";
    public static final String STATE = "state";

    public static final String CURRENT_PWD = "CURRENT_PWD";
    public static final String NEW_PWD = "NEW_PWD";
    public static final String NEW_PWD_CONFIRMATION = "NEW_PWD_CONFIRMATION";

    public static final String LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM =
            "http://wso2.org/claims/identity/lastPasswordUpdateTime";

    public static final String PASSWORD_CHANGE_STREAM_NAME =
            "org.wso2.carbon.identity.policy.password.PendingNotifications:1.0.0";
    public static final String PASSWORD_CHANGE_EVENT_HANDLER_NAME = "passwordExpiry";

    public static final String CONNECTOR_CONFIG_FRIENDLY_NAME = "Password Expiry";
    public static final String CONNECTOR_CONFIG_CATEGORY = "Password Policies";
    public static final String CONNECTOR_CONFIG_SUB_CATEGORY = "DEFAULT";

    public static final String CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS = "passwordExpiry.passwordExpiryInDays";
    public static final String CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DISPLAYED_NAME = "Password Expiry In Days";
    public static final String CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DESCRIPTION =
            "Number of days after which the password will expire";
    public static final int CONNECTOR_CONFIG_PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE = 30;

    public static final String CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS = "passwordExpiry.enableEmailNotifications";
    public static final String CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS_DISPLAYED_NAME =
            "Enable Sending Email Notifications";
    public static final String CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS_DESCRIPTION =
            "Enable to send email notifications to reset the password. " +
                    "This requires an IS Analytics instance.";
    public static final boolean CONNECTOR_CONFIG_ENABLE_EMAIL_NOTIFICATIONS_DEFAULT_VALUE = false;

    public static final String CONNECTOR_CONFIG_PRIOR_REMINDER_TIME_IN_DAYS = "passwordExpiry.priorReminderTimeInDays";
    public static final String CONNECTOR_CONFIG_PRIOR_REMINDER_TIME_IN_DAYS_DISPLAYED_NAME =
            "Prior Reminder Time In Days";
    public static final String CONNECTOR_CONFIG_PRIOR_REMINDER_TIME_IN_DAYS_DESCRIPTION =
            "Number of days before the password expiry that the users should be reminded of password expiry";
    public static final int CONNECTOR_CONFIG_PRIOR_NOTICE_TIME_IN_DAYS_DEFAULT_VALUE = 0;

    public static final String LOGIN_STANDARD_PAGE = "login.do";
    public static final String PASSWORD_RESET_ENFORCER_PAGE = "pwd-reset.jsp";
    public static final String PASSWORD_HISTORY_VIOLATION_ERROR_CODE = "22001";
    public static final String LAST_FAILED_AUTHENTICATOR = "LastFailedAuthenticator";

    private PasswordPolicyConstants() {      // To prevent instantiation
    }
}
