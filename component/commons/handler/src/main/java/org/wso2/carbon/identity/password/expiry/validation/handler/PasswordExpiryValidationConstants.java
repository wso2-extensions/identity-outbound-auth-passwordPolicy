/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.password.expiry.validation.handler;

/**
 * Password expiry validation comments.
 */
public class PasswordExpiryValidationConstants {

    public static final String LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM =
            "http://wso2.org/claims/identity/lastPasswordUpdateTime";
    public static final String CREATED_CLAIM = "http://wso2.org/claims/created";
    public static final String CREATED_CLAIM_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    public static final String CREATED_CLAIM_TIMEZONE = "GMT";
    public static final String PASSWORD_CHANGE_EVENT_HANDLER_NAME = "passwordExpiry";
    public static final String CONFIG_PASSWORD_EXPIRY_IN_DAYS = "passwordExpiry.passwordExpiryInDays";
    public static final String PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE = "30";
    public static final String PASSWORD_EXPIRED_ERROR_MESSAGE = "Password has expired";
    public static final String PASSWORD_EXPIRY_VALIDATION_EVENT_HANDLER_NAME = "passwordExpiryValidation";
    public static final String LAST_CREDENTIAL_CHANGED_TIMESTAMP_CLAIM_NON_IDENTITY =
            "http://wso2.org/claims/lastPasswordChangedTimestamp";
    public static final String AUTHENTICATION_STATUS = "authenticationStatus";

}
