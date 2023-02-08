package org.wso2.carbon.identity.password.expiry.validation.handler;

public class PasswordExpiryValidationConstants {

    public static final String LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM =
            "http://wso2.org/claims/identity/lastPasswordUpdateTime";
    public static final String CREATED_CLAIM = "http://wso2.org/claims/created";
    public static final String CREATED_CLAIM_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    public static final String CREATED_CLAIM_TIMEZONE = "GMT";
    public static final String PASSWORD_CHANGE_EVENT_HANDLER_NAME = "passwordExpiry";
    public static final String CONFIG_PASSWORD_EXPIRY_IN_DAYS = "passwordExpiry.passwordExpiryInDays";
    public static final String LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM_NON_IDENTITY =
            "http://wso2.org/claims/lastPasswordChangedTimestamp";
    public static final String PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE = "30";

}
