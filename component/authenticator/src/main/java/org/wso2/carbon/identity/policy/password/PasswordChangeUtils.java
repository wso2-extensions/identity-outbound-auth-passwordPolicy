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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Utilities for password change enforcing.
 */
public class PasswordChangeUtils {
    private static final Log log = LogFactory.getLog(PasswordChangeUtils.class);

    private static Properties properties = new Properties();

    static {
        loadProperties();
    }

    private PasswordChangeUtils() {
    }

    /**
     * loading the identity-mgt.properties file.
     */
    public static void loadProperties() {
        String configDirectoryPath = CarbonUtils.getCarbonConfigDirPath() + File.separator
                + "identity" + File.separator;
        String configFilePath = configDirectoryPath + PasswordChangeEnforceConstants.IDM_PROPERTIES_FILE;

        try (FileInputStream fileInputStream = new FileInputStream(new File(configFilePath))) {
            properties.load(fileInputStream);
        } catch (IOException e) {
            throw new RuntimeException("identity-mgt.properties file reading error from " + configDirectoryPath, e);
        }
    }

    /**
     * Get the password expiration days.
     *
     * @return The number of days to password expiration from the day of last password change
     */
    public static int getPasswordExpirationInDays() {
        int passwordExpirationInDays = PasswordChangeEnforceConstants.DEFAULT_CREDENTIAL_EXP_IN_DAYS;
        if (properties.get(PasswordChangeEnforceConstants.CREDENTIAL_EXP_IN_DAYS) != null) {
            String passwordExpPropertyValue =
                    (String) properties.get(PasswordChangeEnforceConstants.CREDENTIAL_EXP_IN_DAYS);
            try {
                passwordExpirationInDays = Integer.parseInt(passwordExpPropertyValue);
            } catch (NumberFormatException e) {
                log.warn(String.format("Invalid value: %s for property %s. " +
                                "The password expiration time should be an integer. " +
                                "Returning default password expiration time: %d days.",
                        passwordExpPropertyValue, PasswordChangeEnforceConstants.CREDENTIAL_EXP_IN_DAYS,
                        PasswordChangeEnforceConstants.DEFAULT_CREDENTIAL_EXP_IN_DAYS));
            }
        }
        return passwordExpirationInDays;
    }
}
