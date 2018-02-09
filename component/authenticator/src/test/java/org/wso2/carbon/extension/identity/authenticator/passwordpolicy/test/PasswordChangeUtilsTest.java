/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.extension.identity.authenticator.passwordpolicy.test;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.policy.password.PasswordChangeEnforceConstants;
import org.wso2.carbon.identity.policy.password.PasswordChangeUtils;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Properties;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

/**
 * Tests for password change utils
 */
@PrepareForTest({CarbonUtils.class})
public class PasswordChangeUtilsTest {
    @BeforeMethod
    public void setUp() {
        mockStatic(CarbonUtils.class);
        String path = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        when(CarbonUtils.getCarbonConfigDirPath()).thenReturn(path);

        Whitebox.setInternalState(PasswordChangeUtils.class, "properties", new Properties());
        PasswordChangeUtils.loadProperties();
    }

    @Test
    public void testGetPasswordExpirationInDaysWithProperties() {
        // "1" is set as "password expiration in days" in the config file in test resources
        Assert.assertEquals(PasswordChangeUtils.getPasswordExpirationInDays(), 1);
    }

    @Test
    public void testGetPasswordExpirationInDaysWithoutProperties() {
        PasswordChangeUtils.getPasswordExpirationInDays();  // To run the static block

        Properties properties = Whitebox.getInternalState(PasswordChangeUtils.class, "properties");
        properties.clear();

        Assert.assertEquals(PasswordChangeUtils.getPasswordExpirationInDays(),
                PasswordChangeEnforceConstants.DEFAULT_CREDENTIAL_EXP_IN_DAYS);
    }

    @Test
    public void testGetPasswordExpirationInDaysWithInvalidProperties() {
        PasswordChangeUtils.getPasswordExpirationInDays();  // To run the static block

        // Setting a string as the password expiration in days
        Properties properties = Whitebox.getInternalState(PasswordChangeUtils.class, "properties");
        properties.setProperty(PasswordChangeEnforceConstants.CREDENTIAL_EXP_IN_DAYS, "invalid-integer");

        Assert.assertEquals(PasswordChangeUtils.getPasswordExpirationInDays(),
                PasswordChangeEnforceConstants.DEFAULT_CREDENTIAL_EXP_IN_DAYS);
    }

    @Test(expectedExceptions = {RuntimeException.class})
    public void testLoadPropertiesWithIOException() throws Exception {
        Properties properties = spy(new Properties());
        doThrow(new IOException("Dummy exception")).when(properties).load(any(FileInputStream.class));
        Whitebox.setInternalState(PasswordChangeUtils.class, "properties", properties);

        PasswordChangeUtils.loadProperties();
        Assert.assertEquals(PasswordChangeUtils.getPasswordExpirationInDays(),
                PasswordChangeEnforceConstants.DEFAULT_CREDENTIAL_EXP_IN_DAYS);
    }
}
