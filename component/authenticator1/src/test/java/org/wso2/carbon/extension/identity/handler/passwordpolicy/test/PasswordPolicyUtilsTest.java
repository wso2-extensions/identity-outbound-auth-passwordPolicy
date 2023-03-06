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

package org.wso2.carbon.extension.identity.handler.passwordpolicy.test;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.post.authn.handler.disclaimer.PasswordPolicyUtils;

/**
 * Tests for password change utils
 */
public class PasswordPolicyUtilsTest {
    private static final String TENANT_DOMAIN = "carbon.super";

    @Test
    public void testGetPasswordExpiryPropertyNames() {
        String[] passwordExpiryPropertyNames = PasswordPolicyUtils.getPasswordExpiryPropertyNames();
        Assert.assertEquals(passwordExpiryPropertyNames.length, 3);
    }
}
