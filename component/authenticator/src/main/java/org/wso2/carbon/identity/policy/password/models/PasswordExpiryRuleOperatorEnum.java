/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.policy.password.models;

/**
 * Enum for the password expiry operator types.
 * @deprecated
 * {@link org.wso2.carbon.identity.password.expiry.models.PasswordExpiryRuleOperatorEnum} should be used instead.
 * This class is deprecated and org.wso2.carbon.identity.password.expiry.models.PasswordExpiryRuleOperatorEnum
 * has been introduced as alternative.
 */
@Deprecated
public enum PasswordExpiryRuleOperatorEnum {

    EQ("eq"),
    NE("ne");

    private final String value;

    PasswordExpiryRuleOperatorEnum(String value) {

        this.value = value;
    }

    public String getValue() {

        return value;
    }

    public static PasswordExpiryRuleOperatorEnum fromString(String text) {

        for (PasswordExpiryRuleOperatorEnum operator : PasswordExpiryRuleOperatorEnum.values()) {
            if (operator.value.equalsIgnoreCase(text)) {
                return operator;
            }
        }
        throw new IllegalArgumentException("No enum constant with text " + text + " found");
    }
}
