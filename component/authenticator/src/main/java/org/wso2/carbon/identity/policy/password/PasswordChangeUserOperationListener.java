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
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserOperationEventListener;

import java.util.HashMap;
import java.util.Map;

/**
 * the responsibility of this class is to update the user claim
 * http://wso2.org/claims/lastPasswordChangedTimestamp upon the password change.
 */
public class PasswordChangeUserOperationListener extends AbstractUserOperationEventListener {

    private static Log log = LogFactory.getLog(PasswordChangeUserOperationListener.class);

    @Override
    public int getExecutionOrderId() {
        return 1356;
    }

    /**
     * Add current time to lastPasswordChangedTimestamp claim after changing the password by admin.
     *
     * @param userName         the user name
     * @param credential       the user's credential
     * @param userStoreManager the user store manager
     */
    @Override
    public boolean doPostUpdateCredentialByAdmin(String userName, Object credential, UserStoreManager userStoreManager)
            throws UserStoreException {
        Map<String, String> claimMap = new HashMap<String, String>();
        long timestamp = System.currentTimeMillis();
        claimMap.put(PasswordChangeUtils.LAST_PASSWORD_CHANGED_TIMESTAMP_CLAIM, Long.toString(timestamp));
        userStoreManager.setUserClaimValues(userName, claimMap, null);
        if (log.isDebugEnabled()) {
            log.debug("The claim uri" + PasswordChangeUtils.LAST_PASSWORD_CHANGED_TIMESTAMP_CLAIM + "of " + userName
                    + " updated with the current timestamp");
        }
        return true;
    }

    /**
     * Add current time to lastPasswordChangedTimestamp claim after changing the password by user.
     *
     * @param userName         the user name
     * @param credential       the user's credential
     * @param userStoreManager the user store manager
     */
    @Override
    public boolean doPostUpdateCredential(String userName, Object credential, UserStoreManager userStoreManager)
            throws UserStoreException {
        Map<String, String> claimMap = new HashMap<String, String>();
        long timestamp = System.currentTimeMillis();
        claimMap.put(PasswordChangeUtils.LAST_PASSWORD_CHANGED_TIMESTAMP_CLAIM, Long.toString(timestamp));
        userStoreManager.setUserClaimValues(userName, claimMap, null);
        if (log.isDebugEnabled()) {
            log.debug("The claim uri " + PasswordChangeUtils.LAST_PASSWORD_CHANGED_TIMESTAMP_CLAIM + "of " + userName
                    + " updated with the current timestamp");
        }
        return true;
    }
}
