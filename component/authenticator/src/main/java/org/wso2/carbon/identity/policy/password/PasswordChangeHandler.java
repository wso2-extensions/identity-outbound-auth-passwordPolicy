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
import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.policy.password.internal.PasswordResetEnforcerDataHolder;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * This updates the http://wso2.org/claims/lastPasswordChangedTimestamp claim upon the password change.
 * This also publishes the password change event to IS Analytics.
 */
public class PasswordChangeHandler extends AbstractEventHandler {
    private static Log log = LogFactory.getLog(PasswordChangeHandler.class);

    @Override
    public void handleEvent(Event event) {
        // Fetching event properties
        String username = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_NAME);
        int tenantId = (int) event.getEventProperties().get(IdentityEventConstants.EventProperty.TENANT_ID);
        UserStoreManager userStoreManager = (UserStoreManager) event.getEventProperties()
                .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);

        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        long timestamp = System.currentTimeMillis();

        // Updating the last password changed claim
        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(PasswordChangeEnforceConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM, Long.toString(timestamp));
        try {
            userStoreManager.setUserClaimValues(username, claimMap, null);
            log.debug("The claim uri " + PasswordChangeEnforceConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM
                    + " of " + username + " updated with the current timestamp");
        } catch (UserStoreException e) {
            log.error("Failed to update claim value for "
                    + PasswordChangeEnforceConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM + " claim", e);
        }

        publishToISAnalytics(username, userStoreDomain, tenantId, userStoreManager, timestamp);
    }

    /**
     * Publish the password change event to IS Analytics
     *
     * @param username         The username of the user
     * @param userStoreDomain  The user store domain of the user
     * @param tenantId         The tenantID of the user
     * @param userStoreManager The user store manager of the user
     * @param timestamp        The password changed timestamp
     */
    private void publishToISAnalytics(String username, String userStoreDomain, int tenantId,
                                      UserStoreManager userStoreManager, long timestamp) {
        // Fetching the email
        String email = null;
        try {
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            email = userStoreManager.getUserClaimValue(tenantAwareUsername,
                    PasswordChangeEnforceConstants.EMAIL_ADDRESS_CLAIM, null);
        } catch (UserStoreException e) {
            log.error("Failed to fetch the tenant ID", e);
        }

        EventStreamService service = PasswordResetEnforcerDataHolder.getInstance().getEventStreamService();

        // Creating the event to be sent
        org.wso2.carbon.databridge.commons.Event dataBridgeEvent = new org.wso2.carbon.databridge.commons.Event();
        dataBridgeEvent.setTimeStamp(System.currentTimeMillis());
        dataBridgeEvent.setStreamId(PasswordChangeEnforceConstants.PASSWORD_CHANGE_STREAM_NAME);

        // Creating the payload data
        Object[] payloadData = new Object[5];
        payloadData[0] = tenantId;
        payloadData[1] = userStoreDomain;
        payloadData[2] = username;
        payloadData[3] = email;
        payloadData[4] = timestamp;
        dataBridgeEvent.setPayloadData(payloadData);

        service.publish(dataBridgeEvent);
        log.debug("Published " + dataBridgeEvent.toString() + " to IS Analytics");
    }

    @Override
    public String getName() {
        return PasswordChangeEnforceConstants.PASSWORD_CHANGE_EVENT_HANDLER_NAME;
    }
}
