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

package org.wso2.carbon.identity.policy.password.internal;

import org.wso2.carbon.event.stream.core.EventStreamService;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;

/**
 * The data holder for the password reset enforcer.
 */
public class PasswordResetEnforcerDataHolder {
    private static PasswordResetEnforcerDataHolder instance;

    private EventStreamService eventStreamService;
    private IdentityGovernanceService identityGovernanceService;
    private ApplicationManagementService applicationManagementService;

    private PasswordResetEnforcerDataHolder() {     // Prevent instantiation
    }

    /**
     * Return a singleton instance of the PasswordResetEnforcerDataHolder
     *
     * @return A singleton instance of the PasswordResetEnforcerDataHolder
     */
    public static PasswordResetEnforcerDataHolder getInstance() {
        if (instance == null) {
            instance = new PasswordResetEnforcerDataHolder();
        }
        return instance;
    }

    public EventStreamService getEventStreamService() {
        return eventStreamService;
    }

    public void setEventStreamService(EventStreamService eventStreamService) {
        this.eventStreamService = eventStreamService;
    }

    public IdentityGovernanceService getIdentityGovernanceService() {
        return identityGovernanceService;
    }

    public void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {
        this.identityGovernanceService = identityGovernanceService;
    }

    public ApplicationManagementService getApplicationManagementService() {
        return applicationManagementService;
    }

    public void setApplicationManagementService(ApplicationManagementService applicationManagementService) {
        this.applicationManagementService = applicationManagementService;
    }
}
