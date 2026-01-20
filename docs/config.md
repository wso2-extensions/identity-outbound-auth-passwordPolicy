# Configuring Password Policy

* [Setting up Password Reset Enforcer](#setting-up-password-reset-enforcer)
* [Enabling the Password History Feature](#enabling-the-password-history-feature)
* [Enabling Email Notifications](#enabling-email-notifications)

## Setting up Password Reset Enforcer

### Deploying Artifacts

1. Download the Password Reset Enforcer and its artifacts from [WSO2 Store](https://store.wso2.com/connector/identity-outbound-auth-passwordPolicy).

2. Download the latest U2 updated IS pack from [here](https://wso2.com/identity-and-access-management/).

3. Add the following lines to `<IS_HOME>/repository/conf/deployment.toml` file

   ```
   [[event_handler]]
   name= "passwordExpiry"
   subscriptions =["POST_UPDATE_CREDENTIAL", "POST_UPDATE_CREDENTIAL_BY_ADMIN", "POST_ADD_USER"]
   [event_handler.properties]
   passwordExpiryInDays= "30"
   enableDataPublishing= false
   priorReminderTimeInDays= "0"
   ```
4. **(For WSO2 IS v7.0)** Add the following lines to `<IS_HOME>/repository/conf/deployment.toml` file. This configuration is to enable the password reset authenticator in the application step configurations.

   ```
   [authentication.authenticator.password-reset-enforcer]
   name = "password-reset-enforcer"
   enable = true
   ```
5. Copy the authentication page (`<PASSWORD_RESET_ENFORCER_ARTIFACTS>/is/pwd-reset.jsp`) to the `<IS_HOME>/repository/deployment/server/webapps/authenticationendpoint/` directory.
   
   > This directory is created after the first time you run Identity Server. If this is your first time, start the server once first.

6. Copy the connector (`org.wso2.carbon.extension.identity.authenticator.passwordpolicy.connector-<version>.jar`) to the `<IS_HOME>/repository/components/dropins/` directory.

> Please note that the Identity Server needs to be restarted after doing the above steps for the changes to take effect.

### Configuring the Expiration Policy

Follow the steps given below to configure the number of days after which the password should expire.

**For WSO2 IS v7.0 and above**

1. [Start](https://is.docs.wso2.com/en/latest/deploy/get-started/run-the-product/) the Identity Server and log in. (If you have not already done so)
2. Go to `Password Validation` section under `Login & Registration`.
3. Enable the `Password Expiration` and Change `Password Expiry In Days` according to your requirements.
   > By default, the Password Reset Enforcer will expire passwords in 30 days.
4. Click on`Update` button.

![Configuring the Expiration Policy](img/password-expiry-policy-config-is7.png "Configuring the Expiration Policy")

**For WSO2 IS below v7.0**

1. [Start](https://is.docs.wso2.com/en/6.1.0/deploy/get-started/run-the-product/) the Identity Server and log in. (If you have not already done so)
2. In the `Identity` section under the `Main` tab, click `Resident` under `Identity Providers`.
3. Go to `Password Expiry` under `Password Policies`.
4. Change `Password Expiry In Days` according to your requirements.
   
   > By default, the Password Reset Enforcer will expire passwords in 30 days.
5. Click `Update` to save the changes.

> `Enable Sending Email Notifications` and `Prior Reminder Time In Days` configurations are used for configuring [email notifications](#enabling-email-notifications).

![Configuring the Expiration Policy](img/password-expiry-policy-config.png "Configuring the Expiration Policy")

### Deploying the Sample App

This section explains how to use the Password Reset Enforcer using a sample app.
Deploy the sample web app [travelocity](https://is.docs.wso2.com/en/latest/guides/authentication/saml/saml-federated-idp-initiated-sso/#deploy-the-application).
Once this is done the next step is to configure the service provider.

#### Configuring the Service Provider for the Sample App

- Add the following line to the `/etc/hosts` file.
   ```
   127.0.0.1       wso2is.local
   ```
   > Some browsers do not allow you to create cookies for a naked hostname, such as localhost. Cookies are required when working with SSO. Therefore, to ensure that the SSO capabilities work as expected in this tutorial, you need to configure the etc/host file as explained in this step.

**For WSO2 IS v7.0 and above**

1. [Start](https://is.docs.wso2.com/en/latest/deploy/get-started/run-the-product/) the Identity Server and log in. (If you have not already done so)
2. In the `Applications` section, Click on `New Application` button.
3. Select `Traditional Web Application` template.
4. Select `SAML`, Provide the below details to and Click on `Create` button.
   * Name: `travelocity.com`
   * Issuer: `travelocity.com`
   * Assertion Consumer URL: `http://wso2is.local:8080/travelocity.com/home.jsp`
5. Enable the following options under protocol section of the created application.
   * Response Signing
   * Single Logout
   * Attribute Profile
   * Include Attributes in the Response Always
   > The above options should be enabled or disabled according to your service provider. For travelocity, the relevant properties file (`travelocity.properties`) can be found inside the webapp `travelocy.com/WEB-INF/classes/`.

   ![Configuring SAML SSO](img/create-application-is7.png "Configuring SAML SSO")

   
**For WSO2 IS below v7.0**

1. [Start](https://is.docs.wso2.com/en/6.1.0/deploy/get-started/run-the-product/) the Identity Server and log in. (If you have not already done so)
2. In the `Identity` section under the `Main` tab, click `Add` under `Service Providers`.
3. Enter `travelocity.com` in the `Service Provider Name` text box and click `Register`.
   ![Adding Service Provider](img/add-service-provider.png "Adding Service Provider")
4. In the `Inbound Authentication Configuration` section, click `Configure` under the `SAML2 Web SSO Configuration` section.
5. Configure the sample application (travelocity) as the service provider.
   * Issuer: `travelocity.com`
   * Assertion Consumer URL: `http://wso2is.local:8080/travelocity.com/home.jsp`
6. Enable the following options.
   * Response Signing
   * Single Logout
   * Attribute Profile
   * Include Attributes in the Response Always
   
   > The above options should be enabled or disabled according to your service provider. For travelocity, the relevant properties file (`travelocity.properties`) can be found inside the webapp `travelocy.com/WEB-INF/classes/`.
7. Click `Register` to save the changes. Now you will be sent back to the Service Providers page.
   ![Configuring SAML SSO](img/configure-saml-sso.png "Configuring SAML SSO")


Follow the next few steps to add the password policy to the sample app

**For WSO2 IS v7.0 and above**

1. Go to the `Applications` section and select the created application.
2. Go to the `Login Flow` tab of the application.
3. Click on the `+` button to add a new step to the login flow.
4. Select the `Password Reset Enforcer` authenticator and click `Add` button.
5. Click on the `Update` button to save the changes.

   ![Authentication Configuration](img/authentication-configuration-is7.png "Authentication Configuration")

**For WSO2 IS below v7.0**

1. Go to `Local and Outbound Authentication Configuration` section in the Service Providers page.
2. Select the `Advanced Configuration` radio button option.
3. Add the `basic` authentication as the first step and `Password Reset Enforcer` authentication as the second step.
   * Select `User subject identifier from this step` under `basic` authentication.
   * Select `Use attributes from this step` under `Password Reset Enforcer`.
   ![Authentication Configuration](img/authentication-configuration.png "Authentication Configuration")
4. Click `Update` to save the changes.

#### Testing the Sample App

Follow the steps given below to test the Password Reset Enforcer.

> These steps should not be followed in a production environment. Therefore if you follow these steps make sure you change it back to the original state accordingly before moving to a production environment.

1. In the `Identity` section under the `Main` tab, click `List` under `Claims`.
2. Click `http://wso2.org/claims`.
3. Click `Edit` next to `Last Password Update` claim.
4. To test the sample, the password needs be expired manually. To edit the claim manually later, select `Supported by Default` checkbox.
5. Click `Update` to save the changes.
   ![Updating the Claim](img/update-claim.png "Updating the Claim")
6. In the `Identity` section under the `Main` tab, click `List` under `Users and Roles` and then click `Users`.
7. Click `User Profile` next to the `admin` user (Or any preferred user).
8. Edit `Last Password Update` to a lower number (This is the last password change timestamp in milliseconds).
9. Click `Update` to save the changes.
   ![Updating the Claim Value](img/update-claim-value.png "Updating the Claim Value")
10. Now try to log in to travelocity by going to `http://wso2is.local:8080/travelocity.com` and selecting a SAML SSO login option.
11. You will be requested to change the password.

## Enabling the Password History Feature

You can use the password history feature available on the Identity Server along with the password policy.
This will force the users to not use a previously used password again for a number of times into the future.
Please follow the instructions given in the [Password History Validation Policy](https://is.docs.wso2.com/en/latest/guides/account-configurations/login-security/password-validation/#password-history-count) to enable this feature.

## Enabling Email Notifications

> This feature is only supported for IS versions 5.6.0 .

To enable email notifications you need [WSO2 IS Analytics](https://wso2.com/identity-and-access-management) Instance running alongside the WSO2 Identity Server.

> Please note that the users need to have an email specified in the Identity Server. Otherwise, the expired passwords will only be logged in IS Analytics.

> Email notifications won't be sent to existing users until they change the password again.

### Setting up IS Analytics

#### Configuring Email Adapter

To enable IS Analytics to send emails the email output adapter needs to be configured. Follow the steps given below to configure it.

Edit the `<IS_ANALYTICS_HOME>/repository/conf/output-event-adapters.xml` file and change the following lines. Valid SMTP configuration should be provided to enable emails.
```xml
<adapterConfig type="email">
    <property key="mail.smtp.from">email-address</property>
    <property key="mail.smtp.user">user-name</property>
    <property key="mail.smtp.password">password</property>
    <property key="mail.smtp.host">smtp.gmail.com</property>
    <property key="mail.smtp.port">587</property>
    <property key="mail.smtp.starttls.enable">true</property>
    <property key="mail.smtp.auth">true</property>
    <!-- Thread Pool Related Properties -->
    <property key="maxThread">100</property>
    <property key="keepAliveTimeInMillis">20000</property>
    <property key="jobQueueSize">10000</property>
</adapterConfig>
```
> * In gmail [account security settings](https://myaccount.google.com/security) you may have to enable "Allow less secure apps" option in order to connect account to WSO2 products.
> * When SMTP is used with SSL, it is required to extract the certificate of the email server and add it to the trust store of WSO2 DAS. For detailed instructions, see [Creating New Keystores - Adding the public key to client-truststore.jks](https://docs.wso2.com/display/DAS300/Creating+New+Keystores#CreatingNewKeystores-AddPublicKey).

Please note that the server needs to be restarted for the changes to take effect. (We can restart the server in the next section deploying artifacts.)

#### Deploying Artifacts

The following artifacts need to be deployed for IS Analytics to work properly

1. Copy the domain template (`<PASSWORD_RESET_ENFORCER_ARTIFACTS>/is-analytics/password-policy-notifications.xml`) to the `<IS_ANALYTICS_HOME>/repository/conf/template-manager/domain-template/` directory.
2. Copy the email event publisher (`<PASSWORD_RESET_ENFORCER_ARTIFACTS>/is-analytics/PasswordPolicy-Publisher-email-Notifications-1.0.0.xml`) to the `<IS_ANALYTICS_HOME>/repository/deployment/server/eventpublishers/` directory.
   You may edit the `<inline>` tag in this file to change the email template according to your requirements.
3. [Start](https://docs.wso2.com/display/DAS310/Running+the+Product) the IS Analytics Server and log in. (Restart the server if the server is already running)
4. Install Password Reset Enforcer Carbon App (`<PASSWORD_RESET_ENFORCER_ARTIFACTS>/is-analytics/password_policy.car`)

#### Configuring IS Analytics

For IS Analytics to send notifications a new scenario needs to be added in the Template Manager. Follow the steps given below to create a new scenario.

1. [Start](https://docs.wso2.com/display/DAS310/Running+the+Product) the IS Analytics Server and log in. (If you have not already done so)
2. In the `Dashboard` section under the `Main` tab, click the `Template Manager`.
3. In the new window that appears, Select the PasswordRotationPolicyNotifications domain.
4. Click `Create New Scenario`.
5. Enter the following parameters.
   * Scenario Name - A name to recognize the scenario
   * Description - A description of the scenario
   * Periodic Task interval in days - The interval between two expired password check task runs. Be mindful of this as this will affect the exact day on which the reminder will be sent.
6. Click `Add Scenario`.
   ![Adding Scenario](img/add-scenario.png "Adding Scenario")

### Setting up Identity Server

#### Enabling Data Publishers

* Add the following lines to <IS_HOME>/repository/conf/identity/identity-event.properties file.

```xml
module.name.13=userOperationDataDASPublisher
userOperationDataDASPublisher.subscription.1=POST_UPDATE_CREDENTIAL
userOperationDataDASPublisher.subscription.2=POST_UPDATE_CREDENTIAL_BY_ADMIN
userOperationDataDASPublisher.subscription.3=POST_ADD_USER
userOperationDataDASPublisher.subscription.4=POST_DELETE_USER
userOperationDataDASPublisher.subscription.5=POST_SET_USER_CLAIMS
```
 > Replace the module number `13` in `module.name.13=passwordExpiry` to one higher than the largest module number in the `identity-event.properties` file.

* Follow the below steps to configure Identity Properties Update Audit Data Publishers:

1. Copy the `<PASSWORD_RESET_ENFORCER_ARTIFACTS>/is/org.wso2.carbon.identity.data.publisher.audit.idp.properties-x.x.x.jar ` file to `<IS_HOME>/repository/component/dropins/ directory`.

2. Copy the       `<PASSWORD_RESET_ENFORCER_ARTIFACTS>/is/org.wso2.is.analytics.stream.IdPPropertiesUpdate_1.0.0.json` file to `<IS_HOME>/repository/deployment/server/eventstreams/ directory`.

3. Copy the  
`<PASSWORD_RESET_ENFORCER_ARTIFACTS>/is/IsAnalytics-Publisher-wso2event-IdPPropertiesUpdate.xml` file to `<IS_HOME>/repository/deployment/server/eventpublishers/ directory`.

4. Add the following lines to `<IS_HOME>/repository/conf/identity/identity.xml ` file under the `<EventListeners> ` tag.

```xml
<EventListener type="org.wso2.carbon.idp.mgt.listener.IdentityProviderMgtListener"           name="org.wso2.carbon.identity.data.publisher.audit.idp.properties.impl.ResidentIdPPropertiesDataPublisher" orderId="200" enable="true"/>
```
> Please note that the user emails and some of the configurations will be saved in IS Analytics tables if you enable these data publishers. Upon user deletion in the Identity Server, the emails will be deleted from the tables in IS Analytics as well.


* Follow the steps below to configure user-operations audit data publishers:

1. Copy the `org.wso2.carbon.identity.data.publisher.audit.user.operation-x.x.x.jar` file from the `<IS_HOME>/repository/components/plugins/`  directory to the  `<IS_HOME>/repository/component/dropins/` directory.

2. Copy the `org.wso2.is.analytics.stream.OverallUserData_x.x.x.json` file from the  `<IS_HOME>/repository/components/features/org.wso2.carbon.identity.data.publisher.audit.user.operation.server_x.x.x/`  directory to the `<IS_HOME>/repository/deployment/server/eventstreams/` directory.

#### Configuring Identity Server

Follow the steps given below to enable notifications

1. [Start](https://docs.wso2.com/display/IS540/Running+the+Product) the Identity Server and log in. (If you have not already done so)
2. In the `Identity` section under the `Main` tab, click `Resident` under `Identity Providers`.
3. Go to `Password Expiry` under `Password Policies`.
4. Enable the `Enable Sending Email Notifications` option.
4. Change `Prior Reminder Time In Days` according to your requirements.
   
   > By default, the Password Reset Enforcer will send notifications 0 days prior to the password expiry (after password expiry).
5. Click `Update` to save the changes.

![Configuring the Email Notifications](img/enable-email-notification-config.png "Configuring the Email Notifications")

> Please make sure that the users have an email saved (Upon updating the email it will be sent to IS Analytics.) in the Identity Server. If they don't the expired password notifications will only be logged in IS Analytics.

Now IS Analytics will check for expired passwords at the interval specified and send email notifications to the relevant users.

## Setting up Password Expiry Validation in Password Grant Flow

These steps can be followed to enable validating the user password expiry in password grant. This will pass an error message in response if the user password is expired.

1. Follow steps in [Setting up Password Reset Enforcer](#setting-up-password-reset-enforcer)
2. Add **PASSWORD_GRANT_POST_AUTHENTICATION** to subscriptions of *passwordExpiry* event handler in `<IS_HOME>/repository/conf/deployment.toml` file

 ```
   [[event_handler]]
   name= "passwordExpiry"
   subscriptions =["POST_UPDATE_CREDENTIAL", "POST_UPDATE_CREDENTIAL_BY_ADMIN", "POST_ADD_USER", "PASSWORD_GRANT_POST_AUTHENTICATION"]
   [event_handler.properties]
   passwordExpiryInDays= "30"
   enableDataPublishing= false
   priorReminderTimeInDays= "0"
   ```
3. Restart the WSO2 Identity Server

#### Try Example

1. Run following curl command with proper attribute values to the `client_id`, `client_secret`, `username`, `password`, `redirect_uri`

```
curl -v -X POST --basic -u <client_id>:<client_secret> -H 'Content-Type: application/x-www-form-urlencoded;charset=UTF-8' -k -d 'grant_type=password&username=<username>&password=<password>&redirect_uri=<redirect_uri>&scope=openid' https://<host>:<port>/oauth2/token
```
2. If user's password is expired then the response will be HTTP 400 error with following error message.

```
{"error_description":"Password has expired","error":"invalid_grant"}
```
