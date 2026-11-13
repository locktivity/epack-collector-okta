# Okta API coverage

What the collector reads of the Okta API, and what it leaves out, checked against the Okta API description at revision ec20a8e9f2f2: https://github.com/okta/okta-management-openapi-spec, dist/current/management-oneOfInheritance-noExamples.yaml.

| | Operations |
|---|---|
| In the description | 726 |
| Read operations in scope | 286 |
| Called by the collector | 19 |
| Not collected | 162, in 17 items |
| Left out as irrelevant | 105 |

## What the collector reads

- **api-tokens:** `listApiTokens` (GET /api/v1/api-tokens)
- **apps:** `listApplications` (GET /api/v1/apps)
- **authenticators:** `listAuthenticators` (GET /api/v1/authenticators)
- **device-assurances:** `listDeviceAssurancePolicies` (GET /api/v1/device-assurances)
- **eventHooks:** `listEventHooks` (GET /api/v1/eventHooks)
- **groups:** `listGroups` (GET /api/v1/groups); `listGroupUsers` (GET /api/v1/groups/{groupId}/users)
- **iam:** `listUsersWithRoleAssignments` (GET /api/v1/iam/assignees/users); `listRoles` (GET /api/v1/iam/roles)
- **idps:** `listIdentityProviders` (GET /api/v1/idps)
- **inlineHooks:** `listInlineHooks` (GET /api/v1/inlineHooks)
- **logs:** `listLogEvents` (GET /api/v1/logs)
- **org:** `getOrgSettings` (GET /api/v1/org)
- **policies:** `listPolicies` (GET /api/v1/policies); `listPolicyRules` (GET /api/v1/policies/{policyId}/rules)
- **users:** `listUsers` (GET /api/v1/users); `listFactors` (GET /api/v1/users/{userId}/factors); `listAssignedRolesForUser` (GET /api/v1/users/{userId}/roles)
- **zones:** `listNetworkZones` (GET /api/v1/zones)

## Not collected

### Devices

The devices users enroll in Okta Verify, with each device's OS version and disk encryption, the operating system accounts on them, device integrations, and device posture checks. The collector reads the device assurance policies and writes no endpoint-posture file.

- `listDeviceIntegrations` (GET /api/v1/device-integrations)
- `getDeviceIntegration` (GET /api/v1/device-integrations/{deviceIntegrationId})
- `listDevicePostureChecks` (GET /api/v1/device-posture-checks)
- `listDefaultDevicePostureChecks` (GET /api/v1/device-posture-checks/default)
- `getDevicePostureCheck` (GET /api/v1/device-posture-checks/{postureCheckId})
- `listDevices` (GET /api/v1/devices)
- `getDevice` (GET /api/v1/devices/{deviceId})
- `listDeviceOSAccounts` (GET /api/v1/devices/{deviceId}/os-accounts)
- `getDeviceOSAccount` (GET /api/v1/devices/{deviceId}/os-accounts/{osAccountId})
- `listDeviceUsers` (GET /api/v1/devices/{deviceId}/users)
- `listUserDevices` (GET /api/v1/users/{userId}/devices)

### Service app credentials and grants

The client secrets, key pairs and certificate signing requests of apps that call the Okta API, the Okta API scopes granted to each app, the tokens issued to them, the admin roles assigned to OAuth 2.0 clients, each app's provisioning connection, group push mappings and federated claims, and API service integrations with their secrets. From the audit level the collector reads API tokens only. It writes no access-posture file.

- `getDefaultProvisioningConnectionForApplication` (GET /api/v1/apps/{appId}/connections/default)
- `getUserProvisioningConnectionJWKS` (GET /api/v1/apps/{appId}/connections/default/jwks)
- `listCsrsForApplication` (GET /api/v1/apps/{appId}/credentials/csrs)
- `getCsrForApplication` (GET /api/v1/apps/{appId}/credentials/csrs/{csrId})
- `listJwk` (GET /api/v1/apps/{appId}/credentials/jwks)
- `getJwk` (GET /api/v1/apps/{appId}/credentials/jwks/{keyId})
- `listApplicationKeys` (GET /api/v1/apps/{appId}/credentials/keys)
- `getApplicationKey` (GET /api/v1/apps/{appId}/credentials/keys/{keyId})
- `listOAuth2ClientSecrets` (GET /api/v1/apps/{appId}/credentials/secrets)
- `getOAuth2ClientSecret` (GET /api/v1/apps/{appId}/credentials/secrets/{secretId})
- `listFeaturesForApplication` (GET /api/v1/apps/{appId}/features)
- `getFeatureForApplication` (GET /api/v1/apps/{appId}/features/{featureName})
- `listFederatedClaims` (GET /api/v1/apps/{appId}/federated-claims)
- `getFederatedClaim` (GET /api/v1/apps/{appId}/federated-claims/{claimId})
- `listScopeConsentGrants` (GET /api/v1/apps/{appId}/grants)
- `getScopeConsentGrant` (GET /api/v1/apps/{appId}/grants/{grantId})
- `listGroupPushMappings` (GET /api/v1/apps/{appId}/group-push/mappings)
- `getGroupPushMapping` (GET /api/v1/apps/{appId}/group-push/mappings/{mappingId})
- `listInterclientAllowedApplications` (GET /api/v1/apps/{appId}/interclient-allowed-apps)
- `listInterclientTargetApplications` (GET /api/v1/apps/{appId}/interclient-target-apps)
- `previewSAMLmetadataForApplication` (GET /api/v1/apps/{appId}/sso/saml/metadata)
- `listOAuth2TokensForApplication` (GET /api/v1/apps/{appId}/tokens)
- `getOAuth2TokenForApplication` (GET /api/v1/apps/{appId}/tokens/{tokenId})
- `listApiServiceIntegrationInstances` (GET /integrations/api/v1/api-services)
- `getApiServiceIntegrationInstance` (GET /integrations/api/v1/api-services/{apiServiceId})
- `listApiServiceIntegrationInstanceSecrets` (GET /integrations/api/v1/api-services/{apiServiceId}/credentials/secrets)
- `listRolesForClient` (GET /oauth2/v1/clients/{clientId}/roles)
- `retrieveClientRole` (GET /oauth2/v1/clients/{clientId}/roles/{roleAssignmentId})
- `listAppTargetRoleToClient` (GET /oauth2/v1/clients/{clientId}/roles/{roleAssignmentId}/targets/catalog/apps)
- `listGroupTargetRoleForClient` (GET /oauth2/v1/clients/{clientId}/roles/{roleAssignmentId}/targets/groups)

### App assignments

Which users and groups are assigned to each app, and the apps each user sees. The collector reads the app list for single sign-on coverage and the members of each group.

- `listApplicationGroupAssignments` (GET /api/v1/apps/{appId}/groups)
- `getApplicationGroupAssignment` (GET /api/v1/apps/{appId}/groups/{groupId})
- `listApplicationUsers` (GET /api/v1/apps/{appId}/users)
- `getApplicationUser` (GET /api/v1/apps/{appId}/users/{userId})
- `listAssignedApplicationsForGroup` (GET /api/v1/groups/{groupId}/apps)
- `listAppLinks` (GET /api/v1/users/{id}/appLinks)

### Access reviews

Access certification campaigns, governance bundles and their entitlements, and the governance source of each admin role assignment, in Okta Identity Governance. The Identity Governance APIs require an Okta Identity Governance subscription.

- `listGovernanceBundles` (GET /api/v1/iam/governance/bundles)
- `getGovernanceBundle` (GET /api/v1/iam/governance/bundles/{bundleId})
- `listBundleEntitlements` (GET /api/v1/iam/governance/bundles/{bundleId}/entitlements)
- `listBundleEntitlementValues` (GET /api/v1/iam/governance/bundles/{bundleId}/entitlements/{entitlementId}/values)
- `getOptInStatus` (GET /api/v1/iam/governance/optIn)
- `getUserAssignedRoleGovernance` (GET /api/v1/users/{userId}/roles/{roleAssignmentId}/governance)
- `getRoleAssignmentGovernanceGrant` (GET /api/v1/users/{userId}/roles/{roleAssignmentId}/governance/{grantId})
- `getRoleAssignmentGovernanceGrantResources` (GET /api/v1/users/{userId}/roles/{roleAssignmentId}/governance/{grantId}/resources)

### Admin role scope

Admin roles assigned to groups, the apps and groups an admin role is limited to, the permissions of custom roles, and resource sets with their bindings. The collector reads the users holding admin roles and the custom roles defined.

- `listGroupAssignedRoles` (GET /api/v1/groups/{groupId}/roles)
- `getGroupAssignedRole` (GET /api/v1/groups/{groupId}/roles/{roleAssignmentId})
- `listApplicationTargetsForApplicationAdministratorRoleForGroup` (GET /api/v1/groups/{groupId}/roles/{roleAssignmentId}/targets/catalog/apps)
- `listGroupTargetsForGroupRole` (GET /api/v1/groups/{groupId}/roles/{roleAssignmentId}/targets/groups)
- `listResourceSets` (GET /api/v1/iam/resource-sets)
- `getResourceSet` (GET /api/v1/iam/resource-sets/{resourceSetIdOrLabel})
- `listBindings` (GET /api/v1/iam/resource-sets/{resourceSetIdOrLabel}/bindings)
- `getBinding` (GET /api/v1/iam/resource-sets/{resourceSetIdOrLabel}/bindings/{roleIdOrLabel})
- `listMembersOfBinding` (GET /api/v1/iam/resource-sets/{resourceSetIdOrLabel}/bindings/{roleIdOrLabel}/members)
- `getMemberOfBinding` (GET /api/v1/iam/resource-sets/{resourceSetIdOrLabel}/bindings/{roleIdOrLabel}/members/{memberId})
- `listResourceSetResources` (GET /api/v1/iam/resource-sets/{resourceSetIdOrLabel}/resources)
- `getResourceSetResource` (GET /api/v1/iam/resource-sets/{resourceSetIdOrLabel}/resources/{resourceId})
- `listRolePermissions` (GET /api/v1/iam/roles/{roleIdOrLabel}/permissions)
- `getRolePermission` (GET /api/v1/iam/roles/{roleIdOrLabel}/permissions/{permissionType})
- `listApplicationTargetsForApplicationAdministratorRoleForUser` (GET /api/v1/users/{userId}/roles/{roleAssignmentId}/targets/catalog/apps)
- `listGroupTargetsForRole` (GET /api/v1/users/{userId}/roles/{roleAssignmentId}/targets/groups)
- `getRoleTargetsByUserIdAndRoleId` (GET /api/v1/users/{userId}/roles/{roleIdOrEncodedRoleId}/targets)

### Custom authorization servers

Custom OAuth 2.0 authorization servers: their access policies and rules, scopes, claims, signing keys, the clients registered with them and the refresh tokens they issued.

- `listAuthorizationServers` (GET /api/v1/authorizationServers)
- `getAuthorizationServer` (GET /api/v1/authorizationServers/{authServerId})
- `listAssociatedServersByTrustedType` (GET /api/v1/authorizationServers/{authServerId}/associatedServers)
- `listOAuth2Claims` (GET /api/v1/authorizationServers/{authServerId}/claims)
- `getOAuth2Claim` (GET /api/v1/authorizationServers/{authServerId}/claims/{claimId})
- `listOAuth2ClientsForAuthorizationServer` (GET /api/v1/authorizationServers/{authServerId}/clients)
- `listRefreshTokensForAuthorizationServerAndClient` (GET /api/v1/authorizationServers/{authServerId}/clients/{clientId}/tokens)
- `getRefreshTokenForAuthorizationServerAndClient` (GET /api/v1/authorizationServers/{authServerId}/clients/{clientId}/tokens/{tokenId})
- `listAuthorizationServerKeys` (GET /api/v1/authorizationServers/{authServerId}/credentials/keys)
- `getAuthorizationServerKey` (GET /api/v1/authorizationServers/{authServerId}/credentials/keys/{keyId})
- `listAuthorizationServerPolicies` (GET /api/v1/authorizationServers/{authServerId}/policies)
- `getAuthorizationServerPolicy` (GET /api/v1/authorizationServers/{authServerId}/policies/{policyId})
- `listAuthorizationServerPolicyRules` (GET /api/v1/authorizationServers/{authServerId}/policies/{policyId}/rules)
- `getAuthorizationServerPolicyRule` (GET /api/v1/authorizationServers/{authServerId}/policies/{policyId}/rules/{ruleId})
- `listOAuth2ResourceServerJsonWebKeys` (GET /api/v1/authorizationServers/{authServerId}/resourceservercredentials/keys)
- `getOAuth2ResourceServerJsonWebKey` (GET /api/v1/authorizationServers/{authServerId}/resourceservercredentials/keys/{keyId})
- `listOAuth2Scopes` (GET /api/v1/authorizationServers/{authServerId}/scopes)
- `getOAuth2Scope` (GET /api/v1/authorizationServers/{authServerId}/scopes/{scopeId})

### Org security settings

Whether Okta Support may access the org and the open support cases, third-party admin access, automatic Admin Console assignment, the default privileges of public client apps, ThreatInsight, bot protection and CAPTCHA, attack protection settings for authenticators and user lockout, org contacts and preferences.

- `getBotProtectionConfiguration` (GET /api/v1/bot-protection/configuration)
- `listCaptchaInstances` (GET /api/v1/captchas)
- `getCaptchaInstance` (GET /api/v1/captchas/{captchaId})
- `getOrgCaptchaSettings` (GET /api/v1/org/captcha)
- `listOrgContactTypes` (GET /api/v1/org/contacts)
- `getOrgContactUser` (GET /api/v1/org/contacts/{contactType})
- `getThirdPartyAdminSetting` (GET /api/v1/org/orgSettings/thirdPartyAdminSetting)
- `getOrgPreferences` (GET /api/v1/org/preferences)
- `getAerialConsent` (GET /api/v1/org/privacy/aerial)
- `getOktaCommunicationSettings` (GET /api/v1/org/privacy/oktaCommunication)
- `getOrgOktaSupportSettings` (GET /api/v1/org/privacy/oktaSupport)
- `listOktaSupportCases` (GET /api/v1/org/privacy/oktaSupport/cases)
- `getAutoAssignAdminAppSetting` (GET /api/v1/org/settings/autoAssignAdminAppSetting)
- `getClientPrivilegesSetting` (GET /api/v1/org/settings/clientPrivilegesSetting)
- `getCurrentConfiguration` (GET /api/v1/threats/configuration)
- `getAuthenticatorSettings` (GET /attack-protection/api/v1/authenticator-settings)
- `getUserLockoutSettings` (GET /attack-protection/api/v1/user-lockout-settings)

### Hardware tokens

The YubiKey OTP tokens uploaded to the org and who holds them, and the WebAuthn security keys preregistered for users.

- `listYubikeyOtpTokens` (GET /api/v1/org/factors/yubikey_token/tokens)
- `getYubikeyOtpTokenById` (GET /api/v1/org/factors/yubikey_token/tokens/{tokenId})
- `listWebAuthnPreregistrationFactors` (GET /webauthn-registration/api/v1/users/{userId}/enrollments)

### Risk signals

Behavior detection rules, each user's risk level and classification, user blocks, security events providers, and Shared Signals Framework streams.

- `getWellknownSsfMetadata` (GET /.well-known/ssf-configuration)
- `listBehaviorDetectionRules` (GET /api/v1/behaviors)
- `getBehaviorDetectionRule` (GET /api/v1/behaviors/{behaviorId})
- `listSecurityEventsProviderInstances` (GET /api/v1/security-events-providers)
- `getSecurityEventsProviderInstance` (GET /api/v1/security-events-providers/{securityEventProviderId})
- `getSsfStreams` (GET /api/v1/ssf/stream)
- `getSsfStreamStatus` (GET /api/v1/ssf/stream/status)
- `listUserBlocks` (GET /api/v1/users/{id}/blocks)
- `getUserClassification` (GET /api/v1/users/{userId}/classification)
- `getUserRisk` (GET /api/v1/users/{userId}/risk)

### User sessions and grants

Users' sessions, the OAuth 2.0 clients and grants on each user's account with their refresh tokens, and the tokens users hold from social identity providers.

- `listSocialAuthTokens` (GET /api/v1/idps/{idpId}/users/{userId}/credentials/tokens)
- `getSession` (GET /api/v1/sessions/{sessionId})
- `listUserClients` (GET /api/v1/users/{userId}/clients)
- `listGrantsForUserAndClient` (GET /api/v1/users/{userId}/clients/{clientId}/grants)
- `listRefreshTokensForUserAndClient` (GET /api/v1/users/{userId}/clients/{clientId}/tokens)
- `getRefreshTokenForUserAndClient` (GET /api/v1/users/{userId}/clients/{clientId}/tokens/{tokenId})
- `listUserGrants` (GET /api/v1/users/{userId}/grants)
- `getUserGrant` (GET /api/v1/users/{userId}/grants/{grantId})

### Custom domains and email sending

Custom domains and their certificates, the email domains Okta sends from with their verification status, and custom SMTP servers.

- `listCustomDomains` (GET /api/v1/domains)
- `getCustomDomain` (GET /api/v1/domains/{domainId})
- `listEmailDomains` (GET /api/v1/email-domains)
- `getEmailDomain` (GET /api/v1/email-domains/{emailDomainId})
- `listEmailServers` (GET /api/v1/email-servers)
- `getEmailServer` (GET /api/v1/email-servers/{emailServerId})

### Log streaming

Where the org streams its system log, such as a Splunk or Amazon EventBridge destination, and whether each stream is active. The collector reads the system log itself.

- `listLogStreams` (GET /api/v1/logStreams)
- `getLogStream` (GET /api/v1/logStreams/{logStreamId})
- `listLogStreamSchemas` (GET /api/v1/meta/schemas/logStream)
- `getLogStreamSchema` (GET /api/v1/meta/schemas/logStream/{logStreamType})

### Trusted origins

The origins the org allows for cross-origin requests and redirects.

- `listTrustedOrigins` (GET /api/v1/trustedOrigins)
- `getTrustedOrigin` (GET /api/v1/trustedOrigins/{trustedOriginId})

### Group rules and owners

The rules that assign users to groups automatically, and each group's owners.

- `listGroupRules` (GET /api/v1/groups/rules)
- `getGroupRule` (GET /api/v1/groups/rules/{groupRuleId})
- `listGroupOwners` (GET /api/v1/groups/{groupId}/owners)

### Realms and identity sources

Realms and their assignments, and the users, groups and sessions of custom identity sources and Active Directory group queries.

- `getGroupAttributeQueryResult` (GET /api/v1/directories/{appInstanceId}/groups/{groupId}/query/{resultId})
- `getIdentitySourceGroup` (GET /api/v1/identity-sources/{identitySourceId}/groups/{groupOrExternalId})
- `getIdentitySourceGroupMemberships` (GET /api/v1/identity-sources/{identitySourceId}/groups/{groupOrExternalId}/membership)
- `listIdentitySourceSessions` (GET /api/v1/identity-sources/{identitySourceId}/sessions)
- `getIdentitySourceSession` (GET /api/v1/identity-sources/{identitySourceId}/sessions/{sessionId})
- `getIdentitySourceUser` (GET /api/v1/identity-sources/{identitySourceId}/users/{externalId})
- `listRealmAssignments` (GET /api/v1/realm-assignments)
- `listRealmAssignmentOperations` (GET /api/v1/realm-assignments/operations)
- `getRealmAssignment` (GET /api/v1/realm-assignments/{assignmentId})
- `listRealms` (GET /api/v1/realms)
- `getRealm` (GET /api/v1/realms/{realmId})

### Directory agents

The Active Directory and LDAP agent pools, and their automatic update settings.

- `listAgentPools` (GET /api/v1/agentPools)
- `listAgentPoolsUpdates` (GET /api/v1/agentPools/{poolId}/updates)
- `getAgentPoolsUpdateSettings` (GET /api/v1/agentPools/{poolId}/updates/settings)
- `getAgentPoolsUpdateInstance` (GET /api/v1/agentPools/{poolId}/updates/{updateId})

### Privileged access service accounts

The service accounts Okta Privileged Access manages, which require an Okta Privileged Access subscription.

- `listOktaManagedUserAccounts` (GET /privileged-access/api/v1/okta-service-accounts)
- `getOktaManagedUserAccount` (GET /privileged-access/api/v1/okta-service-accounts/{id})
- `listAppServiceAccounts` (GET /privileged-access/api/v1/service-accounts)
- `getAppServiceAccount` (GET /privileged-access/api/v1/service-accounts/{id})

## Left out as irrelevant

- **Branding, page and template customization.** `getWellKnownAppAuthenticatorConfiguration`, `getAppleAppSiteAssociationWellKnownURI`, `getAssetLinksWellKnownURI`, `getWellknownOrgMetadata`, `getWebAuthnWellKnownURI`, `listBrands`, `getBrand`, `listBrandDomains`, `getErrorPage`, `getCustomizedErrorPage`, `getDefaultErrorPage`, `getPreviewErrorPage`, `getSignInPage`, `getCustomizedSignInPage`, `getDefaultSignInPage`, `getPreviewSignInPage`, `listAllSignInWidgetVersions`, `getSignOutPageSettings`, `listEmailTemplates`, `getEmailTemplate`, `listEmailCustomizations`, `getEmailCustomization`, `getCustomizationPreview`, `getEmailDefaultContent`, `getEmailDefaultPreview`, `getEmailSettings`, `listBrandThemes`, `getBrandTheme`, `getAllWellKnownURIs`, `getRootBrandWellKnownURI`, `getBrandWellKnownURI`, `getFirstPartyAppSettings`, `listUISchemas`, `getUISchema`, `listSmsTemplates`, `getSmsTemplate`
- **Profile schemas, mappings, user types and linked objects.** `listProfileMappings`, `getProfileMapping`, `getApplicationUserSchema`, `getGroupSchema`, `listLinkedObjectDefinitions`, `getLinkedObjectDefinition`, `getUserSchema`, `listUserTypes`, `getUserType`, `listLinkedObjectsForUser`
- **Feature flags, rate limit administration, notification subscriptions and disaster recovery status.** `getDRStatus`, `getDRStatusForDomain`, `listFeatures`, `getFeature`, `listFeatureDependencies`, `listFeatureDependents`, `listPrincipalRateLimitEntities`, `getPrincipalRateLimitEntity`, `getRateLimitSettingsAdminNotifications`, `getRateLimitSettingsPerClient`, `getRateLimitSettingsWarningThreshold`, `listSubscriptionsRole`, `getSubscriptionsNotificationTypeRole`, `listSubscriptionsUser`, `getSubscriptionsNotificationTypeUser`
- **Delivery providers for push, SMS and telephony.** `listPushProviders`, `getPushProvider`, `listAllCustomTelephonyProviderCredentials`, `getCustomTelephonyProviderCredential`
- **Detail of, or another view on, what the collector already reads.** `getApiToken`, `getApplication`, `getAuthenticator`, `listAllCustomAAGUIDs`, `getCustomAAGUID`, `listAuthenticatorMethods`, `getAuthenticatorMethod`, `getDeviceAssurancePolicy`, `getEventHook`, `getGroup`, `listHookKeys`, `getPublicKey`, `getHookKey`, `getRole`, `listIdentityProviderKeys`, `getIdentityProviderKey`, `getIdentityProvider`, `listCsrsForIdentityProvider`, `getCsrForIdentityProvider`, `listIdentityProviderSigningKeys`, `listActiveIdentityProviderSigningKey`, `getIdentityProviderSigningKey`, `listIdentityProviderApplicationUsers`, `getIdentityProviderApplicationUser`, `getInlineHook`, `getPolicy`, `listPolicyMappings`, `getPolicyMapping`, `getPolicyRule`, `getUser`, `listUserGroups`, `listUserIdentityProviders`, `listAuthenticatorEnrollments`, `getAuthenticatorEnrollment`, `listSupportedFactors`, `listSupportedSecurityQuestions`, `getFactor`, `getFactorTransactionStatus`, `getUserAssignedRole`, `getNetworkZone`

## Outside the description

- okta.token.create (POST /oauth2/v1/token): The OAuth 2.0 token endpoint, which the management API description does not cover

Generated by `epack sdk surface` from `docs/surface.yaml` and the collector's recordings. Edit the verdicts there, then run `epack sdk surface --write`.
