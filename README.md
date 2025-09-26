# Microsoft 365 Security Assessments Prerequisites

## Introduction

The following Microsoft 365 security assessments have several prerequisites that need to be installed and configured:
- Microsoft 365 Foundations - Workload Security Assessment
- Security Optimization Assessment for Microsoft Defender

The prerequisites installation script is included in a PowerShell module named SOA.

## Prerequisites Breakdown

The latest version of the following PowerShell modules is installed:
* Exchange Online
* SharePoint Online
* Microsoft Teams
* Power Apps admin
* Microsoft.Graph.Authentication (from the Microsoft Graph PowerShell SDK)
* Active Directory

> [!NOTE]
> For SharePoint Online, if a non-PowerShell Gallery version of the module is installed, it is removed from the PS Module Path to prevent conflicts.

An application, named "Microsoft Security Assessment", is also registered (created) in your tenant. Details are provided below.

## Collection machine
The prerequisites need to be installed on the system that will be used for data collection. It can be any workstation or server, physical or virtual, that can connect via PowerShell to Microsoft Graph, Exchange Online, Security & Compliance Center, SharePoint Online, Microsoft Teams, and Power Platform. It does not need to be AD- or Microsoft Entra-joined unless you have Conditional Access policies requiring it for any of these connections.

If directory synchronization is being used, a collection script will be run on a machine that needs to be domain-joined and has the Active Directory PowerShell module installed (whether that is the collection machine or a different machine).

## Prerequisites Script

### Requirements

In order to install the SOA module and run the prerequisites script, you must have the following on the collection machine:
* PowerShell 5.1 (PowerShell 7 is not supported)
* PowerShellGet version 2.2.4 or higher
   * The installed versions can be determined by running `Get-Module PowerShellGet -ListAvailable`. If at least PowerShellGet 2.2.4 is not installed, run the following to install the latest version:<br>
   
      `Install-Module PowerShellGet -Force`<br>
      `Remove-Module PowerShellGet` (This command removes any loaded PowerShellGet module from the current session.)
* PowerShell execution policy set to RemoteSigned (or Unrestricted)
   * The current policy can be verified by running `Get-ExecutionPolicy`. If it is not set to RemoteSigned or Unrestricted, it can be set to RemoteSigned by running the following:
   
     `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
      
### Permissions
* Local admin (running PowerShell as an administrator) is not required unless the Active Directory module needs to be installed (see [below](#active-directory-module)).
* The user installing the prerequisites needs the following roles:
   * Application Administrator (or Cloud App Administrator or Privileged Role Administrator), to create the app registration. (If this is not possible, contact the resource delivering the assessment for instructions to manually create the app registration.)
   * Billing Administrator, to get the licenses in the tenant.
* Consent must be granted to the Graph PowerShell SDK (which will prompt for it when signing in) for the following delegated scopes for the user installing the prerequisites (granting on behalf of the entire organization is not required):
   * Application.ReadWrite.All (If this is not possible, contact the resource delivering the assessment for instructions to manually create the app registration.)
   * Organization.Read.All
* To grant admin consent for the app registration's permissions (see [below](#microsoft-entra-app-registration)), an account with Global Administrator or Privileged Role Administrator role is required. (The account used to create the app registration can be different than the account used to grant consent.)
* For testing the connections to Exchange Online, Security & Compliance Center, SharePoint Online, Microsoft Teams, and Power Platform, the account used to sign in does not require an admin role.

### Running the prerequisites script

1. In PowerShell, run the following to install the latest version of the SOA module from the [PowerShell Gallery](https://www.powershellgallery.com/packages/SOA/):

   `Install-Module SOA`

2. Run the following:

   `Install-SOAPrerequisites`

> [!IMPORTANT]
> See below for optional parameters that may be applicable

## Optional parameters
### Custom (vanity) SharePoint Online domain

If you use a custom domain to connect to the SharePoint Online admin endpoint (such as a multi-tenant enhanced organization), you need to specify the domain using `-SPOAdminDomain <FQDN>` or the connection test to SPO will fail.

### Requiring a proxy

If traffic to Microsoft 365 routes via proxy infrastructure and the prerequisites installation fails because of this, try again with `-UseProxy`.

#### Microsoft Graph PowerShell SDK app registration in 21Vianet

Microsoft globally registered applications, including the Graph PowerShell SDK, do not replicate to tenants operated by 21Vianet. This means an app registration must be configured to allow the SDK to connect to Microsoft Graph when using delegated authentication:

1. In the Microsoft Entra portal, navigate to **Manage** / **App registrations** and click the **New registration** button.
1. Give the app a desired name.
1. Under **Supported account types**, leave the selection at the default value for a "Single tenant" application.
1. Under **Redirect URI**, click the drop-down for "Select a platform" and select *Public client/native (mobile & desktop)*, then enter `http://localhost`.
1. Click the **Register** button.
1. In the application's **Overview** section, copy the "Application (client) ID" value, which will need to be provided using the `-GraphClientId` parameter when running `Install-SOAPrerequisites` and when running the collection script.

### Active Directory module

If directory synchronization is used and the Active Directory module is not installed and you cannot run PowerShell as a local admin, you can skip the installation of the module by using `-SkipAdModule`. A machine with the module installed will be needed on the first day of the engagement to collect information about the AD environment. The module can be installed on a machine using `-AdModuleOnly` or manually via another method.

## Microsoft Entra app registration

An app registration is required to use Microsoft Graph and other APIs. Registration and configuration is performed by the prerequisites script.

The permission scopes added to the app registration:
|API|Scope|Type|Usage|
|---|---|---|---|
|Graph|Application.ReadWrite.OwnedBy|Application|Update app registrations owned by the application (aka service principal). This allows the application to remove its own client secret when the prerequisites validation and data collection are complete.|
|Graph|AuditLog.Read.All|Application|Get sign-in activity for user and guest accounts.|
|Graph|DeviceManagementConfiguration.Read|Application|Get Intune configuration policies, if applicable.|
|Graph|Directory.Read.All|Application|Get subscriptions in the tenant and sign-in activity for user and guest accounts. (Both this scope and AuditLog.Read.All are required in order to get sign-in activity.)|
|Graph|IdentityRiskEvent.Read.All|Application|Get identity risk events raised by Microsoft Entra ID Protection.|
|Graph|OnPremDirectorySynchronization.Read.All|Application|Get Microsoft Entra directory synchronization settings.|
Graph|Policy.Read.All|Application|Get various Microsoft Entra policies, such as authorisation, cross-tenant access, and conditional access.|
|Graph|PrivilegedAccess.Read.AzureADGroup|Application|Get Privileged Identity Management roles assigned to groups.
|Graph|RoleManagement.Read.All|Application|Get Privileged Identity Management roles assigned to users.|
|Graph|SecurityAlert.Read.All|Application|For organisations with Microsoft Defender for Office 365 (Plan 2) or Microsoft Defender for Endpoint, get Defender alerts.|
|Graph|SecurityIdentitiesHealth.Read.All|Application|For organisations with Microsoft Defender for Identity, get health alerts.|
|Graph|SecurityEvents.Read.All|Application|For organisations with Microsoft Defender for Identity, get configuration details from Secure Score that do not have an API available.|
|Graph|SecurityIdentitiesSensors.Read.All|Application|For organisations with Microsoft Defender for Identity, get sensor details.|
|Graph|ThreatHunting.Read.All|Application|For organisations with Microsoft Defender for Office 365 P2, get active automated investigations. For organisations with Microsoft Defender for Endpoint, get health alerts.|
|Dynamics CRM|user_impersonation|Delegated|Get Dataverse settings.|

### App registration security

As a security-related assessment, the security of the app registration is paramount, which is why the following considerations are made:
* The app registration is scoped to specific activities, as indicated above, using a least-privilege model. All scopes are read-only (except for OwnedBy so it can remove its client secret) and grant access only to configuration settings, not any user-generated data.
* Client secrets
   * A client secret (a password randomly generated by Microsoft Entra) is created by the installation script for validating the configuration of the app registration. It is set to expire after 48 hours, but is removed from the app registration when the validation is complete.
   * When the collection script is run, a client secret (also set to expire after 48 hours) is created to be able to retrieve the necessary data, but is removed from the app registration when the collection script is complete.
   * The client secret is stored only in memory by the script and is no longer accessible after completion.
   * If business policy does not allow client secrets to be created on-demand, contact the resource delivering the assessment for instructions to provide a manually created secret when running the prerequisites and collection scripts. A manually provided secret is also stored only in memory when running the script.

### Removal of app registration

You may remove the app registration at the conclusion of the engagement. It is not necessary, however, because it cannot be used without a valid client secret, which is removed when the collection script completes. It is important that you **do not** remove the app registration (or its enterprise application) between the prerequisites installation and the data collection.
