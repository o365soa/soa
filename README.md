# Microsoft Security Assessment Prerequisites

## Introduction

The following Microsoft security assessments have several prerequisites that need to be installed and configured:
- Office 365 Security Optimization Assessment
- Microsoft 365 Foundations - Workload Security Assessment
- Security Optimization Assessment for Microsoft Defender

The preqrequisites installation script is included in a PowerShell module named SOA.

## Prerequisites Breakdown

The latest version of the following PowerShell modules are installed:
* Azure AD MSOnline (v1)
* Exchange Online Management
* SharePoint Online
* Microsoft Teams
* Power Apps admin
* From the Microsoft Graph PowerShell SDK: 
  * Microsoft.Graph.Authentication
  * Microsoft.Graph.Applications
* Active Directory

Note: For SharePoint Online, if a non-PowerShell Gallery version of the module is installed, it is removed from the PS Module Path to prevent conflicts.

An application, named "Microsoft Security Assessment", is also registered (created) in your tenant. Details are provided below.

## Prerequisites Script

### Requirements

In order to install the SOA module and run the prerequisites script, you must have the following on the collection machine:
* PowerShell 5.1 (PowerShell 7 is not supported)
* PowerShell Gallery (Automatically configured in PowerShell 5, which is standard on Windows 10 and later)
* PowerShellGet version 2.2.4 or higher
   * PowerShell Gallery requires TLS 1.2. While PowerShell and Windows support TLS 1.2, in some proxy environments the proxy server might negotiate a lower version, which will cause a Resource Unavailable error when attempting to install any module from PowerShell Gallery. PowerShellGet 2.2.4 works around this issue by temporarily forcing TLS 1.2 when installing any module from PowerShell Gallery and then changing back to the OS default.  If at least PowerShellGet 2.2.4 is not installed, run the following to install the latest version:<br><br>
   
      `Install-Module PowerShellGet -Force`
      
      `Remove-Module PowerShellGet` (This command removes any loaded PowerShellGet module from the current session.)
* PowerShell execution policy set to RemoteSigned (or Unrestricted)
   * The current policy can be verified by running `Get-ExecutionPolicy`. If it is not set to RemoteSigned or Unrestricted, it can be set to RemoteSigned by running the following:
   
     `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
      
### Permissions
* Local admin (running PowerShell as an adminisrator) is not required unless the Active Directory module needs to be installed (see [below](#active-directory-module)).
* The following delegated scopes are required for the user installing the prerequisites (and will prompt the user for consent, which does not require granting on behalf of the entire organisation):
   * **Application.ReadWrite.All** (The least-privilege scope for creating an app registration in the tenant.)
   * **Organization.Read.All** (The least-privilege common scope for getting the licenses in the tenant and the initial tenant domain.)
* To be able to grant admin consent for the app registration, an account with Global Administrator or Privileged Role Administrator role is required. (The account used to create the app registration can be different than the account used to grant consent.)
* For testing the connections to each workload, the account used to sign in does not require an admin role.

### Collection machine
The collection machine can be any workstation or server, physical or virtual, that can connect via PowerShell to Microsoft Entra ID, Microsoft Graph, Exchange Online, Security & Compliance Center, SharePoint Online, Microsoft Teams, and Power Platform. It does not need to be AD- or Microsoft Entra-joined unless you have Conditional Access policies requiring it for these connections.

If directory synchronisation is used, a script will need to be executed on a domain-joined machine that has the Active Directory PowerShell module installed (whether the collection machine or a different machine).

### Running the prerequisites script

1. Open a new PowerShell window (not the ISE).
2. Run the following to install the latest version of the SOA module from Powershell Gallery:

   `Install-Module SOA`

3. Run the following to install the prerequisites (**important**: see below for optional parameters that may be applicable):

   `Install-SOAPrerequisites`

## Optional parameters
### Custom (vanity) SharePoint Online domain

If you use a custom domain to connect to the SharePoint Online admin endpoint (such as a multi-tenant enhanced organization), you need to specify the domain using `-SPOAdminDomain <FQDN>` or the connection test to SPO will fail.

### Requiring a proxy

If traffic to Microsoft 365 routes via proxy infrastructure and the prerequisites installation fails because of this, try again with `-UseProxy`.

### Sovereign clouds

If the Office 365 tenant is in a sovereign cloud environment, the `-CloudEnvironment` parameter must be used with one of the values below. (The default value is `Commercial`, so the parameter is only required for non-commercial clouds):

* Use `USGovGCC` for Microsoft Cloud for US Government (GCC\GCC-Moderate)
* Use `USGovGCCHigh` for Microsoft Cloud for US Government L4 (GCC-High)
* Use `USGovDoD` for Microsoft Cloud for US Government L5 (DOD)
* Use `Germany` for Microsoft Cloud Germany
* Use `China` for Azure and Microsoft 365 operated by 21Vianet in China

### Active Directory module

If directory synchronisation is used and the Active Directory module is not installed and you cannot run PowerShell as a local admin, you can skip the installation of the module by using `-SkipAdModule`. A machine with the module installed will be needed on the first day of the engagement to collect information about the AD environment. The module can be installed on a machine using `-AdModuleOnly` or manually via another method.

## Microsoft Entra app registration

An app registration is required to use Microsoft Graph and other APIs. Registration and configuration of this application is performed by the prerequisites script.

The permission scopes used by the app registration:
|API|Scope|Type|Usage|
|---|---|---|---|
|Graph|Application.ReadWrite.OwnedBy|Application|Update app registrations owned by the application (aka service principal). This allows the application to remove its own client secret when the prerequisites validation and data collection are complete.|
|Graph|AuditLog.Read.All|Application|Get sign-in activity for user and guest accounts.|
|Graph|DeviceManagementConfiguration.Read|Application|Get Intune configuration policies, if applicable.|
|Graph|Directory.Read.All|Application|Get subscriptions in the tenant and sign-in activity for user and guest accounts. (Both this scope and AuditLog.Read.All are required in order to get sign-in activity.)|
|Graph|IdentityRiskEvent.Read.All|Application|Get identity risk events raised by Microsoft Entra ID Protection.|
|Graph|IdentityRiskyUser.Read.All|Application|Get identity risk events raised by Microsoft Entra ID Protection. (Both this scope and IdentityRiskEvent.Read.All are required to get risk events.)|
|Graph|OnPremDirectorySynchronization.Read.All|Application|Get Microsoft Entra directory synchronization settings.|
Graph|Policy.Read.All|Application|Get various Microsoft Entra policies, such as authorisation, cross-tenant access, and conditional access.|
|Graph|PrivilegedAccess.Read.AzureADGroup|Application|Get Privileged Identity Management roles assigned to groups, if applicable.
|Graph|RoleManagement.Read.All|Application|Get Privileged Identity Management roles assigned to users, if applicable.|
|Graph|SecurityEvents.Read.All|Application|Get active security events within your tenant.
|Graph|SecurityIncident.Read.All|Application|Get Defender security incidents.
|Graph|SecurityIdentitiesHealth.Read.All|Application|For organisations with Microsoft Defender for Identity, get health alerts.|
|Graph|ThreatHunting.Read.All|Application|For organisations with Microsoft Defender for Office 365 P2 to get active AIR investigations, or organisations with Microsoft Defender for Endpoint to get health alerts.|
|Dynamics CRM|user_impersonation|Delegated|Get Dataverse settings.|

### App registration security

As a security-related assessment, we are conscious of the security of the app registration and enterprise application created for it, which is why the following security considerations are made:
* The app registration is scoped to specific activities, as indicated above, using a least-privilege model. All scopes are read-only (except for OwnedBy so it can remove its client secret) and grant access only to configuration settings, not any user-generated data.
* Client secrets
   * A client secret (a password randomly generated by Microsoft Entra) is created by the installation script for validating the configuration of the app registration. It is set to expire after 48 hours, but is removed from the app registration when the validation is complete.
   * When the collection script is executed, a client secret (also set to expire after 48 hours) is created to be able to retrieve the necessary data, but is removed from the app registration when the collection script is complete.
   * In each scenario, the client secret is stored only in memory by the script and is no longer accessible after completion.

### Removal of app registration

You may remove the app registration at the conclusion of the engagement. It is not necessary, however, because it cannot be used without a valid client secret, which is removed when the collection script completes. It is important that you **do not** remove the app registration (or its enterprise application) between the prerequisites installation and the data collection.
