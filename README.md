# Office 365 SOA Prerequisites

## Introduction

The Office 365 Security Optimisation Assessment has several prerequisites that need to be installed or configured. The tool runs in PowerShell, and connects to various workloads in Office 365.

## Prerequisites Breakdown

The latest version of the following modules are installed:
* Azure AD MSOnline (v1)
* Azure AD (v2) Preview
* Exchange Online Management (v3)
* SharePoint Online
* Microsoft Teams
* Power Apps admin
* From the Microsoft Graph PowerShell SDK: 
   * Microsoft.Graph.Authentication
   * Microsoft.Graph.Applications
* Active Directory

Note: For SharePoint Online, if a non-PowerShell Gallery version of the module is installed, it is removed from your PS Module Path to prevent conflicts.

An Azure AD application is also registered in your tenant. Details of this are provided below.

## Prerequisites Script

### Requirements

In order to install the SOA module and run the prerequisites script, you must have the following on the collection machine:
* PowerShell 5.1 (PowerShell 7 is not supported)
* PowerShell Gallery (Automatically configured in PowerShell 5, which is standard on Windows 10 and later)
* PowerShellGet version 2.2.4 or higher
   * PowerShell Gallery requires TLS 1.2.  While PowerShell and Windows support TLS 1.2, in some proxy environments the proxy server might negotiate a lower version, which will cause a Resource Unavailable error when attempting to install any module from PowerShell Gallery.  PowerShellGet 2.2.4 works around this issue by temporarily forcing TLS 1.2 when installing any module from PowerShell Gallery and then changing back to the OS default.  If at least PowerShellGet 2.2.4 is not installed, run the following to install the latest version:<br><br>
   
      `Install-Module PowerShellGet -Force`
      
      `Remove-Module PowerShellGet` (This command removes any loaded PowerShellGet module from the current session.)
* PowerShell execution policy set to RemoteSigned (or Unrestricted)
   * The current policy can be verified by running `Get-ExecutionPolicy`. If it is not set to RemoteSigned or Unrestricted, it can be set to RemoteSigned by running the following:
   
     `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
      
### Permissions
* Local admin (running PowerShell as an adminisrator) is not required except if the Active Directory module needs to be installed (see [below](#active-directory-module)).
* For the connections to each workload, the account used to sign in does not require an admin role except for the connection to Azure AD using the v2 Preview module, as indicated:
   * To be able to discover the URL to use to connect to SharePoint Online, the account used to connect to Azure AD needs to have the Directory Readers role (or "higher").
   * To be able to create and test the Azure AD application:
      * For the application to be created, any user in the tenant can be used, by default. If this setting has been disabled, the account used to connect to Azure AD with the v2 Preview module must have the Global Administrator, Application Administrator, Cloud Application Administraor, or Application Developer role.
      * To be able to grant consent to the application, a user with Global Administrator or Privileged Role Administrator role is required. (The account used to create the application can be different than the account used to grant consent.)
     * To test the application, the account used to connect to Azure AD with the v2 Preview module must have the Application Administrator or Cloud Application Administraor role, or be assigned the owner role in the "Office 365 Security Optimization Assessment" application.

### Collection machine
The collection machine can be any workstation or server, physical or virtual, that can connect via PowerShell to Azure AD, Microsoft Graph, Exchange Online, Security & Compliance Center, SharePoint Online, Microsoft Teams, and Power Platform. It does not need to be AD- or AAD-joined unless you have Conditional Access policies requiring it for these connections.

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

If the Office 365 tenant is in a sovereign cloud environment, the `-O365EnvironmentName` parameter must be used with one of the values below. (The default value is `Commercial`, so the parameter is only required for non-commercial clouds):

* Use `USGovGCC` for Microsoft Cloud for US Government (GCC\GCC-Moderate)
* Use `USGovGCCHigh` for Microsoft Cloud for US Government L4 (GCC-High)
* Use `USGovDoD` for Microsoft Cloud for US Government L5 (DOD)
* Use `Germany` for Microsoft Cloud Germany
* Use `China` for Azure and Microsoft 365 operated by 21Vianet in China

### Active Directory module

If directory synchronisation is used and the Active Directory module is not installed and you cannot run PowerShell as a local admin, you can skip the installation of the module by using `-SkipAdModule`. A machine with the module installed will be needed on the first day of the engagement to collect information about the AD environment. The module can be installed on a machine using `-AdModuleOnly` or manually via another method.

## Azure AD application

An Azure AD application is required in order to use Microsoft Graph and other APIs. Installation and configuration of this application is performed by the prerequisites script.

The permission scope of this application is limited to the following:
#### Microsoft Graph API:
* **SecurityEvents.Read.All** (Retrieve active security events within your tenant.)
* **IdentityRiskyUser.Read.All** (Retrieve identity risk events raised by Azure Identity Protection.)
* **IdentityRiskEvent.Read.All** (Retrieve identity risk events raised by Azure Identity Protection.)
* **DeviceManagementConfiguration.Read** (Retrieve Intune configuration policies, if applicable.)
* **AuditLog.Read.All** (Retrieve sign-in activity for user and guest accounts.)
* **Directory.Read.All** (Retrieve sign-in activity for user and guest accounts. Both this scope and the previous scope are required in order to get sign-in activity.)
* **Policy.Read.All** (Retrieve Azure AD authorization and conditional access policies.)
* **SecurityIncident.Read.All** (Retrieve Defender security incidents.)
* **OnPremDirectorySynchronization.Read.All** (Retrieve Azure AD directory synchronization settings.)
#### Dynamics CRM API:
* **user_impersonation** (Retrieve Dataverse settings.)

### Azure AD application security

Being a security-related assessment, we are conscious of the security of the Azure AD application created for it, which is why the following security considerations are made:
* The application is scoped to specific activities, as indicated above. All scopes are read-only and specific to configuration settings, not access to any user content.
* A client secret (a password specific to the application that is randomly generated by Azure AD ) is created by the installation script for validating the installation of the application. It is configured to expire after 48 hours, but is deleted from the application when the validation is complete.
* A client secret, also configured to expire after 48 hours, is created on the day of the collection to be able to retrieve the necessary data, but is deleted from the application when the collection is complete.
* The client secret is stored only in memory during the execution of the prerequisites installation script and the data collection script.

### Removal of Azure AD application

You can remove the Azure AD application at the conclusion of the engagement. This is not necessary because the application cannot be used without a valid client secret, which is deleted when the collection script completes. It is important, however, that you **do not** remove the Azure AD application between the prerequisites installation and the data collection on the first day of the engagement.
