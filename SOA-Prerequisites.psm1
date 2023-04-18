#Requires -Version 5.1
#Requires -Modules @{ModuleName="PowerShellGet"; ModuleVersion="2.2.4"}

<#

    .SYNOPSIS
        Prerequisite validation/installation module for Office 365: Security Optimization Assessment

    .DESCRIPTION
        Contains installation cmdlet which must be run in advance of a Microsoft
        proactive offering of the Office 365 Security Optimization Assessment

        The output of the script (JSON file) should be sent to the engineer who will be performing
        the assessment.

        ############################################################################
        # This sample script is not supported under any Microsoft standard support program or service. 
        # This sample script is provided AS IS without warranty of any kind. 
        # Microsoft further disclaims all implied warranties including, without limitation, any implied 
        # warranties of merchantability or of fitness for a particular purpose. The entire risk arising 
        # out of the use or performance of the sample script and documentation remains with you. In no
        # event shall Microsoft, its authors, or anyone else involved in the creation, production, or 
        # delivery of the scripts be liable for any damages whatsoever (including, without limitation, 
        # damages for loss of business profits, business interruption, loss of business information, 
        # or other pecuniary loss) arising out of the use of or inability to use the sample script or
        # documentation, even if Microsoft has been advised of the possibility of such damages.
        ############################################################################

#>

Function Get-IsAdministrator {
    <#
        Determine if the script is running in the context of an administrator or not
    #>

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    Return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function Exit-Script {
    Stop-Transcript
    
}

Function Get-PowerShellCount
{
    <#
        Returns count of PowerShell windows opened
    #>

    $Processes = Get-Process -Name PowerShell
    Return $Processes.Count
}

Function Write-Important {
    <#
    
        Writes IMPORTANT to screen - used at various points during execution
    
    #>
    Write-Host ""
    Write-Host "#############################################" -ForegroundColor Yellow
    Write-Host "#                 IMPORTANT                 #" -ForegroundColor Yellow
    Write-Host "#############################################" -ForegroundColor Yellow
    Write-Host ""
}

function New-TemporaryDirectory {
    <#
        Create a new temporary path for storing files
    #>
    $parent = [System.IO.Path]::GetTempPath()
    [string] $name = [System.Guid]::NewGuid()
    $r = New-Item -ItemType Directory -Path (Join-Path $parent $name)
    Return $r.FullName
}

function Get-SOADirectory
{
    <#
        Gets or creates the SOA directory in AppData
    #>

    $Directory = "$($env:LOCALAPPDATA)\Microsoft\SOA"

    If(Test-Path $Directory) 
    {
        Return $Directory
    }
    else 
    {
        mkdir $Directory | out-null
        Return $Directory
    }

}

function Get-SPOTenantName
{
    <#
    
        Used to determine what the SharePoint Tenant Name is during connection tests
    
    #>
    
    $domain = ((Get-AzureADDomain | Where-Object {$_.IsInitial -eq $True}).Name)
    return ($domain -Split ".onmicrosoft.com")[0]

}

function Get-SharePointAdminUrl
{
    <#
    
        Used to determine what the SharePoint Admin URL is during connection tests
    
    #>
    Param (
        [string]$O365EnvironmentName
    )

    # Custom domain provided for connecting to SPO admin endpoint
    if ($SPOAdminDomain) {
        $url = "https://" + $SPOAdminDomain
    }
    else {
        $tenantName = Get-SPOTenantName
        
        switch ($O365EnvironmentName) {
            "Commercial"   {$url = "https://" + $tenantName + "-admin.sharepoint.com";break}
            "USGovGCC"     {$url = "https://" + $tenantName + "-admin.sharepoint.com";break}
            "USGovGCCHigh" {$url = "https://" + $tenantName + "-admin.sharepoint.us";break}
            "USGovDoD"     {$url = "https://" + $tenantName + "-admin.dps.mil";break}
            "Germany"      {$url = "https://" + $tenantName + "-admin.sharepoint.de";break}
            "China"        {$url = "https://" + $tenantName + "-admin.sharepoint.cn"}
        }
    }
    return $url
}

Function Reset-SOAAppSecret {
    <#
    
        This function creates a new secret for the application when the app object is created from Get-AzureADApplication
    
    #>
    Param (
        $App,
        $Task
    )

    # Provision a short lived credential +48 hrs.
    $clientsecret = New-AzureADApplicationPasswordCredential -ObjectId $App.ObjectId -EndDate (Get-Date).AddDays(2) -CustomKeyIdentifier "$Task on $(Get-Date -Format "dd-MMM-yyyy")"

    Return $clientsecret.Value
}
Function Reset-SOAAppSecretv2 {
    <#
    
        This function creates a new secret for the application when the app object is created from Get-MgApplication
    
    #>
    Param (
        $App,
        $Task
    )

    # Provision a short lived credential +48 hrs.
    $clientsecret = New-AzureADApplicationPasswordCredential -ObjectId $App.Id -EndDate (Get-Date).AddDays(2) -CustomKeyIdentifier "$Task on $(Get-Date -Format "dd-MMM-yyyy")"

    Return $clientsecret.Value
}

function Remove-SOAAppSecret {
    # Removes any client secrets associated with the application when the application object is created by Get-AzureADApplication
    param ($app)

    $secrets = Get-AzureADApplicationPasswordCredential -ObjectId $app.ObjectId
    foreach ($secret in $secrets) {
        # Suppress errors in case a secret no longer exists
        try {
            Remove-AzureADApplicationPasswordCredential -ObjectId $app.ObjectId -KeyId $secret.KeyId
        }
        catch {}
    }
}

function Remove-SOAAppSecretv2 {
    # Removes any client secrets associated with the application when the application object is created by Get-MgApplication
    param ($app)

    $secrets = Get-AzureADApplicationPasswordCredential -ObjectId $app.Id
    foreach ($secret in $secrets) {
        # Suppress errors in case a secret no longer exists
        try {
            Remove-AzureADApplicationPasswordCredential -ObjectId $app.Id -KeyId $secret.KeyId
        }
        catch {}
    }
}

Function Import-MSAL {
    <#
    
        Finds a suitable MSAL library from Exchange Online and uses that
        This prevents us having to ship the .dll's ourself.

    #>

    # Add support for the .Net Core version of the library. Variable doesn't exist in PowerShell v4 and below, 
    # so if it doesn't exist it is assumed that 'Desktop' edition is used
    If ($PSEdition -eq 'Core'){
        $Folder = "netCore"
    } Else {
        $Folder = "NetFramework"
    }

    $ExoModule = Get-Module -Name "ExchangeOnlineManagement" -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    $MSAL = Join-Path $ExoModule.ModuleBase "$($Folder)\Microsoft.Identity.Client.dll"

    # Load the MSAL library
    Write-Verbose "$(Get-Date) Loading module from $MSAL"
    Try {Add-Type -LiteralPath $MSAL | Out-Null} Catch {}
}

Function Get-MSALAccessToken {
    <#
    
        Fetch an Access Token using MSAL libraries
    
    #>
    Param(
        $TenantName,
        $ClientID,
        $Secret,
        $Resource,
        [string]$O365EnvironmentName
    )

    Import-MSAL

    switch ($O365EnvironmentName) {
        "Commercial"   {$Authority = "https://login.microsoftonline.com/$TenantName";break}
        "USGovGCC"     {$Authority = "https://login.microsoftonline.com/$TenantName";break}
        "USGovGCCHigh" {$Authority = "https://login.microsoftonline.us/$TenantName";break}
        "USGovDoD"     {$Authority = "https://login.microsoftonline.us/$TenantName";break}
        "Germany"      {$Authority = "https://login.microsoftonline.de/$TenantName";break}
        "China"        {$Authority = "https://login.partner.microsoftonline.cn/$TenantName";break}
    }

    Write-Verbose "$(Get-Date) Get-MSALAccessToken function called from the pre-reqs module - Tenant: $TenantName ClientID: $ClientID Resource: $Resource SecretLength: $($Secret.Length) O365EnvironmentName: $O365EnvironmentName"

    $ccApp = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($ClientID).WithClientSecret($Secret).WithAuthority($Authority).Build()

    $Scopes = New-Object System.Collections.Generic.List[string]
    $Scopes.Add("$($Resource)/.default")

    $RetryDelay = 15
    $TokenAttempt = 1
    Do {
        Try {
            Write-Verbose "Attempt #$($TokenAttempt) to get an Access Token using MSAL for $($Resource)"
            $TokenAttempt++
            $token = $ccApp.AcquireTokenForClient($Scopes).ExecuteAsync().GetAwaiter().GetResult()
        }
        Catch {
            Write-Verbose "$(Get-Date) Failed to get a token using MSAL. Sleeping for $($RetryDelay) seconds and then trying again"
            Start-Sleep $RetryDelay
        }
    }
    While (!$token -And $TokenAttempt -lt 12)

    If ($token){Write-Verbose "$(Get-Date) Successfully got a token using MSAL for $($Resource)"}

    return $token
}

Function Get-AzureADConnected {
    <#
    
        Determine if AzureAD is connected

    #>
    Try {
        Get-AzureADTenantDetail -ErrorAction:SilentlyContinue | Out-Null
        Return $True
    } Catch {
        Return $False
    }
}

Function Invoke-GraphTest {
    <#
    
        Performs a test against Graph by pulling secure scores
    
    #>
    Param (
        $AzureADApp,
        $Secret,
        $TenantDomain,
        [string]$O365EnvironmentName
    )

    $Success = $False
    $RunError = $Null

    switch ($O365EnvironmentName) {
        "Commercial"   {$Resource = "https://graph.microsoft.com/";break}
        "USGovGCC"     {$Resource = "https://graph.microsoft.com/";break}
        "USGovGCCHigh" {$Resource = "https://graph.microsoft.us/";break}
        "USGovDoD"     {$Resource = "https://dod-graph.microsoft.us/";break}
        "Germany"      {$Resource = "https://graph.microsoft.de/";break}
        "China"        {$Resource = "https://microsoftgraph.chinacloudapi.cn/"}
    }

    switch ($O365EnvironmentName) {
        "Commercial"   {$Base = "https://graph.microsoft.com";break}
        "USGovGCC"     {$Base = "https://graph.microsoft.com";break}
        "USGovGCCHigh" {$Base = "https://graph.microsoft.us";break}
        "USGovDoD"     {$Base = "https://dod-graph.microsoft.us";break}
        "Germany"      {$Base = "https://graph.microsoft.de";break}
        "China"        {$Base = "https://microsoftgraph.chinacloudapi.cn"}
    }
    $Uri = "$Base/beta/security/secureScores?`$top=1"

    $Token = Get-MSALAccessToken -TenantName $tenantdomain -ClientID $AzureADApp.AppId -Secret $Secret -Resource $Resource -O365EnvironmentName $O365EnvironmentName
    $headerParams = @{'Authorization'="$($Token.TokenType) $($Token.AccessToken)"}

    $Result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $Uri -ErrorAction:SilentlyContinue -ErrorVariable:RunError)

    If($Result.StatusCode -eq 200) {
        $Success = $True
    } Else {
        $Success = $False
    }

    Return New-Object -TypeName PSObject -Property @{
        Check="AAD App Graph Test"
        Pass=$Success
        Debug=$RunError
    }

}

Function Set-AzureADAppPermission {
    <#
    
        Sets the required permissions on the application
    
    #>
    Param(
        $App,
        $PerformConsent=$False,
        [string]$O365EnvironmentName
    )

    Write-Host "$(Get-Date) Setting Azure AD App Permissions for Application"
    Write-Verbose "$(Get-Date) Set-AzureADAppPermissions App: $($App.Id) Cloud: $O365EnvironmentName"

    $RequiredResources = @()
    $PermissionSet = $False
    $ConsentPerformed = $False

    $Roles = Get-RequiredAppPermissions -O365EnvironmentName $O365EnvironmentName

    <#
    
        The following creates a Required Resources array. The array consists of RequiredResourceAccess objects.
        There is one RequiredResourceAccess object for every resource; for instance, Graph is a resource.
        In the RequiredResourceAccess object is an array of scopes that are required for that resource.
    
    #>
    
    foreach($ResourceRolesGrouping in ($Roles | Group-Object Resource)) {

        # Define the resource
        $Resource = New-Object -TypeName Microsoft.Graph.PowerShell.Models.MicrosoftGraphRequiredResourceAccess
        $Resource.ResourceAppId = $ResourceRolesGrouping.Name

        # Add the permissions
        ForEach($Role in $($ResourceRolesGrouping.Group)) {
            Write-Verbose "$(Get-Date) Set-AzureADAppPermissions Add $($Role.Type) $($Role.Name) ($($Role.ID)) in $O365EnvironmentName cloud"
            $Perm = New-Object -TypeName Microsoft.Graph.PowerShell.Models.MicrosoftGraphResourceAccess
            $Perm.Id = $Role.ID
            $Perm.Type = $Role.Type
            $Resource.ResourceAccess += $Perm
        }

        # Add to the list of required access
        $RequiredResources += $Resource

    }
    
    try {
        Update-MgApplication -ApplicationId $App.Id -RequiredResourceAccess $RequiredResources
        $PermissionSet = $True
    }
    catch {
        $PermissionSet = $False
    }

    if ($PermissionSet -eq $True) {
        Write-Host "$(Get-Date) Verifying new permissions applied (this may take up to 5 minutes)..."
        If($(Invoke-AppPermissionCheck -App $App -NewPermission) -eq $False)
        {    
            $PermissionSet = $False
        }
    }

    if ($PerformConsent -eq $True) {
        If((Invoke-Consent -App $App -O365EnvironmentName $O365EnvironmentName) -eq $True) {
            $ConsentPerformed = $True
        }
    }

    If($PermissionSet -eq $True -and $PerformConsent -eq $True -and $ConsentPerformed -eq $True) 
    {
        Return $True
    } 
    ElseIf ($PermissionSet -eq $True -and $PerformConsent -eq $False) 
    {
        Return $True
    } 
    Else
    {
        Return $False
    }

}

Function Invoke-AppPermissionCheck 
{
    <#
        Check the permissions are set correctly on the Azure AD application
    #>
    Param(
        $App,
        [Switch]$NewPermission
    )

    $Provisioned = $True
    
    $Roles = Get-RequiredAppPermissions -O365EnvironmentName $O365EnvironmentName

    # In the event of a NewPermission, $MaxTime should be longer to prevent race conditions
    If($NewPermission)
    {
        $MaxTime = 300
    }
    else
    {
        $MaxTime = 20
    }

    # SleepTime is how long we sleep between checking the permissions
    $SleepTime = 10
    $Counter = 0

    Write-Verbose "$(Get-Date) Invoke-AppPermissionCheck App ID $($App.AppId) Role Count $($Roles.Count)"

    While($Counter -lt $MaxTime)
    {

        # Refresh roles from AAD
        # Set App ID based on property being from Get-MgApplication or Get-AzureADApplication
        if ($App.ObjectId) {$appId = $App.ObjectId} else {$appId = $App.Id}
        #$App = Get-MgApplication -ApplicationId $appId
        $App = Get-AzureADApplication -ObjectId $appId

        $Missing = @()

        # Go through each role this app should have, and check if this is in the RequiredResources field for the app
        ForEach($Role in $Roles) {

            $RequiredResources = @(($app.RequiredResourceAccess | Where-Object {$_.ResourceAppId -eq $Role.Resource}).ResourceAccess).Id

            If($RequiredResources -notcontains $Role.ID) {
                # Role is missing
                $Provisioned = $False
                $Missing += $Role.Name
            }
        }

        If($Provisioned -eq $True)
        {
            Write-Verbose "$(Get-Date) Invoke-AppPermissionCheck App ID $appId Role Count $($Roles.Count) OK"
            Break
        } 
        Else 
        {
            Start-Sleep $SleepTime
            $Counter += $SleepTime
            Write-Verbose "$(Get-Date) Invoke-AppPermissionCheck loop - waiting for permissions on Azure AD Application - Counter $Counter maxTime $MaxTime Missing $($Missing -join ' ')"
        }

    }

    Return $Provisioned

}

function ConvertFrom-JWT {
    param ($token)
    # Perform decode from JWT
    $tokenPayload = $token.accesstoken.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($tokenPayload.Length % 4) { $tokenPayload += "=" }
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    Write-Verbose "$(Get-Date) Invoke-AppTokenRolesCheck Token JWT $($tokenArray)"
    return ($tokenArray | ConvertFrom-Json)
}

Function Invoke-AppTokenRolesCheck {
    <#
    
        This function checks for the presence of the right roles in the token
        Consent may not have been completed without the right roles

    #>
    Param (
        $App,
        $Secret,
        $TenantDomain,
        [string]$O365EnvironmentName
    )

    switch ($O365EnvironmentName) {
        "Commercial"   {$GraphResource = "https://graph.microsoft.com/";break}
        "USGovGCC"     {$GraphResource = "https://graph.microsoft.com/";break}
        "USGovGCCHigh" {$GraphResource = "https://graph.microsoft.us/";break}
        "USGovDoD"     {$GraphResource = "https://dod-graph.microsoft.us/";break}
        "Germany"      {$GraphResource = "https://graph.microsoft.de/";break}
        "China"        {$GraphResource = "https://microsoftgraph.chinacloudapi.cn/"}
    }

    $Roles = Get-RequiredAppPermissions -O365EnvironmentName $O365EnvironmentName

    # For race conditions, we will wait $MaxTime seconds and Sleep interval of $SleepTime
    $MaxTime = 300
    $SleepTime = 10
    $Counter = 0
    
    # Check Graph endpoint
    While($Counter -lt $MaxTime)
    {
        $MissingRoles = @()
        Write-Verbose "$(Get-Date) Invoke-AppTokenRolesCheck Begin for Graph endpoint"
        # Obtain the token
        $Token = Get-MSALAccessToken -TenantName $tenantdomain -ClientID $App.AppId -Secret $Secret -Resource $GraphResource -O365EnvironmentName $O365EnvironmentName

        If($Null -ne $Token)
        {
            # Perform decode from JWT
            $tokobj = ConvertFrom-JWT -token $Token

            # Check the roles are in the token, only check Graph at this stage.
            ForEach($Role in ($Roles | Where-Object {$_.Resource -eq "00000003-0000-0000-c000-000000000000"})) {
                If($tokobj.Roles -notcontains $Role.Name) {
                    Write-Verbose "$(Get-Date) Invoke-AppTokenRolesCheck missing $($Role.Name)"
                    $MissingRoles += $Role
                }
            }
        }
        If($MissingRoles.Count -eq 0 -and $Null -ne $Token)
        {
            $GraphResult = $True
        }
        Else 
        {
            $GraphResult = $False
        }
    
        If($GraphResult -eq $True)
        {
            Break
        } 
        Else 
        {
            Start-Sleep $SleepTime
            $Counter += $SleepTime
            Write-Verbose "$(Get-Date) Invoke-AppTokenRolesCheck loop - Counter $Counter maxTime $MaxTime"
        }
    }

    if ($GraphResult) {
        $return = $true
    }
    else {$return = $false}
    
    
    return $return
}

Function Invoke-WinRMBasicCheck {
    <#
    
        Checks to determine if WinRM basic authentication is enabled.
        This is required for Exchange Online and Teams modules (the latter when connecting via RPS).
    
    #>

    # Default for WinRM Client is enabled, so check whether it has been explicitly disabled.
    If (((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client\" -Name "auth_basic" -ErrorAction:SilentlyContinue).auth_basic -eq 0) -Or (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name "AllowBasic" -ErrorAction:SilentlyContinue).AllowBasic -eq 0) { 
        $Result=$False
    } Else {
        $Result=$True
    }

    Return New-Object -TypeName PSOBject -Property @{
        Check="WinRM Basic Authentication"
        Pass=$Result
    }

}

Function Invoke-Consent {
    <#
    
        Perform consent for application
    
    #>
    Param (
        $App,
        [string]$O365EnvironmentName
    )

    switch ($O365EnvironmentName) {
        "Commercial"   {$AuthLocBase = "https://login.microsoftonline.com";break}
        "USGovGCC"     {$AuthLocBase = "https://login.microsoftonline.com";break}
        "USGovGCCHigh" {$AuthLocBase = "https://login.microsoftonline.us";break}
        "USGovDoD"     {$AuthLocBase = "https://login.microsoftonline.us";break}
        "Germany"      {$AuthLocBase = "https://login.microsoftonline.de";break}
        "China"        {$AuthLocBase = "https://login.partner.microsoftonline.cn"}
    }
    # Need to use the Application ID, not Object ID
    $Location = "$AuthLocBase/common/adminconsent?client_id=$($App.AppId)&state=12345&redirect_uri=https://soaconsentreturn.azurewebsites.net"
    
    Write-Important
    Write-Host "In 10 seconds, a page in the default browser will load and ask you to grant consent to Security Optimization Assessment."
    write-Host "You must sign in with an account that has Global Administrator or Privileged Role Administrator role."
    Write-Host "After granting consent, a green OK message will appear; you can then close the browser page."
    Write-Host ""
    Write-Host "For more information about this consent, go to https://github.com/o365soa/soa."
    Write-Host ""
    Write-Host "If you use single sign-in (SSO) and you are not signed in with an account that has permission to grant consent,"
    Write-Host "you will need to copy the link and paste it in an private browser session."
    Write-Host ""
    Write-Host $Location
    Write-Host ""
    Write-Host "(If the browser window does not open in 10 seconds, copy it and paste it in a browser tab.)"
    Write-Host ""
    Start-Sleep 10
    Start-Process $Location

    While($(Read-Host -Prompt "Type 'yes' when you have completed consent") -ne "yes") {}

    Return $True
}

Function Install-AzureADApp {
    <#

        Installs the Azure AD Application used for accessing Graph and Security APIs
    
    #>
    Param(
        [string]$O365EnvironmentName
    )

    # Create the Azure AD Application
    Write-Verbose "$(Get-Date) Install-AzureADPApp Installing App"
    #$AzureADApp = New-AzureADApplication -DisplayName "Office 365 Security Optimization Assessment"  -ReplyUrls @("https://security.optimization.assessment.local","https://soaconsentreturn.azurewebsites.net")
    $AzureADApp = New-MgApplication -DisplayName "Office 365 Security Optimization Assessment" `
        -Web @{'RedirectUris'=@("https://security.optimization.assessment.local","https://soaconsentreturn.azurewebsites.net")} `
        -PublicClient @{'RedirectUris'='https://login.microsoftonline.com/common/oauth2/nativeclient'} `
        -SignInAudience AzureADMyOrg

    # Set up the correct permissions
    Set-AzureADAppPermission -App $AzureADApp -PerformConsent:$True -O365EnvironmentName $O365EnvironmentName

    # Return the newly created application
    Return (Get-MgApplication -ApplicationId $AzureADApp.Id)
    
}

Function Get-ModuleStatus {
    <#
    
        Determines the status of the module specified by ModuleName
    
    #>
    Param (
        [String]$ModuleName,
        [Switch]$ConflictModule
    )

    Write-Host "$(Get-Date) Checking module $($ModuleName)"

    # Set variables used
    $MultipleFound = $False
    $Installed = $False

    $InstalledModule = @(Get-Module -Name $ModuleName -ListAvailable)

    ForEach($M in $InstalledModule)
    {
        Write-Verbose "$(Get-Date) Get-ModuleStatus $ModuleName Version $($M.Version.ToString()) Path $($M.Path)"
    }

    $modulePaths = @()
    foreach ($m in ($InstalledModule | Sort-Object Version -Desc)) {
        $modulePaths += $m.Path.Substring(0,$m.Path.LastIndexOf('\'))
    }

    If($InstalledModule.Count -gt 1) {
        # More than one module, flag this
        $MultipleFound = $True
        $Installed = $True

        # Use the latest for comparisons
        $InstalledModule = ($InstalledModule | Sort-Object Version -Desc)[0]
    } ElseIf($InstalledModule.Count -eq 1) {
        # Only one installed
        $Installed = $True
    }

    # Check version in PS Gallery
    $PSGalleryModule = @(Find-Module $ModuleName -ErrorAction:SilentlyContinue)
    If($PSGalleryModule.Count -eq 1) {
        [version]$GalleryVersion = $PSGalleryModule.Version
        If($GalleryVersion -gt $InstalledModule.Version) {
            $NewerAvailable = $true
        } Else {
            $NewerAvailable = $false
        }
    }

    Write-Verbose "$(Get-Date) Get-ModuleStatus $ModuleName Verdict Installed $($Installed) InstalledV $($InstalledModule.Version) GalleryV $($GalleryVersion) Multiple $($Multiple) NewerAvailable $($NewerAvailable)"

    Return New-Object -TypeName PSObject -Property @{
        Module=$ModuleName
        InstalledVersion=$InstalledModule.Version
        GalleryVersion=$GalleryVersion
        Installed=$Installed
        Conflict=$(If($Installed -and $ConflictModule) { $True } Else { $False })
        Multiple=$MultipleFound
        Path=$modulePaths
        NewerAvailable=$NewerAvailable
    }
  
}

Function Uninstall-OldModules {
    <#
    
        Removes old versions of a module

    #>
    Param(
        $Module
    )

    $Modules = (Get-Module $Module -ListAvailable | Sort-Object Version -Descending)
    $Latest = $Modules[0]

    If($Modules.Count -gt 1) {
        ForEach($Module in $Modules) {
            If($Module.Version -ne $Latest.Version) {
                # Not the latest version, remove it.
                Write-Host "$(Get-Date) Uninstalling $($Module.Name) Version $($Module.Version)"
                Try {
                    Uninstall-Module $Module.Name -RequiredVersion $($Module.Version) -ErrorAction:Stop
                } Catch {
                    # Some code needs to be placed here to catch possible error.
                }
                
            }
        }
    }
}

Function Remove-FromPSModulePath {
    <#
    
        Remove from PSModulePath

        This module removes paths from the PSModulePath. It can be used to 'uninstall' the manual installation
        of the SharePoint module, for instance.

    #>
    Param(
        $Folder
    )

    $PathArray = (Get-ChildItem Env:PSModulePath).Value.Split(";")

    If($PathArray -Contains $Folder) {
        Write-Host "$(Get-Date) Removing $Folder from PSModulePath"
        $NewPathArray = $PathArray | Where-Object {$_ -ne $Folder}
        Set-Item Env:PSModulePath -Value ($NewPathArray -Join ";")
        Return $True
    } Else {
        Write-Error "Attempted to remove $Folder from PSModulePath, however, there is no entry. PSModulePath is $((Get-ChildItem Env:PSModulePath).Value)"
        Return $False
    }

}

Function Get-PSModulePath {
    <#
    
    Gets PSModulePath using a like condition.
    This is used for determining if a module is manually installed, and can be used for removing that manual installation.

    #>
    Param (
        $LikeCondition
    )

    $PathArray = (Get-ChildItem Env:PSModulePath).Value.Split(";")
    $Return = @($PathArray | Where-Object {$_ -like $LikeCondition})

    Return $Return

}

function Get-LicenseStatus {
    param ($LicenseType)
    if ($LicenseType -eq 'ATPP2') {
        # SKUs that start with strings include Defender P2 to be able to use the Defender API
        $targetSkus = @('ENTERPRISEPREMIUM','SPE_E5','SPE_F5','M365EDU_A5','IDENTITY_THREAT_PROTECTION','THREAT_INTELLIGENCE','M365_SECURITY_COMPLIANCE','Microsoft_365 G5_Security','M365_G5')
    }
    else {
        Write-Error -Message "$(Get-Date) Invalid license type specified"
        return $false
    }
    
    $subscribedSku = Get-AzureADSubscribedSku
    foreach ($tSku in $targetSkus) {
        foreach ($sku in $subscribedSku) {
            if ($sku.PrepaidUnits.Enabled -gt 0 -or $sku.PrepaidUnits.Warning -gt 0 -and $sku.SkuPartNumber -match $tSku) {
                Write-Verbose "$(Get-Date) Get-LicenseStatus $LicenseType`: True "
                return $true
            }
        }
    }
    Write-Verbose "$(Get-Date) Get-LicenseStatus $LicenseType`: False "
    return $false
}

Function Install-ModuleFromGallery {
    <#
    
        Updates module from PSGallery
    
    #>
    Param(
        $Module,
        [Switch]$Update
    )

    # Install the module from PSGallery specifying Force
    # AllowClobber allows Teams module to be installed when SfBO module is installed/loaded
    if (Get-IsAdministrator) {
        Install-Module $Module -Force -Scope:AllUsers -AllowClobber
    }
    else {
        Install-Module $Module -Force -Scope:CurrentUser -AllowClobber
    }

    If($Update) {
        # Remove old versions of the module
        Uninstall-OldModules -Module $Module
    }
}

Function Install-ADDSModule {
    <#
    
        Installs the on-prem Active Directory module based on the detected OS version
    
    #>

    if (Get-IsAdministrator) {
        $ComputerInfo = Get-ComputerInfo

        If($ComputerInfo) {
            Write-Verbose "Computer type: $($ComputerInfo.WindowsInstallationType)"
            Write-Verbose "OS Build: $($ComputerInfo.OsBuildNumber)"
            If ($ComputerInfo.WindowsInstallationType -eq "Server") {
                Write-Verbose "Server OS detected, using 'Add-WindowsFeature'"
                Try {
                    Add-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature | Out-Null
                } Catch {
                    Write-Error "$(Get-Date) Could not install ActiveDirectory module"
                }
            }
            ElseIf ($ComputerInfo.WindowsInstallationType -eq "Client" -And $ComputerInfo.OsBuildNumber -ge 17763) {
                Write-Verbose "Windows 10 version 1809 or later detected, using 'Add-WindowsCapability'"
                Try {
                    Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" | Out-Null
                } Catch {
                    Write-Error "$(Get-Date) Could not install ActiveDirectory module. Is -UseProxy needed? If configured for WSUS, you will need to deploy the module from there."
                }
            }
            ElseIf ($ComputerInfo.WindowsInstallationType -eq "Client") {
                Write-Verbose "Windows 10 version 1803 or earlier detected, using 'Enable-WindowsOptionalFeature'"
                Try {
                    Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell | Out-Null
                } Catch {
                    Write-Error "$(Get-Date) Could not install ActiveDirectory module. Is -UseProxy needed? If configured for WSUS, you will need to deploy the module from there or install from https://www.microsoft.com/en-us/download/details.aspx?id=45520."
                }
            }
            Else {
                Write-Error "Error detecting the OS type while installing Active Directory module."
            }
        }
    }
    else {
        Exit-Script
        throw "$(Get-Date) You must be running PowerShell as an administrator in order to install the Active Directory module."
    }
}

Function Invoke-ModuleFix {
    <#

        Attempts to fix modules if $Remediate flag is specified
    
    #>
    Param($Modules)

    $OutdatedModules = $Modules | Where-Object {$null -ne $_.InstalledVersion -and $_.NewerAvailable -eq $true -and $_.Conflict -ne $True}
    # Administrator needed to remove modules in other profiles
    if ($RemoveMultipleModuleVersions) {
        if (Get-IsAdministrator) {
        $DupeModules = $Modules | Where-Object {$_.Multiple -eq $True}
        }
        else {
            Exit-Script
            throw "Start PowerShell as an administrator to be able to uninstall multiple versions of modules."
            return $False
        } 
    }
    $MissingGalleryModules = $Modules | Where-Object {$null -eq $_.InstalledVersion -and $null -ne $_.GalleryVersion }
    $ConflictModules = $Modules | Where-Object {$_.Conflict -eq $True}
    $MissingNonGalleryModules = $Modules | Where-Object {$null -eq $_.InstalledVersion -and $null -eq $_.GalleryVersion}

    # Determine status of PSGallery repository
    $PSGallery = Get-PSRepository -Name "PSGallery"
    If($PSGallery) {
        If($PSGallery.InstallationPolicy -eq "Untrusted") {
            # Untrusted PSGallery, set to trust
            Write-Host "$(Get-Date) Trusting PSGallery for remediation activities"
            Try {
                Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction Stop
            } Catch {
                Exit-Script
                throw "$(Get-Date) Unable to set PSGallery as trusted"
                
            }
        }
    } Else {
        Exit-Script
        throw "PSGallery is not present on this host, so modules cannot be installed."
        
    }

    # Conflict modules, need to be removed
    ForEach($ConflictModule in $ConflictModules) {
        Write-Host "$(Get-Date) Removing conflicting module $($ConflictModule.Module)"
        Uninstall-Module -Name $($ConflictModule.Module) -Force
    }

    # Out of date modules
    ForEach($OutdatedModule in $OutdatedModules) {
        Write-Host "$(Get-Date) Installing version $($OutdatedModule.GalleryVersion) of $($OutdatedModule.Module) (highest installed version is $($OutdatedModule.InstalledVersion))"
        if ($RemoveMultipleModuleVersions) {
            Install-ModuleFromGallery -Module $($OutdatedModule.Module) -Update
        }
        else {
            Install-ModuleFromGallery -Module $($OutdatedModule.Module)
        }
    }

    # Missing gallery modules
    ForEach($MissingGalleryModule in $MissingGalleryModules) {
        Write-Host "$(Get-Date) Installing $($MissingGalleryModule.Module)"
        Install-ModuleFromGallery -Module $($MissingGalleryModule.Module)          
    }

    # Dupe modules
    ForEach($DupeModule in $DupeModules) {
        Write-Host "$(Get-Date) Removing older versions of modules for $($DupeModule.Module)"
        Uninstall-OldModules -Module $($DupeModule.Module)
    }

    # Missing modules which are not available from gallery
    ForEach($MissingNonGalleryModule in $MissingNonGalleryModules) {
        Write-Host "$(Get-Date) Installing $($MissingNonGalleryModule.Module)"

        Switch ($MissingNonGalleryModule.Module) {
            "ActiveDirectory" {
                Write-Verbose "$(Get-Date) Installing on-premises Active Directory module"
                Install-ADDSModule
            }
        }
    }
}

Function Get-ManualModules
{
    <#
    
    Determines if there are any manual module installs as opposed to PowerShell Gallery installs
    
    #>
    Param(
        [Switch]$Remediate
    )

    $Return = @()

    $ModuleChecks = @("SharePoint Online Management Shell")

    ForEach($ModuleCheck in $ModuleChecks)
    {
        $RemediateSuccess = $False

        $Result = Get-PSModulePath -LikeCondition "*$($ModuleCheck)*"

        If($Remediate) 
        {
            ForEach ($r in $Result)
            {
                $RemediateSuccess = Remove-FromPSModulePath -Folder $r
            }
        }

        If($Result.Count -gt 0 -and $RemediateSuccess -eq $False) {
            $Return += $ModuleCheck
        }
    }

    Return $Return

}

Function Invoke-SOAModuleCheck {
    param (
        [string]$O365EnvironmentName
    )
    $RequiredModules = @()
    
    # Conflict modules are modules which their presence causes issues
    $ConflictModules = @()

    # Bypass checks
    If($Bypass -notcontains "AAD") { $RequiredModules += "AzureADPreview" }
    If($Bypass -notcontains "MSOL") { $RequiredModules += "MSOnline" }
    If($Bypass -notcontains "SPO") { $RequiredModules += "Microsoft.Online.SharePoint.PowerShell" }
    If($Bypass -notcontains "Teams") {$RequiredModules += "MicrosoftTeams"}
    If (($Bypass -notcontains "EXO" -or $Bypass -notcontains "SCC")) {$RequiredModules += "ExchangeOnlineManagement"}
    If ($Bypass -notcontains "PP") {
        if ($O365EnvironmentName -eq "Germany") {
            Write-Host "$(Get-Date) Skipping Power Apps module because Power Platform isn't supported in Germany cloud..."
        }
        else {
            $RequiredModules += "Microsoft.PowerApps.Administration.PowerShell"
        }
    }
    If($Bypass -notcontains "Graph") {
        $RequiredModules += "Microsoft.Graph.Authentication"
        $RequiredModules += "Microsoft.Graph.Security"
        $RequiredModules += "Microsoft.Graph.Applications"
    }
    If($Bypass -notcontains "ActiveDirectory") { $RequiredModules += "ActiveDirectory" }

    $ModuleCheckResult = @()

    ForEach($m in $RequiredModules) {
        $ModuleCheckResult += (Get-ModuleStatus -ModuleName $m)
    }

    ForEach($m in $ConflictModules) {
        $MInfo = (Get-ModuleStatus -ModuleName $m -ConflictModule)
        If($MInfo.Installed -eq $True) {
            $ModuleCheckResult += $MInfo
        }
    }

    Return $ModuleCheckResult
}

function Import-PSModule {
    param (
        $ModuleName,
        [switch]$Implicit
        )

    if ($Implicit -eq $false) {
        $highestVersion = (Get-Module -Name $ModuleName -ListAvailable | Sort-Object -Property Version -Descending | Select-Object -First 1).Version.ToString()
        # Multiple loaded versions are listed in reverse order of precedence
        $loadedModule = Get-Module -Name $ModuleName | Select-Object -Last 1
        if ($loadedModule -and $loadedModule.Version.ToString() -ne $highestVersion) {
            # Unload module if the highest version isn't loaded or not highest precedence
            Write-Verbose -Message "Version $($loadedModule.Version.ToString()) of $ModuleName is loaded, but the highest installed version is $highestVersion. The module will be unloaded and the highest version loaded."
            Remove-Module -Name $ModuleName
        }
        if ($ModuleName -eq 'Microsoft.PowerApps.Administration.PowerShell') {
            # Explicitly load its auth module using SilentlyContinue to suppress warnings due to Recover-* being an unapproved verb in the Auth module
            $PAPath = (Get-Module -Name $ModuleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).ModuleBase
            Import-Module (Join-Path -Path $PAPath "Microsoft.PowerApps.AuthModule.psm1") -WarningAction:SilentlyContinue -Force
        }
        elseif ($ModuleName -eq 'AzureADPreview') {
            if (Get-Module -Name AzureAD) {
                # Unload AAD module to ensure only cmdlets from the AAD Preview module are used
                Remove-Module AzureAD
            }
        }
        Import-Module -Name $ModuleName -RequiredVersion $highestVersion -ErrorVariable loadError -Force -WarningAction SilentlyContinue
        if ($loadError) {
            Write-Error -Message "Error loading module $ModuleName."
        }
    }
}
Function Test-Connections {
    Param(
        $RPSProxySetting,
        [string]$O365EnvironmentName
    )

    $Connections = @()

    Write-Host "$(Get-Date) Testing connections..."
    #$userUPN = Read-Host -Prompt "What is the UPN of the admin account that you will be signing in with for connection validation and with sufficient privileges to register the Azure AD application"

    <#
        
        AD PowerShell Version 1. Aka MSOL
        
    #>
    If($Bypass -notcontains "MSOL") {

        Import-PSModule -ModuleName MSOnline -Implicit $UseImplicitLoading
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        Write-Host "$(Get-Date) Connecting to Azure AD PowerShell 1..."
        switch ($O365EnvironmentName) {
            "Commercial"   {Connect-MsolService -ErrorAction:SilentlyContinue -ErrorVariable ConnectError;break}
            "USGovGCC"     {Connect-MsolService -ErrorAction:SilentlyContinue -ErrorVariable ConnectError;break}
            "USGovGCCHigh" {Connect-MsolService -AzureEnvironment USGovernment -ErrorAction:SilentlyContinue -ErrorVariable ConnectError;break}
            "USGovDoD"     {Connect-MsolService -AzureEnvironment USGovernment -ErrorAction:SilentlyContinue -ErrorVariable ConnectError;break}
            "Germany"      {Connect-MsolService -AzureEnvironment AzureGermanyCloud -ErrorAction:SilentlyContinue -ErrorVariable ConnectError;break}
            "China"        {Connect-MsolService -AzureEnvironment AzureChinaCloud -ErrorAction:SilentlyContinue -ErrorVariable ConnectError}
        }
        
        # If no error, try test command
        If($ConnectError) { $Connect = $False; $Command = $False} Else { 
            $Connect = $True 
            # Cmdlet that can be run by any user
            Get-MsolUser -MaxResults 1 -ErrorAction SilentlyContinue -ErrorVariable CommandError | Out-Null
            # Cmdlet that requires admin role
            #Get-MsolDomain -ErrorAction SilentlyContinue -ErrorVariable CommandError | Out-Null
            If($CommandError) { $Command = $False } Else { $Command = $True }
        }

        $Connections += New-Object -TypeName PSObject -Property @{
            Name="MSOL"
            Connected=$Connect
            ConnectErrors=$ConnectError
            TestCommand=$Command
            TestCommandErrors=$CommandError
        }
    }

    <#
    
        AD PowerShell Version 2.
    
    #>
    If($Bypass -notcontains "AAD") {
        Import-PSModule -ModuleName AzureADPreview -Implicit $UseImplicitLoading
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        Write-Host "$(Get-Date) Connecting to Azure AD PowerShell 2..."
        switch ($O365EnvironmentName) {
            "Commercial"   {Connect-AzureAD -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
            "USGovGCC"     {Connect-AzureAD -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
            "USGovGCCHigh" {Connect-AzureAD -ErrorAction:SilentlyContinue -ErrorVariable ConnectError -AzureEnvironmentName AzureUSGovernment | Out-Null;break}
            "USGovDoD"     {Connect-AzureAD -ErrorAction:SilentlyContinue -ErrorVariable ConnectError -AzureEnvironmentName AzureUSGovernment | Out-Null;break}
            "Germany"      {Connect-AzureAD -ErrorAction:SilentlyContinue -ErrorVariable ConnectError -AzureEnvironmentName AzureGermanyCloud | Out-Null;break}
            "China"        {Connect-AzureAD -ErrorAction:SilentlyContinue -ErrorVariable ConnectError -AzureEnvironmentName AzureChinaCloud | Out-Null}
        }

        # If no error, try test command
        If($ConnectError) { $Connect = $False; $Command = $False} Else { 
            $Connect = $True 
            # Cmdlet that can be run by any user
            Get-AzureADUser -Top 1 -ErrorAction SilentlyContinue -ErrorVariable CommandError | Out-Null
            # Cmdlet that requires admin role
            # Get-AzureADDomain -ErrorAction SilentlyContinue -ErrorVariable CommandError | Out-Null
            If($CommandError) { $Command = $False } Else { $Command = $True }
        }

        $Connections += New-Object -TypeName PSObject -Property @{
            Name="AADV2"
            Connected=$Connect
            ConnectErrors=$ConnectError
            TestCommand=$Command
            TestCommandErrors=$CommandError
        }
    }

    <#
    
        SCC
    
    #>
    if ($Bypass -notcontains 'SCC' -or $Bypass -notcontains 'EXO') {
        Import-PSModule -ModuleName ExchangeOnlineManagement -Implicit $UseImplicitLoading
    }

    If($Bypass -notcontains "SCC") {
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        # Skip connection test if WinRM Basic is disabled
        if ((Invoke-WinRMBasicCheck).Pass) {
            Write-Host "$(Get-Date) Connecting to SCC..."
            Get-PSSession | Where-Object {$_.ComputerName -like "*protection.o*"} | Remove-PSSession
            switch ($O365EnvironmentName) {
                "Commercial"   {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null;break}
                "USGovGCC"   {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null;break}
                "USGovGCCHigh" {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ConnectionUri https://ps.compliance.protection.office365.us/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.microsoftonline.us/common | Out-Null;break}
                "USGovDoD"     {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ConnectionUri https://l5.ps.compliance.protection.office365.us/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.microsoftonline.us/common | Out-Null;break}
                "Germany"      {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ConnectionUri https://ps.compliance.protection.outlook.de/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.microsoftonline.de/common | Out-Null;break}
                "China"        {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ConnectionUri https://ps.compliance.protection.partner.outlook.cn/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.partner.microsoftonline.cn/common | Out-Null}
            }
        }
        else {
            Write-Host "$(Get-Date) Skipping connection test for SCC because WinRM Basic is disabled. This must be remediated prior to the engagement." -ForegroundColor Red
        }
        If((Get-PSSession | Where-Object {$_.ComputerName -like "*protection.o*" -or $_.ComputerName -like "*protection.partner.o*"}).State -eq "Opened") { $Connect = $True } Else { $Connect = $False }

        # Has test command been imported. Not actually running it
        # Cmdlet available to any user
        if (Get-Command Get-Recipient) {
        # Cmdlet available to admins
        #If(Get-Command "Get-ProtectionAlert") {
            $Command = $True
        } Else {
            $Command = $False
        }

        $Connections += New-Object -TypeName PSObject -Property @{
            Name="SCC"
            Connected=$Connect
            ConnectErrors=$ConnectError
            TestCommand=$Command
            TestCommandErrors=$CommandError
        }
    }

    <#
    
        Exchange
    
    #>
    If($Bypass -notcontains "EXO") {
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        Write-Host "$(Get-Date) Connecting to Exchange..."
        switch ($O365EnvironmentName) {
            "Commercial"   {Connect-ExchangeOnline -ShowBanner:$false -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null;break}
            "USGovGCC"     {Connect-ExchangeOnline -ShowBanner:$false -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null;break}
            "USGovGCCHigh" {Connect-ExchangeOnline -ExchangeEnvironmentName O365USGovGCCHigh -ShowBanner:$false -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null;break}
            "USGovDoD"     {Connect-ExchangeOnline -ExchangeEnvironmentName O365USGovDoD -ShowBanner:$false -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null;break}
            "Germany"      {Connect-ExchangeOnline -ExchangeEnvironmentName O365GermanyCloud -ShowBanner:$false -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null;break}
            "China"        {Connect-ExchangeOnline -ExchangeEnvironmentName O365China -ShowBanner:$false -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null}
        }
       
        If((Get-ConnectionInformation | Where-Object {$_.ConnectionUri -like "*outlook.office*" -or $_.ConnectionUri -like "*webmail.apps.mil*" -or $_.ConnectionUri -like "*partner.outlook.cn*"}).TokenStatus -eq "Active") { $Connect = $True } Else { $Connect = $False }

        # Has test command been imported. Not actually running it
        # Cmdlet available to any user
        if (Get-Command Get-Mailbox) {
        # Cmdlet available to admin
        #If(Get-Command "Get-OrganizationConfig") {
            If((Get-OrganizationConfig).Name) {
                $Command = $True
            } Else {
                $Command = $False
            }
        } Else {
            $Command = $False
        }

        $Connections += New-Object -TypeName PSObject -Property @{
            Name="Exchange"
            Connected=$Connect
            ConnectErrors=$ConnectError
            TestCommand=$Command
            TestCommandErrors=$CommandError
        }
    }

    <#
        SharePoint
    
    #>
    If($Bypass -notcontains "SPO") {
        Import-PSModule -ModuleName Microsoft.Online.SharePoint.PowerShell -Implicit $UseImplicitLoading
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        $adminUrl = Get-SharePointAdminUrl -O365EnvironmentName $O365EnvironmentName
        Write-Host "$(Get-Date) Connecting to SharePoint Online (using $adminUrl)..."
        switch ($O365EnvironmentName) {
            "Commercial"   {Connect-SPOService -Url $adminUrl -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
            "USGovGCC"     {Connect-SPOService -Url $adminUrl -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
            "USGovGCCHigh" {Connect-SPOService -Url $adminUrl -Region ITAR -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
            "USGovDoD"     {Connect-SPOService -Url $adminUrl -Region ITAR -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
            "Germany"      {Connect-SPOService -Url $adminUrl -Region Germany -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
            "China"        {Connect-SPOService -Url $adminUrl -Region China -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null}
        }

        # If no error, try test command
        If($ConnectError) { $Connect = $False; $Command = $False} Else { 
            $Connect = $True 
            # Cmdlet that can be run by anyone
            Get-SPOSite -Limit 1 -ErrorAction SilentlyContinue -ErrorVariable CommandError -WarningAction SilentlyContinue | Out-Null
            # Cmdlet that can be run by admin
            #Get-SPOTenant -ErrorAction SilentlyContinue -ErrorVariable CommandError | Out-Null
            If($CommandError) { $Command = $False } Else { $Command = $True }
        }

        $Connections += New-Object -TypeName PSObject -Property @{
            Name="SPO"
            Connected=$Connect
            ConnectErrors=$ConnectError
            TestCommand=$Command
            TestCommandErrors=$CommandError
        }
    }
    
    <#
    
        Microsoft Teams
    
    #>
    If($Bypass -notcontains "Teams") {
        Import-PSModule -ModuleName MicrosoftTeams -Implicit $UseImplicitLoading
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        Write-Host "$(Get-Date) Connecting to Microsoft Teams..."
        $InitialDomain = (Get-AzureADTenantDetail | Select-Object -ExpandProperty VerifiedDomains | Where-Object { $_.Initial }).Name
        switch ($O365EnvironmentName) {
            "Commercial"    {Connect-MicrosoftTeams -TenantId $InitialDomain -ErrorVariable ConnectError -ErrorAction:SilentlyContinue;break}
            "USGovGCC"      {Connect-MicrosoftTeams -TenantId $InitialDomain -ErrorVariable ConnectError -ErrorAction:SilentlyContinue;break}
            "USGovGCCHigh"  {Connect-MicrosoftTeams -TeamsEnvironmentName TeamsGCCH -TenantId $InitialDomain -ErrorVariable ConnectError -ErrorAction:SilentlyContinue;break}
            "USGovDoD"      {Connect-MicrosoftTeams -TeamsEnvironmentName TeamsDOD -TenantId $InitialDomain -ErrorVariable ConnectError -ErrorAction:SilentlyContinue;break}
            #"Germany"      {"Status of Teams in Germany cloud is unknown";break}
            "China"         {Write-Host "Teams is not available in 21Vianet offering";break}
            default         {Connect-MicrosoftTeams -TenantId $InitialDomain -ErrorVariable ConnectError -ErrorAction:SilentlyContinue}
        }
        #Leaving a 'default' entry to catch Germany until status can be determined, attempting standard connection

        # If no error, try test command
        if ($ConnectError) {
            $Connect = $False
            $Command = $False
        }
        else { 
            $Connect = $true
            # Cmdlet that can be run by anyone
            if (Get-CsOnlineUser -ResultSize 1) {
            # Cmdlet that can be run by admin
            #if (Get-CsTenantFederationConfiguration) {
                $Command = $True
            } 
            else {
                $Command = $False
            }
        }

        $Connections += New-Object -TypeName PSObject -Property @{
            Name="Teams"
            Connected=$Connect
            ConnectErrors=$ConnectError
            TestCommand=$Command
            TestCommandErrors=$CommandError
        }
    }

    <#
    
        Power Apps
    
    #>
    If($Bypass -notcontains 'PP') {
        if ($O365EnvironmentName -eq 'Germany') {
            Write-Host "$(Get-Date) Skipping connection to Power Apps because it is not supported in Germany cloud..."
        }
        else {
            Import-PSModule -ModuleName Microsoft.PowerApps.Administration.PowerShell -Implicit $UseImplicitLoading
            # Reset vars
            $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

            Write-Host "$(Get-Date) Connecting to Power Apps..."
            switch ($O365EnvironmentName) {
                "Commercial"   {Add-PowerAppsAccount -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
                "USGovGCC"     {Add-PowerAppsAccount -ErrorAction:SilentlyContinue -ErrorVariable ConnectError -Endpoint usgov | Out-Null;break}
                "USGovGCCHigh" {Add-PowerAppsAccount -ErrorAction:SilentlyContinue -ErrorVariable ConnectError -Endpoint usgovhigh | Out-Null;break}
                "USGovDoD"     {Add-PowerAppsAccount -ErrorAction:SilentlyContinue -ErrorVariable ConnectError -Endpoint dod | Out-Null;break}
                #"Germany"     {"Power Platform is not available in Germany" | Out-Null;break}
                "China"        {Add-PowerAppsAccount -ErrorAction:SilentlyContinue -ErrorVariable ConnectError -Endpoint china | Out-Null}
            }

            # If no error, try test command
            if ($ConnectError) { $Connect = $False; $Command = ""} Else { 
                $Connect = $True 
                # Check if data is returned
                # Ensure that the correct module is used as Get-DlpPolicy also exists within the Exchange module
                $cmdResult = Microsoft.PowerApps.Administration.PowerShell\Get-DlpPolicy -ErrorAction:SilentlyContinue -ErrorVariable:CommandError
                if ($CommandError -or -not($cmdResult)) {
                    # Cmdlet may not return data if no PA license assigned or user has not been to PPAC before
                    Write-Warning -Message "No data was returned when running the test command. This can occur if the admin has never used the Power Platform Admin Center (PPAC). Please go to https://aka.ms/ppac and sign in as the Global administrator or Dynamics 365 administrator account you used to connect to Power Platform in PowerShell.  Then return here to continue."
                    Read-Host -Prompt "Press Enter after you have navigated to PPAC and signed in with the adminstrator account used above to connect to Power Platform in PowerShell."
                    $cmdResult = Microsoft.PowerApps.Administration.PowerShell\Get-DlpPolicy -ErrorAction:SilentlyContinue -ErrorVariable:CommandError
                    if ($CommandError -or -not($cmdResult)) {
                        $Command = $False
                    }
                    else {
                        $Command = $true
                    }
                }
                else {
                    $Command = $True
                }
            }

            $Connections += New-Object -TypeName PSObject -Property @{
                Name="PowerApps"
                Connected=$Connect
                ConnectErrors=$ConnectError
                TestCommand=$Command
                TestCommandErrors=$CommandError
            }
        }
    }

    Return $Connections
}

Function Get-RequiredAppPermissions {
    param
    (
    [string]$O365EnvironmentName="Commercial"
    )

    <#
        This function returns the required application permissions for the AAD application

        Required Application Permissions

        ID, Name and Resource are required
        - ID is the scope's unique GUID
        - Name is used during the token check (to see we are actually getting these scopes assigned to us)
        - Resource is the application ID for the API we are using, usually this is "00000003-0000-0000-c000-000000000000" which is for Graph
    #>

    $AppRoles = @()

    # Microsoft Graph
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="bf394140-e372-4bf9-a898-299cfc7564e5"
        Name="SecurityEvents.Read.All"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph    
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="dc5007c0-2d7d-4c42-879c-2dab87571379"
        Name="IdentityRiskyUser.Read.All"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="6e472fd1-ad78-48da-a0f0-97ab2c6b769e"
        Name="IdentityRiskEvent.Read.All"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
        Name="DeviceManagementConfiguration.Read.All"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="b0afded3-3588-46d8-8b3d-9842eff778da"
        Name="AuditLog.Read.All"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="7ab1d382-f21e-4acd-a863-ba3e13f7da61"
        Name="Directory.Read.All"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="246dd0d5-5bd0-4def-940b-0421030a5b68"
        Name="Policy.Read.All"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="45cc0394-e837-488b-a098-1918f48d186c"
        Name="SecurityIncident.Read.All"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="78ce3f0f-a1ce-49c2-8cde-64b5c0896db4"
        Name="user_impersonation"
        Type='Scope'
        Resource="00000007-0000-0000-c000-000000000000" # Dynamics 365
    }
    Return $AppRoles
}

Function Invoke-ManualModuleCheck
{
        <#
        
            Manual installation check

            Manual installs can cause issues with modules installed from the PowerShell gallery.
            It is also difficult to update manual PowerShell module installs.
        
        #>

        Write-Host "$(Get-Date) Checking manual module installations..."
        $ManualInstalls = Get-ManualModules

        If($ManualInstalls -gt 0)
        {

            Write-Host "$(Get-Date) Modules manually installed that need to be removed:"
            $ManualInstalls

            If($DoNotRemediate -eq $false){
                # Fix manual installs
                $ManualInstalls = Get-ManualModules -Remediate
            }
            else {
                $ManualInstalls = Get-ManualModules
            }

            If($ManualInstalls.Count -gt 0)
            {
                Write-Important

                Write-Host "$(Get-Date) The module check has failed because some modules have been manually installed. These will conflict with newer required modules from the PowerShell Gallery." -ForegroundColor Red

                if ($DoNotRemediate -eq $false) {
                    Exit-Script
                    throw "$(Get-Date) An attempt to remove these from the PowerShell path was unsuccessful. You must remove them using Add/Remove Programs."
                }
            }
        }
}

Function Invoke-SOAVersionCheck
{
    <#
    
        Determines if SOA module is up to date
    
    #>

    $SOAGallery = Find-Module SOA
    $SOAModule = Get-Module SOA

    If($SOAGallery.Version -gt $SOAModule.Version) 
    {
        $NewerAvailable = $True
    }
    else
    {
        $NewerAvailable = $False
    }

    Write-Verbose "$(Get-Date) Invoke-SOAVersionCheck NewerAvailable $NewerAvailable Gallery $($SOAGallery.Version) Module $($SOAModule.Version)"

    Return New-Object -TypeName PSObject -Property @{
        NewerAvailable = $NewerAvailable
        Gallery = $SOAGallery.Version
        Module = $SOAModule.Version
    }

}

function Get-SOAAzureADApp {
    Param(
        [string]$O365EnvironmentName
    )

    # Determine if Azure AD Application Exists
    #$AzureADApp = Get-AzureADApplication -Filter "displayName eq 'Office 365 Security Optimization Assessment'" | Where-Object {$_.ReplyUrls -Contains "https://security.optimization.assessment.local"}
    $AzureADApp = Get-MgApplication -Filter "displayName eq 'Office 365 Security Optimization Assessment'" | Where-Object {$_.Web.RedirectUris -Contains "https://security.optimization.assessment.local"}

    if (!$AzureADApp) {
        if ($DoNotRemediate -eq $false) {
            Write-Host "$(Get-Date) Installing Azure AD Application..."
            $AzureADApp = Install-AzureADApp -O365EnvironmentName $O365EnvironmentName
            Write-Verbose "$(Get-Date) Get-SOAAzureADApp App $($AzureADApp.Id)"
        }
    }
    else {
        # Check if public client URI is set
        $pcRUrl = 'https://login.microsoftonline.com/common/oauth2/nativeclient'
        if ($AzureADApp.PublicClient.RedirectUris -notcontains $pcRUrl) {
            if ($DoNotRemediate -eq $false){
                # Set as public client to be able to collect from Dynamics with delegated scope
                Write-Verbose "$(Get-Date) Setting Azure AD application public client redirect URI..."
                Update-MgApplication -ApplicationId $AzureADApp.Id -PublicClient @{'RedirectUris'=$pcRUrl}
                # Get app again so public client is set for checking DoNotRemediate in calling function
                $AzureADApp = Get-MgApplication -ApplicationId $AzureADApp.Id
            }
        }
    }

    Return $AzureADApp

}

Function Test-SOAApplication
{
    Param
    (
        [Parameter(Mandatory=$true)]
        $App,
        [Parameter(Mandatory=$true)]
        $Secret,
        [Parameter(Mandatory=$true)]
        $TenantDomain,
        [Switch]$WriteHost,
        [string]$O365EnvironmentName="Commercial"
    )

    Write-Verbose "$(Get-Date) Test-SOAApplication App $($App.AppId) TenantDomain $($TenantDomain) SecretLength $($Secret.Length) O365EnvironmentName $O365EnvironmentName"

    # Perform permission check
    If($WriteHost) { Write-Host "$(Get-Date) Performing application permission check... (This may take up to 5 minutes)" }
    $PermCheck = Invoke-AppPermissionCheck -App $App

    # Perform check for consent
    If($PermCheck -eq $True)
    {
        If($WriteHost) { Write-Host "$(Get-Date) Performing token check... (This may take up to 5 minutes)" }
        $TokenCheck = Invoke-AppTokenRolesCheck -App $App -Secret $Secret -TenantDomain $tenantdomain -O365EnvironmentName $O365EnvironmentName
    }

    Return New-Object -TypeName PSObject -Property @{
        Permissions=$PermCheck
        Token=$TokenCheck
    }
                
}

Function Install-SOAPrerequisites
{
    [CmdletBinding(DefaultParametersetname="Default")]
    Param (
    [Parameter(ParameterSetName='Default')]
    [Parameter(ParameterSetName='ConnectOnly')]
    [Parameter(ParameterSetName='ModulesOnly')]
        [ValidateSet("AAD","MSOL","EXO","SCC","SPO","PP","Teams","Graph")][string[]]$Bypass,
        [Switch]$UseProxy,
        [Parameter(DontShow)][Switch]$AllowMultipleWindows,
        [Parameter(DontShow)][switch]$NoVersionCheck,
        [switch]$RemoveMultipleModuleVersions,
        [switch]$UseImplicitLoading,
    [Parameter(ParameterSetName='Default')]
    [Parameter(ParameterSetName='ConnectOnly')]
        [ValidateScript({if (Resolve-DnsName -Name $PSItem) {$true} else {throw "SPO admin domain does not resolve.  Verify you entered a valid fully qualified domain name."}})]
        [ValidateNotNullOrEmpty()][string]$SPOAdminDomain,
    [Parameter(ParameterSetName='Default')]
    [Parameter(ParameterSetName='ModulesOnly')]
    [Parameter(ParameterSetName='AzureADAppOnly')]
        [Switch]$DoNotRemediate,
    [Parameter(ParameterSetName='Default')]
    [Parameter(ParameterSetName='ConnectOnly')]
    [Parameter(ParameterSetName='AzureADAppOnly')]
    [Parameter(ParameterSetName='ModulesOnly')]
        [ValidateSet("Commercial", "USGovGCC", "USGovGCCHigh", "USGovDoD", "Germany", "China")][string]$O365EnvironmentName="Commercial",
    [Parameter(ParameterSetName='ConnectOnly')]
        [Switch]$ConnectOnly,
    [Parameter(ParameterSetName='ModulesOnly')]
        [Switch]$ModulesOnly,
    [Parameter(ParameterSetName='Default')]
    [Parameter(ParameterSetName='ModulesOnly')]
        [Switch]$SkipADModule,
    [Parameter(ParameterSetName='Default')]
    [Parameter(ParameterSetName='ModulesOnly')]
        [Switch]$ADModuleOnly,
    [Parameter(ParameterSetName='AzureADAppOnly')]
        [Switch]$AzureADAppOnly
    )

    <#

        Variable setting

    #>
    
    #Detect if running in ISE and abort ($psise is an automatic variable that exists only in the ISE)
    if ($psise)
        {
        throw "Running this script in the PowerShell ISE is not supported."
        }

    # Detect if running in PS 7
    # EXO 2.0.3, Teams, MSOnline modules do not support PS 7
    if ($PSVersionTable.PSVersion.ToString() -like "7.*") {
        throw "Running this script in PowerShell 7 is not supported."
    }
    
    # Default run
    $ConnectCheck = $True
    $ModuleCheck = $True
    $AzureADAppCheck = $True

    # Default to remediate (applicable only when not using ConnectOnly)
    if ($DoNotRemediate -eq $false){
        $Remediate = $true
    }
    else {
        $Remediate = $false
    }
    

    # Change based on ModuleOnly flag
    If($ModulesOnly) {
        $ConnectCheck = $False
        $ModuleCheck = $True
        $AzureADAppCheck = $False
    }

    # Change based on ConnectOnly flag
    If($ConnectOnly) {
        $ConnectCheck = $True
        $AzureADAppCheck = $False
        $ModuleCheck = $False
    }

    # Change based on AzureADAppOnly flag
    If($AzureADAppOnly) {
        $ConnectCheck = $False
        $AzureADAppCheck = $True
        $ModuleCheck = $False
    }

    # Change based on SkipADModule flag
    If($SkipADModule) {
        $Bypass+="ActiveDirectory"
    }

    <#
    
        Directory creating and transcript starting
    
    #>
    $SOADirectory = Get-SOADirectory
    $TranscriptName = "prereq-$(Get-Date -Format "MMddyyyyHHmms")-log.txt"
    Start-Transcript "$SOADirectory\$TranscriptName"

    if ($DoNotRemediate){
        Write-Host "$(Get-Date) The DoNotRemediate switch was used.  Any missing or outdated modules, as well as the registration and/or configuration of the Azure AD application will not be performed." -ForegroundColor Yellow
    }

    if ($NoVersionCheck) {
        Write-Host "$(Get-Date) NoVersionCheck switch was used. Skipping version check of the SOA module."
    }
    else {    
        # Check for newer version
        Write-Host "$(Get-Date) Performing version check of the SOA module..."
        $VersionCheck = Invoke-SOAVersionCheck
        If($VersionCheck.NewerAvailable -eq $true)
        {
            Exit-Script
            throw "Version $($VersionCheck.Gallery) of the SOA module has been released. Your version $($VersionCheck.Module) is out of date. Run Update-Module SOA."
            
        }
    }

    # Require local admin and single PowerShell window if multiple modules will be removed
    if ($RemoveMultipleModuleVersions) {
        If($(Get-IsAdministrator) -eq $False -and $ModuleCheck -eq $True -and $DoNotRemediate -eq $false) {
            Exit-Script
            throw "PowerShell must be run as an administrator to be able to uninstall multiple versions of modules."
            
        }
        If($AllowMultipleWindows) {
            Write-Important
            Write-Host "Allow multiple windows has been specified. This should not be used in general operation. Module remediation may fail!"
        } 
        Else 
        {
            If($(Get-PowerShellCount) -gt 1 -and $ModuleCheck -eq $True -and $DoNotRemediate -eq $false) {
                Exit-Script
                throw "There are multiple PowerShell windows open. This can cause issues with PowerShell modules being uninstalled. Close all open PowerShell windows and try again."
                
            }
        }
    }

    # Check that only the AD module is installed on a standalone machine, and then exit the script
    If($ADModuleOnly) {
        Write-Host "$(Get-Date) ADModuleOnly switch was used. The on-premises AD module will be installed and then the script will exit."

        $ModuleCheckResult = @(Get-ModuleStatus -ModuleName "ActiveDirectory")
        $ModuleCheckResult | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,Multiple,NewerAvailable

        If($null -ne $ModuleCheckResult.InstalledVersion) {
            Write-Host "$(Get-Date) ActiveDirectory module is already installed"
        }
        Else {
            If($Remediate) {
                Write-Host "$(Get-Date) Installing AD module"
                Install-ADDSModule
            }

            Write-Host "$(Get-Date) Post-remediation module check..."
            $ModuleCheckResult = @(Get-ModuleStatus -ModuleName "ActiveDirectory")
            $ModuleCheckResult | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,Multiple,NewerAvailable
        }

        Stop-Transcript
        break
    }

    # Final check list
    $CheckResults = @()

    <#

        Display the banner 

    #>
    Write-Host ""
    Write-Host "This scipt is used to install and validate the prerequisites for running the data collection"
    Write-Host "for the Office 365 Security Optimisation Assessment, a Microsoft Services offering."
    Write-Host "At the conclusion of this script running successfully, a file named SOA-PreCheck.json will be created."
    Write-Host "This file should be sent to the engineer who will be delivering the assessment."
    Write-Host ""
    Write-Host "This script MUST be run on the workstation that will be used to perform the data collection for the assessment."
    Write-Host ""

    if ($DoNotRemediate -eq $false -and $ConnectOnly -eq $false) {
        Write-Important
        Write-Host "This script makes changes on this machine and in your Office 365 tenant. Per the parameters used, the following will occur:" -ForegroundColor Green
        if ($ModuleCheck) {
            Write-Host "- Install the latest version of PowerShell modules on this machine that are required for the assessment" -ForegroundColor Green
        }
        if ($AzureADAppCheck) {
            Write-Host "- Register an Azure AD application in your tenant:" -ForegroundColor Green
            Write-Host "   -- The application name is 'Office 365 Security Optimization Assessment'" -ForegroundColor Green
            Write-Host "   -- The application will not be visible to end users" -ForegroundColor Green
            Write-Host "   -- The application secret (password) will not be stored, is randomly generated, and is removed when the prerequisites installation is complete." -ForegroundColor Green
            Write-Host "      (The application will not work without a secret. Do NOT remove the application until the conclusion of the engagement.)" -ForegroundColor Green
        }
        Write-Host ""

        While($True) {
            $rhInput = Read-Host "Is this script being run on the machine that will be used for the data collection, and do you agree with the changes above (y/n)"
            if($rhInput -eq "n") {
                Exit-Script
                throw "Run Install-SOAPrerequisites on the machine that will be used to perform the data collection."
                
            } elseif($rhInput -eq "y") {
                Write-Host ""
                break;
            }
        }
    }

    <#

        Proxy requirement auto-detection

    #>

    If($UseProxy)
    {
        Write-Host "The UseProxy switch was used. An attempt will be made to connect through the proxy infrastructure where possible."
        $RPSProxySetting = New-PSSessionOption -ProxyAccessType IEConfig
    } 
    Else 
    {
        Write-Host "Proxy requirement was not specified with UseProxy. Connection will be attempted directly."
        Write-Host ""
        $RPSProxySetting = New-PSSessionOption -ProxyAccessType None 
    }

    <# 

        Perform the module check

    #>

    If($ModuleCheck -eq $True) {

        # Determine if the nuget provider is available

        If(!(Get-PackageProvider -Name nuget -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -Force | Out-Null
        }

        # Determine if PowerShell Gallery is configured as the default repository
        If(!(Get-PSRepository -Name PSGallery -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue)) {
            Register-PSRepository -Default -InstallationPolicy Trusted | Out-Null
        }

        Invoke-ManualModuleCheck

        Write-Host "$(Get-Date) Checking modules..."

        $ModuleCheckResult = Invoke-SOAModuleCheck -O365EnvironmentName $O365EnvironmentName

        if ($RemoveMultipleModuleVersions) {
            $Modules_OK = @($ModuleCheckResult | Where-Object {$_.Installed -eq $True -and $_.Multiple -eq $False -and $_.NewerAvailable -ne $true})
            $Modules_Error = @($ModuleCheckResult | Where-Object {$_.Installed -eq $False -or $_.Multiple -eq $True -or $_.NewerAvailable -eq $true -or $_.Conflict -eq $True})
        }
        else {
            $Modules_OK = @($ModuleCheckResult | Where-Object {$_.Installed -eq $True -and $_.NewerAvailable -ne $true})
            $Modules_Error = @($ModuleCheckResult | Where-Object {$_.Installed -eq $False -or $_.NewerAvailable -eq $true -or $_.Conflict -eq $True})
        }

        If($Modules_Error.Count -gt 0) {
            Write-Host "$(Get-Date) Modules that require remediation:" -ForegroundColor Yellow
            if ($RemoveMultipleModuleVersions) {
                $Modules_Error | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,Multiple,NewerAvailable
            }
            else {
                $Modules_Error | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,NewerAvailable
            }

            # Fix modules with errors unless instructed not to
            if ($DoNotRemediate -eq $false){
                Invoke-ModuleFix $Modules_Error

                Write-Host "$(Get-Date) Post-remediation module check..."
                $ModuleCheckResult = Invoke-SOAModuleCheck -O365EnvironmentName $O365EnvironmentName
                if ($RemoveMultipleModuleVersions) {
                    $Modules_OK = @($ModuleCheckResult | Where-Object {$_.Installed -eq $True -and $_.Multiple -eq $False -and $_.NewerAvailable -ne $true})
                    $Modules_Error = @($ModuleCheckResult | Where-Object {$_.Installed -eq $False -or $_.Multiple -eq $True -or $_.NewerAvailable -eq $true})
                }
                else {
                    $Modules_OK = @($ModuleCheckResult | Where-Object {$_.Installed -eq $True -and $_.NewerAvailable -ne $true})
                    $Modules_Error = @($ModuleCheckResult | Where-Object {$_.Installed -eq $False -or $_.NewerAvailable -eq $true -or $_.Conflict -eq $True})
                }
            }
            else {
                Write-Host "$(Get-Date) Skipping remediation tasks because DoNotRemediate was used." -ForegroundColor Yellow
            }
            
            If($Modules_Error.Count -gt 0) {
                Write-Host "$(Get-Date) The following modules have errors (a property value is True) that must be remediated:" -ForegroundColor Red
                if ($RemoveMultipleModuleVersions) {
                    $Modules_Error | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,Multiple,NewerAvailable
                }
                else {
                    $Modules_Error | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,NewerAvailable
                }
                
                if ($RemoveMultipleModuleVersions -and ($Modules_Error | Where-Object {$_.Multiple -eq $true})){
                    Write-Host "Paths to modules with multiple versions:"
                    foreach ($m in ($Modules_Error | Where-Object {$_.Multiple -eq $true})) {
                        Write-Host ""
                        Write-Host "Module:" -NoNewline
                        $m | Select-Object -ExpandProperty Module
                        Write-Host "Path:"
                        $m | Select-Object -ExpandProperty Path
                        Write-Host ""
                    }
                }
                
                # Don't continue to check connections
                Exit-Script
                throw "$(Get-Date) The above modules must be remediated before continuing. Contact the delivery engineer for assistance, if needed."
                
            }
        }
    }

    <#

        Generic checks

    #>

    if ($ModuleCheck -or $ConnectCheck) {
        # WinRM Basic Authentication
        $CheckResults += Invoke-WinRMBasicCheck
    }
    <#

        Perform the connection check

    #>

    If($ConnectCheck -eq $True) {
        # Proceed to testing connections
        
        $Connections = @(Test-Connections -RPSProxySetting $RPSProxySetting -O365EnvironmentName $O365EnvironmentName)
        
        $Connections_OK = @($Connections | Where-Object {$_.Connected -eq $True -and $_.TestCommand -eq $True})
        $Connections_Error = @($Connections | Where-Object {$_.Connected -eq $False -or $_.TestCommand -eq $False -or $Null -ne $_.OtherErrors})
    }

    If($AzureADAppCheck -eq $True) {

        # When AzureADAppCheck is run by itself, this script will not be connected to Azure AD
        If((Get-AzureADConnected) -eq $False) {
            switch ($O365EnvironmentName) {
                "Commercial"   {Connect-AzureAD | Out-Null;break}
                "USGovGCC"     {Connect-AzureAD | Out-Null;break}
                "USGovGCCHigh" {Connect-AzureAD -AzureEnvironmentName AzureUSGovernment | Out-Null;break}
                "USGovDoD"     {Connect-AzureAD -AzureEnvironmentName AzureUSGovernment | Out-Null;break}
                "Germany"      {Connect-AzureAD -AzureEnvironmentName AzureGermanyCloud | Out-Null;break}
                "China"        {Connect-AzureAD -AzureEnvironmentName AzureChinaCloud | Out-Null}
            }
        }

        Import-PSModule -ModuleName Microsoft.Graph.Applications -Implicit $UseImplicitLoading
        switch ($O365EnvironmentName) {
            "Commercial"   {$cloud = 'Global'}
            "USGovGCC"     {$cloud = 'Global'}
            "USGovGCCHigh" {$cloud = 'USGov'}
            "USGovDoD"     {$cloud = 'USGovDoD'}
            "Germany"      {$cloud = 'Germany'}
            "China"        {$cloud = 'China'}            
        }
        if ((Get-MgContext).Scopes -notcontains 'Application.ReadWrite.All') {
            Connect-MgGraph -Scopes 'Application.ReadWrite.All' -Environment $cloud
        }
        
        Import-MSAL

        Write-Host "$(Get-Date) Checking Azure AD Application..."

        # Get the default MSOL domain
        $tenantdomain = (Get-AzureADDomain | Where-Object {$_.IsInitial -eq $true}).Name

        # Determine if Azure AD Application exists (and has public client redirect URI set), create if doesnt
        $AzureADApp = Get-SOAAzureADApp -O365EnvironmentName $O365EnvironmentName

        If($AzureADApp) {
            # Check if public client redirect URI not set for existing app because DoNotRemediate is True
            if ($AzureADApp.PublicClient.RedirectUris -notcontains 'https://login.microsoftonline.com/common/oauth2/nativeclient' -and $DoNotRemediate) {
                # Fail the AAD app check
                $CheckResults += New-Object -Type PSObject -Property @{
                    Check="AAD Application"
                    Pass=$false
                }
            }
            else {
                # Pass the AAD app check
                $CheckResults += New-Object -Type PSObject -Property @{
                    Check="AAD Application"
                    Pass=$true
                }
            }
 
            # Reset secret
            $clientsecret = Reset-SOAAppSecretv2 -App $AzureADApp -Task "Prereq"
            Write-Host "$(Get-Date) Sleeping to allow for replication of the application's new client secret..."
            Start-Sleep 10

            $AppTest = Test-SOAApplication -App $AzureADApp -Secret $clientsecret -TenantDomain $tenantdomain -O365EnvironmentName $O365EnvironmentName -WriteHost
                
            # AAD App Permission - Perform remediation if specified
            If($AppTest.Permissions -eq $False -and $DoNotRemediate -eq $false)
            {
                # Set up the correct AAD App Permissions
                Write-Host "$(Get-Date) Remediating application permissions..."
                If((Set-AzureADAppPermission -App $AzureADApp -PerformConsent:$True -O365EnvironmentName $O365EnvironmentName) -eq $True) {
                    # Perform check again after setting permissions
                    $AppTest = Test-SOAApplication -App $AzureADApp -Secret $clientsecret -TenantDomain $tenantdomain -O365EnvironmentName $O365EnvironmentName -WriteHost
                }
            }

            If($AppTest.Token -eq $False)
            {
                Write-Host "$(Get-Date) Missing roles in access token; possible that consent was not completed..."
                if ($DoNotRemediate -eq $false) {
                    # Request admin consent
                    If((Invoke-Consent -App $AzureADApp -O365EnvironmentName $O365EnvironmentName) -eq $True) {
                        # Perform check again after consent
                        $AppTest = Test-SOAApplication -App $AzureADApp -Secret $clientsecret -TenantDomain $tenantdomain -O365EnvironmentName $O365EnvironmentName -WriteHost
                    }
                }
            }

            # Add final result to checkresults object
            $CheckResults += New-Object -Type PSObject -Property @{
                Check="AAD App Permissions"
                Pass=$AppTest.Permissions
            }
            $CheckResults += New-Object -Type PSObject -Property @{
                Check="AAD App Token"
                Pass=$AppTest.Token
            }

            # Perform Graph Check
            Write-Host "$(Get-Date) Performing Graph Test..."
            $CheckResults += Invoke-GraphTest -AzureADApp $AzureADApp -Secret $clientsecret -TenantDomain $tenantdomain -O365EnvironmentName $O365EnvironmentName


            # Check that the Graph SDK modules can connect
            switch ($O365EnvironmentName) {
                "Commercial"   {$Resource = "https://graph.microsoft.com";break}
                "USGovGCC"     {$Resource = "https://graph.microsoft.com";break}
                "USGovGCCHigh" {$Resource = "https://graph.microsoft.us";break}
                "USGovDoD"     {$Resource = "https://dod-graph.microsoft.us";break}
                "Germany"      {$Resource = "https://graph.microsoft.com";break}
                "China"        {$Resource = "https://microsoftgraph.chinacloudapi.cn"}
            }

            $Token = Get-MSALAccessToken -TenantName $tenantdomain -ClientID $AzureADApp.AppId -Secret $clientsecret -Resource $Resource -O365EnvironmentName $O365EnvironmentName 

            Import-PSModule -ModuleName Microsoft.Graph.Authentication -Implicit $UseImplicitLoading
            switch ($O365EnvironmentName) {
                "Commercial"   {Connect-MgGraph -AccessToken $Token.AccessToken -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
                "USGovGCC"     {Connect-MgGraph -AccessToken $Token.AccessToken -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
                "USGovGCCHigh" {Connect-MgGraph -AccessToken $Token.AccessToken -Environment "USGov" -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
                "USGovDoD"     {Connect-MgGraph -AccessToken $Token.AccessToken -Environment "USGovDoD" -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
                "Germany"      {Connect-MgGraph -AccessToken $Token.AccessToken -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
                "China"        {Connect-MgGraph -AccessToken $Token.AccessToken -Environment "China" -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null}
            }

            If($ConnectError){
                $CheckResults += New-Object -Type PSObject -Property @{
                    Check="Graph SDK Connection"
                    Pass=$False
                }
            } Else {
                $CheckResults += New-Object -Type PSObject -Property @{
                    Check="Graph SDK Connection"
                    Pass=$True
                }

                if (Get-MgSecuritySecureScore -Top 1) {
                    $CheckResults += New-Object -Type PSObject -Property @{
                        Check="Graph SDK Command"
                        Pass=$True
                    }
                } 
                else {
                    $CheckResults += New-Object -Type PSObject -Property @{
                        Check="Graph SDK Command"
                        Pass=$False
                    }
                }
            }
            # Remove client secret
            Remove-SOAAppSecretv2 -app $AzureADApp
        } 
        Else 
        {
            # AAD application does not exist
            $CheckResults += New-Object -Type PSObject -Property @{
                Check="AAD Application"
                Pass=$False
            }
        }

    }

    Write-Host "$(Get-Date) Detailed Output"

    If($ModuleCheck -eq $True) 
    {

        Write-Host "$(Get-Date) Installed Modules" -ForegroundColor Green
        if ($RemoveMultipleModuleVersions) {
            $Modules_OK | Format-Table Module,InstalledVersion,GalleryVersion,Multiple,NewerAvailable
        }
        else {
            $Modules_OK | Format-Table Module,InstalledVersion,GalleryVersion,NewerAvailable
        }
        
        If($Modules_Error.Count -gt 0) 
        {
            Write-Host "$(Get-Date) Modules with errors" -ForegroundColor Red
            if ($RemoveMultipleModuleVersions) {
                $Modules_Error | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,Multiple,NewerAvailable
            }
            else {
                $Modules_Error | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,NewerAvailable
            }

            $CheckResults += New-Object -TypeName PSObject -Property @{
                Check="Module Installation"
                Pass=$False
            }

        } 
        Else 
        {
            $CheckResults += New-Object -TypeName PSObject -Property @{
                Check="Module Installation"
                Pass=$True
            }
        }

    }

    If($ConnectCheck -eq $True) 
    {

        Write-Host "$(Get-Date) Connections" -ForegroundColor Green
        $Connections_OK | Format-Table Name,Connected,TestCommand
        
        If($Connections_Error.Count -gt 0) {
            Write-Host "$(Get-Date) Connections with errors" -ForegroundColor Red
            $Connections_Error | Format-Table Name,Connected,TestCommand
            $CheckResults += New-Object -Type PSObject -Property @{
                Check="Module Connections"
                Pass=$False
            }
        } Else {
            $CheckResults += New-Object -Type PSObject -Property @{
                Check="Module Connections"
                Pass=$True
            }
        }

    }

    If($AzureADAppCheck -eq $True) {

        Write-Host "$(Get-Date) Azure AD app checks" -ForegroundColor Green

    }

    Write-Host "$(Get-Date) Summary of Checks"

    $CheckResults | Format-Table Check,Pass

    $SOAModule = Get-Module SOA
    if ($SOAModule) {
        $version = $SOAModule.Version.ToString()
    }
    
    New-Object -TypeName PSObject -Property @{
        Date=(Get-Date).DateTime
        Version=$version
        Results=$CheckResults
        ModulesOK=$Modules_OK
        ModulesError=$Modules_Error
        ConnectionsOK=$Connections_OK
        ConnectionsError=$Connections_Error
    } | ConvertTo-Json | Out-File SOA-PreCheck.json

    Write-Host "$(Get-Date) Output saved to SOA-PreCheck.json which should be sent to the engineer who will be performing the assessment."
    $CurrentDir = Get-Location 
    Write-Host "$(Get-Date) SOA-PreCheck.json is located in: " -NoNewline
    Write-Host "$CurrentDir" -ForegroundColor Yellow
    Write-Host ""

    While($True) {
        $rhInput = Read-Host "Type 'yes' when you have sent the SOA-PreCheck.json file to the engineer who will be performing the assessment."
        if($rhInput -eq "yes") {
            break;
        }
    }

   Exit-Script
}
