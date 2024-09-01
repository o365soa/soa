#Requires -Version 5.1
#Requires -Modules @{ModuleName="PowerShellGet"; ModuleVersion="2.2.4"}

<#

    .SYNOPSIS
        Prerequisite validation/installation module for Microsoft Security Assessments

    .DESCRIPTION
        Contains installation cmdlet which must be run prior to a Microsoft
        proactive offering for any of the following security assessments:
        - Office 365 Security Optimization Assessment
        - Microsoft 365 Foundations: Workload Security Assessment
        - Security Optimization Assessment for Microsoft Defender

        The output of the script (JSON file) should be sent to the engineer who will be performing
        the assessment.

        ############################################################################
        # This script is not supported under any Microsoft standard support program or service. 
        # This script is provided AS IS without warranty of any kind. 
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

function Get-InitialDomain {
    <#
        Used during connection tests for SPO and Teams
    #>
    
    # Get the default onmicrosoft domain. Because the SDK connection is still using a delegated call at this point, the application-based Graph function cannot be used
    $OrgData = (Invoke-MgGraphRequest GET "/v1.0/organization" -OutputType PSObject).Value
    return ($OrgData | Select-Object -ExpandProperty VerifiedDomains | Where-Object { $_.isInitial }).Name 

}

function Get-SharePointAdminUrl
{
    <#
    
        Used to determine what the SharePoint Admin URL is during connection tests
    
    #>
    Param (
        [string]$CloudEnvironment
    )

    # Custom domain provided for connecting to SPO admin endpoint
    if ($SPOAdminDomain) {
        $url = "https://" + $SPOAdminDomain
    }
    else {
        $tenantName = ((Get-InitialDomain) -split ".onmicrosoft")[0]
        
        switch ($CloudEnvironment) {
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
    
        This function creates a new secret for the application when the app is retrieved using Invoke-MgGraphRequest from the Microsoft.Graph.Authentication module
    
    #>
    Param (
        $App,
        $Task
    )

    # Provision a short lived credential (48 hours)
    $Params = @{
        passwordCredential = @{
            displayName = "$Task on $(Get-Date -Format "dd-MMM-yyyy")"
            endDateTime = (Get-Date).ToUniversalTime().AddDays(2).ToString("o")
        }
    }
    $Response = Invoke-MgGraphRequest -Method POST -Uri "/v1.0/applications/$($App.Id)/addPassword" -body $Params

    Return $Response.SecretText
}
function Remove-SOAAppSecret {
    # Removes any client secrets associated with the application when the app is retrieved using Invoke-MgGraphRequest from the Microsoft.Graph.Authentication module
    param ()

    # Get application again from Entra to be sure it includes any added secrets
    $App = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/applications?`$filter=web/redirectUris/any(p:p eq 'https://security.optimization.assessment.local')&`$count=true" -Headers @{'ConsistencyLevel' = 'eventual'} -OutputType PSObject).Value

    $secrets = $App.passwordCredentials
    foreach ($secret in $secrets) {
        # Suppress errors in case a secret no longer exists
        try {
            Invoke-MgGraphRequest -Method POST -Uri "/v1.0/applications(appId=`'$($App.appId)`')/removePassword" -body (ConvertTo-Json -InputObject @{ 'keyId' = $secret.keyId }) #| Out-Null
        }
        catch {}
    }
}

Function Import-MSAL {
    <#
    
        Finds a suitable MSAL library from Graph SDK and uses that
        This prevents us having to ship the .dll's ourself.

    #>

    # Add support for the .Net Core version of the library.
    If ($PSEdition -eq 'Core'){
        $Folder = "Core"
    } Else {
        $Folder = "Desktop"
    }

    $MgAuthModule = Get-Module -Name "Microsoft.Graph.Authentication" -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    $MSAL = Join-Path $MgAuthModule.ModuleBase "Dependencies\$($Folder)\Microsoft.Identity.Client.dll"

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
        [Alias("O365EnvironmentName")][string]$CloudEnvironment
    )

    Import-MSAL

    switch ($CloudEnvironment) {
        "Commercial"   {$Authority = "https://login.microsoftonline.com/$TenantName";break}
        "USGovGCC"     {$Authority = "https://login.microsoftonline.com/$TenantName";break}
        "USGovGCCHigh" {$Authority = "https://login.microsoftonline.us/$TenantName";break}
        "USGovDoD"     {$Authority = "https://login.microsoftonline.us/$TenantName";break}
        "Germany"      {$Authority = "https://login.microsoftonline.de/$TenantName";break}
        "China"        {$Authority = "https://login.partner.microsoftonline.cn/$TenantName";break}
    }

    Write-Verbose "$(Get-Date) Get-MSALAccessToken function called from the pre-reqs module - Tenant: $TenantName ClientID: $ClientID Resource: $Resource SecretLength: $($Secret.Length) CloudEnvironment: $CloudEnvironment"

    $ccApp = [Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]::Create($ClientID).WithClientSecret($Secret).WithAuthority($Authority).WithLegacyCacheCompatibility($false).Build()

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

Function Set-EntraAppPermission {
    <#
    
        Sets the required permissions on the application
    
    #>
    Param(
        $App,
        $PerformConsent=$False,
        [string]$CloudEnvironment
    )

    Write-Host "$(Get-Date) Setting Microsoft Entra enterprise application permissions..."
    Write-Verbose "$(Get-Date) Set-EntraAppPermissions App: $($App.Id) Cloud: $CloudEnvironment"

    $RequiredResources = @()
    $PermissionSet = $False
    $ConsentPerformed = $False

    $Roles = Get-RequiredAppPermissions -CloudEnvironment $CloudEnvironment -HasMDELicense $MDELicensed -HasMDILicense $MDILicensed -HasATPP2License $ATPP2Licensed

    <#
    
        The following creates a Required Resources array. The array consists of RequiredResourceAccess objects.
        There is one RequiredResourceAccess object for every resource; for instance, Graph is a resource.
        In the RequiredResourceAccess object is an array of scopes that are required for that resource.
    
    #>
    
    foreach($ResourceRolesGrouping in ($Roles | Group-Object Resource)) {

        # Define the resource
        $Resource = @{}

        # Add the permissions
        ForEach($Role in $($ResourceRolesGrouping.Group)) {
            Write-Verbose "$(Get-Date) Set-EntraAppPermissions Add $($Role.Type) $($Role.Name) ($($Role.ID)) in $CloudEnvironment cloud"
            $ResourceAccess = @()
            $Perm = @{}
            $Perm.id = $Role.ID
            $Perm.type = $Role.Type
            $ResourceAccess += $Perm

            $Resource.resourceAccess += $ResourceAccess
        }
        $Resource.resourceAppId = $ResourceRolesGrouping.Name

        # Add to the list of required access
        $RequiredResources += $Resource

    }
    
    try {
        $Params = @{
            'requiredResourceAccess' = $RequiredResources
        }

        Invoke-MgGraphRequest -Method PATCH -Uri "/v1.0/applications/$($App.Id)" -Body ($Params | ConvertTo-Json -Depth 5)
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
        If((Invoke-Consent -App $App -CloudEnvironment $CloudEnvironment) -eq $True) {
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
        Check the permissions are set correctly on the Entra application
    #>
    Param(
        $App,
        [Switch]$NewPermission
    )

    $Roles = Get-RequiredAppPermissions -CloudEnvironment $CloudEnvironment -HasMDELicense $MDELicensed -HasMDILicense $MDILicensed -HasATPP2License $ATPP2Licensed

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
        $Provisioned = $True
        # Refresh roles from Entra
        $rCounter = 1
        $appId = $app.Id
        while ($rCounter -le 5) {
            try {
                Write-Verbose "$(Get-Date) Getting application from Entra (attempt #$rCounter)"
                $App = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/applications/$appId" -ErrorAction Stop
                break
            }
            catch {
                Write-Verbose "$(Get-Date) Error getting application from Entra, retrying in 5 seconds"
                $rCounter++
                Start-Sleep -Seconds 5
            }
        }

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
            Write-Verbose "$(Get-Date) Invoke-AppPermissionCheck App ID $($app.Id) Role Count $($Roles.Count) OK"
            Break
        } 
        Else 
        {
            Start-Sleep $SleepTime
            $Counter += $SleepTime
            Write-Verbose "$(Get-Date) Invoke-AppPermissionCheck loop - waiting for permissions on Entra application - Counter $Counter maxTime $MaxTime Missing $($Missing -join ' ')"
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
        [string]$CloudEnvironment
    )

    switch ($CloudEnvironment) {
        "Commercial"   {$GraphResource = "https://graph.microsoft.com/";break}
        "USGovGCC"     {$GraphResource = "https://graph.microsoft.com/";break}
        "USGovGCCHigh" {$GraphResource = "https://graph.microsoft.us/";break}
        "USGovDoD"     {$GraphResource = "https://dod-graph.microsoft.us/";break}
        "Germany"      {$GraphResource = "https://graph.microsoft.de/";break}
        "China"        {$GraphResource = "https://microsoftgraph.chinacloudapi.cn/"}
    }

    $Roles = Get-RequiredAppPermissions -CloudEnvironment $CloudEnvironment -HasMDELicense $MDELicensed -HasMDILicense $MDILicensed -HasATPP2License $ATPP2Licensed

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
        $Token = Get-MSALAccessToken -TenantName $tenantdomain -ClientID $App.AppId -Secret $Secret -Resource $GraphResource -CloudEnvironment $CloudEnvironment

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

Function Invoke-AppTokenRolesCheckV2 {
    <#
    
        This function checks for the presence of the right scopes on the
        Graph connection using the Get-MgContext SDK cmdlet.
        Consent may not have been completed without the right roles

    #>
    Param (
        [string]$CloudEnvironment
    )

    $Roles = Get-RequiredAppPermissions -CloudEnvironment $CloudEnvironment -HasMDELicense $MDELicensed -HasMDILicense $MDILicensed -HasATPP2License $ATPP2Licensed

    $ActiveScopes = (Get-MgContext).Scopes
    $MissingRoles = @()

    ForEach($Role in ($Roles | Where-Object {$_.Resource -eq "00000003-0000-0000-c000-000000000000"})) {
        If($ActiveScopes -notcontains $Role.Name) {
            Write-Verbose "$(Get-Date) Invoke-AppTokenRolesCheckV2 missing $($Role.Name)"
            $MissingRoles += $Role
        }
    }

    If($MissingRoles.Count -eq 0) {
        $return = $true
    } Else {
        $return = $false
    }
  
    return $return
}

Function Invoke-Consent {
    <#
    
        Perform consent for application
    
    #>
    Param (
        $App,
        [string]$CloudEnvironment
    )

    switch ($CloudEnvironment) {
        "Commercial"   {$AuthLocBase = "https://login.microsoftonline.com";break}
        "USGovGCC"     {$AuthLocBase = "https://login.microsoftonline.com";break}
        "USGovGCCHigh" {$AuthLocBase = "https://login.microsoftonline.us";break}
        "USGovDoD"     {$AuthLocBase = "https://login.microsoftonline.us";break}
        "Germany"      {$AuthLocBase = "https://login.microsoftonline.de";break}
        "China"        {$AuthLocBase = "https://login.partner.microsoftonline.cn"}
    }
    # Need to use the Application ID, not Object ID
    $Location = "$AuthLocBase/common/adminconsent?client_id=$($App.AppId)&state=12345&redirect_uri=https://o365soa.github.io/soa/"
    Write-Important
    Write-Host "In 10 seconds, a page in the default browser will load and ask you to grant consent to Microsoft Security Assessment."
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

Function Install-EntraApp {
    <#

        Installs the Entra enterprise application used for accessing Graph and Dynamics
    
    #>
    Param(
        [string]$CloudEnvironment
    )

    # Create the Entra application
    Write-Verbose "$(Get-Date) Install-EntraApp Installing App"
    $Params = @{
        'displayName' = 'Microsoft Security Assessment'
        'SignInAudience' = 'AzureADMyOrg'
        'web' = @{
            'redirectUris' = @("https://security.optimization.assessment.local","https://o365soa.github.io/soa/")
        }
        'publicClient' = @{
            'redirectUris' = @("https://login.microsoftonline.com/common/oauth2/nativeclient")
        }
    }

    $EntraApp = Invoke-MgGraphRequest -Method POST -Uri "/v1.0/applications" -Body $Params

    # Set up the correct permissions
    Set-EntraAppPermission -App $EntraApp -PerformConsent:$True -CloudEnvironment $CloudEnvironment

    # Add service principal (enterprise app) as owner of its app registration
    $appSp = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/servicePrincipals(appId=`'$($EntraApp.AppId)`')" -OutputType PSObject
    $Params = @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($appSp.Id)"
    }
    Invoke-MgGraphRequest -Method POST -Uri "/v1.0/applications(appId=`'$($EntraApp.AppId)`')/owners/`$ref" -body $Params

    # Return the newly created application
    Return (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/applications/$($EntraApp.Id)")
    
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
    switch ($LicenseType) {
        ATPP2 {
            # SKUs that start with strings include MDO P2 (for collecting MDO incidents)
            $targetSkus = @('ENTERPRISEPREMIUM','SPE_E5','SPE_F5','M365EDU_A5','IDENTITY_THREAT_PROTECTION','THREAT_INTELLIGENCE','M365_SECURITY_COMPLIANCE','Microsoft_365 G5_Security','M365_G5',"Microsoft_365_E5")
        }
        MDE {
            # SKUs that start with strings include MDE to be able to use its advanced hunting API
            $targetSkus = @('DEFENDER_ENDPOINT','IDENTITY','M365_G3_R','M365_G5_GCC','M365_S','M365EDU_A3_STUD','M365EDU_A3_F''M365EDU_A5_STUD','M365EDU_A5_F','MDATP','Microsoft 365 A3 Suite','Microsoft_365_E','Microsoft_D','Microsoft_Teams_Rooms_Pro_F','Microsoft_Teams_Rooms_Pro_G','O365_w/o Teams Bundle_M','O365_w/o_Teams_Bundle_M','SPE_','WIN_','WIN10_ENT_A5','WIN10_VDA_E5','WINE5_G')
        }
        MDI {
            # SKUs that start with strings include MDI
            $targetSkus = @('EMSPREMIUM','SPE_E5','SPE_F5','M365EDU_A5','IDENTITY_THREAT_PROTECTION','M365_SECURITY_COMPLIANCE','M365_G5','Microsoft_365_E5','ATA')
        }
        AADP2 {
            $targetSkus = @('AAD_PREMIUM_P2','DEVELOPERPACK_E5','EMSPREMIUM','IDENTITY_THREAT_PROTECTION','M365_G5','M365_SEC','M365EDU_A5','Microsoft_365_E5','SPE_E5','SPE_F5')
        }
        default {
            Write-Error -Message "$(Get-Date) Invalid license type specified"
            return $false
        }
    }
    
    $subscribedSku = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/subscribedSkus" -OutputType PSObject
    foreach ($tSku in $targetSkus) {
        foreach ($sku in $subscribedSku.value) {
            if ($sku.prepaidUnits.enabled -gt 0 -or $sku.prepaidUnits.warning -gt 0 -and $sku.skuPartNumber -match $tSku) {
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
        $Scope = "AllUsers"
    }
    else {
        $Scope = "CurrentUser"
    }

    Install-Module $Module -Force -Scope:$Scope -AllowClobber

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
        [string]$CloudEnvironment
    )
    $RequiredModules = @()
    
    # Conflict modules are modules which their presence causes issues
    $ConflictModules = @()

    # Bypass checks
    If($Bypass -notcontains "SPO") { $RequiredModules += "Microsoft.Online.SharePoint.PowerShell" }
    If($Bypass -notcontains "Teams") {$RequiredModules += "MicrosoftTeams"}
    If (($Bypass -notcontains "EXO" -or $Bypass -notcontains "SCC")) {$RequiredModules += "ExchangeOnlineManagement"}
    If ($Bypass -notcontains "PP") {
        if ($CloudEnvironment -eq "Germany") {
            Write-Host "$(Get-Date) Skipping Power Apps module because Power Platform isn't supported in Germany cloud..."
        }
        else {
            $RequiredModules += "Microsoft.PowerApps.Administration.PowerShell"
        }
    }
    If($Bypass -notcontains "Graph") {
        $RequiredModules += "Microsoft.Graph.Authentication"
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
        Import-Module -Name $ModuleName -RequiredVersion $highestVersion -ErrorVariable loadError -Force -WarningAction SilentlyContinue
        if ($loadError) {
            Write-Error -Message "Error loading module $ModuleName."
        }

        # Check that Graph modules have dependant module (Authentication) loaded with the same version and throw an error if they are not the same version. Only check for non-Auth modules since they will have a RequiredModules statement in the manifest to load the Auth module
        if ($ModuleName -like 'Microsoft.Graph.*' -and $ModuleName -ne 'Microsoft.Graph.Authentication'){            
            $GraphModule = Get-Module -Name $ModuleName | Sort-Object Version -Descending
            $AuthModule = Get-Module -Name 'Microsoft.Graph.Authentication' | Sort-Object Version -Descending

            If (($GraphModule).Version -ne ($AuthModule).Version) {
                Write-Error "The version for loaded modules $ModuleName ($($GraphModule.Version.ToString())) and Microsoft.Graph.Authentication ($($AuthModule.Version.ToString())) are not matching and will cause calls to Microsoft Graph to fail. Run `"Install-SOAPrerequisites -ModulesOnly`" to ensure the latest version of all required Microsoft.Graph modules is installed. If the latest version is installed, open a new PowerShell window."
                Exit-Script
            }
        }
    }
}
Function Test-Connections {
    Param(
        $RPSProxySetting,
        [string]$CloudEnvironment
    )

    $Connections = @()

    Write-Host "$(Get-Date) Testing connections..."
    #$userUPN = Read-Host -Prompt "What is the UPN of the admin account that you will be signing in with for connection validation and with sufficient privileges to register the Microsoft Entra enterprise application"

    <#
    
        Graph PowerShell SDK

    #>
    $connectToGraph = $false
    $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null
    # Teams and SPO connections are dependent on Graph connection to get initial domain
    if ($Bypass -notcontains 'Teams' -or $Bypass -notcontains 'SPO' ) {
        if ($Bypass -contains 'Graph') {
            Write-Warning -Message "Even though Graph is bypassed, Teams and/or SPO are not bypassed and require Graph. Therefore, the Graph connection will still occur."
            $connectToGraph = $true
        }
    }
    if ($Bypass -notcontains 'Graph') {
        $connectToGraph = $true
    }
    if ($connectToGraph -eq $true) {
        Import-PSModule -ModuleName Microsoft.Graph.Authentication -Implicit $UseImplicitLoading
        switch ($CloudEnvironment) {
            "Commercial"   {$cloud = 'Global'}
            "USGovGCC"     {$cloud = 'Global'}
            "USGovGCCHigh" {$cloud = 'USGov'}
            "USGovDoD"     {$cloud = 'USGovDoD'}
            "Germany"      {$cloud = 'Germany'}
            "China"        {$cloud = 'China'}
        }
        $ConnContext = (Get-MgContext).Scopes
        if ($ConnContext -notcontains 'Application.ReadWrite.All' -or ($ConnContext -notcontains 'Organization.Read.All' -and $ConnContext -notcontains 'Directory.Read.All')) {
            Write-Host "$(Get-Date) Connecting to Microsoft Graph with delegated authentication..."
            if ($null -ne (Get-MgContext)){Disconnect-MgGraph | Out-Null}
            $connCount = 0
            $connLimit = 5
            do {
                try {
                    $connCount++
                    Write-Verbose "$(Get-Date) Graph Delegated connection attempt #$connCount"
                    # User.Read is sufficient for using the organization API to get the domain for the Teams/SPO connections
                    # Using Organization.Read.All because that is the least-common scope for getting licenses in the app check
                    Connect-MgGraph -Scopes 'Application.ReadWrite.All','Organization.Read.All' -Environment $cloud -ContextScope "Process" -NoWelcome -ErrorVariable ConnectError | Out-Null
                }
                catch {
                    Write-Verbose $_
                    Start-Sleep 1
                }
            }
            until ($null -ne (Get-MgContext) -or $connCount -eq $connLimit)
            if ($null -eq (Get-MgContext)) {
                Write-Error -Message "Unable to connect to Graph. Skipping dependent connection tests."
                $Connect = $False
            }
            else {
                $Connect = $True
                $GraphSDKConnected = $true
            }
            if ($Connect -eq $true) {
                $org = (Invoke-MgGraphRequest -Method GET -Uri '/v1.0/organization' -OutputType PSObject -ErrorAction SilentlyContinue -ErrorVariable CommandError).Value
                if ($org.id) {$Command = $true} else {$Command = $false}
            }
        }

        $Connections += New-Object -TypeName PSObject -Property @{
            Name="GraphSDK"
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

        Write-Host "$(Get-Date) Connecting to SCC..."
        Get-ConnectionInformation | Where-Object {$_.ConnectionUri -like "*protection.o*" -or $_.ConnectionUri -like "*protection.partner.o*"} | ForEach-Object {Disconnect-ExchangeOnline -ConnectionId $_.ConnectionId -Confirm:$false}
        switch ($CloudEnvironment) {
            "Commercial"   {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ShowBanner:$False | Out-Null;break}
            "USGovGCC"   {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ShowBanner:$False | Out-Null;break}
            "USGovGCCHigh" {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ConnectionUri https://ps.compliance.protection.office365.us/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.microsoftonline.us/common -ShowBanner:$False | Out-Null;break}
            "USGovDoD"     {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ConnectionUri https://l5.ps.compliance.protection.office365.us/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.microsoftonline.us/common -ShowBanner:$False | Out-Null;break}
            "Germany"      {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ConnectionUri https://ps.compliance.protection.outlook.de/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.microsoftonline.de/common -ShowBanner:$False | Out-Null;break}
            "China"        {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ConnectionUri https://ps.compliance.protection.partner.outlook.cn/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.partner.microsoftonline.cn/common -ShowBanner:$False | Out-Null}
        }

        If((Get-ConnectionInformation | Where-Object {$_.ConnectionUri -like "*protection.o*" -or $_.ConnectionUri -like "*protection.partner.o*"}).State -eq "Connected") { $Connect = $True } Else { $Connect = $False }

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
        switch ($CloudEnvironment) {
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

        # Connect only if SPO admin domain provided or if not provided but Graph SDK is connected
        if ($SPOAdminDomain -or (-not($SPOAdminDomain) -and $GraphSDKConnected -eq $true)) {
            $adminUrl = Get-SharePointAdminUrl -CloudEnvironment $CloudEnvironment
            Write-Host "$(Get-Date) Connecting to SharePoint Online (using $adminUrl)..."
            switch ($CloudEnvironment) {
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
        
    }
    
    <#
    
        Microsoft Teams
    
    #>
    If($Bypass -notcontains "Teams") {
        Import-PSModule -ModuleName MicrosoftTeams -Implicit $UseImplicitLoading
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        if ($GraphSDKConnected -eq $true) {
            Write-Host "$(Get-Date) Connecting to Microsoft Teams..."
            $InitialDomain = Get-InitialDomain
            switch ($CloudEnvironment) {
                "Commercial"    {try {Connect-MicrosoftTeams -TenantId $InitialDomain} catch {New-Variable -Name ConnectError -Value $true}}
                "USGovGCC"      {try {Connect-MicrosoftTeams -TenantId $InitialDomain} catch {New-Variable -Name ConnectError -Value $true}}
                "USGovGCCHigh"  {try {Connect-MicrosoftTeams -TenantId $InitialDomain -TeamsEnvironmentName TeamsGCCH } catch {New-Variable -Name ConnectError -Value $true}}
                "USGovDoD"      {try {Connect-MicrosoftTeams -TenantId $InitialDomain -TeamsEnvironmentName TeamsDOD } catch {New-Variable -Name ConnectError -Value $true}}
                #"Germany"      {"Status of Teams in Germany cloud is unknown";break}
                "China"         {Write-Host "Teams is not available in 21Vianet offering";break}
                default         {try {Connect-MicrosoftTeams -TenantId $InitialDomain} catch {New-Variable -Name ConnectError -Value $true}}
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
    }

    <#
    
        Power Apps
    
    #>
    If($Bypass -notcontains 'PP') {
        if ($CloudEnvironment -eq 'Germany') {
            Write-Host "$(Get-Date) Skipping connection to Power Apps because it is not supported in Germany cloud..."
        }
        else {
            Import-PSModule -ModuleName Microsoft.PowerApps.Administration.PowerShell -Implicit $UseImplicitLoading
            # Reset vars
            $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

            Write-Host "$(Get-Date) Connecting to Power Apps..."
            switch ($CloudEnvironment) {
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
    [string]$CloudEnvironment="Commercial",
    $HasMDELicense,
    $HasMDILicense,
    $HasATPP2License
    )

    <#
        This function returns the required application permissions for the Entra application

        Required Application Permissions

        ID, Name and Resource are required
        - ID is the scope's unique GUID
        - Name is used during the token check (to see we are actually getting these scopes assigned to us)
        - Resource is the application ID for the API we are using, usually this is "00000003-0000-0000-c000-000000000000" which is for Graph
    #>

    $AppRoles = @()

    # Microsoft Graph
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
        ID="78ce3f0f-a1ce-49c2-8cde-64b5c0896db4"
        Name="user_impersonation"
        Type='Scope'
        Resource="00000007-0000-0000-c000-000000000000" # Dynamics 365
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="c7fbd983-d9aa-4fa7-84b8-17382c103bc4"
        Name="RoleManagement.Read.All"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="01e37dc9-c035-40bd-b438-b2879c4870a6"
        Name="PrivilegedAccess.Read.AzureADGroup"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="18a4783c-866b-4cc7-a460-3d5e5662c884"
        Name="Application.ReadWrite.OwnedBy"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }

    If ($CloudEnvironment -ne "USGovGCCHigh" -and $CloudEnvironment -ne "USGovDoD"){
        $AppRoles += New-Object -TypeName PSObject -Property @{
            ID="bb70e231-92dc-4729-aff5-697b3f04be95"
            Name="OnPremDirectorySynchronization.Read.All"
            Type='Role'
            Resource="00000003-0000-0000-c000-000000000000" # Graph
        }
    }

    $MDEAvailable = $false
    switch ($CloudEnvironment) {
        "Commercial"   {$MDEAvailable=$true;break}
        "USGovGCCHigh" {$MDEAvailable=$true;break}
        "USGovDoD"     {$MDEAvailable=$true;break}
        "Germany"      {$MDEAvailable=$false;break}
        "China"        {$MDEAvailable=$false}
    }
    if (($HasMDELicense -eq $true -and $MDEAvailable -eq $true) -or $HasATPP2License -eq $true) {
        Write-Verbose "Adding role for Advanced Hunting to App"
        $AppRoles += New-Object -TypeName PSObject -Property @{
            ID="dd98c7f5-2d42-42d3-a0e4-633161547251"
            Name="ThreatHunting.Read.All"
            Type='Role'
            Resource="00000003-0000-0000-c000-000000000000" # Graph
        }
    }

    $MDIAvailable = $false
    switch ($CloudEnvironment) {
        "Commercial"   {$MDIAvailable=$true;break}
        "USGovGCCHigh" {$MDIAvailable=$true;break}
        "USGovDoD"     {$MDIAvailable=$true;break}
        "Germany"      {$MDIAvailable=$false;break}
        "China"        {$MDIAvailable=$false}
    }
    if ($HasMDILicense -eq $true -and $MDIAvailable -eq $true) {
        Write-Verbose "Adding Defender for Identity role to App"
        $AppRoles += New-Object -TypeName PSObject -Property @{
            ID="f8dcd971-5d83-4e1e-aa95-ef44611ad351"
            Name="SecurityIdentitiesHealth.Read.All"
            Type='Role'
            Resource="00000003-0000-0000-c000-000000000000" # Graph
        }
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

function Get-SOAEntraApp {
    Param(
        [string]$CloudEnvironment
    )

    # Determine if Microsoft Entra application exists
    # Retrieving the Count is mandatory when using Eventual consistency level, otherwise a HTTP/400 error is returned
    $EntraApp = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/applications?`$filter=web/redirectUris/any(p:p eq 'https://security.optimization.assessment.local')&`$count=true" -Headers @{'ConsistencyLevel' = 'eventual'} -OutputType PSObject).Value

    if ($EntraApp -and $RemoveExistingEntraApp -and $DoNotRemediate -eq $false) {
        Write-Host "$(Get-Date) Removing existing Microsoft Entra application..."
        try {
            Invoke-MgGraphRequest -Method DELETE -Uri "/v1.0/applications/$($EntraApp.Id)"
            $EntraApp = $null
        }
        catch {
            Write-Warning "$(Get-Date) Unable to remove existing Microsoft Entra application. Please remove it manually."
        }
    }

    if (!$EntraApp) {
        if ($DoNotRemediate -eq $false) {
            Write-Host "$(Get-Date) Creating Microsoft Entra enterprise application..."
            $EntraApp = Install-EntraApp -CloudEnvironment $CloudEnvironment
            Write-Verbose "$(Get-Date) Get-SOAEntraApp App $($EntraApp.Id)"
        }
    }
    else {
        # Check whether the application name should be updated
        if ($EntraApp.displayName -eq 'Office 365 Security Optimization Assessment') {
            Write-Verbose "$(Get-Date) Renaming the display name of the Microsoft Entra application..."
            $Body = @{'displayName' = 'Microsoft Security Assessment'}
            Invoke-MgGraphRequest -Method PATCH -Uri "/v1.0/applications/$($EntraApp.Id)" -Body $Body
        }

        # Check if public client URI is set
        $pcRUrl = @('https://login.microsoftonline.com/common/oauth2/nativeclient')
        if ($EntraApp.PublicClient.RedirectUris -notcontains $pcRUrl) {
            if ($DoNotRemediate -eq $false){
                # Set as public client to be able to collect from Dynamics with delegated scope
                Write-Verbose "$(Get-Date) Setting Microsoft Entra application public client redirect URI..."
                $Params = @{
                    'publicClient' = @{
                        'redirectUris' = $pcRUrl
                    }
                }
                Invoke-MgGraphRequest -Method PATCH -Uri "/v1.0/applications/$($EntraApp.Id)" -Body $Params
                
                # Get app again so public client is set for checking DoNotRemediate in calling function
                $EntraApp = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/applications?`$filter=web/redirectUris/any(p:p eq 'https://security.optimization.assessment.local')&`$count=true" -Headers @{'ConsistencyLevel' = 'eventual'} -OutputType PSObject).Value
            }
        }
        # Check if correct web redirect URIs are set
        $webRUri = @("https://security.optimization.assessment.local","https://o365soa.github.io/soa/")
        if (Compare-Object -ReferenceObject $EntraApp.Web.RedirectUris -DifferenceObject $webRUri) {
            if ($DoNotRemediate -eq $false) {
                Write-Verbose "$(Get-Date) Setting Microsoft Entra application web redirect URIs..."
                $Params = @{
                    'web' = @{
                        'redirectUris' = $webRUri
                    }
                }
                Invoke-MgGraphRequest PATCH "/v1.0/applications/$($EntraApp.Id)" -Body $Params

                $EntraApp = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/applications?`$filter=web/redirectUris/any(p:p eq 'https://security.optimization.assessment.local')&`$count=true" -Headers @{'ConsistencyLevel' = 'eventual'} -OutputType PSObject).Value
            }
        }
        # Check if service principal (enterprise app) is owner of its app registration
        $appOwners = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/applications/$($EntraApp.Id)/owners" -OutputType PSObject).Value
        $appSp = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/servicePrincipals(appId=`'$($EntraApp.AppId)`')" -OutputType PSObject
        if ($appOwners.Id -notcontains $appSp.Id) {
            if ($DoNotRemediate -eq $false) {
                Write-Verbose "$(Get-Date) Adding Microsoft Entra application as owner of its app registration..."
                $Params = @{
                    '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($appSp.Id)"
                }
                Invoke-MgGraphRequest -Method POST -Uri "/v1.0/applications(appId=`'$($EntraApp.AppId)`')/owners/`$ref" -body $Params
            }
        }  
    }

    Return $EntraApp

}

Function Test-SOAApplication
{
    Param
    (
        [Parameter(Mandatory=$true)]
        $App,
        $Secret,
        $TenantDomain,
        [Switch]$WriteHost,
        [Switch]$NewTokens,
        [Alias("O365EnvironmentName")][string]$CloudEnvironment="Commercial"
    )

    Write-Verbose "$(Get-Date) Test-SOAApplication App $($App.AppId) TenantDomain $($TenantDomain) SecretLength $($Secret.Length) CloudEnvironment $CloudEnvironment"

    # Perform permission check
    If($WriteHost) { Write-Host "$(Get-Date) Performing application permission check... (This may take up to 5 minutes)" }
    $PermCheck = Invoke-AppPermissionCheck -App $App

    # Perform check for consent
    If($PermCheck -eq $True)
    {
        If($WriteHost) { Write-Host "$(Get-Date) Performing token check... (This may take up to 5 minutes)" }
        If ($NewTokens){
            $TokenCheck = Invoke-AppTokenRolesCheckV2 -CloudEnvironment $CloudEnvironment
        } Else {
            $TokenCheck = Invoke-AppTokenRolesCheck -App $App -Secret $Secret -TenantDomain $tenantdomain -CloudEnvironment $CloudEnvironment
        }
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
        [ValidateSet("EXO","SCC","SPO","PP","Teams","Graph","ActiveDirectory")][string[]]$Bypass,
    [switch]$UseProxy,
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
    [Parameter(ParameterSetName='EntraAppOnly')]
        [switch]$DoNotRemediate,
    [Parameter(ParameterSetName='Default')]
    [Parameter(ParameterSetName='ConnectOnly')]
    [Parameter(ParameterSetName='EntraAppOnly')]
    [Parameter(ParameterSetName='ModulesOnly')]
        [Alias('O365EnvironmentName')][ValidateSet("Commercial", "USGovGCC", "USGovGCCHigh", "USGovDoD", "Germany", "China")][string]$CloudEnvironment="Commercial",
    [Parameter(ParameterSetName='ConnectOnly')]
        [switch]$ConnectOnly,
    [Parameter(ParameterSetName='ModulesOnly')]
        [switch]$ModulesOnly,
    [Parameter(ParameterSetName='Default')]
    [Parameter(ParameterSetName='ModulesOnly')]
        [switch]$SkipADModule,
    [Parameter(ParameterSetName='Default')]
    [Parameter(ParameterSetName='ModulesOnly')]
        [switch]$ADModuleOnly,
    [Parameter(ParameterSetName='EntraAppOnly')]
        [Alias('AzureADAppOnly')][switch]$EntraAppOnly,
    [Parameter(ParameterSetName='Default')]
    [Parameter(ParameterSetName='EntraAppOnly')]
        [switch]$RemoveExistingEntraApp
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
    # EXO 2.0.3, Teams modules do not support PS 7
    if ($PSVersionTable.PSVersion.ToString() -like "7.*") {
        throw "Running this script in PowerShell 7 is not supported."
    }
    
    # Default run
    $ConnectCheck = $True
    $ModuleCheck = $True
    $EntraAppCheck = $True

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
        $EntraAppCheck = $False
    }

    # Change based on ConnectOnly flag
    If($ConnectOnly) {
        $ConnectCheck = $True
        $EntraAppCheck = $False
        $ModuleCheck = $False
    }

    # Change based on EntraAppOnly flag
    If($EntraAppOnly) {
        $ConnectCheck = $False
        $EntraAppCheck = $True
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
        Write-Host "$(Get-Date) The DoNotRemediate switch was used.  Any missing or outdated modules, as well as the registration and/or configuration of the Microsoft Entra enterprise application will not be performed." -ForegroundColor Yellow
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
    Write-Host "This script is used to install and validate the prerequisites for running the data collection"
    Write-Host "for one of the Microsoft security assessments offered via Microsoft Services."
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
        if ($EntraAppCheck) {
            Write-Host "- Create a Microsoft Entra enterprise application in your tenant:" -ForegroundColor Green
            Write-Host "   -- The application name is 'Microsoft Security Assessment'" -ForegroundColor Green
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

        $ModuleCheckResult = Invoke-SOAModuleCheck -CloudEnvironment $CloudEnvironment

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
                $ModuleCheckResult = Invoke-SOAModuleCheck -CloudEnvironment $CloudEnvironment
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

        Perform the connection check

    #>

    If($ConnectCheck -eq $True) {
        # Proceed to testing connections
        
        $Connections = @(Test-Connections -RPSProxySetting $RPSProxySetting -CloudEnvironment $CloudEnvironment)
        
        $Connections_OK = @($Connections | Where-Object {$_.Connected -eq $True -and $_.TestCommand -eq $True})
        $Connections_Error = @($Connections | Where-Object {$_.Connected -eq $False -or $_.TestCommand -eq $False -or $Null -ne $_.OtherErrors})
    }

    If($EntraAppCheck -eq $True) {

        # When EntraAppOnly is used, this script may not be connected to Microsoft Graph
        switch ($CloudEnvironment) {
            "Commercial"   {$cloud = 'Global'}
            "USGovGCC"     {$cloud = 'Global'}
            "USGovGCCHigh" {$cloud = 'USGov'}
            "USGovDoD"     {$cloud = 'USGovDoD'}
            "Germany"      {$cloud = 'Germany'}
            "China"        {$cloud = 'China'}
        }
        $mgContext =  (Get-MgContext).Scopes
        if ($mgContext -notcontains 'Application.ReadWrite.All' -or ($mgContext -notcontains 'Organization.Read.All' -and $mgContext -notcontains 'Directory.Read.All')) {
            Write-Host "$(Get-Date) Connecting to Graph with delegated authentication..."
            if ($null -ne (Get-MgContext)){Disconnect-MgGraph | Out-Null}
            $connCount = 0
            $connLimit = 5
            do {
                try {
                    $connCount++
                    Write-Verbose "$(Get-Date) Graph Delegated connection attempt #$connCount"
                    Connect-MgGraph -Scopes 'Application.ReadWrite.All','Organization.Read.All' -Environment $cloud -ContextScope "Process" | Out-Null
                }
                catch {
                    Write-Verbose $_
                    Start-Sleep 1
                }
            }
            until ($null -ne (Get-MgContext) -or $connCount -eq $connLimit)
            if ($null -eq (Get-MgContext)) {
                Write-Error -Message "Unable to connect to Graph. Skipping Microsoft Entra application check."
            }
        }
        
        if (Get-MgContext) {
            Write-Host "$(Get-Date) Checking Microsoft Entra enterprise application..."

            # Get the tenant domain
            $tenantdomain = Get-InitialDomain

            $script:MDELicensed = Get-LicenseStatus -LicenseType MDE
            Write-Verbose "$(Get-Date) Get-LicenseStatus MDE License found: $($script:MDELicensed)"

            $script:MDILicensed = Get-LicenseStatus -LicenseType MDI
            Write-Verbose "$(Get-Date) Get-LicenseStatus MDI License found: $($script:MDILicensed)"

            $script:ATPP2Licensed = Get-LicenseStatus -LicenseType ATPP2
            Write-Verbose "$(Get-Date) Get-LicenseStatus ATPP2 License found: $($script:ATPP2Licensed)"

            # Determine if Microsoft Entra application exists (and has public client redirect URI set), create if doesnt
            $EntraApp = Get-SOAEntraApp -CloudEnvironment $CloudEnvironment
        }

        If($EntraApp) {
            # Check if redirect URIs not set for existing app because DoNotRemediate is True
            $webRUri = @("https://security.optimization.assessment.local","https://o365soa.github.io/soa/")
            if (($EntraApp.PublicClient.RedirectUris -notcontains 'https://login.microsoftonline.com/common/oauth2/nativeclient' -or (Compare-Object -ReferenceObject $EntraApp.Web.RedirectUris -DifferenceObject $webRUri)) -and $DoNotRemediate) {
                # Fail the Entra app check
                $CheckResults += New-Object -Type PSObject -Property @{
                    Check="Entra Application"
                    Pass=$false
                }
            }
            else {
                # Pass the Entra app check
                $CheckResults += New-Object -Type PSObject -Property @{
                    Check="Entra Application"
                    Pass=$true
                }
            }

            # Reset secret
            $clientsecret = Reset-SOAAppSecret -App $EntraApp -Task "Prereq"
            Write-Host "$(Get-Date) Sleeping to allow for replication of the application's new client secret..."
            Start-Sleep 10

            # Reconnect with Application permissions
            Disconnect-MgGraph | Out-Null
            $SSCred = $clientsecret | ConvertTo-SecureString -AsPlainText -Force
            $GraphCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($EntraApp.AppId), $SSCred
            $ConnCount = 0
            Write-Host "$(Get-Date) Connecting to Graph with application authentication..."
            Do {
                Try {
                    $ConnCount++
                    Write-Verbose "$(Get-Date) Graph connection attempt #$ConnCount"
                    Connect-MgGraph -TenantId $tenantdomain -ClientSecretCredential $GraphCred -Environment $cloud -ContextScope "Process" -ErrorAction Stop | Out-Null
                } Catch {
                    Start-Sleep 5
                }
            } Until ($null -ne (Get-MgContext))

            $AppTest = Test-SOAApplication -App $EntraApp -Secret $clientsecret -TenantDomain $tenantdomain -CloudEnvironment $CloudEnvironment -WriteHost
                
            # Entra App Permission - Perform remediation if specified
            If($AppTest.Permissions -eq $False -and $DoNotRemediate -eq $false)
            {
                # Set up the correct Entra App Permissions
                Write-Host "$(Get-Date) Remediating application permissions..."
                Write-Host "$(Get-Date) Reconnecting to Graph with delegated authentication..."
                # No scopes need to be explicitly requested here because the user will have already consented to them in the previous delegated connection
                Connect-MgGraph -Environment $cloud -ContextScope "Process" | Out-Null
                If((Set-EntraAppPermission -App $EntraApp -PerformConsent:$True -CloudEnvironment $CloudEnvironment) -eq $True) {
                    # Perform check again after setting permissions
                    $ConnCount = 0
                    Write-Host "$(Get-Date) Reconnecting to Graph with application authentication..."
                    Do {
                        Try {
                            $ConnCount++
                            Write-Verbose "$(Get-Date) Graph connection attempt #$ConnCount"
                            Connect-MgGraph -TenantId $tenantdomain -ClientSecretCredential $GraphCred -Environment $cloud -ContextScope "Process" -ErrorAction Stop | Out-Null
                        } Catch {
                            Start-Sleep 5
                        }
                    } Until ($null -ne (Get-MgContext))
                    $AppTest = Test-SOAApplication -App $EntraApp -Secret $clientsecret -TenantDomain $tenantdomain -CloudEnvironment $CloudEnvironment -WriteHost
                }
            }

            If($AppTest.Token -eq $False)
            {
                Write-Host "$(Get-Date) Missing roles in access token; possible that consent was not completed..."
                if ($DoNotRemediate -eq $false) {
                    # Request admin consent
                    If((Invoke-Consent -App $EntraApp -CloudEnvironment $CloudEnvironment) -eq $True) {
                        # Perform check again after consent
                        $AppTest = Test-SOAApplication -App $EntraApp -Secret $clientsecret -TenantDomain $tenantdomain -CloudEnvironment $CloudEnvironment -WriteHost
                    }
                }
            }

            # Add final result to checkresults object
            $CheckResults += New-Object -Type PSObject -Property @{
                Check="Entra App Permissions"
                Pass=$AppTest.Permissions
            }
            $CheckResults += New-Object -Type PSObject -Property @{
                Check="Entra App Role Consent"
                Pass=$AppTest.Token
            }

            Write-Host "$(Get-Date) Performing Graph Test..."
            # Perform Graph check using credentials on the App
            if ($null -ne (Get-MgContext)){Disconnect-MgGraph | Out-Null}
            Start-Sleep 10 # Avoid a race condition
            Connect-MgGraph -TenantId $tenantdomain -ClientSecretCredential $GraphCred -Environment $cloud -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null
            
            If($ConnectError){
                $CheckResults += New-Object -Type PSObject -Property @{
                    Check="Graph SDK Connection"
                    Pass=$False
                }
            }
            else {
                $CheckResults += New-Object -Type PSObject -Property @{
                    Check="Graph SDK Connection"
                    Pass=$True
                }

                # Remove client secret
                Remove-SOAAppSecret
                # Disconnect
                Disconnect-MgGraph | Out-Null
            }
        } 
        Else 
        {
            # Entra application does not exist
            $CheckResults += New-Object -Type PSObject -Property @{
                Check="Entra Application"
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

    If($EntraAppCheck -eq $True) {

        Write-Host "$(Get-Date) Microsoft Entra enterprise application checks" -ForegroundColor Green

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
