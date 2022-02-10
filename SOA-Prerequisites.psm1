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
    exit
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
    Write-Host "##########################################" -ForegroundColor Yellow
    Write-Host "#                 IMPORTANT              #" -ForegroundColor Yellow
    Write-Host "##########################################" -ForegroundColor Yellow
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

    $sku = (Get-MsolAccountSku -ErrorAction:SilentlyContinue)[0]
    return $sku.AccountName

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
            "USGovGCCHigh" {$url = "https://" + $tenantName + "-admin.sharepoint.us";break}
            "USGovDoD"     {$url = "https://" + $tenantName + "-admin.dps.mil";break}
            "Germany"      {$url = "https://" + $tenantName + "-admin.sharepoint.de";break}
            "China"        {$url = "https://" + $tenantName + "-admin.sharepoint.cn"}
        }
    }
    return $url
}

Function Reset-AppSecret {
    <#
    
        This function creates a new secret for the application
    
    #>
    Param (
        $App
    )

    # Provision a short lived credential +48 hrs.
    $clientsecret = New-AzureADApplicationPasswordCredential -ObjectId $App.ObjectId -EndDate (Get-Date).AddDays(2) -CustomKeyIdentifier "Prereq on $(Get-Date -Format "dd-MMM-yyyy")"
        
    Start-Sleep 30

    Return $clientsecret.Value
}

Function Invoke-LoadAdal {
    <#
    
        Finds a suitable ADAL library from AzureAD Preview and uses that
        This prevents us having to ship the .dll's ourself.

    #>
    $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    $Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]
    $aadModule      = $AadModule | Where-Object { $_.version -eq $Latest_Version.version }
    $adal           = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms      = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
}

Function Get-AccessToken {
    <#
    
        Fetch the Access Token using ADAL libraries
    
    #>
    Param(
        $TenantName,
        $ClientID,
        $Secret,
        $Resource,
        [Switch]$ClearTokenCache, # useful if we need to get newly added scopes
        [string]$O365EnvironmentName
    )

    Write-Verbose "$(Get-Date) Get-AccessToken Tenant $TenantName ClientID $ClientID Resource $Resource TokenCache $ClearTokenCache SecretLength $($Secret.Length) O365EnvironmentName $O365EnvironmentName"

    if (!$CredPrompt){$CredPrompt = 'Auto'}

    switch ($O365EnvironmentName) {
        "Commercial"   {$authority = "https://login.microsoftonline.com/$TenantName";break}
        "USGovGCCHigh" {$authority = "https://login.microsoftonline.us/$TenantName";break}
        "USGovDoD"     {$authority = "https://login.microsoftonline.us/$TenantName";break}
        "Germany"      {$authority = "https://login.microsoftonline.de/$TenantName";break}
        "China"        {$authority = "https://login.partner.microsoftonline.cn/$TenantName"}
    }
    $authContext        = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority   
    
    If($ClearTokenCache) {
        $authContext.TokenCache.Clear()
    }
    
    $ClientCredential   = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential" -ArgumentList @($ClientID,$Secret)
    $authResult         = $authContext.AcquireTokenAsync($Resource,$ClientCredential)

    return $authResult.Result
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

    Write-Host "$(Get-Date) Testing Graph..."
    
    switch ($O365EnvironmentName) {
        "Commercial"   {$Resource = "https://graph.microsoft.com/";break}
        "USGovGCCHigh" {$Resource = "https://graph.microsoft.us/";break}
        "USGovDoD"     {$Resource = "https://dod-graph.microsoft.us/";break}
        "Germany"      {$Resource = "https://graph.microsoft.de/";break}
        "China"        {$Resource = "https://microsoftgraph.chinacloudapi.cn/"}
    }

    switch ($O365EnvironmentName) {
        "Commercial"   {$Base = "https://graph.microsoft.com";break}
        "USGovGCCHigh" {$Base = "https://graph.microsoft.us";break}
        "USGovDoD"     {$Base = "https://dod-graph.microsoft.us";break}
        "Germany"      {$Base = "https://graph.microsoft.de";break}
        "China"        {$Base = "https://microsoftgraph.chinacloudapi.cn"}
    }
    $Uri = "$Base/beta/security/secureScores?`$top=1"

    $Token = Get-AccessToken -TenantName $tenantdomain -ClientID $AzureADApp.AppId -Secret $Secret -Resource $Resource -O365EnvironmentName $O365EnvironmentName
    $headerParams = @{'Authorization'="$($Token.AccessTokenType) $($Token.AccessToken)"}

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
    Write-Verbose "$(Get-Date) Set-AzureADAppPermissions App $($App.ObjectId) O365EnvironmentName $O365EnvironmentName"

    $RequiredResources = @()
    $PermissionSet = $False
    $ConsentPerformed = $False

    $Roles = Get-RequiredAppPermissions -HasATPP2License $ATPLicensed -O365EnvironmentName $O365EnvironmentName

    <#
    
        The following creates a Required Resources array. The array consists of RequiredResourceAccess objects.
        There is one RequiredResourceAccess object for every resource; for instance, Graph is a resource.
        In the RequiredResourceAccess object is an array of scopes that are required for that resource.
    
    #>
    
    ForEach($ResourceRolesGrouping in ($Roles | Group-Object Resource)) 
    {

        # Define the resource
        $Resource = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
        $Resource.ResourceAppId = $ResourceRolesGrouping.Name

        # Add the scopes
        ForEach($Role in $($ResourceRolesGrouping.Group)) {
            Write-Verbose "$(Get-Date) Set-AzureADAppPermissions Add $($Role.Name) $($Role.ID) O365EnvironmentName $O365EnvironmentName"
            $Perm = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $Role.ID,"Role"
            $Resource.ResourceAccess += $Perm
        }

        # Add to the list of required access
        $RequiredResources += $Resource

    }
    
    Try
    {
        Set-AzureADApplication -ObjectId $App.ObjectId -RequiredResourceAccess $RequiredResources
        $PermissionSet = $True
    }
    Catch
    {
        $PermissionSet = $False
    }

    If($PermissionSet -eq $True)
    {
        Write-Host "$(Get-Date) Verifying new permissions applied (this may take up to 5 minutes)..."
        If($(Invoke-AppPermissionCheck -App $App -NewPermission) -eq $False)
        {    
            $PermissionSet = $False
        }
    }

    If($PerformConsent -eq $True)
    {
        If((Invoke-Consent -App $AzureADApp -O365EnvironmentName $O365EnvironmentName) -eq $True) {
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
    
    $Roles = Get-RequiredAppPermissions -HasATPP2License $ATPLicensed -O365EnvironmentName $O365EnvironmentName

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

    Write-Verbose "$(Get-Date) Invoke-AppPermissionCheck App ID $($App.ObjectId) Role Count $($Roles.Count)"

    While($Counter -lt $MaxTime)
    {

        # Refresh roles from AAD
        $App = Get-AzureADApplication -ObjectId $App.ObjectId

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
            Write-Verbose "$(Get-Date) Invoke-AppPermissionCheck App ID $($App.ObjectId) Role Count $($Roles.Count) OK"
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

    $MissingRoles = @()
    switch ($O365EnvironmentName) {
        "Commercial"   {$GraphResource = "https://graph.microsoft.com/";break}
        "USGovGCCHigh" {$GraphResource = "https://graph.microsoft.us/";break}
        "USGovDoD"     {$GraphResource = "https://dod-graph.microsoft.us/";break}
        "Germany"      {$GraphResource = "https://graph.microsoft.de/";break}
        "China"        {$GraphResource = "https://microsoftgraph.chinacloudapi.cn/"}
    }

    $Roles = Get-RequiredAppPermissions -HasATPP2License $ATPLicensed -O365EnvironmentName $O365EnvironmentName

    # For race conditions, we will wait $MaxTime seconds and Sleep interval of $SleepTime
    $MaxTime = 300
    $SleepTime = 10
    $Counter = 0
    
    # Check Graph endpoint
    While($Counter -lt $MaxTime)
    {

        Write-Verbose "$(Get-Date) Invoke-AppTokenRolesCheck Begin for Graph endpoint"
        # Obtain the token
        $Token = Get-AccessToken -TenantName $tenantdomain -ClientID $App.AppId -Secret $Secret -Resource $GraphResource -ClearTokenCache -O365EnvironmentName $O365EnvironmentName

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
    
    $endpointAvailable = $false
    switch ($O365EnvironmentName) {
        "Commercial"   {$SecurityResource = "https://api.security.microsoft.com";$endpointAvailable=$true;break}
        "USGovGCCHigh" {$SecurityResource = "";$endpointAvailable=$false;break}
        "USGovDoD"     {$SecurityResource = "";$endpointAvailable=$false;break}
        "Germany"      {$SecurityResource = "";$endpointAvailable=$false;break}
        "China"        {$SecurityResource = "";$endpointAvailable=$false}
    }
    #Defender API is currently not available for sovereign clouds.  Once endpoints are available, they can be populated and set to True.

    # Check Security endpoint
    if ($ATPLicensed -eq $true -and $endpointAvailable -eq $true) {
        
        $MaxTime = 300
        $SleepTime = 10
        $Counter = 0
        
        While($Counter -lt $MaxTime)
        {

            Write-Verbose "$(Get-Date) Invoke-AppTokenRolesCheck Begin for Security endpoint"

            # Obtain the token
            $Token = Get-AccessToken -TenantName $tenantdomain -ClientID $App.AppId -Secret $Secret -Resource $SecurityResource -ClearTokenCache -O365EnvironmentName $O365EnvironmentName

            If($Null -ne $Token)
            {
                # Perform decode from JWT
                $tokobj = ConvertFrom-JWT -token $Token

                Write-Verbose "$(Get-Date) Invoke-AppTokenRolesCheck Token JWT $($tokenArray)"

                # Check the roles are in the token, check for MTP at this stage.
                ForEach($Role in ($Roles | Where-Object {$_.Resource -eq "8ee8fdad-f234-4243-8f3b-15c294843740"})) {
                    If($tokobj.Roles -notcontains $Role.Name) {
                        Write-Verbose "$(Get-Date) Invoke-AppTokenRolesCheck missing $($Role.Name)"
                        $MissingRoles += $Role
                    }
                }
            }
            If($MissingRoles.Count -eq 0 -and $Null -ne $Token)
            {
                $SecurityResult = $True
            }
            Else 
            {
                $SecurityResult = $False
            }

            If($SecurityResult -eq $True)
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
    }

    # Check if Graph and, if applicable, Security pass.  If Graph fails, return false regardless of Security result
    if ($GraphResult) {
        $return = $true
        if ($ATPLicensed -eq $true -and $endpointAvailable -eq $true) {
            if ($SecurityResult) {$return = $true}
            else {$return = $false}
        }
    }
    else {$return = $false}
    
    
    return $return
}

Function Invoke-WinRMBasicCheck {
    <#
    
        Checks to determine if WinRM basic authentication is enabled.
        This is required for Exchange Online and Teams modules (the latter when connecting via RPS).
    
    #>

    # Default for WinRM Client is enabled, so check whether it has been explicitly disabled. Using the WSMAN drive to avoid querying multiple Registry keys
    If ((Get-ChildItem WSMAN:\localhost\Client\Auth\Basic).Value -eq $False) { 
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
        "USGovGCCHigh" {$AuthLocBase = "https://login.microsoftonline.us";break}
        "USGovDoD"     {$AuthLocBase = "https://login.microsoftonline.us";break}
        "Germany"      {$AuthLocBase = "https://login.microsoftonline.de";break}
        "China"        {$AuthLocBase = "https://login.partner.microsoftonline.cn"}
    }
    $Location = "$AuthLocBase/common/adminconsent?client_id=$($App.AppId)&state=12345&redirect_uri=https://soaconsentreturn.azurewebsites.net"
    
    Write-Important
    Write-Host "In 20 seconds, a window will load asking for you to consent to Security Optimization Assessment reading information in your tenant."
    write-Host "You need to log on and consent as a Global Administrator"
    Write-Host "When consent is complete - a green OK message should appear - You can close the browser window at this point."
    Write-Host ""
    Write-Host "For more information about this consent, please review the Scoping Email."
    Write-Host ""
    Write-Host "If you have Single Sign On (SSO) turned on, and you are not logged on as a Global Administrator, you will need to copy the link below in to an in-private browser session."
    Write-Host ""
    Write-Host "If the browser window does not load in 20 seconds, copy and paste the following in to a browser:"
    Write-Host ""
    Write-Host $Location
    Write-Host ""
    Start-Sleep 20
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
    $AzureADApp = New-AzureADApplication -DisplayName "Office 365 Security Optimization Assessment"  -ReplyUrls @("https://security.optimization.assessment.local","https://soaconsentreturn.azurewebsites.net")
    
    # Set up the correct permissions
    Set-AzureADAppPermission -App $AzureADApp -PerformConsent:$True -O365EnvironmentName $O365EnvironmentName

    # Return the newly created application
    Return (Get-AzureADApplication -ObjectId $AzureADApp.ObjectId)
    
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

    If($InstalledModule.Count -gt 1) {
        # More than one module, flag this
        $MultipleFound = $True
        $modulePaths = @()
        foreach ($m in $InstalledModule) {
            $modulePaths += $m.Path.Substring(0,$m.Path.LastIndexOf('\'))
        }
        $modulePaths = $modulePaths | Sort-Object
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
        $targetSkus = @('ENTERPRISEPREMIUM','SPE_E5','M365EDU_A5','IDENTITY_THREAT_PROTECTION','THREAT_INTELLIGENCE','M365_SECURITY_COMPLIANCE')
    }
    else {
        Write-Error -Message "$(Get-Date) Invalid license type specified"
        return $false
    }
    
    $subscribedSku = Get-AzureADSubscribedSku
    foreach ($tSku in $targetSkus) {
        foreach ($sku in $subscribedSku) {
            if ($sku.PrepaidUnits.Enabled -gt 0 -or $sku.PrepaidUnits.Warning -gt 0 -and $sku.SkuPartNumber -match $tSku) {
                return $true
            }
        }
    }
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
    Install-Module $Module -Force -Scope:AllUsers -AllowClobber

    If($Update) {
        # Remove old versions of the module
        Uninstall-OldModules -Module $Module
    }
}

Function Install-ADDSModule {
    <#
    
        Installs the on-prem Active Directory module based on the detected OS version
    
    #>

    $ComputerInfo = Get-ComputerInfo

    If($ComputerInfo) {
        Write-Verbose "Computer type: $($ComputerInfo.WindowsInstallationType)"
        Write-Verbose "OS Build: $($ComputerInfo.OsBuildNumber)"
        If ($ComputerInfo.WindowsInstallationType -eq "Server") {
            Write-Verbose "Server OS detected, using 'Add-WindowsFeature'"
            Try {
                Add-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature | Out-Null
            } Catch {
                Write-Error "$(Get-Date) Could not install ActiveDirectory module due to error"
            }
        }
        ElseIf ($ComputerInfo.WindowsInstallationType -eq "Client" -And $ComputerInfo.OsBuildNumber -ge 17763) {
            Write-Verbose "Windows 10 version 1809 or later detected, using 'Add-WindowsCapability'"
            Try {
                Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" | Out-Null
            } Catch {
                Write-Error "$(Get-Date) Could not install ActiveDirectory module due to error. Check Proxy server and WSUS settings."
            }
        }
        ElseIf ($ComputerInfo.WindowsInstallationType -eq "Client") {
            Write-Verbose "Windows 10 version 1803 or earlier detected, using 'Enable-WindowsOptionalFeature'"
            Try {
                Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell | Out-Null
            } Catch {
                Write-Error "$(Get-Date) Could not install ActiveDirectory module due to error. Check Proxy server and WSUS settings, or manually download and install from https://www.microsoft.com/en-us/download/details.aspx?id=45520"
            }
        }
        Else {
            Write-Error "Error detecting the OS type while installing ActiveDirectory module."
        }
    }
}

Function Invoke-ModuleFix {
    <#

        Attempts to fix modules if $Remediate flag is specified
    
    #>
    Param($Modules)

    If(Get-IsAdministrator -eq $True) {

        # Administrator so can remediate
        $OutdatedModules = $Modules | Where-Object {$null -ne $_.InstalledVersion -and $_.NewerAvailable -eq $true -and $_.Conflict -ne $True}
        $DupeModules = $Modules | Where-Object {$_.Multiple -eq $True}
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
                    Write-Error "$(Get-Date) Could not trust PSGallery due to error"
                    Exit-Script
                }
            }
        } Else {
            Write-Error "PSGallery is not present on this host, so modules cannot be remediated."
            Exit-Script
        }

        # Conflict modules, need to be removed
        ForEach($ConflictModule in $ConflictModules) {
            Write-Host "$(Get-Date) Removing conflicting module $($ConflictModule.Module)"
            Uninstall-Module -Name $($ConflictModule.Module) -Force
        }

        # Out of date modules
        ForEach($OutdatedModule in $OutdatedModules) {
            Write-Host "$(Get-Date) Updating $($OutdatedModule.Module) from $($OutdatedModule.InstalledVersion) to $($OutdatedModule.GalleryVersion)"
            Install-ModuleFromGallery -Module $($OutdatedModule.Module) -Update
        }

        # Missing gallery modules
        ForEach($MissingGalleryModule in $MissingGalleryModules) {
            Write-Host "$(Get-Date) Installing $($MissingGalleryModule.Module)"
            Install-ModuleFromGallery -Module $($MissingGalleryModule.Module)          
        }

        # Dupe modules
        ForEach($DupeModule in $DupeModules) {
            Write-Host "$(Get-Date) Removing duplicate modules for $($DupeModule.Module)"
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
    } Else {
        Write-Error "Load PowerShell as administrator in order to fix modules"
        Return $False
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

    $RequiredModules = @()
    
    # Conflict modules are modules which their presence causes issues
    $ConflictModules = @("AzureAD")

    # Bypass checks
    If($Bypass -notcontains "AAD") { $RequiredModules += "AzureADPreview" }
    If($Bypass -notcontains "MSOL") { $RequiredModules += "MSOnline" }
    If($Bypass -notcontains "SharePoint") { $RequiredModules += "Microsoft.Online.SharePoint.PowerShell" }
    If($Bypass -notcontains "Teams") {$RequiredModules += "MicrosoftTeams"}
    If (($Bypass -notcontains "Exchange" -or $Bypass -notcontains "SCC")) {$RequiredModules += "ExchangeOnlineManagement"}
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

Function Test-Connections {
    Param(
        $RPSProxySetting,
        [string]$O365EnvironmentName
    )

    $Connections = @()

    Write-Host "$(Get-Date) Testing connections..."

    <#
        
        AD PowerShell Version 1. Aka MSOL
        
    #>
    If($Bypass -notcontains "MSOL") {

        
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        Write-Host "$(Get-Date) Connecting to Azure AD PowerShell 1..."
        switch ($O365EnvironmentName) {
            "Commercial"   {Connect-MsolService -ErrorAction:SilentlyContinue -ErrorVariable ConnectError;break}
            "USGovGCCHigh" {Connect-MsolService -AzureEnvironment USGovernment -ErrorAction:SilentlyContinue -ErrorVariable ConnectError;break}
            "USGovDoD"     {Connect-MsolService -AzureEnvironment USGovernment -ErrorAction:SilentlyContinue -ErrorVariable ConnectError;break}
            "Germany"      {Connect-MsolService -AzureEnvironment AzureGermanyCloud -ErrorAction:SilentlyContinue -ErrorVariable ConnectError;break}
            "China"        {Connect-MsolService -AzureEnvironment AzureChinaCloud -ErrorAction:SilentlyContinue -ErrorVariable ConnectError}
        }
        
        # If no error, try test command
        If($ConnectError) { $Connect = $False; $Command = $False} Else { 
            $Connect = $True 
            Get-MsolDomain -ErrorAction SilentlyContinue -ErrorVariable CommandError | Out-Null
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
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        Write-Host "$(Get-Date) Connecting to Azure AD PowerShell 2..."
        switch ($O365EnvironmentName) {
            "Commercial"   {$AADConnection = Connect-AzureAD -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
            "USGovGCCHigh" {$AADConnection = Connect-AzureAD -ErrorAction:SilentlyContinue -ErrorVariable ConnectError -AzureEnvironmentName AzureUSGovernment | Out-Null;break}
            "USGovDoD"     {$AADConnection = Connect-AzureAD -ErrorAction:SilentlyContinue -ErrorVariable ConnectError -AzureEnvironmentName AzureUSGovernment | Out-Null;break}
            "Germany"      {$AADConnection = Connect-AzureAD -ErrorAction:SilentlyContinue -ErrorVariable ConnectError -AzureEnvironmentName AzureGermanyCloud | Out-Null;break}
            "China"        {$AADConnection = Connect-AzureAD -ErrorAction:SilentlyContinue -ErrorVariable ConnectError -AzureEnvironmentName AzureChinaCloud | Out-Null}
        }

        # If no error, try test command
        If($ConnectError) { $Connect = $False; $Command = $False} Else { 
            $Connect = $True 
            Get-AzureADDomain -ErrorAction SilentlyContinue -ErrorVariable CommandError | Out-Null
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
    If($Bypass -notcontains "SCC") {
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        Write-Host "$(Get-Date) Connecting to SCC..."
        switch ($O365EnvironmentName) {
            "Commercial"   {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null;break}
            "USGovGCCHigh" {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ConnectionUri https://ps.compliance.protection.office365.us/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.microsoftonline.us/common | Out-Null;break}
            "USGovDoD"     {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ConnectionUri https://l5.ps.compliance.protection.office365.us/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.microsoftonline.us/common | Out-Null;break}
            "Germany"      {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ConnectionUri https://ps.compliance.protection.outlook.de/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.microsoftonline.de/common | Out-Null;break}
            "China"        {ExchangeOnlineManagement\Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting -ConnectionUri https://ps.compliance.protection.partner.outlook.cn/PowerShell-LiveID -AzureADAuthorizationEndPointUri https://login.partner.microsoftonline.cn/common | Out-Null}
        }

        If((Get-PSSession | Where-Object {$_.ComputerName -like "*protection.o*" -or $_.ComputerName -like "*protection.partner.o*"}).State -eq "Opened") { $Connect = $True } Else { $Connect = $False }

        # Run test command
        If(Get-Command "Get-ProtectionAlert") {
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
    If($Bypass -notcontains "Exchange") {
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        Write-Host "$(Get-Date) Connecting to Exchange..."
        switch ($O365EnvironmentName) {
            "Commercial"   {Connect-ExchangeOnline -ShowBanner:$false -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null;break}
            "USGovGCCHigh" {Connect-ExchangeOnline -ExchangeEnvironmentName O365USGovGCCHigh -ShowBanner:$false -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null;break}
            "USGovDoD"     {Connect-ExchangeOnline -ExchangeEnvironmentName O365USGovDoD -ShowBanner:$false -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null;break}
            "Germany"      {Connect-ExchangeOnline -ExchangeEnvironmentName O365GermanyCloud -ShowBanner:$false -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null;break}
            "China"        {Connect-ExchangeOnline -ExchangeEnvironmentName O365China -ShowBanner:$false -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors -PSSessionOption $RPSProxySetting | Out-Null}
        }
       
        If((Get-PSSession | Where-Object {$_.ComputerName -like "outlook.office*" -or $_.ComputerName -like "webmail.apps.mil" -or $_.ComputerName -like "partner.outlook.cn"}).State -eq "Opened") { $Connect = $True } Else { $Connect = $False }

        # Run test command
        If(Get-Command "Get-OrganizationConfig") {
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
    If($Bypass -notcontains "SharePoint") {
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        $adminUrl = Get-SharePointAdminUrl -O365EnvironmentName $O365EnvironmentName
        Write-Host "$(Get-Date) Connecting to SharePoint Online (using $adminUrl)..."
        switch ($O365EnvironmentName) {
            "Commercial"   {Connect-SPOService -Url $adminUrl -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
            "USGovGCCHigh" {Connect-SPOService -Url $adminUrl -Region ITAR -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
            "USGovDoD"     {Connect-SPOService -Url $adminUrl -Region ITAR -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
            "Germany"      {Connect-SPOService -Url $adminUrl -Region Germany -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null;break}
            "China"        {Connect-SPOService -Url $adminUrl -Region China -ErrorAction:SilentlyContinue -ErrorVariable ConnectError | Out-Null}
        }

        # If no error, try test command
        If($ConnectError) { $Connect = $False; $Command = $False} Else { 
            $Connect = $True 
            Get-SPOTenant -ErrorAction SilentlyContinue -ErrorVariable CommandError | Out-Null
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
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        Write-Host "$(Get-Date) Connecting to Microsoft Teams..."
        $InitialDomain = (Get-AzureADTenantDetail | Select-Object -ExpandProperty VerifiedDomains | Where-Object { $_.Initial }).Name
        switch ($O365EnvironmentName) {
            "Commercial"   {Connect-MicrosoftTeams -TenantId $InitialDomain -ErrorVariable $ConnectError -ErrorAction:SilentlyContinue;break}
            "USGovGCCHigh" {Connect-MicrosoftTeams -TeamsEnvironmentName TeamsGCCH -TenantId $InitialDomain -ErrorVariable $ConnectError -ErrorAction:SilentlyContinue;break}
            "USGovDoD"     {Connect-MicrosoftTeams -TeamsEnvironmentName TeamsDOD -TenantId $InitialDomain -ErrorVariable $ConnectError -ErrorAction:SilentlyContinue;break}
            #"Germany"      {"Status of Teams in Germany cloud is unknown";break}
            "China"        {Write-Host "Teams is not available in 21Vianet offering";break}
            default        {Connect-MicrosoftTeams -TenantId $InitialDomain -ErrorVariable $ConnectError -ErrorAction:SilentlyContinue}
        }
        #Leaving a 'default' entry to catch Germany until status can be determined, attempting standard connection

    # Run test command that uses RPS
        If(Get-Command "Get-CsTenantFederationConfiguration") {
            If(Get-CsTenantFederationConfiguration) {
                $Command = $True
            } Else {
                $Command = $False
            }
        } Else {
            $Command = $False
        }

    # Check for connection after command test because RPS is not established until after a cmdlet that needs it is run
    If((Get-PSSession | Where-Object {$_.ComputerName -like "*teams.*"}).State -eq "Opened") { $Connect = $True } Else { $Connect = $False }

        $Connections += New-Object -TypeName PSObject -Property @{
            Name="Teams"
            Connected=$Connect
            ConnectErrors=$ConnectError
            TestCommand=$Command
            TestCommandErrors=$CommandError
        }
    }

    Return $Connections
}

Function Get-RequiredAppPermissions {
    param
    (
    $HasATPP2License,
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
        Resource="00000003-0000-0000-c000-000000000000" # Graph    
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="dc5007c0-2d7d-4c42-879c-2dab87571379"
        Name="IdentityRiskyUser.Read.All"
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="6e472fd1-ad78-48da-a0f0-97ab2c6b769e"
        Name="IdentityRiskEvent.Read.All"
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
        Name="DeviceManagementConfiguration.Read.All"
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="b0afded3-3588-46d8-8b3d-9842eff778da"
        Name="AuditLog.Read.All"
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="7ab1d382-f21e-4acd-a863-ba3e13f7da61"
        Name="Directory.Read.All"
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID="246dd0d5-5bd0-4def-940b-0421030a5b68"
        Name="Policy.Read.All"
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }

    #Defender API and threat investigations not currently available in sovereign clouds, only Commercial. Update if/as endpoints become available.
    $DefenderAvailable = $false
    switch ($O365EnvironmentName) {
        "Commercial"   {$DefenderAvailable=$true;break}
        "USGovGCCHigh" {$DefenderAvailable=$false;break}
        "USGovDoD"     {$DefenderAvailable=$false;break}
        "Germany"      {$DefenderAvailable=$false;break}
        "China"        {$DefenderAvailable=$false}
    }

    if ($HasATPP2License -eq $true -and $DefenderAvailable -eq $true) {
        $AppRoles += New-Object -TypeName PSObject -Property @{
            ID="a9790345-4595-42e4-971a-ccdc79f19b7c"
            Name="Incident.Read.All"
            Resource="8ee8fdad-f234-4243-8f3b-15c294843740" # Microsoft Threat Protection
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
                    Throw "$(Get-Date) An attempt to remove these from the PowerShell path was unsuccessful. You must remove them using Add/Remove Programs."
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

Function Get-SOAAzureADApp
{
    Param(
        [string]$O365EnvironmentName
    )

    # Determine if Azure AD Application Exists
    $AzureADApp = Get-AzureADApplication -Filter "displayName eq 'Office 365 Security Optimization Assessment'" | Where-Object {$_.ReplyUrls -Contains "https://security.optimization.assessment.local"}

    If(!$AzureADApp) 
    {
        if ($DoNotRemediate -eq $false) {
            Write-Host "$(Get-Date) Installing Azure AD Application..."
            $AzureADApp = Install-AzureADApp -O365EnvironmentName $O365EnvironmentName
            Write-Verbose "$(Get-Date) Get-SOAAzureADApp App $($AzureADApp.ObjectId)"
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
        $Bypass=@(),
        [Switch]$UseProxy,
        [Parameter(DontShow)][Switch]$AllowMultipleWindows,
        [Parameter(DontShow)][switch]$NoVersionCheck,
        [Parameter(DontShow)][switch]$AllowMultipleModuleVersions,
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
        [ValidateSet("Commercial", "USGovGCCHigh", "USGovDoD", "Germany", "China")][string]$O365EnvironmentName="Commercial",
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
        $AzureADAppCheck = $True
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
        Write-Host "$(Get-Date) The DoNotRemediate switch was used.  Any missing, outdated, or duplicate modules, as well as the registration and/or configuration of the Azure AD application will not be performed." -ForegroundColor Yellow
    }

    if ($NoVersionCheck) {
        Write-Host "$(Get-Date) NoVersionCheck switch was used. Skipping version check..."
    }
    else {    
        # Check for newer version
        Write-Host "$(Get-Date) Performing version check..."
        $VersionCheck = Invoke-SOAVersionCheck
        If($VersionCheck.NewerAvailable -eq $true)
        {
            Throw "Version $($VersionCheck.Gallery) of the SOA module has been released. Your version $($VersionCheck.Module) is out of date. Run Update-Module SOA."
        }
    }

    # Check administrator and multiple PowerShell windows
    If($(Get-IsAdministrator) -eq $False -and $ModuleCheck -eq $True -and $DoNotRemediate -eq $false) {
        Throw "PowerShell must be run as Administrator in order to allow for any changes when running Install-SOAPrerequisites"
    }
    If($AllowMultipleWindows) {
        Write-Important
        Write-Host "Allow multiple windows has been specified. This should not be used in general operation. Module remediation may fail!"
    } 
    Else 
    {
        If($(Get-PowerShellCount) -gt 1 -and $ModuleCheck -eq $True -and $DoNotRemediate -eq $false) {
            Throw "There are multiple PowerShell windows open. This can cause issues with PowerShell modules being loaded, blocking uninstallation and updates. Close all open PowerShell windows and start with a clean PowerShell window running as Administrator."
        }
    }

    # Check that only the AD module is installed on a standalone machine, and then exit the script
    If($ADModuleOnly) {
        Write-Host "$(Get-Date) ADModuleOnly switch was used. All other script functions are disabled. Only the on-premises AD module will be installed and then script will exit."

        $ModuleCheckResult = @(Get-ModuleStatus -ModuleName "ActiveDirectory")
        $ModuleCheckResult | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,Multiple,NewerAvailable

        If($ModuleCheckResult.InstalledVersion -ne $Null) {
            Write-Host "$(Get-Date) ActiveDirectory module is already installed"
        }
        Else {
            If($Remediate) {
                Write-Host "$(Get-Date) Installing AD module"
                Install-ADDSModule
            }

            Write-Host "$(Get-Date) Post-remediation prerequisites check..."
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

    Write-Host "#############################################################" -ForegroundColor Green
    Write-Host "# Office 365 Security Optimization Assessment Prerequisites #" -ForegroundColor Green
    Write-Host "#############################################################" -ForegroundColor Green
    Write-Host ""

    Write-Host "The purpose of this cmdlet (script) is to install and check the prerequisites for running the data collection"
    Write-Host "script for the Office 365 Security Optimization Assessment, a Microsoft Support proactive offering."
    Write-Host "At the conclusion of this cmdlet running successfully, a file named SOA-PreCheck.json will be generated."
    Write-Host "This file should be sent, prior to the first day of the engagement, to the engineer who will be delivering the assessment."
    Write-Host ""
    Write-Host "This cmdlet MUST be run on the workstation that will be used to perform the data collection on Day 1 of the assessment."
    Write-Host ""

    Write-Important

    Write-Host "This cmdlet makes changes on this workstation and in your Office 365 tenant (unless DoNotRemediate was used). The following will occur:" -ForegroundColor Green
    Write-Host "1. Update any existing PowerShell modules on this machine that are required for the assessment" -ForegroundColor Green
    Write-Host "2. Install any PowerShell modules on this machine that are required for the assessment" -ForegroundColor Green
    Write-Host "3. Install/register an Azure AD application in your tenant:" -ForegroundColor Green
    Write-Host "    -- The application name is 'Office 365 Security Optimization Assessment" -ForegroundColor Green
    Write-Host "    -- The application will not be visible to end users" -ForegroundColor Green
    Write-Host "    -- The application secret (password) will not be stored, is randomly generated, and is removed when this cmdlet completes." -ForegroundColor Green
    Write-Host "       (The application will not work without a secret. Do NOT remove the application until the conclusion of the engagement.)" -ForegroundColor Green
    Write-Host ""

    While($True) {
        $rhInput = Read-Host "Is this cmdlet being run on the machine that will be used for collection, are you aware of the potential changes above, and do you want to proceed (y/n)"
        if($rhInput -eq "n") {
            Throw "Run Install-SOAPrerequisites on the machine that will be performing the data collection."
        } elseif($rhInput -eq "y") {
            Write-Host ""
            break;
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

        # Determine if PowerShell gallery is installed
        If(!(Get-PSRepository -Name PSGallery -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue)) {
            Register-PSRepository -Default -InstallationPolicy Trusted | Out-Null
        }

        Invoke-ManualModuleCheck

        Write-Host "$(Get-Date) Checking modules..."

        $ModuleCheckResult = Invoke-SOAModuleCheck

        $Modules_OK = @($ModuleCheckResult | Where-Object {$_.Installed -eq $True -and $_.Multiple -eq $False -and $_.NewerAvailable -ne $true})
        $Modules_Error = @($ModuleCheckResult | Where-Object {$_.Installed -eq $False -or $_.Multiple -eq $True -or $_.NewerAvailable -eq $true -or $_.Conflict -eq $True})

        If($Modules_Error.Count -gt 0) {
            Write-Host "$(Get-Date) Modules with errors" -ForegroundColor Red
            $Modules_Error | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,Multiple,NewerAvailable

            # Fix modules with errors unless instructed not to
            if ($DoNotRemediate -eq $false){
                Invoke-ModuleFix $Modules_Error

                Write-Host "$(Get-Date) Post-remediation prerequisites check..."
                $ModuleCheckResult = Invoke-SOAModuleCheck
                $Modules_OK = @($ModuleCheckResult | Where-Object {$_.Installed -eq $True -and $_.Multiple -eq $False -and $_.NewerAvailable -ne $true})
                $Modules_Error = @($ModuleCheckResult | Where-Object {$_.Installed -eq $False -or $_.Multiple -eq $True -or $_.NewerAvailable -eq $true})
            }
            # Don't continue to check connections, still modules with errors
            If($Modules_Error.Count -gt 0) {
                #Ignore error modules if it is only multiple versions and allow multiples switch has been used
                if ($Modules_Error | Where-Object {$_.Installed -eq $true -and $_.NewerAvailable -eq $false -and $_.Multiple -eq $true -and $AllowMultipleModuleVersions -eq $true}) {
                    Write-Warning "$(Get-Date) A module has an error, but it is only because there are multiple versions installed, and the AllowMultipleModuleVersions switch is True, so continuing."
                }
                else {
                    Write-Important

                    Write-Host "$(Get-Date) The module check has errors. The connection check will not proceed until the module check has no errors." -ForegroundColor Red
                    $Modules_Error | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,Multiple,NewerAvailable
                    
                    if ($Modules_Error | Where-Object {$_.Multiple -eq $true}){
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
                    
                    Throw "$(Get-Date) The modules above must be remediated before continuing. Contact the delivery engineer for assistance, if needed."
                }
            }
        }
    }

    <#

        Generic checks

    #>

    # WinRM Basic Authentication
    $CheckResults += Invoke-WinRMBasicCheck

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
                "Commercial"   {$AADConnection = Connect-AzureAD | Out-Null;break}
                "USGovGCCHigh" {$AADConnection = Connect-AzureAD -AzureEnvironmentName AzureUSGovernment | Out-Null;break}
                "USGovDoD"     {$AADConnection = Connect-AzureAD -AzureEnvironmentName AzureUSGovernment | Out-Null;break}
                "Germany"      {$AADConnection = Connect-AzureAD -AzureEnvironmentName AzureGermanyCloud | Out-Null;break}
                "China"        {$AADConnection = Connect-AzureAD -AzureEnvironmentName AzureChinaCloud | Out-Null}
            }
        }

        $ATPLicensed = Get-LicenseStatus -LicenseType ATPP2
        Write-Verbose "$(Get-Date) Get-LicenseStatus ATPP2 License found: $ATPLicensed"
        $AppRoles = Get-RequiredAppPermissions -HasATPP2License ($ATPLicensed) -O365EnvironmentName $O365EnvironmentName

        Invoke-LoadAdal

        Write-Host "$(Get-Date) Checking Azure AD Application..."

        # Get the default MSOL domain
        $tenantdomain = (Get-AzureADDomain | Where-Object {$_.IsInitial -eq $true}).Name

        # Determine if Azure AD Application Exists and create if doesnt
        $AzureADApp = Get-SOAAzureADApp -O365EnvironmentName $O365EnvironmentName

        If($AzureADApp) 
        {

            # Pass the AAD app check
            $CheckResults += New-Object -Type PSObject -Property @{
                Check="AAD Application"
                Pass=$True
            }

            # Reset secret
            $clientsecret = Reset-AppSecret -App $AzureADApp

            $AppTest = Test-SOAApplication -App $AzureADApp -Secret $clientsecret -TenantDomain $tenantdomain -O365EnvironmentName $O365EnvironmentName -WriteHost
                
            # AAD App Permission - Perform remediation if specified
            If($AppTest.Permissions -eq $False -and $DoNotRemediate -eq $false)
            {
                # Set up the correct AAD App Permissions
                Write-Host "$(Get-Date) Remediating application permissions..."
                If((Set-AzureADAppPermission -App $AzureADApp -Roles $AppRoles -PerformConsent:$True -O365EnvironmentName $O365EnvironmentName) -eq $True) {
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
        $Modules_OK | Format-Table Module,InstalledVersion,GalleryVersion,Multiple,NewerAvailable
        
        If($Modules_Error.Count -gt 0) 
        {
            Write-Host "$(Get-Date) Modules with errors" -ForegroundColor Red
            $Modules_Error | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,Multiple,NewerAvailable

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

    Stop-Transcript
}
