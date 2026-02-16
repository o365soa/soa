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

function Exit-Script {
    Remove-Variable -Name subscribedSku -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name *Licensed -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name ModuleVersions -Scope Script -ErrorAction SilentlyContinue
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

function Get-CloudEnvironment {
    param (
        $UPN
    )

    $domain = $UPN.Split("@")[1]
    try {
        $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$domain/.well-known/openid-configuration"
    } catch {
        Write-Verbose "$(Get-Date) Get-CloudEnvironment: Error executing call to get cloud environment for $domain"
        Write-Verbose "$(Get-Date) Error: $($_.Exception.Message)"
        throw
    }

    if ($response.tenant_region_scope) {
        if ($response.tenant_region_sub_scope -eq 'GCC') {
            Write-Verbose "$(Get-Date) Get-CloudEnvironment: Environment for $domain is USGovGCC"
            return 'USGovGCC'
        }
        if ($response.tenant_region_sub_scope -eq 'DODCON') {
            Write-Verbose "$(Get-Date) Get-CloudEnvironment: Environment for $domain is USGovGCCHigh"
            return 'USGovGCCHigh'
        }
        if ($response.tenant_region_sub_scope -eq 'DOD') {
            Write-Verbose "$(Get-Date) Get-CloudEnvironment: Environment for $domain is USGovDoD"
            return 'USGovDoD'
        }
        if ($response.cloud_instance_name -eq 'partner.microsoftonline.cn') {
            Write-Verbose "$(Get-Date) Get-CloudEnvironment: Environment for $domain is China"
            return 'China'
        }
        Write-Verbose "$(Get-Date) Get-CloudEnvironment: Environment for $domain is Commercial"
        return 'Commercial'
    } else {
        throw
    }

}

function Get-InitialDomain {
    <#
        Used during connection tests for Graph SDK and SPO
    #>
    
    # Get the default OnMicrosoft domain. Because the SDK connection is still using a delegated call at this point, the application-based Graph function cannot be used
    if ($InitialDomain) {
        return $InitialDomain
    } else {
        $OrgData = (Invoke-MgGraphRequest GET "$GraphHost/v1.0/organization" -OutputType PSObject).Value
        return ($OrgData | Select-Object -ExpandProperty VerifiedDomains | Where-Object { $_.isInitial }).Name 
    }
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
        $tenantName = ((Get-InitialDomain) -split "\.")[0]
        
        switch ($CloudEnvironment) {
            "Commercial"   {$url = "https://" + $tenantName + "-admin.sharepoint.com";break}
            "USGovGCC"     {$url = "https://" + $tenantName + "-admin.sharepoint.com";break}
            "USGovGCCHigh" {$url = "https://" + $tenantName + "-admin.sharepoint.us";break}
            "USGovDoD"     {$url = "https://" + $tenantName + "-admin.dps.mil";break}
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
    $Response = Invoke-MgGraphRequest -Method POST -Uri "$GraphHost/v1.0/applications/$($App.Id)/addPassword" -body $Params

    Return $Response.SecretText
}
function Remove-SOAAppSecret {
    # Removes any client secrets associated with the application when the app is retrieved using Invoke-MgGraphRequest from the Microsoft.Graph.Authentication module
    param ()

    # Get application again from Entra to be sure it includes any added secrets
    $App = (Invoke-MgGraphRequest -Method GET -Uri "$GraphHost/v1.0/applications?`$filter=web/redirectUris/any(p:p eq 'https://security.optimization.assessment.local')&`$count=true" -Headers @{'ConsistencyLevel' = 'eventual'} -OutputType PSObject -ErrorAction SilentlyContinue).Value

    $secrets = $App.passwordCredentials
    $i = 0
    foreach ($secret in $secrets) {
        $i++
        if ($i -gt 1) {Start-Sleep -Seconds 1} # Sleep to avoid concurrency errors on subsequent secrets
        # Suppress errors in case a secret no longer exists
        try {
            Invoke-MgGraphRequest -Method POST -Uri "$GraphHost/v1.0/applications(appId=`'$($App.appId)`')/removePassword" -body (ConvertTo-Json -InputObject @{ 'keyId' = $secret.keyId }) #| Out-Null
        }
        catch {}
    }
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

        Invoke-MgGraphRequest -Method PATCH -Uri "$GraphHost/v1.0/applications/$($App.Id)" -Body ($Params | ConvertTo-Json -Depth 5)
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

    Write-Verbose "$(Get-Date) Invoke-AppPermissionCheck; App ID $($App.AppId); Role Count $($Roles.Count)"

    While($Counter -lt $MaxTime)
    {
        $Provisioned = $True
        # Refresh roles from Entra
        $rCounter = 1
        $appId = $app.Id
        while ($rCounter -le 5) {
            try {
                Write-Verbose "$(Get-Date) Getting application from Entra (attempt #$rCounter)"
                $App = Invoke-MgGraphRequest -Method GET -Uri "$GraphHost/v1.0/applications/$appId" -ErrorAction Stop
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
            Write-Verbose "$(Get-Date) Invoke-AppPermissionCheck; App ID $($app.Id); Role Count $($Roles.Count) OK"
            Break
        } 
        Else 
        {
            Write-Verbose "$(Get-Date) Invoke-AppPermissionCheck; App ID $($app.Id); Missing roles: $($Missing -Join ";")"
            Start-Sleep $SleepTime
            $Counter += $SleepTime
            Write-Verbose "$(Get-Date) Invoke-AppPermissionCheck loop - waiting for permissions on Entra application - Counter $Counter maxTime $MaxTime Missing $($Missing -join ' ')"
        }

    }

    Return $Provisioned

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
        'displayName' = 'Microsoft 365 Security Assessment'
        'SignInAudience' = 'AzureADMyOrg'
        'web' = @{
            'redirectUris' = @("https://security.optimization.assessment.local","https://o365soa.github.io/soa/")
        }
        'publicClient' = @{
            'redirectUris' = @("https://login.microsoftonline.com/common/oauth2/nativeclient","http://localhost")
        }
    }

    $EntraApp = Invoke-MgGraphRequest -Method POST -Uri "$GraphHost/v1.0/applications" -Body $Params

    # Set up the correct permissions
    Set-EntraAppPermission -App $EntraApp -PerformConsent:$True -CloudEnvironment $CloudEnvironment

    # Add service principal (enterprise app) as owner of its app registration
    $appSp = Get-SOAAppServicePrincipal -EntraApp $EntraApp
    if ($appSp) {
        if (Add-SOAAppOwner -NewOwnerObjectId $appSp.Id -EntraApp $EntraApp) {
            $script:appSelfOwner = $true
        } else {
            $script:appSelfOwner = $false
        }
    } else {
        $script:appSelfOwner = $false
    }
    
    # Return the newly created application
    return (Invoke-MgGraphRequest -Method GET -Uri "$GraphHost/v1.0/applications/$($EntraApp.Id)")
    
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
    $Arguments = @{}

    # Evaluate the ModuleVersion JSON file to determine if any versions should be excluded
    $MaxVersion = ($script:ModuleVersions | Where-Object {$_.ModuleName -eq $ModuleName}).MaximumVersion

    if ($MaxVersion) {
        Write-Verbose "A MaximumVersion of $MaxVersion was specified for $ModuleName. Only this version will be installed."

        # Splat the arguments when using Find-Module
        $Arguments = @{
            MaximumVersion = $MaxVersion
        }

        $InstalledModule = @(Get-Module -Name $ModuleName -ListAvailable | Where-Object {$_.Version -le $MaxVersion})
    } else {
        $InstalledModule = @(Get-Module -Name $ModuleName -ListAvailable)
    }

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

    $PSGalleryModule = @(Find-Module $ModuleName -ErrorAction:SilentlyContinue @Arguments)

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
        GalleryVersion=$(if ($MaxVersion) { "$GalleryVersion (*)" } else { $GalleryVersion })
        Installed=$Installed
        Conflict=$(if ($Installed -and $ConflictModule) { $True } else { $False })
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
    $resources = (Get-Content -Path (Join-Path -Path $MyInvocation.MyCommand.Module.ModuleBase -ChildPath resources.json) | ConvertFrom-Json)
    if ($LicenseType -eq 'Teams') {
        $targetSkus = ($resources.Sku.$LicenseType.Default + $resources.Sku.$LicenseType.Custom) | Where-Object {$_ -match "[a-z]+"}
    } elseif ($LicenseType -eq 'AADP1' -or $LicenseType -eq 'AADP2' -or $LicenseType -eq 'ATPP2' -or $LicenseType -eq 'MDE' -or $LicenseType -eq 'MDI') {
        $targetSkus = $resources.Sku.$LicenseType | Where-Object {$_ -match "[a-z]+"}
    } else {
        Write-Error "$(Get-Date) Get-LicenseStatus: $LicenseType`: Invalid "
        return $false
    }
    
    #Get SKUs only if not already retrieved
    if (-not $subscribedSku) {
        Write-Verbose "$(Get-Date) Get-LicenseStatus: Getting subscribed SKUs"
        $script:subscribedSku = Invoke-MgGraphRequest -Method GET -Uri "$GraphHost/v1.0/subscribedSkus" -OutputType PSObject
    }
    if ($LicenseType -eq "Teams") {
        # Teams license check is handled differently because it needs to be an exact match
        if ($HasTeamsLicense) {
            Write-Verbose "$(Get-Date) Get-LicenseStatus HasTeamsLicense switch used, skipping license check and returning True"
            Write-Verbose "$(Get-Date) Get-LicenseStatus $LicenseType`: True "
            return $true
        }
        foreach ($tSku in $targetSkus) {
            foreach ($sku in $subscribedSku.value) {
                if ($sku.prepaidUnits.enabled -gt 0 -or $sku.prepaidUnits.warning -gt 0 -and $sku.skuPartNumber -eq $tSku) {
                    Write-Verbose "$(Get-Date) Get-LicenseStatus $LicenseType`: True Matched $($sku.skuPartNumber)"
                    return $true
                }
            }
        }
    } else {
        if ($LicenseType -eq "AADP1" -and $HasEntraP1License) {
            Write-Verbose "$(Get-Date) Get-LicenseStatus HasEntraP1License switch used, skipping license check and returning True"
            Write-Verbose "$(Get-Date) Get-LicenseStatus $LicenseType`: True "
            return $true
        } elseif ($LicenseType -eq "AADP2" -and $HasEntraP2License) {
            Write-Verbose "$(Get-Date) Get-LicenseStatus HasEntraP2License switch used, skipping license check and returning True"
            Write-Verbose "$(Get-Date) Get-LicenseStatus $LicenseType`: True "
            return $true
        } elseif ($LicenseType -eq "ATPP2" -and $HasMDOP2License) {
            Write-Verbose "$(Get-Date) Get-LicenseStatus HasMDOP2License switch used, skipping license check and returning True"
            Write-Verbose "$(Get-Date) Get-LicenseStatus: $LicenseType`: True "
            return $true
        } elseif ($LicenseType -eq "MDE" -and $HasMDELicense) {
            Write-Verbose "$(Get-Date) Get-LicenseStatus HasMDELicense switch used, skipping license check and returning True"
            Write-Verbose "$(Get-Date) Get-LicenseStatus: $LicenseType`: True "
            return $true
        } elseif ($LicenseType -eq "MDI" -and $HasMDILicense) {
            Write-Verbose "$(Get-Date) Get-LicenseStatus HasMDILicense switch used, skipping license check and returning True"
            Write-Verbose "$(Get-Date) Get-LicenseStatus: $LicenseType`: True "
            return $true
        }
        foreach ($tSku in $targetSkus) {
            foreach ($sku in $subscribedSku.value) {
                if ($sku.prepaidUnits.enabled -gt 0 -or $sku.prepaidUnits.warning -gt 0 -and $sku.skuPartNumber -match $tSku) {
                    Write-Verbose "$(Get-Date) Get-LicenseStatus: $LicenseType`: True Matched $($sku.skuPartNumber)"
                    return $true
                }
            }
        }
    }
    Write-Verbose "$(Get-Date) Get-LicenseStatus: $LicenseType`: False "
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

    $InstallArguments = @{}

    # Install the module from PSGallery specifying Force
    # AllowClobber allows Teams module to be installed when SfBO module is installed/loaded
    if (Get-IsAdministrator) {
        $InstallArguments = @{
            Scope = "AllUsers"
        }
    }
    else {
        $InstallArguments = @{
            Scope = "CurrentUser"
        }
    }

    $MaxVersion = ($script:ModuleVersions | Where-Object {$_.ModuleName -eq $Module}).MaximumVersion
    if ($MaxVersion) {
        Write-Verbose "A MaximumVersion of $MaxVersion was specified for $Module. Only this version will be installed from the PSGallery."

        $InstallArguments.Add("RequiredVersion",$MaxVersion)
    }

    Install-Module $Module -Force -AllowClobber @InstallArguments

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

    $RequiredModules = @()
    
    # Conflict modules are modules which their presence causes issues
    $ConflictModules = @()

    # Bypass checks
    if ($Bypass -notcontains "SPO") { $RequiredModules += "Microsoft.Online.SharePoint.PowerShell" }
    if ($Bypass -notcontains "Teams") {$RequiredModules += "MicrosoftTeams"}
    if (($Bypass -notcontains "EXO" -or $Bypass -notcontains "SCC")) {$RequiredModules += "ExchangeOnlineManagement"}
    if ($Bypass -notcontains "PP") {$RequiredModules += "Microsoft.PowerApps.Administration.PowerShell"}
    if ($Bypass -notcontains "Graph") {$RequiredModules += "Microsoft.Graph.Authentication"}
    if ($Bypass -notcontains "ActiveDirectory") { $RequiredModules += "ActiveDirectory" }

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
        # Evaluate the ModuleVersion JSON file to determine if any versions should be excluded
        $MaxVersion = ($script:ModuleVersions | Where-Object {$_.ModuleName -eq $ModuleName}).MaximumVersion

        if ($MaxVersion) {
            Write-Verbose "A MaximumVersion of $MaxVersion was specified for $ModuleName. Only this version will be imported."

            $highestVersion = (Get-Module -Name $ModuleName -ListAvailable | Where-Object {$_.Version -le $MaxVersion} | Sort-Object -Property Version -Descending | Select-Object -First 1).Version.ToString()
        } else {
            $highestVersion = (Get-Module -Name $ModuleName -ListAvailable | Sort-Object -Property Version -Descending | Select-Object -First 1).Version.ToString()
        }

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

        # Check that Graph modules have dependent module (Authentication) loaded with the same version and throw an error if they are not the same version. Only check for non-Auth modules since they will have a RequiredModules statement in the manifest to load the Auth module
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

function Connect-ToSCC {
    param (
        [switch]$NoWAM
    )

    # Multiple loaded versions are listed in reverse order of precedence
    $exoModuleVersion = (Get-Module -Name ExchangeOnlineManagement | Select-Object -Last 1).Version
    # Commented Jan 3, 2025 because don't know that the connection removal is necessary anymore
    # Removing existing connections in case any use a prefix
    # Get-ConnectionInformation | Where-Object {$_.ConnectionUri -like "*protection.o*" -or $_.ConnectionUri -like "*protection.partner.o*"} | ForEach-Object {Disconnect-ExchangeOnline -ConnectionId $_.ConnectionId -Confirm:$false}

    # Build a hashtable of options and then splat them when connecting
    $IPPSArguments = @{}

    # Regional connection parameters
    switch ($CloudEnvironment) {
        "USGovGCCHigh" {
            $IPPSArguments = @{
                ConnectionUri = "https://ps.compliance.protection.office365.us/PowerShell-LiveID"
                AzureADAuthorizationEndPointUri = "https://login.microsoftonline.us/common"
            }
        }
        "USGovDoD" {
            $IPPSArguments = @{
                ConnectionUri = "https://l5.ps.compliance.protection.office365.us/PowerShell-LiveID"
                AzureADAuthorizationEndPointUri = "https://login.microsoftonline.us/common"
            }
        }
        "China" {
            $IPPSArguments = @{
                ConnectionUri = "https://ps.compliance.protection.partner.outlook.cn/PowerShell-LiveID"
                AzureADAuthorizationEndPointUri = "https://login.partner.microsoftonline.cn/common"
            }
        }
    }

    if (!$NoAdminUPN) {
        $IPPSArguments.Add("UserPrincipalName", $AdminUPN)
    }

    # DisableWAM parameter not available prior to version 3.7.2
    if ($NoWAM -and !($exoModuleVersion -lt [version]"3.7.2")) {
        $IPPSArguments.Add("DisableWAM", $NoWAM)
    }

    $IPPSArguments.GetEnumerator() | ForEach-Object {
        Write-Verbose "$($_.Key) : $($_.Value)"
    }

    Connect-IPPSSession -PSSessionOption $RPSProxySetting -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -ErrorVariable ConnectError -ShowBanner:$False @IPPSArguments | Out-Null

    return $ConnectError
}

function Connect-ToExchange {
    param (
        [switch]$NoWAM
    )
    # Multiple loaded versions are listed in reverse order of precedence
    $exoModuleVersion = (Get-Module -Name ExchangeOnlineManagement | Select-Object -Last 1).Version

    $EXOArguments = @{}

    switch ($CloudEnvironment) {
        "USGovGCCHigh" {
            $EXOArguments = @{
                ExchangeEnvironmentName = "O365USGovGCCHigh"
            }
        }
        "USGovDoD" {
            $EXOArguments = @{
                ExchangeEnvironmentName = "O365USGovDoD"
            }
        }
        "China" {
            $EXOArguments = @{
                ExchangeEnvironmentName = "O365China"
            }
        }
    }

    if (!$NoAdminUPN) {
        $EXOArguments.Add("UserPrincipalName", $AdminUPN)
    }

    # DisableWAM parameter not available prior to version 3.7.2
    if ($NoWAM -and !($exoModuleVersion -lt [version]"3.7.2")) {
        $EXOArguments.Add("DisableWAM", $NoWAM)
    }

    $EXOArguments.GetEnumerator() | ForEach-Object {
        Write-Verbose "$($_.Key) : $($_.Value)"
    }

    Connect-ExchangeOnline -PSSessionOption $RPSProxySetting -ShowBanner:$false -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -ErrorVariable ConnectError @EXOArguments | Out-Null

    return $ConnectError
    
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
    if ($Bypass -notcontains 'SCC' -or $Bypass -notcontains 'EXO') {
        # Force EXO module to be loaded before the Graph SDK to avoid conflicts in authentication libraries
        Import-PSModule -ModuleName ExchangeOnlineManagement -Implicit:$UseImplicitLoading
    }
    # Teams and SPO connections are dependent on Graph connection to determine Teams service plans and to get initial domain
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
        Import-PSModule -ModuleName Microsoft.Graph.Authentication -Implicit:$UseImplicitLoading
        switch ($CloudEnvironment) {
            "Commercial"   {$cloud = 'Global'}
            "USGovGCC"     {$cloud = 'Global'}
            "USGovGCCHigh" {$cloud = 'USGov'}
            "USGovDoD"     {$cloud = 'USGovDoD'}
            "China"        {$cloud = 'China'}
        }
        $ConnContext = (Get-MgContext).Scopes
        if (($ConnContext -notcontains 'Application.ReadWrite.All' -and $PromptForApplicationSecret -eq $False) -or ($ConnContext -notcontains 'Application.Read.All' -and $PromptForApplicationSecret -eq $True) -or ($ConnContext -notcontains 'Organization.Read.All' -and $ConnContext -notcontains 'Directory.Read.All')) {
            Write-Host "$(Get-Date) Connecting to Microsoft Graph (with delegated authentication)..."
            if ($null -ne (Get-MgContext)){Disconnect-MgGraph | Out-Null}
            $connCount = 0
            $connLimit = 5
            do {
                try {
                    $connCount++
                    Write-Verbose "$(Get-Date) Test-Connections: Graph Delegated connection attempt #$connCount"
                    # User.Read is sufficient for using the organization API to get the domain for the Teams/SPO connections
                    # Using Organization.Read.All because that is the least-common scope for getting licenses in the app check

                    if ($CloudEnvironment -eq "China") {
                        # Connections to 21Vianet must have provided the ClientID and Tenant manually
                        if (-not $GraphClientId -or -not $InitialDomain ) {
                            Exit-Script
                            throw "$(Get-Date) Connections to Graph in 21Vianet require the application ID (client ID) and tenant name (initial domain) be manually provided. Use both `-GraphClientId` and `-InitialDomain` parameters to provide them. For more information, see https://github.com/o365soa/soa."
                        }
                        Connect-MgGraph -Scopes 'Application.ReadWrite.All','Organization.Read.All' -Environment $cloud -ContextScope "Process" -ClientId $GraphClientId -Tenant $InitialDomain -NoWelcome -ErrorVariable ConnectError| Out-Null
                    } elseif ($PromptForApplicationSecret) {
                        # Request read-only permissions to Graph if manually providing the client secret
                        Connect-MgGraph -Scopes 'Application.Read.All','Organization.Read.All' -Environment $cloud -ContextScope "Process" -NoWelcome -ErrorVariable ConnectError | Out-Null
                    } else {
                        Connect-MgGraph -Scopes 'Application.ReadWrite.All','Organization.Read.All' -Environment $cloud -ContextScope "Process" -NoWelcome -ErrorVariable ConnectError | Out-Null
                    }
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
        } else {
            Write-Host "$(Get-Date) Connecting to Microsoft Graph (with delegated authentication)..." -NoNewline
            Write-Host " Already connected (Run Disconnect-MgGraph if you want to reconnect to Graph)" -ForegroundColor Green
            $Connect = $True
            $GraphSDKConnected = $true
        }
        if ($Connect -eq $true) {
            $org = (Invoke-MgGraphRequest -Method GET -Uri "$GraphHost/v1.0/organization" -OutputType PSObject -ErrorAction SilentlyContinue -ErrorVariable CommandError).Value
            if ($org.id) {$Command = $true} else {$Command = $false}
        }

        $Connections += New-Object -TypeName PSObject -Property @{
            Name="GraphSDK"
            Connected=$Connect
            ConnectErrors=$ConnectError.Exception.Message
            TestCommand=$Command
            TestCommandErrors=$CommandError.Exception.Message
        }
    }


    <#
    
        SCC
    
    #>

    If($Bypass -notcontains "SCC") {
        # Reset vars
        $connectResponse = $null; $Connect = $null; $ConnectError = $null; $Command = $null; $CommandError = $null

        Write-Host "$(Get-Date) Connecting to SCC..."
        if ($DisableWAM) {
            $sccWamDisabled = $true
            $connectResponse = Connect-ToSCC -NoWAM:$true
        } else {
            $connectResponse = Connect-ToSCC -NoWAM:$false
        }
        
        # Check for WAM error if not connected
        if (-not((Get-ConnectionInformation | Where-Object {$_.ConnectionUri -like "*protection.o*" -or $_.ConnectionUri -like "*protection.partner.o*"}).State -eq "Connected") -and $connectResponse.Exception.Message -like "*Unknown Status: Unexpected*") {
            Write-Warning -Message "$(Get-Date) Possible Web Authentication Manager (WAM) error occurred. Trying again without WAM."
            $sccWamDisabled = $true
            $connectResponse = Connect-ToSCC -NoWAM:$true
        }

        if ((Get-ConnectionInformation | Where-Object {$_.ConnectionUri -like "*protection.o*" -or $_.ConnectionUri -like "*protection.partner.o*"}).State -eq "Connected") {
            $Connect = $True
        } else {
            $Connect = $False
            $connectionError = ($connectResponse | Select-Object -Last 1).Exception | Select-Object -ExpandProperty Message
        }

        # Has test command been imported. Not actually running it
        # Cmdlet available to any user
        if ($Connect -eq $true) {
            if (Get-Command -Name Get-Recipient -ErrorAction SilentlyContinue -ErrorVariable CommandError) {
                $Command = $True
            } else {
                $Command = $False
            }
        }

        $Connections += New-Object -TypeName PSObject -Property @{
            Name="SCC"
            Connected=$Connect
            ConnectErrors=$connectionError
            TestCommand=$Command
            TestCommandErrors=$CommandError.Exception.Message
        }
    }

    <#
    
        Exchange
    
    #>
    If($Bypass -notcontains "EXO") {
        # Reset vars
        $connectResponse = $null; $Connect = $null; $ConnectError = $null; $Command = $null; $CommandError = $null

        Write-Host "$(Get-Date) Connecting to Exchange..."
        if ($sccWamDisabled) { # WAM may have been disabled for SCC connection, so skip trying with WAM for EXO
            $connectResponse = Connect-ToExchange -NoWAM:$true
        } else {
            $connectResponse = Connect-ToExchange -NoWAM:$false
            # Check for WAM error if not connected
            if (-not((Get-ConnectionInformation | Where-Object {$_.ConnectionUri -like "*outlook.office*" -or $_.ConnectionUri -like "*webmail.apps.mil*" -or $_.ConnectionUri -like "*partner.outlook.cn*"}).TokenStatus -eq "Active") -and $connectResponse.Exception.Message -like "*Unknown Status: Unexpected*") {
                Write-Warning -Message "$(Get-Date) Possible Web Authentication Manager (WAM) error occurred. Trying again without WAM."
                $connectResponse = Connect-ToExchange -NoWAM:$true
            }
        }
        
        if ((Get-ConnectionInformation | Where-Object {$_.ConnectionUri -like "*outlook.office*" -or $_.ConnectionUri -like "*webmail.apps.mil*" -or $_.ConnectionUri -like "*partner.outlook.cn*"}).TokenStatus -eq "Active") {
            $Connect = $True
        } else {
            $Connect = $False
            $ConnectError = ($connectResponse | Select-Object -Last 1).Exception | Select-Object -ExpandProperty Message
        }

        # Has test command been imported. Not actually running it
        # Cmdlet available to any user
        if ($Connect -eq $true) {
            if (Get-Command -Name Get-Mailbox -ErrorAction SilentlyContinue -ErrorVariable CommandError) {
                $Command = $True
            } else {
                $Command = $False
            }
        }
    
        $Connections += New-Object -TypeName PSObject -Property @{
            Name="Exchange"
            Connected=$Connect
            ConnectErrors=$ConnectError
            TestCommand=$Command
            TestCommandErrors=$CommandError.Exception.Message
        }
    }

    <#
        SharePoint
    
    #>
    If($Bypass -notcontains "SPO") {
        Import-PSModule -ModuleName Microsoft.Online.SharePoint.PowerShell -Implicit:$UseImplicitLoading
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        # Connect only if SPO admin domain provided or if not provided but Graph SDK is connected
        if ($SPOAdminDomain -or (-not $SPOAdminDomain -and $GraphSDKConnected -eq $true)) {
            $adminUrl = Get-SharePointAdminUrl -CloudEnvironment $CloudEnvironment
            Write-Host "$(Get-Date) Connecting to SharePoint Online (using $adminUrl)..."
            # Using the Credential parameter with a username will prompt for Basic auth creds
            switch ($CloudEnvironment) {
                "Commercial"   {Connect-SPOService -Url $adminUrl -ErrorAction SilentlyContinue -ErrorVariable ConnectError | Out-Null}
                "USGovGCC"     {Connect-SPOService -Url $adminUrl -ErrorAction SilentlyContinue -ErrorVariable ConnectError | Out-Null}
                "USGovGCCHigh" {Connect-SPOService -Url $adminUrl -Region ITAR -ErrorAction SilentlyContinue -ErrorVariable ConnectError | Out-Null}
                "USGovDoD"     {Connect-SPOService -Url $adminUrl -Region ITAR -ErrorAction SilentlyContinue -ErrorVariable ConnectError | Out-Null}
                "China"        {Connect-SPOService -Url $adminUrl -Region China -ErrorAction SilentlyContinue -ErrorVariable ConnectError | Out-Null}
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
                ConnectErrors=$ConnectError.Exception.Message
                TestCommand=$Command
                TestCommandErrors=$CommandError.Exception.Message
            }
        
        }
        
    }
    
    <#
    
        Microsoft Teams
    
    #>
    if ($Bypass -notcontains "Teams") {
        # Connect to Teams only if a tenant SKU includes Teams service plan
        if ($GraphSDKConnected -eq $true) {
            $TeamsLicensed = (Get-LicenseStatus -LicenseType Teams)
        }
        if ($TeamsLicensed -eq $true) {
            Import-PSModule -ModuleName MicrosoftTeams -Implicit:$UseImplicitLoading
            # Reset vars
            $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

            Write-Host "$(Get-Date) Connecting to Microsoft Teams..."
            # Although the connection cmdlet supports providing an account ID, if used it will force the user to [re-]authenticate rather than presenting the account picker
            switch ($CloudEnvironment) {
                "Commercial"    {try {Connect-MicrosoftTeams} catch {New-Variable -Name ConnectError -Value $true}}
                "USGovGCC"      {try {Connect-MicrosoftTeams} catch {New-Variable -Name ConnectError -Value $true}}
                "USGovGCCHigh"  {try {Connect-MicrosoftTeams -TeamsEnvironmentName TeamsGCCH } catch {New-Variable -Name ConnectError -Value $true}}
                "USGovDoD"      {try {Connect-MicrosoftTeams -TeamsEnvironmentName TeamsDOD } catch {New-Variable -Name ConnectError -Value $true}}
                "China"         {try {Connect-MicrosoftTeams -TeamsEnvironmentName TeamsChina } catch {New-Variable -Name ConnectError -Value $true}}
            }

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
                ConnectErrors=$ConnectError.Exception.Message
                TestCommand=$Command
                TestCommandErrors=$CommandError.Exception.Message
            }
        }
    }

    <#
    
        Power Apps
    
    #>
    If($Bypass -notcontains 'PP') {

        Import-PSModule -ModuleName Microsoft.PowerApps.Administration.PowerShell -Implicit:$UseImplicitLoading
        # Reset vars
        $Connect = $null; $ConnectError = $Null; $Command = $null; $CommandError = $Null

        Write-Host "$(Get-Date) Connecting to Power Apps..."
        if ($NoAdminUPN) {
            switch ($CloudEnvironment) {
                "Commercial"   {try{Add-PowerAppsAccount | Out-Null}catch{$ConnectError=$_}}
                "USGovGCC"     {try{Add-PowerAppsAccount -Endpoint usgov | Out-Null}catch{$ConnectError=$_}}
                "USGovGCCHigh" {try{Add-PowerAppsAccount -Endpoint usgovhigh | Out-Null}catch{$ConnectError=$_}}
                "USGovDoD"     {try{Add-PowerAppsAccount -Endpoint dod | Out-Null}catch{$ConnectError=$_}}
                "China"        {try{Add-PowerAppsAccount -Endpoint china | Out-Null}catch{$ConnectError=$_}}
            }
        } else {
            switch ($CloudEnvironment) {
                "Commercial"   {try{Add-PowerAppsAccount -UserName $AdminUPN | Out-Null}catch{$ConnectError=$_}}
                "USGovGCC"     {try{Add-PowerAppsAccount -Endpoint usgov -UserName $AdminUPN | Out-Null}catch{$ConnectError=$_}}
                "USGovGCCHigh" {try{Add-PowerAppsAccount -Endpoint usgovhigh -UserName $AdminUPN | Out-Null}catch{$ConnectError=$_}}
                "USGovDoD"     {try{Add-PowerAppsAccount -Endpoint dod -UserName $AdminUPN | Out-Null}catch{$ConnectError=$_}}
                "China"        {try{Add-PowerAppsAccount -Endpoint china -UserName $AdminUPN | Out-Null}catch{$ConnectError=$_}}
            }
        }

        # If no error, try test command
        if ($ConnectError) { $Connect = $False } Else { 
            $Connect = $True 
            # Check if data is returned
            # Ensure that the correct module is used as Get-DlpPolicy also exists within the Exchange module
            $cmdResult = Microsoft.PowerApps.Administration.PowerShell\Get-DlpPolicy -ErrorAction SilentlyContinue -ErrorVariable CommandError
            if ($CommandError -or -not $cmdResult) {
                # Cmdlet may not return data if no PA license assigned or user has not been to PPAC before
                Write-Warning -Message "No data was returned when running the test command. This can occur if the admin has never used the Power Platform Admin Center (PPAC). Please go to https://aka.ms/ppac and sign in as the Global administrator or Dynamics 365 administrator account you used to connect to Power Platform in PowerShell.  Then return here to continue."
                Read-Host -Prompt "Press Enter after you have navigated to PPAC and signed in with the adminstrator account used above to connect to Power Platform in PowerShell."
                $cmdResult = Microsoft.PowerApps.Administration.PowerShell\Get-DlpPolicy -ErrorAction SilentlyContinue -ErrorVariable CommandError
                if ($CommandError -or -not $cmdResult) {
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
            ConnectErrors=$ConnectError.Exception.Message
            TestCommand=$Command
            TestCommandErrors=$CommandError.Exception.Message
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
    if ($CloudEnvironment -ne "China") {
        $AppRoles += New-Object -TypeName PSObject -Property @{
            ID="6e472fd1-ad78-48da-a0f0-97ab2c6b769e"
            Name="IdentityRiskEvent.Read.All"
            Type='Role'
            Resource="00000003-0000-0000-c000-000000000000" # Graph
        }
    }

    switch ($CloudEnvironment) {
        "China" {$GUID = "be6befbd-4448-4fb0-bda5-5dc989bd62c4";break}
        default {$GUID = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"}
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID=$GUID
        Name="DeviceManagementConfiguration.Read.All"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }

    switch ($CloudEnvironment) {
        "China" {$GUID = "c11814fe-adc9-435b-8b25-9e186dcf7606";break}
        default {$GUID = "b0afded3-3588-46d8-8b3d-9842eff778da"}
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID=$GUID
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

    switch ($CloudEnvironment) {
        "China" {$GUID = "9950d8b9-ffec-4dd5-9c9e-19542b393956";break}
        default {$GUID = "246dd0d5-5bd0-4def-940b-0421030a5b68"}
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID=$GUID
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

    switch ($CloudEnvironment) {
        "China" {$GUID = "47d70536-eeb5-4b19-b059-f44e0f475f33";break}
        default {$GUID = "c7fbd983-d9aa-4fa7-84b8-17382c103bc4"}
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID=$GUID
        Name="RoleManagement.Read.All"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }

    switch ($CloudEnvironment) {
        "China" {$GUID = "6f135ef2-d208-48f4-b390-7893518e6950";break}
        default {$GUID = "01e37dc9-c035-40bd-b438-b2879c4870a6"}
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID=$GUID
        Name="PrivilegedAccess.Read.AzureADGroup"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }

    switch ($CloudEnvironment) {
        "China" {$GUID = "d90f9f4f-4a37-4b18-8d8b-d774cd8fd2d1";break}
        default {$GUID = "18a4783c-866b-4cc7-a460-3d5e5662c884"}
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID=$GUID
        Name="Application.ReadWrite.OwnedBy"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }

    switch ($CloudEnvironment) {
        "USGovGCCHigh" {$GUID = "47c980b8-449c-4b30-99e6-aeb22a11a023"}
        "USGovDoD"     {$GUID = "47c980b8-449c-4b30-99e6-aeb22a11a023"}
        "China"        {$GUID = "4cd4e808-f9db-48e3-9455-51ed99ea5ebe"}
        default        {$GUID = "bb70e231-92dc-4729-aff5-697b3f04be95"}
    }
    $AppRoles += New-Object -TypeName PSObject -Property @{
        ID=$GUID
        Name="OnPremDirectorySynchronization.Read.All"
        Type='Role'
        Resource="00000003-0000-0000-c000-000000000000" # Graph
    }

    switch ($CloudEnvironment) {
        "China"        {$AlertsAvailable=$false}
        default        {$AlertsAvailable=$true}
    }
    if ($AlertsAvailable -eq $true) {
        Write-Verbose "Role for Alerts will be included in app"
        switch ($CloudEnvironment) {
            "USGovGCCHigh" {$GUID = "64c33fcb-e6aa-490d-bed5-6016a9ef8f6d"}
            "USGovDoD"     {$GUID = "64c33fcb-e6aa-490d-bed5-6016a9ef8f6d"}
            default        {$GUID = "472e4a4d-bb4a-4026-98d1-0b0d74cb74a5"}
        }
        $AppRoles += New-Object -TypeName PSObject -Property @{
            ID=$GUID
            Name="SecurityAlert.Read.All"
            Type='Role'
            Resource="00000003-0000-0000-c000-000000000000" # Graph
        }
    }

    $MDEAvailable = $false
    switch ($CloudEnvironment) {
        "Commercial"   {$MDEAvailable=$true;$THId="dd98c7f5-2d42-42d3-a0e4-633161547251";break}
        "USGovGCC"     {$MDEAvailable=$true;$THId="dd98c7f5-2d42-42d3-a0e4-633161547251";break}
        "USGovGCCHigh" {$MDEAvailable=$true;$THId="5f804853-e3b1-447b-9a8b-6d3e1257c72a";break}
        "USGovDoD"     {$MDEAvailable=$true;$THId="5f804853-e3b1-447b-9a8b-6d3e1257c72a";break}
        "China"        {$MDEAvailable=$false;$THId="dd98c7f5-2d42-42d3-a0e4-633161547251"}
    }
    if (($HasMDELicense -eq $true -and $MDEAvailable -eq $true) -or $HasATPP2License -eq $true) {
        Write-Verbose "Role for Advanced Hunting will be included in app"
        $AppRoles += New-Object -TypeName PSObject -Property @{
            ID=$THId
            Name="ThreatHunting.Read.All"
            Type='Role'
            Resource="00000003-0000-0000-c000-000000000000" # Graph
        }
    }

    $MDIAvailable = $false
    switch ($CloudEnvironment) {
        "Commercial"   {$MDIAvailable=$true;break}
        "USGovGCC"     {$MDIAvailable=$true;break}
        "USGovGCCHigh" {$MDIAvailable=$true;break}
        "USGovDoD"     {$MDIAvailable=$true;break}
        "China"        {$MDIAvailable=$false}
    }
    if ($HasMDILicense -eq $true -and $MDIAvailable -eq $true) {
        Write-Verbose "Roles for Defender for Identity will be included in app"
        $AppRoles += New-Object -TypeName PSObject -Property @{
            ID="f8dcd971-5d83-4e1e-aa95-ef44611ad351"
            Name="SecurityIdentitiesHealth.Read.All"
            Type='Role'
            Resource="00000003-0000-0000-c000-000000000000" # Graph
        }
        $AppRoles += New-Object -TypeName PSObject -Property @{
            ID="bf394140-e372-4bf9-a898-299cfc7564e5"
            Name="SecurityEvents.Read.All"
            Type='Role'
            Resource="00000003-0000-0000-c000-000000000000" # Graph
        }
        $AppRoles += New-Object -TypeName PSObject -Property @{
            ID="5f0ffea2-f474-4cf2-9834-61cda2bcea5c"
            Name="SecurityIdentitiesSensors.Read.All"
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
    $EntraApp = (Invoke-MgGraphRequest -Method GET -Uri "$GraphHost/v1.0/applications?`$filter=web/redirectUris/any(p:p eq 'https://security.optimization.assessment.local')&`$count=true" -Headers @{'ConsistencyLevel' = 'eventual'} -OutputType PSObject).Value

    if ($EntraApp -and $RemoveExistingEntraApp -and $DoNotRemediate -eq $false) {
        Write-Host "$(Get-Date) Deleting existing Microsoft Entra application..."
        try {
            Invoke-MgGraphRequest -Method DELETE -Uri "$GraphHost/v1.0/applications/$($EntraApp.Id)"
            $EntraApp = $null
        }
        catch {
            Write-Warning "$(Get-Date) Unable to delete existing Microsoft Entra app registration. Please remove it manually."
        }
    }

    if (!$EntraApp) {
        if ($DoNotRemediate -eq $false) {
            Write-Host "$(Get-Date) Creating Microsoft Entra app registration..."
            $EntraApp = Install-EntraApp -CloudEnvironment $CloudEnvironment
            Write-Verbose "$(Get-Date) Get-SOAEntraApp App $($EntraApp.Id)"
        }
    }
    else {
        # Check whether the application name should be updated
        if ($EntraApp.displayName -ne 'Microsoft 365 Security Assessment') {
            Write-Verbose "$(Get-Date) Renaming the display name of the Microsoft Entra application..."
            $Body = @{'displayName' = 'Microsoft 365 Security Assessment'}
            Invoke-MgGraphRequest -Method PATCH -Uri "$GraphHost/v1.0/applications/$($EntraApp.Id)" -Body $Body
        }

        # Check if public client URI is set
        $pcRUrl = @('https://login.microsoftonline.com/common/oauth2/nativeclient','http://localhost')
        if ($EntraApp.PublicClient.RedirectUris -notcontains $pcRUrl) {
            if ($DoNotRemediate -eq $false){
                # Set as public client to be able to collect from Dynamics with delegated scope
                Write-Verbose "$(Get-Date) Setting Microsoft Entra application public client redirect URI..."
                $Params = @{
                    'publicClient' = @{
                        'redirectUris' = $pcRUrl
                    }
                }
                Invoke-MgGraphRequest -Method PATCH -Uri "$GraphHost/v1.0/applications/$($EntraApp.Id)" -Body $Params
                
                # Get app again so public client is set for checking DoNotRemediate in calling function
                $EntraApp = (Invoke-MgGraphRequest -Method GET -Uri "$GraphHost/v1.0/applications?`$filter=web/redirectUris/any(p:p eq 'https://security.optimization.assessment.local')&`$count=true" -Headers @{'ConsistencyLevel' = 'eventual'} -OutputType PSObject).Value
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
                Invoke-MgGraphRequest PATCH "$GraphHost/v1.0/applications/$($EntraApp.Id)" -Body $Params

                $EntraApp = (Invoke-MgGraphRequest -Method GET -Uri "$GraphHost/v1.0/applications?`$filter=web/redirectUris/any(p:p eq 'https://security.optimization.assessment.local')&`$count=true" -Headers @{'ConsistencyLevel' = 'eventual'} -OutputType PSObject).Value
            }
        }
        # Check if service principal (enterprise app) is owner of its app registration
        $appOwners = (Invoke-MgGraphRequest -Method GET -Uri "$GraphHost/v1.0/applications/$($EntraApp.Id)/owners" -OutputType PSObject).Value
        $appSp = Get-SOAAppServicePrincipal -EntraApp $EntraApp
        if ($appSp) {
            if ($appOwners.Id -notcontains $appSp.Id) {
                if ($DoNotRemediate -eq $false) {
                    if (Add-SOAAppOwner -NewOwnerObjectId $appSp.Id -EntraApp $EntraApp) {
                        $script:appSelfOwner = $true
                    } else {
                        $script:appSelfOwner = $false
                    }
                }
            } else {
                $script:appSelfOwner = $true
            }
        } else {
            $script:appSelfOwner = $false
        }
    }

    Return $EntraApp

}

function Get-SOAAppServicePrincipal {
    param (
        $EntraApp
    )
    $connCount = 0
    $connLimit = 5
    do {
        try {
            $connCount++
            Write-Verbose "$(Get-Date) Get-SOAAppServicePrincipal: Getting app service principal attempt #$connCount"
            $sp = Invoke-MgGraphRequest -Method GET -Uri "$GraphHost/v1.0/servicePrincipals(appId=`'$($EntraApp.AppId)`')" -OutputType PSObject
            return $sp
        } catch {
            Write-Verbose $_.Exception.Message
            Start-Sleep -Seconds 2
        }
    } until ($connCount -eq $connLimit)
}

function Add-SOAAppOwner {
    param (
        $NewOwnerObjectId,
        $EntraApp
    )
    $params = @{
        '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$NewOwnerObjectId"
    }
    Write-Verbose "$(Get-Date) Adding Microsoft Entra application as owner of its app registration..."
    Invoke-MgGraphRequest -Method POST -Uri "$GraphHost/v1.0/applications(appId=`'$($EntraApp.AppId)`')/owners/`$ref" -Body $params
    if ($?) {return $true} else {return $false}
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
        [Switch]$ManualCred,
        [Alias("O365EnvironmentName")][string]$CloudEnvironment="Commercial"
    )

    Write-Verbose "$(Get-Date) Test-SOAApplication App $($App.AppId) TenantDomain $($TenantDomain) SecretLength $($Secret.Length) CloudEnvironment $CloudEnvironment"

    # Perform permission check, except when manually providing the secret because there will be no delegated connection
    if ($ManualCred -eq $False) {
        If($WriteHost) { Write-Host "$(Get-Date) Performing application permission check... (This may take up to 5 minutes)" }
        $PermCheck = Invoke-AppPermissionCheck -App $App
    }

    # Perform check for consent
    if ($PermCheck -eq $True) {
        If ($WriteHost) { Write-Host "$(Get-Date) Performing token check... (This may take up to 5 minutes)" }
        $TokenCheck = Invoke-AppTokenRolesCheckV2 -CloudEnvironment $CloudEnvironment
    } else {
        # Set as False to ensure the final result shows the check as Failed instead of Null
        $TokenCheck = $False
    }

    # Get total user count
    if ($TokenCheck -eq $true) {
        $headers = @{
            consistencyLevel = 'eventual'
        }
        # Returns the first page of results along with the total count that will be returned if all pages are requested
        $countResponse = Invoke-MgGraphRequest -Method GET -Uri "$GraphHost/v1.0/users?`$count=true&`$select=id" -headers $headers -OutputType PSObject
        if ($countResponse."@odata.count" -gt 400000) {
            $countNote = 'Recommended to run user-level collection phases separately'
        } elseif ($countResponse."@odata.count" -gt 200000) {
            $countNote = 'Consider running user-level collection phases separately'
        }
    }

    Return New-Object -TypeName PSObject -Property @{
        Permissions=$PermCheck
        Token=$TokenCheck
        UserCount=$countResponse."@odata.count"
        CountNote=$countNote
    }
                
}

Function Install-SOAPrerequisites {
    [CmdletBinding(DefaultParametersetname="Default")]
    Param (
        [Parameter(ParameterSetName='Default')]
        [Parameter(ParameterSetName='ConnectOnly')]
        [Parameter(ParameterSetName='ModulesOnly')]
            [ValidateSet("EXO","SCC","SPO","PP","Teams","Graph","ActiveDirectory")][string[]]$Bypass,
        [switch]$UseProxy,
        [Parameter(DontShow)][Switch]$AllowMultipleWindows,
        [Parameter(DontShow)][switch]$NoVersionCheck,
        [Parameter(DontShow)][switch]$NoModuleLimitCheck,
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
            [Alias('O365EnvironmentName')][ValidateSet("Commercial","USGovGCC","USGovGCCHigh","USGovDoD","China")][string]$CloudEnvironment,
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
            [switch]$RemoveExistingEntraApp,
        [Parameter(ParameterSetName='Default')]
        [Parameter(ParameterSetName='EntraAppOnly')]
            [switch]$PromptForApplicationSecret,
        [Parameter(ParameterSetName='Default')]
        [Parameter(ParameterSetName='EntraAppOnly')]
            [switch]$HasEntraP1License,
        [Parameter(ParameterSetName='Default')]
        [Parameter(ParameterSetName='EntraAppOnly')]
            [switch]$HasEntraP2License,
        [Parameter(ParameterSetName='Default')]
        [Parameter(ParameterSetName='EntraAppOnly')]
            [switch]$HasMDOP2License,
        [Parameter(ParameterSetName='Default')]
        [Parameter(ParameterSetName='EntraAppOnly')]
            [switch]$HasMDELicense,
        [Parameter(ParameterSetName='Default')]
        [Parameter(ParameterSetName='EntraAppOnly')]
            [switch]$HasMDILicense,
        [Parameter(ParameterSetName='Default')]
        [Parameter(ParameterSetName='ModulesOnly')]
            [switch]$HasTeamsLicense,
        [Parameter(ParameterSetName='Default')]
        [Parameter(ParameterSetName='EntraAppOnly')]
            $GraphClientId,
        [Parameter(ParameterSetName='Default')]
        [Parameter(ParameterSetName='EntraAppOnly')]
            [ValidateScript({if ($PSItem -match "^\w+.onmicrosoft.(com|us)`$|^\w+.partner.onmschina.cn`$") {$true} else {throw "The value `"$PSItem`" is not a properly formatted initial domain."}})]
            $InitialDomain,
        [ValidateScript({if ($PSItem -match "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*`$") {$true} else {throw "The value `"$PSItem`" is not a properly formatted UPN."}})]
            [string]$AdminUPN,
        [switch]$NoAdminUPN,
        [Parameter(ParameterSetName='Default')]
        [Parameter(ParameterSetName='ConnectOnly')]
            [switch]$DisableWAM
    )

    <#

        Variable setting

    #>
    
    # Detect if running in ISE and abort ($psise is an automatic variable that exists only in the ISE)
    if ($psise)
        {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }

    # Detect if running in PS 7
    # Teams supports 7.2, EXO supports 7.0.3, Graph supports 7.0, PP and SPO do not natively support 7 (but generally work when using -UseWindowsPowerShell)
    if ($PSVersionTable.PSVersion.ToString() -like "7.*") {
        throw "Running this script in PowerShell 7 is not supported."
    }

    # Default run
    $ConnectCheck = $True
    $ModuleCheck = $True
    $EntraAppCheck = $True

    # Default to remediate (applicable only when not using ConnectOnly)
    if ($DoNotRemediate -eq $false -and $PromptForApplicationSecret -eq $false){
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
        Write-Host "$(Get-Date) Checking if the latest version of the SOA module is installed..."
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
    Write-Host "for one of the Microsoft 365 security assessments offered via Microsoft Services."
    Write-Host "At the conclusion of this script running successfully, a file named SOA-PreCheck.json will be created."
    Write-Host "This file should be sent to the engineer who will be delivering the assessment."
    Write-Host ""
    Write-Host "This script MUST be run on the workstation that will be used to perform the data collection for the assessment."
    Write-Host ""

    if ($DoNotRemediate -eq $false -and $ConnectOnly -eq $false) {
        Write-Important
        Write-Host "This script makes changes on this machine and in your Microsoft 365 tenant. Per the parameters used, the following will occur:" -ForegroundColor Green
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
            if ($EntraAppOnly) {
                $rhInput = Read-Host "Do you agree with the changes above (y/n)"
            } else {
                $rhInput = Read-Host "Is this script being run on the machine that will be used to pertform the data collection, and do you agree with the changes above (y/n)"
            }
            if($rhInput -eq "n") {
                Exit-Script
            } elseif($rhInput -eq "y") {
                Write-Host ""
                break;
            }
        }
    }

    <#

        Proxy requirement auto-detection

    #>

    if ($UseProxy) {
        Write-Host "The UseProxy switch was used. An attempt will be made to connect through the proxy infrastructure where possible."
        $RPSProxySetting = New-PSSessionOption -ProxyAccessType IEConfig
    } else {
        Write-Host "Proxy requirement was not specified with UseProxy. Connection will be attempted directly."
        Write-Host ""
        $RPSProxySetting = New-PSSessionOption -ProxyAccessType None 
    }

    # Download module file to determine if any versions should be skipped. Used by both the Module and Connection checks
    if ($NoModuleLimitCheck -eq $false) {
        try {
            $moduleResponse = Invoke-WebRequest -Uri "https://o365soa.github.io/soa/moduleversion.json" -UseBasicParsing
        } catch {} 
    }
    if ($moduleResponse.StatusCode -eq 200) {
        $script:moduleVersions = $moduleResponse.Content | ConvertFrom-Json
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

        $ModuleCheckResult = Invoke-SOAModuleCheck

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
        # Get the cloud environment if not provided
        if (-not $CloudEnvironment) {
            if (-not $AdminUPN) {
                if ($NoAdminUPN) {
                    Write-Error -Message "When NoAdminUPN is used, the cloud environment must be provided using the CloudEnvironment parameter."
                    Exit-Script
                } else {
                    # Get Admin UPN
                    do {
                        $AdminUPN = Read-Host -Prompt "Enter the UPN of the account that will be used to connect to Microsoft 365. (If providing a UPN is causing authentication issues, you can press Ctrl-C to abort the script and run it again with the NoAdminUPN and CloudEnvironment parameters.)"
                    }
                    until ($AdminUPN -match "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")
                    Write-Host ""
                }
            } 
            try {
                $CloudEnvironment = Get-CloudEnvironment -UPN $AdminUPN
            } catch {
                Exit-Script
                throw "There was an error determining the cloud environment for $UPN. Use the CloudEnvironment parameter to specify a cloud."
            }
        }
        switch ($CloudEnvironment) {
            "Commercial"   {$GraphHost = "https://graph.microsoft.com"}
            "USGovGCC"     {$GraphHost = "https://graph.microsoft.com"}
            "USGovGCCHigh" {$GraphHost = "https://graph.microsoft.us"}
            "USGovDoD"     {$GraphHost = "https://dod-graph.microsoft.us"}
            "China"        {$GraphHost = "https://microsoftgraph.chinacloudapi.cn"}
        }

        # Proceed to testing connections

        $Connections = @(Test-Connections -RPSProxySetting $RPSProxySetting -CloudEnvironment $CloudEnvironment)
        
        $Connections_OK = @($Connections | Where-Object {$_.Connected -eq $True -and $_.TestCommand -eq $True})
        $Connections_Error = @($Connections | Where-Object {$_.Connected -eq $False -or $_.TestCommand -eq $False -or $Null -ne $_.OtherErrors})
    }

    If($EntraAppCheck -eq $True) {
        # Check if the InitialDomain was not provided, which is required when skipping delegated connection entirely
        if (($null -ne $GraphClientId -and $PromptForApplicationSecret -eq $true) -and $null -eq $InitialDomain) {
            Exit-Script
            throw "The GraphClientId and PromptForApplicationSecret parameters were used, but InitialDomain was not specified. Re-run the script with the InitialDomain parameter"
        }
        
        # Get the cloud environment if not provided
        if (-not $CloudEnvironment) {
            if (-not $AdminUPN) {
                if ($NoAdminUPN) {
                    Write-Error -Message "When NoAdminUPN is used, the cloud instance must be provided using the CloudEnvironment parameter."
                    Exit-Script
                } else {
                    # Get Admin UPN
                    do {
                        $AdminUPN = Read-Host -Prompt "Enter the UPN of the account that will be used to connect to Microsoft 365. (If providing a UPN is causing authentication issues, you can press Ctrl-C to abort the script and run it again with the NoAdminUPN and CloudEnvironment parameters.)"
                    }
                    until ($AdminUPN -match "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")
                    Write-Host ""
                }
            } 
            try {
                $CloudEnvironment = Get-CloudEnvironment -UPN $AdminUPN
            } catch {
                Exit-Script
                throw "There was an error determining the cloud environment for $UPN. Use the CloudEnvironment parameter to specify a cloud instance."
            }
        }

        # When EntraAppOnly is used, this script may not be connected to Microsoft Graph
        switch ($CloudEnvironment) {
            "Commercial"   {$cloud = 'Global'}
            "USGovGCC"     {$cloud = 'Global'}
            "USGovGCCHigh" {$cloud = 'USGov'}
            "USGovDoD"     {$cloud = 'USGovDoD'}
            "China"        {$cloud = 'China'}
        }

        $mgContext =  (Get-MgContext).Scopes
        # Skip delegated connection if providing GraphClientId and the App Secret manually, otherwise evaluate whether the correct scope was requested
        if ($mgContext -notcontains 'Application.ReadWrite.All' -or ($mgContext -notcontains 'Organization.Read.All' -and $mgContext -notcontains 'Directory.Read.All') -and ($null -eq $GraphClientId -or $PromptForApplicationSecret -ne $true)) {
            Write-Host "$(Get-Date) Connecting to Graph with delegated authentication..."
            if ($null -ne (Get-MgContext)){Disconnect-MgGraph | Out-Null}
            $connCount = 0
            $connLimit = 5
            do {
                try {
                    $connCount++
                    Write-Verbose "$(Get-Date) Install-SOAPrerequisites: Graph Delegated connection attempt #$connCount"

                    if ($CloudEnvironment -eq "China") {
                        # Connections to 21Vianet must have manually provided the App ID and tenant name
                        if (-not $GraphClientId -or -not $InitialDomain) {
                            Exit-Script
                            throw "$(Get-Date) Connections to Graph in 21Vianet require the application ID (client ID) and tenant name (initial domain) be manually provided. Use both `-GraphClientId` and `-InitialDomain` parameters to provide them. For more information, see https://github.com/o365soa/soa."
                        }

                        Connect-MgGraph -Scopes 'Application.ReadWrite.All','Organization.Read.All' -Environment $cloud -ContextScope "Process" -ClientId $GraphClientId -Tenant $InitialDomain | Out-Null
                    } elseif ($PromptForApplicationSecret) {
                        # Request read-only permissions to Graph if manually providing the client secret
                        Connect-MgGraph -Scopes 'Application.Read.All','Organization.Read.All' -Environment $cloud -ContextScope "Process" | Out-Null
                    } else {
                        Connect-MgGraph -Scopes 'Application.ReadWrite.All','Organization.Read.All' -Environment $cloud -ContextScope "Process" | Out-Null
                    }
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

            $script:MDELicensed = Get-LicenseStatus -LicenseType MDE
            #Write-Verbose "$(Get-Date) Get-LicenseStatus MDE License found: $($script:MDELicensed)"

            $script:MDILicensed = Get-LicenseStatus -LicenseType MDI
            #Write-Verbose "$(Get-Date) Get-LicenseStatus MDI License found: $($script:MDILicensed)"

            $script:ATPP2Licensed = Get-LicenseStatus -LicenseType ATPP2
            #Write-Verbose "$(Get-Date) Get-LicenseStatus ATPP2 License found: $($script:ATPP2Licensed)"

            # Determine if Microsoft Entra application exists (and has public client redirect URI set) and create (or recreate) if it doesn't.
            $EntraApp = Get-SOAEntraApp -CloudEnvironment $CloudEnvironment
        }

        # EntraApp will have a value if connecting using Delegated. If skipping Delegated entirely, then the initial domain still needs to be queried
        If($EntraApp -or ($GraphClientId -and $PromptForApplicationSecret)) {
            # Get the tenant domain
            $tenantdomain = Get-InitialDomain

            if ($PromptForApplicationSecret -eq $True) {
                # Prompt for the client secret needed to connect to the application
                $SSCred = $null

                Write-Host "$(Get-Date) At the prompt, provide a valid client secret for the assessment's app registration."
                Start-Sleep -Seconds 1
                while ($null -eq $SSCred -or $SSCred.Length -eq 0) {
                    # UserName is a required parameter for Get-Credential but it's value is not used elsewhere in the script
                    $SSCred = (Get-Credential -Message "Enter the app registration's client secret into the password field." -UserName "Microsoft Security Assessment").Password
                    Start-Sleep 1 # Add a delay to allow to aborting to console
                }
            } else {
                # Reset secret
                $clientsecret = Reset-SOAAppSecret -App $EntraApp -Task "Prereq"
                $SSCred = $clientsecret | ConvertTo-SecureString -AsPlainText -Force
                Write-Host "$(Get-Date) Sleeping to allow for replication of the app registration's new client secret..."
                Start-Sleep 10
            }

            # Reconnect with Application permissions
            Try {Disconnect-MgGraph -ErrorAction Stop | Out-Null} Catch {}
            if ($GraphClientId) {
                $GraphCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $GraphClientId, $SSCred
            } else {
                $GraphCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($EntraApp.AppId), $SSCred
            }
            
            $ConnCount = 0
            Write-Host "$(Get-Date) Connecting to Graph with application authentication..."
            Do {
                Try {
                    $ConnCount++
                    if ($ConnCount -gt 5) {$ConnectionVerbose = @{Verbose = $true}} # Suppress Verbose output for the first 5 attempts, but display when connection is taking longer
                    Write-Verbose "$(Get-Date) Graph connection attempt #$ConnCount" @ConnectionVerbose
                    Connect-MgGraph -TenantId $tenantdomain -ClientSecretCredential $GraphCred -Environment $cloud -ContextScope "Process" -ErrorAction Stop | Out-Null
                } Catch {
                    Start-Sleep 5
                }
            } Until ($null -ne (Get-MgContext))

            # If the Delegated permissions were skipped, then the EntraApp has not yet been collected. Specifying the App ID allows the Application.ReadWrite.OwnedBy permission to be sufficient.
            if ($GraphClientId -and $PromptForApplicationSecret) {
                $EntraApp = Invoke-MgGraphRequest -Method GET -Uri "$GraphHost/v1.0/applications(appId=`'$GraphClientId`')"
            }

            # Check if redirect URIs not set for existing app because DoNotRemediate is True. Needs to be evaluated after switching to Application permissions for scenarios where Delegated is not used.
            $webRUri = @("https://security.optimization.assessment.local","https://o365soa.github.io/soa/")
            $pcRUri = @("https://login.microsoftonline.com/common/oauth2/nativeclient","http://localhost")
            if (((Compare-Object -ReferenceObject $EntraApp.PublicClient.RedirectUris -DifferenceObject $pcRUri) -or (Compare-Object -ReferenceObject $EntraApp.Web.RedirectUris -DifferenceObject $webRUri)) -and $DoNotRemediate) {
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
            $CheckResults += New-Object -Type PSObject -Property @{
                Check="Entra Application Owner"
                Pass=$script:appSelfOwner
            }

            $AppTest = Test-SOAApplication -App $EntraApp -Secret $clientsecret -TenantDomain $tenantdomain -CloudEnvironment $CloudEnvironment -WriteHost
                
            # Entra App Permission - Perform remediation if specified
            If($AppTest.Permissions -eq $False -and $Remediate -eq $true)
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
                if ($Remediate -eq $true) {
                    # Request admin consent
                    If((Invoke-Consent -App $EntraApp -CloudEnvironment $CloudEnvironment) -eq $True) {
                        # Perform check again after consent
                        $AppTest = Test-SOAApplication -App $EntraApp -Secret $clientsecret -TenantDomain $tenantdomain -CloudEnvironment $CloudEnvironment -WriteHost
                    }
                }
            }

            # Add final result to CheckResults object
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
            Connect-MgGraph -TenantId $tenantdomain -ClientSecretCredential $GraphCred -Environment $cloud -ErrorAction SilentlyContinue -ErrorVariable ConnectError | Out-Null
            
            If($ConnectError){
                # Try again to confirm it wasn't a transient issue
                Write-Verbose "$(Get-Date) Error when connecting using Graph SDK. Retrying in 15 seconds"
                Start-Sleep 15
                Connect-MgGraph -TenantId $tenantdomain -ClientSecretCredential $GraphCred -Environment $cloud -ErrorAction SilentlyContinue -ErrorVariable ConnectError2 | Out-Null
                if ($ConnectError2) {
                    $CheckResults += New-Object -Type PSObject -Property @{
                        Check="Graph SDK Connection"
                        Pass=$False
                    }
                } else {
                    $CheckResults += New-Object -Type PSObject -Property @{
                        Check="Graph SDK Connection"
                        Pass=$True
                    }
                }
            }
            else {
                $CheckResults += New-Object -Type PSObject -Property @{
                    Check="Graph SDK Connection"
                    Pass=$True
                }

                if ($PromptForApplicationSecret -eq $false) {
                    Start-Sleep 10 # Avoid a race condition
                    # Remove client secret
                    Remove-SOAAppSecret
                }
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
    
    [ordered]@{
        Date=(Get-Date).DateTime
        Version=$version
        Cloud=$CloudEnvironment
        UserCount=$AppTest.UserCount
        UserCountNote=$AppTest.CountNote
        Results=$CheckResults
        ModulesOK=$Modules_OK
        ModulesError=$Modules_Error
        ConnectionsOK=($Connections_OK | Select-Object -Property Name,Connected,ConnectErrors,TestCommand,TestCommandErrors)
        ConnectionsError=($Connections_Error | Select-Object -Property Name,Connected,ConnectErrors,TestCommand,TestCommandErrors)
    } | ConvertTo-Json | Out-File SOA-PreCheck.json

    Write-Host "$(Get-Date) Output saved to SOA-PreCheck.json which should be sent to the engineer who will be performing the assessment."
    $CurrentDir = Get-Location 
    Write-Host "$(Get-Date) SOA-PreCheck.json is located in: " -NoNewline
    Write-Host "$CurrentDir" -ForegroundColor Yellow
    Write-Host ""

    While($True) {
        $rhInput = Read-Host "Type 'yes' when you have sent the SOA-PreCheck.json file to the engineer who will be performing the assessment"
        if($rhInput -eq "yes") {
            break;
        }
    }

   Exit-Script
}
