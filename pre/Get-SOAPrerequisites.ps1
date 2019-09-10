#Requires -Version 5.1

<#

	.SYNOPSIS
		Pre-requisite check script for Office 365: Security Optimization Assessment

	.DESCRIPTION
        Script which can be run in advanced of a Security Optimization Assessment Engagement

        The output of the script and JSON file can be sent to the engineer performing the engagement.

    .PARAMETER Remediate
        This attempts to remediate any findings, the following can be remediated
            - Missing modules when the underlying module is in the PowerShell gallery
            - Updating modules when the underlying module in the PowerShell gallery
            - Duplicate modules, where an outdated version is installed
            - Installation of SkypeOnline connector
            - Installation of Enterprise Application for Graph polling

    .PARAMETER ConnectOnly
        Only performs the Connection checks - may be useful if it's confirmed the modules already
        have no issues.
        
    .PARAMETER ModulesOnly
        Only checks the module pre-requisites, does not perform any connection checks.

    .PARAMETER Bypass
        Multi-valued.
        
        Can be used to bypass specific functionality that may not be applicable to the assessment
        being ran, for instance, in order to Bypass SharePoint

        -Bypass SharePoint

        In order to bypass SharePoint and Skype

        -Bypass "SharePoint","Skype"

#>

[CmdletBinding(DefaultParametersetname="Default")]
Param (
    [Switch]$Remediate,
    [Parameter(ParameterSetName='Default')]
        $Bypass=@(),
    [Parameter(ParameterSetName='ConnectOnly')]
        [Switch]$ConnectOnly,
    [Parameter(ParameterSetName='ModulesOnly')]
        [Switch]$ModulesOnly,
    [Parameter(ParameterSetName='GraphOnly')]
        [Switch]$GraphOnly
)

# Variable setting

<#

    Required Graph Permissions

    Both the ID and the Name is required.
    - ID is used during the installation of the permissions
    - Name is used during the token check (to see we are actually getting these scopes assigned to us)

#>

$GraphRoles = @()

$GraphRoles += New-Object -TypeName PSObject -Property @{
    ID="bf394140-e372-4bf9-a898-299cfc7564e5"
    Name="SecurityEvents.Read.All"    
}
$GraphRoles += New-Object -TypeName PSObject -Property @{
    ID="dc5007c0-2d7d-4c42-879c-2dab87571379"
    Name="IdentityRiskyUser.Read.All"
}
$GraphRoles += New-Object -TypeName PSObject -Property @{
    ID="6e472fd1-ad78-48da-a0f0-97ab2c6b769e"
    Name="IdentityRiskEvent.Read.All"
}
$GraphRoles += New-Object -TypeName PSObject -Property @{
    ID="dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
    Name="DeviceManagementConfiguration.Read.All"
}

<#

    Variable setting

#>

# Default run
$ConnectCheck = $True
$ModuleCheck = $True
$GraphCheck = $True

# Change based on ModuleOnly flag
If($ModulesOnly) {
    $ConnectCheck = $False
    $ModuleCheck = $True
    $GraphCheck = $False
}

# Change based on ConnectOnly flag
If($ConnectOnly) {
    $ConnectCheck = $True
    $GraphCheck = $True
    $ModuleCheck = $False
}

# Change based on GraphOnly flag
If($GraphOnly) {
    $ConnectCheck = $False
    $GraphCheck = $True
    $ModuleCheck = $False
}

If($Bypass -contains "Graph") {
    $GraphCheck=$False
} Else {
    $GraphCheck=$True
}

# Final check list
$CheckResults = @()

Function Get-IsAdministrator {
    <#
        Determine if the script is running in the context of an administrator or not
    #>

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    Return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function Get-PowerShellCount
{
    <#
        Returns count of PowerShell windows opened
    #>

    $Processes = Get-Process -Name PowerShell
    Return $Processes.Count
}

# Check administrator for remediate flag
If($Remediate) {
    If($(Get-IsAdministrator) -eq $False -and $ModuleCheck -eq $True) {
        Write-Error "PowerShell must be run as Administrator in order for -Remediate flag"
        exit
    }
    If($(Get-PowerShellCount) -gt 1 -and $ModuleCheck -eq $True) {
        Write-Error "There are multiple PowerShell windows open and the -Remediate flag has been used. This can cause issues with PowerShell modules being loaded, blocking uninstallation and updates. Close all open PowerShell modules, and start with a clean PowerShell window running as administrator."
        Exit
    }
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

    $tenantName = Get-SPOTenantName
    
    $url = "https://" + $tenantName + "-admin.sharepoint.com"
    return $url
}

function Get-SharePointDefaultUrl
{
    <#
    
        Used to determine what the SharePoint URL is during connection tests
    
    #>

    $tenantName = Get-SPOTenantName

    $url = "https://" + $tenantName + ".sharepoint.com"
    return $url
}

function Get-PnPConnection
{
    <#
    
        Establishes a PNP Connection to SharePoint
    
    #>
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Url
    )
    
    if(!$Global:IsSPConnected)
    {
        Connect-PnPOnline -Url $Url -SPOManagementShell -ClearTokenCache
        $Global:IsSPConnected = $true
    }
    else {
        try {
            Connect-PnPOnline -Url $Url -SPOManagementShell -ErrorAction:SilentlyContinue
        }
        catch {
            # Supressing the exception
            Write-Verbose "Call to Connect-PnPOnline failed"
        }  
    }
   
}

Function Install-SkypeConnector {
    <#
    
        This function installs the Skype Connector. It is only used when Remediate flag is specified.

    #>

    Write-Host "$(Get-Date) Installing Skype Online Connector"

    $SkypeDownload = "https://download.microsoft.com/download/2/0/5/2050B39B-4DA5-48E0-B768-583533B42C3B/SkypeOnlinePowerShell.Exe"

    $TempPath = New-TemporaryDirectory

    # Download Skype Connector
    Invoke-WebRequest -Uri $SkypeDownload -OutFile "$TempPath\SkypeOnlinePowerShell.Exe"

    # Attempt to install
    & "$TempPath\SkypeOnlinePowerShell.Exe" /install /passive

    # Wait for task to finish
    $Installed = $False
    $MaxWait = 24 # Maximum wait time x * 5 seconds
    $Wait = 0

    Do {
        $Wait++;
        Sleep 5

        $p = Get-Process | Where-Object {$_.Name -eq "SkypeOnlinePowerShell"}

        # If p count is 0 then installer finished
        If($p.Count -eq 0) {
            # Make a check to determine if we are probably installed
            If(Test-Path "C:\Program Files\Common Files\Skype for Business Online\Modules\SkypeOnlineConnector\SkypeOnlineConnector.psd1") {
                $Installed = $True
                # Reload the PSEnvPath
                $env:PSModulePath = [System.Environment]::GetEnvironmentVariable("PSModulePath","Machine")
            }
        }

    } While ($Installed -eq $False -or $Wait -ge $MaxWait)

    Return $Installed

}

Function Install-ExchangeModule {
    <#
    
        Automates the Exchange Module Deployment

        NOTE: This is a bit of a hack, considering there is no good way to automate
        ClickOnce deployments.

    #>

    # Run the click once shim to deploy the app

    Write-Host "$(Get-Date) Installing Exchange ClickOnce"

    Write-Host ""
    Write-Important
    Write-Host ""
    Write-Host "Exchange Online Module Installation will now be triggered" -ForegroundColor Yellow
    Write-Host
    Write-Host "Depending on your AuthentiCode settings, you may see an 'Application Install - Security Warning'" -ForegroundColor Yellow
    Write-Host "Verify the publisher is Microsoft Corporation and Ensure you select 'Install'" -ForegroundColor Yellow

    Invoke-Expression "rundll32.exe dfshim.dll,ShOpenVerbApplication http://aka.ms/exopspreview"

    $Installing = $True
    $Installed = $False
    
    <#
        FLUFF
        These configure how long we will try sit and wait for the installation to complete
        Because we can't really 'tell' programatically when the ClickOnce deployment is complete
        We need to sit back and monitor the process and see if its closed
    #>
    $Fluff = 0
    $MaxFluff = 10

    $psids = (get-process |where-object {$_.name -eq 'powershell'}).id

    While($Installing -eq $True) {
        Sleep 1
        $dfsvcTitle = (Get-Process | Where-Object {$_.Name -eq "dfsvc"}).Mainwindowtitle

        if($dfsvcTitle -eq "Application Install - Security Warning") {
            Write-Host "Waiting for your approval, change to the window labelled '$dfsvcTitle'"
        }

        if($dfsvcTitle -like "*Installing Microsoft Exchange*") {
            Write-Host "$dfsvcTitle"
        }

        if($dfsvcTitle -eq "") {
            $Fluff++
            $NewPSIDs = @(Compare-Object -ReferenceObject $psids -DifferenceObject (get-process |where-object {$_.name -eq 'powershell'}).id |Where-Object {$_.SideIndicator -eq "=>"}).InputObject
            If($NewPSIDs.Count -gt 0) {
                Stop-Process $NewPSIDs -ErrorAction:SilentlyContinue | Out-Null
                $Installed = $True
                $Installing = $False
            }
            If($Fluff -eq $MaxFluff) {
                # This is to stop an infinite loop and also a false positive when dfsvc doesnt have a window title (not doing anything?)
                $Installing = $False
            }

        }
    }

    Return $Installed

}

Function Reset-GraphSecret {
    <#
    
        This function creates a new secret for the application
    
    #>
    Param (
        $GraphApp
    )

    # Provision a short lived credential +48 hrs.
    $clientsecret = New-AzureADApplicationPasswordCredential -ObjectId $GraphApp.ObjectId -EndDate (Get-Date).AddDays(2) -CustomKeyIdentifier "Prereq on $(Get-Date -Format "dd-MMM-yyyy")"
        
    Start-Sleep 30

    Return $clientsecret.Value
}

Function Load-ADAL {
    <#
    
        Finds a suitable ADAL library from AzureAD Preview and uses that
        This prevents us having to ship the .dll's ourself.

    #>
    $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    $aadModule      = $AadModule | ? { $_.version -eq $Latest_Version.version }
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
        $CredPrompt,
        [Switch]$ClearTokenCache # useful if we need to get newly added scopes
    )

    if (!$CredPrompt){$CredPrompt = 'Auto'}

    Load-ADAL

    $authority          = "https://login.microsoftonline.com/$TenantName"
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
        $r= Get-AzureADTenantDetail -ErrorAction:SilentlyContinue | Out-Null
        Return $True
    } Catch {
        Return $False
    }
}

Function Get-GraphToken {
    <#
    
        Gets a token which can be used for Graph
    
    #>
    Param (
        $GraphApp
    )

    # Get the default MSOL domain
    $tenantdomain = (Get-AzureADDomain | Where-Object {$_.Name -like "*.onmicrosoft.com" -and $_.Name -notlike "*.mail.onmicrosoft.com"}).Name

    $loginURL       = "https://login.windows.net/"
    $msgraphEndpoint = "https://graph.microsoft.com/"

    # Get an Oauth 2 access token based on client id, secret and tenant domain
    $body       = @{grant_type="client_credentials";resource=$msgraphEndpoint;client_id=$($GraphApp.AppId);client_secret=$($clientsecret.Value)}
    $oauth      = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body -ErrorAction:SilentlyContinue -ErrorVariable:AuthError
    
    If($null -ne $oauth.access_token) {
        Return $oauth
    } Else {
        Write-Error "Failed to get access token"
        Return $False
    }
    
}

Function Invoke-GraphTest {
    <#
    
        Performs a test against Graph by pulling secure scores
    
    #>
    Param (
        $GraphApp,
        $Secret,
        $TenantDomain
    )

    $Success = $False
    $AuthError = $null
    $RunError = $Null

    Write-Host "$(Get-Date) Testing Graph..."
    
    $Resource = "https://graph.microsoft.com/"

    $Token = Get-AccessToken -TenantName $tenantdomain -ClientID $GraphApp.AppId -Secret $Secret -Resource $Resource
    $headerParams = @{'Authorization'="$($Token.AccessTokenType) $($Token.AccessToken)"}

    $Result = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri 'https://graph.microsoft.com/beta/security/secureScores?$top=1' -ErrorAction:SilentlyContinue -ErrorVariable:RunError)

    If($Result.StatusCode -eq 200) {
        $Success = $True
    } Else {
        $Success = $False
    }

    Return New-Object -TypeName PSObject -Property @{
        Check="Graph Test"
        Pass=$Success
        Debug=$RunError
    }

}

Function Set-GraphPermission {
    <#
    
        Sets the required permissions on the application
    
    #>
    Param(
        $Roles,
        $App
    )

    Write-Host "$(Get-Date) Setting Graph Permissions for Application"

    $GraphResource = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $GraphResource.ResourceAppId = "00000003-0000-0000-c000-000000000000"

    ForEach($Role in $Roles) {
        $Perm = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList $Role.ID,"Role"
        $GraphResource.ResourceAccess += $Perm
    }

    Try {
        Set-AzureADApplication -ObjectId $App.ObjectId -RequiredResourceAccess $GraphResource
        Return $True
    } Catch {
        Return $False
    }

}

Function Invoke-GraphPermissionCheck {
    <#
        Check the permissions are set correctly on the Graph application
    #>
    Param(
        $Roles,
        $App
    )

    $Provisioned = $True

    $RequiredResources = @(($app.RequiredResourceAccess | Where-Object {$_.ResourceAppId -eq "00000003-0000-0000-c000-000000000000"}).ResourceAccess).Id

    # Go through each role this app should have, and check if this is in the RequiredResources field for the app
    ForEach($Role in $Roles) {
        If($RequiredResources -notcontains $Role.ID) {
            # Role is missing
            $Provisioned = $False
        }
    }

    Return New-Object -TypeName PSObject -Property @{
        Check="Graph Permissions"
        Pass=$Provisioned
    }

}

Function Invoke-GraphTokenRolesCheck {
    <#
    
        This function checks for the presence of the right roles in the token
        Consent may not have been completed without the right roles

    #>
    Param (
        $GraphApp,
        $Roles,
        $Secret,
        $TenantDomain
    )

    $MissingRoles = @()
    $Resource = "https://graph.microsoft.com/"

    # Obtain the token
    $Token = Get-AccessToken -TenantName $tenantdomain -ClientID $GraphApp.AppId -Secret $Secret -Resource $Resource -ClearTokenCache

    # Perform decode from JWT
    $tokenPayload = $token.accesstoken.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($tokenPayload.Length % 4) { $tokenPayload += "=" }
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    $tokobj = $tokenArray | ConvertFrom-Json

    # Check the roles are in the token
    ForEach($Role in $Roles) {
        If($tokobj.Roles -notcontains $Role.Name) {
            $MissingRoles += $Role
        }
    }

    If($MissingRoles.Count -gt 0) {
        $Result = $False
    } Else {
        $Result = $True
    }

    Return New-Object -TypeName PSObject -Property @{
        Check="Graph Token Role Check"
        Pass=$Result
        Debug=$MissingRoles
    }
}

Function Invoke-WinRMBasicCheck {
    <#
    
        Checks to determine if WinRM basic authentication is enabled.
        This is required for Exchange Online and Skype for Business PowerShell modules.
    
    #>

    $RegistrySetting = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\" -Name "AllowBasic" -ErrorAction:SilentlyContinue

    If($RegistrySetting.AllowBasic -eq 0) {
        $Result=$False
    } Else {
        $Result=$True
    }

    Return New-Object -TypeName PSOBject -Property @{
        Check="WinRM Basic Authentication"
        Pass=$Result
    }

}

Function Perform-Consent {
    <#
    
        Perform consent for application
    
    #>
    Param (
        $App
    )

    $Location = "https://login.microsoftonline.com/common/adminconsent?client_id=$($App.AppId)&state=12345&redirect_uri=https://soaconsentreturn.azurewebsites.net"
    
    Write-Important
    Write-Host "In 20 seconds, a window will load asking for you to consent to Security Optimization Assessment reading information in your tenant."
    write-Host "You need to log on and consent as a Global Administrator"
    Write-Host "When consent is complete - a green OK message should appear - You can close the browser window at this point."
    Write-Host ""
    Write-Host "For more information about this consent, please review the Scoping Email."
    Write-Host ""
    Write-Host "If the browser window does not load in 20 seconds, copy and paste the following in to a browser:"
    Write-Host ""
    Write-Host $Location
    Write-Host ""
    Sleep 20
    Start-Process $Location

    While($(Read-Host -Prompt "Type 'yes' when you have completed consent") -ne "yes") {}

    Return $True
}

Function Install-GraphApp {
    <#

        Installs the Azure AD Application used for accessing Graph
    
    #>
    Param (
        $Roles
    )
    
    # Create the Graph Application
    $GraphApp = New-AzureADApplication -DisplayName "Office 365 Security Optimization Assessment"  -ReplyUrls @("https://security.optimization.assessment.local","https://soaconsentreturn.azurewebsites.net")
    
    # Set up the correct Graph Permissions
    Set-GraphPermission -App $GraphApp -Roles $Roles

    # Requst admin consent
    Perform-Consent -App $GraphApp

    # Return the newly created graph application
    Return (Get-AzureADApplication -ObjectId $GraphApp.ObjectId)
    
}

Function Get-ModuleStatus {
    <#
    
        Determines the status of the module specified by ModuleName
    
    #>
    Param (
        [Parameter(ParameterSetName='ExternalModules')]
            [Switch]$ExtModule_Exchange,
        [Parameter(ParameterSetName='GalleryModules')]
            [String]$ModuleName,
            [Switch]$ConflictModule
    )

    # Determine if Gallery Module or not
    If($ExtModule_Exchange) {
        Write-Host "$(Get-Date) Checking module Exchange Online (Non Gallery Module)"
        $GalleryModule = $False
    } Else {      
        Write-Host "$(Get-Date) Checking module $($ModuleName)"
        $GalleryModule = $True
    }

    If($GalleryModule -eq $False) {

        # For the Exchange Module, which is not in the Galary
        If($ExtModule_Exchange) {
            $EXOLoad = Load-EXOPSModule
            If($EXOLoad -eq $True) {
                Return New-Object -TypeName PSObject -Property @{
                    Module="Exchange Online"
                    InstalledVersion=$InstalledModule.Version
                    GalleryVersion=$GalleryVersion
                    Installed=$True
                    Multiple=$False
                    Updated=$True
                }
            } Else {
                Return New-Object -TypeName PSObject -Property @{
                    Module="Exchange Online"
                    InstalledVersion=$InstalledModule.Version
                    GalleryVersion=$GalleryVersion
                    Installed=$False
                    Multiple=$False
                    Updated=$True
                }
            }
        }

    } Else {

        # Set variables used
        $MultipleFound = $False
        $Installed = $False

        # Gallery module

        $InstalledModule = @(Get-Module -ListAvailable | Where-Object {$_.Name -eq $ModuleName})

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
            $GalleryVersion = $PSGalleryModule.Version
            If($GalleryVersion -gt $InstalledModule.Version) {
                $Updated = $False
            } Else {
                $Updated = $True
            }
        }

        Return New-Object -TypeName PSObject -Property @{
            Module=$ModuleName
            InstalledVersion=$InstalledModule.Version
            GalleryVersion=$GalleryVersion
            Installed=$Installed
            Conflict=$(If($Installed -and $ConflictModule) { $True } Else { $False })
            Multiple=$MultipleFound
            Updated=$Updated
        }

    }
    
}

Function Load-EXOPSModule {
    <#
    
        Attempts to load the Exchange Online Module

    #>
    # Module changes the root path, so we want to change back after.
    $CurrentPath = Get-Location

    # Determine Apps folder exists, if it doesn't then it hasnt been installed before we check..
    If($(Test-Path "$($env:LOCALAPPDATA)\Apps\2.0") -eq $True) {
        $modules = @(Get-ChildItem -Path "$($env:LOCALAPPDATA)\Apps\2.0" -Filter "Microsoft.Exchange.Management.ExoPowershellModule.manifest" -Recurse )
        
        If($Modules.Count -gt 0) {
            $moduleName =  Join-Path $modules[0].Directory.FullName "Microsoft.Exchange.Management.ExoPowershellModule.dll"
            Import-Module -FullyQualifiedName $moduleName -Force 2>&1 | Out-Null
            $scriptName =  Join-Path $modules[0].Directory.FullName "CreateExoPSSession.ps1"
            . $scriptName 2>&1 | Out-Null
        
            If(!(Get-Command "Connect-EXOPSSession" -ErrorAction:SilentlyContinue)) {

                $Return = $False
            } Else {
        
                $Return = $True
        
            }
        } Else {
            $Return = $False
        }

    } Else {
        $Return = $False
    }

    Set-Location $CurrentPath
    Return $Return


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
                    # Determine if module is SharePoint module - which may need to be removed from path
                    If($Module.Name -eq "Microsoft.Online.SharePoint.PowerShell") {
                        Remove-FromPSModulePath "C:\Program Files\SharePoint Online Management Shell\"
                    } Else {
                        Write-Error "Failed to uninstall old module $($Module.Name)"
                    }
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
    } Else {
        Write-Error "Attempted to remove $Folder from PSModulePath, however, there is no entry. PSModulePath is $((Get-ChildItem Env:PSModulePath).Value)"
    }

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
    Install-Module $Module -Force -Scope:AllUsers

    If($Update) {
        # Remove old versions of the module
        Uninstall-OldModules -Module $Module
    }
}

Function Fix-Modules {
    <#

        Attempts to fix modules if $Remediate flag is specified
    
    #>
    Param($Modules)

    If(Get-IsAdministrator -eq $True) {

        # Administrator so can remediate
        $OutdatedModules = $Modules | Where-Object {$_.InstalledVersion -ne $null -and $_.Updated -eq $False -and $_.Conflict -ne $True}
        $DupeModules = $Modules | Where-Object {$_.Multiple -eq $True -and $_.Updated -eq $True}
        $MissingGalleryModules = $Modules | Where-Object {$_.InstalledVersion -eq $Null -and $_.GalleryVersion -ne $Null}
        $ConflictModules = $Modules | Where-Object {$_.Conflict -eq $True}

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
                    Exit
                }
            }
        } Else {
            Write-Error "PSGallery is not present on this host, so modules cannot be remediated."
            Exit
        }

        # Skype check
        If($Modules | Where-Object {$_.Module -eq "SkypeOnlineConnector" -and $_.Installed -eq $False}) {
            Install-SkypeConnector
        }

        # Exchange check
        If($Modules | Where-Object {$_.Module -eq "Exchange Online" -and $_.Installed -eq $False}) {
            Install-ExchangeModule | Out-Null
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
            Write-Host "$(Get-Date) Removing dupelicate modules for $($DupeModule.Module)"
            Uninstall-OldModules -Module $($DupeModule.Module)
        }

    } Else {
        Write-Error "Load PowerShell as administrator in order to fix modules"
        Return $False
    }
}

Function Check-Modules {

    $RequiredModules = @()
    
    # Conflict modules are modules which their presence causes issues
    $ConflictModules = @("AzureAD")

    # Bypass checks
    If($Bypass -notcontains "AAD") { $RequiredModules += "AzureADPreview" }
    If($Bypass -notcontains "MSOL") { $RequiredModules += "MSOnline" }
    If($Bypass -notcontains "SharePoint") { $RequiredModules += "SharePointPnPPowerShellOnline","Microsoft.Online.SharePoint.PowerShell" }
    If($Bypass -notcontains "Skype") {$RequiredModules += "SkypeOnlineConnector"}

    $ModuleCheck = @()

    ForEach($m in $RequiredModules) {
        $ModuleCheck += (Get-ModuleStatus -ModuleName $m)
    }

    ForEach($m in $ConflictModules) {
        $MInfo = (Get-ModuleStatus -ModuleName $m -ConflictModule)
        If($MInfo.Installed -eq $True) {
            $ModuleCheck += $MInfo
        }
    }

    If($Bypass -notcontains "Exchange" -or $Bypass -notcontains "SCC") {
        $ModuleCheck += (Get-ModuleStatus -ExtModule_Exchange)
    }

    Return $ModuleCheck
}

Function Test-Connections {

    $Connections = @()

    If($Bypass -notcontains "Exchange" -or $Bypass -notcontains "SCC") {
        # Unfortunately, this code has to be dupelicated in order to bring this in to the same context as this function
        $CurrentPath = Get-Location

        $modules = @(Get-ChildItem -Path "$($env:LOCALAPPDATA)\Apps\2.0" -Filter "Microsoft.Exchange.Management.ExoPowershellModule.manifest" -Recurse )
        $moduleName =  Join-Path $modules[0].Directory.FullName "Microsoft.Exchange.Management.ExoPowershellModule.dll"
        Import-Module -FullyQualifiedName $moduleName -Force 2>&1 | Out-Null
        $scriptName =  Join-Path $modules[0].Directory.FullName "CreateExoPSSession.ps1"
        . $scriptName 2>&1 | Out-Null
        Set-Location $CurrentPath

        # Now connect code can start
    }

    Write-Host "$(Get-Date) Connecting..."

    <#
        
        AD PowerShell Version 1. Aka MSOL
        
    #>
    If($Bypass -notcontains "MSOL") {

        
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        Write-Host "$(Get-Date) Connecting to Azure AD PowerShell 1.."
        Connect-MsolService -ErrorAction:SilentlyContinue -ErrorVariable ConnectError

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

        Write-Host "$(Get-Date) Connecting to Azure AD PowerShell 2.."
        $AADConnection = Connect-AzureAD -ErrorAction:SilentlyContinue -ErrorVariable ConnectError

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
        Connect-IPPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors | Out-Null

        If((Get-PSSession | Where-Object {$_.ComputerName -like "*protection.outlook.com"}).State -eq "Opened") { $Connect = $True } Else { $Connect = $False }

        # Run test command
        If(Get-Command "Get-ProtectionAlert") {
            $Connected=$True
            $Command = $True
        } Else {
            $Connected = $False
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
        Connect-EXOPSSession -WarningAction:SilentlyContinue -ErrorVariable:ConnectErrors | Out-Null

        If((Get-PSSession | Where-Object {$_.ComputerName -eq "outlook.office365.com"}).State -eq "Opened") { $Connect = $True } Else { $Connect = $False }

        # Run test command
        If(Get-Command "Get-OrganizationConfig") {
            If((Get-OrganizationConfig).Name) {
                $Command = $True
            } Else {
                $Command = $False
            }
        } Else {
            $Connected=$False
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

        Write-Host "$(Get-Date) Connecting to SharePoint Online.."
        $adminUrl = Get-SharePointAdminUrl
        Connect-SPOService -Url $adminUrl -ErrorAction:SilentlyContinue -ErrorVariable $ConnectError | Out-Null

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
    
        Skype for Business Online
    
    #>
    If($Bypass -notcontains "Skype") {
        # Reset vars
        $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

        Write-Host "$(Get-Date) Connecting to Skype..."
        $SfBOAdminDomain = (Get-AzureADTenantDetail | Select-Object -ExpandProperty VerifiedDomains | Where-Object { $_.Initial }).Name
        $SfBOSession = New-CsOnlineSession -OverrideAdminDomain $SfBOAdminDomain -ErrorVariable $ConnectError -ErrorAction:SilentlyContinue

        If($SfBOSession.State -eq "Opened") { $Connect = $True } Else { $Connect = $False }

        Import-PSSession -Session $SfBOSession -AllowClobber | Out-Null

        # Run test command
        If(Get-Command "Get-CSTenant") {
            If((Get-CSTenant).TenantID) {
                $Command = $True
            } Else {
                $Command = $False
            }
        } Else {
            $Connected=$False
            $Command = $False
        }

        $Connections += New-Object -TypeName PSObject -Property @{
            Name="Skype"
            Connected=$Connect
            ConnectErrors=$ConnectError
            TestCommand=$Command
            TestCommandErrors=$CommandError
        }
    }

    Return $Connections
}

<#

    Display the banner 

#>

Write-Host "###################################################" -ForegroundColor Green
Write-Host "# Security Optimization Assessment Pre-requisites #" -ForegroundColor Green
Write-Host "###################################################" -ForegroundColor Green
Write-Host ""

Write-Host "The purpose of this script is to check the pre-requisites for performing a Security Optimization Assessment engagement."
Write-Host "At the conclusion of running this script successfully, a file SOA-PreCheck.json will be generated."
Write-Host "This file should be sent to the engineer performing the engagement prior to the first day."
Write-Host ""
Write-Host "If there are any errors generated, please run this script with -Remediate in order to fix."
Write-Host ""
Write-Host "This script MUST be run on the workstation that will be used for performing the collection on Day 1"
Write-Host ""

If($Remediate) {
    Write-Important
    Write-Host "Remediation has been selected, as part of this script, the following may occur" -ForegroundColor Green
    Write-Host "1. Updates to required PowerShell modules installed on this machine" -ForegroundColor Green
    Write-Host "2. Installation of PowerShell modules required for this engagement" -ForegroundColor Green
    Write-Host "3. Installation of an Azure AD Application." -ForegroundColor Green
    Write-Host "    -- The application name is 'Office 365 Security Optimization Assessment" -ForegroundColor Green
    Write-Host "    -- The application will not be visible to end-users" -ForegroundColor Green
    Write-Host "    -- The application secret will not be stored, is randomly generated, and is removed at the conclusion of this script." -ForegroundColor Green
    Write-Host "    -- The application will not work without a secret. Do NOT remove the application until the conclusion of the engagement." -ForegroundColor Green
    Write-Host "4. The computer may restart during this process" -ForegroundColor Green
}

Write-Host ""

While($True) {
    $rhInput = Read-Host "Is this being run on the workstation that will be used for collection, and do you want to proceed (y/n)"
    if($rhInput -eq "n") {
        exit
    } elseif($rhInput -eq "y") {
        break;
    }
}

<# 

    Perform the module check

#>

If($ModuleCheck) {
    Write-Host "$(Get-Date) Checking pre-requisites..."

    $ModuleCheck = Check-Modules

    $Modules_OK = @($ModuleCheck | Where-Object {$_.Installed -eq $True -and $_.Multiple -eq $False -and $_.Updated -ne $False})
    $Modules_Error = @($ModuleCheck | Where-Object {$_.Installed -eq $False -or $_.Multiple -eq $True -or $_.Updated -eq $False -or $_.Conflict -eq $True})

    If($Modules_Error.Count -gt 0) {
        Write-Host "$(Get-Date) Modules with errors" -ForegroundColor Red
        $Modules_Error | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,Multiple,Updated

        If($Remediate) {
            Fix-Modules $Modules_Error

            Write-Host "$(Get-Date) Post remediation pre-requisite check..."
            $ModuleCheck = Check-Modules
            $Modules_OK = @($ModuleCheck | Where-Object {$_.Installed -eq $True -and $_.Multiple -eq $False -and $_.Updated -ne $False})
            $Modules_Error = @($ModuleCheck | Where-Object {$_.Installed -eq $False -or $_.Multiple -eq $True -or $_.Updated -eq $False})
        }

        # Don't continue to check connections, still modules with errors
        If($Modules_Error.Count -gt 0) {
            Write-Important

            Write-Host "$(Get-Date) The module check has failed - run with -Remediate to fix the modules and re-run. The connection check will not proceed until the module check has been completed." -ForegroundColor Red
            Write-Host "$(Get-Date) The modules must be remediated before continuing. Contact your TAM / or engineer for further information if required. "
            Exit
        }
    }
}

<#

    Perform the connection check

#>

If($ConnectCheck) {
    # Proceed to testing connections
    
    $Connections = @(Test-Connections)
    
        $Connections_OK = @($Connections | Where-Object {$_.Connected -eq $True -and $_.TestCommand -eq $True})
        $Connections_Error = @($Connections | Where-Object {$_.Connected -eq $False -or $_.TestCommand -eq $False -or $_.OtherErrors -ne $Null})
}

If($GraphCheck) {

    If((Get-AzureADConnected) -eq $False) {
        $AADConnection = Connect-AzureAD 
    }

    Write-Host "$(Get-Date) Checking Graph..."

    # Get the default MSOL domain
    $tenantdomain = (Get-AzureADDomain | Where-Object {$_.Name -like "*.onmicrosoft.com" -and $_.Name -notlike "*.mail.onmicrosoft.com"}).Name

    $Connect = $False; $ConnectError = $Null; $Command = $False; $CommandError = $Null

    # Determine if Azure AD Application Exists
    $GraphApp = Get-AzureADApplication -Filter "displayName eq 'Office 365 Security Optimization Assessment'" | Where-Object {$_.ReplyUrls -Contains "https://security.optimization.assessment.local"}

    # Graph App doesnt exist and the remediation flag has been specified
    If(!$GraphApp -and $Remediate) {
        If($Remediate) {

            Write-Host "$(Get-Date) Installing Graph Application..."

            $GraphApp = Install-GraphApp -Roles $GraphRoles

        }
    }

    If($GraphApp) {

        # Pass the graph app check
        $CheckResults += New-Object -Type PSObject -Property @{
            Check="Graph Application"
            Pass=$True
        }

        # Reset secret
        $clientsecret = Reset-GraphSecret -GraphApp $GraphApp

        # Perform check for Graph Permission
        Write-Host "$(Get-Date) Performing Application Permission Check..."
        $Result = Invoke-GraphPermissionCheck -App $GraphApp -Roles $GraphRoles
            
        # Graph Permission - Perform remediation if specified
            If($Result.Pass -eq $False -and $Remediate) {
                # Set up the correct Graph Permissions
                Write-Host "$(Get-Date) Remediating Application Permissions..."
                If((Set-GraphPermission -App $GraphApp -Roles $GraphRoles) -eq $True) {
                    # Requst admin consent
                    If((Perform-Consent -App $GraphApp) -eq $True) {
                        # Sleep to prevent race
                        Start-Sleep 60
                        $Result = Invoke-GraphPermissionCheck -App $GraphApp -Roles $GraphRoles
                    }
                }
            }

            $CheckResults += $Result

            # Perform check for consent
            Write-Host "$(Get-Date) Performing token check..."
            $Result = Invoke-GraphTokenRolesCheck -GraphApp $GraphApp -Secret $clientsecret -TenantDomain $tenantdomain -Roles $GraphRoles
            
            If($Result.Pass -eq $False -and $Remediate) {
                Write-Host "$(Get-Date) Missing roles in token, possible that consent was not completed..."
                    # Requst admin consent
                    If((Perform-Consent -App $GraphApp) -eq $True) {
                        # Sleep to prevent race, then re-perform check
                        Start-Sleep 60
                        $Result = Invoke-GraphTokenRolesCheck -GraphApp $GraphApp -Secret $clientsecret -TenantDomain $tenantdomain -Roles $GraphRoles
                    }                
            }

            # Add final result to checkresults
            $CheckResults += $Result

            # Perform Graph Check
            Write-Host "$(Get-Date) Performing Graph Test..."
            $CheckResults += Invoke-GraphTest -GraphApp $GraphApp -Secret $clientsecret -TenantDomain $tenantdomain

        } Else {
            # Graph app does not exist
            $CheckResults += New-Object -Type PSObject -Property @{
                Check="Graph Application"
                Pass=$False
            }
        }

}

<#

    Generic checks

#>

# WinRM Basic Authentication
$CheckResults += Invoke-WinRMBasicCheck

Write-Host "$(Get-Date) Detailed Output"

If($ModuleCheck) {

    Write-Host "$(Get-Date) Installed Modules" -ForegroundColor Green
    $Modules_OK | Format-Table Module,InstalledVersion,GalleryVersion,Multiple,Updated
    
    If($Modules_Error.Count -gt 0) {
        Write-Host "$(Get-Date) Modules with errors" -ForegroundColor Red
        $Modules_Error | Format-Table Module,InstalledVersion,GalleryVersion,Conflict,Multiple,Updated

        $CheckResults += New-Object -TypeName PSObject -Property @{
            Check="Module Installation"
            Pass=$False
        }

    } Else {
        $CheckResults += New-Object -TypeName PSObject -Property @{
            Check="Module Installation"
            Pass=$True
        }
    }

}

If($ConnectCheck) {

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

If($GraphCheck) {

    Write-Host "$(Get-Date) Graph checks" -ForegroundColor Green

}

Write-Host "$(Get-Date) Summary of Checks"

$CheckResults | Format-Table Check,Pass

New-Object -TypeName PSObject -Property @{
    Date=$(Get-Date)
    Results=$CheckResults
    ModulesOK=$Modules_OK
    ModulesError=$Modules_Error
    ConnectionsOK=$Connections_OK
    ConnectionsError=$Connections_Error
} | ConvertTo-Json | Out-File SOA-PreCheck.json

Write-Host "$(Get-Date) Output sent to SOA-PreCheck.json which can be sent to the engineer running the assessment"