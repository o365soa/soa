#Requires -Version 5.1

<#

	.SYNOPSIS
        SOA Export/Import Module

    .DESCRIPTION
    
        LogAnalytics only used for SOA as a Service delivery.

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

Function Export-SOARPS
{
    Param
    (
        [Parameter(ParameterSetName='FromFile')]
        $FromFile,

        [Parameter(ParameterSetName='FromObject')]
        [Array]$FromObject,

        [Parameter(ParameterSetName='FromObject', Mandatory=$True)]
        $AssessmentDate,

        [Parameter(ParameterSetName='FromObject')]
        [Parameter(ParameterSetName='FromFile')]
        [Parameter(ParameterSetName='OutputLogAnalytics')]
        [Switch]$UploadLogAnalytics,

        [Parameter(ParameterSetName='FromObject')]
        [Parameter(ParameterSetName='FromFile')]
        [Parameter(ParameterSetName='OutputLogAnalytics', Mandatory=$True)]
        [String]$LogAnalyticsWorkSpace,

        [Parameter(ParameterSetName='FromObject')]
        [Parameter(ParameterSetName='FromFile')]
        [Parameter(ParameterSetName='OutputLogAnalytics', Mandatory=$True)]
        [String]$LogAnalyticsKey
    )

    $Success = $False

    if(!$FromFile -and !$FromObject)
    {
        Throw "Please specify to import from file (-FromFile filename.csv) or from object (-FromObject)"
    }

    if($FromFile)
    {
        # Check file is in right format
        $Regex = "^Remediation Planning (\d{8})$"

        Try 
        {
            $Item = Get-ChildItem $FromFile
        }
        catch
        {
            Throw "Failed to find/get file $FromFile"
        }

        If($Item.BaseName -match $Regex)
        {
            $AssessmentDate = $Matches[1]

            $data = Import-CSV $FromFile

            # Add assessment date to the control
            ForEach($x in $data)
            {
                $x | Add-Member -MemberType NoteProperty -Name "AssessmentDate" -Value $AssessmentDate
            }
    
        }
        else
        {
            Throw "File must be named correctly as 'Remediation Planning YYYYMMDD' Replacing YYYY with Year, MM with Month (Double Digit), DD with Day (Double Digit). Example 'Remediation Planning 20200728.csv'"
        }

    }

    if($FromObject)
    {
        if($AssessmentDate -notmatch "^(\d{8})$")
        {
            Throw "AssessmentDate must be in format YYYYMMDD. Replacing YYYY with Year, MM with Month (Double Digit), DD with Day (Double Digit). Example '20200517'"
        }

        $data = $FromObject
    }

    if($UploadLogAnalytics)
    {
        # Post data to log analytics
        $json = ConvertTo-Json $data
            
        $Return = Post-LogAnalyticsData -customerId $LogAnalyticsWorkSpace -sharedKey $LogAnalyticsKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType "SecurityOptimizationAssessment"
        
        If($Return -eq 200)
        {
            $Success = $True
        }
    }

    Return New-Object -TypeName PSObject -Property @{
        Completed=$Success
        ControlCount=$($data.Count)
    }
}

# Create the function to create the authorization signature
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}


# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = "DateValue";
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}