###########################################################################
#
# NAME: Privilege Cloud BuiltIn Admin Account Onboard
#
# AUTHOR:  Mike Brook<mike.brook@cyberark.com>
#
# COMMENT: 
# Script will check if you are managing your BuildIn Admin Account and will help you onboard it for rotation.
#
#
###########################################################################
[CmdletBinding()]
param(
    [Parameter(Mandatory = $False)]
    [ValidateSet("cyberark")]
    [string]$AuthType = "cyberark",
    [Parameter(Mandatory = $false)]
    [Switch]
    $SkipVersionCheck
)

$global:LOG_FILE_PATH = "$PSScriptRoot\_PrivCloud_OnboardBuiltInAdminAcc.log"
$global:CONFIG_PARAMETERS_FILE = "$PSScriptRoot\_PrivCloud_OnboardBuiltInAdminAcc.ini"
$global:PlatformID = "CyberArkPrivCloud"
$global:PSMCCID = "PSM-PVWA-v122"
$global:PSMCCDiscID = "PSM-PVWA-v122-Disc"
$global:SafeName = "CyberArk_{0}_ADM"
$global:DefaultChromePath = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"

# Script Version
$ScriptVersion = "1.0"

#region Log functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
# Return Values..: None
# =================================================================================================================================
Function Write-LogMessage
{
    <# 
.SYNOPSIS 
	Method to log a message on screen and in a log file
.DESCRIPTION
	Logging The input Message to the Screen and the Log File. 
	The Message Type is presented in colours on the screen based on the type
.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [Bool]$WriteLog = $true,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH
    )
    Try
    {
        If ([string]::IsNullOrEmpty($LogFile) -and $WriteLog)
        {
            # User wanted to write logs, but did not provide a log file - Create a temporary file
            $LogFile = Join-Path -Path $ENV:Temp -ChildPath "$((Get-Date).ToShortDateString().Replace('/','_')).log"
            Write-Host "No log file path inputted, created a temporary file at: '$LogFile'"
        }
        If ($Header -and $WriteLog)
        {
            "=======================================" | Out-File -Append -FilePath $LogFile 
            Write-Host "=======================================" -ForegroundColor Magenta
        }
        ElseIf ($SubHeader -and $WriteLog)
        { 
            "------------------------------------" | Out-File -Append -FilePath $LogFile 
            Write-Host "------------------------------------" -ForegroundColor Magenta
        }
		
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
        $msgToWrite = ""
		
        # Mask Passwords
        $maskingPattern = '(?:(?:["\s\/\\](password|secret|NewCredentials|credentials|answer)(?!s))\s{0,}["\:= ]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()\-_\=\+\\\/\|\,\;\:\.\[\]\{\}]+))'
        $maskingResult = $Msg | Select-String $maskingPattern -AllMatches
        if ($maskingResult.Matches.Count -gt 0)
        {
            foreach ($item in $maskingResult.Matches)
            {
                if ($item.Success)
                {
                    # Avoid replacing a single comma, space or semi-colon 
                    if ($item.Groups[2].Value -NotMatch '^(,| |;)$')
                    {
                        $Msg = $Msg.Replace($item.Groups[2].Value, "****")
                    }
                }
            }
        }
        # Check the message type
        switch ($type)
        {
            { ($_ -eq "Info") -or ($_ -eq "LogOnly") } 
            { 
                If ($_ -eq "Info")
                {
                    Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) { "Magenta" } Else { "Gray" })
                }
                $msgToWrite = "[INFO]`t$Msg"
                break
            }
            "Success"
            { 
                Write-Host $MSG.ToString() -ForegroundColor darkGreen
                $msgToWrite = "[SUCCESS]`t$Msg"
                break
            }
            "Warning"
            {
                Write-Host $MSG.ToString() -ForegroundColor Yellow
                $msgToWrite = "[WARNING]`t$Msg"
                break
            }
            "Error"
            {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite = "[ERROR]`t$Msg"
                break
            }
            "Debug"
            { 
                if ($InDebug -or $InVerbose)
                {
                    Write-Debug $MSG
                    $msgToWrite = "[DEBUG]`t$Msg"
                }
                break
            }
            "Verbose"
            { 
                if ($InVerbose)
                {
                    Write-Verbose -Msg $MSG
                    $msgToWrite = "[VERBOSE]`t$Msg"
                }
                break
            }
        }

        If ($WriteLog) 
        { 
            If (![string]::IsNullOrEmpty($msgToWrite))
            {				
                "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t$msgToWrite" | Out-File -Append -FilePath $LogFile
            }
        }
        If ($Footer -and $WriteLog)
        { 
            "=======================================" | Out-File -Append -FilePath $LogFile 
            Write-Host "=======================================" -ForegroundColor Magenta
        }
    }
    catch
    {
        Throw $(New-Object System.Exception ("Cannot write message"), $_.Exception)
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Join-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
Function Join-ExceptionMessage
{
    <#
.SYNOPSIS
	Formats exception messages
.DESCRIPTION
	Formats exception messages
.PARAMETER Exception
	The Exception object to format
#>
    param(
        [Exception]$e
    )

    Begin
    {
    }
    Process
    {
        $msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
        while ($e.InnerException)
        {
            $e = $e.InnerException
            $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
        }
        return $msg
    }
    End
    {
    }
}

#endregion


#region Check latest version
# Taken from https://github.com/AssafMiron/CheckLatestVersion

$Script:GitHubAPIURL = "https://api.github.com/repos"

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-ScriptLatestVersion
# Description....: Compare the current version and the online (GitHub) version
# Parameters.....: The online file URL, current Version, a pattern to look for the script version number in the online file
# Return Values..: True if the online version is the latest, False otherwise
# =================================================================================================================================
Function Test-ScriptLatestVersion
{
    <# 
.SYNOPSIS 
	Compare the current version and the online (GitHub) version
.DESCRIPTION
	Compare the current version and the online (GitHub) version.
    Can compare version number based on Major, Major-Minor and Major-Minor-Patch version numbers
    Returns True if the online version is the latest, False otherwise
.PARAMETER fileURL
    The online file URL (in GitHub) to download and inspect
.PARAMETER currentVersion
    The current version number to compare to
.PARAMETER versionPattern
    A pattern of the script version number to search for in the online file
#>
    param(
        [Parameter(Mandatory = $true)]
        [string]$fileURL,
        [Parameter(Mandatory = $true)]
        [string]$currentVersion,
        [Parameter(Mandatory = $false)]
        [string]$versionPattern = "ScriptVersion",
        [Parameter(Mandatory = $false)]
        [ref]$outGitHubVersion
    )
    $getScriptContent = ""
    $isLatestVersion = $false
    try
    {
        $getScriptContent = (Invoke-WebRequest -UseBasicParsing -Uri $scriptURL).Content
        If ($($getScriptContent -match "$versionPattern\s{0,1}=\s{0,1}\""([\d\.]{1,10})\"""))
        {
            $gitHubScriptVersion = $Matches[1]
            if ($null -ne $outGitHubVersion)
            {
                $outGitHubVersion.Value = $gitHubScriptVersion
            }
            Write-LogMessage -type verbose -msg "Current Version: $currentVersion; GitHub Version: $gitHubScriptVersion"
            # Get a Major-Minor number format
            $gitHubMajorMinor = [double]($gitHubScriptVersion.Split(".")[0..1] -join '.')
            $currentMajorMinor = [double]($currentVersion.Split(".")[0..1] -join '.')
            # Check if we have a Major-Minor-Patch version number or only Major-Minor
            If (($gitHubScriptVersion.Split(".").count -gt 2) -or ($currentVersion.Split(".").count -gt 2))
            {
                $gitHubPatch = [int]($gitHubScriptVersion.Split(".")[2])
                $currentPatch = [int]($currentVersion.Split(".")[2])
            }
            # Check the Major-Minor version
            If ($gitHubMajorMinor -ge $currentMajorMinor)
            {
                If ($gitHubMajorMinor -eq $currentMajorMinor)
                {
                    # Check the patch version
                    $isLatestVersion = $($gitHubPatch -gt $currentPatch)
                }
                else
                {
                    $isLatestVersion = $true
                }
            }
        }
        else
        {
            Throw "Test-ScriptLatestVersion: Couldn't match Script Version pattern ($versionPattern)"
        }
    }
    catch
    {
        Throw $(New-Object System.Exception ("Test-ScriptLatestVersion: Couldn't download and check for latest version", $_.Exception))
    }
    return $isLatestVersion
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Copy-GitHubContent
# Description....: Copies all file and folder structure from a specified GitHub repository folder
# Parameters.....: The output folder path, the GitHub item URL to download from
# Return Values..: NONE
# =================================================================================================================================
Function Copy-GitHubContent
{
    <# 
.SYNOPSIS 
	Copies all file and folder structure from a specified GitHub repository folder
.DESCRIPTION
	Copies all file and folder structure from a specified GitHub repository folder
    Will create the content from a GitHub URL in the output folder
    Can handle files and folders recursively
.PARAMETER outputFolderPath
    The folder path to create the files and folders in
.PARAMETER gitHubItemURL
    The GitHub item URL to download from
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$outputFolderPath,
        [Parameter(Mandatory = $true)]
        [string]$gitHubItemURL
    )
    try
    {
        $gitHubFolderObject = (Invoke-RestMethod -Method Get -Uri $gitHubItemURL)
        foreach ($item in $gitHubFolderObject)
        {
            if ($item.type -eq "dir")
            {
                # Create the relevant folder
                $itemDir = Join-Path -Path $outputFolderPath -ChildPath $item.name
                if (! (Test-Path -Path $itemDir))
                {
                    New-Item -ItemType Directory -Path $itemDir | Out-Null
                }		
                # Get all relevant files from the folder
                Copy-GitHubContent -outputFolderPath $itemDir -gitHubItemURL $item.url
            }
            elseif ($item.type -eq "file")
            {
                Invoke-WebRequest -UseBasicParsing -Uri ($item.download_url) -OutFile $(Join-Path -Path $outputFolderPath -ChildPath $item.name)
            }
        }
    }
    catch
    {
        Throw $(New-Object System.Exception ("Copy-GitHubContent: Couldn't download files and folders from GitHub URL ($gitHubItemURL)", $_.Exception))
    }
}

Function Replace-Item
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$Destination,
        [Parameter(Mandatory = $false)]
        [switch]$Recurse
    )

    try
    {
        foreach ($item in $(Get-ChildItem -Recurse:$Recurse -Path $Path))
        {
            $destPath = Split-Path -Path $item.fullName.Replace($Path, $Destination) -Parent
            $oldName = "$($item.name).OLD"
            if (Test-Path -Path $(Join-Path -Path $destPath -ChildPath $item.name))
            {
                Rename-Item -Path $(Join-Path -Path $destPath -ChildPath $item.name) -NewName $oldName
                Copy-Item -Path $item.FullName -Destination $(Join-Path -Path $destPath -ChildPath $item.name)
                Remove-Item -Path $(Join-Path -Path $destPath -ChildPath $oldName)
            }
            Else
            {
                Write-Error "Can't find file $($item.name) in destination location '$destPath' to replace, copying"
                Copy-Item -Path $item.FullName -Destination $destPath
            }
        }
    }
    catch
    {
        Throw $(New-Object System.Exception ("Replace-Item: Couldn't Replace files", $_.Exception))
    }

}

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-GitHubLatestVersion
# Description....: Tests if the script is running the latest version from GitHub
# Parameters.....: NONE
# Return Values..: True / False
# =================================================================================================================================
Function Test-GitHubLatestVersion
{
    <# 
.SYNOPSIS 
	Tests if the script is running the latest version from GitHub
.DESCRIPTION
	Tests if the script is running the latest version from GitHub
    Can support a mode of test only and Test and download new version
    Can support searching the entire repository or a specific folder or a specific branch (default main)
    If not exclusively selected to test only, the function will update the script if a new version is found
.PARAMETER repositoryName
    The repository name
.PARAMETER scriptVersionFileName
    The file name to search the script version in
.PARAMETER currentVersion
    The current version of the script
.PARAMETER sourceFolderPath
    The source folder of the script
    Used to download and replace the new updated script to
.PARAMETER repositoryFolderPath
    The repository Folder path
.PARAMETER branch
    The branch to search for
    Default main
.PARAMETER versionPattern
    The pattern to check in the script
    Default: ScriptVersion
.PARAMETER TestOnly
    Switch parameter to perform only test
    If not exclusively selected, the function will update the script if a new version is found
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$repositoryName,
        [Parameter(Mandatory = $true)]
        [string]$scriptVersionFileName,
        [Parameter(Mandatory = $true)]
        [string]$currentVersion,
        [Parameter(Mandatory = $true)]
        [string]$sourceFolderPath,
        [Parameter(Mandatory = $false)]
        [string]$repositoryFolderPath,
        [Parameter(Mandatory = $false)]
        [string]$branch = "main",
        [Parameter(Mandatory = $false)]
        [string]$versionPattern = "ScriptVersion",
        [Parameter(Mandatory = $false)]
        [switch]$TestOnly
    )
    if ([string]::IsNullOrEmpty($repositoryFolderPath))
    {
        $apiURL = "$GitHubAPIURL/$repositoryName/contents"
    }
    else
    {
        $apiURL = "$GitHubAPIURL/$repositoryName/contents/$repositoryFolderPath`?ref=$branch"
    }
	
    $retLatestVersion = $true
    try
    {
        $folderContents = $(Invoke-RestMethod -Method Get -Uri $apiURL)
        $scriptURL = $($folderContents | Where-Object { $_.Type -eq "file" -and $_.Name -eq $scriptVersionFileName }).download_url
        $gitHubVersion = 0
        $shouldDownloadLatestVersion = Test-ScriptLatestVersion -fileURL $scriptURL -currentVersion $currentVersion -outGitHubVersion ([ref]$gitHubVersion)
    }
    catch
    {
        Throw $(New-Object System.Exception ("Test-GitHubLatestVersion: Couldn't check for latest version", $_.Exception))
    }
	
    try
    {
        # Check if we need to download the gitHub version
        If ($shouldDownloadLatestVersion)
        {
            # GitHub has a more updated version
            $retLatestVersion = $false
            If (! $TestOnly) # Not Test only, update script
            {
                Write-LogMessage -type Info -Msg "Found new version (version $gitHubVersion), Updating..."
                # Create a new tmp folder to download all files to
                $tmpFolder = Join-Path -Path $sourceFolderPath -ChildPath "tmp"
                if (! (Test-Path -Path $tmpFolder))
                {
                    New-Item -ItemType Directory -Path $tmpFolder | Out-Null
                }
                try
                {
                    # Download the entire folder (files and directories) to the tmp folder
                    Copy-GitHubContent -outputFolderPath $tmpFolder -gitHubItemURL $apiURL
                    # Replace the current folder content
                    Replace-Item -Recurse -Path $tmpFolder -Destination $sourceFolderPath
                    # Remove tmp folder
                    Remove-Item -Recurse -Path $tmpFolder -Force
                }
                catch
                {
                    # Revert to current version in case of error
                    $retLatestVersion = $true
                    Write-Error -Message "There was an error downloading GitHub content." -Exception $_.Exception
                }
            }
            else
            {
                Write-LogMessage -type Info -Msg "Found a new version in GitHub (version $gitHubVersion), skipping update."
            }
        }
        Else
        {
            Write-LogMessage -type Info -Msg "Current version ($currentVersion) is the latest!"
        }
    }
    catch
    {
        Throw $(New-Object System.Exception ("Test-GitHubLatestVersion: Couldn't download latest version", $_.Exception))
    }
	
    return $retLatestVersion
}

#endregion 

#region REST Logon
# @FUNCTION@ ======================================================================================================================
# Name...........: IgnoreCertErrors
# Description....: Sets TLS 1.2 and Ignore Cert errors.
# Parameters.....: None
# Return Values..: 
# =================================================================================================================================
Function IgnoreCertErrors()
{
    #Ignore certificate error
    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
        $certCallback = @"
			using System;
			using System.Net;
			using System.Net.Security;
			using System.Security.Cryptography.X509Certificates;
			public class ServerCertificateValidationCallback
			{
				public static void Ignore()
				{
					if(ServicePointManager.ServerCertificateValidationCallback ==null)
					{
						ServicePointManager.ServerCertificateValidationCallback += 
							delegate
							(
								Object obj, 
								X509Certificate certificate, 
								X509Chain chain, 
								SslPolicyErrors errors
							)
							{
								return true;
							};
					}
				}
			}
"@
        Add-Type $certCallback
    }
    [ServerCertificateValidationCallback]::Ignore()
    #ERROR: The request was aborted: Could not create SSL/TLS secure channel.
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LogonHeader
# Description....: Login to PVWA and return logonHeader
# Parameters.....: Credentials
# Return Values..: 
# =================================================================================================================================
Function Get-LogonHeader
{
    <#
    .SYNOPSIS
        Get-LogonHeader
    .DESCRIPTION
        Get-LogonHeader
    .PARAMETER Credentials
        The REST API Credentials to authenticate
    #>
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credentials
    )
    
    # Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password } | ConvertTo-Json -Compress
            
    try
    {
        # Logon
        $logonToken = Invoke-RestMethod -Method Post -Uri $URL_PVWALogon -Body $logonBody -ContentType "application/json" -TimeoutSec 2700
    
        # Clear logon body
        $logonBody = ""
    }
    catch
    {
        Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
    }
    
    $logonHeader = $null
    If ([string]::IsNullOrEmpty($logonToken))
    {
        Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
    }
    
    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    If ($logonToken.PSObject.Properties.Name -contains "CyberArkLogonResult")
    {
        $logonHeader = @{Authorization = $($logonToken.CyberArkLogonResult) }
    }
    else
    {
        $logonHeader = @{Authorization = $logonToken }
    }
    return $logonHeader
}
    
# @FUNCTION@ ======================================================================================================================
# Name...........: Invoke-Logon
# Description....: Logon to PVWA
# Parameters.....: None
# Return Values..: 
# =================================================================================================================================
Function Invoke-Logon
{ 
    # Get Credentials to Login
    # ------------------------
    $caption = "Enter Credentials"
    $msg = "Enter your Privilege Cloud BuiltIn Admin Account"; 
    $global:creds = $Host.UI.PromptForCredential($caption, $msg, $s_BuiltInAdminUsername, "")
    try
    {
        # Ignore SSL Cert issues
        IgnoreCertErrors
        # Login to PVWA
        Write-LogMessage -type Info -MSG "START Logging in to PVWA."
        $script:s_pvwaLogonHeader = Get-LogonHeader -Credentials $creds
        if ($s_pvwaLogonHeader.Keys -contains "Authorization") { Write-LogMessage -type Info -MSG "FINISH Logging in to PVWA." }
    }
    catch
    {
        Throw $(New-Object System.Exception ("Error logging on to PVWA", $_.Exception))
    }
}


# @FUNCTION@ ======================================================================================================================
# Name...........: Invoke-Logoff
# Description....: Logoff PVWA
# Parameters.....: None
# Return Values..: 
# =================================================================================================================================
Function Invoke-Logoff
{
    try
    {
        Write-LogMessage -type Info -Msg "Logoff Session..."
        Invoke-RestMethod -Method Post -Uri $URL_PVWALogoff -Headers $s_pvwaLogonHeader -ContentType "application/json" | Out-Null
    }
    catch
    {
        Throw $(New-Object System.Exception ("Error logging off from PVWA", $_.Exception))
    }
}
#endregion

#region Find Components
# @FUNCTION@ ======================================================================================================================
# Name...........: Get-ServiceInstallPath
# Description....: Get the installation path of a service
# Parameters.....: Service Name
# Return Values..: $true
#                  $false
# =================================================================================================================================
# Save the Services List
$m_ServiceList = $null
Function Get-ServiceInstallPath
{
    <#
  .SYNOPSIS
  Get the installation path of a service
  .DESCRIPTION
  The function receive the service name and return the path or returns NULL if not found
  .EXAMPLE
  (Get-ServiceInstallPath $<ServiceName>) -ne $NULL
  .PARAMETER ServiceName
  The service name to query. Just one.
 #>
    param ($ServiceName)
    Begin
    {

    }
    Process
    {
        $retInstallPath = $Null
        try
        {
            if ($null -eq $m_ServiceList)
            {
                Set-Variable -Name m_ServiceList -Value $(Get-ChildItem "HKLM:\System\CurrentControlSet\Services" | ForEach-Object { Get-ItemProperty $_.pspath }) -Scope Script
                #$m_ServiceList = Get-Reg -Hive "LocalMachine" -Key System\CurrentControlSet\Services -Value $null
            }
            $regPath = $m_ServiceList | Where-Object { $_.PSChildName -eq $ServiceName }
            If ($Null -ne $regPath)
            {
                $retInstallPath = $regPath.ImagePath.Substring($regPath.ImagePath.IndexOf('"'), $regPath.ImagePath.LastIndexOf('"') + 1)
            }
        }
        catch
        {
            Throw $(New-Object System.Exception ("Cannot get Service Install path for $ServiceName", $_.Exception))
        }

        return $retInstallPath
    }
    End
    {

    }
}
Function Set-PVWAURL
{
    <#
.SYNOPSIS
	Sets the PVWA URLs to be used in the script based on the Component found
.DESCRIPTION
	Sets the PVWA URLs to be used in the script based on the Component found
.PARAMETER ComponentID
    The component ID that is used
    Accepts only: PVWA, CPM, PSM
.PARAMETER ConfigPath
    For CPM and PSM, this is the configuration path to extract the PVWA URL from
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("CPM", "PSM")]
        [string]$ComponentID,
        [Parameter(Mandatory = $False)]
        [string]$ConfigPath,
        [Parameter(Mandatory = $False)]
        [ValidateSet("cyberark", "ldap")]
        [string]$AuthType = "cyberark"
    )
    Try
    {
        $foundConfig = $false
        Write-LogMessage -type debug -Msg "Get PVWA URL from component '$ComponentID' and from config file '$ConfigPath'"
        if (Test-Path $ConfigPath)
        {
            if ($ComponentID -eq "PSM")
            {
                [xml]$GetPVWAStringURL = Get-Content $ConfigPath
                if (![string]::IsNullOrEmpty($GetPVWAStringURL) -and $GetPVWAStringURL.PasswordVaultConfiguration.General.ApplicationRoot)
                { 
                    # In case there is more than one address, get the first one
                    $PVWAurl = ($GetPVWAStringURL.PasswordVaultConfiguration.General.ApplicationRoot).Split(",")[0]
                    # Check that the PVWAUrl contains a URL and not IP
                    $foundConfig = ($PVWAurl -NotMatch "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                }
                else
                {
                    Write-LogMessage -type Warning -Msg "Error reading the configuration file."
                }
            }
            if ($ComponentID -eq "CPM")
            {
                try
                {
                    # In case there is more than one address, get the first one
                    $GetPVWAStringURL = ((Get-Content $ConfigPath | Where-Object { $_ -match "Addresses" }).Split("=")[1]).Split(",")[0]
                }
                catch
                {
                    Write-LogMessage -type Error -MSG "There was an error finding PVWA Address from CPM configuration file."
                    $GetPVWAStringURL = $null
                }
                If (![string]::IsNullOrEmpty($GetPVWAStringURL))
                {
                    $PVWAurl = $GetPVWAStringURL
                    $foundConfig = $true
                }
            }
        }
        # We Couldn't find PVWA URL so we prompt the user
        if (($foundConfig -eq $False) -or ([string]::IsNullOrEmpty($PVWAurl)))
        {
            $PVWAurl = (Read-Host "Enter your Portal URL (eg; 'https://mycybrlab.privilegecloud.cyberark.com')")
        }
        Write-LogMessage -type debug -Msg "The PVWA URL to be used is: '$PVWAurl'"
    }
    Catch
    {
        Throw $(New-Object System.Exception ("There was an error reading the $ComponentID configuration file '$ConfigPath'", $_.Exception))
    }
    
    # Set the PVWA URLS
    $script:URL_PVWA = "https://" + ([System.Uri]$PVWAurl).Host
    $global:subdomain = ([System.Uri]$PVWAurl).Host.Split(".")[0]
    $URL_PVWAPasswordVault = $URL_PVWA + "/passwordVault"
    $URL_PVWAAPI = $URL_PVWAPasswordVault + "/api"
    $URL_PVWAAuthentication = $URL_PVWAAPI + "/auth"
    $script:URL_PVWALogon = $URL_PVWAAuthentication + "/$AuthType/Logon"
    $script:URL_PVWALogoff = $URL_PVWAAuthentication + "/Logoff"
    Write-LogMessage -type debug -Msg "Logon URL will be: '$URL_PVWALogon'"
    # URL Methods
    # -----------
    $script:URL_Users = $URL_PVWAAPI + "/Users"
    $script:URL_Accounts = $URL_PVWAAPI + "/Accounts"
    $script:URL_AccountVerify = $URL_Accounts + "/{0}/Verify"
    $script:URL_UsersGroups = $URL_PVWAAPI + "/UserGroups"
    $script:URL_Safes = $URL_PVWAAPI + "/Safes"
    $script:URL_SafeFind = $URL_PVWAPasswordVault + "/WebServices/PIMServices.svc/Safes?query={0}"
    $script:URL_SafeAddMembers = $URL_Safes + "/{0}/Members"
    $script:URL_SafesUnderPlatform = $URL_PVWAAPI + "/Platforms/{0}/Safes" #TO-DO not sure this is needed
    $script:URL_SystemHealthComponent = $URL_PVWAAPI + "/ComponentsMonitoringDetails/{0}"
    $script:URL_UserSetGroup = $URL_UsersGroups + "/{0}/Members"
    $script:URL_UserDelGroup = $URL_UsersGroups + "/{0}/Members/{1}"
    $script:URL_UserExtendedDetails = $URL_Users + "/{0}"
    $script:URL_PlatformVerify = $URL_PVWAAPI + "/Platforms/{0}"
    $script:URL_PlatformImport = $URL_PVWAAPI + "/Platforms/Import"
    $script:URL_ConnectionComponentVerify = $URL_PVWAAPI + "/ConnectionComponents/{0}"
    $script:URL_ConnectionComponentImport = $URL_PVWAAPI + "/ConnectionComponents/Import"
    $script:URL_GetAllPSMs = $URL_PVWAAPI + "/PSM/Servers"
    $script:URL_SystemHealthComponent = $URL_PVWAAPI + "/ComponentsMonitoringDetails/{0}"
    $script:URL_DomainDirectories = $URL_PVWAAPI + "/Configuration/LDAP/Directories"
    $script:URL_VaultMappings = $URL_PVWAAPI + "/Configuration/LDAP/Directories/{0}/mappings"
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Find-Components
# Description....: Detects all CyberArk Components installed on the local server
# Parameters.....: None
# Return Values..: Array of detected components on the local server
# =================================================================================================================================
Function Find-Components
{
    <#
.SYNOPSIS
	Method to query a local server for CyberArk components
.DESCRIPTION
	Detects all CyberArk Components installed on the local server
#>
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "CPM", "PSM")]
        [String]$Component = "All",
        [switch]$FindOne
    )

    Begin
    {
        $retArrComponents = @()
        # COMPONENTS SERVICE NAMES
        $REGKEY_CPMSERVICE = "CyberArk Password Manager"
        $REGKEY_PSMSERVICE = "Cyber-Ark Privileged Session Manager"
    }
    Process
    {
        if (![string]::IsNullOrEmpty($Component))
        {
            Switch ($Component)
            {
                "CPM"
                {
                    try
                    {
                        # Check if CPM is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for CPM..."
                        if ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_CPMSERVICE)))
                        {
                            # Get the CPM Installation Path
                            Write-LogMessage -Type "Info" -MSG "Found CPM installation."
                            $cpmPath = $componentPath.Replace("Scanner\CACPMScanner.exe", "").Replace("PMEngine.exe", "").Replace("/SERVICE", "").Replace('"', "").Trim()
                            $ConfigPath = (Join-Path -Path $cpmPath -ChildPath "Vault\Vault.ini")
                            $myObject = New-Object PSObject -Property @{
                                Name        = "CPM"; 
                                DisplayName = "CyberArk Password Manager (CPM)";
                                Path        = $cpmPath; 
                                ConfigPath  = $ConfigPath;
                            }
                            $myObject | Add-Member -MemberType ScriptMethod -Name InitPVWAURL -Value { Set-PVWAURL -ComponentID $this.Name -ConfigPath $this.ConfigPath -AuthType "cyberark" } | Out-Null
                            return $myObject
                        }
                    }
                    catch
                    {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "PSM"
                {
                    try
                    {
                        # Check if PSM is installed
                        Write-LogMessage -Type "Debug" -MSG "Searching for PSM..."
                        if ($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_PSMSERVICE)))
                        {
                            Write-LogMessage -Type "Info" -MSG "Found PSM installation."
                            $PSMPath = $componentPath.Replace("CAPSM.exe", "").Replace('"', "").Trim()
                            $ConfigPath = (Join-Path -Path $PSMPath -ChildPath "temp\PVConfiguration.xml")
                            $myObject = New-Object PSObject -Property @{
                                Name        = "PSM"; 
                                DisplayName = "CyberArk Privileged Session Manager (PSM)";
                                Path        = $PSMPath;
                                ConfigPath  = $ConfigPath;
                            }
                            $myObject | Add-Member -MemberType ScriptMethod -Name InitPVWAURL -Value { Set-PVWAURL -ComponentID $this.Name -ConfigPath $this.ConfigPath -AuthType "cyberark" } | Out-Null
                            return $myObject
                        }
                    }
                    catch
                    {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
                "All"
                {
                    try
                    {
                        ForEach ($comp in @("CPM", "PSM"))
                        {
                            $retArrComponents += Find-Components -Component $comp -FindOne:$FindOne
                            if ($FindOne -and $retArrComponents.Count -gt 0)
                            { 
                                # Exit the ForEach loop
                                break
                            }
                        }
                        return $retArrComponents
                    }
                    catch
                    {
                        Write-LogMessage -Type "Error" -Msg "Error detecting components. Error: $(Join-ExceptionMessage $_.Exception)"
                    }
                    break
                }
            }
        }
    }
    End
    {
    }
}
#endregion

#region Helper functions

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-AdminUser
# Description....: Check if the user is a Local Admin
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function Test-AdminUser()
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.SecurityIdentifier] "S-1-5-32-544")  # Local Administrators group SID
}

Function Get-Choice
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        $Title,

        [Parameter(Mandatory = $true, Position = 1)]
        [String[]]
        $Options,

        [Parameter(Position = 2)]
        $DefaultChoice = -1
    )
    if ($DefaultChoice -ne -1 -and ($DefaultChoice -gt $Options.Count -or $DefaultChoice -lt 1))
    {
        Write-Warning "DefaultChoice needs to be a value between 1 and $($Options.Count) or -1 (for none)"
        exit
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $script:result = ""
    $form = New-Object System.Windows.Forms.Form
    $form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog
    $form.BackColor = [Drawing.Color]::White
    $form.TopMost = $True
    $form.Text = $Title
    $form.ControlBox = $False
    $form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
    #calculate width required based on longest option text and form title
    $minFormWidth = 300
    $formHeight = 44
    $minButtonWidth = 100
    $buttonHeight = 23
    $buttonY = 12
    $spacing = 10
    $buttonWidth = [Windows.Forms.TextRenderer]::MeasureText((($Options | Sort-Object Length)[-1]), $form.Font).Width + 1
    $buttonWidth = [Math]::Max($minButtonWidth, $buttonWidth)
    $formWidth = [Windows.Forms.TextRenderer]::MeasureText($Title, $form.Font).Width
    $spaceWidth = ($options.Count + 1) * $spacing
    $formWidth = ($formWidth, $minFormWidth, ($buttonWidth * $Options.Count + $spaceWidth) | Measure-Object -Maximum).Maximum
    $form.ClientSize = New-Object System.Drawing.Size($formWidth, $formHeight)
    $index = 0
    #create the buttons dynamically based on the options
    foreach ($option in $Options)
    {
        Set-Variable "button$index" -Value (New-Object System.Windows.Forms.Button)
        $temp = Get-Variable "button$index" -ValueOnly
        $temp.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
        $temp.UseVisualStyleBackColor = $True
        $temp.Text = $option
        $buttonX = ($index + 1) * $spacing + $index * $buttonWidth
        $temp.Add_Click({ 
                $script:result = $this.Text; 
                $form.Close() 
            })
        $temp.Location = New-Object System.Drawing.Point($buttonX, $buttonY)
        $form.Controls.Add($temp)
        $index++
    }
    $shownString = '$this.Activate();'
    if ($DefaultChoice -ne -1)
    {
        $shownString += '(Get-Variable "button$($DefaultChoice-1)" -ValueOnly).Focus()'
    }
    $shownSB = [ScriptBlock]::Create($shownString)
    $form.Add_Shown($shownSB)
    [void]$form.ShowDialog()
    return $result
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Insert-AuditorsGroup
# Description....: Check if user belongs to Auditors Group and if not, insert itself to it.
# Parameters.....: None
# Return Values..: Array of detected components on the local server
# =================================================================================================================================
Function Insert-AuditorsGroup()
{
    Write-LogMessage -MSG "Checking if user is part of Auditors group, this is needed to find out if the account was previously onboarded."

    $global:IsUserInAuditGroup = $null
    $SearchUserURL = $URL_Users + "?filter==UserName&search=$s_BuiltInAdminUsername"

    #Find our user
    Try
    {
        $GetUsersResponse = Invoke-RestMethod -Method Get -Uri $SearchUserURL -Headers $s_pvwaLogonHeader -ContentType "application/json" -TimeoutSec 2700
    }
    Catch
    {
        Write-LogMessage -type Error -MSG $_.exception
    }
    if ($GetUsersResponse.Total -eq 0)
    {
        Write-LogMessage -type Error -MSG "Can't find user $s_BuiltInAdminUsername, aborting script."
        Write-LogMessage -type Error -MSG "*** Please create a support ticket stating your builtin admin account doesn't exist, and we will help you rebuild it ***"
        Pause
        Break
    }

    #In case we find more than one user with similar name (for example mike_admin and mike_admin1 it will return both, so we need to exact match them to pull ID).
    if (($GetUsersResponse.users.username).count -gt 1)
    {
        $i = 0
        foreach ($user in $GetUsersResponse)
        {
            if ($user.users.username[$i] -eq $s_BuiltInAdminUsername)
            {
                $global:BuiltIndAdminUserId = $user.users.id[$i]
            }
            $i += 1
        }
    }
    Else
    {
        $BuiltIndAdminUserId = $GetUsersResponse.users.id
    }

    #Get user extended details to check if in Auditor group. (Compatible with 11.7 - 12.2)
    $global:GetUserDetailsResponse = Invoke-RestMethod -Method Get -Uri ($URL_UserExtendedDetails -f $BuiltIndAdminUserId) -Headers $s_pvwaLogonHeader -ContentType "application/json" -TimeoutSec 2700

    #Check if User is inside Auditors Group
    if ($GetUserDetailsResponse.groupsMembership.groupName -contains "Auditors")
    {
        Write-LogMessage -MSG "User is already part of Auditors Group, skipping..."
        #Save the Status of user in group or not and store it in a file in case the script was stopped.
        $parameters = @{IsUserInAuditGroup = "True" }
        $parameters | Export-Clixml -Path $CONFIG_PARAMETERS_FILE -Encoding ASCII
    }
    Else
    {
        Write-LogMessage -MSG "Adding User to Auditors group, will be removed later on."
        #Get the Auditor Group ID
    
        $GetUserGroupsResponse = Invoke-RestMethod -Method Get -Uri $URL_UsersGroups -Headers $s_pvwaLogonHeader -ContentType "application/json" -TimeoutSec 2700
        $i = 0
        foreach ($userGroup in $GetUserGroupsResponse)
        {
            if ($userGroup.value.groupname[$i] -eq "Auditors") { $global:GetUserGroupsId = $userGroup.value.id[$i] }
            $i += 1
        }
        #Add User to Auditors Group.
        $body = @{MemberId = "" + $s_BuiltInAdminUsername + "" } | ConvertTo-Json -Compress
        $SetGroupResponse = $null
        Try
        {
            $SetGroupResponse = Invoke-RestMethod -Method Post -Uri ($URL_UserSetGroup -f $GetUserGroupsId) -Headers $s_pvwaLogonHeader -Body $body -ContentType "application/json" -TimeoutSec 2700
        }
        Catch
        {
            Write-LogMessage -type Error -MSG $_.Exception.Response.StatusDescription
            Write-LogMessage -type Error -MSG $_.ErrorDetails.Message
        }
        #if we get a some response we proceed to save the status of the user in a variable and a local file.
        if ($null -ne $SetGroupResponse)
        {
            #Save the Status of user in group or not and store it in a file in case the script was stopped.
            $parameters = @{IsUserInAuditGroup = "False" }
            $parameters | Export-Clixml -Path $CONFIG_PARAMETERS_FILE -Encoding ASCII
        }
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Extract-AuditorsGroup
# Description....: Check if user belongs to Auditors Group and if not, remove itself from it.
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Extract-AuditorsGroup()
{
    param($adminusername)
    # if $IsUserInAuditGroup is empty, it means the script was interrupted, we need to check the .ini file.
    if ($null -eq $IsUserInAuditGroup)
    {
        $parameters = Import-Clixml -Path $CONFIG_PARAMETERS_FILE
        $global:IsUserInAuditGroup = $parameters.IsUserInAuditGroup
    }
    # Check if use was in auditor group then do nothing, else we remove it.
    Write-LogMessage -MSG "Checking if user was in Auditors group."
    if ($IsUserInAuditGroup -eq "True")
    {
        Write-LogMessage -MSG "User was already part of the Auditor group, skipping..."
    }
    Else
    {
        Write-LogMessage -MSG "Removing user from Auditors group as it wasn't there on the initial run."
        Try
        {
            $body = @{MemberId = "" + $s_BuiltInAdminUsername + "" } | ConvertTo-Json -Compress
            $SetGroupResponse = Invoke-RestMethod -Method Delete -Uri ($URL_UserDelGroup -f $GetUserGroupsId, $adminusername) -Headers $s_pvwaLogonHeader -Body $body -ContentType "application/json" -TimeoutSec 2700
        }
        Catch
        {
            Write-LogMessage -type Error -MSG $_.Exception.Response.StatusDescription
            Write-LogMessage -type Error -MSG $_.ErrorDetails.Message
        }
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: VerifyComponentExists
# Description....: Check if Component/Platform exists in PVWA
# Parameters.....: Uri, ComponentType
# Return Values..: Rest Value
# =================================================================================================================================
Function VerifyComponentExists
{
    Param($Uri, $ComponentName)

    Write-LogMessage -type Info -MSG "Checking if: `"$ComponentName`" exists." 
    Try
    {
        $global:VerifyComponentExists = Invoke-RestMethod -Uri $Uri -Headers $s_pvwaLogonHeader -Method Get -TimeoutSec 2700
    }
    Catch
    {
        $_.exception
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Read-File
# Description....: Reads a local file and converts it to bytes, then encodes with base64
# Parameters.....: File_Path
# Return Values..: Base64 String
# =================================================================================================================================
Function Read-File
{
    param($File_Path)
    Write-LogMessage -type Info -MSG "Reading file `"$File_Path`" and converting it to Base64 for upload."
    try
    {
        $Input_File = ([IO.File]::ReadAllBytes($File_Path))
        $Input_File = [Convert]::ToBase64String($Input_File)
    }
    catch
    {
        Write-LogMessage -type Error -MSG "Failed to read file `"$File_Path`", check file exists."
        Write-LogMessage -type Error -MSG $_.exception
        exit
    }
    return $Input_File
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Import
# Description....: Imports the component into PVWA
# Parameters.....: 
# Return Values..: 
# =================================================================================================================================
Function Import
{
    param($Input_File, $URL_Import, $ComponentName)
    Write-LogMessage -type Info -MSG "Start importing $ComponentName..."
    $restBody = @{ ImportFile = $Input_File } | ConvertTo-Json -Depth 3 -Compress
        
    Try
    {
        $restResult = Invoke-RestMethod -Uri $URL_Import -Header $s_pvwaLogonHeader -Method Post -Body $restBody -ContentType "application/json"
    }
    Catch
    {
        Write-LogMessage -type Error -MSG "$($Error[0])"
        Write-LogMessage -type Error -MSG $_.exception
    }
    if ($restResult -ne $null)
    {
        Write-LogMessage -type Success -MSG "Finished importing $ComponentName successfully."
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: VerifyAccount
# Description....: Searches an account is exists in the Vault
# Parameters.....: 
# Return Values..: AccountId
# =================================================================================================================================
Function VerifyAccount
{
    Param($Uri, $AdminUsername)
    $errors = @()
    $SearchFilter = "?searchType=startswith&limit=5&search=$AdminUsername"
    Write-LogMessage -type Info -MSG "Checking if: `"$AdminUsername`" exists." 
    Try
    {
        $global:VerifyAccount = Invoke-RestMethod -Uri ($Uri + $SearchFilter) -Headers $s_pvwaLogonHeader -Method Get -TimeoutSec 2700
    }
    Catch
    {
        Write-LogMessage -type Error -MSG "$($Error[0])"
        Write-LogMessage -type Error -MSG $_.exception
    }

    if ($VerifyAccount.value.userName -eq $AdminUsername)
    {
        Write-LogMessage -type Info -MSG "Account already exists! will check if it's in healthy status"
        #Get dates to compare how old is the account.
        $AcctUnixTimeLastModified = $((([System.DateTimeOffset]::FromUnixTimeSeconds($VerifyAccount.value.SecretManagement.lastModifiedTime)).DateTime).toString("d"))
        $AcctUnixTimeCreatedTime = $((([System.DateTimeOffset]::FromUnixTimeSeconds($VerifyAccount.value.createdTime)).DateTime).toString("d"))
        $CurrentUnixTime = (Get-Date)
        if ($VerifyAccount.value.SecretManagement.automaticManagementEnabled -eq "true")
        {
            Write-LogMessage -type Success -MSG "The account has `"Allow automatic password management`" enabled!"
            if ($VerifyAccount.value.SecretManagement.status -eq "success")
            {
                Write-LogMessage -type Success -MSG "Latest password change/verify attempt was a `"success`""
            }
            Elseif (($AcctUnixTimeCreatedTime -le $CurrentUnixTime.ToString("d") -and ($null -eq $VerifyAccount.value.SecretManagement.status)))
            {
                $errors += "Detected account was only recently onboarded but no attempt at change/verify password was made, please check the account and attempt password change/verify and rerun the script to confirm."
            }
            Else
            {
                $errors += "Password change/verify attempt was never triggered or didn't return a `"success`", find the account in the portal and check, once password is changed/verified you can rerun the script to confirm."
            }
        }
        Else
        {
            $errors += "The account has `"Allow automatic password management`" disabled which prevents CPM from changing/verifying the account, please check account status and enable password management."
        }
        if ($null -ne $errors)
        {
            Write-LogMessage -type Error -MSG "Detected issues with the account, please fix below:"
            foreach ($err in $errors)
            {
                Write-LogMessage -type Error -MSG $err
            }
            Pause
            Exit
        }
        Else
        {
            Write-LogMessage -type Info -MSG "Account is onboarded and no issues found! You're all set." -Header
        }
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LDAPVaultAdmins
# Description....: Search Vault Directory and mappings for LDAP Admin groups
# Parameters.....: 
# Return Values..: LDAP Admin Groups
# =================================================================================================================================
Function Get-LDAPVaultAdmins
{
    Param($Uri)

    $MappingAuthorizations = @("AddUpdateUsers", "AddSafes", "AddNetworkAreas", "ManageServerFileCategories", "AuditUsers", "ResetUsersPasswords", "ActivateUsers")
    
    Write-LogMessage -type Info -MSG "Getting LDAP Vault Group"
    Try
    {
        $global:Directory = Invoke-RestMethod -Uri $Uri -Headers $s_pvwaLogonHeader -Method Get -TimeoutSec 2700
        foreach ($dir in $Directory)
        {
            $Mappings = Invoke-RestMethod -Uri ($URL_VaultMappings -f $($dir.DomainName)) -Headers $s_pvwaLogonHeader -Method Get -TimeoutSec 2700
            $global:LDAPVaultAdmins = $Mappings | Where-Object { !(Compare-Object -ReferenceObject $MappingAuthorizations -DifferenceObject $_.MappingAuthorizations) }
            $global:DirNames += $dir.DomainName
        }
    }
    Catch
    {
        Write-LogMessage -type Error -MSG "$($Error[0])"
        Write-LogMessage -type Error -MSG $_.exception
    }
    if ($LDAPVaultAdmins -eq $null)
    {
        Write-LogMessage -type Error -MSG "Failed to Identify external LDAP groups (needed for granting safe permissions)."
        Pause
        Exit
    }
}


# @FUNCTION@ ======================================================================================================================
# Name...........: Get-CPMName
# Description....: Check System health and find a connected CPM to use for Safe Creation
# Parameters.....: 
# Return Values..: FirstCPM
# =================================================================================================================================
Function Get-CPMName
{
    Param($Uri)
    
    Write-LogMessage -type Info -MSG "Getting valid CPM so we can bind it to a new Safe."
    Try
    {
        $GetSystemHealthResponse = Invoke-RestMethod -Uri ($URL_SystemHealthComponent -f "CPM") -Headers $s_pvwaLogonHeader -Method Get -TimeoutSec 2700
        $global:FirstCPM = ($GetSystemHealthResponse.ComponentsDetails | Where-Object { $_.IsLoggedOn -eq 'True' }).ComponentUserName
    }
    Catch
    {
        Write-LogMessage -type Error -MSG ("Cannot get '$GetSystemHealthResponse' status. Error: $($_.Exception.Response.StatusDescription)", $_.Exception)
    }
    if ($FirstCPM.count -eq 0)
    {
        Write-LogMessage -type Error -MSG "Couldn't find a healthy CPM to use for Safe creation, check CPM service is running and appears online in SystemHealth and rerun the script."
        Pause
        Exit
    }
    Else
    {
        Write-LogMessage -type Success -MSG "Found valid CPM $FirstCPM"
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-SafeNCreate
# Description....: Checks if a safe exists, bound to platform and have right permissions, otherwise creates it and grants permissions.
# Parameters.....: 
# Return Values..: SafeId
# =================================================================================================================================
Function Get-SafeNCreate
{
    Param($SafeName, $FirstCPM)

    $SafeProperties = @{
        "SafeName"                 = "$SafeName";
        "Description"              = "CyberArk BuiltIn Admin safe.";
        "ManagingCPM"              = $FirstCPM;
        "numberOfVersionRetention" = "2";
        #"numberOfDaysRetention" = "1";
    }

    #Check if Safe exists first
    Write-LogMessage -type Info -MSG "Checking if Safe: `"$SafeName`" exists."
    Try
    {
        $global:VerifySafeExists = Invoke-RestMethod -Uri ($URL_SafeFind -f $SafeName) -Headers $s_pvwaLogonHeader -Method Get -TimeoutSec 2700
        if ($VerifySafeExists.SearchSafesResult.Count -gt 0)
        {
            #Safe found, let's check permissions
            Write-LogMessage -type Info -MSG "Safe already exists, skipping."

        }
        Else
        {
            #Create Safe
            Write-LogMessage -type Info -MSG "Safe doesn't exist, will create it."
            $CreateNewSafe = Invoke-RestMethod -Uri $URL_Safes -Headers $s_pvwaLogonHeader -Method Post -TimeoutSec 2700 -Body $SafeProperties
            #Grant Safe permissions, need to account for multiple LDAP domains to find all LDAP Vault group admins.
            Write-LogMessage -type Info -MSG "Granting safe permissions."
            foreach ($ldap in $LDAPVaultAdmins)
            {
                $SafePermissions = @{
                    "MemberName"  = $($ldap.DomainGroups)#.replace("{}","")
                    "Permissions" = @{
                        "UseAccounts"                            = "true";
                        "RetrieveAccounts"                       = "true";
                        "ListAccounts"                           = "true" ;
                        "AddAccounts"                            = "true" ;
                        "UpdateAccountContent"                   = "true" ;
                        "UpdateAccountProperties"                = "true" ;
                        "InitiateCPMAccountManagementOperations" = "true" ;
                        "SpecifyNextAccountContent"              = "true" ;
                        "RenameAccounts"                         = "true" ;
                        "DeleteAccounts"                         = "true" ;
                        "UnlockAccounts"                         = "true" ;
                        "ManageSafe"                             = "true" ;
                        "ManageSafeMembers"                      = "true" ;
                        "ViewAuditLog"                           = "true" ;
                        "ViewSafeMembers"                        = "true" ;
                        "AccessWithoutConfirmation"              = "true" ;
                        "RequestsAuthorizationLevel1"            = "true" ;
                        "MoveAccountsAndFolders"                 = "true" ;
                    }
                }
                $CreateSafeAddMember = Invoke-RestMethod -Uri ($URL_SafeAddMembers -f $SafeName) -Headers $s_pvwaLogonHeader -Method Post -TimeoutSec 2700 -Body ($SafePermissions | ConvertTo-Json -Depth 5) -ContentType "application/json"
            }
            
        }
    }
    Catch
    {
        Write-LogMessage -type Error -MSG "$($Error[0])"
        Write-LogMessage -type Error -MSG $_.exception
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Create-Account
# Description....: Create Account in safe
# Parameters.....: 
# Return Values..: 
# =================================================================================================================================
Function Create-Account
{
    Param($Uri, $AdminUsername, $address, $safeName, $subdomain)
    Write-LogMessage -type Info -MSG "Creating account `"$AdminUsername`""     
   
    $AccBody = @{
        "Name"                      = "$($AdminUsername)_BuiltInAdmin"
        "Address"                   = $address
        "Username"                  = $AdminUsername
        "SafeName"                  = $safeName
        "PlatformID"                = $PlatformID
        "secretType"                = "password"
        "secret"                    = ($creds.GetNetworkCredential().password)
        "PlatformAccountProperties" = @{
            "PSMRemoteMachine" = $subdomain
        }
        "SecretManagement"          = @{
            "automaticManagementEnabled" = "true";
        }
    }
    Try
    {
        $global:GetAccountResponse = Invoke-RestMethod -Uri $URL_Accounts -Headers $s_pvwaLogonHeader -Method Post -TimeoutSec 2700 -ContentType "application/json" -Body ($AccBody | ConvertTo-Json)
    }
    Catch
    {
        Write-LogMessage -type Error -MSG "$($Error[0])"
        Write-LogMessage -type Error -MSG $_.exception
    }
    if ($GetAccountResponse.userName -eq $AdminUsername)
    {
        Write-LogMessage -type Success -MSG "Successfully created account, see output:"
        $GetAccountResponse
        Write-Host ""
        Write-Host ""
        #This will happen because platform is set to verifyonadd = yes
        Write-LogMessage -type Info -MSG "Sending account for password **verification**, please wait at least 2 mins and then check the account in the portal if it was successfully verified."
    }
    $creds = $null
    $AccBody = $null
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Update-ZipWithNewChrome
# Description....: Updates the zip file with BrowserPath entry
# Parameters.....: File_Path, BrowserPath
# Return Values..: 
# =================================================================================================================================
Function Update-ZipWithNewChrome
{
    Param($file_path, $BrowserPath)

    Write-LogMessage -type Info -MSG "Detected non 32bit chrome is installed, will update PSM CC before importing it to PVWA."
    Try
    {
        $Package = Get-Item -Path $File_Path
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        # Extract ZIP to temp folder logic
        $tempFolder = Join-Path -Path $Package.Directory -ChildPath $Package.BaseName
    
        #Remove folder if it exists already before unzipping 
        if (Test-Path $tempFolder)
        {
            Remove-Item -Recurse $tempFolder -Force
        }	
        #Unzip to temp folder
        [System.IO.Compression.ZipFile]::ExtractToDirectory($Package.FullName, $tempFolder)
    
        # Find all XML files in the ConnectionComponent ZIP
        $fileEntries = Get-ChildItem -Path $tempFolder -Filter '*.xml'
    
        #Read XML file
        [xml]$xmlContent = Get-Content $fileEntries[0].FullName
        #Add custom Chrome Path
        $xmlContent.ConnectionComponent.TargetSettings.ClientSpecific.InnerXml += "<Parameter Name='BrowserPath' Value='$BrowserPath'/>"
        $xmlContent.Save($fileEntries[0].FullName)

        #Zip the file back again.
        $UpdateZip = [System.IO.Compression.ZipFile]::Open($file_path, [System.IO.Compression.ZipArchiveMode]::Update)
        #If the file already contains the customer entry, delete it since we are importing it again.
        Try
        {
            foreach ($entry in ($UpdateZip.Entries | Where-Object { $_.Name -eq $fileEntries[0].Name }))
            {
                $UpdateZip.Entries[3].Delete()
            }
        }
        Catch {}
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($UpdateZip, $fileEntries[0].FullName, $fileEntries[0].Name) | Out-Null
        $UpdateZip.Dispose()
    
        #Delete temporary File
        Remove-Item $tempFolder -Recurse
    }
    Catch
    {
        Write-LogMessage -type Error -MSG $_.Exception
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-PSMName
# Description....: Get a list of all PSMs and use the first one to bind to Platform.
# Parameters.....: 
# Return Values..: FirstPSM
# =================================================================================================================================
Function Get-PSMName
{
    
    Write-LogMessage -type Info -MSG "Getting valid PSM so we can bind it to platform."
    Try
    {
        $response = Invoke-RestMethod -Uri $URL_GetAllPSMs -Headers $s_pvwaLogonHeader -Method Get -TimeoutSec 2700
        
        return ($response.PSMServers.ID[0])
    }
    Catch
    {
        Write-LogMessage -type Error -MSG $_.Exception
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: UpdatePlatformPSM
# Description....: Update the platform and add a healthy PSM instead of "PSMServer" default PSM.
# Parameters.....: 
# Return Values..: 
# =================================================================================================================================
Function UpdatePlatformPSM
{
    param($FirstPSM)
    
    $Body = @"
{
    "PSMServerId" : "$FirstPSM",
    "PSMServerName" : "$FirstPSM",
        "PSMConnectors" :  [
            {
                "PSMConnectorId" : "$PSMCCID",
                "Enabled" : "true"
            },
            {
                "PSMConnectorId" : "$PSMCCDiscID",
                "Enabled" : "true"
            }
      ]        
    }
"@
    
    Try
    {
        $allplatformsresponse = Invoke-RestMethod -Method Get -Uri $URL_PlatformsFindAll -Headers $s_pvwaLogonHeader
        $PlatformNumId = $allplatformsresponse.Platforms | Where-Object { $_.platformid -eq $PlatformID } | Select-Object -ExpandProperty ID
        
        Write-LogMessage -type Info -MSG "Updating Platform with valid PSM instance."
        
        $response = Invoke-RestMethod -Uri ($URL_PlatformUpdatePSM -f $PlatformNumId) -Headers $s_pvwaLogonHeader -Method Put -ContentType "application/json" -Body $Body -TimeoutSec 2700
    }
    Catch
    {
        Write-LogMessage -type Error -MSG $_.Exception
    }
}

Function ConvertTo-URL($sText)
{
    <# 
.SYNOPSIS 
	HTTP Encode test in URL
.DESCRIPTION
	HTTP Encode test in URL
.PARAMETER sText
	The text to encode
#>
    if (![string]::IsNullOrEmpty($sText))
    {
        Write-Debug "Returning URL Encode of $sText"
        return [URI]::EscapeDataString($sText)
    }
    else
    {
        return $sText
    }
}



# ------------------------------------------------------------
# Script Begins Here
If ($(Test-AdminUser) -eq $False)
{
    Write-LogMessage -Type Error -Msg "You must be logged on as a local administrator in order to run this script."
    Pause
    Exit
}


#Check all relevant files exist in the same folder as the script.
[array]$Prerequisitefiles = @{PSMCC = "PSM-PVWA-v122.zip" }, @{PSMCCDisc = "PSM-PVWA-v122-Disc.zip" }, @{CyberArkPrivCloudPlatform = "CyberArkPrivCloud.zip" }
foreach ($file in $Prerequisitefiles)
{
    if (-not(Test-Path "$PSScriptRoot\$($file.values)"))
    {
        Write-Warning "Missing prerequisite file: `"$($file.values)`" please download it and run script again."
        Pause
        #Exit
    }
}

#Cleanup log file if it gets too big
if (Test-Path $LOG_FILE_PATH)
{
    if (Get-ChildItem $LOG_FILE_PATH -File | Where-Object { $_.Length -gt 400KB })
    {
        Write-LogMessage -type Info -MSG "Log file is getting too big, deleting it."
        Remove-Item $LOG_FILE_PATH -Force
    }

}

Write-LogMessage -type Info -MSG "Starting Onboard BuiltIn Admin Script." -Header
# Check latest version
$gitHubLatestVersionParameters = @{
    currentVersion        = $ScriptVersion;
    repositoryName        = "pCloudServices/OnboardBuiltInAdmin";
    scriptVersionFileName = "PrivCloud_OnboardBuiltInAdminAcc.ps1";
    sourceFolderPath      = $PSScriptRoot;
    
    # More parameters that can be used
    # repositoryFolderPath = "FolderName";
    # branch = "main";
    # versionPattern = "ScriptVersion";
}

If (! $SkipVersionCheck)
{
    try
    {
        Write-LogMessage -type Info -Msg "Current script version $ScriptVersion"
        $isLatestVersion = $(Test-GitHubLatestVersion @gitHubLatestVersionParameters)
        If ($isLatestVersion -eq $false)
        {
            # Skip the version check so we don't get into a loop
            $scriptPathAndArgs = "`& `"$PSScriptRoot\PrivCloud-OnboardBuiltInAdminAcc.ps1`" -SkipVersionCheck"
            Write-LogMessage -type Info -Msg "Finished Updating, relaunching the script."
            # Run the updated script
            Invoke-Expression $scriptPathAndArgs
            # Exit the current script
            return
        }
    }
    catch
    {
        Write-LogMessage -type Error -Msg "Error checking for latest version. Error: $(Join-ExceptionMessage $_.Exception)"
    }
}

try
{
    #Check if any CYBR components installed before proceeding
    $detectedComponent = $(Find-Components -Component "All" -FindOne)
    If (($null -ne $detectedComponent) -and ($detectedComponent.Name.Count -gt 0))
    {
        # Set PVWA URL
        $detectedComponent.InitPVWAURL

        # Set BuiltInAdmin Username, (in the future, maybe we'll want to onboard multiple accounts)
        $script:s_BuiltInAdminUsername = ([System.Uri]$URL_PVWA).host.split(".")[0] + "_admin"
        $decision = Get-Choice -Title "Confirm User: `"$s_BuiltInAdminUsername`"" -Options "Yes", "No, let me type it" -DefaultChoice 1
        if ($decision -eq "Yes")
        {
            Write-LogMessage -type Info -MSG "Confirmed user: $s_BuiltInAdminUsername"
        }
        else
        {
            $script:s_BuiltInAdminUsername = (Read-Host "Enter your CyberArk BuiltIn Admin Username").Trim()
        }
        
        # Login
        Invoke-Logon

        # Check if in Auditors Group and add yourself.
        Write-LogMessage -type Info -MSG "START Auditor Flow" -SubHeader
        Insert-AuditorsGroup
        Write-LogMessage -type Info -MSG "START Import Plugins Flow" -SubHeader
        # Import CC and Bind it to Platform
        Foreach ($psmcomp in @($PSMCCID, $PSMCCDiscID))
        {
            VerifyComponentExists -Uri ($URL_ConnectionComponentVerify -f $psmcomp) -ComponentName $psmcomp
            if ($VerifyComponentExists.ConnectionComponentID -eq $psmcomp)
            {
                Write-LogMessage -type Success -MSG "Verified `"$psmcomp`" exists."
            }
            Else
            {
                $File_Path = "$PSScriptRoot\$psmcomp.zip"
                # Check if Chrome exists and path32/64 and adjust it in the file.
                $actualChromePath = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty `(default`)
                if ($DefaultChromePath -ne $actualChromePath)
                {
                    Update-ZipWithNewChrome -file_path $File_Path -BrowserPath $actualChromePath
                }
                Write-LogMessage -type Info -MSG "`"$psmcomp`" doesn't exist, will attempt to import it..."
                $Input_File = $(Read-File -File_Path $File_Path)
                Import -Input_File $Input_File -URL_Import $URL_ConnectionComponentImport -ComponentName $psmcomp
            }
        }
        # Import CyberArk platform if it doesn't exist
        VerifyComponentExists -Uri ($URL_PlatformVerify -f $PlatformID) -ComponentName $PlatformID
        if ($VerifyComponentExists.platformID -eq $platformID)
        {
            Write-LogMessage -type Success -MSG "Verified `"$PlatformID`" exists."
        }
        Else
        {
            Write-LogMessage -type Info -MSG "`"$PlatformID`" doesn't exist, will attempt to import it..."
            $File_Path = "$PSScriptRoot\$($Prerequisitefiles.CyberArkPrivCloudPlatform)"
            $Input_File = $(Read-File -File_Path $File_Path)
            Import -Input_File $Input_File -URL_Import $URL_PlatformImport -ComponentName $PlatformID
            UpdatePlatformPSM -FirstPSM $(Get-PSMName)
        }
        Write-LogMessage -type Info -MSG "FINISH Import Plugins Flow" -SubHeader
        #Onboard Account
        Write-LogMessage -type Info -MSG "START Onboarding Flow" -SubHeader
        VerifyAccount -Uri $URL_Accounts -AdminUsername $s_BuiltInAdminUsername
        #Check if in need to remove yourself from Auditors group.
        Extract-AuditorsGroup -adminusername $s_BuiltInAdminUsername
        Write-LogMessage -type Info -MSG "FINISH Auditor Flow" -SubHeader
        if ($VerifyAccount.value.userName -ne $s_BuiltInAdminUsername)
        {
            Write-LogMessage -type Info -MSG "Not Found Account `"$s_BuiltInAdminUsername`" will now attempt onboarding it to platform `"$PlatformID`""
            #Get Healthy CPM
            Get-CPMName -Uri ($URL_SystemHealthComponent -f "CPM")
            Get-LDAPVaultAdmins -Uri $URL_DomainDirectories
            Get-SafeNCreate -Uri $URL_Safes -SafeName ($SafeName -f "TestBuiltint01") -FirstCPM $FirstCPM
            Create-Account -Uri $URL_Accounts -AdminUsername $s_BuiltInAdminUsername -address "vault-$subdomain.privilegecloud.cyberark.com" -safeName ($SafeName -f "TestBuiltint01") -subdomain $subdomain
            Write-LogMessage -type Info -MSG "FINISH Onboarding Flow" -SubHeader
        }
        #Logoff
        Invoke-Logoff
    }
    else
    {
        Write-LogMessage -Type Warning -MSG "There were no CyberArk components found on this machine, please execute the script from CyberArk machine to ensure proper connectivity."
    }
}
catch
{
    Write-LogMessage -type Error -Msg "There was an error running the script. Error $(Join-ExceptionMessage $_.Exception)"
}