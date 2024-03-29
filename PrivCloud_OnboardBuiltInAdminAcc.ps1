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
$ScriptVersion = "1.9"
$debug = $false

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
        $maskingPattern = '(?:(?:["\s\/\\](secret|NewCredentials|credentials|answer)(?!s))\s{0,}["\:= ]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()\-_\=\+\\\/\|\,\;\:\.\[\]\{\}]+))'
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
            if ($outGitHubVersion -ne $null)
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
            Write-LogMessage -type Info -MSG "Test-ScriptLatestVersion: Couldn't match Script Version pattern ($versionPattern)"
        }
    }
    catch
    {
        Write-LogMessage -type Info -MSG ("Test-ScriptLatestVersion: Couldn't download and check for latest version", $_.Exception)
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
        Write-LogMessage -type Info -MSG ("Test-GitHubLatestVersion: Couldn't check for latest version $($_.Exception.Message)")
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
        Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.ErrorDetails.Message)"))
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
        if ($debug)
        {
            $script:s_pvwaLogonHeader = @{ Authorization = "MyToken" }
        }
        else 
        {    
            $script:s_pvwaLogonHeader = Get-LogonHeader -Credentials $creds
        }
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
            if ($m_ServiceList -eq $null)
            {
                Set-Variable -Name m_ServiceList -Value $(Get-ChildItem "HKLM:\System\CurrentControlSet\Services" | ForEach-Object { Get-ItemProperty $_.pspath }) -Scope Script
                #$m_ServiceList = Get-Reg -Hive "LocalMachine" -Key System\CurrentControlSet\Services -Value $null
            }
            $regPath = $m_ServiceList | Where-Object { $_.PSChildName -eq $ServiceName }
            If ($regPath -ne $null)
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
        [ValidateSet("CPM", "PSM", "Debug")]
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
            if ($ComponentID -eq "Debug")
            {
                $PVWAurl = "https://myPVWA.mydomain.com/PasswordVault"
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
    $script:URL_PlatformsFindAll = $URL_PVWAAPI+"/platforms/targets"
    $script:URL_ConnectionComponentVerify = $URL_PVWAAPI + "/ConnectionComponents/{0}"
    $script:URL_ConnectionComponentImport = $URL_PVWAAPI + "/ConnectionComponents/Import"
    $script:URL_PlatformUpdatePSM = $URL_PVWAAPI+"/Platforms/Targets/{0}/PrivilegedSessionManagement"
    $script:URL_GetAllPSMs = $URL_PVWAAPI + "/PSM/Servers"
    $script:URL_SystemHealthComponent = $URL_PVWAAPI + "/ComponentsMonitoringDetails/{0}"
    $script:URL_DomainDirectories = $URL_PVWAAPI + "/Configuration/LDAP/Directories"
    $script:URL_VaultMappings = $URL_PVWAAPI + "/Configuration/LDAP/Directories/{0}/mappings"
    $script:URL_VaultVersion = $URL_PVWAPasswordVault + "/WebServices/PIMServices.svc/Server"
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
        [ValidateSet("All", "CPM", "PSM", "Debug")]
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
                "Debug"
                {
                    if ($debug)
                    {
                        try
                        {
                            # Check if PSM is installed
                            Write-LogMessage -Type "Debug" -MSG "Searching for Debug..."
    
                            Write-LogMessage -Type "Info" -MSG "Found Debug installation."
                            $PSMPath = "C:\Temp"
                            $ConfigPath = (Join-Path -Path $PSMPath -ChildPath "temp\PVConfiguration.xml")
                            $myObject = New-Object PSObject -Property @{
                                Name        = "Debug"; 
                                DisplayName = "Debug";
                                Path        = $PSMPath;
                                ConfigPath  = $ConfigPath;
                            }
                            $myObject | Add-Member -MemberType ScriptMethod -Name InitPVWAURL -Value { Set-PVWAURL -ComponentID $this.Name -ConfigPath $this.ConfigPath -AuthType "cyberark" } | Out-Null
                            return $myObject
                            
                        }
                        catch
                        {
                            Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
                        }
                    }
                    break
                }
                "All"
                {
                    try
                    {
                        ForEach ($comp in @("CPM", "PSM", "Debug"))
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

    $SearchUserURL = $URL_Users + "?filter==UserName&search=$s_BuiltInAdminUsername"

    #Find our user
    Try
    {
        $GetUsersResponse = Invoke-RestMethod -Method Get -Uri $SearchUserURL -Headers $s_pvwaLogonHeader -ContentType "application/json" -TimeoutSec 2700
    }
    Catch
    {
        Throw $_.exception
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
                break
            }
            $i += 1
        }
    }
    Else
    {
        $BuiltIndAdminUserId = $GetUsersResponse.users.id
    }
    Try{
    #Get Auditor Group and search if user exists in it. - 12.2
    $SearchGroupURL = $URL_UsersGroups + "?filter=groupName eq Auditors&includeMembers=True"
    $GetAuditorsGroupResponse = Invoke-RestMethod -Method Get -Uri ($SearchGroupURL) -Headers $s_pvwaLogonHeader -TimeoutSec 2700

    #get Username Details and check if it has Auditors group - 11.7
    $GetUserDetailsResponse = Invoke-RestMethod -Method Get -Uri ($URL_UserExtendedDetails -f $BuiltIndAdminUserId) -Headers $pvwaLogonHeader -ContentType "application/json" -TimeoutSec 2700
    }
    Catch{

    }

    #Check if User is inside Auditors Group
    if (($GetAuditorsGroupResponse.value.members.username -contains $s_BuiltInAdminUsername) -or ($GetUserDetailsResponse.groupsMembership.groupName -contains "Auditors"))
    {
        Write-LogMessage -MSG "User is already part of Auditors Group, skipping..."
        #Save the Status of user in group or not and store it in a file in case the script was stopped.
        $parameters = @{IsUserInAuditGroup = "True" }
        if(-not(Test-Path $CONFIG_PARAMETERS_FILE)){
        $parameters | Export-Clixml -Path $CONFIG_PARAMETERS_FILE -NoClobber -Encoding ASCII -Force
        }
    }
    Else
    {
        Write-LogMessage -MSG "Adding User to Auditors group, will be removed later on."
        #Get the Auditor Group ID
    
        $GetUserGroupsResponse = Invoke-RestMethod -Method Get -Uri $URL_UsersGroups -Headers $s_pvwaLogonHeader -ContentType "application/json" -TimeoutSec 2700
        $i = 0
        foreach ($userGroup in $GetUserGroupsResponse)
        {
            if($userGroup.value.groupname[$i] -eq "Auditors")
            {
             $global:GetUserGroupsId = $userGroup.value.id[$i]
             break
            }
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
        if ($SetGroupResponse -ne $null)
        {
            #Save the Status of user in group or not and store it in a file in case the script was stopped.
            $parameters = @{IsUserInAuditGroup = "False" }
            if(-not(Test-Path $CONFIG_PARAMETERS_FILE)){
            $parameters | Export-Clixml -Path $CONFIG_PARAMETERS_FILE -NoClobber -Encoding ASCII -Force
            }
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
    $parameters = Import-Clixml -Path $CONFIG_PARAMETERS_FILE
    $IsUserInAuditGroup = ($parameters.Values)
    # Check if use was in auditor group then do nothing, else we remove it.
    Write-LogMessage -MSG "Checking if user was in Auditors group."
    if($IsUserInAuditGroup -eq "True")
    {
        Write-LogMessage -MSG "User was already part of the Auditor group, skipping..."
    }
    Else
    {
        Write-LogMessage -MSG "Removing user from Auditors group as it wasn't there on the initial run."
        $GetUserGroupsResponse = Invoke-RestMethod -Method Get -Uri $URL_UsersGroups -Headers $s_pvwaLogonHeader -ContentType "application/json" -TimeoutSec 2700
        $i = 0
        foreach ($userGroup in $GetUserGroupsResponse)
        {
            if($userGroup.value.groupname[$i] -eq "Auditors")
            {
             $global:GetUserGroupsId = $userGroup.value.id[$i]
             break
            }
            $i += 1
        }
        Try
        {
            $SetGroupResponse = Invoke-RestMethod -Method Delete -Uri ($URL_UserDelGroup -f $GetUserGroupsId, $adminusername) -Headers $s_pvwaLogonHeader -TimeoutSec 2700
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
        if ($debug)
        {
            Write-LogMessage -type Info "Invoke-RestMethod -Uri $Uri -Method Get"
            return $true
        }
        else
        {
            return Invoke-RestMethod -Uri $Uri -Headers $s_pvwaLogonHeader -Method Get -TimeoutSec 2700
        }
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
        $restResult = Invoke-RestMethod -Uri $URL_Import -Headers $s_pvwaLogonHeader -Method Post -Body $restBody -ContentType "application/json"
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
        $_VerifyAccount = Invoke-RestMethod -Uri ($Uri + $SearchFilter) -Headers $s_pvwaLogonHeader -Method Get -TimeoutSec 2700
    }
    Catch
    {
        Write-LogMessage -type Error -MSG "$($Error[0])"
        Write-LogMessage -type Error -MSG $_.exception
    }
    $retAccountExists = $false
    if ($_VerifyAccount.value.userName -eq $AdminUsername)
    {
        Write-LogMessage -type Info -MSG "Account already exists! will check if it's in healthy status"
        Write-LogMessage -type Info -MSG "--------------------------------------------"
        Write-LogMessage -type Info -MSG "ObjectName: $($_VerifyAccount.value.Name)"
        Write-LogMessage -type Info -MSG "UserName: $($_VerifyAccount.value.userName)"
        Write-LogMessage -type Info -MSG "SafeName: $($_VerifyAccount.value.SafeName)"
        Write-LogMessage -type Info -MSG "Platform: $($_VerifyAccount.value.platformId)"
        Write-LogMessage -type Info -MSG "--------------------------------------------"
        $retAccountExists = $true
        #Get dates to compare how old is the account.
        $AcctUnixTimeCreatedTime = $((([System.DateTimeOffset]::FromUnixTimeSeconds($_VerifyAccount.value.createdTime)).DateTime).toString("d"))
        $CurrentUnixTime = (Get-Date)
        if ($_VerifyAccount.value.SecretManagement.automaticManagementEnabled -eq "true")
        {
            Write-LogMessage -type Success -MSG "The account has `"Allow automatic password management`" enabled!"
            if ($_VerifyAccount.value.SecretManagement.status -eq "success")
            {
                Write-LogMessage -type Success -MSG "Latest password change/verify attempt was a `"success`""
            }
            Elseif (($AcctUnixTimeCreatedTime -le $CurrentUnixTime.ToString("d") -and ($null -eq $_VerifyAccount.value.SecretManagement.status)))
            {
                $errors += "Account was only recently onboarded but no attempt at change/verify password was made, please check the account and attempt password change/verify and rerun the script to confirm."
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
        if ($errors -ne $null)
        {
            Write-Host $errors
            Write-LogMessage -type Error -MSG "Detected issues with the account, please fix below:"
            Write-LogMessage -type Error -MSG "----------------------------------------------------"
            foreach ($err in $errors)
            {
                Write-LogMessage -type Error -MSG "# $($err)"
            }
            Pause
            Exit
        }
        Else
        {
            Write-LogMessage -type Info -MSG "Account is onboarded and no issues found! You're all set." -Header
        }
    }

    return $retAccountExists
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
    $MappingAuthorizationsCustomFull = @("AddUpdateUsers", "AddSafes", "AddNetworkAreas", "ManageServerFileCategories", "AuditUsers", "ResetUsersPasswords", "ActivateUsers", "BackupAllSafes","RestoreAllSafes")
    
    Write-LogMessage -type Info -MSG "Getting LDAP Vault Group"
    Try
    {
        $global:Directory = Invoke-RestMethod -Uri $Uri -Headers $s_pvwaLogonHeader -Method Get -TimeoutSec 2700
        foreach ($dir in $Directory)
        {
            $Mappings += Invoke-RestMethod -Uri ($URL_VaultMappings -f $($dir.DomainName)) -Headers $s_pvwaLogonHeader -Method Get -TimeoutSec 2700
            $global:LDAPVaultAdmins = $Mappings | Where-Object { !(Compare-Object -ReferenceObject $MappingAuthorizations -DifferenceObject $_.MappingAuthorizations) -or  !(Compare-Object -ReferenceObject $MappingAuthorizationsCustomFull -DifferenceObject $_.MappingAuthorizations)}
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
    }
    Catch
    {
        Write-LogMessage -type Error -MSG ($_.Exception.Response.StatusDescription)
    }
    $AvailableCPMs = ($GetSystemHealthResponse.ComponentsDetails | Where-Object { $_.IsLoggedOn -eq 'True' }).ComponentUserName
    $global:FirstCPM = @($AvailableCPMs)[0]
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
				Write-LogMessage -type Info -MSG "LDAP group `"$($ldap.DomainGroups)`""
                $SafePermissions = @{
                    "MemberName"  = $($ldap.DomainGroups)
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
        Write-LogMessage -type Info -MSG "Sending account for password **verification**, pleast wait at least 2 mins and then check the account in the portal if it was successfully verified." -Header
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
        if ($xmlContent.ConnectionComponent.TargetSettings.ClientSpecific.Parameter.name -NotContains "BrowserPath")
        {
            $xmlContent.ConnectionComponent.TargetSettings.ClientSpecific.InnerXml += "<Parameter Name='BrowserPath' Value='$BrowserPath'/>"
        }
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
    #Write-LogMessage -type Info -MSG "Getting valid PSM so we can bind it to platform."
    Try
    {
        $response = Invoke-RestMethod -Uri $URL_GetAllPSMs -Headers $s_pvwaLogonHeader -Method Get -TimeoutSec 2700
        
        return @($response.PSMServers.ID)[0]
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
    
if($FirstPSM -ne $null)
{	
	
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
        
        Write-LogMessage -type Info -MSG "Updating Platform with valid PSM instance: `"$FirstPSM`"."
        
        $response = Invoke-RestMethod -Uri ($URL_PlatformUpdatePSM -f $PlatformNumId) -Headers $s_pvwaLogonHeader -Method Put -ContentType "application/json" -Body $Body -TimeoutSec 2700
    }
    Catch
    {
        Write-LogMessage -type Error -MSG $_.Exception
    }
}
    else
    {
        Write-LogMessage -type Info -MSG "Didn't find valid PSM to bind to platform, skipping..."
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
if (-not $debug)
{
    If ($(Test-AdminUser) -eq $False)
    {
        Write-LogMessage -Type Error -Msg "You must be logged on as a local administrator in order to run this script."
        Pause
        Exit
    }
}

#Check all relevant files exist in the same folder as the script.
[array]$Prerequisitefiles = @{PSMCC = "PSM-PVWA-v122.zip" }, @{PSMCCDisc = "PSM-PVWA-v122-Disc.zip" }, @{CyberArkPrivCloudPlatform = "CyberArkPrivCloud.zip" }
foreach ($file in $Prerequisitefiles.values)
{
    if (-not(Test-Path "$PSScriptRoot\$file"))
    {
        Write-Warning "Missing prerequisite file: `"$file`" please download it and run script again."
        $missingfiles = "true"
    }
}
    #After we display all missing files, exit the script.
    if($missingfiles -eq "true"){
        Pause
        Exit
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
            $scriptPathAndArgs = "`& `"$PSScriptRoot\PrivCloud_OnboardBuiltInAdminAcc.ps1`" -SkipVersionCheck"
            Write-LogMessage -type Info -Msg "Finished Updating, relaunching the script."
            # Run the updated script
            Invoke-Expression $scriptPathAndArgs
            # Exit the current script
            return
        }
    }
    catch
    {
        Write-LogMessage -type info -Msg "Error checking for latest version. Error: $($_.Exception.Message)"
    }
}

try
{
    #Check if any CYBR components installed before proceeding
    $detectedComponent = $(Find-Components -Component "All" -FindOne)
    $FindPSM = $(Find-Components -Component PSM)
    If (($null -ne $detectedComponent) -and ($detectedComponent.Name.Count -gt 0))
    {
        # Set PVWA URL
        $detectedComponent.InitPVWAURL()

        # Set BuiltInAdmin Username, (in the future, maybe we'll want to onboard multiple accounts)
        $script:s_BuiltInAdminUsername = ([System.Uri]$URL_PVWA).host.split(".")[0] + "_admin"
        $decision = Get-Choice -Title "Confirm User: `"$s_BuiltInAdminUsername`"" -Options "Yes", "No, let me type it" -DefaultChoice 1
        if ($decision -eq "Yes")
        {
            Write-LogMessage -type Info -MSG "Confirmed user: $s_BuiltInAdminUsername"
        }
        else
        {
            Write-LogMessage -type Info -MSG "User chose to insert custom username"
            $script:s_BuiltInAdminUsername = (Read-Host "Enter your CyberArk BuiltIn Admin Username").Trim()
        }
        
        # Login
        Invoke-Logon

        # Check if in Auditors Group and add yourself.
        Write-LogMessage -type Info -MSG "START Auditor Flow"
        Insert-AuditorsGroup
        Write-LogMessage -type Info -MSG "START Import Plugins Flow"
        # If PSM isn't installed, we skip the entire Connection Component Section
        If($FindPSM)
        {
            #Get Chrome Path and check if it's whitelisted in applocker, if not we skip this step until the user whitelists chrome.
            $actualChromePath = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty `(default`)
            $ChromeApplockerStatus = Try{Get-AppLockerPolicy -local | Test-AppLockerPolicy -path $actualChromePath -User PSMShadowUsers -Filter Denied -ErrorAction SilentlyContinue}Catch{}
            if(($ChromeApplockerStatus) -or -not($actualChromePath)){
                Write-LogMessage -type Warning -MSG "Chrome isn't whitelisted in machine Applocker, we highly recommend whitelisting chrome so you could connect through PSM with the account we onboard (more info in readme file)."
            }
            Else{
                # Import CC and Bind it to Platform
                Foreach ($psmcomp in @($PSMCCID, $PSMCCDiscID))
                {
                    $connectionCompExists = VerifyComponentExists -Uri ($URL_ConnectionComponentVerify -f $psmcomp) -ComponentName $psmcomp
                    if ($connectionCompExists.ConnectionComponentID -eq $psmcomp)
                    {
                        Write-LogMessage -type Success -MSG "Verified `"$psmcomp`" exists."
                    }
                    Else
                    {
                        $File_Path = "$PSScriptRoot\$psmcomp.zip"
                        #Check if Chrome exists and path32/64 and adjust it in the file.
                        if (($DefaultChromePath -ne $actualChromePath) -and ($actualChromePath -ne $null))
                        {
                            Update-ZipWithNewChrome -file_path $File_Path -BrowserPath $actualChromePath
                        }
                        Write-LogMessage -type Info -MSG "`"$psmcomp`" doesn't exist, will attempt to import it..."
                        $Input_File = $(Read-File -File_Path $File_Path)
                        Import -Input_File $Input_File -URL_Import $URL_ConnectionComponentImport -ComponentName $psmcomp
                    }
                }
            }
        }
        # Import CyberArk platform if it doesn't exist
        $platformExists = VerifyComponentExists -Uri ($URL_PlatformVerify -f $PlatformID) -ComponentName $PlatformID
        if ($platformExists.platformID -eq $platformID)
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
        Write-LogMessage -type Info -MSG "FINISH Import Plugins Flow"
        #Onboard Account
        Write-LogMessage -type Info -MSG "START Onboarding Flow"
        
        if ($(VerifyAccount -Uri $URL_Accounts -AdminUsername $s_BuiltInAdminUsername) -eq $False)
        {
            Write-LogMessage -type Info -MSG "Not Found Account `"$s_BuiltInAdminUsername`" will now attempt onboarding it to platform `"$PlatformID`""
            #Get Healthy CPM
            Get-CPMName -Uri ($URL_SystemHealthComponent -f "CPM")
            Get-LDAPVaultAdmins -Uri $URL_DomainDirectories
            Get-SafeNCreate -Uri $URL_Safes -SafeName ($SafeName -f $subdomain) -FirstCPM $FirstCPM
            Create-Account -Uri $URL_Accounts -AdminUsername $s_BuiltInAdminUsername -address "vault-$subdomain.privilegecloud.cyberark.com" -safeName ($SafeName -f $subdomain) -subdomain $subdomain
            Write-LogMessage -type Info -MSG "======================= FINISH Onboarding Flow ======================="
        }
        #Check if in need to remove yourself from Auditors group.
        Extract-AuditorsGroup -adminusername $s_BuiltInAdminUsername
        Write-LogMessage -type Info -MSG "======================= FINISH Auditor Flow ======================="
        
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
# SIG # Begin signature block
# MIIgTgYJKoZIhvcNAQcCoIIgPzCCIDsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDekbqGkHBfyT+u
# 22ceK0GD5yvP6JdA7MArAOToIvUg0qCCDl8wggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB28wggVXoAMCAQICDHBNxPwWOpXgXVV8
# DDANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjIwMjE1MTMzODM1WhcNMjUwMjE1MTMzODM1WjCB
# 1DEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEjAQBgNVBAUTCTUxMjI5
# MTY0MjETMBEGCysGAQQBgjc8AgEDEwJJTDELMAkGA1UEBhMCSUwxEDAOBgNVBAgT
# B0NlbnRyYWwxFDASBgNVBAcTC1BldGFoIFRpa3ZhMRMwEQYDVQQJEwo5IEhhcHNh
# Z290MR8wHQYDVQQKExZDeWJlckFyayBTb2Z0d2FyZSBMdGQuMR8wHQYDVQQDExZD
# eWJlckFyayBTb2Z0d2FyZSBMdGQuMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA8rPX6yAVM64+/qMQEttWp7FdAvq9UfgxBrW+R0NtuXhKnjV05zmIL6zi
# AS0TlNrQqu5ypmuagOWzYKDtIcWEDm6AuSK+QeZprW69c0XYRdIf8X/xNUawXLGe
# 5LG6ngs2uHGtch9lt2GLMRWILnKviS6l6F06HOAow+aIDcNGOukddypveFrqMEbP
# 7YKMekkB6c2/whdHzDQiW6V0K82Xp9XUexrbdnFpKWXLfQwkzjcG1xmSiHQUpkSH
# 4w2AzBzcs+Nidoon5FEIFXGS2b1CcCA8+Po5Dg7//vn2thirXtOqaC+fjP1pUG7m
# vrZQMg3lTHQA/LTL78R3UzzNb4I9dc8yualcYK155hRU3vZJ3/UtktAvDPC/ewoW
# thebG77NuKU8YI6l2lMg7jMFZ1//brICD0RGqhmPMK9MrB3elSuMLaO566Ihdrlp
# zmj4BRDCfPuH0QfwkrejsikGEMo0lErfHSjL3NaiE0PPoC4NW7nc6Wh4Va4e3VFF
# Z9zdnoTsCKJqk4s13MxBbjdLIkCcfknMSxAloOF9h6IhzWOylSROAy/TZfGL5kzQ
# qxzcIhdXLWHHWdbz4DD3qxYc6g1G3ZwgFPWf7VbKQU3FsAxgiJvmKPVeOfIN4iYT
# V4toilRR8KX/IaA1NMrN9EiA//ZhN3HONS/s6AxjjHJTR29GOQkCAwEAAaOCAbYw
# ggGyMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYBBQUH
# MAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2NjcjQ1
# ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3NwLmds
# b2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAETjBM
# MEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1UdHwRA
# MD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVldmNv
# ZGVzaWduY2EyMDIwLmNybDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSMEGDAW
# gBQlndD8WQmGY8Xs87ETO1ccA5I2ETAdBgNVHQ4EFgQU0Vg7IAYAK18fI9dI1YKi
# WA0D1bEwDQYJKoZIhvcNAQELBQADggIBAFOdA15mFwRIM54PIL/BDZq9RU9IO+YO
# lAoAYTJHbiTY9ZqvA1isS6EtdYKJgdP/MyZoW7RZmcY5IDXvXFj70TWWvfdqW/Qc
# MMHtSqhiRb4L92LtR4lS+hWM2fptECpl9BKH28LBZemdKS0jryBEqyAmuEoFJNDk
# wxzQVKPksvapvmSYwPiBCtzPyHTRo5HnLBXpK/LUBJu8epAgKz6LoJjnrTIF4U8R
# owrtUC0I6f4uj+sKYE0iV3/TzwsTJsp7MQShoILPr1/75fQjU/7Pl2fbM++uAFBC
# sHQHYvar9KLslFPX4g+cDdtOHz5vId8QYZnhCduVgzUGvELmXXR1FYV7oJNnh3eY
# Xc5gm7vSNKlZB8l7Ls6h8icBV2zQbojDiH0JOD//ph62qvnMp8ev9mvhvLXRCIxc
# aU7CYI0gNVvg9LPi5j1/tswqBc9XAfHUG9ZYVxYCgvynEmnJ5TuEh6GesGRPbNIL
# l418MFn4EPQUqxB51SMihIcyqu6+3qOlco8Dsy1y0gC0Hcx+unDZPsN8k+rhueN2
# HXrPkAJ2bsEJd7adPy423FKbA7bRCOc6dWOFH1OGANfEG0Rjw9RfcsI84OkKpQ7R
# XldpKIcWuaYMlfYzsl+P8dJru+KgA8Vh7GTVb5USzFGeMyOMtyr1/L2bIyRVSiLL
# 8goMl4DTDOWeMYIRRTCCEUECAQEwbDBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjACDHBNxPwWOpXgXVV8DDANBglghkgBZQMEAgEF
# AKB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBZ
# 0yJ8Z5mVZ6PmFtftgDB8HdFRWbfBRFWuzJur5fNo5TANBgkqhkiG9w0BAQEFAASC
# AgC/7j/adSNYWthBntg9ZKNc69jZHXoCMNEDHKEoqyOc6HId70WKgiCdvBPz0s7z
# rYrN007pRdFX5yoJn7PHfKlFYWmjEX+/+/ryqjP7RGCr35cmD99ZmGF2D3goGKHp
# DLBiSUOS6YQkxmhjooalBrxrKymVkZGW/GODsfSB2l7CNxPYrfhb3B1LX/wb5uHC
# lLwPkapCf354q4BPpoNxP0tYg2SDtaVXLlqWBJ7NE8Ro9zrl9RAOZVVgFB8Tge8n
# jMcsmjijM2Rt34MBAJbTJxCi/YHmJi6LNCyp/S0aJZPwKEkjACnTVbwpd07vVGB1
# mFkUdI/SVLt/J3ebyRCRII7zjZC8Uzt1+c4wb2LbhLkhZ8JVWxLaWG8SGFDnZwQ7
# Uokxd9K2XHY6epA/9xMV/Ipc3dUahend894Lv1DTQz7LUoPcRH5lr1QOkxYiCHsm
# m+C6bZKrLW0fuMICRHlUaKwHgGzexXlhZCjjWcKTZ6ompxuPe/MlltQa9X1VxhRP
# YI7bKtDsCUm/YbmUcV3YUEinvm+mPB/1TOHh9Ov5NOa/BTM0Do00NdKkrA/zUKvN
# DGagJ039Zq9Y6Wu1RpLVVeDdPW1JmUA7PJ6VCHQlRFJrj7ogTukg0QMbNJ/W1RKr
# NeenDyGTfK4Ad6md8Vv8WXoVcfMuqpmhJHHXzUAmVSuYiKGCDiwwgg4oBgorBgEE
# AYI3AwMBMYIOGDCCDhQGCSqGSIb3DQEHAqCCDgUwgg4BAgEDMQ0wCwYJYIZIAWUD
# BAIBMIH/BgsqhkiG9w0BCRABBKCB7wSB7DCB6QIBAQYLYIZIAYb4RQEHFwMwITAJ
# BgUrDgMCGgUABBS5KGpocHKOGKUK8/U1mpTxicB6OwIVAJSRMJZ/GXnJzi7Btlfj
# xC9OlAt+GA8yMDIyMDcyNzExNTQ1OVowAwIBHqCBhqSBgzCBgDELMAkGA1UEBhMC
# VVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1h
# bnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYgVGlt
# ZVN0YW1waW5nIFNpZ25lciAtIEczoIIKizCCBTgwggQgoAMCAQICEHsFsdRJaFFE
# 98mJ0pwZnRIwDQYJKoZIhvcNAQELBQAwgb0xCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5WZXJpU2lnbiwgSW5jLjEfMB0GA1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29y
# azE6MDgGA1UECxMxKGMpIDIwMDggVmVyaVNpZ24sIEluYy4gLSBGb3IgYXV0aG9y
# aXplZCB1c2Ugb25seTE4MDYGA1UEAxMvVmVyaVNpZ24gVW5pdmVyc2FsIFJvb3Qg
# Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTYwMTEyMDAwMDAwWhcNMzEwMTEx
# MjM1OTU5WjB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9y
# YXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxKDAmBgNVBAMT
# H1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQC7WZ1ZVU+djHJdGoGi61XzsAGtPHGsMo8Fa4aaJwAy
# l2pNyWQUSym7wtkpuS7sY7Phzz8LVpD4Yht+66YH4t5/Xm1AONSRBudBfHkcy8ut
# G7/YlZHz8O5s+K2WOS5/wSe4eDnFhKXt7a+Hjs6Nx23q0pi1Oh8eOZ3D9Jqo9ITh
# xNF8ccYGKbQ/5IMNJsN7CD5N+Qq3M0n/yjvU9bKbS+GImRr1wOkzFNbfx4Dbke7+
# vJJXcnf0zajM/gn1kze+lYhqxdz0sUvUzugJkV+1hHk1inisGTKPI8EyQRtZDqk+
# scz51ivvt9jk1R1tETqS9pPJnONI7rtTDtQ2l4Z4xaE3AgMBAAGjggF3MIIBczAO
# BgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADBmBgNVHSAEXzBdMFsG
# C2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20v
# Y3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBhMC4GCCsG
# AQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDovL3Muc3ltY2QuY29tMDYGA1Ud
# HwQvMC0wK6ApoCeGJWh0dHA6Ly9zLnN5bWNiLmNvbS91bml2ZXJzYWwtcm9vdC5j
# cmwwEwYDVR0lBAwwCgYIKwYBBQUHAwgwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMT
# EFRpbWVTdGFtcC0yMDQ4LTMwHQYDVR0OBBYEFK9j1sqjToVy4Ke8QfMpojh/gHVi
# MB8GA1UdIwQYMBaAFLZ3+mlIR59TEtXC6gcydgfRlwcZMA0GCSqGSIb3DQEBCwUA
# A4IBAQB16rAt1TQZXDJF/g7h1E+meMFv1+rd3E/zociBiPenjxXmQCmt5l30otlW
# ZIRxMCrdHmEXZiBWBpgZjV1x8viXvAn9HJFHyeLojQP7zJAv1gpsTjPs1rSTyEyQ
# Y0g5QCHE3dZuiZg8tZiX6KkGtwnJj1NXQZAv4R5NTtzKEHhsQm7wtsX4YVxS9U72
# a433Snq+8839A9fZ9gOoD+NT9wp17MZ1LqpmhQSZt/gGV+HGDvbor9rsmxgfqrnj
# OgC/zoqUywHbnsc4uw9Sq9HjlANgCk2g/idtFDL8P5dA4b+ZidvkORS92uTTw+or
# WrOVWFUEfcea7CMDjYUq0v+uqWGBMIIFSzCCBDOgAwIBAgIQe9Tlr7rMBz+hASME
# IkFNEjANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3lt
# YW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdv
# cmsxKDAmBgNVBAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcN
# MTcxMjIzMDAwMDAwWhcNMjkwMzIyMjM1OTU5WjCBgDELMAkGA1UEBhMCVVMxHTAb
# BgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBU
# cnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1w
# aW5nIFNpZ25lciAtIEczMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# rw6Kqvjcv2l7VBdxRwm9jTyB+HQVd2eQnP3eTgKeS3b25TY+ZdUkIG0w+d0dg+k/
# J0ozTm0WiuSNQI0iqr6nCxvSB7Y8tRokKPgbclE9yAmIJgg6+fpDI3VHcAyzX1uP
# CB1ySFdlTa8CPED39N0yOJM/5Sym81kjy4DeE035EMmqChhsVWFX0fECLMS1q/Js
# I9KfDQ8ZbK2FYmn9ToXBilIxq1vYyXRS41dsIr9Vf2/KBqs/SrcidmXs7DbylpWB
# Jiz9u5iqATjTryVAmwlT8ClXhVhe6oVIQSGH5d600yaye0BTWHmOUjEGTZQDRcTO
# PAPstwDyOiLFtG/l77CKmwIDAQABo4IBxzCCAcMwDAYDVR0TAQH/BAIwADBmBgNV
# HSAEXzBdMFsGC2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5z
# eW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1jYi5jb20v
# cnBhMEAGA1UdHwQ5MDcwNaAzoDGGL2h0dHA6Ly90cy1jcmwud3Muc3ltYW50ZWMu
# Y29tL3NoYTI1Ni10c3MtY2EuY3JsMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4G
# A1UdDwEB/wQEAwIHgDB3BggrBgEFBQcBAQRrMGkwKgYIKwYBBQUHMAGGHmh0dHA6
# Ly90cy1vY3NwLndzLnN5bWFudGVjLmNvbTA7BggrBgEFBQcwAoYvaHR0cDovL3Rz
# LWFpYS53cy5zeW1hbnRlYy5jb20vc2hhMjU2LXRzcy1jYS5jZXIwKAYDVR0RBCEw
# H6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0yMDQ4LTYwHQYDVR0OBBYEFKUTAamf
# hcwbbhYeXzsxqnk2AHsdMB8GA1UdIwQYMBaAFK9j1sqjToVy4Ke8QfMpojh/gHVi
# MA0GCSqGSIb3DQEBCwUAA4IBAQBGnq/wuKJfoplIz6gnSyHNsrmmcnBjL+NVKXs5
# Rk7nfmUGWIu8V4qSDQjYELo2JPoKe/s702K/SpQV5oLbilRt/yj+Z89xP+YzCdmi
# WRD0Hkr+Zcze1GvjUil1AEorpczLm+ipTfe0F1mSQcO3P4bm9sB/RDxGXBda46Q7
# 1Wkm1SF94YBnfmKst04uFZrlnCOvWxHqcalB+Q15OKmhDc+0sdo+mnrHIsV0zd9H
# CYbE/JElshuW6YUI6N3qdGBuYKVWeg3IRFjc5vlIFJ7lv94AvXexmBRyFCTfxxEs
# HwA/w0sUxmcczB4Go5BfXFSLPuMzW4IPxbeGAk5xn+lmRT92MYICWjCCAlYCAQEw
# gYswdzELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9u
# MR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMSgwJgYDVQQDEx9TeW1h
# bnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENBAhB71OWvuswHP6EBIwQiQU0SMAsG
# CWCGSAFlAwQCAaCBpDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZI
# hvcNAQkFMQ8XDTIyMDcyNzExNTQ1OVowLwYJKoZIhvcNAQkEMSIEINBh+gKokTNn
# nfoONBCou4EWAZ5jjGumYVDTQi6LoVWxMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIE
# IMR0znYAfQI5Tg2l5N58FMaA+eKCATz+9lPvXbcf32H4MAsGCSqGSIb3DQEBAQSC
# AQBRN3ksBg/e4qcs4uexdMyzP6f8aSYLsGuCJ1x10D23DSrPyMt3fmeWESyK7c8N
# BhHBJmwiyFR3EE2Hfh1Y3CKiPpGw/gCm000bR/pnH+6Xzy+bTLQTr+MmsSEX3fNf
# THSYMQsMvL3gJh/8VO97wzF+P51PVXZNC39xBkslzkiCWBEMswX4Wf9DXUyk3kP6
# 04sCFqRBBaAKyaECumIE7rsHLfZjbhiUw11PiVCGKqyKXrpNaH+zGEaiRopOMvRu
# x57xvkuHa+1SLU5zeyt20bEhSf5qJg922U0wHJx8errDLjf2xSUJNPAxWruXlp9i
# ncjao7/YFWd5HhASS76raqH0
# SIG # End signature block
