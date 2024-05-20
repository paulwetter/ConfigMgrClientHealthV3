<#
.SYNOPSIS
    ConfigMgr Client Health is a tool that validates and automatically fixes errors on Windows computers managed by Microsoft Configuration Manager.
.EXAMPLE
   .\ConfigMgrClientHealth.ps1
   The above example will read the config.json file located in the same directory as the script.
.EXAMPLE
    \\cm01.domain.com\ClientHealth$\ConfigMgrClientHealth.ps1 -Config \\cm01.domain.com\ClientHealth$\Config.json
.PARAMETER Config
    A single parameter specifying the path to the configuration json file.
.DESCRIPTION
    ConfigMgr Client Health detects and fixes following errors:
        * ConfigMgr client is not installed.
        * ConfigMgr client is assigned the correct site code.
        * ConfigMgr client is upgraded to current version if not at specified minimum version.
        * ConfigMgr client not able to forward state messages to management point.
        * ConfigMgr client stuck in provisioning mode.
        * ConfigMgr client maximum log file size.
        * ConfigMgr client cache size.
        * Corrupt WMI.
        * Services for ConfigMgr client is not running or disabled.
        * Other services can be specified to start and run and specific state.
        * Hardware inventory is running at correct schedule
        * Group Policy failes to update registry.pol
        * Pending reboot blocking updates from installing
        * ConfigMgr Client Update Handler is working correctly with registry.pol
        * Windows Update Agent not working correctly, causing client not to receive patches.
        * Windows Update Agent missing patches that fixes known bugs.
.NOTES
    You should run this with at least local administrator rights. It is recommended to run this script under the SYSTEM context.

    DO NOT GIVE USERS WRITE ACCESS TO THIS FILE. LOCK IT DOWN !  Do not allow access to the config file as that has the API key for writing to the database.

    Updated by: Paul Wetter (wetterssource.com)
    Twitter: @paulwetter

    Original Author: Anders Rødland
    Blog: https://www.andersrodland.com
    Twitter: @AndersRodland
.LINK
    Full documentation: https://www.andersrodland.com/configmgr-client-health/
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="Medium")]
param(
    [Parameter(HelpMessage='Path to JSON Configuration File')]
    [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
    [ValidatePattern('.json$')]
    [string]$ConfigFilePath
)

Begin {
    # ConfigMgr Client Health Version
    $ClientHealthScriptVersion = '3.0.0'
    $PowerShellVersion = [int]$PSVersionTable.PSVersion.Major
    $global:ScriptPath = split-path -parent $MyInvocation.MyCommand.Definition

    #If no config file was passed in, use the default.
    If (!$PSBoundParameters.ContainsKey('Config')) {
        $ConfigFilePath = Join-Path ($global:ScriptPath) "Config.json"
        Write-Verbose "No config provided, defaulting to $ConfigFilePath"
    }

    Write-Verbose "Script version: $ClientHealthScriptVersion"
    Write-Verbose "PowerShell version: $PowerShellVersion"

    # Import Modules
    # Import BitsTransfer Module (Does not work on PowerShell Core (6), disable check if module failes to import.)
    $BitsCheckable = $false
    if (Get-Module -ListAvailable -Name BitsTransfer) {
		try {
			Import-Module BitsTransfer -ErrorAction stop
			$BitsCheckable = $true
		}
		catch { $BitsCheckable = $false }
	}

    #region functions
    Function Get-JsonConfig {
        <#
        .SYNOPSIS
        Test the validity of an json file
        #>
        [CmdletBinding()]
        param ([parameter(mandatory=$true)][ValidateNotNullorEmpty()][string]$JsonString)
        # Check for Load or Parse errors when loading the JSON file
        try {
            $json = ConvertFrom-Json -InputObject $JsonString -ErrorAction stop
            return $json
        }
        catch {
            return $false
        }
    }

    # use ClientHealth v3 Webservice to update database. RESTful API.
    Function Update-Webservice {
        Param(
            [Parameter(Mandatory=$true)]
            [String]$URI,
            [Parameter(Mandatory=$true)]
            $Log,
            [Parameter(Mandatory=$true)]
            [String]$ApiKey)

        $logAsJson = $Log | ConvertTo-Json
        $URI = $URI + "/api/Clients/Client"
        $ContentType = "application/json"
        $Method = "PUT"
        $header = @{
            'ApiKey' = "$ApiKey"
        }

        try { $Response = Invoke-RestMethod -Method $Method -Uri $URI -Body $logAsJson -Headers $header -ContentType $ContentType}
        catch {
            $ExceptionMessage = $_.Exception.Message
            Write-Host "Error Invoking RestMethod $Method on URI $URI. Failed to update database using webservice. Exception: $ExceptionMessage"
        }
        return $Response
    }

    # Retrieve configuration from SQL using webserivce
    Function Get-ConfigFromWebservice {
        Param(
            [Parameter(Mandatory=$true)][String]$URI,
            [Parameter(Mandatory=$true)][String]$ApiKey
            )
        if ($URI[-1] -ne '/'){
            $URI = $URI + '/'
        }
        $URI = $URI + "api/Clients/ClientConfiguration"
        $header = @{
            'ApiKey' = "$ApiKey"
        }
        Write-Verbose "Retrieving configuration from webservice. URI: $URI"
        try {
            $configFromApi = Invoke-RestMethod -Uri $URI -Method Get -Headers $header
        }
        catch {
            Write-Error "Error retrieving configuration from webservice $URI. Exception: $ExceptionMessage"
            Exit 1
        }
        return $configFromApi
    }

    Function Get-LogFileName {
        $logshare = Get-ChConfigLoggingShare
        return "$logshare\$env:computername.log"
    }

    Function Get-ServiceUpTime {
        param([Parameter(Mandatory=$true)]$Name)

        Try{$ServiceDisplayName = (Get-Service $Name).DisplayName}
        Catch{
            Write-Warning "The '$($Name)' service could not be found."
            Return
        }

        #First try and get the service start time based on the last start event message in the system log.
        Try{
            [datetime]$ServiceStartTime = (Get-EventLog -LogName System -Source "Service Control Manager" -EntryType Information -Message "*$($ServiceDisplayName)*running*" -Newest 1).TimeGenerated
            Return (New-TimeSpan -Start $ServiceStartTime -End (Get-Date)).Days
        }
        Catch {
            Write-Verbose "Could not get the uptime time for the '$($Name)' service from the event log.  Relying on the process instead."
        }

        #If the event log doesn't contain a start event then use the start time of the service's process.  Since processes can be shared this is less reliable.
        Try{
            if ($PowerShellVersion -ge 6) { $ServiceProcessID = (Get-CimInstance Win32_Service -Filter "Name='$($Name)'").ProcessID }
            else { $ServiceProcessID = (Get-WMIObject -Class Win32_Service -Filter "Name='$($Name)'").ProcessID }

            [datetime]$ServiceStartTime = (Get-Process -Id $ServiceProcessID).StartTime
            Return (New-TimeSpan -Start $ServiceStartTime -End (Get-Date)).Days

        }
        Catch{
            Write-Warning "Could not get the uptime time for the '$($Name)' service.  Returning max value."
            Return [int]::MaxValue
        }
    }

    #Loop backwards through a Configuration Manager log file looking for the latest matching message after the start time.
    Function Search-CMLogFile {
        Param(
            [Parameter(Mandatory=$true)]$LogFile,
            [Parameter(Mandatory=$true)][String[]]$SearchStrings,
            [datetime]$StartTime = [datetime]::MinValue
        )

        #Get the log data.
        $LogData = Get-Content $LogFile

        #Loop backwards through the log file.
        :loop for ($i=($LogData.Count - 1);$i -ge 0; $i--) {

            #Parse the log line into its parts.
            try{
                $LogData[$i] -match '\<\!\[LOG\[(?<Message>.*)?\]LOG\]\!\>\<time=\"(?<Time>.+)(?<TZAdjust>[+|-])(?<TZOffset>\d{2,3})\"\s+date=\"(?<Date>.+)?\"\s+component=\"(?<Component>.+)?\"\s+context="(?<Context>.*)?\"\s+type=\"(?<Type>\d)?\"\s+thread=\"(?<TID>\d+)?\"\s+file=\"(?<Reference>.+)?\"\>' | Out-Null
                $LogTime = [datetime]::ParseExact($("$($matches.date) $($matches.time)"),"MM-dd-yyyy HH:mm:ss.fff", $null)
                $LogMessage = $matches.message
            }
            catch{
                Write-Warning "Could not parse the line $($i) in '$($LogFile)': $($LogData[$i])"
				continue
            }

            #If we have gone beyond the start time then stop searching.
            If ($LogTime -lt $StartTime) {
                Write-Verbose "No log lines in $($LogFile) matched $($SearchStrings) before $($StartTime)."
                break loop
            }

            #Loop through each search string looking for a match.
            ForEach($String in $SearchStrings){
                If ($LogMessage -match $String) {
					return $LogData[$i]
					break loop
				}
            }
        }

        #Looped through log file without finding a match.
        #Return
    }

    Function Test-LocalLogging {
        $clientpath = Get-ChLocalFilesPath
        if ((Test-Path -Path $clientpath) -eq $False) { New-Item -Path $clientpath -ItemType Directory -Force | Out-Null }
    }

    Function Write-ChLog {
        Param([Parameter(Mandatory = $false)]$Text, $Mode,
            [Parameter(Mandatory = $false)][ValidateSet(1, 2, 3, 'Information', 'Warning', 'Error')]$Severity = 1)

        switch ($Severity) {
            'Information' {$Severity = 1}
            'Warning' {$Severity = 2}
            'Error' {$Severity = 3}
        }

        if ($Mode -like "Local") {
            Test-LocalLogging
            $clientpath = Get-ChLocalFilesPath
            $Logfile = "$clientpath\ClientHealth.log"
        }
        else { $Logfile = Get-LogFileName }

        if ($mode -like "ClientInstall" ) { 
            $text = "ConfigMgr Client installation failed. Agent not detected 10 minutes after triggering installation." 
            $Severity = 3
        }

        foreach ($item in $text) {
            $item = '<![LOG[' + $item + ']LOG]!>'
            $time = 'time="' + (Get-Date -Format HH:mm:ss.fff) + '+000"' #Should actually be the bias
            $date = 'date="' + (Get-Date -Format MM-dd-yyyy) + '"'
            $component = 'component="ConfigMgrClientHealth"'
            $context = 'context=""'
            $type = 'type="' + $Severity + '"'  #Severity 1=Information, 2=Warning, 3=Error
            $thread = 'thread="' + $PID + '"'
            $file = 'file=""'

            $logblock = ($time, $date, $component, $context, $type, $thread, $file) -join ' '
            $logblock = '<' + $logblock + '>'

            $item + $logblock | Out-File -Encoding utf8 -Append $logFile
        }
        # $obj | Out-File -Encoding utf8 -Append $logFile
    }

    Function Get-OperatingSystem {
        if ($PowerShellVersion -ge 6) { $OS = Get-CimInstance Win32_OperatingSystem }
        else { $OS = Get-WmiObject Win32_OperatingSystem }


        # Handles different OS languages
        $OSArchitecture = ($OS.OSArchitecture -replace ('([^0-9])(\.*)', '')) + '-Bit'
        switch -Wildcard ($OS.Caption) {
            "*Embedded*" {$OSName = "Windows 7 " + $OSArchitecture}
            "*Windows 7*" {$OSName = "Windows 7 " + $OSArchitecture}
            "*Windows 8.1*" {$OSName = "Windows 8.1 " + $OSArchitecture}
            "*Windows 10*" {$OSName = "Windows 10 " + $OSArchitecture}
            "*Windows 11*" {$OSName = "Windows 11 " + $OSArchitecture}
            "*Server 2008*" {
                if ($OS.Caption -like "*R2*") { $OSName = "Windows Server 2008 R2 " + $OSArchitecture }
                else { $OSName = "Windows Server 2008 " + $OSArchitecture }
            }
            "*Server 2012*" {
                if ($OS.Caption -like "*R2*") { $OSName = "Windows Server 2012 R2 " + $OSArchitecture }
                else { $OSName = "Windows Server 2012 " + $OSArchitecture }
            }
            "*Server 2016*" { $OSName = "Windows Server 2016 " + $OSArchitecture }
            "*Server 2019*" { $OSName = "Windows Server 2019 " + $OSArchitecture }
            "*Server 2022*" { $OSName = "Windows Server 2022 " + $OSArchitecture }
        }
        return $OSName
    }

    Function Get-MissingUpdates {
        $UpdateShare = Get-ChConfigUpdatesShare
        $OSName = Get-OperatingSystem

        $build = $null
        if ($OSName -like "*Windows 10*") {
            $build = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber
            switch ($build) {
                10240 {$OSName = $OSName + " 1507"}
                10586 {$OSName = $OSName + " 1511"}
                14393 {$OSName = $OSName + " 1607"}
                15063 {$OSName = $OSName + " 1703"}
                16299 {$OSName = $OSName + " 1709"}
                17134 {$OSName = $OSName + " 1803"}
                17763 {$OSName = $OSName + " 1809"}
                18362 {$OSName = $OSName + " 1903"}
                18363 {$OSName = $OSName + " 1909"}
                19041 {$OSName = $OSName + " 2004"}
                19042 {$OSName = $OSName + " 20H2"}
                19043 {$OSName = $OSName + " 21H1"}
                19044 {$OSName = $OSName + " 21H2"}
                19045 {$OSName = $OSName + " 22H2"}
                default {$OSName = $OSName + " Insider Preview"}
            }
        }

        $Updates = $UpdateShare + "\" + $OSName + "\"
        $obj = New-Object PSObject @{}
        If ((Test-Path $Updates) -eq $true) {
            $regex = "\b(?!(KB)+(\d+)\b)\w+"
            $hotfixes = (Get-ChildItem $Updates | Select-Object -ExpandProperty Name)
            if ($PowerShellVersion -ge 6) { $installedUpdates = (Get-CimInstance -ClassName Win32_QuickFixEngineering).HotFixID }
            else { $installedUpdates = Get-Hotfix | Select-Object -ExpandProperty HotFixID }

            foreach ($hotfix in $hotfixes) {
                $kb = $hotfix -replace $regex -replace "\." -replace "-"
                if ($installedUpdates -like $kb) {}
                else { $obj.Add('Hotfix', $hotfix) }
            }
        }
        return $obj
    }

    Function Get-RegistryValue {
        param (
            [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Path,
            [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Name
        )

        Return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    }

    Function Set-RegistryValue {
        param (
            [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Path,
            [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Name,
            [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Value,
            [ValidateSet("String","ExpandString","Binary","DWord","MultiString","Qword")]$ProperyType="String"
        )

        #Make sure the key exists
        If (!(Test-Path $Path)){
            New-Item $Path -Force | Out-Null
        }

        New-ItemProperty -Force -Path $Path -Name $Name -Value $Value -PropertyType $ProperyType | Out-Null
    }

    Function Get-Sitecode {
        try {
            $sms = new-object -comobject 'Microsoft.SMS.Client'
            $obj = $sms.GetAssignedSite()
        }
        catch { $obj = '...' }
        return $obj
    }

    Function Get-ClientVersion {
        try {
            if ($PowerShellVersion -ge 6) { $obj = (Get-CimInstance -Namespace 'root/ccm' -ClassName 'SMS_Client' -ErrorAction Stop).ClientVersion}
            else { $cliVer = (Get-WmiObject -Namespace 'root/ccm' -ClassName 'SMS_Client' -ErrorAction Stop).ClientVersion }
        }
        catch { $cliVer = "0.0" }
        return $cliVer
    }

    Function Get-ClientCache {
        $CmCacheSize = 0
        try {
            $CmCacheSize = (New-Object -ComObject UIResource.UIResourceMgr).GetCacheInfo().TotalSize
        }
        catch { $CmCacheSize = 0}
        return $CmCacheSize
    }

    Function Get-ClientMaxLogSize {
        try { $CmMaxLogSize = [Math]::Round(((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global' -ErrorAction Stop ).LogMaxSize) / 1000) }
        catch { $CmMaxLogSize = 0 }
        return $CmMaxLogSize
    }


    Function Get-ClientMaxLogHistory {
        try { $CMMaxLogHistory = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global' -ErrorAction Stop).LogMaxHistory }
        catch { $CMMaxLogHistory = 0 }
        return $CMMaxLogHistory
    }

    Function Get-CCMLogDirectory {
        $CmLogDir = "$env:SystemDrive\windows\ccm\Logs"
        try {
            $CmLogDir = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global').LogDirectory
        }
        catch{
            $CmLogDir = "$env:SystemDrive\windows\ccm\Logs" 
        }
        return $CmLogDir
    }

    Function Get-CCMDirectory {
        $logdir = Get-CCMLogDirectory
        $CmClientDir = $logdir.replace("\Logs", "")
        return $CmClientDir
    }

    Function Test-CcmSDF {
        <#
        .SYNOPSIS
        Function to test if local database files are missing from the ConfigMgr client.

        .DESCRIPTION
        Function to test if local database files are missing from the ConfigMgr client. Will tag client for reinstall if less than 7. Returns $True if compliant or $False if non-compliant

        .NOTES
        Returns $True if compliant or $False if non-compliant. Non.compliant computers require remediation and will be tagged for ConfigMgr client reinstall.
        #>
        $ccmdir = Get-CCMDirectory
        $files = @(Get-ChildItem "$ccmdir\*.sdf" -ErrorAction SilentlyContinue)
        if ($files.Count -lt 7) { $compliant = $false }
        else { $compliant = $true }
        return $compliant
    }

    Function Test-CcmSQLCELog {
        $logdir = Get-CCMLogDirectory
        $ccmdir = Get-CCMDirectory
        $logFile = "$logdir\CcmSQLCE.log"
        $logLevel = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global').logLevel

        if ( (Test-Path -Path $logFile) -and ($logLevel -ne 0) ) {
            # Not in debug mode, and CcmSQLCE.log exists. This could be bad.
            $LastWriteTime = (Get-ChildItem $logFile).LastWriteTime
            $CreationTime = (Get-ChildItem $logFile).CreationTime
            $FileDate = Get-Date($LastWriteTime)
            $FileCreated = Get-Date($CreationTime)

            $now = Get-Date
            if ( (($now - $FileDate).Days -lt 7) -and ((($now - $FileCreated).Days) -gt 7) ) {
                $text = "CM client not in debug mode, and CcmSQLCE.log exists. This is very bad. Cleaning up local SDF files and reinstalling CM client"
                Write-Host $text -ForegroundColor Red
                # Delete *.SDF Files
                $Service = Get-Service -Name ccmexec
                $Service.Stop()

                $seconds = 0
                Do {
                    Start-Sleep -Seconds 1
                    $seconds++
                } while ( ($Service.Status -ne "Stopped") -and ($seconds -le 60) )

                # Do another test to make sure CcmExec service really is stopped
                if ($Service.Status -ne "Stopped") { Stop-Service -Name ccmexec -Force }

                Write-Verbose "Waiting 10 seconds to allow file locking issues to clear up"
                Start-Sleep -seconds 10

                try {
                    $files = Get-ChildItem "$ccmdir\*.sdf"
                    $files | Remove-Item -Force -ErrorAction Stop
                    Remove-Item -Path $logFile -Force -ErrorAction Stop
                }
                catch {
                    Write-Verbose "Obviously that wasn't enough time"
                    Start-Sleep -Seconds 30
                    # We try again
                    $files = Get-ChildItem "$ccmdir\*.sdf"
                    $files | Remove-Item -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path $logFile -Force -ErrorAction SilentlyContinue
                }

                $status = $true
            }

            # CcmSQLCE.log has not been updated for two days. We are good for now.
            else { $status = $false }
        }

        # we are good
        else { $status = $false }
        return $status

    }

    function Test-CCMCertificateError {
		[CmdletBinding()]
        Param()
        # More checks to come
        $logdir = Get-CCMLogDirectory
        $logFile1 = "$logdir\ClientIDManagerStartup.log"
        $error1 = 'Failed to find the certificate in the store'
        $error2 = '[RegTask] - Server rejected registration 3'
        $content = Get-Content -Path $logFile1

        $ok = $true

        if ($content -match $error1) {
            $ok = $false
            $text = 'ConfigMgr Client Certificate: Error failed to find the certificate in store. Attempting fix.'
            Write-Warning $text
            Stop-Service -Name ccmexec -Force
            # Name is persistant across systems.
            $cert = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\19c5cf9c7b5dc9de3e548adb70398402_50e417e0-e461-474b-96e2-077b80325612"
            # CCM creates new certificate when missing.
            Remove-Item -Path $cert -Force -ErrorAction SilentlyContinue | Out-Null
            # Remove the error from the logfile to avoid double remediations based on false positives
            $newContent = $content | Select-String -pattern $Error1 -notmatch
            Out-File -FilePath $logfile -InputObject $newContent -Encoding utf8 -Force
            Start-Service -Name ccmexec

            # Update log object
            $logClientCertificate = $error1
        }

        #$content = Get-Content -Path $logFile2
        if ($content -match $error2) {
            $ok = $false
            $text = 'ConfigMgr Client Certificate: Error! Server rejected client registration. Client Certificate not valid. No auto-remediation.'
            Write-Error $text
            $logClientCertificate = $error2
        }

        if ($ok -eq $true) {
            $text = 'ConfigMgr Client Certificate: OK'
            Write-Host $text
            $logClientCertificate = 'OK'
        }
        return $logClientCertificate
    }

    Function Test-InTaskSequence {
		[CmdletBinding()]
        Param()
        try { $tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment }
        catch { $tsenv = $null }

        if ($tsenv) {
            Write-Host "Configuration Manager Task Sequence detected on computer. Exiting script"
            return $true
        }
        return $false
    }


    Function Test-BITS {
        [CmdletBinding()]
        Param()

        if ($BitsCheckable -eq $true)  {
            $Errors = Get-BitsTransfer -AllUsers | Where-Object { ($_.JobState -like "TransientError") -or ($_.JobState -like "Transient_Error") -or ($_.JobState -like "Error") }

            if ($null -ne $Errors) {
                $fix = (Get-ChConfigBITSCheckFix).ToLower()

                if ($fix -eq "true") {
                    $text = "BITS: Error. Remediating"
                    $Errors | Remove-BitsTransfer -ErrorAction SilentlyContinue
                    Invoke-Expression -Command 'sc.exe sdset bits "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"' | out-null
                    $logBITS = 'Remediated'
                }
                else {
                    $text = "BITS: Error. Monitor only"
                    $logBITS = 'Error'
                }
            }

            else {
                $text = "BITS: OK"
                $logBITS = 'OK'
            }

        }
        else {
            $text = "BITS: PowerShell Module BitsTransfer missing. Skipping check"
            $logBITS = "PS Module BitsTransfer missing"
        }

        Write-Host $text
        return $logBITS

    }

	Function Test-ClientSettingsConfiguration {
		[CmdletBinding()]
        Param()

		$ClientSettingsConfig = @(Get-WmiObject -Namespace "root\ccm\Policy\DefaultMachine\RequestedConfig" -Class CCM_ClientAgentConfig -ErrorAction SilentlyContinue | Where-Object {$_.PolicySource -eq "CcmTaskSequence"})

		if ($ClientSettingsConfig.Count -gt 0) {

			$fix = (Get-ChConfigClientSettingsCheckFix).ToLower()

			if ($fix -eq "true") {
				$text = "ClientSettings: Error. Remediating"
				DO {
					Get-WmiObject -Namespace "root\ccm\Policy\DefaultMachine\RequestedConfig" -Class CCM_ClientAgentConfig | Where-Object {$_.PolicySource -eq "CcmTaskSequence"} | Select-Object -first 1000 | ForEach-Object {Remove-WmiObject -InputObject $_}
				} Until (!(Get-WmiObject -Namespace "root\ccm\Policy\DefaultMachine\RequestedConfig" -Class CCM_ClientAgentConfig | Where-Object {$_.PolicySource -eq "CcmTaskSequence"} | Select-Object -first 1))
				$logClientSettings = 'Remediated'
			}
			else {
				$text = "ClientSettings: Error. Monitor only"
				$logClientSettings = 'Error'
			}
		}

		else {
			$text = "ClientSettings: OK"
			$logClientSettings = 'OK'
		}
		Write-Host $text
        return $logClientSettings
    }

    function Get-PendingReboot {
        $result = @{
            CBSRebootPending =$false
            WindowsUpdateRebootRequired = $false
            FileRenamePending = $false
            SCCMRebootPending = $false
        }

        #Check CBS Registry
        $key = Get-ChildItem "HKLM:Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
        if ($null -ne $key) { $result.CBSRebootPending = $true }

        #Check Windows Update
        $key = Get-Item 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue
        if ($null -ne $key) { $result.WindowsUpdateRebootRequired = $true }

        #Check PendingFileRenameOperations
        $prop = Get-ItemProperty 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($null -ne $prop)
        {
            #PendingFileRenameOperations is not *must* to reboot?
            #$result.FileRenamePending = $true
        }

        try
        {
            $util = [wmiclass]'\\.\root\ccm\clientsdk:CCM_ClientUtilities'
            $status = $util.DetermineIfRebootPending()
            if(($null -ne $status) -and $status.RebootPending){ $result.SCCMRebootPending = $true }
        }
        catch{}

        #Return Reboot required
        if ($result.ContainsValue($true)) {
            $logPendingReboot = 'Pending Reboot'
        }
        else {
            $logPendingReboot = 'OK'
        }
        return $logPendingReboot
    }

    Function Get-ProvisioningMode {
        $registryPath = 'HKLM:\SOFTWARE\Microsoft\CCM\CcmExec'
        $provisioningMode = (Get-ItemProperty -Path $registryPath).ProvisioningMode
        if ($provisioningMode -eq 'true') { $obj = $true }
        else { $obj = $false }
        return $obj
    }

    Function Get-OSDiskFreeSpace {

        if ($PowerShellVersion -ge 6) { $driveC = Get-CimInstance -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "$env:SystemDrive"} | Select-Object FreeSpace, Size }
        else { $driveC = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "$env:SystemDrive"} | Select-Object FreeSpace, Size }
        $freeSpace = (($driveC.FreeSpace / $driveC.Size) * 100)
        return ([math]::Round($freeSpace,2))
    }

    Function Get-Computername {
        if ($PowerShellVersion -ge 6) { $obj = (Get-CimInstance Win32_ComputerSystem).Name }
        else { $obj = (Get-WmiObject Win32_ComputerSystem).Name }
        return $obj
    }

    Function Get-LastBootTime {
        if ($PowerShellVersion -ge 6) { $wmi = Get-CimInstance Win32_OperatingSystem }
        else { $wmi = Get-WmiObject Win32_OperatingSystem }
        $obj = $wmi.ConvertToDateTime($wmi.LastBootUpTime)
        return $obj
    }

    Function Get-LastInstalledPatches {
        # Reading date from Windows Update COM object.
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        $HistoryCount = $Searcher.GetTotalHistoryCount()

        $OS = Get-OperatingSystem
        Switch -Wildcard ($OS) {
            "*Windows 7*" {
                $Date = $Searcher.QueryHistory(0, $HistoryCount) | Where-Object {
                    ($_.ClientApplicationID -eq 'AutomaticUpdates' -or $_.ClientApplicationID -eq 'ccmexec') -and ($_.Title -notmatch "Security Intelligence Update|Definition Update")
                } | Select-Object -ExpandProperty Date | Measure-Latest
            }
            "*Windows 8*" {
                $Date = $Searcher.QueryHistory(0, $HistoryCount) | Where-Object {
                    ($_.ClientApplicationID -eq 'AutomaticUpdatesWuApp' -or $_.ClientApplicationID -eq 'ccmexec') -and ($_.Title -notmatch "Security Intelligence Update|Definition Update")
                } | Select-Object -ExpandProperty Date | Measure-Latest
            }
            "*Windows 10*" {
                $Date = $Searcher.QueryHistory(0, $HistoryCount) | Where-Object {
                    ($_.ClientApplicationID -eq 'UpdateOrchestrator' -or $_.ClientApplicationID -eq 'ccmexec') -and ($_.Title -notmatch "Security Intelligence Update|Definition Update|Update for Windows Security platform antimalware platform|Update for Microsoft Defender Antivirus antimalware platform|Windows Malicious Software Removal Tool")
                } | Select-Object -ExpandProperty Date | Measure-Latest
            }
            "*Windows 11*" {
                $Date = $Searcher.QueryHistory(0, $HistoryCount) | Where-Object {
                    ($_.ClientApplicationID -eq 'MoUpdateOrchestrator' -or $_.ClientApplicationID -eq 'ccmexec') -and ($_.Title -notmatch "Security Intelligence Update|Definition Update|Update for Windows Security platform antimalware platform|Update for Microsoft Defender Antivirus antimalware platform|Windows Malicious Software Removal Tool")
                } | Select-Object -ExpandProperty Date | Measure-Latest
            }
            "*Server 2008*" {
                $Date = $Searcher.QueryHistory(0, $HistoryCount) | Where-Object {
                    ($_.ClientApplicationID -eq 'AutomaticUpdates' -or $_.ClientApplicationID -eq 'ccmexec') -and ($_.Title -notmatch "Security Intelligence Update|Definition Update")
                } | Select-Object -ExpandProperty Date | Measure-Latest
            }
            "*Server 2012*" {
                $Date = $Searcher.QueryHistory(0, $HistoryCount) | Where-Object {
                    ($_.ClientApplicationID -eq 'AutomaticUpdatesWuApp' -or $_.ClientApplicationID -eq 'ccmexec') -and ($_.Title -notmatch "Security Intelligence Update|Definition Update")
                } | Select-Object -ExpandProperty Date | Measure-Latest
            }
            "*Server 2016*" {
                $Date = $Searcher.QueryHistory(0, $HistoryCount) | Where-Object {
                    ($_.ClientApplicationID -eq 'UpdateOrchestrator' -or $_.ClientApplicationID -eq 'ccmexec') -and ($_.Title -notmatch "Security Intelligence Update|Definition Update")
                } | Select-Object -ExpandProperty Date | Measure-Latest
            }
		}

        # Reading date from PowerShell Get-Hotfix
        #$now = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        #$Hotfix = Get-Hotfix | Where-Object {$_.InstalledOn -le $now} | Select-Object -ExpandProperty InstalledOn -ErrorAction SilentlyContinue

        #$Hotfix = Get-Hotfix | Select-Object -ExpandProperty InstalledOn -ErrorAction SilentlyContinue

        if ($PowerShellVersion -ge 6) { $Hotfix = Get-CimInstance -ClassName Win32_QuickFixEngineering | Select-Object @{Name="InstalledOn";Expression={[DateTime]::Parse($_.InstalledOn,$([System.Globalization.CultureInfo]::GetCultureInfo("en-US")))}} }
        else { $Hotfix = Get-Hotfix | Select-Object @{l="InstalledOn";e={[DateTime]::Parse($_.psbase.properties["installedon"].value,$([System.Globalization.CultureInfo]::GetCultureInfo("en-US")))}} }

        $Hotfix = $Hotfix | Select-Object -ExpandProperty InstalledOn

        $Date2 = $null

        if ($null -ne $hotfix) { $Date2 = Get-Date($hotfix | Measure-Latest) -ErrorAction SilentlyContinue }

        if (($Date -ge $Date2) -and ($null -ne $Date)) { $OSUpdates = Get-SmallDateTime -Date $Date }
        elseif (($Date2 -gt $Date) -and ($null -ne $Date2)) { $OSUpdates = Get-SmallDateTime -Date $Date2 }
        else {$OSUpdates = [datetime]::MinValue}
        return $OSUpdates
    }

    function Measure-Latest {
        BEGIN { $latest = $null }
        PROCESS { if (($null -ne $_) -and (($null -eq $latest) -or ($_ -gt $latest))) { $latest = $_ } }
        END { $latest }
    }

    Function Test-LogFileHistory {
        Param([Parameter(Mandatory=$true)]$LogFilePath)
        $startString = '<--- ConfigMgr Client Health Check starting --->'
        $content = ''

        # Handle the network share log file
        if (Test-Path $logfile -ErrorAction SilentlyContinue)  { $content = Get-Content $logfile -ErrorAction SilentlyContinue }
		else { return }
        $maxHistory = Get-ChConfigLoggingMaxHistory
        $startCount = [regex]::matches($content,$startString).count

        # Delete logfile if more start and stop entries than max history
        if ($startCount -ge $maxHistory) { Remove-Item $logfile -Force }
    }

    Function Test-DNSConfiguration {
        #$dnsdomain = (Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'").DNSDomain
        $fqdn = [System.Net.Dns]::GetHostEntry([string]"localhost").HostName
        if ($PowerShellVersion -ge 6) { $localIPs = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -Match "True"} |  Select-Object -ExpandProperty IPAddress }
        else { $localIPs = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -Match "True"} |  Select-Object -ExpandProperty IPAddress }
        $dnscheck = [System.Net.DNS]::GetHostByName($fqdn)

        $OSName = Get-OperatingSystem
        if (($OSName -notlike "*Windows 7*") -and ($OSName -notlike "*Server 2008*")) {
            # This method is supported on Windows 8 / Server 2012 and higher. More acurate than using .NET object method
            try {
                $ActiveAdapters = (get-netadapter | Where-Object {$_.Status -like "Up"}).Name
                $dnsServers = Get-DnsClientServerAddress | Where-Object {$ActiveAdapters -contains $_.InterfaceAlias} | Where-Object {$_.AddressFamily -eq 2} | Select-Object -ExpandProperty ServerAddresses
                $dnsAddressList = Resolve-DnsName -Name $fqdn -Server ($dnsServers | Select-Object -First 1) -Type A -DnsOnly -ErrorAction Stop | Select-Object -ExpandProperty IPAddress
            }
            catch {
                # Fallback to depreciated method
                $dnsAddressList = $dnscheck.AddressList | Select-Object -ExpandProperty IPAddressToString
                $dnsAddressList = $dnsAddressList -replace("%(.*)", "")
            }
        }

        else {
            # This method cannot guarantee to only resolve against DNS sever. Local cache can be used in some circumstances.
            # For Windows 7 only

            $dnsAddressList = $dnscheck.AddressList | Select-Object -ExpandProperty IPAddressToString
            $dnsAddressList = $dnsAddressList -replace("%(.*)", "")
        }

        $dnsFail = ''
        $logFail = ''

        Write-Verbose 'Verify that local machines FQDN matches DNS'
        if ($dnscheck.HostName -like $fqdn) {
            $obj = $true
            Write-Verbose 'Checking if one local IP matches on IP from DNS'
            Write-Verbose 'Loop through each IP address published in DNS'
            foreach ($dnsIP in $dnsAddressList) {
                #Write-Host "Testing if IP address: $dnsIP published in DNS exist in local IP configuration."
                ##if ($dnsIP -notin $localIPs) { ## Requires PowerShell 3. Works fine :(
                if ($localIPs -notcontains $dnsIP) {
                   $dnsFail += "IP '$dnsIP' in DNS record do not exist locally`n"
                   $logFail += "$dnsIP "
                   $obj = $false
                }
            }
        }
        else {
            $hn = $dnscheck.HostName
            $dnsFail = 'DNS name: ' +$hn + ' local fqdn: ' +$fqdn + ' DNS IPs: ' +$dnsAddressList + ' Local IPs: ' + $localIPs
            $obj = $false
            Write-Host $dnsFail
        }

        $FileLogLevel = ((Get-ChConfigLoggingLevel).ToString()).ToLower()

        switch ($obj) {
            $false {
                $fix = (Get-ChConfigDNSFix).ToLower()
                if ($fix -eq "true") {
                    $text = 'DNS Check: FAILED. IP address published in DNS do not match IP address on local machine. Trying to resolve by registerting with DNS server'
                    if ($PowerShellVersion -ge 4) { Register-DnsClient | out-null  }
                    else { ipconfig /registerdns | out-null }
                    Write-Host $text
                    $logDNS = $logFail
                    if (-NOT($FileLogLevel -like "clientlocal")) {
                        Write-ChLog -Text $text -Severity 2
                        Write-ChLog -Text $dnsFail -Severity 2
                    }

                }
                else {
                    $text = 'DNS Check: FAILED. IP address published in DNS do not match IP address on local machine. Monitor mode only, no remediation'
                    $logDNS = $logFail
                    if (-NOT($FileLogLevel -like "clientlocal")) { Write-ChLog -Text $text  -Severity 2}
                    Write-Host $text
                }

            }
            $true {
                $text = 'DNS Check: OK'
                Write-Host $text
                $logDNS = 'OK'
            }
        }
        return $logDNS
    }

    Function Test-CCMSetup1 {
        # Function to test that 'HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\' is set to '%USERPROFILE%\AppData\Roaming'. CCMSETUP will fail if not.
        # Reference: https://www.systemcenterdudes.com/could-not-access-network-location-appdata-ccmsetup-log/
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
        $correctValue = '%USERPROFILE%\AppData\Roaming'
        $currentValue = (Get-Item 'HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\').GetValue('AppData', $null, 'DoNotExpandEnvironmentNames')

       # Only fix if the value is wrong
       if ($currentValue -ne $correctValue) { Set-ItemProperty -Path  'HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\' -Name 'AppData' -Value $correctValue }
    }

    Function Test-Update {
        #if (($Json.Option | Where-Object {$_.Name -like 'Updates'} | Select-Object -ExpandProperty 'Enable') -like 'True') {

        $UpdateShare = Get-ChConfigUpdatesShare
        #$UpdateShare = $Json.Option | Where-Object {$_.Name -like 'Updates'} | Select-Object -ExpandProperty 'Share'


        Write-Verbose "Validating required updates is installed on the client. Required updates will be installed if missing on client."
        #$OS = Get-WmiObject -class Win32_OperatingSystem
        $OSName = Get-OperatingSystem


        $build = $null
        if ($OSName -like "*Windows 10*") {
            $build = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber
            switch ($build) {
                10240 {$OSName = $OSName + " 1507"}
                10586 {$OSName = $OSName + " 1511"}
                14393 {$OSName = $OSName + " 1607"}
                15063 {$OSName = $OSName + " 1703"}
                16299 {$OSName = $OSName + " 1709"}
                17134 {$OSName = $OSName + " 1803"}
                17763 {$OSName = $OSName + " 1809"}
                18362 {$OSName = $OSName + " 1903"}
                18363 {$OSName = $OSName + " 1909"}
                19041 {$OSName = $OSName + " 2004"}
                19042 {$OSName = $OSName + " 20H2"}
                19043 {$OSName = $OSName + " 21H1"}
                19044 {$OSName = $OSName + " 21H2"}
                19045 {$OSName = $OSName + " 22H2"}
                default {$OSName = $OSName + " Insider Preview"}
            }
        }

        $Updates = (Join-Path $UpdateShare $OSName)
        If ((Test-Path $Updates) -eq $true) {
            $regex = '(?i)^.+-kb[0-9]{6,}-(?:v[0-9]+-)?x[0-9]+\.msu$'
            $hotfixes = @(Get-ChildItem $Updates | Where-Object { $_.Name -match $regex } | Select-Object -ExpandProperty Name)

            if ($PowerShellVersion -ge 6) { $installedUpdates = @((Get-CimInstance Win32_QuickFixEngineering).HotFixID) }
            else { $installedUpdates = @(Get-Hotfix | Select-Object -ExpandProperty HotFixID) }

            $count = $hotfixes.count

            if (($count -eq 0) -or ($count -eq $null)) {
                $text = 'Updates: No mandatory updates to install.'
                Write-Host $text
                $logUpdates = 'OK'
            }
            else {
                $logEntry = $null

				$regex = '\b(?!(KB)+(\d+)\b)\w+'
                foreach ($hotfix in $hotfixes) {
                    $kb = $hotfix -replace $regex -replace "\." -replace "-"
                    if ($installedUpdates -contains $kb) {
                        $text = "Update $hotfix" + ": OK"
                        Write-Host $text
                    }
                    else {
                        if ($null -eq $logEntry) { $logEntry = $kb }
                        else { $logEntry += ", $kb" }

                        $fix = (Get-ChConfigUpdatesFix).ToLower()
                        if ($fix -eq "true") {
                            $kbfullpath = Join-Path $updates $hotfix
                            $text = "Update $hotfix" + ": Missing. Installing now..."
                            Write-Warning $text

                            $temppath = Join-Path (Get-ChLocalFilesPath) "Temp"

                            If ((Test-Path $temppath) -eq $false) { New-Item -Path $temppath -ItemType Directory | Out-Null }

                            Copy-Item -Path $kbfullpath -Destination $temppath
                            $install = Join-Path $temppath $hotfix

                            wusa.exe $install /quiet /norestart
                            While (Get-Process wusa -ErrorAction SilentlyContinue) { Start-Sleep -Seconds 2 }
                            Remove-Item $install -Force -Recurse

                        }
                        else {
                            $text = "Update $hotfix" + ": Missing. Monitor mode only, no remediation."
                            Write-Warning $text
                        }
                    }

                    if ($null -eq $logEntry) { $logUpdates = 'OK' }
                    else { $logUpdates = $logEntry }
                }
            }
        }
        Else {
            $logUpdates = 'Failed'
            Write-Warning "Updates Failed: Could not locate update folder '$($Updates)'."
        }
        return $logUpdates
    }

    Function Test-ConfigMgrClient {
        $ClientStatus = [PSCustomObject]@{
            ClientInstalledReason = ""
            ClientInstalled = $null
        }

        $installenabled = Get-ChConfigClientInstallEnabled

        # Check if the SCCM Agent is installed or not.
        # If installed, perform tests to decide if reinstall is needed or not.
        if (Get-Service -Name ccmexec -ErrorAction SilentlyContinue) {
            $text = "Configuration Manager Client is installed"
            Write-Host $text

            # Lets not reinstall client unless tests tells us to.
            $Reinstall = $false

            # We test that the local database files exists. Less than 7 means the client is horrible broken and requires reinstall.
            $LocalDBFilesPresent = Test-CcmSDF
            if ($LocalDBFilesPresent -eq $False) {
                    $ClientStatus.ClientInstalledReason += "ConfigMgr Client database files missing. "
                    Write-Host "ConfigMgr Client database files missing. Reinstalling..."
                    # Add /ForceInstall to Client Install Properties to ensure the client is uninstalled before we install client again.
                    #if (-NOT ($clientInstallProperties -like "*/forceinstall*")) { $clientInstallProperties = $clientInstallProperties + " /forceinstall" }
                    $Reinstall = $true
                    $Uninstall = $true
            }

            # Only test CM client local DB if this check is enabled
            $testLocalDB = (Get-ChConfigCcmSQLCELog).ToLower()
            if ($testLocalDB -like "enable") {
                Write-Host "Testing CcmSQLCELog"
                $LocalDB = Test-CcmSQLCELog
                if ($LocalDB -eq $true) {
                    # LocalDB is messed up
                    $ClientStatus.ClientInstalledReason += "ConfigMgr Client database corrupt. "
                    Write-Host "ConfigMgr Client database corrupt. Reinstalling..."
                    $Reinstall = $true
                    $Uninstall = $true
                }
            }

            $CCMService = Get-Service -Name ccmexec -ErrorAction SilentlyContinue

            # Reinstall if we are unable to start the CM client
            if (($CCMService.Status -eq "Stopped") -and ($LocalDB -eq $false)) {
                try {
                    Write-Host "ConfigMgr Agent not running. Attempting to start it."
                    if ($CCMService.StartType -ne "Automatic") {
                        $text = "Configuring service CcmExec StartupType to: Automatic (Delayed Start)..."
                        Write-Host $text
                        Set-Service -Name CcmExec -StartupType Automatic
                    }
                    Start-Service -Name CcmExec
                }
                catch {
                    $Reinstall = $true
                    $ClientStatus.ClientInstalledReason += "Service not running, failed to start. "
                }
            }

            # Test that we are able to connect to SMS_Client WMI class
            Try {
                if ($PowerShellVersion -ge 6) { $WMI = Get-CimInstance -Namespace root/ccm -Class SMS_Client -ErrorAction Stop }
                else { $WMI = Get-WmiObject -Namespace root/ccm -Class SMS_Client -ErrorAction Stop }
            } Catch {
                Write-Verbose 'Failed to connect to WMI namespace "root/ccm" class "SMS_Client". Clearing WMI and tagging client for reinstall to fix.'

                # Clear the WMI namespace to avoid having to uninstall first
                # This is the same action the install after an uninstall would perform
                Get-WmiObject -Query "Select * from __Namespace WHERE Name='CCM'" -Namespace root | Remove-WmiObject

                $Reinstall = $true
                $ClientStatus.ClientInstalledReason += "Failed to connect to SMS_Client WMI class. "
            }

            if ( $reinstall -eq $true) {
                $text = "ConfigMgr Client Health thinks the agent need to be reinstalled.."
                Write-Host $text
                # Lets check that registry settings are OK before we try a new installation.
                Test-CCMSetup1

                # Adding forceinstall to the client install properties to make sure previous client is uninstalled.
                #if ( ($localDB -eq $true) -and (-NOT ($clientInstallProperties -like "*/forceinstall*")) ) { $clientInstallProperties = $clientInstallProperties + " /forceinstall" }
                Resolve-Client -ClientInstallProperties $clientInstallProperties -FirstInstall $false
                $ClientStatus.ClientInstalled = Get-SmallDateTime
                Start-Sleep 600
            }
        }
        else {
            if ($installenabled -eq 'true') {
                $text = "Configuration Manager client is not installed. Installing..."
                Write-Host $text
                Resolve-Client -ClientInstallProperties $clientInstallProperties -FirstInstall $true
                $ClientStatus.ClientInstalledReason += "No agent found. "
                $ClientStatus.ClientInstalled = Get-SmallDateTime
                # Test again if agent is installed
                if (Get-Service -Name ccmexec -ErrorAction SilentlyContinue) {}
                else { Write-ChLog "ConfigMgr Client installation failed. Agent not detected 10 minutes after triggering installation."  -Mode "ClientInstall" -Severity 3}
            } else {
                $ClientStatus.ClientInstalledReason += "No agent found. Client install disabled in config. "
            }
        }
        return $ClientStatus
    }

    Function Test-ClientCacheSize {
        $ClientCacheSize = Get-ChConfigClientCache
        #if ($PowerShellVersion -ge 6) { $Cache = Get-CimInstance -Namespace "ROOT\CCM\SoftMgmtAgent" -Class CacheConfig }
        #else { $Cache = Get-WmiObject -Namespace "ROOT\CCM\SoftMgmtAgent" -Class CacheConfig }
        $CacheSize = [PSCustomObject]@{
            'Log'     = 0
            'Changed' = $false
        }

        $CurrentCache = Get-ClientCache

        if ($ClientCacheSize -match '%') {
            $type = 'percentage'
            # percentage based cache based on disk space
            $num = $ClientCacheSize -replace '%'
            $num = ($num / 100)
            # TotalDiskSpace in Byte
            if ($PowerShellVersion -ge 6) { $TotalDiskSpace = (Get-CimInstance -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "$env:SystemDrive"} | Select-Object -ExpandProperty Size) }
            else { $TotalDiskSpace = (Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "$env:SystemDrive"} | Select-Object -ExpandProperty Size) }
            $ClientCacheSize = ([math]::Round(($TotalDiskSpace * $num) / 1048576))
        }
        else { $type = 'fixed' }

        if ($CurrentCache -eq $ClientCacheSize) {
            $text = "ConfigMgr Client Cache Size: OK"
            Write-Host $text
            $CacheSize.Log = $CurrentCache
            $CacheSize.Changed = $false
        } else {
            switch ($type) {
                'fixed' {$text = "ConfigMgr Client Cache Size: $CurrentCache. Expected: $ClientCacheSize. Redmediating."}
                'percentage' {
                    $percent = Get-ChConfigClientCache
                    if ($ClientCacheSize -gt "99999") { $ClientCacheSize = "99999" }
                    $text = "ConfigMgr Client Cache Size: $CurrentCache. Expected: $ClientCacheSize ($percent). (99999 maxium). Redmediating."
                }
            }

            Write-Warning $text
            $CacheSize.Log = $ClientCacheSize
            try {
                $UIResourceMgr = New-Object -ComObject UIResource.UIResourceMgr -ErrorAction Stop
                $UIResourceMgr.GetCacheInfo().TotalSize = "$ClientCacheSize"
                $CacheSize.Changed = $true
            }
            catch {
                $CacheSize.Changed = $false
            }
        }
        return $CacheSize
    }

    Function Test-ClientVersion {
        $CVObject = [PSCustomObject]@{
            'Version'   = ""
            'VersionMismatch' = $true
        }
        $ClientVersion = Get-ChConfigClientVersion
        [String]$ClientAutoUpgrade = Get-ChConfigClientAutoUpgrade
        $ClientAutoUpgrade = $ClientAutoUpgrade.ToLower()
        $installedVersion = Get-ClientVersion
        $CVObject.Version = $installedVersion

        if ([version]$installedVersion -ge [version]$ClientVersion) {
            $text = 'ConfigMgr Client version is: ' +$installedVersion + ': OK'
            Write-Host $text
            $CVObject.VersionMismatch = $false
        }
        elseif ($ClientAutoUpgrade -like 'true') {
            $text = 'ConfigMgr Client version is: ' +$installedVersion +': Tagging client for upgrade to version: '+$ClientVersion
            Write-Warning $text
            $CVObject.VersionMismatch = $true
        }
        else {
            $text = 'ConfigMgr Client version is: ' +$installedVersion +': Required version: '+$ClientVersion +' AutoUpgrade: false. Skipping upgrade'
            Write-Host $text
            $CVObject.VersionMismatch = $false
        }
        return $CVObject
    }

    Function Test-ClientSiteCode {
        try {
            $sms = New-Object -ComObject "Microsoft.SMS.Client" -ErrorAction Stop
        }
        catch {
            return "NA"
        }
        $ClientSiteCode = Get-ChConfigClientSitecode
        #[String]$currentSiteCode = Get-Sitecode
        $currentSiteCode = $sms.GetAssignedSite()
        $currentSiteCode = $currentSiteCode.Trim()
        $LogSitecode = $currentSiteCode

        # Do more investigation and testing on WMI Method "SetAssignedSite" to possible avoid reinstall of client for this check.
        if ($ClientSiteCode -like $currentSiteCode) {
            $text = "ConfigMgr Client Site Code: OK"
            Write-Host $text
            #$obj = $false
        }
        else {
            $text = 'ConfigMgr Client Site Code is "' +$currentSiteCode + '". Expected: "' +$ClientSiteCode +'". Changing sitecode.'
            Write-Warning $text
            $sms.SetAssignedSite($ClientSiteCode)
            #$obj = $true
        }
        return $LogSitecode
    }

    function Test-PendingReboot {
        $PRObject = [PSCustomObject]@{
            'Message'       = ""
            'AppStartTime'  = $null
        }
        # Only run pending reboot check if enabled in config
        if (($json.Option | Where-Object {$_.Name -like 'PendingReboot'} | Select-Object -ExpandProperty 'Enable') -like 'True') {
            $result = @{
                CBSRebootPending =$false
                WindowsUpdateRebootRequired = $false
                FileRenamePending = $false
                SCCMRebootPending = $false
            }

            #Check CBS Registry
            $key = Get-ChildItem "HKLM:Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
            if ($null -ne $key) { $result.CBSRebootPending = $true }

            #Check Windows Update
            $key = Get-Item 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue
            if ($null -ne $key) { $result.WindowsUpdateRebootRequired = $true }

            #Check PendingFileRenameOperations
            $prop = Get-ItemProperty 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
            if ($null -ne $prop)
            {
                #PendingFileRenameOperations is not *must* to reboot?
                #$result.FileRenamePending = $true
            }

            try
            {
                $util = [wmiclass]'\\.\root\ccm\clientsdk:CCM_ClientUtilities'
                $status = $util.DetermineIfRebootPending()
                if(($null -ne $status) -and $status.RebootPending){ $result.SCCMRebootPending = $true}
            }
            catch{}

            #Return Reboot required
            if ($result.ContainsValue($true)) {
                $text = 'Pending Reboot: Computer is in pending reboot'
                Write-Warning $text
                $PRObject.Message = 'Pending Reboot'

                if ((Get-ChConfigPendingRebootApp) -eq $true) {
                    Start-RebootApplication
                    $PRObject.AppStartTime = Get-SmallDateTime
                }
            }
            else {
                $text = 'Pending Reboot: OK'
                Write-Host $text
                $PRObject.Message = 'OK'
            }
        }
        return $PRObject
    }

    # Functions to detect and fix errors
    Function Test-ProvisioningMode {
        $registryPath = 'HKLM:\SOFTWARE\Microsoft\CCM\CcmExec'
        $provisioningMode = (Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue).ProvisioningMode

        if ($provisioningMode -eq 'true') {
            $text = 'ConfigMgr Client Provisioning Mode: YES. Remediating...'
            Write-Warning $text
            Set-ItemProperty -Path $registryPath -Name ProvisioningMode -Value "false"
            $ArgumentList = @($false)
            if ($PowerShellVersion -ge 6) { Invoke-CimMethod -Namespace 'root\ccm' -Class 'SMS_Client' -MethodName 'SetClientProvisioningMode' -Arguments @{bEnable=$false} | Out-Null }
            else { Invoke-WmiMethod -Namespace 'root\ccm' -Class 'SMS_Client' -Name 'SetClientProvisioningMode' -ArgumentList $ArgumentList | Out-Null  }
            $logProvisioningMode = 'Repaired'
        }
        else {
            $text = 'ConfigMgr Client Provisioning Mode: OK'
            Write-Host $text
            $logProvisioningMode = 'OK'
        }
        return $logProvisioningMode
    }

    Function Test-StateMessages {
        [CmdletBinding()]
        param()
        Write-Verbose "Check StateMessage.log if State Messages are successfully forwarded to Management Point"
        $logdir = Get-CCMLogDirectory
        $logfile = "$logdir\StateMessage.log"
        $StateMessage = Get-Content($logfile)
        if ($StateMessage -match 'Successfully forwarded State Messages to the MP') {
            $text = 'StateMessage: OK'
            $logStateMessages = 'OK'
            Write-Verbose $text
        }
        else {
            $text = 'StateMessage: ERROR. Remediating...'
            Write-Warning $text
            Write-Verbose "Start Refreshing State messages"
            try{
                $SCCMUpdatesStore = New-Object -ComObject Microsoft.CCM.UpdatesStore
                $SCCMUpdatesStore.RefreshServerComplianceState()
                $logStateMessages = 'Repaired'
                Write-Verbose "End Refreshing State messages"
            }
            catch{
                $logStateMessages = 'Repair Failed'
                Write-Verbose "End Refreshing State messages - FAILED!"
            }
        }
        return $logStateMessages
    }

    Function Test-RegistryPol {
        [CmdletBinding()]
        Param(
            [datetime]$StartTime=[datetime]::MinValue,
            $Days)
        $logWUAHandler = "Checking"
        $RepairReason = ""
        $MachineRegistryFile = "$($env:WinDir)\System32\GroupPolicy\Machine\registry.pol"

        # Check 1 - Error in WUAHandler.log
        Write-Verbose "Check WUAHandler.log for errors since $($StartTime)."
        $logdir = Get-CCMLogDirectory
        $logfile = "$logdir\WUAHandler.log"
        $logLine = Search-CMLogFile -LogFile $logfile -StartTime $StartTime -SearchStrings @('0x80004005','0x87d00692')
        if ($logLine) {$RepairReason = "WUAHandler Log"}

        # Check 2 - Registry.pol is too old.
        if ($Days) {
            Write-Verbose "Check machine registry file to see if it's older than $($Days) days."
            try {
                $file = Get-ChildItem -Path $MachineRegistryFile -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty LastWriteTime
                $regPolDate = Get-Date($file)
                $now = Get-Date
                if (($now - $regPolDate).Days -ge $Days) {$RepairReason = "File Age"}
            }
            catch { Write-Warning "GPO Cache: Failed to check machine policy age." }
        }

        # Check 3 - Look back through the last 7 days for group policy processing errors.
        #Event IDs documented here: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749336(v=ws.10)#troubleshooting-group-policy-using-event-logs-1
        try {
            Write-Verbose "Checking the Group Policy event log for errors since $($StartTime)."
            $numberOfGPOErrors = (Get-WinEvent -Verbose:$false -FilterHashTable @{LogName='Microsoft-Windows-GroupPolicy/Operational';Level=2;StartTime=$StartTime} -ErrorAction SilentlyContinue | Where-Object {($_.ID -ge 7000 -and $_.ID -le 7007) -or ($_.ID -ge 7017 -and $_.ID -le 7299) -or ($_.ID -eq 1096)}).Count
            if ($numberOfGPOErrors -gt 0) {$RepairReason = "Event Log"}

        }
        catch { Write-Warning "GPO Cache: Failed to check the event log for policy errors." }

        #If we need to repart the policy files then do so.
        if ($RepairReason -ne ""){
            $logWUAHandler = "Broken ($RepairReason)"
            Write-Host "GPO Cache: Broken ($RepairReason)"
            Write-Verbose 'Deleting registry.pol and running gpupdate...'

            try { if (Test-Path -Path $MachineRegistryFile) {Remove-Item $MachineRegistryFile -Force } }
            catch { Write-Warning "GPO Cache: Failed to remove the registry file ($($MachineRegistryFile))." }
            finally { & Write-Output n | gpupdate.exe /force /target:computer | Out-Null  }

            #Write-Verbose 'Sleeping for 1 minute to allow for group policy to refresh'
            #Start-Sleep -Seconds 60

            Write-Verbose 'Refreshing update policy'
            Get-SCCMPolicyScanUpdateSource
            Get-SCCMPolicySourceUpdateMessage

            $logWUAHandler = "Repaired ($RepairReason)"
            Write-Host "GPO Cache: $logWUAHandler"
        }
        else {
            $logWUAHandler = 'OK'
            Write-Host "GPO Cache: OK"
        }
        return $logWUAHandler
    }

    Function Test-ClientLogSize {
        [CmdletBinding()]
        param()
        try { [int]$currentLogSize = Get-ClientMaxLogSize }
        catch { [int]$currentLogSize = 0 }
        try { [int]$currentMaxHistory = Get-ClientMaxLogHistory }
        catch { [int]$currentMaxHistory = 0 }
        try { $logLevel = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global' -ErrorAction stop).logLevel }
        catch { $logLevel = 1 }

        $LogSizeObject = [PSCustomObject]@{
            'RestartClient'    = $false
            'LogMaxLogSize'    = $currentLogSize
            'LogMaxLogHistory' = $currentMaxHistory
        }
        $clientLogSize = Get-ChConfigClientMaxLogSize
        $clientLogMaxHistory = Get-ChConfigClientMaxLogHistory

        $text = ''

        if ( ($currentLogSize -eq $clientLogSize) -and ($currentMaxHistory -eq $clientLogMaxHistory) ) {
            $LogSizeObject.LogMaxLogSize = $currentLogSize
            $LogSizeObject.LogMaxLogHistory = $currentMaxHistory
            $text = "ConfigMgr Client Max Log Size: OK ($currentLogSize)"
            Write-Host $text
            $text = "ConfigMgr Client Max Log History: OK ($currentMaxHistory)"
            Write-Host $text
            $LogSizeObject.RestartClient = $false
        }
        else {
            if ($currentLogSize -ne $clientLogSize) {
                $text = 'ConfigMgr Client Max Log Size: Configuring to '+ $clientLogSize +' KB'
                $LogSizeObject.LogMaxLogSize = $clientLogSize
                Write-Warning $text
            }
            else {
                $text = "ConfigMgr Client Max Log Size: OK ($currentLogSize)"
                Write-Host $text
            }
            if ($currentMaxHistory -ne $clientLogMaxHistory) {
                $text = 'ConfigMgr Client Max Log History: Configuring to ' +$clientLogMaxHistory
                $LogSizeObject.LogMaxLogHistory = $clientLogMaxHistory
                Write-Warning $text
            }
            else {
                $text = "ConfigMgr Client Max Log History: OK ($currentMaxHistory)"
                Write-Host $text
            }

            $newLogSize = [int]$clientLogSize
            $newLogSize = $newLogSize * 1000

            <#
            if ($PowerShellVersion -ge 6) {Invoke-CimMethod -Namespace "root/ccm" -ClassName "sms_client" -MethodName SetGlobalLoggingConfiguration -Arguments @{LogLevel=$loglevel; LogMaxHistory=$clientLogMaxHistory; LogMaxSize=$newLogSize} }
            else {
                $smsClient = [wmiclass]"root/ccm:sms_client"
                $smsClient.SetGlobalLoggingConfiguration($logLevel, $newLogSize, $clientLogMaxHistory)
            }
            #Write-Verbose 'Returning true to trigger restart of ccmexec service'
            #>
            
            # Rewrote after the WMI Method stopped working in previous CM client version
            try {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Logging\@GLOBAL" -Name LogMaxHistory -PropertyType DWORD -Value $clientLogMaxHistory -Force -ErrorAction Stop | Out-Null
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Logging\@GLOBAL" -Name LogMaxSize -PropertyType DWORD -Value $newLogSize -Force  -ErrorAction Stop | Out-Null
                $LogSizeObject.RestartClient = $true
            }
            catch {
                $LogSizeObject.RestartClient = $false
            }
            try { $LogSizeObject.LogMaxLogSize = Get-ClientMaxLogSize }
            catch { $LogSizeObject.LogMaxLogSize = 0 }
            try { $LogSizeObject.LogMaxLogHistory = Get-ClientMaxLogHistory }
            catch { $LogSizeObject.LogMaxLogHistory = 0 }
        }
        return $LogSizeObject
    }

    Function Remove-CCMOrphanedCache {
        [CmdletBinding()]
        param()
        Write-Host "Clearing ConfigMgr orphaned Cache items."
        try {
            $CCMCache = "$env:SystemDrive\Windows\ccmcache"
            $CCMCache = (New-Object -ComObject "UIResource.UIResourceMgr").GetCacheInfo().Location
            if ($null -eq $CCMCache) { $CCMCache = "$env:SystemDrive\Windows\ccmcache" }
            $ValidCachedFolders = (New-Object -ComObject "UIResource.UIResourceMgr").GetCacheInfo().GetCacheElements() | ForEach-Object {$_.Location}
            $AllCachedFolders = (Get-ChildItem -Path $CCMCache) | Select-Object Fullname -ExpandProperty Fullname

            ForEach ($CachedFolder in $AllCachedFolders) {
                If ($ValidCachedFolders -notcontains $CachedFolder) {
                    #Don't delete new folders that might be syncing data with BITS
                    if ((Get-ItemProperty $CachedFolder).LastWriteTime -le (get-date).AddDays(-14)) {
                        Write-Verbose "Removing orphaned folder: $CachedFolder - LastWriteTime: $((Get-ItemProperty $CachedFolder).LastWriteTime)"
                        Remove-Item -Path $CachedFolder -Force -Recurse
                    }
                }
            }
        }
        catch { Write-Host "Failed Clearing ConfigMgr orphaned Cache items." }
        }

    Function Resolve-Client {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true)]$ClientInstallProperties,
            [Parameter(Mandatory=$false)]$FirstInstall=$false
            )

        $ClientShare = Get-ChConfigClientShare
        if ((Test-Path $ClientShare -ErrorAction SilentlyContinue) -eq $true) {
            if ($FirstInstall -eq $true) { $text = 'Installing Configuration Manager Client.' }
            else { $text = 'Client tagged for reinstall. Reinstalling client...' }
            Write-Host $text

            Write-Verbose "Perform a test on a specific registry key required for ccmsetup to succeed."
            Test-CCMSetup1

            Write-Verbose "Enforce registration of common DLL files to make sure CCM Agent works."
            $DllFiles = 'actxprxy.dll', 'atl.dll', 'Bitsprx2.dll', 'Bitsprx3.dll', 'browseui.dll', 'cryptdlg.dll', 'dssenh.dll', 'gpkcsp.dll', 'initpki.dll', 'jscript.dll', 'mshtml.dll', 'msi.dll', 'mssip32.dll', 'msxml.dll', 'msxml3.dll', 'msxml3a.dll', 'msxml3r.dll', 'msxml4.dll', 'msxml4a.dll', 'msxml4r.dll', 'msxml6.dll', 'msxml6r.dll', 'muweb.dll', 'ole32.dll', 'oleaut32.dll', 'Qmgr.dll', 'Qmgrprxy.dll', 'rsaenh.dll', 'sccbase.dll', 'scrrun.dll', 'shdocvw.dll', 'shell32.dll', 'slbcsp.dll', 'softpub.dll', 'rlmon.dll', 'userenv.dll', 'vbscript.dll', 'Winhttp.dll', 'wintrust.dll', 'wuapi.dll', 'wuaueng.dll', 'wuaueng1.dll', 'wucltui.dll', 'wucltux.dll', 'wups.dll', 'wups2.dll', 'wuweb.dll', 'wuwebv.dll', 'Xpob2res.dll', 'WBEM\wmisvc.dll'
            foreach ($Dll in $DllFiles) {
                $file =  $env:windir +"\System32\$Dll"
                Register-DLLFile -FilePath $File
            }

            if ($Uninstall -eq $true) {
				Write-Verbose "Trigger ConfigMgr Client uninstallation using Invoke-Expression."
				Invoke-Expression "&'$ClientShare\ccmsetup.exe' /uninstall"

				$launched = $true
				do {
					Start-Sleep -seconds 5
					if (Get-Process "ccmsetup" -ErrorAction SilentlyContinue) {
						Write-Verbose "ConfigMgr Client Uninstallation still running"
						$launched = $true
					}
					else { $launched = $false }
                } while ($launched -eq $true)
            }

            Write-Verbose "Trigger ConfigMgr Client installation using Invoke-Expression."
            Write-Verbose "Client install string: $ClientShare\ccmsetup.exe $ClientInstallProperties"
            Invoke-Expression "&'$ClientShare\ccmsetup.exe' $ClientInstallProperties"

			$launched = $true
			do {
				Start-Sleep -seconds 5
				if (Get-Process "ccmsetup" -ErrorAction SilentlyContinue) {
					Write-Verbose "ConfigMgr Client installation still running"
					$launched = $true
				}
				else { $launched = $false }
            } while ($launched -eq $true)

            if ($FirstInstall -eq $true) {
                Write-Host "ConfigMgr Client was installed for the first time. Waiting 6 minutes for client to syncronize policy before proceeding."
                Start-Sleep -Seconds 360
            }
        }
        else {
            $text = 'ERROR: Client tagged for reinstall, but failed to access fileshare: ' +$ClientShare
            Write-Error $text
            Exit 1
        }
    }

    function Register-DLLFile {
        [CmdletBinding()]
        param ([string]$FilePath)

        try { $Result = Start-Process -FilePath 'regsvr32.exe' -Args "/s `"$FilePath`"" -Wait -NoNewWindow -PassThru }
        catch {}
    }

    Function Test-WMI {
        [CmdletBinding()]
        $vote = 0
        $result = winmgmt /verifyrepository
        switch -wildcard ($result) {
            # Always fix if this returns inconsistent
            "*inconsistent*" { $vote = 100 } # English
            "*not consistent*"  { $vote = 100 } # English
            "*inkonsekvent*" { $vote = 100 } # Swedish
            "*epäyhtenäinen*" { $vote = 100 } # Finnish
            "*inkonsistent*" { $vote = 100 } # German
            # Add more languages as I learn their inconsistent value
        }

        Try {
            if ($PowerShellVersion -ge 6) { $WMI = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
            else { $WMI = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop }
        } Catch {
            Write-Verbose 'Failed to connect to WMI class "Win32_ComputerSystem". Voting for WMI fix...'
            $vote++
        } Finally {
            if ($vote -eq 0) {
                $text = 'WMI Check: OK'
                $logWMI = 'OK'
                Write-Host $text
            }
            else {
                $fix = Get-ChConfigWMIRepairEnable
                if ($fix -like "True") {
                    $text = 'WMI Check: Corrupt. Attempting to repair WMI and reinstall ConfigMgr client.'
                    Write-Warning $text
                    Repair-WMI
                    $logWMI = 'Repaired'
                }
                else {
                    $text = 'WMI Check: Corrupt. Autofix is disabled'
                    Write-Warning $text
                    $logWMI = 'Corrupt'
                }
                Write-Verbose "returning true to tag client for reinstall"
                $Reinstall = $true
            }
        }
        return $logWMI
    }

    Function Repair-WMI {
        [CmdletBinding()]
        $text ='Repairing WMI'
        Write-Host $text

        # Check PATH
        if((! (@(($ENV:PATH).Split(";")) -contains "$env:SystemDrive\WINDOWS\System32\Wbem")) -and (! (@(($ENV:PATH).Split(";")) -contains "%systemroot%\System32\Wbem"))){
            $text = "WMI Folder not in search path!."
            Write-Warning $text
        }
        # Stop WMI
        Stop-Service -Force ccmexec -ErrorAction SilentlyContinue
        Stop-Service -Force winmgmt

        # WMI Binaries
        [String[]]$aWMIBinaries=@("unsecapp.exe","wmiadap.exe","wmiapsrv.exe","wmiprvse.exe","scrcons.exe")
        foreach ($sWMIPath in @(($ENV:SystemRoot+"\System32\wbem"),($ENV:SystemRoot+"\SysWOW64\wbem"))) {
            if(Test-Path -Path $sWMIPath){
                push-Location $sWMIPath
                foreach($sBin in $aWMIBinaries){
                    if(Test-Path -Path $sBin){
                        $oCurrentBin=Get-Item -Path  $sBin
                        & $oCurrentBin.FullName /RegServer
                    }
                    else{
                        # Warning only for System32
                        if($sWMIPath -eq $ENV:SystemRoot+"\System32\wbem"){
                            Write-Warning "File $sBin not found!"
                        }
                    }
                }
                Pop-Location
            }
        }

        # Reregister Managed Objects
        Write-Verbose "Reseting Repository..."
        & ($ENV:SystemRoot+"\system32\wbem\winmgmt.exe") /resetrepository
        & ($ENV:SystemRoot+"\system32\wbem\winmgmt.exe") /salvagerepository
        Start-Service winmgmt
        $text = 'Tagging ConfigMgr client for reinstall'
        Write-Warning $text
    }

    # Test if the compliance state messages should be resent.
    Function Test-RefreshComplianceState {
        Param(
            $Days=0,
            [Parameter(Mandatory=$true)]$ClientHealthRegistryKey
        )
        $RegValueName="RefreshServerComplianceState"

        #Get the last time this script was ran.  If the registry isn't found just use the current date.
        Try { [datetime]$LastSent = Get-RegistryValue -Path $ClientHealthRegistryKey -Name $RegValueName }
        Catch { [datetime]$LastSent = Get-Date }

        Write-Verbose "The compliance states were last sent on $($LastSent)"
        #Determine the number of days until the next run.
        $NumberOfDays = (New-Timespan -Start (Get-Date) -End ($LastSent.AddDays($Days))).Days

        #Resend complianc states if the next interval has already arrived or randomly based on the number of days left until the next interval.
        If (($NumberOfDays -le 0) -or ((Get-Random -Maximum $NumberOfDays) -eq 0 )){
            Try{
                Write-Verbose "Resending compliance states."
                (New-Object -ComObject Microsoft.CCM.UpdatesStore).RefreshServerComplianceState()
                $LastSent=Get-Date
                Write-Host "Compliance States: Refreshed."
            }
            Catch{
                Write-Error "Failed to resend the compliance states."
                $LastSent=[datetime]::MinValue
            }
        }
        Else{
            Write-Host "Compliance States: OK."
        }

        Set-RegistryValue -Path $ClientHealthRegistryKey -Name $RegValueName -Value $LastSent
        $LogRefreshComplianceState = Get-SmallDateTime $LastSent
        return $LogRefreshComplianceState
    }

    Function Test-SMSTSMgr {
        If ($service) {
            $service = get-service -Name smstsmgr -ErrorAction SilentlyContinue
            if (($service.ServicesDependedOn).name -contains "ccmexec") {
                write-host "SMSTSMgr: Removing dependency on CCMExec service."
                start-process sc.exe -ArgumentList "config smstsmgr depend= winmgmt" -wait
            }

            # WMI service depenency is present by default
            if (($service.ServicesDependedOn).name -notcontains "Winmgmt") {
                write-host "SMSTSMgr: Adding dependency on Windows Management Instrumentaion service."
                start-process sc.exe -ArgumentList "config smstsmgr depend= winmgmt" -wait
            }
            else { Write-Host "SMSTSMgr: OK"}
        } else {
            Write-Host "SMSTSMgr: Not Found"
        }
    }


    # Windows Service Functions
    Function Test-Services {
        [CmdletBinding()]
        Param([Parameter(Mandatory=$true)]$Services)

        $logServices = 'OK'

        # Test services defined within config.json
        Write-Verbose 'Test services from JSON configuration file'
        foreach ($service in $Services)
        {
            $startuptype = ($service.StartupType).ToLower()

            if ($startuptype -like "automatic (delayed start)") { $service.StartupType = "automaticd" }

            if ($service.uptime) {
                $uptime = ($service.Uptime).ToLower()
                $logServices = Test-Service -Name $service.Name -StartupType $service.StartupType -State $service.State -Uptime $uptime
            }
            else {
                $logServices = Test-Service -Name $service.Name -StartupType $service.StartupType -State $service.State
            }
        }
        return $logServices
    }

    Function Test-Service {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory=$True,
                    HelpMessage='Name')]
                    [string]$Name,
        [Parameter(Mandatory=$True,
                    HelpMessage='StartupType: Automatic, Automatic (Delayed Start), Manual, Disabled')]
                    [string]$StartupType,
        [Parameter(Mandatory=$True,
                    HelpMessage='State: Running, Stopped')]
                    [string]$State,
        [Parameter(Mandatory=$False,
                    HelpMessage='Updatime in days')]
                    [int]$Uptime
        )

        $OSName = Get-OperatingSystem
        # Handle all sorts of casing and mispelling of delayed and triggerd start in config.json services
        $val = $StartupType.ToLower()
        switch -Wildcard ($val) {
            "automaticd*" {$StartupType = "Automatic (Delayed Start)"}
            "automatic(d*" {$StartupType = "Automatic (Delayed Start)"}
            "automatic(t*" {$StartupType = "Automatic (Trigger Start)"}
            "automatict*" {$StartupType = "Automatic (Trigger Start)"}
        }
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        $DelayedAutostart = (Get-ItemProperty -Path $path).DelayedAutostart
        if ($DelayedAutostart -ne 1) {
            $DelayedAutostart = 0
        }
        $service = Get-Service -Name $Name
        if ($PowerShellVersion -ge 6) { $WMIService = Get-CimInstance -Class Win32_Service -Property StartMode, ProcessID, Status -Filter "Name='$Name'" }
        else { $WMIService = Get-WmiObject -Class Win32_Service -Property StartMode, ProcessID, Status -Filter "Name='$Name'" }
        $StartMode = ($WMIService.StartMode).ToLower()
        switch -Wildcard ($StartMode) {
            "auto*" {
                if ($DelayedAutostart -eq 1) { $serviceStartType = "Automatic (Delayed Start)" }
                else { $serviceStartType = "Automatic" }
            }
            <# This will be implemented at a later time.
            "automatic d*" {$serviceStartType = "Automatic (Delayed Start)"}
            "automatic (d*" {$serviceStartType = "Automatic (Delayed Start)"}
            "automatic (t*" {$serviceStartType = "Automatic (Trigger Start)"}
            "automatic t*" {$serviceStartType = "Automatic (Trigger Start)"}
            #>
            "manual" {$serviceStartType = "Manual"}
            "disabled" {$serviceStartType = "Disabled"}
        }
        Write-Verbose "Verify startup type"
        if ($serviceStartType -eq $StartupType)
        {
            $text = "Service $Name startup: OK"
            Write-Host $text
        }
        elseif ($StartupType -like "Automatic (Delayed Start)") {
            # Handle Automatic Trigger Start the dirty way for these two services. Implement in a nice way in future version.
            if ( (($name -eq "wuauserv") -or ($name -eq "W32Time")) -and (($OSName -like "Windows 10*") -or ($OSName -like "*Server 2016*")) ) {
                if ($service.StartType -ne "Automatic") {
                    $text = "Configuring service $Name StartupType to: Automatic (Trigger Start)..."
                    Set-Service -Name $service.Name -StartupType Automatic
                }
                else { $text = "Service $Name startup: OK" }
                Write-Host $text
            }
            else {
                # Automatic delayed requires the use of sc.exe
                & sc.exe config $service start= delayed-auto | Out-Null
                $text = "Configuring service $Name StartupType to: $StartupType..."
                Write-Host $text
                $logService = 'Started'
            }
        }
        else {
            try {
                $text = "Configuring service $Name StartupType to: $StartupType..."
                Write-Host $text
                Set-Service -Name $service.Name -StartupType $StartupType
                $logService = 'Started'
            }
            catch {
                $text = "Failed to set $StartupType StartupType on service $Name"
                Write-Error $text
            }
        }
        Write-Verbose 'Verify service is running'
        if ($service.Status -eq "Running") {
            $text = 'Service ' +$Name+' running: OK'
            Write-Host $text
            #If we are checking uptime.
            If ($Uptime){
                Write-Verbose "Verify the $($Name) service hasn't exceeded uptime of $($Uptime) days."
                $ServiceUptime= Get-ServiceUpTime -Name $Name
                if ($ServiceUptime -ge $Uptime) {
                    try {

                        #Before restarting the service wait for some known processes to end.  Restarting the service while an app or updates is installing might cause issues.
                        $Timer = [Diagnostics.Stopwatch]::StartNew()
                        $WaitMinutes = 30
                        $ProcessesStopped=$True
                        While ((Get-Process -Name WUSA,wuauclt,setup,TrustedInstaller,msiexec,TiWorker,ccmsetup -ErrorAction SilentlyContinue).Count -gt 0){
                            $MinutesLeft = $WaitMinutes - $Timer.Elapsed.Minutes

                            If($MinutesLeft -le 0){
                                Write-Warning "Timed out waiting $($WaitMinutes) minutes for installation processes to complete.  Will not restart the $($Name) service."
                                $ProcessesStopped=$False
                                Break
                            }
                            Write-Warning "Waiting $($MinutesLeft) minutes for installation processes to complete."
                            Start-Sleep -Seconds 30
                        }
                        $Timer.Stop()
                        #If the processes are not running the restart the service.
                        If ($ProcessesStopped){
                            Write-Host "Restarting service: $($Name)..."
                            Restart-Service  -Name $service.Name -Force
                            Write-Host "Restarted service: $($Name)..."
                            $logService = 'Restarted'
                        }
                    } catch {
                        $text = "Failed to restart service $($Name)"
                        Write-Error $text
                    }
                }
                else {
                    Write-Host "Service $($Name) uptime: OK"
                }
            }
        }
        else {
            if ($WMIService.Status -eq 'Degraded') {
                try {
                    Write-Warning "Identified $Name service in a 'Degraded' state. Will force $Name process to stop."
                    $ServicePID = $WMIService | Select-Object -ExpandProperty ProcessID
                    Stop-Process -ID $ServicePID -Force:$true -Confirm:$false -ErrorAction Stop
                    Write-Verbose "Succesfully stopped the $Name service process which was in a degraded state."
                }
                Catch{
                    Write-Error "Failed to force $Name process to stop."
                }
            }
            try {
                $RetryService= $False
                $text = 'Starting service: ' + $Name + '...'
                Write-Host $text
                Start-Service -Name $service.Name -ErrorAction Stop
                $logService = 'Started'
            } catch {
                #Error 1290 (-2146233087) indicates that the service is sharing a thread with another service that is protected and cannot share its thread.
                #This is resolved by configuring the service to run on its own thread.
                If ($_.Exception.Hresult -eq '-2146233087'){
                    Write-Host "Failed to start service $Name because it's sharing a thread with another process.  Changing to use its own thread."
                    & cmd /c sc config $Name type= own
                    $RetryService= $True
                }
                Else{
                    $text = 'Failed to start service ' +$Name
                    Write-Error $text
                }
            }
            #If a recoverable error was found, try starting it again.
            If ($RetryService){
                try {
                    Start-Service -Name $service.Name -ErrorAction Stop
                    $logService = 'Started'
                } catch {
                    $text = 'Failed to start service ' +$Name
                    Write-Error $text
                }
            }
        }
        return $logService
    }

    function Test-AdminShare {
        [CmdletBinding()]
        param()
        Write-Verbose "Test the ADMIN$ and C$"
        if ($PowerShellVersion -ge 6) { $share = Get-CimInstance Win32_Share | Where-Object {$_.Name -like 'ADMIN$'} }
        else { $share = Get-WmiObject Win32_Share | Where-Object {$_.Name -like 'ADMIN$'} }
        #$shareClass = [WMICLASS]"WIN32_Share"  # Depreciated

        if ($share.Name -contains 'ADMIN$') {
            $text = 'Adminshare Admin$: OK'
            Write-Host $text
        }
        else { $fix = $true }

        if ($PowerShellVersion -ge 6) { $share = Get-CimInstance Win32_Share | Where-Object {$_.Name -like 'C$'} }
        else { $share = Get-WmiObject Win32_Share | Where-Object {$_.Name -like 'C$'} }
        #$shareClass = [WMICLASS]'WIN32_Share'  # Depreciated

        if ($share.Name -contains "C$") {
            $text = 'Adminshare C$: OK'
            Write-Host $text
        }
        else { $fix = $true }

        if ($fix -eq $true) {
            $text = 'Error with Adminshares. Remediating...'
            $logAdminShare = 'Repaired'
            Write-Warning $text
            Stop-Service server -Force
            Start-Service server
        }
        else { $logAdminShare = 'OK' }
        return $logAdminShare
    }

    Function Test-DiskSpace {
        [CmdletBinding()]
        param()
        $ConfigDiskSpace = Get-ChConfigOSDiskFreeSpace
        if ($PowerShellVersion -ge 6) { $driveC = Get-CimInstance -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "$env:SystemDrive"} | Select-Object FreeSpace, Size }
        else { $driveC = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "$env:SystemDrive"} | Select-Object FreeSpace, Size }
        $freeSpace = (($driveC.FreeSpace / $driveC.Size) * 100)

        if ($freeSpace -le $ConfigDiskSpace) {
            $text = "Local disk $env:SystemDrive Less than $ConfigDiskSpace % free space"
            Write-Error $text
        }
        else {
            $text ="Free space $env:SystemDrive OK"
            Write-Host $text
        }
    }


    Function Test-CCMSoftwareDistribution {
        # TODO Implement this function
        Get-WmiObject -Class CCM_SoftwareDistributionClientConfig
    }

    Function Invoke-RebootIfNeeded {
        [CmdletBinding()]
        param()
        # Only run if option in config is enabled
        if ((Get-ChConfigRebootApplicationEnable) -like 'True') {

            [float]$maxRebootDays = Get-ChConfigMaxRebootDays
            if ($PowerShellVersion -ge 6) { $wmi = Get-CimInstance Win32_OperatingSystem }
            else { $wmi = Get-WmiObject Win32_OperatingSystem }

            $lastBootTime = $wmi.ConvertToDateTime($wmi.LastBootUpTime)

            $uptime = (Get-Date) - ($wmi.ConvertToDateTime($wmi.lastbootuptime))
            if ($uptime.TotalDays -lt $maxRebootDays) {
                $text = 'Last boot time: ' +$lastBootTime + ': OK'
                Write-Host $text
            }
            elseif (($uptime.TotalDays -ge $maxRebootDays) -and (Get-ChConfigRebootApplicationEnable -eq $true)) {
                $text = 'Last boot time: ' +$lastBootTime + ': More than '+$maxRebootDays +' days since last reboot. Starting reboot application.'
                Write-Warning $text
                Start-RebootApplication
            }
            else {
                $text = 'Last boot time: ' +$lastBootTime + ': More than '+$maxRebootDays +' days since last reboot. Reboot application disabled.'
                Write-Warning $text
            }
        }
    }

    Function Start-RebootApplication {
        [CmdletBinding()]
        param()
        $taskName = 'ConfigMgr Client Health - Reboot on demand'
        #$OS = Get-OperatingSystem
        #if ($OS -like "*Windows 7*") {
            $task = schtasks.exe /query | FIND /I "ConfigMgr Client Health - Reboot"
        #}
        #else { $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
        if ($task -eq $null) { New-RebootTask -taskName $taskName }
        #if ($OS -notlike "*Windows 7*") {Start-ScheduledTask -TaskName $taskName }
        #else {
            schtasks.exe /Run /TN $taskName
        #}
    }

    Function New-RebootTask {
        [CmdletBinding()]
        Param([Parameter(Mandatory=$true)]$taskName)
        $rebootApp = Get-ChConfigRebootApplication

        # $execute is the executable file, $arguement is all the arguments added to it.
        $execute,$arguments = $rebootApp.Split(' ')
        $argument = $null

        foreach ($i in $arguments) { $argument += $i + " " }

        # Trim the " " from argument if present
        $i = $argument.Length -1
        if ($argument.Substring($i) -eq ' ') { $argument = $argument.Substring(0, $argument.Length -1) }

        #$OS = Get-OperatingSystem
        #if ($OS -like "*Windows 7*") {
            schtasks.exe /Create /tn $taskName /tr "$execute $argument" /ru "BUILTIN\Users" /sc ONCE /st 00:00 /sd 01/01/1901
        #}
        <#
        else {
            $action = New-ScheduledTaskAction -Execute $execute -Argument $argument
            $userPrincipal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545"
            Register-ScheduledTask -Action $action -TaskName $taskName -Principal $userPrincipal | Out-Null
        }
        #>
    }

    Function Start-Ccmeval {
        [CmdletBinding()]
        param()
        Write-Host "Starting Built-in Configuration Manager Client Health Evaluation"
        $task = "Microsoft\Configuration Manager\Configuration Manager Health Evaluation"
        schtasks.exe /Run /TN $task | Out-Null
    }

    Function Test-MissingDrivers {
        [CmdletBinding()]
        param()
        $FileLogLevel = ((Get-ChConfigLoggingLevel).ToString()).ToLower()
        $i = 0
        if ($PowerShellVersion -ge 6) { $devices = Get-CimInstance Win32_PNPEntity | Where-Object{ ($_.ConfigManagerErrorCode -ne 0) -and ($_.ConfigManagerErrorCode -ne 22) -and ($_.Name -notlike "*PS/2*") } | Select-Object Name, DeviceID }
        else { $devices = Get-WmiObject Win32_PNPEntity | Where-Object{ ($_.ConfigManagerErrorCode -ne 0) -and ($_.ConfigManagerErrorCode -ne 22) -and ($_.Name -notlike "*PS/2*") } | Select-Object Name, DeviceID }
        $devices | ForEach-Object {$i++}

        if ($devices -ne $null) {
            $text = "Drivers: $i unknown or faulty device(s)"
            Write-Warning $text
            $logDrivers = "$i unknown or faulty driver(s)"

            foreach ($device in $devices) {
                $text = 'Missing or faulty driver: ' +$device.Name + '. Device ID: ' + $device.DeviceID
                Write-Warning $text
                if (-NOT($FileLogLevel -like "clientlocal")) { Write-ChLog -Text $text -Severity 2}
            }
        }
        else {
            $text = "Drivers: OK"
            Write-Host $text
            $logDrivers = 'OK'
        }
        return $logDrivers
    }

    # Function to store SCCM log file changes to be processed
    Function New-SCCMLogFileJob {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true)]$Logfile,
            [Parameter(Mandatory=$true)]$Text,
            [Parameter(Mandatory=$true)]$SCCMLogJobs
        )

        $path = Get-CCMLogDirectory
        $file = "$path\$LogFile"
        $SCCMLogJobs.Rows.Add($file, $text)
    }

    # Function to remove info in SCCM logfiles after remediation. This to prevent false positives triggering remediation next time script runs
    Function Update-SCCMLogFile {
        [CmdletBinding()]
        Param([Parameter(Mandatory=$true)]$SCCMLogJobs)
        Write-Verbose "Start Update-SCCMLogFile"
        foreach ($job in $SCCMLogJobs) { get-content -Path $job.File | Where-Object {$_ -notmatch $job.Text} | Out-File $job.File -Force }
        Write-Verbose "End Update-SCCMLogFile"
    }

    Function Test-SCCMHardwareInventoryScan {
        [CmdletBinding()]
        Param()
        Write-Verbose "Start Test-SCCMHardwareInventoryScan"
        $days = Get-ChConfigHardwareInventoryDays
        if ($PowerShellVersion -ge 6) { $wmi = Get-CimInstance -Namespace root\ccm\invagt -Class InventoryActionStatus | Where-Object {$_.InventoryActionID -eq '{00000000-0000-0000-0000-000000000001}'} | Select-Object @{label='HWSCAN';expression={$_.ConvertToDateTime($_.LastCycleStartedDate)}} }
        else { $wmi = Get-WmiObject -Namespace root\ccm\invagt -Class InventoryActionStatus | Where-Object {$_.InventoryActionID -eq '{00000000-0000-0000-0000-000000000001}'} | Select-Object @{label='HWSCAN';expression={$_.ConvertToDateTime($_.LastCycleStartedDate)}} }
        $HWScanDate = $wmi | Select-Object -ExpandProperty HWSCAN
        $HWScanDate = Get-SmallDateTime $HWScanDate
        $minDate = Get-SmallDateTime((Get-Date).AddDays(-$days))
        if ($HWScanDate -le $minDate) {
            $fix = (Get-ChConfigHardwareInventoryFix).ToLower()
            if ($fix -eq "true") {
                $text = "ConfigMgr Hardware Inventory scan: $HWScanDate. Starting hardware inventory scan of the client."
                Write-Host $Text
                Get-SCCMPolicyHardwareInventory

                # Get the new date after policy trigger
                if ($PowerShellVersion -ge 6) { $wmi = Get-CimInstance -Namespace root\ccm\invagt -Class InventoryActionStatus | Where-Object {$_.InventoryActionID -eq '{00000000-0000-0000-0000-000000000001}'} | Select-Object @{label='HWSCAN';expression={$_.ConvertToDateTime($_.LastCycleStartedDate)}} }
                else { $wmi = Get-WmiObject -Namespace root\ccm\invagt -Class InventoryActionStatus | Where-Object {$_.InventoryActionID -eq '{00000000-0000-0000-0000-000000000001}'} | Select-Object @{label='HWSCAN';expression={$_.ConvertToDateTime($_.LastCycleStartedDate)}} }
                $HWScanDate = $wmi | Select-Object -ExpandProperty HWSCAN
                $HWScanDate = Get-SmallDateTime -Date $HWScanDate
            }
            else {
                # No need to update anything if fix = false. Last date will still be set in log
            }


        }
        else {
            $text = "ConfigMgr Hardware Inventory scan: OK"
            Write-Host $text
        }
        Write-Verbose "End Test-SCCMHardwareInventoryScan"
        return $HWScanDate
    }

    # TODO: Implement so result of this remediation is stored in WMI log object, next to result of previous WMI check. This do not require db or webservice update
    # ref: https://social.technet.microsoft.com/Forums/de-DE/1f48e8d8-4e13-47b5-ae1b-dcb831c0a93b/setup-was-unable-to-compile-the-file-discoverystatusmof-the-error-code-is-8004100e?forum=configmanagerdeployment
    Function Test-PolicyPlatform {
        [CmdletBinding()]
        Param([Parameter(Mandatory=$true)]$LogWMI)
        try {
            if (Get-WmiObject -Namespace 'root/Microsoft' -Class '__Namespace' -Filter 'Name = "PolicyPlatform"') { Write-Host "PolicyPlatform: OK" }
            else {
                Write-Warning "PolicyPlatform: Not found, recompiling WMI 'Microsoft Policy Platform\ExtendedStatus.mof'"

                if ($PowerShellVersion -ge 6) { $OS = Get-CimInstance Win32_OperatingSystem }
                else { $OS = Get-WmiObject Win32_OperatingSystem }

                # 32 or 64?
                if ($OS.OSArchitecture -match '64') { & mofcomp "$env:ProgramW6432\Microsoft Policy Platform\ExtendedStatus.mof" }
                else { &  mofcomp "$env:ProgramFiles\Microsoft Policy Platform\ExtendedStatus.mof" }

                # Update WMI log object
                $text = 'PolicyPlatform Recompiled.'
                if (-NOT($LogWMI -eq 'OK')) { $LogWMI += ". $text" }
                else { $LogWMI = $text }
            }
        }
        catch { Write-Warning "PolicyPlatform: RecompilePolicyPlatform failed!" }
        return $LogWMI
    }


    # Get the clients SiteName in Active Directory
    Function Get-ClientSiteName {
        [CmdletBinding()]
        param()
        try {
            if ($PowerShellVersion -ge 6) { $obj = (Get-CimInstance Win32_NTDomain).ClientSiteName }
            else { $obj = (Get-WmiObject Win32_NTDomain).ClientSiteName }
        }
        catch {$obj = $false}
        finally { if ($obj -ne $false) { Write-Output ($obj | Select-Object -First 1) } }
    }

    Function Test-SoftwareMeteringPrepDriver {
        [CmdletBinding()]
        param()
        # Thanks to Paul Andrews for letting me know about this issue.
        # And Sherry Kissinger for a nice fix: https://mnscug.org/blogs/sherry-kissinger/481-configmgr-ccmrecentlyusedapps-blank-or-mtrmgr-log-with-startprepdriver-openservice-failed-with-error-issue

        Write-Verbose "Start Test-SoftwareMeteringPrepDriver"

        $logdir = Get-CCMLogDirectory
        $logfile = "$logdir\mtrmgr.log"
        $content = Get-Content -Path $logfile
        $error1 = "StartPrepDriver - OpenService Failed with Error"
        $error2 = "Software Metering failed to start PrepDriver"

        if (($content -match $error1) -or ($content -match $error2)) {
            $fix = (Get-ChConfigSoftwareMeteringFix).ToLower()

            if ($fix -eq "true") {
                $Text = "Software Metering - PrepDriver: Error. Remediating..."
                Write-Host $Text
                $CMClientDIR = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Configuration\Client Properties" -Name 'Local SMS Path').'Local SMS Path'
                $ExePath = $env:windir + '\system32\RUNDLL32.EXE'
                $CLine = ' SETUPAPI.DLL,InstallHinfSection DefaultInstall 128 ' + $CMClientDIR + 'prepdrv.inf'
                $ExePath = $env:windir + '\system32\RUNDLL32.EXE'
                $Prms = $Cline.Split(" ")
                & "$Exepath" $Prms

                $newContent = $content | Select-String -pattern $error1, $error2 -notmatch
                Stop-Service -Name CcmExec
                Out-File -FilePath $logfile -InputObject $newContent -Encoding utf8 -Force
                Start-Service -Name CcmExec
                $LogSWMetering = "Remediated"
            }
            else {
                # Set $obj to true as we don't want to do anything with the CM agent.
                $LogSWMetering = "Error"
            }
        }
        else {
            $Text = "Software Metering - PrepDriver: OK"
            Write-Host $Text
            $LogSWMetering = "OK"
        }
        $content = $null # Clean the variable containing the log file.

        Write-Verbose "End Test-SoftwareMeteringPrepDriver"
        return $LogSWMetering
    }

    # SCCM Client evaluation policies
    Function Get-SCCMPolicySourceUpdateMessage {
        $trigger = "{00000000-0000-0000-0000-000000000032}"
        if ($PowerShellVersion -ge 6) { Invoke-CimMethod -Namespace 'root\ccm' -ClassName 'sms_client' -MethodName TriggerSchedule -Arguments @{sScheduleID=$trigger} -ErrorAction SilentlyContinue | Out-Null }
        else { Invoke-WmiMethod -Namespace 'root\ccm' -Class 'sms_client' -Name TriggerSchedule -ArgumentList @($trigger) -ErrorAction SilentlyContinue | Out-Null }
    }

    Function Get-SCCMPolicySendUnsentStateMessages {
        $trigger = "{00000000-0000-0000-0000-000000000111}"
        if ($PowerShellVersion -ge 6) { Invoke-CimMethod -Namespace 'root\ccm' -ClassName 'sms_client' -MethodName TriggerSchedule -Arguments @{sScheduleID=$trigger} -ErrorAction SilentlyContinue | Out-Null }
        else { Invoke-WmiMethod -Namespace 'root\ccm' -Class 'sms_client' -Name TriggerSchedule -ArgumentList @($trigger) -ErrorAction SilentlyContinue | Out-Null }
    }

    Function Get-SCCMPolicyScanUpdateSource {
        $trigger = "{00000000-0000-0000-0000-000000000113}"
        if ($PowerShellVersion -ge 6) { Invoke-CimMethod -Namespace 'root\ccm' -ClassName 'sms_client' -MethodName TriggerSchedule -Arguments @{sScheduleID=$trigger} -ErrorAction SilentlyContinue | Out-Null }
        else { Invoke-WmiMethod -Namespace 'root\ccm' -Class 'sms_client' -Name TriggerSchedule -ArgumentList @($trigger) -ErrorAction SilentlyContinue | Out-Null }
    }

    Function Get-SCCMPolicyHardwareInventory {
        $trigger = "{00000000-0000-0000-0000-000000000001}"
        if ($PowerShellVersion -ge 6) { Invoke-CimMethod -Namespace 'root\ccm' -ClassName 'sms_client' -MethodName TriggerSchedule -Arguments @{sScheduleID=$trigger} -ErrorAction SilentlyContinue | Out-Null }
        else { Invoke-WmiMethod -Namespace 'root\ccm' -Class 'sms_client' -Name TriggerSchedule -ArgumentList @($trigger) -ErrorAction SilentlyContinue | Out-Null }
    }

    Function Get-SCCMPolicyMachineEvaluation {
        $trigger = "{00000000-0000-0000-0000-000000000022}"
        if ($PowerShellVersion -ge 6) { Invoke-CimMethod -Namespace 'root\ccm' -ClassName 'sms_client' -MethodName TriggerSchedule -Arguments @{sScheduleID=$trigger} -ErrorAction SilentlyContinue | Out-Null }
        else { Invoke-WmiMethod -Namespace 'root\ccm' -Class 'sms_client' -Name TriggerSchedule -ArgumentList @($trigger) -ErrorAction SilentlyContinue | Out-Null }
    }

    <# Trigger codes
    {00000000-0000-0000-0000-000000000001} Hardware Inventory
    {00000000-0000-0000-0000-000000000002} Software Inventory
    {00000000-0000-0000-0000-000000000003} Discovery Inventory
    {00000000-0000-0000-0000-000000000010} File Collection
    {00000000-0000-0000-0000-000000000011} IDMIF Collection
    {00000000-0000-0000-0000-000000000012} Client Machine Authentication
    {00000000-0000-0000-0000-000000000021} Request Machine Assignments
    {00000000-0000-0000-0000-000000000022} Evaluate Machine Policies
    {00000000-0000-0000-0000-000000000023} Refresh Default MP Task
    {00000000-0000-0000-0000-000000000024} LS (Location Service) Refresh Locations Task
    {00000000-0000-0000-0000-000000000025} LS (Location Service) Timeout Refresh Task
    {00000000-0000-0000-0000-000000000026} Policy Agent Request Assignment (User)
    {00000000-0000-0000-0000-000000000027} Policy Agent Evaluate Assignment (User)
    {00000000-0000-0000-0000-000000000031} Software Metering Generating Usage Report
    {00000000-0000-0000-0000-000000000032} Source Update Message
    {00000000-0000-0000-0000-000000000037} Clearing proxy settings cache
    {00000000-0000-0000-0000-000000000040} Machine Policy Agent Cleanup
    {00000000-0000-0000-0000-000000000041} User Policy Agent Cleanup
    {00000000-0000-0000-0000-000000000042} Policy Agent Validate Machine Policy / Assignment
    {00000000-0000-0000-0000-000000000043} Policy Agent Validate User Policy / Assignment
    {00000000-0000-0000-0000-000000000051} Retrying/Refreshing certificates in AD on MP
    {00000000-0000-0000-0000-000000000061} Peer DP Status reporting
    {00000000-0000-0000-0000-000000000062} Peer DP Pending package check schedule
    {00000000-0000-0000-0000-000000000063} SUM Updates install schedule
    {00000000-0000-0000-0000-000000000071} NAP action
    {00000000-0000-0000-0000-000000000101} Hardware Inventory Collection Cycle
    {00000000-0000-0000-0000-000000000102} Software Inventory Collection Cycle
    {00000000-0000-0000-0000-000000000103} Discovery Data Collection Cycle
    {00000000-0000-0000-0000-000000000104} File Collection Cycle
    {00000000-0000-0000-0000-000000000105} IDMIF Collection Cycle
    {00000000-0000-0000-0000-000000000106} Software Metering Usage Report Cycle
    {00000000-0000-0000-0000-000000000107} Windows Installer Source List Update Cycle
    {00000000-0000-0000-0000-000000000108} Software Updates Assignments Evaluation Cycle
    {00000000-0000-0000-0000-000000000109} Branch Distribution Point Maintenance Task
    {00000000-0000-0000-0000-000000000110} DCM policy
    {00000000-0000-0000-0000-000000000111} Send Unsent State Message
    {00000000-0000-0000-0000-000000000112} State System policy cache cleanout
    {00000000-0000-0000-0000-000000000113} Scan by Update Source
    {00000000-0000-0000-0000-000000000114} Update Store Policy
    {00000000-0000-0000-0000-000000000115} State system policy bulk send high
    {00000000-0000-0000-0000-000000000116} State system policy bulk send low
    {00000000-0000-0000-0000-000000000120} AMT Status Check Policy
    {00000000-0000-0000-0000-000000000121} Application manager policy action
    {00000000-0000-0000-0000-000000000122} Application manager user policy action
    {00000000-0000-0000-0000-000000000123} Application manager global evaluation action
    {00000000-0000-0000-0000-000000000131} Power management start summarizer
    {00000000-0000-0000-0000-000000000221} Endpoint deployment reevaluate
    {00000000-0000-0000-0000-000000000222} Endpoint AM policy reevaluate
    {00000000-0000-0000-0000-000000000223} External event detection
    #>

    function Test-SQLConnection {
        $SQLServer = Get-ChConfigSQLServer
        $Database = 'ClientHealth'
        $FileLogLevel = ((Get-ChConfigLoggingLevel).ToString()).ToLower()

        $ConnectionString = "Server={0};Database={1};Integrated Security=True;" -f $SQLServer,$Database

        try
        {
            $sqlConnection = New-Object System.Data.SqlClient.SqlConnection $ConnectionString;
            $sqlConnection.Open();
            $sqlConnection.Close();

            $obj = $true;
            Write-Verbose "SQL connection test successfull"
        }
        catch {
            $text = "Error connecting to SQLDatabase $Database on SQL Server $SQLServer"
            Write-Error -Message $text
            if (-NOT($FileLogLevel -like "clientinstall")) { Write-ChLog -Text $text -Severity 3}
            $obj = $false;
            Write-Verbose "SQL connection test failed"
        }
        return $obj
    }

    # Invoke-SqlCmd2 - Created by Chad Miller
    function Invoke-Sqlcmd2 {
        [CmdletBinding()]
        param(
        [Parameter(Position=0, Mandatory=$true)] [string]$ServerInstance,
        [Parameter(Position=1, Mandatory=$false)] [string]$Database,
        [Parameter(Position=2, Mandatory=$false)] [string]$Query,
        [Parameter(Position=3, Mandatory=$false)] [string]$Username,
        [Parameter(Position=4, Mandatory=$false)] [string]$Password,
        [Parameter(Position=5, Mandatory=$false)] [Int32]$QueryTimeout=600,
        [Parameter(Position=6, Mandatory=$false)] [Int32]$ConnectionTimeout=15,
        [Parameter(Position=7, Mandatory=$false)] [ValidateScript({test-path $_})] [string]$InputFile,
        [Parameter(Position=8, Mandatory=$false)] [ValidateSet("DataSet", "DataTable", "DataRow")] [string]$As="DataRow"
        )

        if ($InputFile)
        {
            $filePath = $(resolve-path $InputFile).path
            $Query =  [System.IO.File]::ReadAllText("$filePath")
        }

        $conn=new-object System.Data.SqlClient.SQLConnection

        if ($Username) { $ConnectionString = "Server={0};Database={1};User ID={2};Password={3};Trusted_Connection=False;Connect Timeout={4}" -f $ServerInstance,$Database,$Username,$Password,$ConnectionTimeout }
        else { $ConnectionString = "Server={0};Database={1};Integrated Security=True;Connect Timeout={2}" -f $ServerInstance,$Database,$ConnectionTimeout }

        $conn.ConnectionString=$ConnectionString

        #Following EventHandler is used for PRINT and RAISERROR T-SQL statements. Executed when -Verbose parameter specified by caller
        if ($PSBoundParameters.Verbose)
        {
            $conn.FireInfoMessageEventOnUserErrors=$true
            $handler = [System.Data.SqlClient.SqlInfoMessageEventHandler] {Write-Verbose "$($_)"}
            $conn.add_InfoMessage($handler)
        }

        $conn.Open()
        $cmd=new-object system.Data.SqlClient.SqlCommand($Query,$conn)
        $cmd.CommandTimeout=$QueryTimeout
        $ds=New-Object system.Data.DataSet
        $da=New-Object system.Data.SqlClient.SqlDataAdapter($cmd)
        [void]$da.fill($ds)
        $conn.Close()
        switch ($As)
        {
            'DataSet'   { Write-Output ($ds) }
            'DataTable' { Write-Output ($ds.Tables) }
            'DataRow'   { Write-Output ($ds.Tables[0]) }
        }
    }




#Region Getters - JSON config file
    Function Get-ChWebServiceEnabled {
        if ($ConfigFilePath) {
            $obj = $json.WebService | Where-Object {$_.Name -like 'URI'} | Select-Object -ExpandProperty 'Enable'
        }
        Return $obj
    }
    Function Get-ChWebServiceUri {
        if ($ConfigFilePath) {
            $obj = $json.WebService | Where-Object {$_.Name -like 'URI'} | Select-Object -ExpandProperty 'Value'
        }
        Return $obj
    }
    Function Get-ChWebServiceApiKey {
        if ($ConfigFilePath) {
            $obj = $json.WebService | Where-Object {$_.Name -like 'ApiKey'} | Select-Object -ExpandProperty 'Value'
        }
        Return $obj
    }

    Function Get-ChWebServiceUseConfigFromApi {
        if ($ConfigFilePath) {
            $obj = $json.WebService | Where-Object {$_.Name -like 'URI'} | Select-Object -ExpandProperty 'Enable'
        }
        Return $obj
    }

    Function Get-ChLocalFilesPath {
        if ($ConfigFilePath) {
            $obj = $json.LocalFiles.value
        }
        $obj = $ExecutionContext.InvokeCommand.ExpandString($obj)
        if ($obj -eq $null) { $obj = Join-path $env:SystemDrive "ClientHealth" }
        Return $obj
    }

    Function Get-ChConfigClientInstallEnabled {
        if ($ConfigFilePath) {
            $obj = $json.Client | Where-Object {$_.Name -like 'InstallEnabled'} | Select-Object -ExpandProperty 'value'
        }

        return $obj
    }

    Function Get-ChConfigClientVersion {
        if ($ConfigFilePath) {
            $obj = $json.Client | Where-Object {$_.Name -like 'Version'} | Select-Object -ExpandProperty 'value'
        }

        return $obj
    }

    Function Get-ChConfigClientSitecode {
        if ($ConfigFilePath) {
            $obj = $json.Client | Where-Object {$_.Name -like 'SiteCode'} | Select-Object -ExpandProperty 'value'
        }
        return $obj
    }

    Function Get-ChConfigClientDomain {
        if ($ConfigFilePath) {
            $obj = $json.Client | Where-Object {$_.Name -like 'Domain'} | Select-Object -ExpandProperty 'value'
        }
        return $obj
    }

    Function Get-ChConfigClientAutoUpgrade {
        if ($ConfigFilePath) {
            $obj = $json.Client | Where-Object {$_.Name -like 'AutoUpgrade'} | Select-Object -ExpandProperty 'value'
        }
        return $obj
    }

    Function Get-ChConfigClientMaxLogSize {
        if ($ConfigFilePath) {
            $obj = $json.Client | Where-Object {$_.Name -like 'MaxLogSize'} | Select-Object -ExpandProperty 'Value'
        }
        return $obj
    }

    Function Get-ChConfigClientMaxLogHistory {
        if ($ConfigFilePath) {
            $obj = $json.Client | Where-Object {$_.Name -like 'MaxLogHistory'} | Select-Object -ExpandProperty 'Value'
        }
        return $obj
    }

    Function Get-ChConfigClientMaxLogSizeEnabled {
        if ($ConfigFilePath) {
            $obj = $json.Client | Where-Object {$_.Name -like 'MaxLogEnabled'} | Select-Object -ExpandProperty 'Value'
        }
        return $obj
    }

    Function Get-ChConfigClientCache {
        if ($ConfigFilePath) {
            $obj = $json.Client | Where-Object {$_.Name -like 'CacheSize'} | Select-Object -ExpandProperty 'Value'
        }
        return $obj
    }

    Function Get-ChConfigClientCacheDeleteOrphanedData {
        if ($ConfigFilePath) {
            $obj = $json.Client | Where-Object {$_.Name -like 'DeleteOrphanedData'} | Select-Object -ExpandProperty 'Value'
        }
        return $obj
    }

    Function Get-ChConfigClientCacheEnable {
        if ($ConfigFilePath) {
            $obj = $json.Client | Where-Object {$_.Name -like 'CacheSizeEnable'} | Select-Object -ExpandProperty 'Value'
        }
        return $obj
    }

    Function Get-ChConfigClientShare {
        if ($ConfigFilePath) {
            $obj = $json.Client | Where-Object {$_.Name -like 'Share'} | Select-Object -ExpandProperty 'Value' -ErrorAction SilentlyContinue
        }

        if(!($obj)){$obj=$global:ScriptPath} #If Client share is empty, default to the script folder.
        return $obj
    }

    Function Get-ChConfigUpdatesShare {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'Updates'} | Select-Object -ExpandProperty 'Value'
        }

        If (!($obj)){$obj = Join-Path $global:ScriptPath "Updates"}
        Return $obj
    }

    Function Get-ChConfigUpdatesEnable {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'Updates'} | Select-Object -ExpandProperty 'Enable'
        }
        return $obj
    }

    Function Get-ChConfigUpdatesFix {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'Updates'} | Select-Object -ExpandProperty 'Fix' }
        return $obj
    }

    Function Get-ChConfigLoggingShare {
        if ($ConfigFilePath) {
            $obj = $json.Log | Where-Object {$_.Name -like 'RemoteFile'} | Select-Object -ExpandProperty 'Value'
        }

        $obj = $ExecutionContext.InvokeCommand.ExpandString($obj)
        Return $obj
    }

    Function Get-ChConfigLoggingLocalFile {
        if ($ConfigFilePath) {
            $obj = $json.Log | Where-Object {$_.Name -like 'LocalLogFile'} | Select-Object -ExpandProperty 'Enable'
        }
        return $obj
    }

    Function Get-ChConfigLoggingEnable {
        if ($ConfigFilePath) {
            $obj = $json.Log | Where-Object {$_.Name -like 'RemoteFile'} | Select-Object -ExpandProperty 'Enable'
        }
        return $obj
    }

    Function Get-ChConfigLoggingMaxHistory {
        if ($ConfigFilePath) {
            $obj = $json.Log | Where-Object {$_.Name -like 'FileMaxLogHistory'} | Select-Object -ExpandProperty 'Value'
        }
        return $obj
    }

    Function Get-ChConfigLoggingLevel {
        if ($ConfigFilePath) {
            $obj = $json.Log | Where-Object {$_.Name -like 'FileLevel'} | Select-Object -ExpandProperty 'Value'
        }
        return $obj
    }

    Function Get-ChConfigLoggingTimeFormat {
        if ($ConfigFilePath) {
            $obj = $json.Log | Where-Object {$_.Name -like 'Time'} | Select-Object -ExpandProperty 'Value'
        }
        return $obj
    }

    Function Get-ChConfigPendingRebootApp {
        # TODO verify this function
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'PendingReboot'} | Select-Object -ExpandProperty 'Fix'
        }
        return $obj
    }

    Function Get-ChConfigMaxRebootDays {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'MaxRebootDays'} | Select-Object -ExpandProperty 'Value'
        }
        return $obj
    }

    Function Get-ChConfigRebootApplication {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'RebootApplication'} | Select-Object -ExpandProperty 'Value'
        }
        return $obj
    }

    Function Get-ChConfigRebootApplicationEnable {
        ### TODO implement in webservice
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'RebootApplication'} | Select-Object -ExpandProperty 'Enable'
        }
        return $obj
    }

    Function Get-ChConfigDNSCheck {
        # TODO verify switch, skip test and monitor for console extension
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'DNSCheck'} | Select-Object -ExpandProperty 'Enable'
        }
        return $obj
    }

    Function Get-ChConfigCcmSQLCELog {
        # TODO implement monitor mode
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'CcmSQLCELog'} | Select-Object -ExpandProperty 'Enable'
        }

        return $obj
    }

    Function Get-ChConfigDNSFix {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'DNSCheck'} | Select-Object -ExpandProperty 'Fix'
        }
        return $obj
    }

    Function Get-ChConfigDrivers {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'Drivers'} | Select-Object -ExpandProperty 'Enable'
        }
        return $obj
    }

    Function Get-ChConfigPatchLevel {
        if ($ConfigFilePath) {
            $obj = $Json.Option | Where-Object {$_.Name -like 'PatchLevel'} | Select-Object -ExpandProperty 'Enable'
        }
        return $obj
    }

    Function Get-ChConfigOSDiskFreeSpace {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'OSDiskFreeSpace'} | Select-Object -ExpandProperty 'value'
        }
        return $obj
    }

    Function Get-ChConfigHardwareInventoryEnable {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'HardwareInventory'} | Select-Object -ExpandProperty 'Enable'
        }
        return $obj
    }

    Function Get-ChConfigHardwareInventoryFix {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'HardwareInventory'} | Select-Object -ExpandProperty 'Fix'
        }
        return $obj
    }

    Function Get-ChConfigSoftwareMeteringEnable {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'SoftwareMetering'} | Select-Object -ExpandProperty 'Enable'
        }
        return $obj
    }

    Function Get-ChConfigSoftwareMeteringFix {
        # TODO implement this check in console extension and webservice
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'SoftwareMetering'} | Select-Object -ExpandProperty 'Fix'
        }
        return $obj
    }

    Function Get-ChConfigHardwareInventoryDays {
        # TODO implement this check in console extension and webservice
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'HardwareInventory'} | Select-Object -ExpandProperty 'Value'
        }
        return $obj
    }

    Function Get-ChConfigRemediationAdminShare {
        if ($ConfigFilePath) {
            $obj = $json.Remediation | Where-Object {$_.Name -like 'AdminShare'} | Select-Object -ExpandProperty 'Fix'
        }
        return $obj
    }

    Function Get-ChConfigRemediationClientProvisioningMode {
        if ($ConfigFilePath) {
            $obj = $json.Remediation | Where-Object {$_.Name -like 'ClientProvisioningMode'} | Select-Object -ExpandProperty 'Fix'
        }
        return $obj
    }

    Function Get-ChConfigRemediationClientStateMessages {
        if ($ConfigFilePath) {
            $obj = $json.Remediation | Where-Object {$_.Name -like 'ClientStateMessages'} | Select-Object -ExpandProperty 'Fix'
        }
        return $obj
    }

    Function Get-ChConfigRemediationClientWUAHandler {
        if ($ConfigFilePath) {
            $obj = $json.Remediation | Where-Object {$_.Name -like 'ClientWUAHandler'} | Select-Object -ExpandProperty 'Fix'
        }
        return $obj
    }

    Function Get-ChConfigRemediationClientWUAHandlerDays {
        # TODO implement days in console extension and webservice
        if ($ConfigFilePath) {
            $obj = $json.Remediation | Where-Object {$_.Name -like 'ClientWUAHandler'} | Select-Object -ExpandProperty 'Days'
        }
        return $obj
    }

    Function Get-ChConfigBITSCheck {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'BITSCheck'} | Select-Object -ExpandProperty 'Enable'
        }
        return $obj
    }

    Function Get-ChConfigBITSCheckFix {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'BITSCheck'} | Select-Object -ExpandProperty 'Fix'
        }
        return $obj
    }

	Function Get-ChConfigClientSettingsCheck {
        # TODO implement in console extension and webservice
        $obj = $Json.Option | Where-Object {$_.Name -like 'ClientSettingsCheck'} | Select-Object -ExpandProperty 'Enable'
        return $obj
	}

	Function Get-ChConfigClientSettingsCheckFix {
        # TODO implement in console extension and webservice
        $obj = $json.Option | Where-Object {$_.Name -like 'ClientSettingsCheck'} | Select-Object -ExpandProperty 'Fix'
        return $obj
	}

    Function Get-ChConfigWMI {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'WMI'} | Select-Object -ExpandProperty 'Enable'
        }
        return $obj
    }

    Function Get-ChConfigWMIRepairEnable {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'WMI'} | Select-Object -ExpandProperty 'Fix'
        }
        return $obj
    }

    Function Get-ChConfigRefreshComplianceState {
        # Measured in days
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'RefreshComplianceState'} | Select-Object -ExpandProperty 'Enable'
        }
        return $obj
    }

    Function Get-ChConfigRefreshComplianceStateDays {
        if ($ConfigFilePath) {
            $obj = $json.Option | Where-Object {$_.Name -like 'RefreshComplianceState'} | Select-Object -ExpandProperty 'Value'
        }
        return $obj
    }

    Function Get-ChConfigRemediationClientCertificate {
        if ($ConfigFilePath) {
            $obj = $json.Remediation | Where-Object {$_.Name -like 'ClientCertificate'} | Select-Object -ExpandProperty 'Fix'
        }
        return $obj
    }

    Function Get-ChConfigSQLServer {
        $obj = $json.Log | Where-Object {$_.Name -like 'SQL'} | Select-Object -ExpandProperty 'value'
        return $obj
    }

    Function Get-ChConfigSQLLoggingEnable {
        $obj = $json.Log | Where-Object {$_.Name -like 'SQL'} | Select-Object -ExpandProperty 'Enable'
        return $obj
    }
#EndRegion Getters - JSON config file

    function Test-ValidGuid {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]
            $GuidString
        )
        if ([string]::IsNullOrEmpty($GuidString)){
            return $false
        }
        $tryGuid = [guid]::Empty
        $OkGuid = [guid]::TryParse($GuidString,[ref]$tryGuid)
        return $OkGuid
    }

    Function Test-ConfigMgrHealthLogging {
        # Verifies that logfiles are not bigger than max history

        
        $localLogging = (Get-ChConfigLoggingLocalFile).ToLower()
        $fileshareLogging = (Get-ChConfigLoggingEnable).ToLower()

        if ($localLogging -eq "true") {
            $clientpath = Get-ChLocalFilesPath
            $logfile = "$clientpath\ClientHealth.log"
            Test-LogFileHistory -LogFilePath $logfile
        }


        if ($fileshareLogging -eq "true") {
            $logfile = Get-LogFileName
            Test-LogFileHistory -LogFilePath $logfile
        }
    }

    Function CleanUp {
        $clientpath = (Get-ChLocalFilesPath).ToLower()
        $forbidden = "$env:SystemDrive", "$env:SystemDrive\", "$env:SystemDrive\windows", "$env:SystemDrive\windows\"
        $NoDelete = $false
        foreach ($item in $forbidden) { if ($clientpath -like $item) { $NoDelete = $true } }

        if (((Test-Path "$clientpath\Temp" -ErrorAction SilentlyContinue) -eq $True) -and ($NoDelete -eq $false) ) {
            Write-Verbose "Cleaning up temporary files in $clientpath\ClientHealth"
            Remove-Item "$clientpath\Temp" -Recurse -Force | Out-Null
        }

        $LocalLogging = ((Get-ChConfigLoggingLocalFile).ToString()).ToLower()
        if (($LocalLogging -ne "true") -and ($NoDelete -eq $false)) {
            Write-Verbose "Local logging disabled. Removing $clientpath\ClientHealth"
            Remove-Item "$clientpath\Temp" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }

    class ClientHealthLog {
        [string]$clientHealthId = ([guid]::Empty).Guid.ToString()
        [string]$hostname
        [string]$operatingSystem
        [string]$architecture
        [string]$build
        [string]$manufacturer
        [string]$model
        [string]$installDate
        [string]$osUpdates = $null
        [string]$lastLoggedOnUser
        [string]$clientVersion = 'Unknown'
        [double]$psVersion
        [int]$psBuild
        [string]$sitecode
        [string]$domain
        [int]$maxLogSize = 0
        [int]$maxLogHistory = 0
        [int]$cacheSize
        [string]$clientCertificate = 'Unknown'
        [string]$provisioningMode = 'Unknown'
        [string]$dns = 'Unknown'
        [string]$drivers = 'Unknown'
        [string]$updates = 'Unknown'
        [string]$pendingReboot = 'Unknown'
        [string]$lastBootTime
        [double]$osDiskFreeSpace
        [string]$services = 'Unknown'
        [string]$adminShare = 'Unknown'
        [string]$stateMessages = 'Unknown'
        [string]$wuaHandler = 'Unknown'
        [string]$wmi = 'Unknown'
        [string]$refreshComplianceState
        [string]$clientInstalled = $null
        [string]$version
        [string]$timestamp
        [string]$hwInventory = $null
        [string]$swMetering = $null
##        [string]$clientSettings = $null
        [string]$bits = $null
        [int]$patchLevel
        [string]$clientInstalledReason = $null
##        [string]$rebootApp = 'Unknown'
        [string]$extension_000 = $null
        [string]$extension_001 = $null
        [string]$extension_002 = $null
        [string]$extension_003 = $null
        [string]$extension_004 = $null
        [string]$extension_005 = $null
        [string]$extension_006 = $null
        [string]$extension_007 = $null
        [string]$extension_008 = $null
        [string]$extension_009 = $null
        [string]$extension_010 = $null
        [string]$extension_011 = $null
        [string]$extension_012 = $null
        [string]$extension_013 = $null
        [string]$extension_014 = $null
        [string]$extension_015 = $null
        [string]$extension_016 = $null
        [string]$extension_017 = $null
        [string]$extension_018 = $null
        [string]$extension_019 = $null
    
        ClientHealthLog([datetime]$startDate, $PSVer, $ScriptVersion){
            $OS = Get-CimInstance -class Win32_OperatingSystem
            $CS = Get-CimInstance -class Win32_ComputerSystem
            if ($CS.Manufacturer -like 'Lenovo') { $this.Model = (Get-CimInstance Win32_ComputerSystemProduct).Version }
            else { $this.Model = $CS.Model }
            $this.Hostname = $env:COMPUTERNAME
            $this.InstallDate = Get-SmallDateTime -Date ($OS.InstallDate)
            $this.Operatingsystem = $OS.Caption
            $this.Architecture = ($OS.OSArchitecture -replace ('([^0-9])(\.*)', '')) + '-Bit'
            $this.Build = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').BuildLabEx
            $this.Manufacturer = $CS.Manufacturer
            $this.Sitecode = Get-Sitecode
            $this.Domain = $CS.Domain
            $this.LastLoggedOnUser = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\').LastLoggedOnUser
            $this.CacheSize = Get-ClientCache
            $this.LastBootTime = Get-SmallDateTime -Date ($OS.LastBootUpTime)
            $this.OSDiskFreeSpace = Get-OSDiskFreeSpace
            $this.RefreshComplianceState = $startDate
            $this.Timestamp = $startDate
            $this.PSVersion = [double]"$($PSVer.PSVersion.Major).$($PSVer.PSversion.Minor)"
            $this.PSBuild = $PSVer.PSVersion.Build
            $this.PatchLevel = (Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion').UBR
            $this.Version = $ScriptVersion
        }
    }
    
    Function Get-SmallDateTime {
        Param([Parameter(Mandatory=$false)]$Date = (Get-Date))
        #Write-Verbose "Start Get-SmallDateTime"
        $thisdate = Get-Date $Date

        $TimeFormat = (Get-ChConfigLoggingTimeFormat).ToLower()
        if ($TimeFormat -eq "utc") {
            $thisdate = $thisdate.ToUniversalTime()
            $thisdate = $thisdate.ToString("yyyy-MM-dd HH:mm:ss")
        } else {
            $thisdate = $thisdate.ToString("yyyy-MM-dd HH:mm:ss")
        }
        $thisdate = $thisdate -replace '\.', ':'
        return $thisdate
    }

    # Test some values are whole numbers before attempting to insert / update database
    <# Should no longer be needed with a class that will force rounding.
    Function Test-ValuesBeforeLogUpdate {
        Write-Verbose "Start Test-ValuesBeforeLogUpdate"
        [int]$Log.MaxLogSize = [Math]::Round($Log.MaxLogSize)
        [int]$Log.MaxLogHistory = [Math]::Round($Log.MaxLogHistory)
        [int]$Log.PSBuild = [Math]::Round($Log.PSBuild)
        [int]$Log.CacheSize = [Math]::Round($Log.CacheSize)
        Write-Verbose "End Test-ValuesBeforeLogUpdate"
    } #>

    Function Update-SQL {
        Param(
            [Parameter(Mandatory=$true)]$Log,
            [Parameter(Mandatory=$false)]$Table
        )

        Write-Verbose "Start Update-SQL"
        # Test-ValuesBeforeLogUpdate  Should no longer be needed with a class that will force rounding.

        $SQLServer = Get-ChConfigSQLServer
        $Database = 'ClientHealth'
        $table = 'dbo.Clients'
        $smallDateTime = Get-SmallDateTime

        if ($null -ne $log.OSUpdates) {
            # UPDATE
            $q1 = "OSUpdates='"+$log.OSUpdates+"', "
            # INSERT INTO
            $q2 = "OSUpdates, "
            # VALUES
            $q3 = "'"+$log.OSUpdates+"', "
        }
        else {
            $q1 = $null
            $q2 = $null
            $q3 = $null
        }

        if ($null -ne $log.ClientInstalled) {
            # UPDATE
            $q10 = "ClientInstalled='"+$log.ClientInstalled+"', "
            # INSERT INTO
            $q20 = "ClientInstalled, "
            # VALUES
            $q30 = "'"+$log.ClientInstalled+"', "
        }
        else {
            $q10 = $null
            $q20 = $null
            $q30 = $null
        }
		#ADD ClientSettings.log...
        $query= "begin tran
        if exists (SELECT * FROM $table WITH (updlock,serializable) WHERE ClientHealthId='"+$log.clientHealthId+"')
        begin
            UPDATE $table SET Hostname = '"+$log.Hostname+"', Operatingsystem='"+$log.Operatingsystem+"', Architecture='"+$log.Architecture+"', Build='"+$log.Build+"', Manufacturer='"+$log.Manufacturer+"', Model='"+$log.Model+"', InstallDate='"+$log.InstallDate+"', $q1 LastLoggedOnUser='"+$log.LastLoggedOnUser+"', ClientVersion='"+$log.ClientVersion+"', PSVersion='"+$log.PSVersion+"', PSBuild='"+$log.PSBuild+"', Sitecode='"+$log.Sitecode+"', Domain='"+$log.Domain+"', MaxLogSize='"+$log.MaxLogSize+"', MaxLogHistory='"+$log.MaxLogHistory+"', CacheSize='"+$log.CacheSize+"', ClientCertificate='"+$log.ClientCertificate+"', ProvisioningMode='"+$log.ProvisioningMode+"', DNS='"+$log.DNS+"', Drivers='"+$log.Drivers+"', Updates='"+$log.Updates+"', PendingReboot='"+$log.PendingReboot+"', LastBootTime='"+$log.LastBootTime+"', OSDiskFreeSpace='"+$log.OSDiskFreeSpace+"', Services='"+$log.Services+"', AdminShare='"+$log.AdminShare+"', StateMessages='"+$log.StateMessages+"', WUAHandler='"+$log.WUAHandler+"', WMI='"+$log.WMI+"', RefreshComplianceState='"+$log.RefreshComplianceState+"', HWInventory='"+$log.HWInventory+"', Version='"+$log.Version+"', $q10 Timestamp='"+$smallDateTime+"', SWMetering='"+$log.SWMetering+"', BITS='"+$log.BITS+"', PatchLevel='"+$Log.PatchLevel+"', ClientInstalledReason='"+$log.ClientInstalledReason+"'
            WHERE ClientHealthId = '"+$log.clientHealthId+"'
        end
        else
        begin
            INSERT INTO $table (ClientHealthId, Hostname, Operatingsystem, Architecture, Build, Manufacturer, Model, InstallDate, $q2 LastLoggedOnUser, ClientVersion, PSVersion, PSBuild, Sitecode, Domain, MaxLogSize, MaxLogHistory, CacheSize, ClientCertificate, ProvisioningMode, DNS, Drivers, Updates, PendingReboot, LastBootTime, OSDiskFreeSpace, Services, AdminShare, StateMessages, WUAHandler, WMI, RefreshComplianceState, HWInventory, Version, $q20 Timestamp, SWMetering, BITS, PatchLevel, ClientInstalledReason)
            VALUES ('"+$log.clientHealthId+"', '"+$log.Hostname+"', '"+$log.Operatingsystem+"', '"+$log.Architecture+"', '"+$log.Build+"', '"+$log.Manufacturer+"', '"+$log.Model+"', '"+$log.InstallDate+"', $q3 '"+$log.LastLoggedOnUser+"', '"+$log.ClientVersion+"', '"+$log.PSVersion+"', '"+$log.PSBuild+"', '"+$log.Sitecode+"', '"+$log.Domain+"', '"+$log.MaxLogSize+"', '"+$log.MaxLogHistory+"', '"+$log.CacheSize+"', '"+$log.ClientCertificate+"', '"+$log.ProvisioningMode+"', '"+$log.DNS+"', '"+$log.Drivers+"', '"+$log.Updates+"', '"+$log.PendingReboot+"', '"+$log.LastBootTime+"', '"+$log.OSDiskFreeSpace+"', '"+$log.Services+"', '"+$log.AdminShare+"', '"+$log.StateMessages+"', '"+$log.WUAHandler+"', '"+$log.WMI+"', '"+$log.RefreshComplianceState+"', '"+$log.HWInventory+"', '"+$log.Version+"', $q30 '"+$smallDateTime+"', '"+$log.SWMetering+"', '"+$log.BITS+"', '"+$Log.PatchLevel+"', '"+$Log.ClientInstalledReason+"')
        end
        commit tran"

        try { Invoke-SqlCmd2 -ServerInstance $SQLServer -Database $Database -Query $query }
        catch {
            $ErrorMessage = $_.Exception.Message
            $text = "Error updating SQL with the following query: $query. Error: $ErrorMessage"
            Write-Error $text
            Write-ChLog -Text "ERROR Insert/Update SQL. SQL Query: $query `nSQL Error: $ErrorMessage" -Severity 3
        }
        Write-Verbose "End Update-SQL"
    }

    Function Update-LogFile {
        Param(
            [Parameter(Mandatory=$true)]$Log,
            [Parameter(Mandatory=$false)]$Mode
            )
        # Start the logfile
        Write-Verbose "Start Update-LogFile"
        #$share = Get-ChConfigLoggingShare

        #Test-ValuesBeforeLogUpdate   Should no longer be needed with a class that will force rounding.
        $logfile = Get-LogFileName
        Test-LogFileHistory -LogFilePath $logfile
        $text = "<--- ConfigMgr Client Health Check starting --->"
        $text += $log | Select-Object Hostname, Operatingsystem, Architecture, Build, Model, InstallDate, OSUpdates, LastLoggedOnUser, ClientVersion, PSVersion, PSBuild, SiteCode, Domain, MaxLogSize, MaxLogHistory, CacheSize, Certificate, ProvisioningMode, DNS, PendingReboot, LastBootTime, OSDiskFreeSpace, Services, AdminShare, StateMessages, WUAHandler, WMI, RefreshComplianceState, ClientInstalled, Version, Timestamp, HWInventory, SWMetering, BITS, ClientSettings, PatchLevel, ClientInstalledReason | Out-String
        $text = $text.replace("`t","")
        $text = $text.replace("  ","")
        $text = $text.replace(" :",":")
        $text = $text -creplace '(?m)^\s*\r?\n',''

        if ($Mode -eq 'Local') { Write-ChLog -Text $text -Mode $Mode -Severity 1}
        elseif ($Mode -eq 'ClientInstalledFailed') { Write-ChLog -Text $text -Mode $Mode -Severity 1}
        else { Write-ChLog -Text $text -Severity 1}
        Write-Verbose "End Update-LogFile"
    }

    #endregion

    # Set default restart values to false
    $newinstall = $false
    $restartCCMExec = $false
    $Reinstall = $false




    # Create a DataTable to store all changes to log files to be processed later. This to prevent false positives to remediate the next time script runs if error is already remediated.
    $SCCMLogJobs = New-Object System.Data.DataTable
    [Void]$SCCMLogJobs.Columns.Add("File")
    [Void]$SCCMLogJobs.Columns.Add("Text")

}

Process {
    # Read configuration from JSON file
    if ($ConfigFilePath) {
        if ((Test-Path -Path $ConfigFilePath)) {
            # Load JSON file into variable
            Try {
                $jsonContent = Get-Content -Path $ConfigFilePath -Raw
                if (!($json = Get-JsonConfig -JsonString $jsonContent -ErrorAction SilentlyContinue)){
                    Write-Error "Unable to convert contents of Json file."
                    exit 1
                }
            }
            Catch {
                $ErrorMessage = $_.Exception.Message
                $text = "Error, could not read $ConfigFilePath. Check file location and share/ntfs permissions. Is JSON config file damaged?"
                $text += "`nError message: $ErrorMessage"
                Write-Error $text
                Exit 1
            }
        }
        else {
            $text = "Error, could not access $ConfigFilePath. Check file location and share/ntfs permissions. Did you misspell the name?"
            Write-Error $text
            Exit 1
        }
    }

    $GetConfigFromAPI = Get-ChWebServiceUseConfigFromApi
    if ($GetConfigFromAPI) {
        $WebApiUrl = Get-ChWebServiceUri
        $WebApiKey = Get-ChWebServiceApiKey
        try {
            $configText = Get-ConfigFromWebservice -URI $WebApiUrl -ApiKey $WebApiKey -ErrorAction Stop
            $json = $configText
        }
        catch {
            write-Error $_
            Exit 1
        }
        try {
            $configJsonString = ConvertTo-Json $configText
            Out-File -FilePath $ConfigFilePath -InputObject $configJsonString -ErrorAction Stop
        }
        catch{
            Write-Warning "Failed to write updated Configuration locally to file: $ConfigFilePath"
        }
    }
    
    # Build the ConfigMgr Client Install Property string
    $propertyString = ""
    foreach ($property in $json.ClientInstallProperty) {
        $propertyString = $propertyString + $property
        $propertyString = $propertyString + ' '
    }
    $clientCacheSize = Get-ChConfigClientCache
    #replace to account for multiple skipreqs and escapee the character
    $clientInstallProperties = $propertyString.Replace(';', '`;')
    $clientAutoUpgrade = (Get-ChConfigClientAutoUpgrade).ToLower()
    $AdminShare = Get-ChConfigRemediationAdminShare
    $ClientProvisioningMode = Get-ChConfigRemediationClientProvisioningMode
    $ClientStateMessages = Get-ChConfigRemediationClientStateMessages
    $ClientWUAHandler = Get-ChConfigRemediationClientWUAHandler
    $LogShare = Get-ChConfigLoggingShare
    
    Write-Verbose "Starting precheck. Determing if script will run or not."
    # Veriy script is running with administrative priveleges.
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        $text = 'ERROR: Powershell not running as Administrator! Client Health aborting.'
        Write-ChLog -Text $text -Severity 3
        Write-Error $text
        Exit 1
    }
    else {
        $StartupText1 = "PowerShell version: " + $PSVersionTable.PSVersion + ". Script executing with Administrator rights."
        Write-Host $StartupText1

        # Will exit with errorcode 2 if in task sequence
        Write-Verbose "Determing if a task sequence is running."
        if (Test-InTaskSequence){
            Write-Host "Task sequence is active executing on computer. ConfigMgr Client Health will not execute."
            Exit 2
        }
        $StartupText2 = "ConfigMgr Client Health " + $ClientHealthScriptVersion + " starting..."
        Write-Host $StartupText2
    }

    # If config.json is used
    $LocalLogging = ((Get-ChConfigLoggingLocalFile).ToString()).ToLower()
    $RemoteFileLogging = ((Get-ChConfigLoggingEnable).ToString()).ToLower()
    $FileLogLevel = ((Get-ChConfigLoggingLevel).ToString()).ToLower()
    $SQLLogging = ((Get-ChConfigSQLLoggingEnable).ToString()).ToLower()


    $ClientHealthRegistryKey = "HKLM:\Software\ConfigMgrClientHealth"
    $LastRunRegistryValueName = "LastRun"
    $ClientHealthIdValueName = "ClientHealthId"

    # Create the log object containing the result of health check
    $Log = [ClientHealthLog]::new((Get-SmallDateTime), $PSVersionTable, $ClientHealthScriptVersion)

    $KeyIDValue = Get-RegistryValue -Path $ClientHealthRegistryKey -Name $ClientHealthIdValueName
    If ((![string]::IsNullOrEmpty($KeyIDValue)) -and (Test-ValidGuid "$KeyIDValue")){
        $log.clientHealthId = $KeyIDValue
    }
    #Get the last run from the registry, defaulting to the minimum date value if the script has never ran.
    try{[datetime]$LastRun = Get-RegistryValue -Path $ClientHealthRegistryKey -Name $LastRunRegistryValueName}
    catch{$LastRun=[datetime]::MinValue}
    Write-Host "Script last ran: $($LastRun)"

    Write-Verbose "Testing if client health log files are bigger than max history for logfiles."
    Test-ConfigMgrHealthLogging

    Write-Verbose 'Validating WMI is not corrupt...'
    $WMI = Get-ChConfigWMI
    if ($WMI -like 'True') {
        Write-Verbose 'Checking if WMI is corrupt. Will reinstall configmgr client if WMI is rebuilt.'
        $log.WMI = Test-WMI
        if ($log.WMI -ne 'OK') {
            $reinstall = $true
            $log.ClientInstalledReason += "Corrupt WMI. "
        }
    }

    Write-Verbose 'Determining if compliance state should be resent...'
    $RefreshComplianceState = Get-ChConfigRefreshComplianceState
    if ($RefreshComplianceState -like 'True') {
        $RefreshComplianceStateDays = Get-ChConfigRefreshComplianceStateDays

        Write-Verbose "Checking if compliance state should be resent after $($RefreshComplianceStateDays) days."
        $Log.RefreshComplianceState = Test-RefreshComplianceState -Days $RefreshComplianceStateDays -ClientHealthRegistryKey $ClientHealthRegistryKey
    }

    Write-Verbose 'Testing if ConfigMgr client is installed. Installing if not.'
    $ClientStatus = Test-ConfigMgrClient
    $log.ClientInstalledReason = $ClientStatus.ClientInstalledReason
    $log.ClientInstalled = $ClientStatus.ClientInstalled

    Write-Verbose 'Validating if ConfigMgr client is running the minimum version...'
    $ClientVersionObject = Test-ClientVersion
    $log.ClientVersion = $ClientVersionObject.Version
    if ($ClientVersionObject.VersionMismatch -eq $true) {
        if ($clientAutoUpgrade -like 'true') {
            $reinstall = $true
            $log.ClientInstalledReason += "Below minimum verison. "
        } else {
            $log.ClientInstalledReason += "Below minimum verison. Autoupgrade disabled in config."
        }
    }

    <#
    Write-Verbose 'Validate that ConfigMgr client do not have CcmSQLCE.log and are not in debug mode'
    if (Test-CcmSQLCELog -eq $true) {
        # This is a very bad situation. ConfigMgr agent is fubar. Local SDF files are deleted by the test itself, now reinstalling client immediatly. Waiting 10 minutes before continuing with health check.
        Resolve-Client -ClientInstallProperties $ClientInstallProperties
        Start-Sleep -Seconds 600
    }
    #>

    Write-Verbose 'Validating services...'
    $log.Services = Test-Services -Services $Json.Service

    Write-Verbose 'Validating SMSTSMgr service is depenent on CCMExec service...'
    Test-SMSTSMgr

    Write-Verbose 'Validating ConfigMgr SiteCode...'
    $Log.Sitecode = Test-ClientSiteCode

    Write-Verbose 'Validating client cache size. Will restart configmgr client if cache size is changed'

    $CacheCheckEnabled = Get-ChConfigClientCacheEnable
    if ($CacheCheckEnabled -like 'True') {
        $TestClientCacheSize = Test-ClientCacheSize
        $Log.CacheSize = $TestClientCacheSize.Log
        # This check is now able to set ClientCacheSize without restarting CCMExec service.
        if ($TestClientCacheSize.Changed -eq $true) { $restartCCMExec = $false }
    }


    if (Get-ChConfigClientMaxLogSizeEnabled -eq 'True') {
        Write-Verbose 'Validating Max CCMClient Log Size...'
        $TestClientLogSize = Test-ClientLogSize
        $Log.MaxLogSize = $TestClientLogSize.LogMaxLogSize
        $Log.MaxLogHistory = $TestClientLogSize.LogMaxLogHistory

        if ($TestClientLogSize.RestartClient -eq $true) { $restartCCMExec = $true }
    }

    Write-Verbose 'Validating CCMClient provisioning mode...'
    if (($ClientProvisioningMode -like 'True') -eq $true) {
        $log.ProvisioningMode = Test-ProvisioningMode
    }
    Write-Verbose 'Validating CCMClient certificate...'

    if (Get-Service -Name ccmexec -ErrorAction SilentlyContinue) {
        if ((Get-ChConfigRemediationClientCertificate -like 'True') -eq $true) {
            $log.ClientCertificate = Test-CCMCertificateError
        }
        if (Get-ChConfigHardwareInventoryEnable -like 'True') {
            $log.HWInventory = Test-SCCMHardwareInventoryScan
        }
        if (Get-ChConfigSoftwareMeteringEnable -like 'True') {
            Write-Verbose "Testing software metering prep driver check"
            $LogSWMetering = Test-SoftwareMeteringPrepDriver
            $Log.SWMetering = $LogSWMetering
            if ($LogSWMetering -like "Remediated") {
                $restartCCMExec = $true
            }
        }
        if (($ClientWUAHandler -like 'True') -eq $true) {
            Write-Verbose 'Validating Windows Update Scan not broken by bad group policy...'
            $days = Get-ChConfigRemediationClientWUAHandlerDays
            $log.WUAHandler = Test-RegistryPol -Days $days -StartTime $LastRun
        }
        if (($ClientStateMessages -like 'True') -eq $true) {
            Write-Verbose 'Validating that CCMClient is sending state messages...'
            $log.StateMessages = Test-StateMessages
        }
        Write-Verbose 'Sending unsent state messages if any'
        Get-SCCMPolicySendUnsentStateMessages    
    } else {
        $log.ClientCertificate = "NA"
        $log.HWInventory = [datetime]::MinValue
        $Log.SWMetering = "NA"
        $log.WUAHandler = "NA"
        $log.StateMessages = "NA"
    }

    Write-Verbose 'Validating DNS...'
    if ((Get-ChConfigDNSCheck -like 'True' ) -eq $true) {
        $log.DNS = Test-DNSConfiguration
    }

    Write-Verbose 'Validating BITS'
    if (Get-ChConfigBITSCheck -like 'True') {
        $logBITS = Test-BITS
        $log.BITS = $logBITS
        if ($logBITS -like "Remediated") {
            #$Reinstall = $true
        }
    }

    Write-Verbose 'Validating ClientSettings'
	If (Get-ChConfigClientSettingsCheck -like 'True') {
        #$log.ClientSettings = Test-ClientSettingsConfiguration
	}

    Write-Verbose 'Validating Admin$ and C$ are shared...'
    if (($AdminShare -like 'True') -eq $true) {
        $log.AdminShare = Test-AdminShare
    }

    Write-Verbose 'Testing that all devices have functional drivers.'
    if ((Get-ChConfigDrivers -like 'True') -eq $true) {
        $log.Drivers = Test-MissingDrivers
    }

    $UpdatesEnabled = Get-ChConfigUpdatesEnable
    if ($UpdatesEnabled -like 'True') {
		Write-Verbose 'Validating required updates are installed...'
		$log.Updates = Test-Update
	} else {
        $log.Updates = "NA"
    }

    Write-Verbose "Validating $env:SystemDrive free diskspace (Only warning, no remediation)..."
    Test-DiskSpace #doesn't log anywhere
    Write-Verbose 'Getting install date of last OS patch for SQL log'
    $Log.OSUpdates = Get-LastInstalledPatches
    Write-Verbose 'Sending unsent state messages if any'
    Get-SCCMPolicySendUnsentStateMessages
    Write-Verbose 'Getting Source Update Message policy and policy to trigger scan update source'

    if ($newinstall -eq $false) {
        Get-SCCMPolicySourceUpdateMessage
        Get-SCCMPolicyScanUpdateSource
        Get-SCCMPolicySendUnsentStateMessages
    }
    Get-SCCMPolicyMachineEvaluation

    # Restart ConfigMgr client if tagged for restart and no reinstall tag
    if (($restartCCMExec -eq $true) -and ($Reinstall -eq $false)) {
        Write-Host "Restarting service CcmExec..."

        if ($SCCMLogJobs.Rows.Count -ge 1) {
            Stop-Service -Name CcmExec
            Write-Verbose "Processing changes to SCCM logfiles after remediation to prevent remediation again next time script runs."
            Update-SCCMLogFile
            Start-Service -Name CcmExec
        }
        else {Restart-Service -Name CcmExec}

        $Log.MaxLogSize = Get-ClientMaxLogSize
        $Log.MaxLogHistory = Get-ClientMaxLogHistory
        $log.CacheSize = Get-ClientCache
    }

    # Updating SQL Log object with current version number
    $log.Version = $ClientHealthScriptVersion

    Write-Verbose 'Cleaning up after healthcheck'
    CleanUp
    Write-Verbose 'Validating pending reboot...'
    $PendingReboot = Test-PendingReboot
    $log.PendingReboot = $PendingReboot.Message
    #$log.RebootApp = $PendingReboot.AppStartTime

    Write-Verbose 'if endabled, Getting last reboot time and rebooting if needed.'
    Invoke-RebootIfNeeded #this doesn't log anywhere

    if (Get-ChConfigClientCacheDeleteOrphanedData -like "true") {
        Write-Verbose "Removing orphaned ccm client cache items."
        Remove-CCMOrphanedCache
    }

    # Reinstall client if tagged for reinstall and configmgr client is not already installing
    $proc = Get-Process ccmsetup -ErrorAction SilentlyContinue

    if (($reinstall -eq $true) -and ($null -ne $proc) ) { Write-Warning "ConfigMgr Client set to reinstall, but ccmsetup.exe is already running." }
    elseif (($Reinstall -eq $true) -and ($null -eq $proc)) {
        Write-Verbose 'Reinstalling ConfigMgr Client'
        Resolve-Client -ClientInstallProperties $ClientInstallProperties
        # Add smalldate timestamp in SQL for when client was installed by Client Health.
        $log.ClientInstalled = Get-SmallDateTime
        $Log.MaxLogSize = Get-ClientMaxLogSize
        $Log.MaxLogHistory = Get-ClientMaxLogHistory
        $log.CacheSize = Get-ClientCache

        # Verify that installed client version is now equal or better that minimum required client version
        $NewClientVersion = Get-ClientVersion
        $MinimumClientVersion = Get-ChConfigClientVersion

        if ( $NewClientVersion -lt $MinimumClientVersion) {
            # ConfigMgr client version is still not at expected level.
            # Log for now, remediation is comming
            $Log.ClientInstalledReason += " Upgrade failed."
        }

    }

    # Get the latest client version in case it was reinstalled by the script
    $log.ClientVersion = Get-ClientVersion

    # Trigger default Microsoft CM client health evaluation
    Start-Ccmeval
    Write-Verbose "End Process"
}

End {
    # Update database and logfile with results

    #Set the last run.
    $Date = Get-Date
    Set-RegistryValue -Path $ClientHealthRegistryKey -Name $LastRunRegistryValueName -Value $Date
    Write-Host "Setting last ran to $($Date)"

    if ($LocalLogging -like 'true') {
        Write-Host 'Updating local logfile with results'
        Update-LogFile -Log $log -Mode 'Local'
    }

    if (($RemoteFileLogging -like 'true') -and ($FileLogLevel -like 'full')) {
        Write-Host 'Updating fileshare logfile with results'
        Update-LogFile -Log $log
    }

    if (($SQLLogging -eq 'true') -and (Get-ChWebServiceEnabled) -ne 'true') {
        Write-Host 'Updating SQL database with results'
        #since sql isn't awesome like the api, we need to check if we ever got a guid and if not, set it.
        if ($log.clientHealthId -eq ([guid]::Empty).Guid.ToString()){
            $log.clientHealthId = (New-Guid).Guid
            Set-RegistryValue -Path $ClientHealthRegistryKey -Name $ClientHealthIdValueName -Value $log.clientHealthId
            Write-ChLog -Text "Updating ClientHealthId in registry with SQL Action. ID [$($log.clientHealthId)]" -Severity 1
        }
        Update-SQL -Log $log
    }

    if ((Get-ChWebServiceEnabled) -eq 'true') {
        Write-Host 'Updating SQL database with results using webservice'
        $WebApiUrl = Get-ChWebServiceUri
        $WebApiKey = Get-ChWebServiceApiKey
        $Response = Update-Webservice -URI $WebApiUrl -ApiKey $WebApiKey -Log $Log
        $KeyIDValue = Get-RegistryValue -Path $ClientHealthRegistryKey -Name $ClientHealthIdValueName
        if ($KeyIDValue -ne $Response.ClientHealthId){
            if (![string]::IsNullOrEmpty($Response.ClientHealthId) -and $Response.ClientHealthId -ne ([guid]::Empty).Guid.ToString() -and (Test-ValidGuid -GuidString $Response.ClientHealthId)) {
                Set-RegistryValue -Path $ClientHealthRegistryKey -Name $ClientHealthIdValueName -Value $Response.ClientHealthId
                Write-ChLog -Text "Updating ClientHealthId in registry with Webservice Action. ID [$($log.clientHealthId)]" -Severity 1 
            } else {
                Write-ChLog -Text "Response from API did not include a valid ClientHealthID" -Severity 2
            }
        }

    }
    Write-Verbose "Client Health script finished"
}
