try{
    $CMID = get-wmiobject -ComputerName '.' -Namespace root\ccm -Query "Select ClientID from CCM_Client" -erroraction Stop
    $CMGuid = $CMID.ClientId
} catch {
    "CM NOT FOUND"
}


$header = @{
    'ApiKey' = 'Thisisthekey12345678'
}

$json=Invoke-RestMethod -Method Get -Uri 'http://testdb/api/Clients/Client?name=6e1853d0-8d83-4c6e-89d0-e2ea2c829ad7' -Headers $header
$json=Invoke-RestMethod -Method Get -Uri 'http://testdb/api/Clients/ClientConfiguration' -Headers $header


$json=Invoke-RestMethod -Method Get -Uri 'https://localhost:7107/api/Clients/ClientConfiguration' -Headers $header

$json=Invoke-RestMethod -Method Get -Uri 'https://localhost:7107/api/Clients/Client?name=6e1853d0-8d83-4c6e-89d0-e2ea2c829ad7' -Headers $header
#$json=Invoke-RestMethod -Method Get -Uri 'https://localhost:7107/api/Clients/Clients' -Headers $header

$json=Invoke-RestMethod -Method Put -Uri 'https://localhost:7107/api/Clients/Client' -Headers $header -Body $client -ContentType 'application/json'
$json=Invoke-RestMethod -Method Put -Uri 'https://localhost:7107/api/Clients/Client' -Headers $header -Body $NewClient -ContentType 'application/json'

$json=Invoke-RestMethod -Method Get -Uri 'https://localhost:7107/api/Clients/Client?name=1cc78973-2d87-463c-a73d-3e8855e2c04e' -Headers $header

$json.localFiles.value



$header = @{
    'ApiKey' = 'ForWritingAPIConfig'
}


$config = @'
{
    "WebService":[
        {
            "Name":"URI",
            "Value":"http://testdb",
            "Enable":"True"
        },
        {
            "Name":"ApiKey",
            "Value":"Thisisthekey12345678"
        },
        {
            "Name":"UseConfigFromAPI",
            "Enable":"True"
        }
    ],
    "LocalFiles": {
        "comment": "Path locally on computer for temporary files and local clienthealth.log if LocalLogFile=\"True\"",
        "Value":"C:\\ClientHealth"
    },
    "Client":[
        {
            "Name":"Version",
            "Value":"5.00.9012.1010"
        },
        {
            "Name":"SiteCode",
            "Value":"AR1"
        },
        {
            "Name":"Domain",
            "Value":"andersrodland.com"
        },
        {
            "Name":"AutoUpgrade",
            "Value":"True"
        },
        {
            "Name":"Share",
            "Value":"\\\\MEMCM01.andersrodland.com\\Clienthealth$\\Client"
        },
        {
            "Name":"CacheSize",
            "Value":"16384"
        },
        {
            "Name":"CacheSizeEnable",
            "Value":"True"
        },
        {
            "Name":"DeleteOrphanedData",
            "Value":"True"
        },
        {
            "Name":"MaxLogSize",
            "Value":"4096"
        },
        {
            "Name":"MaxLogHistory",
            "Value":"2"
        },
        {
            "Name":"MaxLogEnabled",
            "Value":"True"
        }
    ],
    "ClientInstallProperty": [
        "SMSSITECODE=AR1",
        "MP=MEMCM01.andersrodland.com",
        "FSP=MEMCM01.andersrodland.com",
        "DNSSUFFIX=andersrodland.com",
        "/Source:\\\\MEMCM01.andersrodland.com\\Clienthealth$\\client",
        "/MP:MEMCM01.andersrodland.com",
        "/skipprereq:silverlight.exe"
    ],
    "Log": [
        {
            "Name": "File",
            "Share": "\\\\MEMCM01.andersrodland.com\\ClientHealthLogs$",
            "Level": "Full",
            "MaxLogHistory": "8",
            "LocalLogFile": "True",
            "Enable": "True" 
        },
        {
            "Name": "SQL",
            "Value": "MEMCM01.andersrodland.com",
            "Enable": "True"
        },
        {
            "Name": "Time",
            "Value": "ClientLocal",
            "comment": "Valid time formats: ClientLocal / UTC"
        }
    ],
    "Option": [
        {
            "Name":"CcmSQLCELog",
            "Enable":"False"
        },
        {
            "Name":"BITSCheck",
            "Enable": "True",
            "Fix": "True"
        },
        {
            "Name":"ClientSettingsCheck",
            "Enable": "True",
            "Fix": "True"
        },
        {
            "Name":"DNSCheck",
            "Enable": "True",
            "Fix": "True"
        },
        {
            "Name":"Drivers",
            "Enable": "True"
        },
        {
            "Name":"Updates",
            "Fix": "True",
            "Enable": "False",
            "Share":"\\\\MEMCM01.andersrodland.com\\ClientHealth$\\Updates"
        },
        {
            "Name":"PendingReboot",
            "Fix": "False",
            "Enable": "True"
        },
        {
            "Name":"RebootApplication",
            "Value": "\\\\MEMCM01.andersrodland.com\\ClientHealth$\\RebootApp\\shutdowntool.exe /t:7200 /m:1440",
            "Enable": "False"
        },
        {
            "Name":"MaxRebootDays",
            "Days": "7",
            "Enable": "True"
        },
        {
            "Name":"OSDiskFreeSpace",
            "Value": "10"
        },
        {
            "Name": "HardwareInventory",
            "Days": "10",
            "Fix": "True",
            "Enable": "True"
        },
        {
            "Name":"SoftwareMetering",
            "Fix": "True",
            "Enable": "True"
        },
        {
            "Name":"WMI",
            "Fix": "True",
            "Enable": "True"
        },
        {
            "Name":"RefreshComplianceState",
            "Days": "30",
            "Enable": "True"
        }
    ],
    "Service": [
        {
            "Name":"BITS",
            "StartupType": "Automatic (Delayed Start)",
            "State": "Running",
            "Uptime": ""
        },
        {
            "Name":"winmgmt",
            "StartupType": "Automatic",
            "State": "Running",
            "Uptime": ""
        },
        {
            "Name":"wuauserv",
            "StartupType": "Automatic (Delayed Start)",
            "State": "Running",
            "Uptime": ""
        },
        {
            "Name":"lanmanserver",
            "StartupType": "Automatic",
            "State": "Running",
            "Uptime": ""
        },
        {
            "Name":"RpcSs",
            "StartupType": "Automatic",
            "State": "Running",
            "Uptime": ""
        },
        {
            "Name":"W32Time",
            "StartupType": "Automatic",
            "State": "Running",
            "Uptime": ""
        },
        {
            "Name":"ccmexec",
            "StartupType": "Automatic (Delayed Start)",
            "State": "Running",
            "Uptime": ""
        }
    ],
    "Remediation": [
        {
            "Name":"AdminShare",
            "Fix": "True"
        },
        {
            "Name":"ClientProvisioningMode",
            "Fix": "True"
        },
        {
            "Name":"ClientStateMessages",
            "Fix": "True"
        },
        {
            "Name":"ClientWUAHandler",
            "Fix": "True",
            "Days": "30"
        },
        {
            "Name":"ClientCertificate",
            "Fix": "True"
        }
    ]
}
'@

$json=Invoke-RestMethod -Method Put -Uri 'https://localhost:7107/api/Clients/ClientConfiguration' -Headers $header -Body $config -ContentType 'application/json'





$client = @'
{
    "clientHealthId": "6e1853d0-8d83-4c6e-89d0-e2ea2c829ad9",
    "hostname": "Bob",
    "operatingSystem": "Windows XP",
    "architecture": "x86",
    "build": "sp3",
    "manufacturer": "Peeps",
    "model": "1",
    "installDate": "2024-03-18T07:50:39.840Z",
    "osUpdates": "2024-03-18T07:50:39.840Z",
    "lastLoggedOnUser": "Mikey",
    "clientVersion": "1.2.3.4",
    "psVersion": 5.1,
    "psBuild": 66,
    "sitecode": "ABC",
    "domain": "xyz.com",
    "maxLogSize": 12333,
    "maxLogHistory": 3,
    "cacheSize": 123456667,
    "clientCertificate": "true",
    "provisioningMode": "true",
    "dns": "yes",
    "drivers": "",
    "updates": "",
    "pendingReboot": "false",
    "lastBootTime": "2024-03-18T07:50:39.841Z",
    "osDiskFreeSpace": 12754543,
    "services": "true",
    "adminShare": "true",
    "stateMessages": "some",
    "wuaHandler": "true",
    "wmi": "true",
    "refreshComplianceState": "2024-03-18T07:50:39.841Z",
    "clientInstalled": "2024-03-18T07:50:39.841Z",
    "version": "string",
    "timestamp": "2024-03-18T07:50:39.841Z",
    "hwInventory": "2024-03-18T07:50:39.841Z",
    "swMetering": "false",
    "bits": "true",
    "patchLevel": 0,
    "clientInstalledReason": "Fun",
    "extension_000": "",
    "extension_001": "",
    "extension_002": "",
    "extension_003": "",
    "extension_004": "",
    "extension_005": "",
    "extension_006": "",
    "extension_007": "",
    "extension_008": "",
    "extension_009": "",
    "extension_010": "",
    "extension_011": "",
    "extension_012": "",
    "extension_013": "",
    "extension_014": "",
    "extension_015": "",
    "extension_016": "",
    "extension_017": "",
    "extension_018": "",
    "extension_019": ""
}
'@


$NewClient = @'
{
    "hostname": "NewBob",
    "operatingSystem": "Windows 2000 Professional",
    "architecture": "x86",
    "build": "sp2",
    "manufacturer": "Peeps",
    "model": "1",
    "installDate": "2024-03-18T07:50:39.840Z",
    "osUpdates": "2024-03-18T07:50:39.840Z",
    "lastLoggedOnUser": "Mikey",
    "clientVersion": "1.2.3.4",
    "psVersion": 5.1,
    "psBuild": 66,
    "sitecode": "ABC",
    "domain": "xyz.com",
    "maxLogSize": 12333,
    "maxLogHistory": 3,
    "cacheSize": 123456667,
    "clientCertificate": "true",
    "provisioningMode": "true",
    "dns": "yes",
    "drivers": "",
    "updates": "",
    "pendingReboot": "false",
    "lastBootTime": "2024-03-18T07:50:39.841Z",
    "osDiskFreeSpace": 12754543,
    "services": "true",
    "adminShare": "true",
    "stateMessages": "some",
    "wuaHandler": "true",
    "wmi": "true",
    "refreshComplianceState": "2024-03-18T07:50:39.841Z",
    "clientInstalled": "2024-03-18T07:50:39.841Z",
    "version": "string",
    "timestamp": "2024-03-18T07:50:39.841Z",
    "hwInventory": "2024-03-18T07:50:39.841Z",
    "swMetering": "false",
    "bits": "true",
    "patchLevel": 0,
    "clientInstalledReason": "Fun",
    "extension_000": "",
    "extension_001": "",
    "extension_002": "",
    "extension_003": "",
    "extension_004": "",
    "extension_005": "",
    "extension_006": "",
    "extension_007": "",
    "extension_008": "",
    "extension_009": "",
    "extension_010": "",
    "extension_011": "",
    "extension_012": "",
    "extension_013": "",
    "extension_014": "",
    "extension_015": "",
    "extension_016": "",
    "extension_017": "",
    "extension_018": "",
    "extension_019": ""
}
'@