try{
    $CMID = get-wmiobject -ComputerName '.' -Namespace root\ccm -Query "Select ClientID from CCM_Client" -erroraction Stop
    $CMGuid = $CMID.ClientId
} catch {
    "CM NOT FOUND"
}


$header = @{
    'ApiKey' = 'Thisisthekey12345678'
}
Invoke-RestMethod -Method Get -Uri 'https://soup-ws1.soup.wetterssource.com/api/Clients/ClientConfiguration' -Headers $header
$json=Invoke-RestMethod -Method Put -Uri 'https://soup-ws1.soup.wetterssource.com/api/Clients/Client' -Headers $header -Body $NewClient -ContentType 'application/json'


$json=Invoke-RestMethod -Method Get -Uri 'http://testdb/api/Clients/Client?name=6e1853d0-8d83-4c6e-89d0-e2ea2c829ad7' -Headers $header
$json=Invoke-RestMethod -Method Get -Uri 'http://testdb/api/Clients/ClientConfiguration' -Headers $header

$json=Invoke-RestMethod -Method Put -Uri 'http://testdb/api/Clients/Client' -Headers $header -Body $client -ContentType 'application/json'
$json=Invoke-RestMethod -Method Put -Uri 'http://testdb/api/Clients/Client' -Headers $header -Body $NewClient -ContentType 'application/json'


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
            "Value": "\\\\MEMCM01.andersrodland.com\\ClientHealthLogs$",
            "Enable": "True" 
        },
        {
            "Name": "FileLevel",
            "Value": "Full",
            "Enable": "True" 
        },
        {
            "Name": "FileMaxLogHistory",
            "Value": "8",
            "Enable": "True" 
        },
        {
            "Name": "LocalLogFile",
            "Value": "",
            "Enable": "True" 
        },
        {
            "Name": "SQL",
            "Value": "MEMCM01.andersrodland.com",
            "Enable": "False"
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
    "hostname": "NewPhil",
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



('{"webService":[{"name":"URI","value":"https://localhost:7107","enable":"true"},{"name":"ApiKey","value":"Thisisthekey12345678","enable":"true"},{"name":"UseApiConfig","value":"","enable":"true"}],"LocalFiles":{"_comment":"Path locally on computer for temporary files and local clienthealth.log if LocalLogFile=\"True\"","Value":"C:\\ClientHealth"},"Client":[{"Name":"Version","Value":"5.00.9012.1010","Enable":null},{"Name":"SiteCode","Value":"AR1","Enable":null},{"Name":"Domain","Value":"andersrodland.com","Enable":null},{"Name":"AutoUpgrade","Value":"True","Enable":null},{"Name":"Share","Value":"\\\\MEMCM01.andersrodland.com\\Clienthealth$\\Client","Enable":null},{"Name":"CacheSize","Value":"16384","Enable":null},{"Name":"CacheSizeEnable","Value":"True","Enable":null},{"Name":"DeleteOrphanedData","Value":"True","Enable":null},{"Name":"MaxLogSize","Value":"4096","Enable":null},{"Name":"MaxLogHistory","Value":"2","Enable":null},{"Name":"MaxLogEnabled","Value":"True","Enable":null}],"ClientInstallProperty":["SMSSITECODE=AR1","MP=MEMCM01.andersrodland.com","FSP=MEMCM01.andersrodland.com","DNSSUFFIX=andersrodland.com","/Source:\\\\MEMCM01.andersrodland.com\\Clienthealth$\\client","/MP:MEMCM01.andersrodland.com","/skipprereq:silverlight.exe"],"Log":[{"Name":"File","Share":"\\\\MEMCM01.andersrodland.com\\ClientHealthLogs$","Level":"Full","MaxLogHistory":"8","LocalLogFile":"True","Enable":"True","Value":null,"Comment":"Valid time formats: ClientLocal / UTC"},{"Name":"SQL","Share":null,"Level":null,"MaxLogHistory":null,"LocalLogFile":null,"Enable":"True","Value":"MEMCM01.andersrodland.com","Comment":"Valid time formats: ClientLocal / UTC"},{"Name":"Time","Share":null,"Level":null,"MaxLogHistory":null,"LocalLogFile":null,"Enable":null,"Value":"ClientLocal","Comment":"Valid time formats: ClientLocal / UTC"}],"Option":[{"Name":"CcmSQLCELog","Enable":"False","Fix":null,"Value":null,"Days":null,"Share":null},{"Name":"BITSCheck","Enable":"True","Fix":"True","Value":null,"Days":null,"Share":null},{"Name":"ClientSettingsCheck","Enable":"True","Fix":"True","Value":null,"Days":null,"Share":null},{"Name":"DNSCheck","Enable":"True","Fix":"True","Value":null,"Days":null,"Share":null},{"Name":"Drivers","Enable":"True","Fix":null,"Value":null,"Days":null,"Share":null},{"Name":"Updates","Enable":"False","Fix":"True","Value":null,"Days":null,"Share":"\\\\MEMCM01.andersrodland.com\\ClientHealth$\\Updates"},{"Name":"PendingReboot","Enable":"True","Fix":"False","Value":null,"Days":null,"Share":null},{"Name":"RebootApplication","Enable":"False","Fix":null,"Value":"\\\\MEMCM01.andersrodland.com\\ClientHealth$\\RebootApp\\shutdowntool.exe /t:7200 /m:1440","Days":null,"Share":null},{"Name":"MaxRebootDays","Enable":"True","Fix":null,"Value":null,"Days":"7","Share":null},{"Name":"OSDiskFreeSpace","Enable":null,"Fix":null,"Value":"10","Days":null,"Share":null},{"Name":"HardwareInventory","Enable":"True","Fix":"True","Value":null,"Days":"10","Share":null},{"Name":"SoftwareMetering","Enable":"True","Fix":"True","Value":null,"Days":null,"Share":null},{"Name":"WMI","Enable":"True","Fix":"True","Value":null,"Days":null,"Share":null},{"Name":"RefreshComplianceState","Enable":"True","Fix":null,"Value":null,"Days":"30","Share":null}],"Service":[{"Name":"BITS","StartupType":"Automatic (Delayed Start)","State":"Running","Uptime":""},{"Name":"winmgmt","StartupType":"Automatic","State":"Running","Uptime":""},{"Name":"wuauserv","StartupType":"Automatic (Delayed Start)","State":"Running","Uptime":""},{"Name":"lanmanserver","StartupType":"Automatic","State":"Running","Uptime":""},{"Name":"RpcSs","StartupType":"Automatic","State":"Running","Uptime":""},{"Name":"W32Time","StartupType":"Automatic","State":"Running","Uptime":""},{"Name":"ccmexec","StartupType":"Automatic (Delayed Start)","State":"Running","Uptime":""}],"Remediation":[{"Name":"AdminShare","Fix":"True","Days":null},{"Name":"ClientProvisioningMode","Fix":"True","Days":null},{"Name":"ClientStateMessages","Fix":"True","Days":null},{"Name":"ClientWUAHandler","Fix":"True","Days":"30"},{"Name":"ClientCertificate","Fix":"True","Days":null}]}'|ConvertFrom-Json).webService




@'
{
    "webService":  [
                       {
                           "name":  "URI",
                           "value":  "https://localhost:7107",
                           "enable":  "true"
                       },
                       {
                           "name":  "ApiKey",
                           "value":  "Thisisthekey12345678",
                           "enable":  "true"
                       },
                       {
                           "name":  "UseApiConfig",
                           "value":  "",
                           "enable":  "true"
                       }
                   ],
    "localFiles":  {
                       "comment":  "Path locally on computer for temporary files and local clienthealth.log if LocalLogFile=\"True\"",
                       "value":  "C:\\ClientHealth"
                   },
    "client":  [
                   {
                       "name":  "InstallEnabled",
                       "value":  "False"
                   },
                   {
                       "name":  "Version",
                       "value":  "5.00.9012.1010"
                   },
                   {
                       "name":  "SiteCode",
                       "value":  "AR1"
                   },
                   {
                       "name":  "Domain",
                       "value":  "andersrodland.com"
                   },
                   {
                       "name":  "AutoUpgrade",
                       "value":  "False"
                   },
                   {
                       "name":  "Share",
                       "value":  "\\\\MEMCM01.andersrodland.com\\Clienthealth$\\Client"
                   },
                   {
                       "name":  "CacheSize",
                       "value":  "16384"
                   },
                   {
                       "name":  "CacheSizeEnable",
                       "value":  "True"
                   },
                   {
                       "name":  "DeleteOrphanedData",
                       "value":  "True"
                   },
                   {
                       "name":  "MaxLogSize",
                       "value":  "4096"
                   },
                   {
                       "name":  "MaxLogHistory",
                       "value":  "2"
                   },
                   {
                       "name":  "MaxLogEnabled",
                       "value":  "True"
                   }
               ],
    "clientInstallProperty":  [
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
            "Name": "RemoteFile",
            "Value": "\\\\MEMCM01.andersrodland.com\\ClientHealthLogs$",
            "Enable": "False",
            "comment": ""
        },
        {
            "Name": "FileLevel",
            "Value": "Full",
            "Enable": "True",
            "comment": ""
        },
        {
            "Name": "FileMaxLogHistory",
            "Value": "8",
            "Enable": "True",
            "comment": ""
        },
        {
            "Name": "LocalLogFile",
            "Value": "",
            "Enable": "True",
            "comment": ""
        },
        {
            "Name": "SQL",
            "Value": "MEMCM01.andersrodland.com",
            "Enable": "False",
            "comment": ""
        },
        {
            "Name": "Time",
            "Value": "ClientLocal",
            "comment": "Valid time formats: ClientLocal / UTC"
        }
    ],
    "option":  [
                   {
                       "name":  "CcmSQLCELog",
                       "enable":  "False",
                       "fix":  null,
                       "value":  null
                   },
                   {
                       "name":  "BITSCheck",
                       "enable":  "True",
                       "fix":  "True",
                       "value":  null
                   },
                   {
                       "name":  "ClientSettingsCheck",
                       "enable":  "True",
                       "fix":  "True",
                       "value":  null
                   },
                   {
                       "name":  "DNSCheck",
                       "enable":  "True",
                       "fix":  "True",
                       "value":  null
                   },
                   {
                       "name":  "Drivers",
                       "enable":  "True",
                       "fix":  null,
                       "value":  null
                   },
                   {
                       "name":  "Updates",
                       "enable":  "False",
                       "fix":  "True",
                       "value":  "\\\\MEMCM01.andersrodland.com\\ClientHealth$\\Updates"
                   },
                   {
                       "name":  "PendingReboot",
                       "enable":  "True",
                       "fix":  "False",
                       "value":  null
                   },
                   {
                       "name":  "RebootApplication",
                       "enable":  "False",
                       "fix":  null,
                       "value":  "\\\\MEMCM01.andersrodland.com\\ClientHealth$\\RebootApp\\shutdowntool.exe /t:7200 /m:1440"
                   },
                   {
                       "name":  "MaxRebootDays",
                       "enable":  "True",
                       "fix":  null,
                       "value": "7"
                   },
                   {
                       "name":  "OSDiskFreeSpace",
                       "enable":  null,
                       "fix":  null,
                       "value":  "10"
                   },
                   {
                       "name":  "HardwareInventory",
                       "enable":  "True",
                       "fix":  "True",
                       "value":  "10"
                   },
                   {
                       "name":  "SoftwareMetering",
                       "enable":  "True",
                       "fix":  "True",
                       "value":  null
                   },
                   {
                       "name":  "WMI",
                       "enable":  "True",
                       "fix":  "True",
                       "value":  null
                   },
                   {
                       "name":  "RefreshComplianceState",
                       "enable":  "True",
                       "fix":  null,
                       "value":  "30"
                   }
               ],
    "service":  [
                    {
                        "name":  "BITS",
                        "startupType":  "Automatic (Delayed Start)",
                        "state":  "Running",
                        "uptime":  ""
                    },
                    {
                        "name":  "winmgmt",
                        "startupType":  "Automatic",
                        "state":  "Running",
                        "uptime":  ""
                    },
                    {
                        "name":  "wuauserv",
                        "startupType":  "Automatic (Delayed Start)",
                        "state":  "Running",
                        "uptime":  ""
                    },
                    {
                        "name":  "lanmanserver",
                        "startupType":  "Automatic",
                        "state":  "Running",
                        "uptime":  ""
                    },
                    {
                        "name":  "RpcSs",
                        "startupType":  "Automatic",
                        "state":  "Running",
                        "uptime":  ""
                    },
                    {
                        "name":  "W32Time",
                        "startupType":  "Automatic",
                        "state":  "Running",
                        "uptime":  ""
                    },
                    {
                        "name":  "ccmexec",
                        "startupType":  "Automatic (Delayed Start)",
                        "state":  "Running",
                        "uptime":  ""
                    }
                ],
    "remediation":  [
                        {
                            "name":  "AdminShare",
                            "fix":  "True",
                            "days":  null
                        },
                        {
                            "name":  "ClientProvisioningMode",
                            "fix":  "True",
                            "days":  null
                        },
                        {
                            "name":  "ClientStateMessages",
                            "fix":  "True",
                            "days":  null
                        },
                        {
                            "name":  "ClientWUAHandler",
                            "fix":  "True",
                            "days":  "30"
                        },
                        {
                            "name":  "ClientCertificate",
                            "fix":  "True",
                            "days":  null
                        }
                    ]
}
'@|ConvertFrom-Json|ConvertTo-Json -Compress|clip