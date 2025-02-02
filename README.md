# ConfigMgr Client Health 3.x

Version: 3.0.0 alpha

__WARNING:__ Not fully functional yet.  Still needs some work.

Verision 3 of the API uses entity framework to build the database.  The api is built on .net 8.  The api can serve the configuration for the client as well through the endpoint.

## API Endpoints:

### Get

* /api/Clients/ClientConfiguration
* /api/Clients/Client

### Put

* /api/Clients/ClientConfiguration
* /api/Clients/Client

## Installation of 3.x

### API Install

1. Create `ClientHealth` database on your database server.
1. Install IIS with default options on server that will host API.
1. Install [.Net 8 Hosting bundle](https://dotnet.microsoft.com/en-us/download/dotnet/8.0) on server.
1. Create a new Website in IIS with a custom port of your choice.
1. Copy the [ClientHealthWebServiceV3.zip](./ClientHealthWebServiceV3.zip) file to the server.
1. Extract the files from the zip onto the root of the new IIS website.
1. Once Extracted, open `appsettings.json` in your favorite text editor.
   * On line 3, update the `DefaultConnection` string with your database name and a username and password.
   * At the end of the file, set the `EnableSwagger` line to `true`.
   * Note the `ClientApiKeys`.  Update the key to a password/secret you will use for reading configurations and writing the client health to the database.
   * Note the `ConfigurationApiKeys`.  Update the key to a password/secret you will use for writing configurations to the database.  This should be kept more secret than the `ClientApiKeys` as the configuration key will only be used to write the client configuration. (I'll probably eventually write a powershell script to use the endpoint to modify the configuration more easily.)
1. Restart the website.
1. Review log file.  It should have applied migrations.
1. Check the database.  It should now contain a `Clients` and `ClientConfiguration` table.
1. Browse to https://server.domain.com:7107/swagger.  Adjust this url to your iis server and port.

### API Configuration

1. Browse to https://server.domain.com:7107/swagger.
1. Take a copy of the [config.json](./config.json).
1. Make your adjustments to the configuration.
1. On the Swagger page, open the `/api/Clients/ClientConfiguration` __PUT__ endpoint.
1. Click "Try it out".
1. Enter the `ConfigurationApiKeys` in the __ApiKey__ field.
1. in the "Request body", copy the entire "config.json" text into the field and click `Execute`.
   * This will write the configuration to the `ClientConfiguration` table in the database and can then be read by the clients.

### Clienthealth Script Install and Configuration

Client Health script can be copied to each of your clients in various methods either Group Policy, Configuration Manager, Intune, Etc. Below are general guidelines on how to install it.

The config file from the old script has been changed to json.  The configuration settings are generally the same as the old.

* You will have to copy the `ConfigMgrClientHealth.ps1` and the `config.json` that you copied and modified from above.
* "Install" these on all of your PCs you want to monitor health on.
* Install location would be recommended at `C:\ProgramData\ClientHealth`.
* Create a scheduled task that will run on a daily schedule.  The command line will look something like this:

```powershell
C:\ProgramData\ClientHealth\ConfigMgrClientHealth.ps1 -Config C:\ProgramData\ClientHealth\Config.json
```

The above are the basics of the v3.  the V3 client health script when configured to get the config from the API will be able to update the config from the API.


## Original Change log from 2.x

[ConfigMgr Client Health Full documentation](https://www.andersrodland.com/configmgr-client-health/)

### Changes since stable release

* Client Health now successfully sets the client max log history.
* Client Health now successfully sets the client cache size.
* Fixed an issue where ClientInstallProperty using /skipprereq and specifying multiple components while separating with ";" would break the script.
* Updated criteria for excluding Defender signature updates in the Get-LastInstalledPatches function. Thanks to Scott Ladewig.
* Enabled debug logging in the webservice by default to make troubleshooting easier. Debug logs are stored in the "logs" folder.


This software is provided "AS IS" with no warranties. Use at your own risk.
