# ConfigMgr Client Health

Version: 3.0.0 alpha

__WARNING:__ Not fully functional yet.  Still needs some work.

This is the master branch of ConfigMgr Client Health and is ready for production.

[ConfigMgr Client Health Full documentation](https://www.andersrodland.com/configmgr-client-health/)



## Changes since stable release

* Client Health now successfully sets the client max log history.
* Client Health now successfully sets the client cache size.
* Fixed an issue where ClientInstallProperty using /skipprereq and specifying multiple components while separating with ";" would break the script.
* Updated criteria for excluding Defender signature updates in the Get-LastInstalledPatches function. Thanks to Scott Ladewig.
* Enabled debug logging in the webservice by default to make troubleshooting easier. Debug logs are stored in the "logs" folder.


This software is provided "AS IS" with no warranties. Use at your own risk.
