#PowerShade

##Assumptions 

The study of Ryan Kazanciyan and Matt Hastings in [8] mainly influences our works in this paper. Thus, we based this preliminary study on the following assumptions:
* Attackers could find a way to get into the system and gain privilege accounts such as an account in domain admins or local administrators group 
* Attackers could enable PowerShell remoting and remotely run PowerShell via WS-MAN, or Web Services for Management protocol
* Attackers could finally bypass or change the endpoint control including Execution Policy, constrained PowerShell, AppLocker, PSLockdownPolicy, PowerShell logging and audit policies.

##Prototype Design 
Working under these assumptions is challenging because there is no study suggest the way to intercept or interpret the PowerShell remoting commands. We decided to build adaptors to intercept and wait for the call from WinRM service when a listener receives traffic. Command and Control was brought to the design because we want to discriminate PowerShell’s usage between administrators and attackers. The figure below shows the components of PowerShade protoype. 

1. C2:Command and Control - This is a centralised log server collecting PowerShell artifacts sending by the sensor(5). C2 could change sensor mode by sending C2 command explained in (4).
2. EndPoint – in our experiment, we tested PowerShade prototype on PowerShell V2.0, the most widely used version of PowerShell, which is installed by default in Window 7 and Window Server 2008.
3. Internal Components – The prototype contains adaptors for powershell.exe and wsmprovhost.exe. Its objectives are for intercepting and collecting artifacts while the sensor is used for endpoint management.
4. C2 command – the commands from C2 were sent AES-encrypted to the sensor in order to select the operation modes including monitor, block, call, and beacon.  Monitor mode is default set to collect and send PowerShell artifacts to C2. Block mode is to prevent unauthorised PowerShell call. Beacon mode intends to check sensor status, and Call mode is designed to call the real powershell.exe, not the adaptor. This is used only for administrative purposes.  
5. PowerShell artifacts – sensor sends all PowerShell artifacts to C2 every time PowerShell or wsmprovhost was called.

###Install
1. install winappdbg
2. easy_install requests
3. easy_install cherrypy
4. pip install pshutil
5. install pycrypto
6. install pyinstaller
7. build powershell_adaptor
8. build wsmprovhost
9. copy config file into the path specify in the sourcecode
10. get-service winrm
11. enable-psremoting -force
12. run server 
> python powershade_server.py -p 5001 runserver -h 0.0.0.0_
13. run client
> python powershell_client.py
