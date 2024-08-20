# Pre-Requisites

The only thing that the user needs is write privileges over the specific group policy as such:

![image](https://github.com/user-attachments/assets/2d79536e-45c5-4de6-91ed-b3046e677eeb)


Some group policies don't affect domain controllers, in that case local administrator escalation on affected computers are viable.

# How to Use

1. Download the ScheduledTasks.xml file
2. Download/IEX GPOwned.ps1
3. If downloaded - import module
4. Run Invoke-GPOwned using the following flags:

   |Flag|Alias|Description|
   |-|-|-|
   |-GPOGUID|-guid|Group Policy GUID|
   |-Computer|-c|Target Computer|
   |-ScheduledTasksXMLPath|-xml|Full path to the ScheduledTasks xml file|
   |-LoadDLL|-dll|Load the Microsoft.ActiveDirectory.Management.dll from a custom path, if not supplied it will try to download it to the current directory|
   |-DA|*|Adds the user to the domain admins group|
   |-Local|*|Adds a chosen user to the local administrators group on the defined computer|
   |-CMD|*|Execute a custom cmd command|
   |-PowerShell|-ps|Execute a custom powershell command|
   |-User|-u|Target user to elevate, **mandatory** for DA/Local technique|
   |-Domain|-d|Target domain, current domain is used by default|
   |-SecondTaskXMLPath|-stx|Using the the wsadd.xml file, run commands as a domain admin on workstations that are not domain controllers|

 6. If you get an error at the end of execution that removing the scheduled task failed, don't forget to remove it manually
