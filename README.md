# Pre-Requisites

The only thing that the user needs is write privileges over the specific group policy as such:

![image](https://github.com/user-attachments/assets/2d79536e-45c5-4de6-91ed-b3046e677eeb)


*****Escalating to domain admin:*****

* Group policy linked to the domain controllers &rarr; **DA/Local Flag**
* Group policy linked to a workstation which has a session of a DA &rarr; **Second XML technique**

*****Escalating to local admin:*****

* Group policy linked to a workstation which has a session of a local admin &rarr; **Local Flag**

# How to Use

1. Download the ScheduledTasks.xml file
2. Download/IEX GPOwned.ps1
3. If downloaded - import module
4. Run Invoke-GPOwned using the following flags:

| Flag | Alias | Description |
|------|-------|-------------|
| -GPOGUID | -guid | Group Policy GUID |
| -GPOName | -gpo | Group Policy Name (alternative to GUID) |
| -Computer | -c | Target Computer |
| -ScheduledTasksXMLPath | -xml | Full path to the ScheduledTasks xml file |
| -LoadDLL | -dll | Load the Microsoft.ActiveDirectory.Management.dll from a custom path, if not supplied it will try to download it to the current directory |
| -DA | | Adds the user to the domain admins group |
| -Local | | Adds a chosen user to the local administrators group on the defined computer |
| -CMD | | Execute a custom cmd command |
| -PowerShell | -ps | Execute a custom powershell command |
| -User | -u | Target user to elevate, mandatory for DA/Local technique |
| -Domain | -d | Target domain, current domain is used by default |
| -SecondTaskXMLPath | -stx | Using the wsadd.xml file, run commands as a domain admin on workstations that are not domain controllers, No need for -CMD or -PowerShell flags! |
| -SecondXMLCMD | -scmd | Execute a CMD command in the second XML |
| -SecondPowerShell | -sps | Execute a PowerShell command in the second XML |
| -Author | -a | Specify a domain admin account to use (otherwise auto-detected) |
| -Interval | -int | Custom interval in minutes to wait for GPO update (default is 5 minutes) |
| -Help | -h | Display help message |
| -Log | | Log the entire output of the tool to a text file |

 6. If you get an error at the end of execution that removing the scheduled task failed, don't forget to remove it manually

 7. When using the second XML technique, note that it may take up to 24 hours for the scheduled task to remove itself, best practice would be to unregister the scheduled task manually to assure proper clean-up.  



# TO ADD

1. ~~Second XML handling #> -User param to change in the XML, custom cmd/ps to go to that xml, verify deletion~~
2. Better error handling #> GPT.INI could be loaded by a process, JUST CHECK THAT EVERY CASE IS HANDLED
3. ~~GPO name to GUID, might be a terrible idea... but maybe...~~
4. A better loading screen hopefully
5. ~~Better output... probably colored, probably more informative~~
