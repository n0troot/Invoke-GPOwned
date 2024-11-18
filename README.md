# Pre-Requisites

The only thing that the user needs is write privileges over the specific group policy as such:

![image](https://github.com/user-attachments/assets/2d79536e-45c5-4de6-91ed-b3046e677eeb)


*****Escalating to domain admin:*****

* Group policy linked to the domain controllers &rarr; **DA/Local Flag**
* Group policy linked to a workstation which has a session of a DA &rarr; **Second XML technique**

*****Escalating to local admin:*****

* Group policy linked to a workstation &rarr; **Local Flag**

# How to Use Invoke-GPOwned

1. Download the entire repo
2. Import-Module .\Microsoft.ActiveDirectory.Management.dll
3. *If Import-Module failed, Open the DLL's properties and "Unblock" the file 
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


# MultiTasking Attack - SecondTask

In the case of control over a GPO that is linked to the domain but not to the domain controllers, this attack would grant the attacker DA privileges by using a second scheduled task.
The rationale behind it is that the GPO Immediate Task is always executed with NT Authority\SYSTEM privileges, which is sufficient for escalation to DA from domain controllers yet not from a workstation.
MultiTasking attack essentially runs an immediate task on a workstation, which executes a powershell Register-ScheduledTask command as admin, adding a second scheduled task that is pre-built to add the attacker's
user to the domain admin group, by running in the context of the "highest available privileges" of the users group("S-1-5-32-545"), as a session of a domain admin is in place, the command would run in its context. 

# How to Use Get-GPRecon

This PowerShell function checks for writable Group Policy Objects (GPOs) in an Active Directory environment and can identify where these GPOs are linked. It's particularly useful for security assessments and identifying potential privilege escalation paths through GPO modifications.

| Flag | Mandatory | Description |
|------|-----------|-------------|
| -All | No | Checks all GPOs in the domain for write access |
| -GPO | No | Checks a specific GPO (can be specified by name or GUID) |
| -Full | No | Shows all computers in linked OUs when used with other parameters |

## Usage Examples

*****Check a specific GPO by name:*****
Get-GPRecon -GPO "Default Domain Policy"

*****Check a specific GPO by name and show computers in linked OUs:*****
Get-GPRecon -GPO "Default Domain Policy" -Full

*****Check a specific GPO by GUID:*****
Get-GPRecon -GPO "{31B2F340-016D-11D2-945F-00C04FB984F9}"

*****Check all GPOs in the domain:*****
Get-GPRecon -All

*****Check all GPOs and show computers in linked OUs:*****
Get-GPRecon -All -Full

# TO ADD

1. ~~Second XML handling #> -User param to change in the XML, custom cmd/ps to go to that xml, verify deletion~~
2. Better error handling #> GPT.INI could be loaded by a process, JUST CHECK THAT EVERY CASE IS HANDLED
3. ~~GPO name to GUID, might be a terrible idea... but maybe...~~
4. A better loading screen hopefully
5. ~~Better output... probably colored, probably more informative~~
6. Fix the interval parameter
