# Information
A script for a user to the "domain admins" group by creating an immediate task by abusing GPO misconfigurations.

**Requirements:**
Write permissions on a GPO (GenericWrite/GenericAll etc.)

The GPO must be Linked to the domain/domain controllers

Edit the ScheduledTasks.xml for the cmd arguments to match the user you want to elevate + Filter the right domain controller you want to target


# Usage
Check the domain GUID, this could typically be done through BloodHound.

Under the \\domain\SYSVOL\domain\<GUID> folder, create a Preferences folder if needed, and inside it a "ScheduledTasks" folder.

Put the ScheduledTasks.xml file inside the ScheduledTasks folder.

Run the script, supply it with the GPO's GUID.

# Flow
The script loads the powershell ActiveDirectory module from github to memory.

gPCMachineExtensionNames value is checked and put into a variable.

GPT.INI file is incremented by 1 (Computer Policy).

GPO AD versionNumber is incremented by 1.

gPCMachineExtensionNames for scheduled tasks are added.

After the scheduled task is created and the user is added to the "domain admins" group, the gPCMachineExtensionNames are reverted back to what they were.

The scheduled task is removed remotely.
