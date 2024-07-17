# Information
A script for a user to the "domain admins" group by creating an immediate task by abusing GPO misconfigurations.

**Requirements:**
Write permissions on a GPO (GenericWrite/GenericAll etc.)

The GPO must be Linked to the domain/domain controllers


# Usage
Check the domain GUID, this could typically be done through BloodHound.

Run the script from the same folder that the ScheduledTasks.xml exists in, supply it with the GPO's GUID.

# Flow
The Powershell ActiveDirectory module is loaded to memory.

The path \\<domain>\sysvol\<domain>\<gpo-guid>\machine\preferences\scheduledtasks is created.

ScheduledTasks.xml is copied to the path.

ScheduledTasks.xml is modified automatically.

gPCMachineExtensionNames value is checked and put into a variable.

GPT.INI file is incremented by 1 (Computer Policy).

GPO AD versionNumber is incremented by 1.

gPCMachineExtensionNames for scheduled tasks are added.

After the scheduled task is created and the user is added to the "domain admins" group, the gPCMachineExtensionNames are reverted back to what they were.

The scheduled task is removed remotely. (Half broken)
