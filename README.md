# Pre-Requisites

The only thing that the user needs is write privileges over the specific group policy as such:

![image](https://github.com/user-attachments/assets/bd348768-a26c-40be-9c9d-17b8d9547327)

Some group policies don't affect domain controllers, in that case local administrator escalation on affected computers are viable.

# How to Use

1. Download the ScheduledTasks.xml file
2. Download/IEX GPOAttack.ps1
3. If downloaded - import module
4. Run Invoke-GPOAttack using the following flags:

     -GPOGUID: Group Policy GUID

     -ScheduledTasksXMLPath: Full path to the ScheduledTasks xml file

     -Computer: Target computer
 
     -Local - Adds a chosen user to the local administrators goup on the defined computer
 
     -DA - Adds the user to the domain admins group
 
     -User: Target user to elevate, mandatory for Local technique
 
     -Domain: Target domain

     *NOTE that aside from the "-Domain" flag the rest are mandatory for execution.

 5. If you get an error at the end of execution that removing the scheduled task failed, don't forget to remove it manually
